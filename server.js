
import express from "express";
import nodemailer from "nodemailer";
import emailValidator from "email-validator";
import dns from "node:dns/promises";
import net from "node:net";
import https from "node:https";
import { isIP } from "node:net";

const app = express();

app.disable("x-powered-by");
app.use(express.json({ limit: "1mb" }));
app.use(express.static("public", {
  index: "index.html",
  dotfiles: "deny"
}));

app.use((_req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Cache-Control", "no-store");
  next();
});

const MAX_BATCH_SIZE = 100;
const DNS_TIMEOUT_MS = 4000;
const SMTP_TIMEOUT_MS = 6000;

const DNS_SERVERS = [
  {
    host: "cloudflare-dns.com",
    path: "/dns-query"
  },
  {
    host: "dns.google",
    path: "/resolve"
  }
];

function queryDnsHttps(domain, type) {
  return new Promise((resolve, reject) => {
    let finished = false;

    const finish = (error, value) => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      error ? reject(error) : resolve(value);
    };

    const timer = setTimeout(() => {
      finish(new Error("DNS request timed out"));
    }, DNS_TIMEOUT_MS);

    const tryProvider = (index) => {
      if (index >= DNS_SERVERS.length) {
        finish(new Error("DNS providers unavailable"));
        return;
      }

      const provider = DNS_SERVERS[index];
      const path =
        `${provider.path}?name=${encodeURIComponent(domain)}` +
        `&type=${encodeURIComponent(type)}`;

      const req = https.request({
        hostname: provider.host,
        path,
        method: "GET",
        headers: {
          Accept: "application/dns-json"
        },
        timeout: DNS_TIMEOUT_MS
      }, (res) => {
        let body = "";

        res.setEncoding("utf8");
        res.on("data", chunk => {
          body += chunk;
          if (body.length > 256 * 1024) {
            req.destroy(new Error("DNS response too large"));
          }
        });

        res.on("end", () => {
          if (res.statusCode !== 200) {
            tryProvider(index + 1);
            return;
          }

          try {
            const data = JSON.parse(body);

            if (typeof data.Status !== "number") {
              tryProvider(index + 1);
              return;
            }

            finish(null, data);
          } catch {
            tryProvider(index + 1);
          }
        });
      });

      req.on("error", () => {
        if (!finished) tryProvider(index + 1);
      });

      req.on("timeout", () => {
        req.destroy(new Error("DNS request timed out"));
      });

      req.end();
    };

    tryProvider(0);
  });
}

function extractRecords(response, type) {
  return (response?.Answer || []).filter(
    record => Number(record.type) === type
  );
}

async function validateEmail(raw) {
  const email = String(raw ?? "").trim();

  if (!email) {
    return {
      email,
      status: "Unknown",
      reason: "Empty input."
    };
  }

  if (email.length > 254 || !emailValidator.validate(email)) {
    return {
      email,
      status: "Invalid",
      reason: "Invalid email syntax or address length."
    };
  }

  const separator = email.lastIndexOf("@");
  const domain = email.slice(separator + 1).toLowerCase();

  let mx;

  try {
    mx = await queryDnsHttps(domain, "MX");
  } catch {
    return {
      email,
      status: "Unknown",
      reason: "DNS providers timed out or were unavailable."
    };
  }

  if (mx.Status === 3) {
    return {
      email,
      status: "Invalid",
      reason: "The domain does not exist (NXDOMAIN)."
    };
  }

  if (mx.Status !== 0) {
    return {
      email,
      status: "Unknown",
      reason: "DNS returned an inconclusive response."
    };
  }

  const mxRecords = extractRecords(mx, 15);

  if (mxRecords.length) {
    const targets = mxRecords.map(record => {
      const parts = String(record.data || "").trim().split(/\s+/);
      return (parts.at(-1) || "").replace(/\.$/, "").toLowerCase();
    });

    if (targets.length && targets.every(target => target === "")) {
      return {
        email,
        status: "Invalid",
        reason: "The domain publishes Null MX and does not accept email."
      };
    }

    if (targets.some(Boolean)) {
      return {
        email,
        status: "Valid",
        reason: "Syntax and MX routing look valid. Mailbox existence is unconfirmed."
      };
    }

    return {
      email,
      status: "Unknown",
      reason: "MX records could not be interpreted."
    };
  }

  // No MX records: check implicit MX fallback through A/AAAA records.
  let a;
  let aaaa;

  try {
    [a, aaaa] = await Promise.all([
      queryDnsHttps(domain, "A"),
      queryDnsHttps(domain, "AAAA")
    ]);
  } catch {
    return {
      email,
      status: "Unknown",
      reason: "MX is absent and address-record checks were inconclusive."
    };
  }

  if (a.Status === 0 && extractRecords(a, 1).length) {
    return {
      email,
      status: "Valid",
      reason: "Domain has an address record and may use implicit mail routing. Mailbox existence is unconfirmed."
    };
  }

  if (aaaa.Status === 0 && extractRecords(aaaa, 28).length) {
    return {
      email,
      status: "Valid",
      reason: "Domain has an IPv6 address and may use implicit mail routing. Mailbox existence is unconfirmed."
    };
  }

  const statuses = [a.Status, aaaa.Status];

  if (statuses.some(status => status !== 0 && status !== 3)) {
    return {
      email,
      status: "Unknown",
      reason: "Address-record DNS responses were inconclusive."
    };
  }

  return {
    email,
    status: "Invalid",
    reason: "No MX or usable A/AAAA records were found."
  };
}

app.get("/health", (_req, res) => {
  res.json({
    status: "ok",
    service: "Mora Leads Checker"
  });
});

app.post("/api/validate", async (req, res) => {
  const emails = req.body?.emails;

  if (!Array.isArray(emails)) {
    return res.status(400).json({
      error: "Send an emails array."
    });
  }

  if (emails.length === 0) {
    return res.status(400).json({
      error: "Enter at least one email address."
    });
  }

  if (emails.length > MAX_BATCH_SIZE) {
    return res.status(400).json({
      error: `Maximum ${MAX_BATCH_SIZE} addresses per request.`
    });
  }

  if (emails.some(email => typeof email !== "string")) {
    return res.status(400).json({
      error: "Every address must be a string."
    });
  }

  // Sequential processing limits outbound DNS request bursts.
  const results = [];

  for (const email of emails) {
    try {
      results.push(await validateEmail(email));
    } catch {
      results.push({
        email,
        status: "Unknown",
        reason: "Unexpected validation error."
      });
    }
  }

  res.json({ results });
});

function validateSmtpSettings(body) {
  const host = String(body.host || "").trim().toLowerCase();
  const port = Number(body.port);
  const encryption = String(body.encryption || "");
  const username = String(body.username || "");
  const password = String(body.password || "");

  if (!host || host.length > 253) {
    throw new Error("Enter a valid SMTP hostname.");
  }

  if (host.includes("/") || host.includes(":") || host.includes("@")) {
    throw new Error("Enter a hostname only, without a URL or port.");
  }

  if (isIP(host)) {
    throw new Error("Enter a hostname rather than a raw IP address.");
  }

  if (host === "localhost" || host.endsWith(".localhost")) {
    throw new Error("Local SMTP hosts are not permitted.");
  }

  if (!/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*$/.test(host)) {
    throw new Error("SMTP hostname format is invalid.");
  }

  if (![465, 587].includes(port)) {
    throw new Error("Only ports 465 and 587 are supported.");
  }

  if (
    (port === 465 && encryption !== "ssl") ||
    (port === 587 && encryption !== "starttls")
  ) {
    throw new Error("Use SSL/TLS on port 465 or STARTTLS on port 587.");
  }

  if (username.length > 320 || password.length > 1024) {
    throw new Error("Credential field is too long.");
  }

  if (Boolean(username) !== Boolean(password)) {
    throw new Error("Enter both username and password, or leave both empty.");
  }

  return { host, port, encryption, username, password };
}

async function ensurePublicHost(host) {
  const records = await dns.lookup(host, { all: true, verbatim: true });

  if (!records.length) {
    throw new Error("SMTP hostname did not resolve.");
  }

  for (const record of records) {
    const ip = record.address;
    if (!isIP(ip)) throw new Error("Invalid resolved address.");

    // Conservative SSRF protection: do not connect to private,
    // loopback, link-local, or non-public destination addresses.
    if (ip.includes(":")) {
      const lower = ip.toLowerCase();
      if (
        lower === "::1" ||
        lower.startsWith("fe80:") ||
        lower.startsWith("fc") ||
        lower.startsWith("fd") ||
        lower.startsWith("::ffff:127.") ||
        lower.startsWith("::ffff:10.") ||
        lower.startsWith("::ffff:192.168.")
      ) {
        throw new Error("SMTP hostname resolves to a non-public address.");
      }
    } else {
      const parts = ip.split(".").map(Number);
      const [a, b] = parts;

      if (
        a === 0 || a === 10 || a === 127 ||
        a >= 224 ||
        (a === 169 && b === 254) ||
        (a === 172 && b >= 16 && b <= 31) ||
        (a === 192 && b === 168)
      ) {
        throw new Error("SMTP hostname resolves to a non-public address.");
      }
    }
  }
}

app.post("/api/smtp-check", async (req, res) => {
  let transporter;

  try {
    const settings = validateSmtpSettings(req.body || {});

    await ensurePublicHost(settings.host);

    transporter = nodemailer.createTransport({
      host: settings.host,
      port: settings.port,
      secure: settings.port === 465,
      requireTLS: settings.port === 587,
      connectionTimeout: SMTP_TIMEOUT_MS,
      greetingTimeout: SMTP_TIMEOUT_MS,
      socketTimeout: SMTP_TIMEOUT_MS,
      ...(settings.username && settings.password
        ? {
            auth: {
              user: settings.username,
              pass: settings.password
            }
          }
        : {})
    });

    await transporter.verify();

    res.json({
      ok: true,
      reason: settings.username
        ? "SMTP connection and authentication succeeded. No email was sent."
        : "SMTP connection succeeded. Authentication was not tested."
    });
  } catch (error) {
    // Do not return raw SMTP error messages; they can contain
    // infrastructure details. Never log request bodies or credentials.
    let reason = "SMTP connection failed. Check the host, port, encryption, and provider restrictions.";

    if (error instanceof Error && [
      "Enter a valid SMTP hostname.",
      "Enter a hostname only, without a URL or port.",
      "Enter a hostname rather than a raw IP address.",
      "Local SMTP hosts are not permitted.",
      "SMTP hostname format is invalid.",
      "Only ports 465 and 587 are supported.",
      "Use SSL/TLS on port 465 or STARTTLS on port 587.",
      "Credential field is too long.",
      "Enter both username and password, or leave both empty.",
      "SMTP hostname did not resolve.",
      "Invalid resolved address.",
      "SMTP hostname resolves to a non-public address."
    ].includes(error.message)) {
      reason = error.message;
    } else if (error?.code === "EAUTH") {
      reason = "SMTP authentication failed. Check the username and password or app password.";
    } else if (["ETIMEDOUT", "ESOCKET", "ECONNECTION"].includes(error?.code)) {
      reason = "SMTP connection timed out or was refused. The provider may block this connection.";
    }

    res.json({ ok: false, reason });
  } finally {
    if (transporter) {
      transporter.close();
    }
  }
});

const port = Number(process.env.PORT || 3000);

if (!process.env.VERCEL) {
  app.listen(port, "127.0.0.1", () => {
    console.log(`Mora Leads Checker running on port ${port}`);
  });
}

export default app;
