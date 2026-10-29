
import os
import re
import ssl
import smtplib
import socket
import threading
import ipaddress
from datetime import datetime, timezone
from email.message import EmailMessage
from functools import wraps

from flask import (
    Flask, render_template, request, jsonify,
    session, redirect, url_for, flash
)

app = Flask(__name__)

# Configure these as environment variables on your hosting provider.
app.secret_key = os.environ.get("SECRET_KEY", "")
APP_PASSWORD = os.environ.get("APP_PASSWORD", "")

MAX_PER_BATCH = 10
MAX_PER_DAY = 30
SMTP_TIMEOUT = 15

if not app.secret_key:
    # Development fallback only. Set SECRET_KEY before deployment.
    app.secret_key = "development-only-change-this-secret"


EMAIL_PATTERN = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$"
)

_counter_lock = threading.Lock()
_daily_counter = {
    "date": datetime.now(timezone.utc).date().isoformat(),
    "sent": 0,
}


def require_login(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("logged_in"):
            if request.path.startswith("/api/"):
                return jsonify({
                    "error": "Your session has expired. Please sign in again."
                }), 401

            return redirect(url_for("login"))

        return fn(*args, **kwargs)

    return wrapper


def valid_email(value):
    return (
        isinstance(value, str)
        and len(value) <= 254
        and bool(EMAIL_PATTERN.fullmatch(value.strip()))
    )


def reset_daily_counter_if_needed():
    today = datetime.now(timezone.utc).date().isoformat()

    with _counter_lock:
        if _daily_counter["date"] != today:
            _daily_counter["date"] = today
            _daily_counter["sent"] = 0


def reserve_daily_capacity(count):
    reset_daily_counter_if_needed()

    with _counter_lock:
        if _daily_counter["sent"] + count > MAX_PER_DAY:
            return False

        _daily_counter["sent"] += count
        return True


def release_daily_capacity(count):
    with _counter_lock:
        _daily_counter["sent"] = max(
            0, _daily_counter["sent"] - count
        )


def get_smtp_settings(data):
    """
    Read SMTP credentials from this request only.
    Credentials are not saved to the session, database, or disk.
    """
    host = str(data.get("host", "smtp.gmail.com")).strip().lower()
    port_value = str(data.get("port", "587")).strip()
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))
    sender = str(data.get("sender", "")).strip()
    security = str(data.get("security", "starttls")).strip().lower()

    if not host or len(host) > 253:
        raise ValueError("Enter a valid SMTP hostname.")

    # Accept a hostname, not a URL or arbitrary URL scheme.
    if (
        "://" in host
        or "/" in host
        or "\\" in host
        or any(ch.isspace() for ch in host)
    ):
        raise ValueError("Enter a hostname such as smtp.gmail.com, not a URL.")

    # Reject localhost, private, loopback and literal IP destinations.
    # Public SMTP hostnames remain allowed.
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
        if not ip.is_global:
            raise ValueError("Private or local SMTP addresses are not allowed.")
        raise ValueError("Use the SMTP provider's hostname, not an IP address.")
    except ValueError as exc:
        if "not allowed" in str(exc) or "Use the SMTP" in str(exc):
            raise

    if port_value not in ("465", "587"):
        raise ValueError("Use port 587 (STARTTLS) or 465 (SSL/TLS).")

    port = int(port_value)

    expected_security = "ssl" if port == 465 else "starttls"
    if security != expected_security:
        raise ValueError(
            "Choose SSL/TLS for port 465 or STARTTLS for port 587."
        )

    if not username or len(username) > 254 or not valid_email(username):
        raise ValueError("Enter a valid SMTP username/email address.")

    if not password or len(password) > 512:
        raise ValueError("Enter your SMTP password or app password.")

    if not valid_email(sender):
        raise ValueError("Enter a valid sender email address.")

    # Avoid spoofed From addresses. Gmail/Workspace users should send
    # from the authenticated account or an explicitly authorized alias.
    if sender.casefold() != username.casefold():
        raise ValueError(
            "For safety, Sender Email must match SMTP Username. "
            "Use the authenticated mailbox or configure an approved alias."
        )

    return {
        "host": host,
        "port": port,
        "username": username,
        "password": password,
        "sender": sender,
        "security": security,
    }


def open_smtp_connection(settings):
    """
    Establish an authenticated SMTP session.
    Does not save or log credentials.
    """
    context = ssl.create_default_context()

    if settings["security"] == "ssl":
        server = smtplib.SMTP_SSL(
            settings["host"],
            settings["port"],
            timeout=SMTP_TIMEOUT,
            context=context,
        )
    else:
        server = smtplib.SMTP(
            settings["host"],
            settings["port"],
            timeout=SMTP_TIMEOUT,
        )
        server.ehlo()
        server.starttls(context=context)

    server.ehlo()
    server.login(settings["username"], settings["password"])

    return server


def safe_smtp_error(exc):
    """
    Return a short error message without including credentials.
    """
    if isinstance(exc, smtplib.SMTPAuthenticationError):
        return (
            "SMTP authentication failed. Check your username and app "
            "password. Gmail usually requires a Google App Password."
        )

    if isinstance(exc, smtplib.SMTPConnectError):
        return "The SMTP provider refused the connection."

    if isinstance(exc, (socket.timeout, TimeoutError)):
        return "The SMTP connection timed out. Check the host and port."

    if isinstance(exc, ssl.SSLError):
        return "TLS security negotiation failed. Check the SMTP security option."

    if isinstance(exc, smtplib.SMTPNotSupportedError):
        return "The SMTP server does not support the selected security method."

    if isinstance(exc, smtplib.SMTPException):
        return "The SMTP server returned an error. Check your SMTP settings."

    if isinstance(exc, OSError):
        return (
            "Could not reach the SMTP server. Check network access, "
            "the hostname, and your hosting provider's SMTP restrictions."
        )

    return "SMTP connection failed. Check the settings and try again."


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"

    # The dashboard uses inline CSS and JavaScript. Avoid adding an
    # incompatible restrictive CSP without moving those assets first.
    return response


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if not APP_PASSWORD:
            flash(
                "The administrator must configure APP_PASSWORD "
                "in the hosting environment.",
                "error",
            )
        elif request.form.get("password", "") == APP_PASSWORD:
            session.clear()
            session["logged_in"] = True
            session.permanent = False
            return redirect(url_for("index"))
        else:
            flash("Incorrect password.", "error")

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@require_login
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@require_login
def index():
    return render_template(
        "index.html",
        max_per_batch=MAX_PER_BATCH,
        max_per_day=MAX_PER_DAY,
    )


@app.route("/api/test-smtp", methods=["POST"])
@require_login
def test_smtp():
    data = request.get_json(silent=True) or {}

    try:
        settings = get_smtp_settings(data)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    server = None

    try:
        server = open_smtp_connection(settings)

        return jsonify({
            "ok": True,
            "message": (
                "SMTP connection and authentication succeeded. "
                "No email was sent."
            ),
        })

    except (
        smtplib.SMTPException,
        OSError,
        ssl.SSLError,
        socket.timeout,
        TimeoutError,
    ) as exc:
        return jsonify({
            "error": safe_smtp_error(exc)
        }), 502

    finally:
        if server is not None:
            try:
                server.quit()
            except Exception:
                pass


@app.route("/api/send", methods=["POST"])
@require_login
def send_hello():
    data = request.get_json(silent=True) or {}

    try:
        settings = get_smtp_settings(data)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    raw_emails = data.get("emails", "")
    consent = data.get("confirm", False)

    if consent is not True:
        return jsonify({
            "error": (
                "Confirm that the recipients expect or have agreed "
                "to receive the test email."
            )
        }), 400

    if not isinstance(raw_emails, str):
        return jsonify({"error": "The email list must be text."}), 400

    addresses = []
    seen = set()

    for line in raw_emails.replace(",", "\n").replace(";", "\n").splitlines():
        address = line.strip()

        if address and address.casefold() not in seen:
            seen.add(address.casefold())
            addresses.append(address)

    if not addresses:
        return jsonify({"error": "Enter at least one email address."}), 400

    if len(addresses) > MAX_PER_BATCH:
        return jsonify({
            "error": f"Maximum {MAX_PER_BATCH} unique addresses per batch."
        }), 400

    invalid = [address for address in addresses if not valid_email(address)]
    valid = [address for address in addresses if valid_email(address)]

    results = [
        {
            "email": address,
            "status": "Invalid format",
            "detail": "The address does not pass basic syntax checks.",
        }
        for address in invalid
    ]

    if not valid:
        return jsonify({
            "results": results,
            "summary": {
                "total": len(addresses),
                "accepted_for_sending": 0,
                "not_accepted_or_invalid": len(addresses),
                "note": "No messages were sent.",
            },
        })

    if not reserve_daily_capacity(len(valid)):
        return jsonify({
            "error": (
                f"Daily limit reached. The current limit is "
                f"{MAX_PER_DAY} messages per UTC day."
            )
        }), 429

    accepted_count = 0
    attempted_count = 0
    server = None

    try:
        server = open_smtp_connection(settings)

        for address in valid:
            message = EmailMessage()
            message["Subject"] = "Hello — email delivery test"
            message["From"] = settings["sender"]
            message["To"] = address
            message["Auto-Submitted"] = "auto-generated"
            message.set_content(
                "Hello,\n\n"
                "This is a short email delivery test requested by the sender.\n\n"
                "No action or confirmation link is required.\n\n"
                "If you did not expect this message, you can ignore it.\n"
            )

            attempted_count += 1

            try:
                refused = server.send_message(message)

                if refused:
                    results.append({
                        "email": address,
                        "status": "Rejected by SMTP server",
                        "detail": "The SMTP server refused this recipient.",
                    })
                else:
                    accepted_count += 1
                    results.append({
                        "email": address,
                        "status": "Accepted for sending",
                        "detail": (
                            "The SMTP server accepted the message. "
                            "Inbox delivery and mailbox existence are not confirmed."
                        ),
                    })

            except smtplib.SMTPRecipientsRefused:
                results.append({
                    "email": address,
                    "status": "Rejected by SMTP server",
                    "detail": "The SMTP server refused this recipient.",
                })

            except (smtplib.SMTPException, OSError, socket.timeout):
                results.append({
                    "email": address,
                    "status": "Send failed / unknown",
                    "detail": (
                        "The SMTP operation failed. Delivery status may be uncertain."
                    ),
                })

    except (
        smtplib.SMTPException,
        OSError,
        ssl.SSLError,
        socket.timeout,
        TimeoutError,
    ) as exc:
        # The batch failed before it could be processed normally.
        # Refund the reservation for the entire batch.
        release_daily_capacity(len(valid))

        return jsonify({
            "error": safe_smtp_error(exc)
        }), 502

    finally:
        if server is not None:
            try:
                server.quit()
            except Exception:
                pass

    # The daily limit counts attempted messages to prevent repeated retries
    # from bypassing the quota. Keep the reservation for attempted messages
    # and refund addresses not reached because a prior SMTP failure occurred.
    not_attempted = max(0, len(valid) - attempted_count)
    if not_attempted:
        release_daily_capacity(not_attempted)

    return jsonify({
        "results": results,
        "summary": {
            "total": len(addresses),
            "accepted_for_sending": accepted_count,
            "not_accepted_or_invalid": len(addresses) - accepted_count,
            "note": (
                "Accepted for sending is not proof of inbox delivery or "
                "mailbox existence. This app does not automatically collect "
                "later bounce reports."
            ),
        },
    })


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "5000")),
        debug=False,
    )
