#!/usr/bin/env python3
"""
Send randomized PASS/FAIL email headers to your FastAPI /tickets endpoint.

Examples:
  python .\FastAPI-Pipeline\send_sample_ticket.py --endpoint http://localhost:8000/tickets --n 5
  python .\FastAPI-Pipeline\send_sample_ticket.py --endpoint https://<your-ngrok>/tickets --n 10 --pass-prob 0.3
"""

import argparse
import random
import string
import time
from datetime import datetime, timezone
import requests

# ----------------------------
# Helpers to generate headers
# ----------------------------

SENDER_DOMAINS_TRUSTY = ["zoom.us", "google.com", "microsoft.com"]
SENDER_DOMAINS_SUSPICIOUS = ["secure-login.click", "update-verify.top", "mail-reset.xyz", "invoicing-rest.work"]
FAIL_FLAVORS = ["fail", "softfail", "none", "permerror", "temperror", "neutral"]

def rfc2822_now() -> str:
    return datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S %z")

def rand_ipv6() -> str:
    # cheap-looking IPv6 for demo purposes
    hex4 = lambda: "".join(random.choices("0123456789abcdef", k=4))
    return ":".join(hex4() for _ in range(8))

def rand_id(n=22) -> str:
    return "".join(random.choices(string.ascii_letters + string.digits, k=n))

def rand_local(n=6) -> str:
    return "".join(random.choices(string.ascii_lowercase, k=n))

def make_received_chain(hops=3) -> list[str]:
    lines = []
    src = f"{rand_local()}{random.randint(10,999)}.namprd{random.randint(1,20):02d}.prod.outlook.com"
    for _ in range(hops):
        dst = f"{rand_local()}{random.randint(10,999)}.namprd{random.randint(1,20):02d}.prod.outlook.com"
        lines.append(
            f"Received: from {src} ({rand_ipv6()})\n"
            f" by {dst} ({rand_ipv6()}) with Microsoft SMTP Server;"
            f" {rfc2822_now()}"
        )
        src = dst
    return lines

def make_auth_results(pass_triplet: bool, legit_sender: bool) -> tuple[str, str]:
    """
    Returns:
      auth_results_line, mail_from_domain
    """
    if pass_triplet:
        spf = dkim = dmarc = "pass"
    else:
        # At least one must be non-pass; others random
        vals = [random.choice(FAIL_FLAVORS), random.choice([GOOD := "pass", *FAIL_FLAVORS]),
                random.choice([GOOD, *FAIL_FLAVORS])]
        random.shuffle(vals)
        spf, dkim, dmarc = vals

    mail_from_domain = random.choice(SENDER_DOMAINS_TRUSTY if legit_sender else SENDER_DOMAINS_SUSPICIOUS)

    line = (
        "Authentication-Results: "
        f"spf={spf} smtp.mailfrom=bounce@{mail_from_domain}; "
        f"dkim={dkim} header.d={mail_from_domain}; "
        f"dmarc={dmarc} header.from={mail_from_domain}"
    )
    return line, mail_from_domain

def generate_headers(pass_prob: float) -> tuple[str, bool]:
    """
    Build a realistic header block.
    Returns: (headers_string, is_all_pass)
    """
    is_pass = random.random() < pass_prob
    legit_sender = is_pass or (random.random() < 0.3)

    received = make_received_chain(hops=random.randint(3, 5))
    auth_line, sender_domain = make_auth_results(is_pass, legit_sender)

    from_local = "no-reply" if legit_sender else random.choice(["support", "security", "it-help"])
    to_addr = random.choice(["student@example.edu", "you@example.com", "it@example.org"])
    subj = random.choice([
        "Meeting assets are ready",
        "Password reset",
        "Action required",
        "Invoice available",
        "Please verify your account",
    ])
    if not is_pass:
        subj = random.choice(["URGENT", "VERIFY", "RESET", "ACTION REQUIRED"]) + ": " + subj

    hdrs = []
    hdrs.extend(received)
    hdrs.append(auth_line)
    hdrs.append(f"Date: {rfc2822_now()}")
    hdrs.append(f"From: {sender_domain.split('.')[0].title()} <{from_local}@{sender_domain}>")
    hdrs.append(f"To: {to_addr}")
    hdrs.append(f"Message-ID: <{rand_id()}@{sender_domain}>")
    hdrs.append(f"Subject: {subj}")

    return "\n".join(hdrs), is_pass

# ----------------------------
# Main
# ----------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--endpoint", required=True, help="FastAPI POST /tickets endpoint")
    ap.add_argument("--n", type=int, default=5, help="how many tickets to send")
    ap.add_argument("--pass-prob", type=float, default=0.4,
                    help="probability that SPF/DKIM/DMARC are all pass (default 0.4)")
    ap.add_argument("--timeout", type=float, default=15.0)
    args = ap.parse_args()

    ok = 0
    for i in range(args.n):
        headers_block, is_pass = generate_headers(args.pass_prob)

        payload = {
            "reporter": random.choice(["alice@example.com", "bob@example.com", "carol@example.com"]),
            "title": ("Benign email" if is_pass else "Suspicious email"),
            "body": ("Looks fine to me." if is_pass else "Looks odd—please review."),
            "urls": (["https://zoom.us"] if is_pass else ["http://example.bad/reset"]),
            "headers": headers_block
        }

        try:
            r = requests.post(args.endpoint, json=payload, timeout=args.timeout)
            status_code = r.status_code
            try:
                resp = r.json()
            except Exception:
                resp = {"raw": r.text}

            # The API returns {"ticket_id": ..., "status": "..."} where status may be "pass", "fail", "unknown", or "analyzer_error"
            print(f"[{i+1}/{args.n}] SENT "
                  f"(wanted={'PASS' if is_pass else 'FAIL'}) "
                  f"→ HTTP {status_code}, resp={str(resp)[:120]}")
            if r.ok:
                ok += 1
        except Exception as e:
            print(f"[{i+1}/{args.n}] ERROR: {e}")

        time.sleep(0.2)  # tiny spacing

    print(f"\nDone. Sent OK: {ok}/{args.n}")

if __name__ == "__main__":
    main()
