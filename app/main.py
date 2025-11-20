import os, time, json, sqlite3, re
from typing import List, Optional, Any, Dict
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, EmailStr
import httpx

DB_PATH = os.getenv("DATABASE_URL", "tickets.db")
ANALYZER_FORM_URL = os.getenv("ANALYZER_FORM_URL", "http://analyzer:8080/").strip()

app = FastAPI(title="Gatekeeper API")

# ---- SQLite ----
conn = sqlite3.connect(DB_PATH, check_same_thread=False)
cur = conn.cursor()
cur.execute("""
CREATE TABLE IF NOT EXISTS tickets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL,
  reporter TEXT,
  title TEXT,
  body TEXT,
  urls TEXT,
  headers TEXT,
  analyzer_status TEXT,
  analyzer_result TEXT
)
""")
conn.commit()

# ---- Models ----
class TicketIn(BaseModel):
    reporter: EmailStr
    title: str
    body: str
    urls: Optional[List[str]] = []
    headers: str  # raw RFC-822 header block

class TicketOut(BaseModel):
    ticket_id: int
    status: str

# ---- Helpers ----
_RESULT_RE = re.compile(r'\b(spf|dkim|dmarc)\s*=\s*([a-zA-Z]+)', re.IGNORECASE)

BAD_VALUES = {
    "fail", "softfail", "permerror", "temperror", "neutral", "none", "invalid",
    "policy", "hardfail"
}
GOOD_VALUE = "pass"

def auth_verdict_from_headers(raw_headers: str) -> Dict[str, Optional[str]]:
    """
    Parse Authentication-Results lines and return per-signal result + overall verdict.
    overall: 'pass' iff spf=pass & dkim=pass & dmarc=pass
             'fail' if any present and not 'pass'
             'unknown' if none were found
    """
    # collect all auth-results lines (can be folded, keep simple string scan)
    lines = []
    for line in raw_headers.splitlines():
        if line.lower().startswith("authentication-results"):
            lines.append(line)
        elif line.lower().startswith("authentication-results-original"):
            lines.append(line)

    found = {}
    for l in lines:
        for m in _RESULT_RE.finditer(l):
            k = m.group(1).lower()
            v = m.group(2).lower()
            # keep the first seen explicit result for each key
            found.setdefault(k, v)

    spf = found.get("spf")
    dkim = found.get("dkim")
    dmarc = found.get("dmarc")

    # derive overall
    present = [x for x in (spf, dkim, dmarc) if x is not None]
    if not present:
        overall = "unknown"
    else:
        # if any non-pass value appears -> fail
        if any(v != GOOD_VALUE for v in present):
            overall = "fail"
        else:
            # all present are pass; require all three to exist to be strict:
            overall = "pass" if (spf == dkim == dmarc == "pass") else "fail"

    return {"spf": spf, "dkim": dkim, "dmarc": dmarc, "overall": overall}

# ---- Endpoints ----
@app.get("/")
def health():
    return {
        "msg": "FastAPI ok",
        "db": DB_PATH,
        "analyzer_form_url": ANALYZER_FORM_URL or None
    }

@app.get("/tickets")
def list_tickets():
    cur.execute("""
        SELECT id, ts, reporter, title, body, urls, analyzer_status
        FROM tickets ORDER BY id DESC
    """)
    rows = cur.fetchall()
    return [
        {
            "id": r[0],
            "ts": r[1],
            "reporter": r[2],
            "title": r[3],
            "body": r[4],
            "urls": r[5].split(",") if r[5] else [],
            "analyzer_status": r[6],
        } for r in rows
    ]

@app.get("/tickets/{ticket_id}")
def get_ticket(ticket_id: int):
    cur.execute("""
        SELECT id, ts, reporter, title, body, urls, headers, analyzer_status, analyzer_result
        FROM tickets WHERE id=?
    """, (ticket_id,))
    r = cur.fetchone()
    if not r:
        raise HTTPException(404, "ticket not found")
    return {
        "id": r[0],
        "ts": r[1],
        "reporter": r[2],
        "title": r[3],
        "body": r[4],
        "urls": r[5].split(",") if r[5] else [],
        "headers": r[6],
        "analyzer_status": r[7],
        "analyzer_result": json.loads(r[8]) if r[8] else None
    }

@app.post("/tickets", response_model=TicketOut)
def create_ticket(t: TicketIn):
    # 1) Store ticket (queued)
    cur.execute(
        "INSERT INTO tickets (ts, reporter, title, body, urls, headers, analyzer_status, analyzer_result) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (time.time(), t.reporter, t.title, t.body, ",".join(t.urls or []), t.headers, "queued", None)
    )
    conn.commit()
    ticket_id = cur.lastrowid

    # 2) Call analyzer UI (store HTML regardless of pass/fail)
    analysis: Optional[Dict[str, Any]] = None
    analyzer_call_ok = True
    try:
        with httpx.Client(timeout=20.0) as client:
            resp = client.post(ANALYZER_FORM_URL, data={"headers": t.headers})
        resp.raise_for_status()
        analysis = {"html": resp.text}
    except Exception as e:
        analysis = {"error": str(e)}
        analyzer_call_ok = False

    # 3) Compute pass/fail from raw headers
    verdict = auth_verdict_from_headers(t.headers)
    if analyzer_call_ok:
        status = verdict["overall"]  # "pass" / "fail" / "unknown"
    else:
        status = "analyzer_error"

    # Optional: include parsed verdict alongside HTML to help the UI
    if analysis is not None:
        analysis["verdict"] = verdict

    # 4) Save outcome
    cur.execute(
        "UPDATE tickets SET analyzer_status=?, analyzer_result=? WHERE id=?",
        (status, json.dumps(analysis) if analysis is not None else None, ticket_id)
    )
    conn.commit()

    return TicketOut(ticket_id=ticket_id, status=status)

