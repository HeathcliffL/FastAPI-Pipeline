# Gatekeeper: Email Ticket Classifier + Header Analyzer (FastAPI + MHA)

This project ingests user-reported tickets via a **FastAPI** service, stores them in **SQLite**, submits the email **headers** to a self-hosted **Mail Header Analyzer (MHA)** web app, and assigns an `analyzer_status` of **pass/fail/unknown** based on the `Authentication-Results` fields **SPF/DKIM/DMARC** parsed from the raw headers.

**Pass** = `spf=pass` **AND** `dkim=pass` **AND** `dmarc=pass`  
**Fail** = any of SPF/DKIM/DMARC exists and is **not** `pass` (e.g., `softfail`, `fail`, `none`, `permerror`, `temperror`, `neutral`, …)  
**Unknown** = none of SPF/DKIM/DMARC appear in the headers

---

## Architecture

```mermaid
flowchart LR
  U[User / Script / Postman] -->|POST /tickets| A[FastAPI]
  subgraph A1[FastAPI app]
    A -->|insert| DB[(SQLite: tickets.db)]
    A -->|POST form: headers| MHA[MHA (Mail Header Analyzer) UI]
    MHA -->|HTML response| A
    A -->|update row (HTML + verdict)| DB
  end

  DB -->|GET /tickets, /tickets/{id}| V[Viewer / Dashboard]
```

**Key Data Flow**
1. **Ticket Ingestion** → `POST /tickets` with JSON (`reporter`, `title`, `body`, `urls`, **`headers`**).
2. **Store** → Ticket is saved to SQLite as `queued`.
3. **Analyze** → FastAPI posts `headers` (form-encoded) to MHA (`ANALYZER_FORM_URL`), receives **HTML**.
4. **Verdict** → FastAPI parses raw headers for SPF/DKIM/DMARC and sets `analyzer_status` = `pass`/`fail`/`unknown`.
5. **Persist** → Save HTML + verdict JSON into `analyzer_result`, and status into `analyzer_status`.
6. **Read** → `GET /tickets` lists tickets; `GET /tickets/{id}` returns full record inc. analyzer results.

---

## Repo Layout (suggested)

```
.
├─ app/
│  ├─ main.py                 # FastAPI service (stores tickets, calls MHA, parses verdict)
│  └─ requirements.txt
├─ email-header-analyzer/     # MHA cloned repo (or image build context)
├─ docker-compose.yml         # Runs api + analyzer on one network
├─ send_sample_ticket.py      # Generates randomized pass/fail headers & POSTs tickets
└─ README.md
```

---

## Prerequisites

- Python 3.10+ (if running FastAPI directly)
- Docker + Docker Compose v2 (if using containers)

---

## Quick Start (Docker Compose)

> **Recommended**: Easiest way to run both FastAPI and MHA together.

1) **Clone the analyzer repo** next to this project (or use your own path):
```bash
git clone https://github.com/lnxg33k/email-header-analyzer.git
```

2) **Configure** `docker-compose.yml` (already set in this project):
- FastAPI service (`api`) exposes **8000**
- Analyzer service (`analyzer`) is reachable from API at `http://analyzer:8080/`
- Optionally map analyzer to host (e.g., `8081:8080`) if you want to open its UI in your browser

3) **Build & run**:
```bash
sudo docker compose up -d --build
sudo docker compose ps
```

4) **Health checks**:
```bash
curl http://localhost:8000/         # FastAPI health JSON
# If analyzer mapped to host 8081:
curl http://localhost:8081/         # Analyzer UI HTML
```

5) **Send a sample ticket** (randomized pass/fail headers):
```bash
python3 send_sample_ticket.py --endpoint http://localhost:8000/tickets --n 3 --pass-prob 0.4
```

6) **Inspect results**:
```bash
curl http://localhost:8000/tickets | jq
curl http://localhost:8000/tickets/1 | jq
```

You should see `analyzer_status` as `pass`/`fail`/`unknown` and `analyzer_result` containing `{ "html": "...", "verdict": { spf,dkim,dmarc,overall } }`.

> **Tip**: To view the analyzer’s HTML for a ticket, you can add an optional route in `main.py`:
> ```py
> from fastapi import Response, HTTPException
> @app.get("/tickets/{ticket_id}/analysis.html")
> def analysis_html(ticket_id: int):
>     cur.execute("SELECT analyzer_result FROM tickets WHERE id=?", (ticket_id,))
>     r = cur.fetchone()
>     if not r or not r[0]: raise HTTPException(404, "analysis not found")
>     data = json.loads(r[0]); html = data.get("html")
>     if not html: raise HTTPException(404, "no html analysis stored")
>     return Response(content=html, media_type="text/html")
> ```
> Then open: `http://localhost:8000/tickets/<ID>/analysis.html`

---

## Alternative: Run FastAPI directly (venv)

```bash
cd app
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# If analyzer runs in Docker on the same host:
export ANALYZER_FORM_URL="http://localhost:8080/"
# If using docker-compose for both, within the compose network it's:
# export ANALYZER_FORM_URL="http://analyzer:8080/"

uvicorn main:app --host 0.0.0.0 --port 8000
```

**Systemd (optional)**  
Create a unit if you want FastAPI to run on boot (edit paths accordingly).

---

## Environment Variables

- `DATABASE_URL` — SQLite path (default: `tickets.db`, or `/data/tickets.db` in Docker)
- `ANALYZER_FORM_URL` — URL of the MHA form endpoint.  
  - In Docker Compose: `http://analyzer:8080/`  
  - On host (MHA mapped to 8081): `http://localhost:8081/`

> MHA is a **web UI**. We submit `headers` via **form-encoded POST** and store the returned **HTML**.  
> If you later add a JSON adapter, switch to `ANALYZER_URL` with JSON payload and `resp.json()` parsing.

---

## API Endpoints

- `GET /` → health + config
- `POST /tickets` → create ticket & analyze headers  
  **Body (JSON):**
  ```json
  {
    "reporter": "alice@example.com",
    "title": "Suspicious email",
    "body": "Looks odd",
    "urls": ["http://example.bad/reset"],
    "headers": "Received: ...\nAuthentication-Results: spf=softfail; dkim=fail; dmarc=fail\n..."
  }
  ```
  **Response:**
  ```json
  {"ticket_id": 7, "status": "fail"}
  ```

- `GET /tickets` → list tickets (id, fields, `analyzer_status`)
- `GET /tickets/{id}` → full record including `analyzer_result` (HTML + verdict)

---

## `send_sample_ticket.py` (randomized headers)

Usage:
```bash
python3 send_sample_ticket.py --endpoint http://localhost:8000/tickets --n 5 --pass-prob 0.4
python3 send_sample_ticket.py --endpoint https://<your-ngrok>.ngrok-free.dev/tickets --n 10 --pass-prob 0.3
```

What it does:
- Generates realistic **Received** chain and `Authentication-Results`
- Randomly picks all-pass (probability `--pass-prob`) or fail/no-pass variants
- Sends to your API and prints the server’s response

---

## Troubleshooting

- **Port collision (8080 in use)**: Either change analyzer mapping to `8081:8080` or remove `ports:` and use `expose:` for internal-only. Re-run `docker compose up -d --build`.
- **Permissions with Docker**: add your user to the `docker` group or prefix with `sudo`.
- **`analyzer_status=analyzer_error`**: MHA not reachable. Check `ANALYZER_FORM_URL` and container logs: `docker compose logs -f analyzer`.
- **Ngrok**: the API must be reachable from your PC; use ngrok on the FastAPI port (8000).

---

## Metrics (what to report in class)

- **Classifier metrics**: precision/recall/F1 for the pass/fail from headers *(if you build a small labeled set)*
- **System metrics**: average latency per ticket, automation rate, success rate of analyzer call, end-to-end demo.
- **Reproducibility**: include `docker-compose.yml`, `requirements.txt`, and a small seed dataset (e.g., a few sample headers).

---

## License & Credits

- FastAPI app: this project
- Mail Header Analyzer (MHA): https://github.com/lnxg33k/email-header-analyzer (credit to original authors)
