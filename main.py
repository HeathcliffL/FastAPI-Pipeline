from fastapi import FastAPI
from pydantic import BaseModel
from typing import List, Optional

app = FastAPI()

class Ticket(BaseModel):
    reporter: str
    title: str
    body: str
    urls: Optional[List[str]] = []

@app.get("/")
def read_root():
    return {"msg": "FastAPI is running on the VM"}

@app.post("/tickets")
def create_ticket(ticket: Ticket):
    # for now, just echo it back
    return {"status": "queued", "ticket": ticket}
