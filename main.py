"""COSC-3506 Phase 3: degree-audit REST service (FastAPI, in-memory state)."""
import os
import re
import time
from collections import deque
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
from bs4 import BeautifulSoup
from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from pydantic import BaseModel

app = FastAPI(title="Degree Audit API")

GRAD_TOTAL = 120
PAST = {"Completed", "In-Progress", "Attempted"}
CODE_RE = re.compile(r"[A-Za-z]{2,5}[\s\-]?\d{3,4}[A-Za-z]?")

# shortcut: in-memory state, lost on restart; fine because clients re-import before auditing
catalog: dict[str, dict] = {}
history: dict[str, list[dict]] = {}
plans: dict[str, list[dict]] = {}

# Phase 4: auth + rate limiting state (in memory)
JWT_SECRET = os.environ.get("JWT_SECRET", "cosc3506-phase4-dev-secret-change-me-0123456789")
JWT_ALG = "HS256"
ADMIN_USER = "admin"
users: dict[str, bytes] = {ADMIN_USER: bcrypt.hashpw(b"admin", bcrypt.gensalt(rounds=10))}
audit_hits: dict[str, deque] = {}
RATE_LIMIT, RATE_WINDOW = 10, 60.0


def norm(code: str) -> str:
    return re.sub(r"[\s\-]", "", code or "").upper()


def pretty(code: str) -> str:
    m = re.fullmatch(r"([A-Z]+)(\d.*)", norm(code))
    return f"{m.group(1)}-{m.group(2)}" if m else norm(code)


def term_key(t: str):
    m = re.fullmatch(r"(\d{2})([WSF])", (t or "").strip().upper())
    return (int(m.group(1)), "WSF".index(m.group(2))) if m else (0, 0)


def tables(html: str, required: set):
    soup = BeautifulSoup(html, "html.parser")
    for t in soup.find_all("table"):
        if required <= {th.get_text(strip=True) for th in t.find_all("th")}:
            for r in t.find_all("tr"):
                tds = [c.get_text(" ", strip=True) for c in r.find_all("td")]
                if tds:
                    yield tds


def parse_catalog(html: str) -> dict:
    out = {}
    for tds in tables(html, {"Credits", "Prerequisites"}):
        if len(tds) < 4 or not tds[0]:
            continue
        cross = tds[4] if len(tds) > 4 else ""
        out[norm(tds[0])] = {
            "code": pretty(tds[0]),
            "title": tds[1],
            "credits": int(tds[2]) if tds[2].isdigit() else 0,
            "prereq_text": tds[3],
            "prereqs": [norm(c) for c in CODE_RE.findall(tds[3])],
            "any_of": bool(re.search(r"\bor\b", tds[3], re.I)),
            "cross_listed": [norm(c) for c in CODE_RE.findall(cross)],
        }
    return out


def grade_rank(g: str):
    g = (g or "").strip()
    if re.fullmatch(r"\d+(\.\d+)?", g):
        return (2, float(g))
    return (1, 0.0) if re.fullmatch(r"[A-EF][+-]?", g, re.I) else (0, 0.0)


def parse_history(html: str) -> list[dict]:
    best = {}
    for tds in tables(html, {"Status", "Course", "Credits"}):
        if len(tds) < 6 or not tds[1] or tds[0] not in PAST or not tds[4]:
            continue
        row = {"course": norm(tds[1]), "term": tds[4], "status": tds[0], "grade": tds[3],
               "credits": int(tds[5]) if tds[5].isdigit() else 0}
        k = (row["course"], row["term"])  # duplicate rows for one course+term: keep best grade
        if k not in best or (grade_rank(row["grade"]), row["credits"]) > (grade_rank(best[k]["grade"]), best[k]["credits"]):
            best[k] = row
    return list(best.values())


async def read_html(file: UploadFile) -> str:
    raw = (await file.read()).decode("utf-8", errors="replace")
    if "<table" not in raw.lower():
        raise HTTPException(400, "uploaded file contains no HTML table")
    return raw


class Credentials(BaseModel):
    username: str
    password: str


def make_token(username: str) -> str:
    role = "admin" if username == ADMIN_USER else "student"
    exp = datetime.now(timezone.utc) + timedelta(hours=12)
    return jwt.encode({"sub": username, "role": role, "exp": exp}, JWT_SECRET, algorithm=JWT_ALG)


def token_claims(request: Request):
    """Return decoded JWT claims, or None when the header is missing/invalid/expired."""
    auth = request.headers.get("authorization", "")
    parts = auth.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    try:
        return jwt.decode(parts[1].strip(), JWT_SECRET, algorithms=[JWT_ALG])
    except jwt.PyJWTError:
        return None


def require_owner(request: Request, sid: str, allow_admin: bool = False) -> dict:
    claims = token_claims(request)
    if not claims or not claims.get("sub"):
        raise HTTPException(401, "Unauthorized")
    if claims["sub"] == sid or (allow_admin and claims.get("role") == "admin"):
        return claims
    raise HTTPException(401, "Unauthorized")


def to_record(row: dict) -> dict:
    return {"course_code": pretty(row["course"]), "term": row["term"],
            "credits_earned": row["credits"], "status": row["status"]}


@app.post("/api/v1/auth/register", status_code=201)
def register(body: Credentials):
    if not body.username or not body.password:
        raise HTTPException(400, "username and password required")
    if body.username in users:
        raise HTTPException(409, "username already exists")
    users[body.username] = bcrypt.hashpw(body.password.encode("utf-8"), bcrypt.gensalt(rounds=10))
    return {"status": "registered"}


@app.post("/api/v1/auth/login")
def login(body: Credentials):
    stored = users.get(body.username)
    if stored is None or not bcrypt.checkpw(body.password.encode("utf-8"), stored):
        raise HTTPException(401, "invalid credentials")
    return {"access_token": make_token(body.username), "token_type": "bearer"}


@app.get("/")
def health():
    return {"status": "ok"}


@app.post("/api/v1/admin/catalog/import")
async def import_catalog(file: UploadFile = File(...)):
    parsed = parse_catalog(await read_html(file))
    if not parsed:
        raise HTTPException(400, "no catalog rows found")
    catalog.clear()
    catalog.update(parsed)
    return {"imported": len(parsed)}


@app.post("/api/v1/students/{sid}/history/import", status_code=201)
async def import_history(sid: str, request: Request, file: UploadFile = File(...)):
    require_owner(request, sid)  # BOLA lock: token sub must equal student_id
    rows = parse_history(await read_html(file))
    history[sid] = rows
    return {"status": "success", "past_courses_imported": len(rows),
            "student_id": sid, "imported": len(rows)}


class HistoryRecord(BaseModel):
    course_code: str
    term: str
    credits_earned: int = 0
    status: str


class HistoryBody(BaseModel):
    history: list[HistoryRecord]


@app.put("/api/v1/students/{sid}/history")
def replace_history(sid: str, body: HistoryBody):
    if sid not in history:
        raise HTTPException(404, "unknown student")
    history[sid] = [{"course": norm(h.course_code), "term": h.term, "status": h.status,
                     "grade": "", "credits": h.credits_earned} for h in body.history]
    return {"status": "success", "message": "Academic history updated successfully"}


@app.delete("/api/v1/students/{sid}/history")
def clear_history(sid: str):
    if sid not in history:
        raise HTTPException(404, "unknown student")
    history[sid] = []
    return {"status": "success", "message": "Academic history cleared"}


@app.get("/api/v1/students/{sid}/profile")
def profile(sid: str, request: Request):
    require_owner(request, sid, allow_admin=True)
    if sid not in history and sid not in plans:
        raise HTTPException(404, "unknown student")
    return {"student_id": sid,
            "history": [to_record(r) for r in history.get(sid, [])],
            "plan": [{"course_code": p["course_code"], "term": p["term"]} for p in plans.get(sid, [])]}


class PlannedCourse(BaseModel):
    course_code: str
    term: str


class Plan(BaseModel):
    planned_courses: list[PlannedCourse]


@app.post("/api/v1/students/{sid}/plan")
def set_plan(sid: str, plan: Plan):
    plans[sid] = [p.model_dump() for p in plan.planned_courses]
    return {"status": "success", "planned_courses_saved": len(plans[sid]),
            "student_id": sid, "planned_courses": plans[sid]}


@app.put("/api/v1/students/{sid}/plan")
def replace_plan(sid: str, plan: Plan):
    if sid not in history and sid not in plans:
        raise HTTPException(404, "unknown student")
    plans[sid] = [p.model_dump() for p in plan.planned_courses]
    return {"status": "success", "planned_courses_saved": len(plans[sid])}


@app.delete("/api/v1/students/{sid}/plan")
def clear_plan(sid: str):
    if sid not in history and sid not in plans:
        raise HTTPException(404, "unknown student")
    plans[sid] = []
    return {"status": "success", "message": "Plan cleared"}


@app.get("/api/v1/students/{sid}/plan")
def get_plan(sid: str, request: Request):
    require_owner(request, sid, allow_admin=True)
    if sid not in history and sid not in plans:
        raise HTTPException(404, "unknown student")
    return {"student_id": sid, "planned_courses": plans.get(sid, [])}


@app.get("/api/v1/students/{sid}/audit-report")
def audit_report(sid: str, request: Request, strict: bool = False):
    claims = token_claims(request)
    fwd = request.headers.get("x-forwarded-for", "")
    ip = fwd.split(",")[0].strip() if fwd else (request.client.host if request.client else "unknown")
    key = f"sub:{claims['sub']}" if claims and claims.get("sub") else f"ip:{ip}"
    now = time.monotonic()
    hits = audit_hits.setdefault(key, deque())
    while hits and now - hits[0] >= RATE_WINDOW:
        hits.popleft()
    if len(hits) >= RATE_LIMIT:
        raise HTTPException(429, "Too Many Requests")
    hits.append(now)
    if sid not in history and sid not in plans:
        raise HTTPException(404, "unknown student")
    rows = history.get(sid, [])
    planned = plans.get(sid, [])
    completed = {r["course"] for r in rows if r["status"] == "Completed"}
    # earned: Completed credits, each (course, term) once; a retake that was only Attempted earlier adds nothing
    total_earned = sum(r["credits"] for r in rows if r["status"] == "Completed")

    timeline, cross, total_planned = [], [], 0
    for p in sorted(planned, key=lambda p: term_key(p["term"])):
        n = norm(p["course_code"])
        course = catalog.get(n)
        errors = []
        if not course:
            errors.append({"type": "UNKNOWN_COURSE", "course_code": pretty(n),
                           "message": f"{pretty(n)} is not in the catalog"})
        else:
            total_planned += course["credits"]
            have = completed | {norm(q["course_code"]) for q in planned
                                if term_key(q["term"]) < term_key(p["term"])}
            missing = [c for c in course["prereqs"] if c not in have]
            unmet = len(missing) == len(course["prereqs"]) if course["any_of"] else bool(missing)
            if unmet:
                errors.append({"type": "MISSING_PREREQUISITE", "course_code": pretty(n),
                               "missing": [pretty(c) for c in missing],
                               "message": f"{pretty(n)} requires {course['prereq_text']}"})
            for other in course["cross_listed"]:
                if other in completed:
                    cross.append({"type": "CROSS_LIST_VIOLATION", "course_code": pretty(n),
                                  "term": p["term"], "cross_listed_with": pretty(other),
                                  "message": f"{pretty(n)} is cross-listed with completed {pretty(other)}"})
        timeline.append({"course_code": pretty(n), "term": p["term"], "errors": errors})

    has_issue = bool(cross) or any(e["errors"] for e in timeline)
    status = ("failed" if strict else "warning") if has_issue else "ok"
    return {
        "student_id": sid,
        "status": status,
        "timeline_validation": timeline,
        "cross_list_violations": cross,
        "credit_summary": {
            "total_earned": total_earned,
            "total_planned": total_planned,
            "total_remaining_for_graduation": max(0, GRAD_TOTAL - total_earned - total_planned),
        },
    }


def next_term(label: str) -> str:
    year, season = term_key(label)
    seasons = "WSF"
    if season + 1 < len(seasons):
        return f"{year:02d}{seasons[season + 1]}"
    return f"{(year + 1) % 100:02d}W"


@app.get("/api/v1/students/{sid}/recommendations")
def recommendations(sid: str, request: Request):
    require_owner(request, sid, allow_admin=True)
    if sid not in history and sid not in plans:
        raise HTTPException(404, "unknown student")
    rows = history.get(sid, [])
    done = {r["course"] for r in rows if r["status"] == "Completed"}
    todo = {c for c in catalog if c not in done}

    # DAG: edge prereq -> course, only among not-yet-completed catalog courses
    indeg = {c: 0 for c in todo}
    out: dict[str, list[str]] = {c: [] for c in todo}
    for c in todo:
        info = catalog[c]
        if info["any_of"] and any(q in done for q in info["prereqs"]):
            continue
        for q in dict.fromkeys(info["prereqs"]):
            if q in todo and q != c:
                out[q].append(c)
                indeg[c] += 1

    started = [term_key(r["term"]) for r in rows if term_key(r["term"]) != (0, 0)]
    term = "26F"
    if started and max(started) >= term_key("26F"):
        y, s_ = max(started)
        term = next_term(f"{y:02d}{'WSF'[s_]}")

    pathway = []
    ready = sorted(c for c, d in indeg.items() if d == 0)
    placed = 0
    while ready:
        pathway.append({"term": term, "courses": [catalog[c]["code"] for c in ready]})
        placed += len(ready)
        nxt = []
        for c in ready:
            for d in out[c]:
                indeg[d] -= 1
                if indeg[d] == 0:
                    nxt.append(d)
        ready = sorted(nxt)
        term = next_term(term)
    if placed < len(todo):  # prerequisite cycle in the catalog: list leftovers last
        pathway.append({"term": term, "courses": sorted(catalog[c]["code"] for c in todo if indeg[c] > 0)})
    return {"student_id": sid, "recommended_pathway": pathway}
