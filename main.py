"""COSC-3506 Phase 3: degree-audit REST service (FastAPI, in-memory state)."""
import re

from bs4 import BeautifulSoup
from fastapi import FastAPI, File, HTTPException, UploadFile
from pydantic import BaseModel

app = FastAPI(title="Degree Audit API")

GRAD_TOTAL = 120
PAST = {"Completed", "In-Progress", "Attempted"}
CODE_RE = re.compile(r"[A-Za-z]{2,5}[\s\-]?\d{3,4}[A-Za-z]?")

# shortcut: in-memory state, lost on restart; fine because clients re-import before auditing
catalog: dict[str, dict] = {}
history: dict[str, list[dict]] = {}
plans: dict[str, list[dict]] = {}


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


@app.post("/api/v1/students/{sid}/history/import")
async def import_history(sid: str, file: UploadFile = File(...)):
    rows = parse_history(await read_html(file))
    history[sid] = rows
    return {"student_id": sid, "imported": len(rows)}


class PlannedCourse(BaseModel):
    course_code: str
    term: str


class Plan(BaseModel):
    planned_courses: list[PlannedCourse]


@app.post("/api/v1/students/{sid}/plan")
def set_plan(sid: str, plan: Plan):
    plans[sid] = [p.model_dump() for p in plan.planned_courses]
    return {"student_id": sid, "planned_courses": plans[sid]}


@app.get("/api/v1/students/{sid}/audit-report")
def audit_report(sid: str, strict: bool = False):
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
