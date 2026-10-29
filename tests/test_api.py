from pathlib import Path

from fastapi.testclient import TestClient

from main import app

D = Path(__file__).parent / "data"
c = TestClient(app)


def test_audit_practice_scenario():
    c.post("/api/v1/admin/catalog/import", files={"file": ("c.html", (D / "catalog_hidden.html").read_bytes())})
    c.post("/api/v1/students/770001/history/import", files={"file": ("t.html", (D / "studentB_hidden.html").read_bytes())})
    c.post("/api/v1/students/770001/plan", json={"planned_courses": [
        {"course_code": "COSC-4426", "term": "26F"},
        {"course_code": "ITEC-3506", "term": "26F"},
        {"course_code": "COSC-2406", "term": "26F"}]})
    lax = c.get("/api/v1/students/770001/audit-report").json()
    assert lax["status"] == "warning"
    assert c.get("/api/v1/students/770001/audit-report?strict=true").json()["status"] == "failed"
    assert lax["credit_summary"] == {"total_earned": 9, "total_planned": 9, "total_remaining_for_graduation": 102}
    assert lax["cross_list_violations"][0]["course_code"] == "ITEC-3506"
    assert any(e["type"] == "MISSING_PREREQUISITE" for t in lax["timeline_validation"] for e in t["errors"])


def test_unknown_student_404():
    assert c.get("/api/v1/students/nobody/audit-report").status_code == 404
