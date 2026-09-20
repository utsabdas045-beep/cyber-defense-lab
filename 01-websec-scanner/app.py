import json
import os
import secrets
from collections import OrderedDict
from pathlib import Path

from flask import Flask, Response, abort, redirect, render_template, request, url_for

from scanner import (ALL_CHECKS, SEVERITY_ORDER, ScopeError, Scanner,
                     is_local_target, normalize_target)

BASE = Path(__file__).parent
app = Flask(__name__)
CSS = (BASE / "static" / "style.css").read_text(encoding="utf-8")
ALLOW_EXTERNAL = os.environ.get("WEBSEC_ALLOW_EXTERNAL") == "1"

CHECK_INFO = [
    ("headers", "Security headers", "CSP, HSTS, framing, MIME sniffing, referrer, version leaks"),
    ("cookies", "Cookie flags", "HttpOnly, Secure, SameSite"),
    ("methods", "HTTP methods", "Reads the Allow header; checks TRACE"),
    ("directories", "Exposed paths", "Admin, backup, .env, .git, directory listings"),
    ("forms", "Form hygiene", "CSRF tokens, passwords over HTTP"),
    ("inputs", "Input handling", "Marker reflection and error leakage"),
]

RESULTS: "OrderedDict[str, dict]" = OrderedDict()  # in-memory, newest 20 scans
DEFAULT_FORM = {"target": "http://127.0.0.1:5001", "max_pages": 15, "delay": 200,
                "checks": ALL_CHECKS, "test_post": False}


def render_index(error=None, form=None):
    return render_template("index.html", css=CSS, error=error, form=form or DEFAULT_FORM,
                           checks=CHECK_INFO, allow_external=ALLOW_EXTERNAL)


@app.get("/")
def index():
    return render_index()


@app.post("/scan")
def scan():
    checks = [c for c in request.form.getlist("checks") if c in ALL_CHECKS]
    try:
        max_pages = max(1, min(int(request.form.get("max_pages", 15)), 50))
        delay_ms = max(0, min(int(request.form.get("delay", 200)), 5000))
    except ValueError:
        max_pages, delay_ms = 15, 200
    form = {"target": request.form.get("target", "").strip(), "max_pages": max_pages,
            "delay": delay_ms, "checks": checks, "test_post": bool(request.form.get("test_post"))}

    try:
        if not checks:
            raise ValueError("Select at least one check.")
        target = normalize_target(form["target"])
        if not is_local_target(target):
            if not ALLOW_EXTERNAL:
                raise ScopeError("This target is not a local or private address. The scanner only tests local "
                                 "test applications unless the app is started with WEBSEC_ALLOW_EXTERNAL=1.")
            if not request.form.get("authorized"):
                raise ScopeError("Confirm that you own this target or have written permission to test it.")
        result = Scanner(target, max_pages=max_pages, delay=delay_ms / 1000, checks=checks,
                         test_post=form["test_post"]).run()
    except (ScopeError, ValueError, ConnectionError) as exc:
        return render_index(error=str(exc), form=form), 400

    rid = secrets.token_urlsafe(8)
    RESULTS[rid] = result
    while len(RESULTS) > 20:
        RESULTS.popitem(last=False)
    return redirect(url_for("report", rid=rid))


def _get(rid):
    r = RESULTS.get(rid)
    if r is None:
        abort(404)
    return r


def _render_report(rid, standalone=False):
    r = _get(rid)
    return render_template("results.html", css=CSS, r=r, rid=rid, order=SEVERITY_ORDER,
                           total=len(r["findings"]), standalone=standalone)


@app.get("/report/<rid>")
def report(rid):
    return _render_report(rid)


@app.get("/report/<rid>/html")
def report_html(rid):
    html = _render_report(rid, standalone=True)
    return Response(html, mimetype="text/html",
                    headers={"Content-Disposition": f"attachment; filename=security-report-{rid}.html"})


@app.get("/report/<rid>/json")
def report_json(rid):
    return Response(json.dumps(_get(rid), indent=2), mimetype="application/json",
                    headers={"Content-Disposition": f"attachment; filename=security-report-{rid}.json"})


@app.errorhandler(404)
def not_found(_):
    return render_index(error="That report is no longer available (reports are kept in memory for this session)."), 404


@app.after_request
def secure_headers(resp):
    # The dashboard follows its own advice.
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com; script-src 'unsafe-inline'; frame-ancestors 'none'")
    return resp


if __name__ == "__main__":
    print("Scanner dashboard on http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False)
