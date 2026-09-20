import sys

from flask import Flask, make_response, request
from markupsafe import escape

HARDENED = "--hardened" in sys.argv
PORT = 5002 if HARDENED else 5001

app = Flask(__name__)

LAYOUT = """<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Demo Shop</title></head>
<body><h1>Demo Shop {tag}</h1>
<nav><a href="/">Home</a> | <a href="/search?q=laptop">Search</a> | <a href="/item?id=1">Item 1</a> | <a href="/login">Login</a></nav>
<hr>{body}</body></html>"""


def page(body, status=200):
    tag = "(hardened)" if HARDENED else "(intentionally weak)"
    return make_response(LAYOUT.format(tag=tag, body=body), status)


@app.route("/", methods=["GET"] if HARDENED else ["GET", "PUT", "DELETE"])
def home():
    resp = page("<p>Welcome. This app exists to be scanned.</p>")
    resp.set_cookie(
        "session_id", "demo-session-value",
        secure=HARDENED, httponly=HARDENED, samesite="Lax" if HARDENED else None,
    )
    return resp


@app.route("/search")
def search():
    q = request.args.get("q", "")
    shown = escape(q) if HARDENED else q          # weak version reflects raw input
    return page(f'<form action="/search" method="get"><input name="q" value="">'
                f'<button>Search</button></form><p>Results for: {shown}</p>')


@app.route("/item")
def item():
    item_id = request.args.get("id", "1")
    if "'" in item_id:
        if HARDENED:
            return page("<p>Invalid item id.</p>", 400)
        return ("sqlite3.OperationalError: unrecognized token: \"'\"\n"
                "  (simulated error for scanner practice)", 500, {"Content-Type": "text/plain"})
    return page(f"<p>Item {escape(item_id)}: Sample product</p>")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        return page("<p>Invalid credentials.</p>", 401)
    token = '<input type="hidden" name="csrf_token" value="demo-token">' if HARDENED else ""
    return page(f'<form action="/login" method="post">{token}'
                '<input name="username"><input name="password" type="password">'
                '<button>Log in</button></form>')


@app.route("/admin/")
def admin():
    if HARDENED:
        return page("Forbidden", 403)
    return page("<h2>Admin panel</h2><p>No login required (oops).</p>")


@app.route("/backup/")
def backup():
    if HARDENED:
        return page("Not found", 404)
    return ("<html><head><title>Index of /backup</title></head><body><h1>Index of /backup</h1>"
            "<ul><li>site-2024.zip</li><li>db-dump.sql</li></ul></body></html>")


@app.route("/.env")
def dotenv():
    if HARDENED:
        return page("Not found", 404)
    return "SECRET_KEY=not-a-real-secret\nDB_PASSWORD=not-a-real-password\n", 200, {"Content-Type": "text/plain"}


@app.route("/robots.txt")
def robots():
    return "User-agent: *\nDisallow: /admin/\nDisallow: /backup/\n", 200, {"Content-Type": "text/plain"}


@app.after_request
def harden(resp):
    if HARDENED:
        resp.headers["Content-Security-Policy"] = "default-src 'self'; object-src 'none'; frame-ancestors 'none'"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        resp.headers["Server"] = "demo"
    return resp


if __name__ == "__main__":
    print(f"Demo target ({'hardened' if HARDENED else 'weak'}) on http://127.0.0.1:{PORT}")
    app.run(host="127.0.0.1", port=PORT, debug=False)
