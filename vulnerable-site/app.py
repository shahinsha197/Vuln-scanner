"""
Vulnerable Company Website - For educational/passive scanning demo purposes only.
Intentional vulnerabilities are planted here for learning.
"""
from flask import Flask, render_template, make_response, request, redirect

app = Flask(__name__)

# ----------------------------------------------------------------
# Intentional Vuln #6: Server version disclosed via custom header
# ----------------------------------------------------------------
@app.after_request
def add_vulnerable_headers(response):
    # Vuln #6: Disclose server info
    response.headers["Server"] = "Apache/2.2.14 (Win32)"
    # NOTE: We deliberately do NOT set:
    # - X-Frame-Options          (Vuln #1)
    # - Content-Security-Policy  (Vuln #2)
    # - X-Content-Type-Options   (Vuln #3)
    # - Strict-Transport-Security(Vuln #4)
    return response


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    response = make_response(render_template("login.html"))
    # Vuln #7: Cookie missing HttpOnly and Secure flags
    response.set_cookie(
        "session_id",
        "abc123xyz",
        httponly=False,   # <-- Vuln: should be True
        secure=False,     # <-- Vuln: should be True
        samesite=None
    )
    return response


@app.route("/robots.txt")
def robots():
    # Vuln #8: Sensitive paths exposed in robots.txt
    content = """User-agent: *
Disallow: /admin/
Disallow: /backup/
Disallow: /config/
Disallow: /db-backup/
Disallow: /internal/
"""
    response = make_response(content, 200)
    response.headers["Content-Type"] = "text/plain"
    return response


@app.route("/backup/")
def backup():
    # Vuln #9: Directory listing exposed (simulated)
    html = """<!DOCTYPE html>
<html>
<head><title>Index of /backup/</title></head>
<body>
<h1>Index of /backup/</h1>
<pre>
Name                    Last modified         Size
---------------------------------------------------
<a href="db_backup_2024.sql">db_backup_2024.sql</a>   2024-01-15 10:30     2.4M
<a href="users_export.csv">users_export.csv</a>     2024-01-14 09:15     512K
<a href="config.bak">config.bak</a>           2024-01-10 14:22     8.1K
</pre>
</body>
</html>"""
    return make_response(html, 200)


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5001)
