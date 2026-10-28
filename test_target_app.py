"""
SentinelX Authorized Vulnerable Test Application
A safe, intentionally vulnerable local target application used exclusively
for verifying scanner engines, alert parsers, evidence extraction, and report generation.
"""
from flask import Flask, request, Response, jsonify

test_app = Flask("SentinelX_Test_Target")

@test_app.route("/")
def index():
    # Intentionally missing HSTS, CSP, X-Frame-Options, X-Content-Type-Options
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Authorized Vulnerable Test Target - SentinelX QA</title>
    </head>
    <body>
        <h1>SentinelX Test Target (Authorized Safe Fixture)</h1>
        <p>This is a synthetic test application containing controlled security flaws.</p>
        <nav>
            <a href="/about">About Us</a> |
            <a href="/dashboard">User Dashboard</a> |
            <a href="/api/data">Internal API</a> |
            <a href="/login">Login Portal</a>
        </nav>
        <script src="/static/test_bundle.js"></script>
    </body>
    </html>
    """
    resp = Response(html, mimetype="text/html")
    # Intentionally leak server banners
    resp.headers["Server"] = "Apache/2.4.52 (Ubuntu) OpenSSL/3.0.2"
    resp.headers["X-Powered-By"] = "PHP/8.1.2-1ubuntu2.14"
    # Set insecure test cookie
    resp.set_cookie("auth_session", "synthetic_test_cookie_998811", secure=False, httponly=False, samesite=None)
    return resp

@test_app.route("/about")
def about():
    return "<h1>About Page</h1><p>Accessible internal page for crawler testing.</p>"

@test_app.route("/dashboard")
def dashboard():
    # Intentionally exposes synthetic AWS dummy test token in HTML
    html = """
    <div>
        <h2>Dashboard Analytics</h2>
        <!-- AWS Cloud Config: AKIAIOSFODNN7EXAMPLE -->
        <script>
            const cloudConfig = {
                apiKey: "AKIAIOSFODNN7EXAMPLE",
                region: "us-east-1"
            };
        </script>
    </div>
    """
    return Response(html, mimetype="text/html")

@test_app.route("/static/test_bundle.js")
def test_bundle():
    # Intentionally exposes synthetic Google Cloud API key pattern in JS
    js_code = """
    console.log("Loading analytics...");
    const MAPS_KEY = "AIzaSyD-TEST_KEY_FOR_QA_AUDITOR_12345";
    """
    return Response(js_code, mimetype="application/javascript")

@test_app.route("/api/data", methods=["GET", "OPTIONS"])
def api_data():
    origin = request.headers.get("Origin", "*")
    resp = jsonify({"status": "success", "data": [1, 2, 3]})
    # Intentionally permissive CORS reflecting Origin with Allow-Credentials
    resp.headers["Access-Control-Allow-Origin"] = origin
    resp.headers["Access-Control-Allow-Credentials"] = "true"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS, TRACE"
    return resp

@test_app.route("/login")
def login():
    return "<form><input name='username'/><input type='password' name='password'/></form>"

@test_app.route("/.env")
def env_file():
    # Intentionally exposed synthetic test environment file
    return Response(
        "DB_HOST=127.0.0.1\nDB_USER=test_admin\nDB_PASSWORD=synthetic_test_pwd_xyz99\nSECRET_KEY=super_secret_test_key\n",
        mimetype="text/plain"
    )

@test_app.route("/robots.txt")
def robots():
    return Response("User-agent: *\nDisallow: /admin\nDisallow: /private\n", mimetype="text/plain")

if __name__ == "__main__":
    print("Starting SentinelX Authorized Vulnerable Test Application on http://127.0.0.1:5050 ...")
    test_app.run(host="127.0.0.1", port=5050, debug=False)
