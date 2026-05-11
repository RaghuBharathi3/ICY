# Quicklink QR – Lab Workflow

## 1. Overview
This document captures a **step‑by‑step pseudo‑code** that can be used as a reference implementation for the Quicklink QR system during a lab session. It details every major component, error handling, logging, and security checks.  A short **architecture diagram** (Mermaid) follows the code.

---

## 2. Expanded Pseudo‑code
```text
# ------------------------------------------------------------
# QUICKLINK QR – LAB WORKFLOW (Extended Version)
# ------------------------------------------------------------
# Assumptions:
#   • Front‑end is a Next.js (React) application.
#   • Back‑end is a Node/Express API.
#   • PostgreSQL is used for persistent storage.
#   • Redis (optional) stores short‑lived JWT/session tokens.
#   • QR payload contains a URL to a protected page and a one‑time token.
#   • All secrets (DB passwords, JWT secret) are loaded from environment vars.
# ------------------------------------------------------------

# ---------- 0️⃣ INITIALISATION ----------
# Load environment configuration
CONFIG = load_env({
    "PORT": 3000,
    "API_PORT": 4000,
    "DB_URL": "postgres://user:pass@localhost/quicklink",
    "REDIS_URL": "redis://localhost:6379",
    "JWT_SECRET": "super‑secret-key",
    "QR_TOKEN_TTL": 300   # seconds, one‑time use
})

# Initialise logger (structured JSON for easy parsing)
LOGGER = create_logger(level="INFO", output="stdout")

# Initialise database connection pool
DB = postgres_pool(CONNECTION_STRING=CONFIG.DB_URL)

# Initialise optional Redis cache for session tokens
if CONFIG.REDIS_URL:
    CACHE = redis_client(url=CONFIG.REDIS_URL)
else:
    CACHE = None

# ------------------------------------------------------------
# ---------- 1️⃣ QR CODE GENERATION (offline step) ----------
# This step is usually performed by a CI job or an admin UI.
function generate_qr(target_path: string, user_id: string) -> binary_image:
    # Build a one‑time token bound to the user and an expiry timestamp
    token_payload = {
        "user_id": user_id,
        "iat": now_unix(),
        "exp": now_unix() + CONFIG.QR_TOKEN_TTL,
        "nonce": random_uuid()
    }
    signed_token = sign_jwt(token_payload, secret=CONFIG.JWT_SECRET)

    # Encode the full URL that the front‑end will consume
    full_url = f"https://{HOSTNAME}:{CONFIG.PORT}{target_path}?qr_token={signed_token}"

    # Use a QR library to create an image (PNG)
    qr_image = qrcode_create(data=full_url, version=2, error_correction='M')
    return qr_image

# ------------------------------------------------------------
# ---------- 2️⃣ FRONT‑END ENTRY POINT ----------
# In Next.js, a page (e.g. pages/quicklink.js) reads the QR payload
function on_page_load(request):
    # Extract query parameters
    qr_token = request.query.get("qr_token")
    target_path = request.path   # e.g. "/quicklink"

    if not qr_token:
        LOGGER.warn("Missing QR token", {"path": target_path})
        redirect_to_home()
        return

    # Store the token in a temporary client‑side store (memory or localStorage)
    client_state.qr_token = qr_token

    # Render the login form UI
    render_login_form()

# ---------- 2b️⃣ USER SUBMITS CREDENTIALS ----------
async function submit_credentials(username, password):
    # Pull the QR token that was stored on page load
    qr_token = client_state.qr_token

    # Prepare request payload for the verification API
    payload = {
        "username": username,
        "password": password,
        "qr_token": qr_token   # may be optional depending on policy
    }

    try:
        response = await fetch("/api/verify-password", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify(payload)
        })
    except NetworkError as e:
        LOGGER.error("Network failure while calling verify‑password", {"error": e})
        show_toast("Network error – please try again later")
        return

    if response.status == 200:
        data = await response.json()
        # Store JWT securely (httpOnly cookie or in‑memory store)
        set_auth_token(data.session_token)
        # Navigate to protected dashboard
        router.push("/dashboard")
    else:
        err = await response.json()
        LOGGER.info("Auth failure", {"username": username, "code": response.status})
        show_error(err.error || "Authentication failed")

# ------------------------------------------------------------
# ---------- 3️⃣ BACK‑END: PASSWORD VERIFICATION ENDPOINT ----------
# Express style route handler (Node.js)
POST "/api/verify-password" (req, res) => {
    LOG = LOGGER.child({"endpoint": "verify-password"})
    start = now()

    # 3a) Validate request shape
    if !(req.body?.username && req.body?.password):
        LOG.warn("Missing fields", {"body": req.body})
        return res.status(400).json({"error": "username and password required"})

    username = req.body.username
    password = req.body.password
    qr_token = req.body.qr_token   # optional

    # 3b) Retrieve user record (use a parameterised query to avoid SQLi)
    user = DB.query_one(
        "SELECT id, password_hash, is_active FROM users WHERE username = $1", [username]
    )
    if !user:
        LOG.info("User not found", {"username": username})
        return res.status(401).json({"error": "Invalid credentials"})

    if !user.is_active:
        LOG.warn("Inactive account attempted login", {"user_id": user.id})
        return res.status(403).json({"error": "Account disabled"})

    # 3c) Verify password using bcrypt (or argon2)
    if !bcrypt.compare(password, user.password_hash):
        LOG.info("Password mismatch", {"user_id": user.id})
        return res.status(401).json({"error": "Invalid credentials"})

    # 3d) OPTIONAL: Validate the QR one‑time token
    if qr_token:
        try:
            token_payload = verify_jwt(qr_token, secret=CONFIG.JWT_SECRET)
        except JwtError as e:
            LOG.warn("Invalid QR token", {"error": e, "user_id": user.id})
            return res.status(403).json({"error": "Invalid QR token"})

        # Ensure token belongs to the same user and is not expired
        if token_payload.user_id != user.id:
            LOG.warn("QR token user mismatch", {"token_user": token_payload.user_id, "real_user": user.id})
            return res.status(403).json({"error": "QR token does not match user"})

        # Optional: consume token (store nonce in Redis to prevent replay)
        if CACHE:
            used = CACHE.get(token_payload.nonce)
            if used:
                LOG.warn("Replay attack detected for QR nonce", {"nonce": token_payload.nonce})
                return res.status(403).json({"error": "QR token already used"})
            CACHE.set(token_payload.nonce, "used", ex=CONFIG.QR_TOKEN_TTL)

    # 3e) Issue a JWT session token for the front‑end
    session_payload = {
        "sub": user.id,
        "iat": now_unix(),
        "exp": now_unix() + 3600,   # 1 hour session
        "role": "standard"
    }
    session_jwt = sign_jwt(session_payload, secret=CONFIG.JWT_SECRET)

    # 3f) Respond with the token
    LOG.info("Authentication success", {"user_id": user.id, "duration_ms": now() - start})
    return res.status(200).json({"session_token": session_jwt})
}

# ------------------------------------------------------------
# ---------- 4️⃣ FRONT‑END: DASHBOARD PAGE ----------
# After successful login the router redirects to /dashboard
function load_dashboard():
    # Extract stored JWT (could be an httpOnly cookie)
    token = get_auth_token()
    if !token:
        redirect_to_login()
        return

    # Make an authenticated request for user‑specific data
    fetch("/api/dashboard-data", {
        method: "GET",
        headers: {"Authorization": `Bearer ${token}`}
    })
    .then(handle_dashboard_response)
    .catch(err => {
        LOGGER.error("Dashboard fetch failed", {err})
        show_toast("Unable to load dashboard – please refresh")
    })

async function handle_dashboard_response(resp):
    if resp.status == 200:
        data = await resp.json()
        render_dashboard(data)
    else if resp.status == 401:
        // Token may have expired
        show_toast("Session expired – please log in again")
        redirect_to_login()
    else:
        show_error("Unexpected error loading dashboard")

# ------------------------------------------------------------
# ---------- 5️⃣ BACK‑END: DASHBOARD DATA ENDPOINT ----------
GET "/api/dashboard-data" (req, res) => {
    LOG = LOGGER.child({"endpoint": "dashboard-data"})
    auth_header = req.headers["authorization"]
    if !auth_header?.startsWith("Bearer "):
        LOG.warn("Missing Authorization header")
        return res.status(401).json({"error": "Missing token"})

    token = auth_header.split(" ")[1]
    try:
        payload = verify_jwt(token, secret=CONFIG.JWT_SECRET)
    except JwtError:
        LOG.warn("Invalid session JWT")
        return res.status(401).json({"error": "Invalid token"})

    user_id = payload.sub
    # Fetch user‑specific data (could be dashboards, settings, etc.)
    user_data = DB.query("SELECT * FROM user_data WHERE user_id = $1", [user_id])
    LOG.info("Dashboard data served", {"user_id": user_id})
    return res.status(200).json(user_data)
}

# ------------------------------------------------------------
# ---------- 6️⃣ CLEAN‑UP & SECURITY NOTES ----------
# • All secret keys are loaded from environment variables – never hard‑code.
# • Use rate‑limiting / IP‑based throttling on the /verify‑password endpoint.
# • Store password hashes with bcrypt (cost >= 12) or argon2.
# • QR tokens are short‑lived and stored as a nonce in Redis to prevent replay.
# • Log every authentication attempt with timestamp, IP, and outcome (no passwords!).
# • Enable HTTPS everywhere; the demo may run locally with self‑signed certs.
# ------------------------------------------------------------
```

---

## 3. Architecture Diagram (Mermaid)
```mermaid
flowchart TD
    %% Actors
    User[User] -->|Scans QR| QR["QR Code (URL + token)"]

    %% Front‑end
    subgraph FE["Next.js Front-end"]
        FE_App["App (React UI)"]
        FE_Router[Router / Pages]
    end
    QR --> FE_App
    FE_App -->|Loads| FE_Router

    %% API Layer
    subgraph BE["API Layer (Node/Express)"]
        Verify["POST /api/verify-password"]
        Dashboard["GET /api/dashboard-data"]
    end
    FE_Router -->|POST credentials| Verify
    Verify -->|Success JWT| FE_Router
    FE_Router -->|GET data| Dashboard

    %% Persistence
    subgraph DB["Database (PostgreSQL)"]
        Users[users table]
        Data[user_data table]
    end
    Verify -->|SELECT/UPDATE| Users
    Dashboard -->|SELECT| Data

    %% Session Store (optional)
    subgraph Sess["Session Store (Redis)"]
        JWT["JWT / Session Token"]
    end
    Verify -->|store token| JWT
    Dashboard -->|validate token| JWT

    %% External
    QRGen[QR Generator Service] -->|creates| QR

    classDef user fill:#f9f,stroke:#333,stroke-width:2px;
    classDef frontend fill:#bbf,stroke:#333,stroke-width:2px;
    classDef backend fill:#bfb,stroke:#333,stroke-width:2px;
    classDef db fill:#ffb,stroke:#333,stroke-width:2px;
    classDef session fill:#fcc,stroke:#333,stroke-width:2px;
    class User user;
    class FE frontend;
    class BE backend;
    class Users,Data db;
    class JWT session;
```

---

### How to Use This File
1. **Save** the file as `quicklink_architecture.md` in your project root (e.g., `c:/Users/Windows/Documents/ICY`).
2. Open it in any Markdown viewer that supports **Mermaid** to see the rendered diagram.
3. Follow the pseudo‑code comments when implementing the real code – each block maps directly to a concrete function or route.

---

*Prepared for the Quicklink QR lab – feel free to extend or trim sections to match your exact lab scope.*
