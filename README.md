# MuScanAI Admin Page

This folder contains a standalone admin website + API for mitigation recommendations by severity.

## Features
- MySQL database (`muscan_admin`)
- Sidebar admin UI at `/admin` for `Users`, `Mitigations`, and `Library`
- Mitigation draft versions are **not** auto-delivered to app clients
- Manual **Send Mitigation v{version}** release flow per severity
- Mitigation send history log
- Severity levels: `Functional`, `Mild`, `Moderate`, `Severe`

## Database Setup (MySQL)

### 1. Install MySQL
- Download and install [MySQL Community Server 8.0](https://dev.mysql.com/downloads/mysql/)
- Also recommended: [MySQL Workbench](https://dev.mysql.com/downloads/workbench/) for GUI management

### 2. Create Database and User
In MySQL Workbench or MySQL CLI, run:

```sql
CREATE DATABASE muscan_admin CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'muscan_app'@'localhost' IDENTIFIED BY 'StrongPasswordHere123!';
GRANT ALL PRIVILEGES ON muscan_admin.* TO 'muscan_app'@'localhost';
FLUSH PRIVILEGES;
```

### 3. Set Environment Variables (PowerShell)
```powershell
$env:DB_HOST="127.0.0.1"
$env:DB_PORT="3306"
$env:DB_NAME="muscan_admin"
$env:DB_USER="muscan_app"
$env:DB_PASSWORD="StrongPasswordHere123!"
```

Or add to your system environment variables permanently in Windows Settings.

## Run Locally

From `CAPSTONE/Admin Page`:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app:app --host 0.0.0.0 --port 8010 --reload
```

Open:
- `http://localhost:8010/admin` (Dashboard)
- `http://localhost:8010/api/mitigations` (API endpoint)

## Migrate from SQLite to MySQL (One-time)

If you previously used SQLite:

1. **Backup your SQLite database:**
   ```powershell
   Copy-Item mitigations.db mitigations.db.backup
   ```

2. **Run the migration script:**
   ```powershell
   .\.venv\Scripts\Activate.ps1
   python migrate_sqlite_to_mysql.py
   ```

3. **Verify the migration:**
   - Check MySQL Workbench or run in MySQL CLI:
     ```sql
     SELECT COUNT(*) FROM muscan_admin.users;
     SELECT COUNT(*) FROM muscan_admin.detections;
     ```
   - Start the API and test login/endpoints

4. **Keep the SQLite backup** until production is stable.

## Endpoints
- `GET /api/mitigations`
- `GET /api/mitigations/by-severity/{severity}`
- `GET /api/mitigations/{id}`
- `POST /api/mitigations`
- `PUT /api/mitigations/{id}`
- `DELETE /api/mitigations/{id}`
- `GET /api/mitigations/versions` (draft vs sent versions)
- `POST /api/mitigations/send/{severity}` (publish draft version to app)
- `GET /api/mitigations/send-history` (history of sent versions)
- `GET /api/mitigations/sync/{severity}` (app sync endpoint returns latest **sent** version)

## Connect from Phone/Device
1. Ensure phone + dev machine are on same Wi-Fi.
2. Find PC LAN IP (example: `192.168.1.50`).
3. Set MySQL DATABASE to localhost if phone is on same LAN as PC.
4. Use base URL in mobile app:
   - `http://192.168.1.50:8010`
5. App sync should use the controlled sync endpoint:

```ts
const baseUrl = 'http://192.168.1.50:8010';
const severity = 'Mild';
const res = await fetch(`${baseUrl}/api/mitigations/sync/${severity}`);
const payload = await res.json();
// payload.version is the latest sent version
// payload.items contains mitigations for that severity
```

## Notes
- If phone cannot access API, allow inbound port `8010` in Windows Firewall.
- The API currently allows all CORS origins for easier dev usage.
- MySQL credentials should be set via environment variables for security.

## Production Deployment (GitHub Pages + Hosted API)

GitHub Pages can host the Admin dashboard UI, but it cannot run the Python/FastAPI server.

Use this architecture:
- Frontend: GitHub Pages (serves `static/index.html`)
- Backend API: Render/Railway/Fly.io/VM (runs `app.py` + MySQL)

### 1) Deploy the backend API first
1. Push this repo to GitHub.
2. Deploy `app.py` as an ASGI app on your backend host.
3. Start command example:
   ```bash
   uvicorn app:app --host 0.0.0.0 --port 10000
   ```
4. Configure environment variables on the host (`DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_PASSWORD`, SMS keys if needed).
5. Confirm public API URL works (example: `https://your-admin-api.onrender.com/api/mitigations`).

### 2) Deploy the static Admin dashboard to GitHub Pages
This repo includes workflow: `.github/workflows/admin-page-pages.yml`

1. In GitHub repo Settings -> Pages:
   - Source: `GitHub Actions`
2. Push to `main`.
3. The workflow publishes `static`.
4. Your site URL will be like:
   - `https://<username>.github.io/<repo>/`

### 3) Connect dashboard to hosted backend API
The dashboard now supports dynamic API base URL.

Set backend URL by opening your Pages URL with `?api=`:

```text
https://<username>.github.io/<repo>/?api=https://your-admin-api.onrender.com
```

This value is saved in browser localStorage and reused on next visits.

If needed, change API URL by re-opening with a different `?api=` value.

### 4) CORS/security notes
- Current API uses `allow_origins=["*"]` for easy setup.
- For production hardening, restrict `allow_origins` to your GitHub Pages domain.

### 5) Render quick-start for app.py
This repo also includes `render.yaml` for one-click backend setup on Render.

1. In Render, click **New +** -> **Blueprint**.
2. Connect this GitHub repo.
3. Render detects `render.yaml` automatically.
4. Fill required env vars (`DB_HOST`, `DB_NAME`, `DB_USER`, `DB_PASSWORD`, etc.).
5. Deploy and copy the API URL.
6. Open your GitHub Pages admin URL with `?api=<your-api-url>`.

