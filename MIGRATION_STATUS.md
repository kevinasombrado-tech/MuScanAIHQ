# MySQL Migration - Completion Steps

## What's Done ✅

1. **Updated imports** - pymysql instead of sqlite3
2. **Database connection** - get_db() now uses MySQL with environment variable config
3. **Table creation** - all CREATE TABLE statements updated to MySQL syntax (BIGINT AUTO_INCREMENT PRIMARY KEY, etc.)
4. **Critical utility functions** - updated:
   - bump_version()
   - create_session()  
   - session_user()
   - get_severity_version(), get_sent_version()
   - snapshot functions
   - log_activity()
5. **Migration script** ready - `migrate_sqlite_to_mysql.py`
6. **README.md** updated with MySQL setup instructions
7. **API imports work** - app.py successfully imports

## What Still Needs Fixing ⚠️

The remaining endpoints still have old SQLite syntax that needs conversion:

### Pattern to fix in all remaining functions:
1. `?` placeholders → `%s` in all SQL strings
2. `sqlite3.IntegrityError` → `pymysql.err.IntegrityError`
3. `conn.execute(...)` → `conn.cursor().execute(...)`
4. `datetime('now', ...)` → `DATE_ADD(NOW(), ...)`
5. `datetime(column) > datetime('now')` → `column > NOW()`

### Endpoints that need fixing:
- `/api/mitigations/{item_id}` (GET, POST, PUT, DELETE)
- `/api/users/*` (all user endpoints)
- `/api/auth/*` (signup, login, OTP)
- `/api/detections/*`
- `/api/remarks/*`
- `/api/library/*`

## Quick Fix Option

Run this Python script to auto-fix all remaining % placeholders:

```python
import re
from pathlib import Path

app_file = Path("Admin Page/app.py")
content = app_file.read_text()

# Fix ? placeholders
lines = content.split('\n')
for i, line in enumerate(lines):
    if ' VALUES (' in line and '?' in line:
        lines[i] = line.replace('?', '%s')
    if 'WHERE ' in line and '?' in line:
        lines[i] = line.replace('?', '%s')

content = '\n'.join(lines)

# Fix IntegrityError
content = content.replace('sqlite3.IntegrityError', 'pymysql.err.IntegrityError')

# Fix datetime functions (careful - only in SQL strings)
content = content.replace('datetime(\'now\'', 'NOW()')

app_file.write_text(content)
print("Fixed!")
```

OR manually search-and-replace in VS Code:
- Find: `?` (in SQL context) → Replace: `%s`
- Find: `sqlite3.IntegrityError` → Replace: `pymysql.err.IntegrityError`
- Find: `datetime(\` → Replace: `NOW()`

## Test the Migration

Once all endpoints are fixed:

```powershell
# 1. Run migration
python migrate_sqlite_to_mysql.py

# 2. Start the API
uvicorn app:app --host 0.0.0.0 --port 8010 --reload

# 3. Test endpoints
curl http://localhost:8010/api/mitigations

# 4. Test login
curl -X POST http://localhost:8010/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"contact_number":"09000000001","password":"superadmin123"}'
```

## Recommended Next Steps

1. **Option A (Easiest):** Let Claude/Copilot finish the remaining replacements
2. **Option B (Manual):** Use Find-Replace in VS Code for the patterns above
3. **Option C (Test as-is):** Try starting the app now - it may work for many endpoints

## Files Created
- `migrate_sqlite_to_mysql.py` - Data migration script
- `fix_sqlite_to_mysql.py` - (Optional) Auto-fix script
- `README.md` - Updated with MySQL setup

## Environment Variables Required

Before running:
```powershell
$env:DB_HOST="127.0.0.1"
$env:DB_PORT="3306"
$env:DB_NAME="muscan_admin"
$env:DB_USER="muscan_app"
$env:DB_PASSWORD="YourPassword123!"
```
