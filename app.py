from __future__ import annotations

import hashlib
import html
import hmac
import json
import os
import re
import secrets
import sys
import time
import traceback
import ssl
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Literal

import pymysql
from pymysql.cursors import DictCursor
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Query, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr, Field
import shutil

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
UPLOADS_DIR = BASE_DIR / "uploads"
load_dotenv(BASE_DIR / ".env")

# Ensure uploads directory exists
UPLOADS_DIR.mkdir(parents=True, exist_ok=True)


def _env(*keys: str, default: str = "") -> str:
    for key in keys:
        value = os.getenv(key)
        if value is not None and value != "":
            return value
    return default

# MySQL Configuration from environment variables
DB_HOST = _env("DB_HOST", "MYSQL_HOST", default="127.0.0.1")
DB_PORT = int(_env("DB_PORT", "MYSQL_PORT", default="3306"))
DB_NAME = _env("DB_NAME", "MYSQL_DATABASE", default="muscan_admin")
DB_USER = _env("DB_USER", "MYSQL_USER", default="muscan_app")
DB_PASSWORD = _env("DB_PASSWORD", "MYSQL_PASSWORD", default="")
DB_SSL = _env("DB_SSL", "MYSQL_SSL", default="false").strip().lower() in {"1", "true", "yes", "on"}
MODEL_OVERVIEW_PULL_URL = _env("MODEL_OVERVIEW_PULL_URL", default="").strip()
MODEL_OVERVIEW_PULL_TOKEN = _env("MODEL_OVERVIEW_PULL_TOKEN", default="").strip()
MODEL_OVERVIEW_REFRESH_INTERVAL_SECONDS = int(
    _env("MODEL_OVERVIEW_REFRESH_INTERVAL_SECONDS", default="3600")
)


def _is_render_runtime() -> bool:
    return bool(os.getenv("RENDER") or os.getenv("RENDER_SERVICE_ID"))

SEVERITIES = {"Functional", "Mild", "Moderate", "Severe"}
SEVERITY_NORMALIZED = {s.casefold(): s for s in SEVERITIES}

ROLES = {"Farmer", "Researcher", "Admin", "Superadmin"}
ROLE_NORMALIZED = {r.casefold(): r for r in ROLES}
PHONE_REGEX = re.compile(r"^[0-9]{10,15}$")
PASSWORD_MIN_LENGTH = 8
OTP_TTL_SECONDS = 300
SESSION_TTL_SECONDS = 60 * 60 * 24 * 30
SMS_PROVIDER = os.getenv("SMS_PROVIDER", "smsapi").strip().lower()
SMSAPI_KEY = os.getenv("SMSAPI_KEY", "").strip()
TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID", "").strip()
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN", "").strip()
TWILIO_FROM_NUMBER = os.getenv("TWILIO_FROM_NUMBER", "").strip()
SEMAPHORE_API_KEY = os.getenv("SEMAPHORE_API_KEY", "").strip()
SEMAPHORE_SENDER_NAME = os.getenv("SEMAPHORE_SENDER_NAME", "").strip()


class MitigationCreate(BaseModel):
    severity: Literal["Functional", "Mild", "Moderate", "Severe"]
    slot_no: int = Field(default=1, ge=1, le=1)
    title: str = Field(min_length=3, max_length=200)
    instruction: str | None = Field(default=None, min_length=1)
    description: str | None = Field(default=None, min_length=1)


class MitigationUpdate(BaseModel):
    title: str = Field(min_length=3, max_length=200)
    instruction: str | None = Field(default=None, min_length=1)
    description: str | None = Field(default=None, min_length=1)


class MitigationSendRequest(BaseModel):
    actor_role: Literal["Farmer", "Researcher", "Admin", "Superadmin"] = "Admin"
    actor_name: str = Field(default="Dashboard Admin", min_length=2, max_length=100)


class LibrarySendRequest(BaseModel):
    actor_role: Literal["Farmer", "Researcher", "Admin", "Superadmin"] = "Admin"
    actor_name: str = Field(default="Dashboard Admin", min_length=2, max_length=100)


class UserCreate(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    contact_number: str = Field(min_length=10, max_length=15)
    email: EmailStr | None = None
    password: str | None = Field(default=None, min_length=PASSWORD_MIN_LENGTH, max_length=128)
    profile_image: str | None = Field(default=None, max_length=4000)
    role: Literal["Farmer", "Researcher", "Admin", "Superadmin"]
    source: Literal["signup", "manual"] = "manual"


class UserUpdate(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    contact_number: str = Field(min_length=10, max_length=15)
    email: EmailStr | None = None
    password: str | None = Field(default=None, min_length=PASSWORD_MIN_LENGTH, max_length=128)
    profile_image: str | None = Field(default=None, max_length=4000)
    role: Literal["Farmer", "Researcher", "Admin", "Superadmin"]


class SignupCreate(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    contact_number: str = Field(min_length=10, max_length=15)
    email: EmailStr | None = None
    password: str = Field(min_length=PASSWORD_MIN_LENGTH, max_length=128)
    role: Literal["Farmer", "Researcher", "Admin", "Superadmin"] = "Farmer"


class ManualUserCreate(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    contact_number: str = Field(min_length=10, max_length=15)
    email: EmailStr | None = None
    password: str | None = Field(default=None, min_length=PASSWORD_MIN_LENGTH, max_length=128)
    role: Literal["Farmer", "Researcher", "Admin", "Superadmin"]
    actor_role: Literal["Farmer", "Researcher", "Admin", "Superadmin"] = "Superadmin"


class SignupOtpRequest(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    contact_number: str = Field(min_length=10, max_length=15)
    email: EmailStr | None = None
    password: str = Field(min_length=PASSWORD_MIN_LENGTH, max_length=128)
    role: Literal["Farmer", "Researcher", "Admin", "Superadmin"] = "Farmer"


class SignupOtpVerify(BaseModel):
    contact_number: str = Field(min_length=10, max_length=15)
    otp: str = Field(min_length=4, max_length=8)


class SignupMobileOtpRequest(BaseModel):
    contact_number: str = Field(min_length=10, max_length=20)


class SignupMobileOtpVerify(BaseModel):
    contact_number: str = Field(min_length=10, max_length=20)
    otp: str = Field(min_length=4, max_length=8)


class SignupCompleteRequest(BaseModel):
    otp_token: str = Field(min_length=20, max_length=255)
    name: str = Field(min_length=2, max_length=100)
    password: str = Field(min_length=PASSWORD_MIN_LENGTH, max_length=128)
    email: EmailStr | None = None
    role: Literal["Farmer", "Researcher", "Admin", "Superadmin"] = "Farmer"


class LoginRequest(BaseModel):
    contact_number: str = Field(min_length=10, max_length=15)
    password: str = Field(min_length=PASSWORD_MIN_LENGTH, max_length=128)


class SessionRequest(BaseModel):
    token: str = Field(min_length=20, max_length=255)


class LibraryCreate(BaseModel):
    title: str = Field(min_length=3, max_length=200)
    body: str = Field(min_length=5)
    image: str = Field(min_length=5, max_length=2000)
    actor_role: Literal["Farmer", "Researcher", "Admin", "Superadmin"] = "Superadmin"


class LibraryUpdate(BaseModel):
    title: str = Field(min_length=3, max_length=200)
    body: str = Field(min_length=5)
    image: str = Field(min_length=5, max_length=2000)
    actor_role: Literal["Farmer", "Researcher", "Admin", "Superadmin"] = "Superadmin"


class FarmCreate(BaseModel):
    farm_name: str = Field(min_length=2, max_length=200)
    farm_address: str = Field(min_length=5, max_length=500)
    farmer_user_id: int = Field(gt=0)
    geotag_id: str = Field(min_length=1, max_length=120)
    actor_role: Literal["Farmer", "Researcher", "Admin", "Superadmin"] = "Superadmin"


class FarmUpdate(BaseModel):
    farm_name: str = Field(min_length=2, max_length=200)
    farm_address: str = Field(min_length=5, max_length=500)
    farmer_user_id: int = Field(gt=0)
    geotag_id: str = Field(min_length=1, max_length=120)
    actor_role: Literal["Farmer", "Researcher", "Admin", "Superadmin"] = "Superadmin"

class DetectionCreate(BaseModel):
    user_id: int
    image_path: str
    predicted_label: str
    severity: Literal["Functional", "Mild", "Moderate", "Severe"]
    confidence: float | None = None

class RemarkCreate(BaseModel):
    detection_id: int
    user_id: int
    remark: str = Field(min_length=1)


class UploadedMitigation(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(min_length=1)


class UploadedScanContentItem(BaseModel):
    history_id: str = Field(min_length=1, max_length=255)
    user_id: int | None = None
    farm_id: int | None = None
    image_uri: str = Field(min_length=1, max_length=4000)
    severity: str = Field(min_length=1, max_length=50)
    mitigations: list[UploadedMitigation] = []
    remark: str = Field(min_length=1)
    scanned_at: str | None = None


class UploadedScanContentBatch(BaseModel):
    uploads: list[UploadedScanContentItem] = Field(min_length=1)


class ModelOverviewPayload(BaseModel):
    user_id: int = Field(gt=0)
    overall_accuracy: float = Field(ge=0, le=100)
    total_scans: int = Field(ge=0)
    average_confidence: float | None = Field(default=None, ge=0, le=100)
    last7_accuracy: float | None = Field(default=None, ge=0, le=100)
    last30_accuracy: float | None = Field(default=None, ge=0, le=100)
    trend: list[dict] = Field(default_factory=list)
    severity_distribution: dict[str, int] = Field(default_factory=dict)
    confidence_distribution: dict[str, int] = Field(default_factory=dict)
    top_issues: list[dict] = Field(default_factory=list)
    source_updated_at: str | None = None


class ModelOverviewReport(BaseModel):
    items: list[ModelOverviewPayload] = Field(min_length=1)
    source: str = Field(default="app", min_length=1, max_length=40)


app = FastAPI(title="MuScanAI Admin API", version="2.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

# Mount uploads directory for static file serving
app.mount("/api/uploads", StaticFiles(directory=str(UPLOADS_DIR)), name="uploads")


def get_db():
    """Get MySQL database connection with dict cursor for easy row access."""
    try:
        connection_kwargs = dict(
            host=DB_HOST,
            port=DB_PORT,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME,
            cursorclass=DictCursor,
            charset="utf8mb4",
            autocommit=False,
            connect_timeout=5,
            read_timeout=5,
            write_timeout=5,
        )
        if DB_SSL:
            connection_kwargs["ssl"] = ssl.create_default_context()

        conn = pymysql.connect(
            **connection_kwargs
        )
        return conn
    except pymysql.err.OperationalError as exc:
        # Provide an actionable startup error when credentials are missing or invalid.
        if exc.args and exc.args[0] == 1045:
            msg = str(exc)
            if "using password: NO" in msg:
                raise RuntimeError(
                    "MySQL authentication failed: no password was provided. "
                    "Set DB_PASSWORD (or MYSQL_PASSWORD) before starting the API."
                ) from exc
            raise RuntimeError(
                "MySQL authentication failed: check DB_USER/DB_PASSWORD (or MYSQL_USER/MYSQL_PASSWORD)."
            ) from exc
        if exc.args and exc.args[0] in {2002, 2003}:
            raise RuntimeError(
                f"MySQL connection failed for host {DB_HOST}:{DB_PORT}. "
                "Use a reachable cloud MySQL host in Render environment variables; "
                "localhost/127.0.0.1 only works on the same machine as MySQL."
            ) from exc
        raise


def init_db() -> None:
    conn = get_db()
    cur = conn.cursor()

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS mitigations (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            severity VARCHAR(50) NOT NULL,
            slot_no TINYINT,
            title VARCHAR(200) NOT NULL,
            description TEXT NOT NULL,
            created_at DATETIME NOT NULL DEFAULT NOW(),
            updated_at DATETIME
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS mitigation_versions (
            severity VARCHAR(50) PRIMARY KEY,
            version INT NOT NULL DEFAULT 1,
            updated_at DATETIME NOT NULL DEFAULT NOW()
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS mitigation_sent_versions (
            severity VARCHAR(50) PRIMARY KEY,
            sent_version INT NOT NULL DEFAULT 1,
            sent_at DATETIME,
            sent_by VARCHAR(255)
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS mitigation_send_logs (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            severity VARCHAR(50) NOT NULL,
            sent_version INT NOT NULL,
            sent_by VARCHAR(255) NOT NULL,
            sent_at DATETIME NOT NULL DEFAULT NOW()
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS mitigation_sent_items (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            severity VARCHAR(50) NOT NULL,
            sent_version INT NOT NULL,
            slot_no TINYINT,
            source_mitigation_id BIGINT,
            title VARCHAR(200) NOT NULL,
            description TEXT NOT NULL,
            sent_at DATETIME NOT NULL DEFAULT NOW()
        )
        """
    )
    try:
        cur.execute("ALTER TABLE mitigations ADD COLUMN slot_no TINYINT NULL")
    except pymysql.err.OperationalError as exc:
        if exc.args and int(exc.args[0]) != 1060:
            raise
    try:
        cur.execute("ALTER TABLE mitigation_sent_items ADD COLUMN slot_no TINYINT NULL")
    except pymysql.err.OperationalError as exc:
        if exc.args and int(exc.args[0]) != 1060:
            raise
    try:
        cur.execute("ALTER TABLE user_uploaded_content ADD COLUMN farm_id BIGINT NULL")
    except pymysql.err.OperationalError as exc:
        if exc.args and int(exc.args[0]) != 1060:
            raise
    try:
        cur.execute("ALTER TABLE detections ADD COLUMN farm_id BIGINT NULL")
    except pymysql.err.OperationalError as exc:
        if exc.args and int(exc.args[0]) != 1060:
            raise
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            contact_number VARCHAR(20) NOT NULL UNIQUE,
            email VARCHAR(255) UNIQUE,
            password_hash VARCHAR(500),
            profile_image VARCHAR(4000),
            role VARCHAR(50) NOT NULL,
            source VARCHAR(20) NOT NULL,
            created_at DATETIME NOT NULL DEFAULT NOW(),
            updated_at DATETIME
        )
        """
    )
    try:
        cur.execute("ALTER TABLE users ADD COLUMN profile_image VARCHAR(4000) NULL")
    except pymysql.err.OperationalError as exc:
        # Duplicate column error means the schema is already up to date.
        if exc.args and int(exc.args[0]) != 1060:
            raise
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS user_signup_otps (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            contact_number VARCHAR(20) NOT NULL UNIQUE,
            otp_hash VARCHAR(500) NOT NULL,
            otp_salt VARCHAR(500) NOT NULL,
            name VARCHAR(100) NOT NULL,
            email VARCHAR(255),
            password_hash VARCHAR(500) NOT NULL,
            role VARCHAR(50) NOT NULL,
            expires_at DATETIME NOT NULL,
            attempts INT NOT NULL DEFAULT 0,
            created_at DATETIME NOT NULL DEFAULT NOW()
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS user_sessions (
            token VARCHAR(255) PRIMARY KEY,
            user_id BIGINT NOT NULL,
            created_at DATETIME NOT NULL DEFAULT NOW(),
            expires_at DATETIME NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS signup_otp_sessions (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            contact_number VARCHAR(20) NOT NULL UNIQUE,
            otp_hash VARCHAR(500) NOT NULL,
            otp_salt VARCHAR(500) NOT NULL,
            expires_at DATETIME NOT NULL,
            attempts INT NOT NULL DEFAULT 0,
            otp_token VARCHAR(255) NULL,
            verified_at DATETIME NULL,
            created_at DATETIME NOT NULL DEFAULT NOW(),
            INDEX idx_signup_otp_sessions_expires_at (expires_at)
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS library_entries (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            title VARCHAR(200) NOT NULL,
            body TEXT NOT NULL,
            image VARCHAR(2000) NOT NULL,
            draft_version INT NOT NULL DEFAULT 1,
            sent_version INT NOT NULL DEFAULT 1,
            sent_at DATETIME,
            sent_by VARCHAR(255),
            created_at DATETIME NOT NULL DEFAULT NOW(),
            modified_at DATETIME NOT NULL DEFAULT NOW() ON UPDATE NOW()
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS farm_entries (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            farm_name VARCHAR(200) NOT NULL,
            farm_address VARCHAR(500) NOT NULL,
            farmer_user_id BIGINT NOT NULL,
            geotag_id VARCHAR(120) NOT NULL,
            created_at DATETIME NOT NULL DEFAULT NOW(),
            modified_at DATETIME NOT NULL DEFAULT NOW() ON UPDATE NOW(),
            INDEX idx_farm_farmer_user (farmer_user_id),
            FOREIGN KEY (farmer_user_id) REFERENCES users(id) ON DELETE RESTRICT
        )
        """
    )
    try:
        cur.execute("ALTER TABLE library_entries ADD COLUMN draft_version INT NOT NULL DEFAULT 1")
    except pymysql.err.OperationalError as exc:
        if exc.args and int(exc.args[0]) != 1060:
            raise
    try:
        cur.execute("ALTER TABLE library_entries ADD COLUMN sent_version INT NOT NULL DEFAULT 1")
    except pymysql.err.OperationalError as exc:
        if exc.args and int(exc.args[0]) != 1060:
            raise
    try:
        cur.execute("ALTER TABLE library_entries ADD COLUMN sent_at DATETIME NULL")
    except pymysql.err.OperationalError as exc:
        if exc.args and int(exc.args[0]) != 1060:
            raise
    try:
        cur.execute("ALTER TABLE library_entries ADD COLUMN sent_by VARCHAR(255) NULL")
    except pymysql.err.OperationalError as exc:
        if exc.args and int(exc.args[0]) != 1060:
            raise
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS library_version (
            id INT PRIMARY KEY DEFAULT 1,
            version INT NOT NULL DEFAULT 1,
            updated_at DATETIME NOT NULL DEFAULT NOW() ON UPDATE NOW()
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS library_sent_version (
            id INT PRIMARY KEY DEFAULT 1,
            sent_version INT NOT NULL DEFAULT 1,
            sent_at DATETIME,
            sent_by VARCHAR(255)
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS library_send_logs (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            sent_version INT NOT NULL,
            sent_by VARCHAR(255) NOT NULL,
            sent_at DATETIME NOT NULL DEFAULT NOW()
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS library_sent_items (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            sent_version INT NOT NULL,
            source_library_id BIGINT,
            title VARCHAR(200) NOT NULL,
            body TEXT NOT NULL,
            image VARCHAR(2000) NOT NULL,
            sent_at DATETIME NOT NULL DEFAULT NOW()
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS library_entry_send_logs (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            library_id BIGINT NOT NULL,
            sent_version INT NOT NULL,
            sent_by VARCHAR(255) NOT NULL,
            sent_at DATETIME NOT NULL DEFAULT NOW(),
            INDEX idx_library_entry_send_logs_library (library_id),
            FOREIGN KEY (library_id) REFERENCES library_entries(id) ON DELETE CASCADE
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS library_entry_sent_items (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            library_id BIGINT NOT NULL,
            sent_version INT NOT NULL,
            title VARCHAR(200) NOT NULL,
            body TEXT NOT NULL,
            image VARCHAR(2000) NOT NULL,
            sent_at DATETIME NOT NULL DEFAULT NOW(),
            INDEX idx_library_entry_sent_items_library_ver (library_id, sent_version),
            FOREIGN KEY (library_id) REFERENCES library_entries(id) ON DELETE CASCADE
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS detections (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            user_id BIGINT NOT NULL,
            farm_id BIGINT,
            image_path TEXT NOT NULL,
            predicted_label VARCHAR(255) NOT NULL,
            severity VARCHAR(50) NOT NULL,
            confidence FLOAT,
            recommendation_version INT,
            source VARCHAR(50) NOT NULL DEFAULT 'upload',
            created_at DATETIME NOT NULL DEFAULT NOW(),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (farm_id) REFERENCES farm_entries(id) ON DELETE SET NULL
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS remarks (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            detection_id BIGINT NOT NULL,
            user_id BIGINT NOT NULL,
            remark TEXT NOT NULL,
            created_at DATETIME NOT NULL DEFAULT NOW(),
            FOREIGN KEY (detection_id) REFERENCES detections(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS activity_logs (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            user_id BIGINT,
            action VARCHAR(255) NOT NULL,
            reference_type VARCHAR(50),
            reference_id BIGINT,
            created_at DATETIME NOT NULL DEFAULT NOW(),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS user_uploaded_content (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            history_id VARCHAR(255) NOT NULL,
            user_id BIGINT,
            farm_id BIGINT,
            image_uri VARCHAR(4000) NOT NULL,
            severity VARCHAR(50) NOT NULL,
            mitigations_json LONGTEXT NOT NULL,
            remark TEXT NOT NULL,
            scanned_at DATETIME NULL,
            uploaded_at DATETIME NOT NULL DEFAULT NOW(),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
            FOREIGN KEY (farm_id) REFERENCES farm_entries(id) ON DELETE SET NULL
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS model_overview_records (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            user_id BIGINT NOT NULL UNIQUE,
            overall_accuracy DECIMAL(5,2) NOT NULL DEFAULT 0,
            total_scans INT NOT NULL DEFAULT 0,
            average_confidence DECIMAL(5,2) NULL,
            last7_accuracy DECIMAL(5,2) NULL,
            last30_accuracy DECIMAL(5,2) NULL,
            trend_json LONGTEXT NULL,
            severity_distribution_json LONGTEXT NULL,
            confidence_distribution_json LONGTEXT NULL,
            top_issues_json LONGTEXT NULL,
            source VARCHAR(40) NOT NULL DEFAULT 'app',
            source_updated_at DATETIME NULL,
            fetched_at DATETIME NOT NULL DEFAULT NOW(),
            updated_at DATETIME NOT NULL DEFAULT NOW() ON UPDATE NOW(),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS model_overview_refresh_state (
            id INT PRIMARY KEY,
            last_attempt_at DATETIME NULL,
            last_success_at DATETIME NULL,
            last_status VARCHAR(20) NULL,
            last_message TEXT NULL
        )
        """
    )
    cur.execute(
        """
        INSERT IGNORE INTO model_overview_refresh_state (id, last_status, last_message)
        VALUES (1, 'idle', 'No refresh attempt yet')
        """
    )

    conn.commit()
    ensure_users_schema(conn)

    for sev in SEVERITIES:
        cur.execute(
            """
            INSERT IGNORE INTO mitigation_versions (severity, version)
            VALUES (%s, 1)
            """,
            (sev,)
        )
        cur.execute(
            "SELECT version FROM mitigation_versions WHERE severity = %s",
            (sev,)
        )
        current_version = cur.fetchone()["version"]
        cur.execute(
            """
            INSERT IGNORE INTO mitigation_sent_versions (severity, sent_version, sent_at, sent_by)
            VALUES (%s, %s, NOW(), %s)
            """,
            (sev, int(current_version), "System Seed")
        )

    cur.execute("SELECT COUNT(*) AS c FROM mitigations")
    mitigation_count = cur.fetchone()["c"]
    if mitigation_count == 0:
        seed_mitigations = [
            ("Functional", 1, "No immediate intervention required", "<p>Leaf appears healthy. Continue routine monitoring, sanitation, and balanced fertilization.</p>"),
            ("Mild", 1, "Start preventive management", "<p>Prune lightly infected leaves, improve air circulation, and begin scheduled fungicide prevention.</p>"),
            ("Moderate", 1, "Apply curative treatment plan", "<p>Increase fungicide frequency per label, remove infected foliage, and closely monitor nearby plants.</p>"),
            ("Severe", 1, "Urgent containment required", "<p>Isolate heavily infected plants, remove severely damaged leaves, and execute immediate intensive treatment.</p>"),
        ]
        cur.executemany(
            "INSERT INTO mitigations (severity, slot_no, title, description) VALUES (%s, %s, %s, %s)",
            seed_mitigations
        )

    ensure_single_mitigation_entries(conn)
    try:
        cur.execute("ALTER TABLE mitigations ADD UNIQUE KEY uq_mitigations_severity_slot (severity, slot_no)")
    except pymysql.err.OperationalError as exc:
        if exc.args and int(exc.args[0]) not in {1061, 1062}:
            raise

    cur.execute("SELECT COUNT(*) AS c FROM users")
    user_count = cur.fetchone()["c"]
    if user_count == 0:
        seed_users = [
            (
                "System Superadmin",
                "09000000001",
                "superadmin@muscan.local",
                hash_password("superadmin123"),
                "Superadmin",
                "manual"
        ),
            (
                "Field Admin",
                "09000000002",
                "admin@muscan.local",
                hash_password("admin12345"),
                "Admin",
                "manual"
        ),
        ]
        cur.executemany(
            """
            INSERT INTO users (name, contact_number, email, password_hash, role, source)
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            seed_users
        )

    cur.execute("SELECT COUNT(*) AS c FROM library_entries")
    library_count = cur.fetchone()["c"]
    if library_count == 0:
        seed_library = [
            (
                "Black Sigatoka Basics",
                "Black Sigatoka is a fungal leaf disease that can reduce banana yield. Early detection and consistent control are critical.",
                "https://images.unsplash.com/photo-1528825871115-3581a5387919"
        )
        ]
        cur.executemany(
            "INSERT INTO library_entries (title, body, image) VALUES (%s, %s, %s)",
            seed_library
        )

    cur.execute(
        """
        INSERT IGNORE INTO library_version (id, version, updated_at)
        VALUES (1, 1, NOW())
        """
    )
    cur.execute("SELECT version FROM library_version WHERE id = 1")
    current_library_version = cur.fetchone()["version"]
    cur.execute(
        """
        INSERT IGNORE INTO library_sent_version (id, sent_version, sent_at, sent_by)
        VALUES (1, %s, NOW(), %s)
        """,
        (int(current_library_version), "System Seed")
        )

    ensure_library_entry_versions(conn)

    conn.commit()

    # Ensure at least one sent snapshot exists for each severity.
    for sev in SEVERITIES:
        sent_ver = get_sent_version(conn, sev)
        check_cur = conn.cursor()
        check_cur.execute(
            """
            SELECT 1 FROM mitigation_sent_items
            WHERE severity = %s AND sent_version = %s
            LIMIT 1
            """,
            (sev, int(sent_ver))
        )
        has_snapshot = check_cur.fetchone()
        if not has_snapshot:
            snapshot_mitigation_version(conn, sev, int(sent_ver))

    check_cur = conn.cursor()
    check_cur.execute("SELECT id, sent_version FROM library_entries")
    library_rows = check_cur.fetchall()
    for row in library_rows:
        check_cur.execute(
            """
            SELECT 1 FROM library_entry_sent_items
            WHERE library_id = %s AND sent_version = %s
            LIMIT 1
            """,
            (int(row["id"]), int(row.get("sent_version") or 1)),
        )
        has_library_snapshot = check_cur.fetchone()
        if not has_library_snapshot:
            snapshot_library_version(conn, int(row.get("sent_version") or 1), int(row["id"]))

    conn.commit()

    conn.close()


def bump_version(conn, severity: str) -> None:
    conn.cursor().execute(
        """
        UPDATE mitigation_versions
        SET version = version + 1, updated_at = NOW()
        WHERE severity = %s
        """,
        (severity,)
        )


def default_instruction_html(severity: str) -> str:
    return (
        f"<p>Draft instruction for <strong>{html.escape(severity)}</strong> "
        "mitigation. Add step-by-step text and optional images.</p>"
    )


def ensure_single_mitigation_entries(conn) -> None:
    cur = conn.cursor()
    for severity in sorted(SEVERITIES):
        cur.execute(
            """
            SELECT id, slot_no
            FROM mitigations
            WHERE LOWER(TRIM(severity)) = LOWER(TRIM(%s))
            ORDER BY
                CASE WHEN slot_no IS NULL THEN 999 ELSE slot_no END ASC,
                id ASC
            """,
            (severity,),
        )
        rows = cur.fetchall()

        kept = rows[:1]
        extras = rows[1:]

        if kept and kept[0].get("slot_no") != 1:
            cur.execute("UPDATE mitigations SET slot_no = 1 WHERE id = %s", (int(kept[0]["id"]),))

        for row in extras:
            cur.execute("DELETE FROM mitigations WHERE id = %s", (int(row["id"]),))

        if not kept:
            cur.execute(
                """
                INSERT INTO mitigations (severity, slot_no, title, description)
                VALUES (%s, %s, %s, %s)
                """,
                (
                    severity,
                    1,
                    f"{severity} mitigation",
                    default_instruction_html(severity),
                ),
            )


def sanitize_instruction_html(raw: str) -> str:
    candidate = (raw or "").strip()
    if not candidate:
        raise HTTPException(status_code=400, detail="Instruction is required")

    cleaned = re.sub(r"(?is)<(script|style).*?>.*?</\\1>", "", candidate)
    cleaned = re.sub(r"(?i)on[a-z]+\s*=\s*\"[^\"]*\"", "", cleaned)
    cleaned = re.sub(r"(?i)on[a-z]+\s*=\s*'[^']*'", "", cleaned)
    cleaned = re.sub(r"(?i)on[a-z]+\s*=\s*[^\s>]+", "", cleaned)
    cleaned = re.sub(r"(?i)javascript:", "", cleaned)
    cleaned = cleaned.strip()

    if "<" not in cleaned and ">" not in cleaned:
        return f"<p>{html.escape(cleaned).replace(chr(10), '<br>')}</p>"

    if not cleaned:
        raise HTTPException(status_code=400, detail="Instruction is required")
    return cleaned


def ensure_library_entry_versions(conn) -> None:
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, title, body, image, draft_version, sent_version, sent_at, sent_by
        FROM library_entries
        ORDER BY id ASC
        """
    )
    rows = cur.fetchall()

    for row in rows:
        entry_id = int(row["id"])
        draft_version = int(row.get("draft_version") or 1)
        sent_version = int(row.get("sent_version") or 1)
        sent_at = row.get("sent_at")
        sent_by = row.get("sent_by") or "System Seed"

        if draft_version < 1:
            draft_version = 1
        if sent_version < 1:
            sent_version = 1
        if sent_version > draft_version:
            draft_version = sent_version

        cur.execute(
            """
            UPDATE library_entries
            SET draft_version = %s,
                sent_version = %s,
                sent_at = COALESCE(sent_at, NOW()),
                sent_by = COALESCE(sent_by, %s)
            WHERE id = %s
            """,
            (draft_version, sent_version, sent_by, entry_id),
        )

        cur.execute(
            """
            SELECT 1 FROM library_entry_sent_items
            WHERE library_id = %s AND sent_version = %s
            LIMIT 1
            """,
            (entry_id, sent_version),
        )
        has_snapshot = cur.fetchone()
        if not has_snapshot:
            snapshot_library_version(conn, sent_version, entry_id)


def bump_library_version(conn, entry_id: int | None = None) -> None:
    if entry_id is None:
        return
    conn.cursor().execute(
        """
        UPDATE library_entries
        SET draft_version = draft_version + 1,
            modified_at = NOW()
        WHERE id = %s
        """,
        (int(entry_id),),
    )


def get_library_draft_version(conn, entry_id: int | None = None) -> int:
    cur = conn.cursor()
    if entry_id is not None:
        cur.execute("SELECT draft_version FROM library_entries WHERE id = %s", (int(entry_id),))
        row = cur.fetchone()
        return int(row["draft_version"]) if row else 1

    cur.execute("SELECT COALESCE(MAX(draft_version), 1) AS version FROM library_entries")
    row = cur.fetchone()
    return int(row["version"] if row else 1)


def get_library_sent_version(conn, entry_id: int | None = None) -> int:
    cur = conn.cursor()
    if entry_id is not None:
        cur.execute("SELECT sent_version FROM library_entries WHERE id = %s", (int(entry_id),))
        row = cur.fetchone()
        return int(row["sent_version"]) if row else 1

    cur.execute("SELECT COALESCE(MAX(sent_version), 1) AS sent_version FROM library_entries")
    row = cur.fetchone()
    return int(row["sent_version"] if row else 1)


def snapshot_library_version(conn, version: int, entry_id: int | None = None) -> None:
    cur = conn.cursor()
    if entry_id is None:
        return

    cur.execute(
        "DELETE FROM library_entry_sent_items WHERE library_id = %s AND sent_version = %s",
        (int(entry_id), int(version)),
    )
    cur.execute(
        """
        INSERT INTO library_entry_sent_items (library_id, sent_version, title, body, image)
        SELECT id, %s, title, body, image
        FROM library_entries
        WHERE id = %s
        """,
        (int(version), int(entry_id)),
    )


def get_severity_version(conn, severity: str) -> int:
    cur = conn.cursor()
    cur.execute("SELECT version FROM mitigation_versions WHERE severity = %s", (severity,))
    row = cur.fetchone()
    if row is None:
        conn.cursor().execute(
            "INSERT INTO mitigation_versions (severity, version) VALUES (%s, 1)",
            (severity,)
        )
        conn.commit()
        return 1
    return int(row["version"])


def get_sent_version(conn, severity: str) -> int:
    cur = conn.cursor()
    cur.execute("SELECT sent_version FROM mitigation_sent_versions WHERE severity = %s", (severity,))
    row = cur.fetchone()
    if row is None:
        current = get_severity_version(conn, severity)
        conn.cursor().execute(
            """
            INSERT INTO mitigation_sent_versions (severity, sent_version, sent_at, sent_by)
            VALUES (%s, %s, NOW(), %s)
            """,
            (severity, int(current), "System Auto")
        )
        conn.commit()
        return int(current)
    return int(row["sent_version"])


def snapshot_mitigation_version(conn, severity: str, version: int) -> None:
    cur = conn.cursor()
    cur.execute(
        """
        DELETE FROM mitigation_sent_items
        WHERE severity = %s AND sent_version = %s
        """,
        (severity, int(version))
        )
    cur.execute(
        """
        INSERT INTO mitigation_sent_items (severity, sent_version, slot_no, source_mitigation_id, title, description)
        SELECT severity, %s, slot_no, id, title, description
        FROM mitigations
        WHERE LOWER(TRIM(severity)) = LOWER(TRIM(%s))
        ORDER BY id ASC
        """,
        (int(version), severity)
        )


def mitigation_row_to_dict(row: sqlite3.Row) -> dict:
    instruction = row["description"]
    return {
        "id": row["id"],
        "slot_no": 1,
        "severity": row["severity"],
        "title": row["title"],
        "description": instruction,
        "instruction": instruction,
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def user_row_to_dict(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "name": row["name"],
        "contact_number": row["contact_number"],
        "email": row["email"],
        "profile_image": row.get("profile_image") if hasattr(row, "get") else row["profile_image"],
        "role": row["role"],
        "source": row["source"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def normalize_contact_number(raw: str) -> str:
    digits = "".join(ch for ch in raw if ch.isdigit())
    if not PHONE_REGEX.fullmatch(digits):
        raise HTTPException(status_code=400, detail="Invalid contact number. Use 10 to 15 digits.")
    return digits


def normalize_ph_contact_number(raw: str) -> str:
    digits = normalize_contact_number(raw)

    # Accept common PH mobile formats and normalize to 09XXXXXXXXX.
    if digits.startswith("639") and len(digits) == 12:
        digits = f"0{digits[2:]}"
    elif digits.startswith("9") and len(digits) == 10:
        digits = f"0{digits}"

    if not re.fullmatch(r"09\d{9}", digits):
        raise HTTPException(
            status_code=400,
            detail="Invalid Philippine mobile number. Use 09XXXXXXXXX or +639XXXXXXXXX.",
        )
    return digits


def to_ph_e164(phone_number: str) -> str:
    """Convert a normalized PH local mobile (09XXXXXXXXX) to +639XXXXXXXXX."""
    normalized = normalize_ph_contact_number(phone_number)
    return f"+63{normalized[1:]}"


def hash_secret(value: str, *, salt: bytes | None = None) -> str:
    salt = salt or os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", value.encode("utf-8"), salt, 200_000)
    return f"{salt.hex()}${digest.hex()}"


def verify_secret(value: str, packed_hash: str | None) -> bool:
    if not packed_hash or "$" not in packed_hash:
        return False
    salt_hex, digest_hex = packed_hash.split("$", 1)
    try:
        salt = bytes.fromhex(salt_hex)
    except ValueError:
        return False
    compare = hash_secret(value, salt=salt)
    return hmac.compare_digest(compare, packed_hash)


def hash_password(password: str) -> str:
    return hash_secret(password)

def log_activity(
    conn,
    user_id: int | None,
    action: str,
    reference_type: str | None = None,
    reference_id: int | None = None
        ) -> None:
    conn.cursor().execute(
        """
        INSERT INTO activity_logs (user_id, action, reference_type, reference_id)
        VALUES (%s, %s, %s, %s)
        """,
        (user_id, action, reference_type, reference_id)
        )

def ensure_users_schema(conn) -> None:
    cur = conn.cursor()
    # In MySQL, we just ensure the table exists with the correct schema.
    # The CREATE TABLE IF NOT EXISTS in init_db() already handles this.
    # This function is now a no-op for MySQL but kept for compatibility.
    pass


def create_session(conn, user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    conn.cursor().execute(
        """
        INSERT INTO user_sessions (token, user_id, expires_at)
        VALUES (%s, %s, DATE_ADD(NOW(), INTERVAL %s SECOND))
        """,
        (token, int(user_id), int(SESSION_TTL_SECONDS))
        )
    conn.commit()
    return token


def send_sms_message(phone_number: str, body: str) -> tuple[bool, str, str]:
    """Send SMS with provider fallback: smsapi → semaphore → twilio.

    Returns: (sent, provider_used_or_last_attempted, error_message)
    """
    local_phone = normalize_ph_contact_number(phone_number)
    e164_phone = to_ph_e164(local_phone)
    providers = [SMS_PROVIDER]  # Try configured provider first
    last_provider = SMS_PROVIDER or "unknown"
    last_error = "No SMS provider is configured."
    
    # Build fallback list based on configuration
    if SMS_PROVIDER != "smsapi" and SMSAPI_KEY:
        providers.append("smsapi")
    if SMS_PROVIDER != "semaphore" and SEMAPHORE_API_KEY:
        providers.append("semaphore")
    if SMS_PROVIDER != "twilio" and TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN and TWILIO_FROM_NUMBER:
        providers.append("twilio")
    
    for provider in providers:
        last_provider = provider
        if provider == "smsapi":
            if not SMSAPI_KEY:
                last_error = "SMSAPI_KEY is missing."
                continue
            try:
                request = urllib.request.Request(
                    "https://smsapiph.onrender.com/api/v1/send/sms",
                    data=json.dumps({
                        "recipient": e164_phone,
                        "message": body,
                    }).encode("utf-8"),
                    headers={
                        "x-api-key": SMSAPI_KEY,
                        "Content-Type": "application/json",
                    },
                    method="POST",
                )
                with urllib.request.urlopen(request, timeout=15) as response:
                    status = int(response.status)
                    payload_raw = response.read().decode("utf-8", errors="replace")
                    payload_json = json.loads(payload_raw) if payload_raw else {}

                    # SMSAPI PH can return an error payload with 2xx status.
                    if isinstance(payload_json, dict):
                        error_info = payload_json.get("error")
                        if error_info:
                            code = error_info.get("code") if isinstance(error_info, dict) else None
                            message = error_info.get("message") if isinstance(error_info, dict) else "SMS delivery failed"
                            details = error_info.get("details") if isinstance(error_info, dict) else ""
                            last_error = f"smsapi error {code}: {message}. {details}".strip()
                            continue
                        if payload_json.get("success") is False:
                            last_error = str(payload_json.get("message") or "SMS delivery failed")
                            continue

                    if 200 <= status < 300:
                        return True, provider, ""
                    last_error = f"smsapi HTTP {status}"
            except urllib.error.HTTPError as exc:
                error_body = ""
                try:
                    error_body = exc.read().decode("utf-8", errors="replace")
                except Exception:
                    error_body = ""
                last_error = f"smsapi HTTP {exc.code}: {error_body[:300]}".strip()
                continue
            except (urllib.error.URLError, json.JSONDecodeError, Exception) as exc:
                last_error = f"smsapi request error: {exc}"
                continue  # Try next provider
        
        elif provider == "semaphore":
            if not SEMAPHORE_API_KEY:
                last_error = "SEMAPHORE_API_KEY is missing."
                continue
            try:
                payload_dict = {
                    "apikey": SEMAPHORE_API_KEY,
                    "number": local_phone,
                    "message": body,
                }
                if SEMAPHORE_SENDER_NAME:
                    payload_dict["sendername"] = SEMAPHORE_SENDER_NAME
                request = urllib.request.Request(
                    "https://api.semaphore.co/api/v4/messages",
                    data=urllib.parse.urlencode(payload_dict).encode("utf-8"),
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    method="POST",
                )
                with urllib.request.urlopen(request, timeout=15) as response:
                    if 200 <= int(response.status) < 300:
                        return True, provider, ""
                    last_error = f"semaphore HTTP {int(response.status)}"
            except urllib.error.HTTPError as exc:
                error_body = ""
                try:
                    error_body = exc.read().decode("utf-8", errors="replace")
                except Exception:
                    error_body = ""
                last_error = f"semaphore HTTP {exc.code}: {error_body[:300]}".strip()
                continue
            except (urllib.error.URLError, Exception) as exc:
                last_error = f"semaphore request error: {exc}"
                continue
        
        elif provider == "twilio":
            if not TWILIO_ACCOUNT_SID or not TWILIO_AUTH_TOKEN or not TWILIO_FROM_NUMBER:
                last_error = "Twilio credentials are missing."
                continue
            try:
                url = f"https://api.twilio.com/2010-04-01/Accounts/{TWILIO_ACCOUNT_SID}/Messages.json"
                payload = urllib.parse.urlencode(
                    {
                        "To": e164_phone,
                        "From": TWILIO_FROM_NUMBER,
                        "Body": body,
                    }
                ).encode("utf-8")
                credentials = f"{TWILIO_ACCOUNT_SID}:{TWILIO_AUTH_TOKEN}".encode("utf-8")
                auth_header = "Basic " + __import__("base64").b64encode(credentials).decode("ascii")
                request = urllib.request.Request(
                    url,
                    data=payload,
                    headers={
                        "Authorization": auth_header,
                        "Content-Type": "application/x-www-form-urlencoded",
                    },
                    method="POST"
                )
                with urllib.request.urlopen(request, timeout=15) as response:
                    if 200 <= int(response.status) < 300:
                        return True, provider, ""
                    last_error = f"twilio HTTP {int(response.status)}"
            except urllib.error.HTTPError as exc:
                error_body = ""
                try:
                    error_body = exc.read().decode("utf-8", errors="replace")
                except Exception:
                    error_body = ""
                last_error = f"twilio HTTP {exc.code}: {error_body[:300]}".strip()
                continue
            except (urllib.error.URLError, Exception) as exc:
                last_error = f"twilio request error: {exc}"
                continue
    
    return False, last_provider, last_error


def session_user(conn, token: str):
    cur = conn.cursor()
    cur.execute(
        """
        SELECT u.*
        FROM user_sessions s
        JOIN users u ON u.id = s.user_id
        WHERE s.token = %s
          AND s.expires_at > NOW()
        """,
        (token,),
    )
    return cur.fetchone()


def parse_iso_datetime(raw: str | None) -> datetime | None:
    value = (raw or "").strip()
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def json_dump(value) -> str:
    return json.dumps(value if value is not None else {}, ensure_ascii=False)


def json_load(value: str | None, fallback):
    if not value:
        return fallback
    try:
        parsed = json.loads(value)
        if parsed is None:
            return fallback
        return parsed
    except (json.JSONDecodeError, TypeError):
        return fallback


def upsert_model_overview(conn, item: ModelOverviewPayload, source: str = "app") -> None:
    source_updated_at = parse_iso_datetime(item.source_updated_at)
    conn.cursor().execute(
        """
        INSERT INTO model_overview_records (
            user_id,
            overall_accuracy,
            total_scans,
            average_confidence,
            last7_accuracy,
            last30_accuracy,
            trend_json,
            severity_distribution_json,
            confidence_distribution_json,
            top_issues_json,
            source,
            source_updated_at,
            fetched_at
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
        ON DUPLICATE KEY UPDATE
            overall_accuracy = VALUES(overall_accuracy),
            total_scans = VALUES(total_scans),
            average_confidence = VALUES(average_confidence),
            last7_accuracy = VALUES(last7_accuracy),
            last30_accuracy = VALUES(last30_accuracy),
            trend_json = VALUES(trend_json),
            severity_distribution_json = VALUES(severity_distribution_json),
            confidence_distribution_json = VALUES(confidence_distribution_json),
            top_issues_json = VALUES(top_issues_json),
            source = VALUES(source),
            source_updated_at = VALUES(source_updated_at),
            fetched_at = NOW()
        """,
        (
            int(item.user_id),
            float(item.overall_accuracy),
            int(item.total_scans),
            float(item.average_confidence) if item.average_confidence is not None else None,
            float(item.last7_accuracy) if item.last7_accuracy is not None else None,
            float(item.last30_accuracy) if item.last30_accuracy is not None else None,
            json_dump(item.trend),
            json_dump(item.severity_distribution),
            json_dump(item.confidence_distribution),
            json_dump(item.top_issues),
            source[:40],
            source_updated_at,
        ),
    )


def model_overview_row_to_dict(row: dict) -> dict:
    return {
        "user_id": int(row["user_id"]),
        "user_name": row.get("user_name") or "Unknown",
        "user_contact_number": row.get("user_contact_number") or "",
        "user_role": row.get("user_role") or "",
        "overall_accuracy": float(row.get("overall_accuracy") or 0),
        "total_scans": int(row.get("total_scans") or 0),
        "average_confidence": (
            float(row["average_confidence"]) if row.get("average_confidence") is not None else None
        ),
        "last7_accuracy": float(row.get("last7_accuracy") or 0),
        "last30_accuracy": float(row.get("last30_accuracy") or 0),
        "trend": json_load(row.get("trend_json"), []),
        "severity_distribution": json_load(row.get("severity_distribution_json"), {}),
        "confidence_distribution": json_load(row.get("confidence_distribution_json"), {}),
        "top_issues": json_load(row.get("top_issues_json"), []),
        "source": row.get("source") or "app",
        "source_updated_at": row.get("source_updated_at"),
        "fetched_at": row.get("fetched_at"),
        "updated_at": row.get("updated_at"),
    }


def list_model_overview_rows(conn) -> list[dict]:
    cur = conn.cursor()
    cur.execute(
        """
        SELECT
            u.id AS user_id,
            u.name AS user_name,
            u.contact_number AS user_contact_number,
            u.role AS user_role,
            m.overall_accuracy,
            m.total_scans,
            m.average_confidence,
            m.last7_accuracy,
            m.last30_accuracy,
            m.trend_json,
            m.severity_distribution_json,
            m.confidence_distribution_json,
            m.top_issues_json,
            m.source,
            m.source_updated_at,
            m.fetched_at,
            m.updated_at
        FROM users u
        LEFT JOIN model_overview_records m ON m.user_id = u.id
        ORDER BY u.id DESC
        """
    )
    return [model_overview_row_to_dict(row) for row in cur.fetchall()]


def read_model_overview_refresh_state(conn) -> dict:
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, last_attempt_at, last_success_at, last_status, last_message
        FROM model_overview_refresh_state
        WHERE id = 1
        """
    )
    row = cur.fetchone() or {}
    return {
        "last_attempt_at": row.get("last_attempt_at"),
        "last_success_at": row.get("last_success_at"),
        "last_status": row.get("last_status") or "idle",
        "last_message": row.get("last_message") or "No refresh attempt yet",
    }


def mark_model_overview_refresh(
    conn,
    *,
    status: str,
    message: str,
    success: bool,
) -> None:
    conn.cursor().execute(
        """
        UPDATE model_overview_refresh_state
        SET
            last_attempt_at = NOW(),
            last_success_at = CASE WHEN %s THEN NOW() ELSE last_success_at END,
            last_status = %s,
            last_message = %s
        WHERE id = 1
        """,
        (1 if success else 0, status[:20], message[:2000]),
    )


def maybe_refresh_model_overview(conn, force: bool = False) -> dict:
    state_row = read_model_overview_refresh_state(conn)
    now_epoch = int(time.time())
    last_attempt = state_row.get("last_attempt_at")

    if last_attempt and not force:
        try:
            last_epoch = int(last_attempt.timestamp())
            if now_epoch - last_epoch < MODEL_OVERVIEW_REFRESH_INTERVAL_SECONDS:
                return {
                    "attempted": False,
                    "refreshed": False,
                    "status": state_row.get("last_status") or "idle",
                    "message": "Refresh skipped: still inside hourly interval.",
                    "last_attempt_at": state_row.get("last_attempt_at"),
                    "last_success_at": state_row.get("last_success_at"),
                }
        except Exception:
            pass

    if not MODEL_OVERVIEW_PULL_URL:
        return {
            "attempted": False,
            "refreshed": False,
            "status": state_row.get("last_status") or "idle",
            "message": "MODEL_OVERVIEW_PULL_URL is not configured. Returning last saved metrics.",
            "last_attempt_at": state_row.get("last_attempt_at"),
            "last_success_at": state_row.get("last_success_at"),
        }

    headers = {"Accept": "application/json"}
    if MODEL_OVERVIEW_PULL_TOKEN:
        headers["Authorization"] = f"Bearer {MODEL_OVERVIEW_PULL_TOKEN}"

    try:
        request = urllib.request.Request(MODEL_OVERVIEW_PULL_URL, headers=headers, method="GET")
        with urllib.request.urlopen(request, timeout=20) as response:
            payload = json.loads(response.read().decode("utf-8"))

        raw_items = payload.get("items") if isinstance(payload, dict) else None
        if not isinstance(raw_items, list):
            raise ValueError("Invalid pull response: expected { items: [] }")

        updated_count = 0
        for raw_item in raw_items:
            parsed = ModelOverviewPayload(**raw_item)
            upsert_model_overview(conn, parsed, source="app-pull")
            updated_count += 1

        mark_model_overview_refresh(
            conn,
            status="ok",
            message=f"Refreshed {updated_count} user metrics from app source.",
            success=True,
        )
        conn.commit()
        refreshed_state = read_model_overview_refresh_state(conn)
        return {
            "attempted": True,
            "refreshed": True,
            "status": "ok",
            "message": f"Refreshed {updated_count} user metrics.",
            "last_attempt_at": refreshed_state.get("last_attempt_at"),
            "last_success_at": refreshed_state.get("last_success_at"),
        }
    except Exception as exc:
        conn.rollback()
        mark_model_overview_refresh(
            conn,
            status="err",
            message=f"Refresh failed: {exc}",
            success=False,
        )
        conn.commit()
        refreshed_state = read_model_overview_refresh_state(conn)
        return {
            "attempted": True,
            "refreshed": False,
            "status": "err",
            "message": f"Refresh failed. Kept last saved metrics. ({exc})",
            "last_attempt_at": refreshed_state.get("last_attempt_at"),
            "last_success_at": refreshed_state.get("last_success_at"),
        }


def library_row_to_dict(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "title": row["title"],
        "body": row["body"],
        "image": row["image"],
        "created_at": row["created_at"],
        "modified_at": row["modified_at"],
    }


def farm_row_to_dict(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "farm_name": row["farm_name"],
        "farm_address": row["farm_address"],
        "farmer_user_id": row["farmer_user_id"],
        "farmer_name": row.get("farmer_name") if hasattr(row, "get") else row["farmer_name"],
        "farmer_contact_number": row.get("farmer_contact_number") if hasattr(row, "get") else row["farmer_contact_number"],
        "geotag_id": row["geotag_id"],
        "created_at": row["created_at"],
        "modified_at": row["modified_at"],
    }


def normalize_severity(raw: str) -> str:
    key = raw.strip().casefold()
    canonical = SEVERITY_NORMALIZED.get(key)
    if not canonical:
        raise HTTPException(status_code=400, detail="Invalid severity")
    return canonical


def normalize_role(raw: str) -> str:
    key = raw.strip().casefold()
    canonical = ROLE_NORMALIZED.get(key)
    if not canonical:
        raise HTTPException(status_code=400, detail="Invalid role")
    return canonical


def enforce_superadmin(raw_role: str) -> None:
    if normalize_role(raw_role) != "Superadmin":
        raise HTTPException(status_code=403, detail="Only Superadmin can modify library entries")


def ensure_farmer_user(conn, farmer_user_id: int) -> dict:
    cur = conn.cursor()
    cur.execute("SELECT id, name, contact_number, role FROM users WHERE id = %s", (int(farmer_user_id),))
    user = cur.fetchone()
    if not user:
        raise HTTPException(status_code=404, detail="Selected farmer user was not found")
    if normalize_role(user["role"]) != "Farmer":
        raise HTTPException(status_code=400, detail="Selected user must have Farmer role")
    return user


@app.on_event("startup")
def startup() -> None:
    if _is_render_runtime() and DB_HOST.strip().lower() in {"127.0.0.1", "localhost"}:
        raise RuntimeError(
            "Invalid DB_HOST for Render: localhost/127.0.0.1 points to the app container itself. "
            "Use your external MySQL host in DB_HOST."
        )

    last_error: Exception | None = None
    for attempt in range(1, 4):
        try:
            print(f"Starting database initialization against {DB_HOST}:{DB_PORT}", file=sys.stderr)
            init_db()
            return
        except pymysql.err.OperationalError as exc:
            last_error = exc
            if exc.args and int(exc.args[0]) in {10048, 2003} and attempt < 3:
                time.sleep(1.0 * attempt)
                continue
            raise

    if last_error is not None:
        print("Startup failed after retries:", repr(last_error), file=sys.stderr)
        traceback.print_exception(type(last_error), last_error, last_error.__traceback__, file=sys.stderr)
        raise last_error


@app.get("/")
def root() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/admin")
def admin() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/mitigations")
def list_mitigations() -> list[dict]:
    conn = get_db()
    cur = conn.cursor()
    ensure_single_mitigation_entries(conn)
    cur.execute("SELECT * FROM mitigations ORDER BY severity ASC, id ASC")
    rows = cur.fetchall()
    conn.commit()
    conn.close()
    return [mitigation_row_to_dict(r) for r in rows]


@app.get("/api/mitigations/by-severity/{severity}")
def mitigations_by_severity(severity: str) -> list[dict]:
    severity_cap = normalize_severity(severity)

    conn = get_db()
    cur = conn.cursor()
    ensure_single_mitigation_entries(conn)
    cur.execute(
        """
        SELECT * FROM mitigations
        WHERE LOWER(TRIM(severity)) = LOWER(TRIM(%s))
        ORDER BY id ASC
        """,
        (severity_cap,),
    )
    rows = cur.fetchall()
    conn.commit()
    conn.close()
    return [mitigation_row_to_dict(r) for r in rows]


@app.get("/api/mitigations/versions")
def mitigation_versions() -> dict:
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT
            mv.severity AS severity,
            mv.version AS draft_version,
            mv.updated_at AS draft_updated_at,
            COALESCE(msv.sent_version, 0) AS sent_version,
            msv.sent_at AS sent_at,
            msv.sent_by AS sent_by
        FROM mitigation_versions mv
        LEFT JOIN mitigation_sent_versions msv ON msv.severity = mv.severity
        ORDER BY mv.severity ASC
        """
    )
    rows = cur.fetchall()
    conn.close()
    return {
        "versions": {
            r["severity"]: {
                "draft_version": int(r["draft_version"]),
                "draft_updated_at": r["draft_updated_at"],
                "sent_version": int(r["sent_version"]),
                "sent_at": r["sent_at"],
                "sent_by": r["sent_by"],
                "pending": int(r["draft_version"]) > int(r["sent_version"]),
            }
            for r in rows
        }
    }


@app.get("/api/mitigations/sync/{severity}")
def sync_mitigations(severity: str) -> dict:
    severity_cap = normalize_severity(severity)

    conn = get_db()
    cur = conn.cursor()
    ensure_single_mitigation_entries(conn)
    draft_version = get_severity_version(conn, severity_cap)
    sent_version = get_sent_version(conn, severity_cap)
    cur.execute(
        """
        SELECT
            source_mitigation_id AS id,
            slot_no,
            severity,
            title,
            description,
            sent_at
        FROM mitigation_sent_items
        WHERE LOWER(TRIM(severity)) = LOWER(TRIM(%s))
          AND sent_version = %s
            ORDER BY id ASC
        """,
        (severity_cap, int(sent_version)),
    )
    rows = cur.fetchall()

    if not rows:
        # Legacy fallback if snapshots are missing.
        cur.execute(
            """
            SELECT * FROM mitigations
            WHERE LOWER(TRIM(severity)) = LOWER(TRIM(%s))
            ORDER BY id ASC
            """,
            (severity_cap,),
        )
        rows = cur.fetchall()

    # Keep response contract aligned with single-entry-per-severity behavior.
    if rows:
        rows = rows[:1]

    cur.execute(
        """
        SELECT sent_at, sent_by FROM mitigation_sent_versions WHERE severity = %s
        """,
        (severity_cap,),
    )
    release_rows = cur.fetchall()
    release_row = release_rows[0] if release_rows else None
    conn.close()

    if rows and "sent_at" in rows[0].keys():
        items = [
            {
                "id": r["id"],
                "slot_no": int(r["slot_no"] or 0),
                "severity": r["severity"],
                "title": r["title"],
                "description": r["description"],
                "instruction": r["description"],
                "created_at": r["sent_at"],
                "updated_at": None,
            }
            for r in rows
        ]
    else:
        items = [mitigation_row_to_dict(r) for r in rows]

    return {
        "severity": severity_cap,
        "version": sent_version,
        "draft_version": draft_version,
        "pending": int(draft_version) > int(sent_version),
        "sent_at": release_row["sent_at"] if release_row else None,
        "sent_by": release_row["sent_by"] if release_row else None,
        "items": items,
    }


@app.post("/api/mitigations/send/{severity}")
def send_mitigation_version(severity: str, payload: MitigationSendRequest) -> dict:
    severity_cap = normalize_severity(severity)
    _ = normalize_role(payload.actor_role)

    conn = get_db()
    cur = conn.cursor()
    ensure_single_mitigation_entries(conn)
    draft_version = get_severity_version(conn, severity_cap)
    sent_version = get_sent_version(conn, severity_cap)

    if int(draft_version) <= int(sent_version):
        conn.close()
        return {
            "sent": False,
            "severity": severity_cap,
            "draft_version": int(draft_version),
            "sent_version": int(sent_version),
            "message": "No newer mitigation version to send.",
        }

    cur.execute(
        """
        UPDATE mitigation_sent_versions
        SET sent_version = %s, sent_at = NOW(), sent_by = %s
        WHERE severity = %s
        """,
        (
            int(draft_version),
            f"{payload.actor_name.strip()} ({payload.actor_role})",
            severity_cap,
        ),
    )
    snapshot_mitigation_version(conn, severity_cap, int(draft_version))
    cur.execute(
        """
        INSERT INTO mitigation_send_logs (severity, sent_version, sent_by)
        VALUES (%s, %s, %s)
        """,
        (
            severity_cap,
            int(draft_version),
            f"{payload.actor_name.strip()} ({payload.actor_role})",
        ),
    )
    conn.commit()
    cur.execute(
        "SELECT * FROM mitigation_send_logs WHERE severity = %s ORDER BY id DESC LIMIT 1",
        (severity_cap,),
    )
    last_log = cur.fetchone()
    conn.close()

    return {
        "sent": True,
        "severity": severity_cap,
        "sent_version": int(draft_version),
        "sent_at": last_log["sent_at"] if last_log else None,
        "sent_by": last_log["sent_by"] if last_log else None,
    }


@app.get("/api/mitigations/send-history")
def mitigation_send_history() -> list[dict]:
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, severity, sent_version, sent_by, sent_at
        FROM mitigation_send_logs
        ORDER BY id DESC
        """
    )
    rows = cur.fetchall()
    conn.close()
    return [
        {
            "id": r["id"],
            "severity": r["severity"],
            "sent_version": int(r["sent_version"]),
            "sent_by": r["sent_by"],
            "sent_at": r["sent_at"],
        }
        for r in rows
    ]


@app.get("/api/mitigations/archive/{severity}")
def mitigation_archive_by_severity(severity: str) -> list[dict]:
    severity_cap = normalize_severity(severity)

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT sent_version, sent_at, sent_by
        FROM mitigation_send_logs
        WHERE severity = %s
        ORDER BY sent_version DESC
        """,
        (severity_cap,),
    )
    versions = cur.fetchall()

    archived: list[dict] = []
    for v in versions:
        sent_version = int(v["sent_version"])
        cur.execute(
            """
            SELECT title, description, source_mitigation_id, slot_no
            FROM mitigation_sent_items
            WHERE severity = %s AND sent_version = %s
            ORDER BY id ASC
            """,
            (severity_cap, sent_version),
        )
        items = cur.fetchall()[:1]
        archived.append(
            {
                "severity": severity_cap,
                "sent_version": sent_version,
                "sent_at": v["sent_at"],
                "sent_by": v["sent_by"],
                "items": [
                    {
                        "title": i["title"],
                        "description": i["description"],
                        "instruction": i["description"],
                        "slot_no": 1,
                        "source_mitigation_id": i["source_mitigation_id"],
                    }
                    for i in items
                ],
            }
        )

    conn.close()
    return archived


@app.get("/api/mitigations/{item_id}")
def get_mitigation(item_id: int) -> dict:
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM mitigations WHERE id = %s", (item_id,))
    row = cur.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Mitigation not found")
    return mitigation_row_to_dict(row)


@app.post("/api/mitigations", status_code=201)
def create_mitigation(payload: MitigationCreate) -> dict:
    raise HTTPException(
        status_code=405,
        detail="Mitigation creation is locked. Exactly one mitigation exists per severity and can only be updated.",
    )


@app.put("/api/mitigations/{item_id}")
def update_mitigation(item_id: int, payload: MitigationUpdate) -> dict:
    conn = get_db()
    cur = conn.cursor()
    ensure_single_mitigation_entries(conn)
    cur.execute("SELECT * FROM mitigations WHERE id = %s", (item_id,))
    current_row = cur.fetchone()
    if not current_row:
        conn.close()
        raise HTTPException(status_code=404, detail="Mitigation not found")

    instruction_raw = payload.instruction if payload.instruction is not None else payload.description
    instruction_html = sanitize_instruction_html(instruction_raw or "")

    cur.execute(
        """
        UPDATE mitigations
        SET title = %s, description = %s, updated_at = NOW()
        WHERE id = %s
        """,
        (payload.title.strip(), instruction_html, item_id),
    )
    bump_version(conn, current_row["severity"])
    conn.commit()
    cur.execute("SELECT * FROM mitigations WHERE id = %s", (item_id,))
    row = cur.fetchone()
    conn.close()
    return mitigation_row_to_dict(row)


@app.delete("/api/mitigations/{item_id}")
def delete_mitigation(item_id: int) -> dict:
    raise HTTPException(
        status_code=405,
        detail="Mitigation deletion is locked. Exactly one mitigation entry must always exist per severity.",
    )


@app.post("/api/mitigations/restore/{severity}/{sent_version}")
def restore_mitigation_version(severity: str, sent_version: int) -> dict:
    severity_cap = normalize_severity(severity)
    conn = get_db()
    cur = conn.cursor()

    cur.execute(
        """
        SELECT title, description
        FROM mitigation_sent_items
        WHERE severity = %s AND sent_version = %s
        ORDER BY id ASC
        """,
        (severity_cap, int(sent_version)),
    )
    snapshot_rows = cur.fetchall()
    if not snapshot_rows:
        conn.close()
        raise HTTPException(status_code=404, detail="Requested mitigation version snapshot was not found")

    ensure_single_mitigation_entries(conn)
    cur.execute(
        """
        SELECT id
        FROM mitigations
        WHERE severity = %s
        ORDER BY id ASC
        """,
        (severity_cap,),
    )
    current_rows = cur.fetchall()
    latest_row = snapshot_rows[0]
    next_title = latest_row["title"] if latest_row else f"{severity_cap} mitigation"
    next_instruction = latest_row["description"] if latest_row else default_instruction_html(severity_cap)

    if current_rows:
        cur.execute(
            """
            UPDATE mitigations
            SET title = %s, description = %s, updated_at = NOW()
            WHERE id = %s
            """,
            (next_title, next_instruction, int(current_rows[0]["id"])),
        )
    else:
        cur.execute(
            """
            INSERT INTO mitigations (severity, slot_no, title, description)
            VALUES (%s, %s, %s, %s)
            """,
            (severity_cap, 1, next_title, next_instruction),
        )

    ensure_single_mitigation_entries(conn)
    bump_version(conn, severity_cap)
    log_activity(
        conn,
        None,
        f"Restored mitigation draft for {severity_cap} from sent version v{int(sent_version)}",
        "mitigation",
        None,
    )
    conn.commit()
    conn.close()
    return {
        "restored": True,
        "severity": severity_cap,
        "from_sent_version": int(sent_version),
    }


@app.get("/api/users")
def list_users() -> list[dict]:
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users ORDER BY id DESC")
    rows = cur.fetchall()
    conn.close()
    return [user_row_to_dict(r) for r in rows]


@app.get("/api/users/{user_id}")
def get_user(user_id: int) -> dict:
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    row = cur.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="User not found")
    return user_row_to_dict(row)


@app.post("/api/users", status_code=201)
def create_user(payload: UserCreate) -> dict:
    contact = normalize_contact_number(payload.contact_number)
    email = payload.email.strip().lower() if payload.email else None
    password_hash = hash_password(payload.password) if payload.password else None

    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO users (name, contact_number, email, password_hash, profile_image, role, source)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            """,
            (
                payload.name.strip(),
                contact,
                email,
                password_hash,
                payload.profile_image.strip() if payload.profile_image else None,
                payload.role,
                payload.source,
            ),
        )
        log_activity(conn, int(cur.lastrowid), "User account created", "user", int(cur.lastrowid))
        conn.commit()
        cur.execute("SELECT * FROM users WHERE id = %s", (cur.lastrowid,))
        row = cur.fetchone()
    except pymysql.err.IntegrityError:
        conn.close()
        raise HTTPException(status_code=409, detail="Contact number or email already exists")
    conn.close()
    return user_row_to_dict(row)


@app.post("/api/users/signup", status_code=201)
def signup_user(payload: SignupCreate) -> dict:
    create_payload = UserCreate(
        name=payload.name,
        contact_number=payload.contact_number,
        email=payload.email,
        password=payload.password,
        role=payload.role,
        source="signup"
        )
    return create_user(create_payload)


@app.post("/api/users/manual", status_code=201)
def create_user_manual(payload: ManualUserCreate) -> dict:
    if normalize_role(payload.actor_role) != "Superadmin":
        raise HTTPException(status_code=403, detail="Only Superadmin can manually add users")
    create_payload = UserCreate(
        name=payload.name,
        contact_number=payload.contact_number,
        email=payload.email,
        password=payload.password,
        role=payload.role,
        source="manual"
        )
    return create_user(create_payload)


@app.put("/api/users/{user_id}")
def update_user(user_id: int, payload: UserUpdate) -> dict:
    contact = normalize_contact_number(payload.contact_number)
    email = payload.email.strip().lower() if payload.email else None

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    existing = cur.fetchone()
    if not existing:
        conn.close()
        raise HTTPException(status_code=404, detail="User not found")

    try:
        cur.execute(
            """
            UPDATE users
            SET name = %s, contact_number = %s, email = %s,
                password_hash = COALESCE(%s, password_hash),
                profile_image = COALESCE(%s, profile_image),
                role = %s,
                updated_at = NOW()
            WHERE id = %s
            """,
            (
                payload.name.strip(),
                contact,
                email,
                hash_password(payload.password) if payload.password else None,
                payload.profile_image.strip() if payload.profile_image else None,
                payload.role,
                user_id,
            ),
        )
        conn.commit()
        cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        row = cur.fetchone()
    except pymysql.err.IntegrityError:
        conn.close()
        raise HTTPException(status_code=409, detail="Contact number or email already exists")

    conn.close()
    return user_row_to_dict(row)


@app.delete("/api/users/{user_id}")
def delete_user(user_id: int) -> dict:
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE id = %s", (user_id,))
    existing = cur.fetchone()
    if not existing:
        conn.close()
        raise HTTPException(status_code=404, detail="User not found")

    cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
    conn.commit()
    conn.close()
    return {"deleted": True, "id": user_id}


@app.get("/api/model-overview")
def list_model_overview(force_refresh: bool = Query(default=False)) -> dict:
    conn = get_db()
    refresh_meta = maybe_refresh_model_overview(conn, force=bool(force_refresh))
    items = list_model_overview_rows(conn)
    conn.close()
    return {
        "items": items,
        "refresh": refresh_meta,
    }


@app.get("/api/model-overview/{user_id}")
def get_model_overview_user(user_id: int) -> dict:
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT
            u.id AS user_id,
            u.name AS user_name,
            u.contact_number AS user_contact_number,
            u.role AS user_role,
            m.overall_accuracy,
            m.total_scans,
            m.average_confidence,
            m.last7_accuracy,
            m.last30_accuracy,
            m.trend_json,
            m.severity_distribution_json,
            m.confidence_distribution_json,
            m.top_issues_json,
            m.source,
            m.source_updated_at,
            m.fetched_at,
            m.updated_at
        FROM users u
        LEFT JOIN model_overview_records m ON m.user_id = u.id
        WHERE u.id = %s
        """,
        (int(user_id),),
    )
    row = cur.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="User not found")
    return model_overview_row_to_dict(row)


@app.post("/api/model-overview/refresh")
def refresh_model_overview() -> dict:
    conn = get_db()
    refresh_meta = maybe_refresh_model_overview(conn, force=True)
    items = list_model_overview_rows(conn)
    conn.close()
    return {
        "items": items,
        "refresh": refresh_meta,
    }


@app.post("/api/model-overview/report", status_code=201)
def report_model_overview(payload: ModelOverviewReport) -> dict:
    conn = get_db()
    cur = conn.cursor()

    accepted = 0
    skipped_user_ids: list[int] = []

    for item in payload.items:
        cur.execute("SELECT id FROM users WHERE id = %s", (int(item.user_id),))
        exists = cur.fetchone()
        if not exists:
            skipped_user_ids.append(int(item.user_id))
            continue
        upsert_model_overview(conn, item, source=payload.source)
        accepted += 1

    mark_model_overview_refresh(
        conn,
        status="ok",
        message=f"Stored {accepted} model overview rows from report.",
        success=True,
    )
    conn.commit()
    conn.close()

    return {
        "stored": accepted,
        "skipped_user_ids": skipped_user_ids,
        "message": "Model overview metrics saved.",
    }


@app.post("/api/auth/signup/request-otp")
def request_signup_otp(payload: SignupOtpRequest) -> dict:
    contact = normalize_ph_contact_number(payload.contact_number)
    email = payload.email.strip().lower() if payload.email else None

    conn = get_db()
    cur = conn.cursor()
    if cur.execute("SELECT 1 FROM users WHERE contact_number = %s", (contact,)):
        conn.close()
        raise HTTPException(
            status_code=409,
            detail="An existing account already uses this phone number. Please log in instead."
        )
    if email and cur.execute("SELECT 1 FROM users WHERE LOWER(email) = LOWER(%s)", (email,)):
        conn.close()
        raise HTTPException(status_code=409, detail="Email already exists")

    otp = f"{secrets.randbelow(1_000_000):06d}"
    otp_hash = hash_secret(otp)
    otp_salt, otp_digest = otp_hash.split("$", 1)
    password_hash = hash_password(payload.password)

    cur.execute("DELETE FROM user_signup_otps WHERE contact_number = %s", (contact,))
    cur.execute(
        """
        INSERT INTO user_signup_otps
            (contact_number, otp_hash, otp_salt, name, email, password_hash, role, expires_at)
        VALUES (%s, %s, %s, %s, %s, %s, %s, DATE_ADD(NOW(), INTERVAL %s SECOND))
        """,
        (
            contact,
            otp_digest,
            otp_salt,
            payload.name.strip(),
            email,
            password_hash,
            payload.role,
            int(OTP_TTL_SECONDS)
        )
        )
    conn.commit()
    conn.close()

    sms_sent, sms_provider, sms_error = send_sms_message(
        contact,
        f"Your MuScanAI verification code is {otp}. It expires in 5 minutes."
        )
    if not sms_sent:
        cleanup_conn = get_db()
        cleanup_conn.cursor().execute("DELETE FROM user_signup_otps WHERE contact_number = %s", (contact,))
        cleanup_conn.commit()
        cleanup_conn.close()
        raise HTTPException(
            status_code=503,
            detail=(
                f"OTP SMS delivery failed via {sms_provider}. "
                f"Reason: {sms_error}"
            ),
        )

    return {
        "sent": True,
        "message": "OTP sent to the provided mobile number.",
        "contact_number": contact,
        "delivery": "sms",
        "expires_in_seconds": OTP_TTL_SECONDS,
    }


@app.post("/api/auth/signup/request-otp-mobile")
def request_signup_mobile_otp(payload: SignupMobileOtpRequest) -> dict:
    contact = normalize_ph_contact_number(payload.contact_number)

    conn = get_db()
    cur = conn.cursor()

    if cur.execute("SELECT 1 FROM users WHERE contact_number = %s", (contact,)):
        conn.close()
        raise HTTPException(
            status_code=409,
            detail="An existing account already uses this phone number. Please log in instead.",
        )

    otp = f"{secrets.randbelow(1_000_000):06d}"
    otp_hash = hash_secret(otp)
    otp_salt, otp_digest = otp_hash.split("$", 1)

    cur.execute("DELETE FROM signup_otp_sessions WHERE contact_number = %s", (contact,))
    cur.execute(
        """
        INSERT INTO signup_otp_sessions
            (contact_number, otp_hash, otp_salt, expires_at)
        VALUES (%s, %s, %s, DATE_ADD(NOW(), INTERVAL %s SECOND))
        """,
        (contact, otp_digest, otp_salt, int(OTP_TTL_SECONDS)),
    )
    conn.commit()
    conn.close()

    sms_sent, sms_provider, sms_error = send_sms_message(
        contact,
        f"Your MuScanAI verification code is {otp}. It expires in 5 minutes.",
    )
    if not sms_sent:
        cleanup_conn = get_db()
        cleanup_conn.cursor().execute("DELETE FROM signup_otp_sessions WHERE contact_number = %s", (contact,))
        cleanup_conn.commit()
        cleanup_conn.close()
        raise HTTPException(
            status_code=503,
            detail=(
                f"OTP SMS delivery failed via {sms_provider}. "
                f"Reason: {sms_error}"
            ),
        )

    return {
        "sent": True,
        "message": "OTP sent to the provided mobile number.",
        "contact_number": contact,
        "delivery": "sms",
        "expires_in_seconds": OTP_TTL_SECONDS,
    }


@app.post("/api/auth/signup/verify-otp-mobile")
def verify_signup_mobile_otp(payload: SignupMobileOtpVerify) -> dict:
    contact = normalize_ph_contact_number(payload.contact_number)

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT * FROM signup_otp_sessions
        WHERE contact_number = %s
          AND expires_at > NOW()
        """,
        (contact,),
    )
    otp_row = cur.fetchone()
    if not otp_row:
        conn.close()
        raise HTTPException(status_code=400, detail="OTP expired or not found")

    if int(otp_row["attempts"]) >= 5:
        cur.execute("DELETE FROM signup_otp_sessions WHERE contact_number = %s", (contact,))
        conn.commit()
        conn.close()
        raise HTTPException(status_code=429, detail="Too many OTP attempts. Request a new OTP.")

    packed = f"{otp_row['otp_salt']}${otp_row['otp_hash']}"
    if not verify_secret(payload.otp, packed):
        cur.execute(
            "UPDATE signup_otp_sessions SET attempts = attempts + 1 WHERE contact_number = %s",
            (contact,),
        )
        conn.commit()
        conn.close()
        raise HTTPException(status_code=400, detail="Invalid OTP")

    otp_token = secrets.token_urlsafe(32)
    cur.execute(
        """
        UPDATE signup_otp_sessions
        SET verified_at = NOW(), otp_token = %s
        WHERE contact_number = %s
        """,
        (otp_token, contact),
    )
    conn.commit()
    conn.close()

    return {
        "verified": True,
        "message": "OTP verified. Continue with your profile details.",
        "otp_token": otp_token,
        "contact_number": contact,
    }


@app.post("/api/auth/signup/complete", status_code=201)
def complete_signup(payload: SignupCompleteRequest) -> dict:
    otp_token = payload.otp_token.strip()
    email = payload.email.strip().lower() if payload.email else None

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT * FROM signup_otp_sessions
        WHERE otp_token = %s
          AND verified_at IS NOT NULL
          AND expires_at > NOW()
        """,
        (otp_token,),
    )
    otp_row = cur.fetchone()
    if not otp_row:
        conn.close()
        raise HTTPException(status_code=400, detail="OTP verification session is invalid or expired")

    contact = otp_row["contact_number"]
    if cur.execute("SELECT 1 FROM users WHERE contact_number = %s", (contact,)):
        conn.close()
        raise HTTPException(status_code=409, detail="Account already exists")

    if email and cur.execute("SELECT 1 FROM users WHERE LOWER(email) = LOWER(%s)", (email,)):
        conn.close()
        raise HTTPException(status_code=409, detail="Email already exists")

    try:
        cur.execute(
            """
            INSERT INTO users (name, contact_number, email, password_hash, role, source)
            VALUES (%s, %s, %s, %s, %s, 'signup')
            """,
            (
                payload.name.strip(),
                contact,
                email,
                hash_password(payload.password),
                payload.role,
            ),
        )
        cur.execute("DELETE FROM signup_otp_sessions WHERE id = %s", (otp_row["id"],))
        token = create_session(conn, int(cur.lastrowid))
        cur.execute("SELECT * FROM users WHERE id = %s", (cur.lastrowid,))
        user = cur.fetchone()
    except pymysql.err.IntegrityError:
        conn.close()
        raise HTTPException(status_code=409, detail="Account already exists")

    conn.close()
    return {
        "registered": True,
        "token": token,
        "user": user_row_to_dict(user),
    }


@app.post("/api/auth/signup/verify-otp", status_code=201)
def verify_signup_otp(payload: SignupOtpVerify) -> dict:
    contact = normalize_ph_contact_number(payload.contact_number)

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT * FROM user_signup_otps
        WHERE contact_number = %s
          AND expires_at > NOW()
        """,
        (contact,),
    )
    otp_row = cur.fetchone()
    if not otp_row:
        conn.close()
        raise HTTPException(status_code=400, detail="OTP expired or not found")

    if int(otp_row["attempts"]) >= 5:
        cur.execute("DELETE FROM user_signup_otps WHERE contact_number = %s", (contact,))
        conn.commit()
        conn.close()
        raise HTTPException(status_code=429, detail="Too many OTP attempts. Request a new OTP.")

    packed = f"{otp_row['otp_salt']}${otp_row['otp_hash']}"
    if not verify_secret(payload.otp, packed):
        cur.execute(
            "UPDATE user_signup_otps SET attempts = attempts + 1 WHERE contact_number = %s",
            (contact,)
        )
        conn.commit()
        conn.close()
        raise HTTPException(status_code=400, detail="Invalid OTP")

    try:
        cur.execute(
            """
            INSERT INTO users (name, contact_number, email, password_hash, role, source)
            VALUES (%s, %s, %s, %s, %s, 'signup')
            """,
            (
                otp_row["name"],
                contact,
                otp_row["email"],
                otp_row["password_hash"],
                otp_row["role"]
        )
        )
        cur.execute("DELETE FROM user_signup_otps WHERE contact_number = %s", (contact,))
        token = create_session(conn, int(cur.lastrowid))
        cur.execute("SELECT * FROM users WHERE id = %s", (cur.lastrowid,))
        user = cur.fetchone()
    except pymysql.err.IntegrityError:
        conn.close()
        raise HTTPException(status_code=409, detail="Account already exists")

    conn.close()
    return {
        "registered": True,
        "token": token,
        "user": user_row_to_dict(user),
    }


@app.post("/api/auth/login")
def login(payload: LoginRequest) -> dict:
    contact = normalize_contact_number(payload.contact_number)
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT * FROM users WHERE contact_number = %s",
        (contact,),
    )
    user = cur.fetchone()
    if not user or not verify_secret(payload.password, user["password_hash"]):
        conn.close()
        raise HTTPException(status_code=401, detail="Invalid contact number or password")

    token = create_session(conn, int(user["id"]))
    log_activity(conn, int(user["id"]), "Logged in", "user", int(user["id"]))
    conn.commit()
    conn.close()
    return {"token": token, "user": user_row_to_dict(user)}


@app.post("/api/auth/session")
def validate_session(payload: SessionRequest) -> dict:
    conn = get_db()
    user = session_user(conn, payload.token.strip())
    if not user:
        conn.close()
        raise HTTPException(status_code=401, detail="Session expired or invalid")
    conn.close()
    return {"valid": True, "user": user_row_to_dict(user)}


@app.post("/api/auth/logout")
def logout(payload: SessionRequest) -> dict:
    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM user_sessions WHERE token = %s", (payload.token.strip(),))
    conn.commit()
    conn.close()
    return {"logged_out": True}

@app.post("/api/detections", status_code=201)
def create_detection(payload: DetectionCreate) -> dict:
    conn = get_db()
    cur = conn.cursor()

    cur.execute(
        """
        INSERT INTO detections (
            user_id, image_path, predicted_label, severity, confidence
        )
        VALUES (%s, %s, %s, %s, %s)
        """,
        (
            payload.user_id,
            payload.image_path.strip(),
            payload.predicted_label.strip(),
            payload.severity,
            payload.confidence,
        ),
    )

    detection_id = cur.lastrowid

    log_activity(
        conn,
        payload.user_id,
        f"Detection created: {payload.predicted_label}",
        "detection",
        int(detection_id)
        )

    conn.commit()

    cur.execute("SELECT * FROM detections WHERE id = %s", (detection_id,))
    row = cur.fetchone()

    conn.close()

    return dict(row)

@app.get("/api/detections")
def list_detections(user_id: int | None = None) -> list[dict]:
    conn = get_db()
    cur = conn.cursor()

    if user_id is None:
        cur.execute(
            """
            SELECT * FROM detections
            ORDER BY created_at DESC, id DESC
            """
        )
        rows = cur.fetchall()
    else:
        cur.execute(
            """
            SELECT * FROM detections
            WHERE user_id = %s
            ORDER BY created_at DESC, id DESC
            """,
            (user_id,),
        )
        rows = cur.fetchall()

    conn.close()
    return [dict(r) for r in rows]

@app.post("/api/remarks", status_code=201)
def create_remark(payload: RemarkCreate) -> dict:
    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT id FROM detections WHERE id = %s", (payload.detection_id,))
    detection = cur.fetchone()
    if not detection:
        conn.close()
        raise HTTPException(status_code=404, detail="Detection not found")

    cur.execute("SELECT id FROM users WHERE id = %s", (payload.user_id,))
    user = cur.fetchone()
    if not user:
        conn.close()
        raise HTTPException(status_code=404, detail="User not found")

    cur.execute(
        """
        INSERT INTO remarks (detection_id, user_id, remark)
        VALUES (%s, %s, %s)
        """,
        (
            payload.detection_id,
            payload.user_id,
            payload.remark.strip(),
        ),
    )

    remark_id = cur.lastrowid

    log_activity(
        conn,
        payload.user_id,
        "Added remark",
        "remark",
        int(remark_id)
        )

    conn.commit()

    cur.execute("SELECT * FROM remarks WHERE id = %s", (remark_id,))
    row = cur.fetchone()

    conn.close()
    return dict(row)

@app.get("/api/remarks/{detection_id}")
def list_remarks(detection_id: int) -> list[dict]:
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT * FROM remarks
        WHERE detection_id = %s
        ORDER BY created_at DESC, id DESC
        """,
        (detection_id,),
    )
    rows = cur.fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.post("/api/user-uploaded-content", status_code=201)
def upload_user_scan_content(payload: UploadedScanContentBatch) -> dict:
    conn = get_db()
    cur = conn.cursor()

    inserted = 0
    for item in payload.uploads:
        severity = item.severity.strip()
        if not severity:
            continue

        if item.user_id is not None:
            cur.execute("SELECT id FROM users WHERE id = %s", (int(item.user_id),))
            user_row = cur.fetchone()
            if not user_row:
                item_user_id = None
            else:
                item_user_id = int(item.user_id)
        else:
            item_user_id = None

        # Validate farm_id if provided
        item_farm_id = None
        if item.farm_id is not None:
            cur.execute("SELECT id FROM farm_entries WHERE id = %s", (int(item.farm_id),))
            farm_row = cur.fetchone()
            if farm_row:
                item_farm_id = int(item.farm_id)

        scanned_at_value = None
        if item.scanned_at:
            try:
                scanned_at_value = datetime.fromisoformat(item.scanned_at.replace("Z", "+00:00"))
            except ValueError:
                scanned_at_value = None

        cur.execute(
            """
            INSERT INTO user_uploaded_content (
                history_id,
                user_id,
                farm_id,
                image_uri,
                severity,
                mitigations_json,
                remark,
                scanned_at
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                item.history_id.strip(),
                item_user_id,
                item_farm_id,
                item.image_uri.strip(),
                severity,
                json.dumps([m.model_dump() for m in item.mitigations]),
                item.remark.strip(),
                scanned_at_value,
            ),
        )
        inserted += 1

    conn.commit()
    conn.close()
    return {"inserted": inserted}


@app.post("/api/upload-scan", status_code=201)
async def upload_scan_with_file(
    file: UploadFile | None = File(default=None),
    history_id: str | None = Form(default=None),
    user_id: int | None = Form(default=None),
    farm_id: int | None = Form(default=None),
    severity: str | None = Form(default=None),
    mitigations: str | None = Form(default=None),
    remark: str | None = Form(default=None),
    scanned_at: str | None = Form(default=None),
) -> dict:
    """Upload scan metadata without storing the scan image file."""
    if not severity or not severity.strip():
        raise HTTPException(status_code=400, detail="Severity is required")
    
    severity = severity.strip()
    
    # Validate severity
    if severity not in SEVERITIES:
        raise HTTPException(status_code=400, detail=f"Invalid severity: {severity}")
    
    try:
        if file is not None:
            await file.read()

        image_uri = ""
        
        # Insert into database
        conn = get_db()
        cur = conn.cursor()
        
        # Validate user_id if provided
        if user_id is not None:
            cur.execute("SELECT id FROM users WHERE id = %s", (int(user_id),))
            user_row = cur.fetchone()
            if not user_row:
                user_id = None
        
        # Validate farm_id if provided
        item_farm_id = None
        if farm_id is not None:
            cur.execute("SELECT id FROM farm_entries WHERE id = %s", (int(farm_id),))
            farm_row = cur.fetchone()
            if farm_row:
                item_farm_id = int(farm_id)
        
        # Parse scanned_at
        scanned_at_value = None
        if scanned_at:
            try:
                scanned_at_value = datetime.fromisoformat(scanned_at.replace("Z", "+00:00"))
            except ValueError:
                scanned_at_value = None
        
        # Parse mitigations JSON
        mitigations_json = "[]"
        if mitigations:
            try:
                mitigations_json = json.dumps(json.loads(mitigations))
            except (json.JSONDecodeError, TypeError):
                pass
        
        cur.execute(
            """
            INSERT INTO user_uploaded_content (
                history_id,
                user_id,
                farm_id,
                image_uri,
                severity,
                mitigations_json,
                remark,
                scanned_at
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                history_id.strip() if history_id else None,
                user_id,
                item_farm_id,
                image_uri,
                severity,
                mitigations_json,
                remark.strip() if remark else None,
                scanned_at_value,
            ),
        )
        
        conn.commit()
        conn.close()
        
        return {"uploaded": True, "image_uri": image_uri}
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"File upload failed: {str(e)}")


@app.post("/api/mitigation-image-upload")
async def upload_mitigation_image(file: UploadFile = File(...)) -> dict:
    if not file or not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")

    content_type = (file.content_type or "").lower()
    if not content_type.startswith("image/"):
        raise HTTPException(status_code=400, detail="Only image files are allowed")

    try:
        ext = Path(file.filename).suffix or ".jpg"
        filename = f"mitigation-{int(datetime.now().timestamp())*1000}-{secrets.token_hex(4)}{ext}"
        filepath = UPLOADS_DIR / filename

        with open(filepath, "wb") as buffer:
            buffer.write(await file.read())

        return {"uploaded": True, "url": f"/api/uploads/{filename}"}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Image upload failed: {str(exc)}")


@app.get("/api/user-uploaded-content")
def list_user_uploaded_content(search: str | None = Query(default=None)) -> list[dict]:
    conn = get_db()
    cur = conn.cursor()

    if search and search.strip():
        term = f"%{search.strip()}%"
        cur.execute(
            """
            SELECT
                uuc.id,
                uuc.history_id,
                uuc.user_id,
                uuc.image_uri,
                uuc.severity,
                uuc.mitigations_json,
                uuc.remark,
                uuc.scanned_at,
                uuc.uploaded_at,
                usr.name AS user_name,
                usr.contact_number AS user_contact
            FROM user_uploaded_content uuc
            LEFT JOIN users usr ON usr.id = uuc.user_id
            WHERE
                uuc.severity LIKE %s
                OR uuc.remark LIKE %s
                OR uuc.history_id LIKE %s
                OR usr.name LIKE %s
                OR usr.contact_number LIKE %s
            ORDER BY uuc.uploaded_at DESC, uuc.id DESC
            """,
            (term, term, term, term, term),
        )
    else:
        cur.execute(
            """
            SELECT
                uuc.id,
                uuc.history_id,
                uuc.user_id,
                uuc.image_uri,
                uuc.severity,
                uuc.mitigations_json,
                uuc.remark,
                uuc.scanned_at,
                uuc.uploaded_at,
                usr.name AS user_name,
                usr.contact_number AS user_contact
            FROM user_uploaded_content uuc
            LEFT JOIN users usr ON usr.id = uuc.user_id
            ORDER BY uuc.uploaded_at DESC, uuc.id DESC
            """
        )

    rows = cur.fetchall()
    conn.close()

    parsed: list[dict] = []
    for row in rows:
        try:
            mitigations = json.loads(row["mitigations_json"] or "[]")
        except json.JSONDecodeError:
            mitigations = []
        parsed.append(
            {
                "id": row["id"],
                "history_id": row["history_id"],
                "user_id": row["user_id"],
                "user_name": row["user_name"],
                "user_contact": row["user_contact"],
                "image_uri": row["image_uri"],
                "severity": row["severity"],
                "mitigations": mitigations,
                "remark": row["remark"],
                "scanned_at": row["scanned_at"],
                "uploaded_at": row["uploaded_at"],
            }
        )

    return parsed


@app.get("/api/library")
def list_library() -> list[dict]:
    conn = get_db()
    ensure_library_entry_versions(conn)
    cur = conn.cursor()
    cur.execute("SELECT * FROM library_entries ORDER BY modified_at DESC, id DESC")
    rows = cur.fetchall()
    conn.close()
    return [library_row_to_dict(r) for r in rows]


@app.get("/api/library/versions")
def library_versions() -> dict:
    conn = get_db()
    ensure_library_entry_versions(conn)
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, title, draft_version, sent_version, sent_at, sent_by
        FROM library_entries
        ORDER BY modified_at DESC, id DESC
        """
    )
    rows = cur.fetchall()
    conn.close()

    entries = [
        {
            "id": int(r["id"]),
            "title": r["title"],
            "draft_version": int(r.get("draft_version") or 1),
            "sent_version": int(r.get("sent_version") or 1),
            "pending": int(r.get("draft_version") or 1) > int(r.get("sent_version") or 1),
            "sent_at": r.get("sent_at"),
            "sent_by": r.get("sent_by"),
        }
        for r in rows
    ]

    return {
        "entries": entries,
        "pending_count": sum(1 for e in entries if e["pending"]),
    }


@app.get("/api/library/sync")
def sync_library() -> dict:
    conn = get_db()
    ensure_library_entry_versions(conn)
    cur = conn.cursor()

    cur.execute(
        """
        SELECT
            e.id,
            e.title AS live_title,
            e.body AS live_body,
            e.image AS live_image,
            e.created_at,
            e.modified_at,
            e.draft_version,
            e.sent_version,
            e.sent_at,
            e.sent_by,
            s.title AS sent_title,
            s.body AS sent_body,
            s.image AS sent_image,
            s.sent_at AS snapshot_sent_at
        FROM library_entries e
        LEFT JOIN library_entry_sent_items s
          ON s.library_id = e.id AND s.sent_version = e.sent_version
        ORDER BY e.modified_at DESC, e.id DESC
        """
    )
    rows = cur.fetchall()
    conn.close()

    items = [
        {
            "id": int(r["id"]),
            "title": r.get("sent_title") or r["live_title"],
            "body": r.get("sent_body") or r["live_body"],
            "image": r.get("sent_image") or r["live_image"],
            "created_at": r.get("snapshot_sent_at") or r.get("created_at"),
            "modified_at": r.get("modified_at"),
        }
        for r in rows
    ]

    draft_version = max([int(r.get("draft_version") or 1) for r in rows], default=1)
    sent_version = max([int(r.get("sent_version") or 1) for r in rows], default=1)
    pending = any(int(r.get("draft_version") or 1) > int(r.get("sent_version") or 1) for r in rows)
    latest_sent = max(
        [r for r in rows if r.get("sent_at")],
        key=lambda x: x.get("sent_at"),
        default=None,
    )

    return {
        "version": int(sent_version),
        "draft_version": int(draft_version),
        "pending": pending,
        "sent_at": latest_sent.get("sent_at") if latest_sent else None,
        "sent_by": latest_sent.get("sent_by") if latest_sent else None,
        "items": items,
    }

@app.post("/api/library/send/{entry_id}")
def send_library_version(entry_id: int, payload: LibrarySendRequest) -> dict:
    _ = normalize_role(payload.actor_role)

    conn = get_db()
    ensure_library_entry_versions(conn)
    cur = conn.cursor()
    cur.execute("SELECT * FROM library_entries WHERE id = %s", (entry_id,))
    existing = cur.fetchone()
    if not existing:
        conn.close()
        raise HTTPException(status_code=404, detail="Library entry not found")

    draft_version = int(existing.get("draft_version") or 1)
    sent_version = int(existing.get("sent_version") or 1)

    if int(draft_version) <= int(sent_version):
        conn.close()
        return {
            "sent": False,
            "library_id": int(entry_id),
            "draft_version": int(draft_version),
            "sent_version": int(sent_version),
            "message": "No newer library version to send.",
        }

    sent_by = f"{payload.actor_name.strip()} ({payload.actor_role})"
    cur.execute(
        """
        UPDATE library_entries
        SET sent_version = %s, sent_at = NOW(), sent_by = %s
        WHERE id = %s
        """,
        (int(draft_version), sent_by, int(entry_id)),
    )
    snapshot_library_version(conn, int(draft_version), int(entry_id))
    cur.execute(
        """
        INSERT INTO library_entry_send_logs (library_id, sent_version, sent_by)
        VALUES (%s, %s, %s)
        """,
        (int(entry_id), int(draft_version), sent_by),
    )
    conn.commit()
    cur.execute("SELECT * FROM library_entry_send_logs ORDER BY id DESC LIMIT 1")
    last_log = cur.fetchone()
    conn.close()

    return {
        "sent": True,
        "library_id": int(entry_id),
        "sent_version": int(draft_version),
        "sent_at": last_log["sent_at"] if last_log else None,
        "sent_by": last_log["sent_by"] if last_log else None,
    }


@app.post("/api/library/send")
def send_library_version_legacy(payload: LibrarySendRequest) -> dict:
    raise HTTPException(status_code=405, detail="Use /api/library/send/{entry_id} for per-entry version sending.")


@app.get("/api/library/send-history")
def library_send_history() -> list[dict]:
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT l.id, l.library_id, l.sent_version, l.sent_by, l.sent_at, e.title
        FROM library_entry_send_logs l
        LEFT JOIN library_entries e ON e.id = l.library_id
        ORDER BY l.id DESC
        """
    )
    rows = cur.fetchall()
    conn.close()
    return [
        {
            "id": r["id"],
            "library_id": int(r["library_id"]),
            "title": r.get("title") or f"Entry #{int(r['library_id'])}",
            "sent_version": int(r["sent_version"]),
            "sent_by": r["sent_by"],
            "sent_at": r["sent_at"],
        }
        for r in rows
    ]


@app.get("/api/library/archive")
def library_archive() -> list[dict]:
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT l.id, l.library_id, l.sent_version, l.sent_by, l.sent_at, e.title
        FROM library_entry_send_logs l
        LEFT JOIN library_entries e ON e.id = l.library_id
        ORDER BY l.id DESC
        """
    )
    versions = cur.fetchall()

    archived: list[dict] = []
    for v in versions:
        sent_version = int(v["sent_version"])
        library_id = int(v["library_id"])
        cur.execute(
            """
            SELECT title, body, image
            FROM library_entry_sent_items
            WHERE library_id = %s AND sent_version = %s
            ORDER BY id ASC
            """,
            (library_id, sent_version),
        )
        items = cur.fetchall()
        archived.append(
            {
                "source_library_id": library_id,
                "title": v.get("title") or f"Entry #{library_id}",
                "sent_version": sent_version,
                "sent_at": v["sent_at"],
                "sent_by": v["sent_by"],
                "items": [
                    {
                        "title": i["title"],
                        "body": i["body"],
                        "image": i["image"],
                        "source_library_id": library_id,
                    }
                    for i in items
                ],
            }
        )

    conn.close()
    return archived


@app.get("/api/library/{entry_id}")
def get_library_entry(entry_id: int) -> dict:
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM library_entries WHERE id = %s", (entry_id,))
    row = cur.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Library entry not found")
    return library_row_to_dict(row)


@app.post("/api/library", status_code=201)
def create_library_entry(payload: LibraryCreate) -> dict:
    enforce_superadmin(payload.actor_role)
    conn = get_db()
    cur = conn.cursor()
    body_html = sanitize_instruction_html(payload.body.strip())
    cur.execute(
        """
        INSERT INTO library_entries (title, body, image, draft_version, sent_version, sent_at, sent_by)
        VALUES (%s, %s, %s, 1, 1, NOW(), %s)
        """,
        (payload.title.strip(), body_html, payload.image.strip(), "System Seed"),
    )
    new_id = int(cur.lastrowid)
    snapshot_library_version(conn, 1, new_id)
    cur.execute(
        """
        INSERT INTO library_entry_send_logs (library_id, sent_version, sent_by)
        VALUES (%s, 1, %s)
        """,
        (new_id, "System Seed"),
    )
    log_activity(conn, None, "Created library entry", "library", int(cur.lastrowid))
    conn.commit()
    cur.execute("SELECT * FROM library_entries WHERE id = %s", (cur.lastrowid,))
    row = cur.fetchone()
    conn.close()
    return library_row_to_dict(row)


@app.put("/api/library/{entry_id}")
def update_library_entry(entry_id: int, payload: LibraryUpdate) -> dict:
    enforce_superadmin(payload.actor_role)

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM library_entries WHERE id = %s", (entry_id,))
    existing = cur.fetchone()
    if not existing:
        conn.close()
        raise HTTPException(status_code=404, detail="Library entry not found")

    body_html = sanitize_instruction_html(payload.body.strip())

    cur.execute(
        """
        UPDATE library_entries
        SET title = %s, body = %s, image = %s, modified_at = NOW()
        WHERE id = %s
        """,
        (payload.title.strip(), body_html, payload.image.strip(), entry_id),
    )
    bump_library_version(conn, entry_id)
    conn.commit()
    cur.execute("SELECT * FROM library_entries WHERE id = %s", (entry_id,))
    row = cur.fetchone()
    conn.close()
    return library_row_to_dict(row)


@app.delete("/api/library/{entry_id}")
def delete_library_entry(
    entry_id: int,
    actor_role: str = Query(..., description="Role performing the action")
        ) -> dict:
    enforce_superadmin(actor_role)

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id FROM library_entries WHERE id = %s", (entry_id,))
    existing = cur.fetchone()
    if not existing:
        conn.close()
        raise HTTPException(status_code=404, detail="Library entry not found")

    cur.execute("DELETE FROM library_entries WHERE id = %s", (entry_id,))
    conn.commit()
    conn.close()
    return {"deleted": True, "id": entry_id}


@app.get("/api/farms")
def list_farms() -> list[dict]:
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT
            f.id,
            f.farm_name,
            f.farm_address,
            f.farmer_user_id,
            f.geotag_id,
            f.created_at,
            f.modified_at,
            u.name AS farmer_name,
            u.contact_number AS farmer_contact_number
        FROM farm_entries f
        JOIN users u ON u.id = f.farmer_user_id
        ORDER BY f.modified_at DESC, f.id DESC
        """
    )
    rows = cur.fetchall()
    conn.close()
    return [farm_row_to_dict(r) for r in rows]


@app.get("/api/farms/{farm_id}")
def get_farm(farm_id: int) -> dict:
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT
            f.id,
            f.farm_name,
            f.farm_address,
            f.farmer_user_id,
            f.geotag_id,
            f.created_at,
            f.modified_at,
            u.name AS farmer_name,
            u.contact_number AS farmer_contact_number
        FROM farm_entries f
        JOIN users u ON u.id = f.farmer_user_id
        WHERE f.id = %s
        """,
        (farm_id,),
    )
    row = cur.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Farm entry not found")
    return farm_row_to_dict(row)


@app.post("/api/farms", status_code=201)
def create_farm(payload: FarmCreate) -> dict:
    _ = normalize_role(payload.actor_role)

    conn = get_db()
    ensure_farmer_user(conn, payload.farmer_user_id)
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO farm_entries (farm_name, farm_address, farmer_user_id, geotag_id)
        VALUES (%s, %s, %s, %s)
        """,
        (
            payload.farm_name.strip(),
            payload.farm_address.strip(),
            int(payload.farmer_user_id),
            payload.geotag_id.strip(),
        ),
    )
    log_activity(conn, None, "Created farm entry", "farm", int(cur.lastrowid))
    conn.commit()
    cur.execute(
        """
        SELECT
            f.id,
            f.farm_name,
            f.farm_address,
            f.farmer_user_id,
            f.geotag_id,
            f.created_at,
            f.modified_at,
            u.name AS farmer_name,
            u.contact_number AS farmer_contact_number
        FROM farm_entries f
        JOIN users u ON u.id = f.farmer_user_id
        WHERE f.id = %s
        """,
        (cur.lastrowid,),
    )
    row = cur.fetchone()
    conn.close()
    return farm_row_to_dict(row)


@app.put("/api/farms/{farm_id}")
def update_farm(farm_id: int, payload: FarmUpdate) -> dict:
    _ = normalize_role(payload.actor_role)

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id FROM farm_entries WHERE id = %s", (farm_id,))
    existing = cur.fetchone()
    if not existing:
        conn.close()
        raise HTTPException(status_code=404, detail="Farm entry not found")

    ensure_farmer_user(conn, payload.farmer_user_id)

    cur.execute(
        """
        UPDATE farm_entries
        SET farm_name = %s, farm_address = %s, farmer_user_id = %s, geotag_id = %s, modified_at = NOW()
        WHERE id = %s
        """,
        (
            payload.farm_name.strip(),
            payload.farm_address.strip(),
            int(payload.farmer_user_id),
            payload.geotag_id.strip(),
            farm_id,
        ),
    )
    log_activity(conn, None, "Updated farm entry", "farm", int(farm_id))
    conn.commit()
    cur.execute(
        """
        SELECT
            f.id,
            f.farm_name,
            f.farm_address,
            f.farmer_user_id,
            f.geotag_id,
            f.created_at,
            f.modified_at,
            u.name AS farmer_name,
            u.contact_number AS farmer_contact_number
        FROM farm_entries f
        JOIN users u ON u.id = f.farmer_user_id
        WHERE f.id = %s
        """,
        (farm_id,),
    )
    row = cur.fetchone()
    conn.close()
    return farm_row_to_dict(row)


@app.delete("/api/farms/{farm_id}")
def delete_farm(
    farm_id: int,
    actor_role: str = Query(..., description="Role performing the action")
        ) -> dict:
    _ = normalize_role(actor_role)

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id FROM farm_entries WHERE id = %s", (farm_id,))
    existing = cur.fetchone()
    if not existing:
        conn.close()
        raise HTTPException(status_code=404, detail="Farm entry not found")

    cur.execute("DELETE FROM farm_entries WHERE id = %s", (farm_id,))
    log_activity(conn, None, "Deleted farm entry", "farm", int(farm_id))
    conn.commit()
    conn.close()
    return {"deleted": True, "id": farm_id}


@app.get("/api/farms/current-user/{user_id}")
def list_user_farms(user_id: int) -> list[dict]:
    """Get all farms for a specific user (farmer)."""
    conn = get_db()
    cur = conn.cursor()
    
    # Verify user exists
    cur.execute("SELECT id FROM users WHERE id = %s", (user_id,))
    if not cur.fetchone():
        conn.close()
        raise HTTPException(status_code=404, detail="User not found")
    
    cur.execute(
        """
        SELECT
            f.id,
            f.farm_name,
            f.farm_address,
            f.farmer_user_id,
            f.geotag_id,
            f.created_at,
            f.modified_at,
            u.name AS farmer_name,
            u.contact_number AS farmer_contact_number
        FROM farm_entries f
        JOIN users u ON u.id = f.farmer_user_id
        WHERE f.farmer_user_id = %s
        ORDER BY f.created_at DESC, f.id DESC
        """,
        (user_id,),
    )
    rows = cur.fetchall()
    conn.close()
    return [farm_row_to_dict(r) for r in rows]


@app.post("/api/library-image-upload")
async def upload_library_image(file: UploadFile = File(...)) -> dict:
    if not file or not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")

    content_type = (file.content_type or "").lower()
    if not content_type.startswith("image/"):
        raise HTTPException(status_code=400, detail="Only image files are allowed")

    try:
        ext = Path(file.filename).suffix or ".jpg"
        filename = f"library-{int(datetime.now().timestamp())*1000}-{secrets.token_hex(4)}{ext}"
        filepath = UPLOADS_DIR / filename

        with open(filepath, "wb") as buffer:
            buffer.write(await file.read())

        return {"uploaded": True, "url": f"/api/uploads/{filename}"}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Image upload failed: {str(exc)}")

