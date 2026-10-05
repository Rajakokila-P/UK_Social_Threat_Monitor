import os
import sqlite3
import hashlib
import hmac
import secrets
from datetime import datetime


DATABASE_NAME = "data/threat_monitor.db"


def ensure_data_directory():
    os.makedirs("data", exist_ok=True)


# ---------------------------------------------------------
# MAIN DATABASE
# ---------------------------------------------------------

def create_database():
    ensure_data_directory()

    connection = sqlite3.connect(DATABASE_NAME)
    cursor = connection.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS analysed_posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            platform TEXT NOT NULL,
            username TEXT NOT NULL,
            display_name TEXT,
            public_location TEXT,
            original_text TEXT NOT NULL,
            translated_text TEXT,
            translation_status TEXT,
            language TEXT,
            uk_relevant INTEGER,
            severity TEXT,
            risk_score INTEGER,
            risk_level TEXT,
            risk_indicators TEXT,
            detected_terms TEXT,
            human_review_required INTEGER,
            case_status TEXT DEFAULT 'NEW',
            analyst_notes TEXT,
            stored_filename TEXT,
            stored_path TEXT,
            content_type TEXT,
            file_size INTEGER,
            extracted_location TEXT,
            media_metadata TEXT,
            face_detection_summary TEXT,
            deleted_at TEXT,
            deleted_by TEXT,
            created_at TEXT NOT NULL
        )
        """
    )

    required_columns = {
        "display_name": "TEXT",
        "public_location": "TEXT",
        "translated_text": "TEXT",
        "translation_status": "TEXT",
        "language": "TEXT",
        "uk_relevant": "INTEGER",
        "severity": "TEXT",
        "risk_score": "INTEGER",
        "risk_level": "TEXT",
        "risk_indicators": "TEXT",
        "detected_terms": "TEXT",
        "human_review_required": "INTEGER",
        "case_status": "TEXT DEFAULT 'NEW'",
        "analyst_notes": "TEXT",
        "stored_filename": "TEXT",
        "stored_path": "TEXT",
        "content_type": "TEXT",
        "file_size": "INTEGER",
        "extracted_location": "TEXT",
        "media_metadata": "TEXT",
        "face_detection_summary": "TEXT",
        "deleted_at": "TEXT",
        "deleted_by": "TEXT",
        "created_at": "TEXT",
    }

    cursor.execute(
        "PRAGMA table_info(analysed_posts)"
    )

    existing_columns = {
        row[1]
        for row in cursor.fetchall()
    }

    for column_name, column_type in required_columns.items():
        if column_name not in existing_columns:
            cursor.execute(
                f"""
                ALTER TABLE analysed_posts
                ADD COLUMN {column_name} {column_type}
                """
            )

    connection.commit()
    connection.close()


# ---------------------------------------------------------
# USERS / AUTHENTICATION
# ---------------------------------------------------------

def create_users_table():
    ensure_data_directory()

    connection = sqlite3.connect(DATABASE_NAME)
    cursor = connection.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'ANALYST',
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            last_login TEXT,
            first_name TEXT,
            surname TEXT,
            id_number TEXT,
            email TEXT,
            phone_number TEXT
        )
        """
    )


    cursor.execute(
        "PRAGMA table_info(users)"
    )

    existing_columns = {
        row[1]
        for row in cursor.fetchall()
    }

    profile_columns = {
        "first_name": "TEXT",
        "surname": "TEXT",
        "id_number": "TEXT",
        "email": "TEXT",
        "phone_number": "TEXT",
    }

    for column_name, column_type in profile_columns.items():
        if column_name not in existing_columns:
            cursor.execute(
                f"""
                ALTER TABLE users
                ADD COLUMN {column_name} {column_type}
                """
            )

    connection.commit()
    connection.close()


def create_audit_log_table():
    ensure_data_directory()

    connection = sqlite3.connect(DATABASE_NAME)
    cursor = connection.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS security_audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            action TEXT NOT NULL,
            details TEXT,
            created_at TEXT NOT NULL
        )
        """
    )

    connection.commit()
    connection.close()


def hash_password(password: str):
    salt = secrets.token_hex(32)

    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        600000,
    ).hex()

    return f"{salt}${password_hash}"


def verify_password(
    password: str,
    stored_password_hash: str,
):
    try:
        salt, stored_hash = (
            stored_password_hash.split("$", 1)
        )
    except ValueError:
        return False

    test_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        600000,
    ).hex()

    return hmac.compare_digest(
        stored_hash,
        test_hash,
    )


def create_user(
    username: str,
    password: str,
    role: str = "ANALYST",
):
    allowed_roles = {
        "ADMIN",
        "SENIOR_ANALYST",
        "ANALYST",
        "VIEWER",
    }

    username = username.strip()
    role = role.upper().strip()

    if not username:
        return {
            "success": False,
            "message": "Username is required",
        }

    if len(password) < 12:
        return {
            "success": False,
            "message":
                "Password must be at least 12 characters",
        }

    if role not in allowed_roles:
        return {
            "success": False,
            "message": "Invalid user role",
        }

    password_hash = hash_password(password)

    connection = sqlite3.connect(DATABASE_NAME)
    cursor = connection.cursor()

    try:
        cursor.execute(
            """
            INSERT INTO users (
                username,
                password_hash,
                role,
                is_active,
                created_at
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                username,
                password_hash,
                role,
                1,
                datetime.utcnow().isoformat(),
            ),
        )

        connection.commit()

    except sqlite3.IntegrityError:
        connection.close()

        return {
            "success": False,
            "message": "Username already exists",
        }

    connection.close()

    return {
        "success": True,
        "username": username,
        "role": role,
    }


def get_user_by_username(username: str):
    connection = sqlite3.connect(DATABASE_NAME)
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            id,
            username,
            password_hash,
            role,
            is_active,
            created_at,
            last_login,
            first_name,
            surname,
            id_number,
            email,
            phone_number
        FROM users
        WHERE username = ?
        """,
        (username,),
    )

    row = cursor.fetchone()
    connection.close()

    if row is None:
        return None

    return {
        "id": row["id"],
        "username": row["username"],
        "password_hash": row["password_hash"],
        "role": row["role"],
        "is_active": bool(row["is_active"]),
        "created_at": row["created_at"],
        "last_login": row["last_login"],
        "first_name": row["first_name"],
        "surname": row["surname"],
        "id_number": row["id_number"],
        "email": row["email"],
        "phone_number": row["phone_number"],
    }


def authenticate_user(
    username: str,
    password: str,
):
    user = get_user_by_username(username)

    if user is None:
        return None

    if not user["is_active"]:
        return None

    if not verify_password(
        password,
        user["password_hash"],
    ):
        return None

    connection = sqlite3.connect(
        DATABASE_NAME
    )
    cursor = connection.cursor()

    last_login = datetime.utcnow().isoformat()

    cursor.execute(
        """
        UPDATE users
        SET last_login = ?
        WHERE id = ?
        """,
        (
            last_login,
            user["id"],
        ),
    )

    connection.commit()
    connection.close()

    return {
        "id": user["id"],
        "username": user["username"],
        "role": user["role"],
    }


def log_security_event(
    username,
    action,
    details=None,
):
    connection = sqlite3.connect(
        DATABASE_NAME
    )
    cursor = connection.cursor()

    cursor.execute(
        """
        INSERT INTO security_audit_log (
            username,
            action,
            details,
            created_at
        )
        VALUES (?, ?, ?, ?)
        """,
        (
            username,
            action,
            details,
            datetime.utcnow().isoformat(),
        ),
    )

    connection.commit()
    connection.close()


def get_security_audit_log():
    connection = sqlite3.connect(
        DATABASE_NAME
    )
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            id,
            username,
            action,
            details,
            created_at
        FROM security_audit_log
        ORDER BY id DESC
        """
    )

    rows = cursor.fetchall()
    connection.close()

    return [
        {
            "id": row["id"],
            "username": row["username"],
            "action": row["action"],
            "details": row["details"],
            "created_at": row["created_at"],
        }
        for row in rows
    ]





# ---------------------------------------------------------
# PASSWORD RECOVERY
# ---------------------------------------------------------

def reset_password_with_email(
    username: str,
    email: str,
    new_password: str,
):
    username = username.strip()
    email = email.strip().lower()

    if not username or not email:
        return {
            "success": False,
            "message": "Invalid recovery details",
        }

    if len(new_password) < 12:
        return {
            "success": False,
            "message": "Password must be at least 12 characters",
        }

    connection = sqlite3.connect(DATABASE_NAME)
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT id, username, email, is_active
        FROM users
        WHERE username = ?
        """,
        (username,),
    )

    row = cursor.fetchone()

    if (
        row is None
        or not bool(row["is_active"])
        or not row["email"]
        or row["email"].strip().lower() != email
    ):
        connection.close()
        return {
            "success": False,
            "message": "Invalid recovery details",
        }

    new_hash = hash_password(new_password)

    cursor.execute(
        """
        UPDATE users
        SET password_hash = ?
        WHERE id = ?
        """,
        (new_hash, row["id"]),
    )

    connection.commit()
    connection.close()

    return {
        "success": True,
        "username": row["username"],
    }

# ---------------------------------------------------------
# USER PROFILE
# ---------------------------------------------------------

def get_user_profile(user_id: int):
    connection = sqlite3.connect(DATABASE_NAME)
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            id,
            username,
            role,
            first_name,
            surname,
            id_number,
            email,
            phone_number
        FROM users
        WHERE id = ?
        """,
        (user_id,),
    )

    row = cursor.fetchone()
    connection.close()

    if row is None:
        return None

    return {
        "id": row["id"],
        "username": row["username"],
        "role": row["role"],
        "first_name": row["first_name"] or "",
        "surname": row["surname"] or "",
        "id_number": row["id_number"] or "",
        "email": row["email"] or "",
        "phone_number": row["phone_number"] or "",
    }


def update_user_profile(
    user_id: int,
    first_name: str,
    surname: str,
    id_number: str,
    email: str,
    phone_number: str,
):
    connection = sqlite3.connect(DATABASE_NAME)
    cursor = connection.cursor()

    cursor.execute(
        """
        UPDATE users
        SET
            first_name = ?,
            surname = ?,
            id_number = ?,
            email = ?,
            phone_number = ?
        WHERE id = ?
        """,
        (
            first_name.strip(),
            surname.strip(),
            id_number.strip(),
            email.strip(),
            phone_number.strip(),
            user_id,
        ),
    )

    connection.commit()
    updated = cursor.rowcount > 0
    connection.close()

    if not updated:
        return {
            "success": False,
            "message": "User not found",
        }

    return {
        "success": True,
        "message": "Personal details updated successfully",
    }


# ---------------------------------------------------------
# CASE STATUS HISTORY
# ---------------------------------------------------------

def create_status_history_table():
    ensure_data_directory()

    connection = sqlite3.connect(DATABASE_NAME)
    cursor = connection.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS case_status_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            record_id INTEGER NOT NULL,
            old_status TEXT,
            new_status TEXT NOT NULL,
            changed_at TEXT NOT NULL
        )
        """
    )

    connection.commit()
    connection.close()


# ---------------------------------------------------------
# ANALYST NOTE HISTORY
# ---------------------------------------------------------

def create_analyst_note_history_table():
    ensure_data_directory()

    connection = sqlite3.connect(DATABASE_NAME)
    cursor = connection.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS analyst_note_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            record_id INTEGER NOT NULL,
            old_notes TEXT,
            new_notes TEXT,
            changed_at TEXT NOT NULL
        )
        """
    )

    connection.commit()
    connection.close()


# ---------------------------------------------------------
# SAVE ANALYSIS
# ---------------------------------------------------------

def save_analysis(
    platform,
    username,
    display_name,
    public_location,
    original_text,
    translated_text,
    translation_status,
    language,
    uk_relevant,
    severity,
    risk_score,
    risk_level,
    risk_indicators,
    detected_terms,
    human_review_required,
):
    ensure_data_directory()

    connection = sqlite3.connect(DATABASE_NAME)
    cursor = connection.cursor()

    cursor.execute(
        """
        INSERT INTO analysed_posts (
            platform,
            username,
            display_name,
            public_location,
            original_text,
            translated_text,
            translation_status,
            language,
            uk_relevant,
            severity,
            risk_score,
            risk_level,
            risk_indicators,
            detected_terms,
            human_review_required,
            case_status,
            analyst_notes,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            platform,
            username,
            display_name,
            public_location,
            original_text,
            translated_text,
            translation_status,
            language,
            int(uk_relevant),
            severity,
            risk_score,
            risk_level,
            ",".join(
                risk_indicators or []
            ),
            ",".join(
                detected_terms or []
            ),
            int(
                human_review_required
            ),
            "NEW",
            "",
            datetime.utcnow().isoformat(),
        ),
    )

    connection.commit()
    connection.close()


# ---------------------------------------------------------
# GET ALL RECORDS
# ---------------------------------------------------------

def get_all_records():
    connection = sqlite3.connect(DATABASE_NAME)
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            id,
            platform,
            username,
            display_name,
            public_location,
            original_text,
            translated_text,
            translation_status,
            language,
            uk_relevant,
            severity,
            risk_score,
            risk_level,
            risk_indicators,
            detected_terms,
            human_review_required,
            case_status,
            analyst_notes,
            stored_filename,
            stored_path,
            content_type,
            file_size,
            extracted_location,
            media_metadata,
            face_detection_summary,
            created_at
        FROM analysed_posts
        ORDER BY id DESC
        """
    )

    rows = cursor.fetchall()
    connection.close()

    records = []

    for row in rows:
        records.append(
            {
                "id": row["id"],
                "platform": row["platform"],
                "username": row["username"],
                "display_name": row["display_name"],
                "public_location": row["public_location"],
                "original_text": row["original_text"],
                "translated_text": row["translated_text"],
                "translation_status": row["translation_status"],
                "language": row["language"],
                "uk_relevant": bool(
                    row["uk_relevant"]
                ),
                "severity": row["severity"],
                "risk_score": row["risk_score"],
                "risk_level": row["risk_level"],
                "risk_indicators": (
                    row["risk_indicators"].split(",")
                    if row["risk_indicators"]
                    else []
                ),
                "detected_terms": (
                    row["detected_terms"].split(",")
                    if row["detected_terms"]
                    else []
                ),
                "human_review_required": bool(
                    row[
                        "human_review_required"
                    ]
                ),
                "case_status": row["case_status"],
                "analyst_notes": row["analyst_notes"],
                "created_at": row["created_at"],
            }
        )

    return records


# ---------------------------------------------------------
# DATABASE MIGRATIONS
# ---------------------------------------------------------

def add_translation_columns():
    connection = sqlite3.connect(DATABASE_NAME)
    cursor = connection.cursor()

    try:
        cursor.execute(
            """
            ALTER TABLE analysed_posts
            ADD COLUMN translated_text TEXT
            """
        )
    except sqlite3.OperationalError:
        pass

    try:
        cursor.execute(
            """
            ALTER TABLE analysed_posts
            ADD COLUMN translation_status TEXT
            """
        )
    except sqlite3.OperationalError:
        pass

    connection.commit()
    connection.close()


def add_risk_columns():
    connection = sqlite3.connect(DATABASE_NAME)
    cursor = connection.cursor()

    columns = [
        (
            "risk_score",
            "INTEGER",
        ),
        (
            "risk_level",
            "TEXT",
        ),
        (
            "risk_indicators",
            "TEXT",
        ),
    ]

    for column_name, column_type in columns:
        try:
            cursor.execute(
                f"""
                ALTER TABLE analysed_posts
                ADD COLUMN {column_name} {column_type}
                """
            )
        except sqlite3.OperationalError:
            pass

    connection.commit()
    connection.close()


def add_case_status_column():
    connection = sqlite3.connect(DATABASE_NAME)
    cursor = connection.cursor()

    try:
        cursor.execute(
            """
            ALTER TABLE analysed_posts
            ADD COLUMN case_status TEXT DEFAULT 'NEW'
            """
        )
    except sqlite3.OperationalError:
        pass

    connection.commit()
    connection.close()


def add_analyst_notes_column():
    connection = sqlite3.connect(DATABASE_NAME)
    cursor = connection.cursor()

    try:
        cursor.execute(
            """
            ALTER TABLE analysed_posts
            ADD COLUMN analyst_notes TEXT
            """
        )
    except sqlite3.OperationalError:
        pass

    connection.commit()
    connection.close()


# ---------------------------------------------------------
# PRIORITY RECORDS
# ---------------------------------------------------------

def get_priority_records():
    connection = sqlite3.connect(DATABASE_NAME)
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            id,
            platform,
            username,
            display_name,
            public_location,
            original_text,
            translated_text,
            translation_status,
            language,
            uk_relevant,
            severity,
            risk_score,
            risk_level,
            risk_indicators,
            detected_terms,
            human_review_required,
            case_status,
            analyst_notes,
            stored_filename,
            stored_path,
            content_type,
            file_size,
            extracted_location,
            media_metadata,
            face_detection_summary,
            created_at
        FROM analysed_posts
        WHERE risk_level IN (
            'high',
            'critical'
        )
        ORDER BY
            risk_score DESC,
            id DESC
        """
    )

    rows = cursor.fetchall()
    connection.close()

    records = []

    for row in rows:
        records.append(
            {
                "id": row["id"],
                "platform": row["platform"],
                "username": row["username"],
                "display_name": row["display_name"],
                "public_location": row["public_location"],
                "original_text": row["original_text"],
                "translated_text": row["translated_text"],
                "translation_status": row["translation_status"],
                "language": row["language"],
                "uk_relevant": bool(
                    row["uk_relevant"]
                ),
                "severity": row["severity"],
                "risk_score": row["risk_score"],
                "risk_level": row["risk_level"],
                "risk_indicators": (
                    row[
                        "risk_indicators"
                    ].split(",")
                    if row[
                        "risk_indicators"
                    ]
                    else []
                ),
                "detected_terms": (
                    row[
                        "detected_terms"
                    ].split(",")
                    if row[
                        "detected_terms"
                    ]
                    else []
                ),
                "human_review_required": bool(
                    row[
                        "human_review_required"
                    ]
                ),
                "case_status": row["case_status"],
                "analyst_notes": row["analyst_notes"],
                "created_at": row["created_at"],
            }
        )

    return records


# ---------------------------------------------------------
# UPDATE CASE STATUS
# ---------------------------------------------------------

def update_case_status(
    record_id: int,
    new_status: str,
):
    allowed_statuses = {
        "NEW",
        "UNDER_REVIEW",
        "MONITORING",
        "ESCALATED",
        "CLOSED",
        "FALSE_POSITIVE",
    }

    new_status = new_status.upper()

    if new_status not in allowed_statuses:
        return {
            "success": False,
            "message":
                "Invalid case status",
        }

    connection = sqlite3.connect(DATABASE_NAME)
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT case_status
        FROM analysed_posts
        WHERE id = ?
        """,
        (record_id,),
    )

    row = cursor.fetchone()

    if row is None:
        connection.close()

        return {
            "success": False,
            "message":
                "Record not found",
        }

    old_status = row[0]

    cursor.execute(
        """
        UPDATE analysed_posts
        SET case_status = ?
        WHERE id = ?
        """,
        (
            new_status,
            record_id,
        ),
    )

    cursor.execute(
        """
        INSERT INTO case_status_history (
            record_id,
            old_status,
            new_status,
            changed_at
        )
        VALUES (?, ?, ?, ?)
        """,
        (
            record_id,
            old_status,
            new_status,
            datetime.utcnow().isoformat(),
        ),
    )

    connection.commit()
    connection.close()

    return {
        "success": True,
        "record_id": record_id,
        "old_status": old_status,
        "case_status": new_status,
    }


def get_case_status_history(
    record_id: int,
):
    connection = sqlite3.connect(DATABASE_NAME)
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            id,
            record_id,
            old_status,
            new_status,
            changed_at
        FROM case_status_history
        WHERE record_id = ?
        ORDER BY id DESC
        """,
        (record_id,),
    )

    rows = cursor.fetchall()
    connection.close()

    return [
        {
            "id": row["id"],
            "record_id":
                row["record_id"],
            "old_status":
                row["old_status"],
            "new_status":
                row["new_status"],
            "changed_at":
                row["changed_at"],
        }
        for row in rows
    ]


# ---------------------------------------------------------
# ANALYST NOTES
# ---------------------------------------------------------

def update_analyst_notes(
    record_id: int,
    analyst_notes: str,
):
    connection = sqlite3.connect(DATABASE_NAME)
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT analyst_notes
        FROM analysed_posts
        WHERE id = ?
        """,
        (record_id,),
    )

    row = cursor.fetchone()

    if row is None:
        connection.close()

        return {
            "success": False,
            "message":
                "Record not found",
        }

    old_notes = row[0] or ""

    cursor.execute(
        """
        UPDATE analysed_posts
        SET analyst_notes = ?
        WHERE id = ?
        """,
        (
            analyst_notes,
            record_id,
        ),
    )

    cursor.execute(
        """
        INSERT INTO analyst_note_history (
            record_id,
            old_notes,
            new_notes,
            changed_at
        )
        VALUES (?, ?, ?, ?)
        """,
        (
            record_id,
            old_notes,
            analyst_notes,
            datetime.utcnow().isoformat(),
        ),
    )

    connection.commit()
    connection.close()

    return {
        "success": True,
        "record_id": record_id,
        "analyst_notes":
            analyst_notes,
    }


def get_analyst_note_history(
    record_id: int,
):
    connection = sqlite3.connect(DATABASE_NAME)
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            id,
            record_id,
            old_notes,
            new_notes,
            changed_at
        FROM analyst_note_history
        WHERE record_id = ?
        ORDER BY id DESC
        """,
        (record_id,),
    )

    rows = cursor.fetchall()
    connection.close()

    return [
        {
            "id": row["id"],
            "record_id": row["record_id"],
            "old_notes": row["old_notes"],
            "new_notes": row["new_notes"],
            "changed_at": row["changed_at"],
        }
        for row in rows
    ]


# ---------------------------------------------------------
# SOCIAL EVIDENCE
# ---------------------------------------------------------

def create_social_evidence_table():
    ensure_data_directory()

    connection = sqlite3.connect(DATABASE_NAME)
    cursor = connection.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS social_evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            evidence_id TEXT NOT NULL UNIQUE,
            platform TEXT NOT NULL,
            source_url TEXT,
            public_username TEXT,
            public_profile_url TEXT,
            post_text TEXT,
            public_location TEXT,
            observed_at TEXT,
            evidence_type TEXT NOT NULL,
            original_filename TEXT,
            sha256_hash TEXT,
            case_id INTEGER,
            submitted_by TEXT,
            status TEXT NOT NULL DEFAULT 'NEW',
            analyst_notes TEXT,
            stored_filename TEXT,
            stored_path TEXT,
            content_type TEXT,
            file_size INTEGER,
            extracted_location TEXT,
            media_metadata TEXT,
            face_detection_summary TEXT,
            deleted_at TEXT,
            deleted_by TEXT,
            created_at TEXT NOT NULL
        )
        """
    )

    cursor.execute(
        "PRAGMA table_info(social_evidence)"
    )

    existing_columns = {
        row[1]
        for row in cursor.fetchall()
    }

    evidence_columns = {
        "stored_filename": "TEXT",
        "stored_path": "TEXT",
        "content_type": "TEXT",
        "file_size": "INTEGER",
        "extracted_location": "TEXT",
        "media_metadata": "TEXT",
        "face_detection_summary": "TEXT",
        "deleted_at": "TEXT",
        "deleted_by": "TEXT",
    }

    for column_name, column_type in evidence_columns.items():
        if column_name not in existing_columns:
            cursor.execute(
                f"""
                ALTER TABLE social_evidence
                ADD COLUMN {column_name} {column_type}
                """
            )

    connection.commit()
    connection.close()


def create_evidence_audit_log_table():
    ensure_data_directory()

    connection = sqlite3.connect(DATABASE_NAME)
    cursor = connection.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS evidence_audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            evidence_id TEXT NOT NULL,
            username TEXT,
            action TEXT NOT NULL,
            details TEXT,
            created_at TEXT NOT NULL
        )
        """
    )

    connection.commit()
    connection.close()


def generate_evidence_id():
    timestamp = datetime.utcnow().strftime(
        "%Y%m%d%H%M%S"
    )

    random_part = secrets.token_hex(4).upper()

    return f"EVD-{timestamp}-{random_part}"


def calculate_sha256(file_path):
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        for chunk in iter(
            lambda: file.read(1024 * 1024),
            b"",
        ):
            sha256.update(chunk)

    return sha256.hexdigest()


def create_social_evidence(
    platform,
    source_url=None,
    public_username=None,
    public_profile_url=None,
    post_text=None,
    public_location=None,
    observed_at=None,
    evidence_type="TEXT",
    original_filename=None,
    sha256_hash=None,
    case_id=None,
    submitted_by=None,
    status="NEW",
    analyst_notes=None,
    stored_filename=None,
    stored_path=None,
    content_type=None,
    file_size=None,
    extracted_location=None,
    media_metadata=None,
    face_detection_summary=None,
):
    ensure_data_directory()

    evidence_id = generate_evidence_id()

    connection = sqlite3.connect(
        DATABASE_NAME
    )
    cursor = connection.cursor()

    cursor.execute(
        """
        INSERT INTO social_evidence (
            evidence_id,
            platform,
            source_url,
            public_username,
            public_profile_url,
            post_text,
            public_location,
            observed_at,
            evidence_type,
            original_filename,
            sha256_hash,
            case_id,
            submitted_by,
            status,
            analyst_notes,
            stored_filename,
            stored_path,
            content_type,
            file_size,
            extracted_location,
            media_metadata,
            face_detection_summary,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            evidence_id,
            platform,
            source_url,
            public_username,
            public_profile_url,
            post_text,
            public_location,
            observed_at,
            evidence_type,
            original_filename,
            sha256_hash,
            case_id,
            submitted_by,
            status,
            analyst_notes,
            stored_filename,
            stored_path,
            content_type,
            file_size,
            extracted_location,
            media_metadata,
            face_detection_summary,
            datetime.utcnow().isoformat(),
        ),
    )

    connection.commit()
    connection.close()

    return {
        "success": True,
        "evidence_id": evidence_id,
    }


def get_social_evidence(
    evidence_id
):
    connection = sqlite3.connect(
        DATABASE_NAME
    )

    connection.row_factory = sqlite3.Row

    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            id,
            evidence_id,
            platform,
            source_url,
            public_username,
            public_profile_url,
            post_text,
            public_location,
            observed_at,
            evidence_type,
            original_filename,
            sha256_hash,
            case_id,
            submitted_by,
            status,
            analyst_notes,
            stored_filename,
            stored_path,
            content_type,
            file_size,
            extracted_location,
            media_metadata,
            face_detection_summary,
            created_at
        FROM social_evidence
        WHERE evidence_id = ?
        """,
        (evidence_id,),
    )

    row = cursor.fetchone()

    connection.close()

    if row is None:
        return None

    return dict(row)


def get_all_social_evidence():
    connection = sqlite3.connect(
        DATABASE_NAME
    )

    connection.row_factory = sqlite3.Row

    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            id,
            evidence_id,
            platform,
            source_url,
            public_username,
            public_profile_url,
            post_text,
            public_location,
            observed_at,
            evidence_type,
            original_filename,
            sha256_hash,
            case_id,
            submitted_by,
            status,
            analyst_notes,
            stored_filename,
            stored_path,
            content_type,
            file_size,
            extracted_location,
            media_metadata,
            face_detection_summary,
            created_at
        FROM social_evidence
        WHERE deleted_at IS NULL
        ORDER BY id DESC
        """
    )

    rows = cursor.fetchall()

    connection.close()

    return [
        dict(row)
        for row in rows
    ]


def get_deleted_social_evidence():
    connection = sqlite3.connect(
        DATABASE_NAME
    )

    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            id,
            evidence_id,
            platform,
            source_url,
            public_username,
            public_profile_url,
            post_text,
            public_location,
            observed_at,
            evidence_type,
            original_filename,
            sha256_hash,
            case_id,
            submitted_by,
            status,
            analyst_notes,
            stored_filename,
            stored_path,
            content_type,
            file_size,
            extracted_location,
            media_metadata,
            face_detection_summary,
            deleted_at,
            deleted_by,
            created_at
        FROM social_evidence
        WHERE deleted_at IS NOT NULL
        ORDER BY deleted_at DESC
        """
    )

    rows = cursor.fetchall()
    connection.close()

    return [
        dict(row)
        for row in rows
    ]


def soft_delete_social_evidence(
    evidence_id,
    deleted_by,
):
    connection = sqlite3.connect(
        DATABASE_NAME
    )
    cursor = connection.cursor()

    cursor.execute(
        """
        UPDATE social_evidence
        SET
            deleted_at = ?,
            deleted_by = ?,
            status = ?
        WHERE evidence_id = ?
        """,
        (
            datetime.utcnow().isoformat(),
            deleted_by,
            "RECOVERABLE_DELETED",
            evidence_id,
        ),
    )

    updated = cursor.rowcount > 0
    connection.commit()
    connection.close()

    if not updated:
        return {
            "success": False,
            "message": "Evidence not found",
        }

    return {
        "success": True,
        "evidence_id": evidence_id,
    }


def restore_social_evidence(
    evidence_id,
):
    connection = sqlite3.connect(
        DATABASE_NAME
    )
    cursor = connection.cursor()

    cursor.execute(
        """
        UPDATE social_evidence
        SET
            deleted_at = NULL,
            deleted_by = NULL,
            status = ?
        WHERE evidence_id = ?
        """,
        (
            "UNDER_REVIEW",
            evidence_id,
        ),
    )

    updated = cursor.rowcount > 0
    connection.commit()
    connection.close()

    if not updated:
        return {
            "success": False,
            "message": "Evidence not found",
        }

    return {
        "success": True,
        "evidence_id": evidence_id,
    }

def update_social_evidence_status(
    evidence_id,
    new_status,
):
    allowed_statuses = {
        "NEW",
        "UNDER_REVIEW",
        "VERIFIED",
        "ESCALATED",
        "CLOSED",
        "REJECTED",
        "RECOVERABLE_DELETED",
    }

    new_status = (
        new_status.upper().strip()
    )

    if new_status not in allowed_statuses:
        return {
            "success": False,
            "message": "Invalid evidence status",
        }

    connection = sqlite3.connect(
        DATABASE_NAME
    )

    cursor = connection.cursor()

    cursor.execute(
        """
        UPDATE social_evidence
        SET status = ?
        WHERE evidence_id = ?
        """,
        (
            new_status,
            evidence_id,
        ),
    )

    updated = cursor.rowcount > 0

    connection.commit()
    connection.close()

    if not updated:
        return {
            "success": False,
            "message": "Evidence not found",
        }

    return {
        "success": True,
        "evidence_id": evidence_id,
        "status": new_status,
    }


def update_social_evidence_notes(
    evidence_id,
    analyst_notes,
):
    connection = sqlite3.connect(
        DATABASE_NAME
    )

    cursor = connection.cursor()

    cursor.execute(
        """
        UPDATE social_evidence
        SET analyst_notes = ?
        WHERE evidence_id = ?
        """,
        (
            analyst_notes,
            evidence_id,
        ),
    )

    updated = cursor.rowcount > 0

    connection.commit()
    connection.close()

    if not updated:
        return {
            "success": False,
            "message": "Evidence not found",
        }

    return {
        "success": True,
        "evidence_id": evidence_id,
        "analyst_notes": analyst_notes,
    }

def log_evidence_audit_event(
    evidence_id,
    username,
    action,
    details=None,
):
    connection = sqlite3.connect(
        DATABASE_NAME
    )

    cursor = connection.cursor()

    cursor.execute(
        """
        INSERT INTO evidence_audit_log (
            evidence_id,
            username,
            action,
            details,
            created_at
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            evidence_id,
            username,
            action,
            details,
            datetime.utcnow().isoformat(),
        ),
    )

    connection.commit()
    connection.close()


def get_evidence_audit_log(
    evidence_id=None
):
    connection = sqlite3.connect(
        DATABASE_NAME
    )

    connection.row_factory = sqlite3.Row

    cursor = connection.cursor()

    if evidence_id:
        cursor.execute(
            """
            SELECT
                id,
                evidence_id,
                username,
                action,
                details,
                created_at
            FROM evidence_audit_log
            WHERE evidence_id = ?
            ORDER BY id DESC
            """,
            (evidence_id,),
        )
    else:
        cursor.execute(
            """
            SELECT
                id,
                evidence_id,
                username,
                action,
                details,
                created_at
            FROM evidence_audit_log
            ORDER BY id DESC
            """
        )

    rows = cursor.fetchall()

    connection.close()

    return [
        dict(row)
        for row in rows
    ]