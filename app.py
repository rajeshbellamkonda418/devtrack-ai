
import logging
import os
import secrets
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path

import mysql.connector
from mysql.connector import pooling, IntegrityError, Error as MySQLError

from flask import Flask, jsonify, redirect, render_template, request, session, url_for
from dotenv import load_dotenv
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.security import check_password_hash, generate_password_hash

from ml.model import recommend_jobs
from ml.resume_analyzer import analyze_resume_for_role, extract_text_from_file
from ml.job_search import search_role_jobs
from ml.interview_questions import INTERVIEW_QUESTIONS, LEVELS, get_interview_questions
from ml.dsa_questions import DSA_LEVELS, DSA_TOPICS, get_dsa_questions


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env", override=False)

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO").upper())
logger = logging.getLogger(__name__)

is_vercel = bool(os.getenv("VERCEL"))
secret_key = os.getenv("FLASK_SECRET_KEY")
if not secret_key and is_vercel:
    raise RuntimeError(
        "FLASK_SECRET_KEY must be configured in Vercel Project Settings > Environment Variables."
    )

app = Flask(__name__, static_folder="public/static")
app.config.update(
    SECRET_KEY=secret_key or secrets.token_hex(32),
    MAX_CONTENT_LENGTH=10 * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv(
        "SESSION_COOKIE_SECURE", "true" if is_vercel else "false"
    ).lower() == "true",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
)

if not secret_key:
    logger.warning("FLASK_SECRET_KEY is not set; sessions will reset when the app restarts.")


# ---------------------------------------------------------------------------
# MySQL connection pool
# ---------------------------------------------------------------------------
_mysql_pool = None


def get_db_connection():
    """Return a checked-out connection from the MySQL pool."""
    global _mysql_pool

    if _mysql_pool is None:
        try:
            _mysql_pool = pooling.MySQLConnectionPool(
                pool_name="devtrack_ai_pool",
                pool_size=max(1, min(int(os.getenv("DB_POOL_SIZE", "5")), 32)),
                pool_reset_session=True,
                host=os.getenv("DB_HOST", "localhost"),
                port=int(os.getenv("DB_PORT", "3306")),
                user=os.getenv("DB_USER", "root"),
                password=os.getenv("DB_PASSWORD", ""),
                database=os.getenv("DB_NAME", "devtrack_ai"),
                connection_timeout=10,
                autocommit=False,
            )
        except (MySQLError, ValueError):
            logger.exception("Could not initialize MySQL connection pool")
            raise

    return _mysql_pool.get_connection()


def create_guest_user():
    """Create a database-backed guest so applications always have an INT user_id."""
    connection = get_db_connection()
    cursor = connection.cursor()
    try:
        guest_name = "guest_" + secrets.token_hex(16)
        guest_password = generate_password_hash(secrets.token_urlsafe(32))
        cursor.execute(
            "INSERT INTO users (name, password_hash) VALUES (%s, %s)",
            (guest_name, guest_password),
        )
        connection.commit()
        return cursor.lastrowid
    except Exception:
        connection.rollback()
        raise
    finally:
        cursor.close()
        connection.close()


def ensure_session_user():
    """Ensure the browser has a database-backed guest or signed-in user."""
    if "user_id" not in session:
        guest_id = create_guest_user()
        session.permanent = True
        session["user_id"] = int(guest_id)
        session["user_name"] = "Guest"
        session["is_guest"] = True
    elif "user_name" not in session or not session["user_name"]:
        session["user_name"] = "Guest"

    return int(session["user_id"]), session["user_name"]


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        try:
            ensure_session_user()
        except MySQLError:
            logger.exception("Could not initialize user session")
            return jsonify({"error": "Database is unavailable"}), 503
        return view(*args, **kwargs)

    return wrapped


def request_json_object():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def transfer_guest_applications(cursor, guest_user_id, new_user_id):
    """Move jobs created in a guest session to the newly registered/logged-in user."""
    if guest_user_id and guest_user_id != new_user_id:
        cursor.execute(
            "UPDATE applications SET user_id = %s WHERE user_id = %s",
            (new_user_id, guest_user_id),
        )


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------
@app.route("/")
def home():
    return render_template("index.html")


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")


@app.route("/login")
def login():
    return redirect(url_for("home"))


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------
@app.route("/api/auth/register", methods=["POST"])
def api_register():
    data = request_json_object()
    name = data.get("name")
    password = data.get("password")

    if not isinstance(name, str) or not isinstance(password, str):
        return jsonify({"error": "Name and password are required"}), 400

    name = name.strip()
    if not 2 <= len(name) <= 80:
        return jsonify({"error": "Name must be between 2 and 80 characters"}), 400
    if not 8 <= len(password) <= 128:
        return jsonify({"error": "Password must be between 8 and 128 characters"}), 400

    guest_user_id = session.get("user_id") if session.get("is_guest") else None
    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        cursor.execute("SELECT id FROM users WHERE name = %s LIMIT 1", (name,))
        if cursor.fetchone():
            return jsonify({"error": "An account with that name already exists"}), 409

        cursor.execute(
            "INSERT INTO users (name, password_hash) VALUES (%s, %s)",
            (name, generate_password_hash(password)),
        )
        new_user_id = cursor.lastrowid

        transfer_guest_applications(cursor, guest_user_id, new_user_id)
        connection.commit()

        session.clear()
        session.permanent = True
        session["user_id"] = int(new_user_id)
        session["user_name"] = name
        session["is_guest"] = False

        return jsonify({
            "message": "Account created",
            "redirect": url_for("dashboard"),
        }), 201

    except IntegrityError:
        if connection:
            connection.rollback()
        return jsonify({"error": "An account with that name already exists"}), 409
    except MySQLError:
        if connection:
            connection.rollback()
        logger.exception("Could not register account")
        return jsonify({"error": "Could not create your account"}), 500
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


@app.route("/api/auth/login", methods=["POST"])
def api_login():
    data = request_json_object()
    name = data.get("name")
    password = data.get("password")

    if not isinstance(name, str) or not isinstance(password, str):
        return jsonify({"error": "Name and password are required"}), 400
    name = name.strip()
    if not 2 <= len(name) <= 80 or not 1 <= len(password) <= 128:
        return jsonify({"error": "Invalid name or password"}), 400

    guest_user_id = session.get("user_id") if session.get("is_guest") else None
    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        cursor.execute(
            "SELECT id, name, password_hash FROM users WHERE name = %s LIMIT 1",
            (name,),
        )
        user = cursor.fetchone()

        if not user or not check_password_hash(user["password_hash"], password):
            return jsonify({"error": "Invalid name or password"}), 401

        transfer_guest_applications(cursor, guest_user_id, user["id"])
        connection.commit()

        session.clear()
        session.permanent = True
        session["user_id"] = int(user["id"])
        session["user_name"] = user["name"]
        session["is_guest"] = False

        return jsonify({"message": "Signed in", "redirect": url_for("dashboard")})

    except MySQLError:
        if connection:
            connection.rollback()
        logger.exception("Could not sign in")
        return jsonify({"error": "Could not sign in right now"}), 500
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


@app.route("/api/auth/logout", methods=["POST"])
def api_logout():
    session.clear()
    return jsonify({"message": "Signed out", "redirect": url_for("home")})


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("home"))


# ---------------------------------------------------------------------------
# Job applications CRUD
# ---------------------------------------------------------------------------
@app.route("/api/jobs", methods=["GET"])
@login_required
def get_jobs():
    user_id, _ = ensure_session_user()
    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT id, company, role, status, skills, applied_date
            FROM applications
            WHERE user_id = %s
            ORDER BY applied_date DESC, id DESC
            """,
            (user_id,),
        )
        jobs = cursor.fetchall()

        for job in jobs:
            job["id"] = str(job["id"])
            if job["applied_date"]:
                job["applied_date"] = job["applied_date"].isoformat()

        return jsonify(jobs)

    except MySQLError:
        logger.exception("Could not load applications")
        return jsonify({"error": "Could not load applications right now"}), 500
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


@app.route("/api/jobs", methods=["POST"])
@login_required
def add_job():
    user_id, _ = ensure_session_user()
    data = request_json_object()

    company = data.get("company", "")
    role = data.get("role", "")
    status = data.get("status", "Applied")
    skills = data.get("skills", "")

    if not all(isinstance(value, str) for value in (company, role, status, skills)):
        return jsonify({"error": "Company, role, status, and skills must be text"}), 400

    company, role = company.strip(), role.strip()
    status, skills = status.strip(), skills.strip()

    if not company or not role:
        return jsonify({"error": "Company and role are required"}), 400
    if len(company) > 120 or len(role) > 120:
        return jsonify({"error": "Company and role must be 120 characters or fewer"}), 400
    if status not in {"Applied", "Interview", "Selected", "Rejected"}:
        return jsonify({"error": "Invalid status"}), 400

    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute(
            """
            INSERT INTO applications (user_id, company, role, status, skills)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (user_id, company, role, status, skills),
        )
        application_id = cursor.lastrowid
        connection.commit()

        return jsonify({
            "message": "Application added successfully",
            "id": str(application_id),
        }), 201

    except MySQLError:
        if connection:
            connection.rollback()
        logger.exception("Could not add application")
        return jsonify({"error": "Could not add application right now"}), 500
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


@app.route("/api/jobs/<job_id>", methods=["PUT"])
@login_required
def update_job(job_id):
    user_id, _ = ensure_session_user()
    data = request_json_object()
    status = data.get("status", "")

    if not isinstance(status, str):
        return jsonify({"error": "Status must be text"}), 400
    status = status.strip()
    if status not in {"Applied", "Interview", "Selected", "Rejected"}:
        return jsonify({"error": "Invalid status"}), 400

    try:
        application_id = int(job_id)
        if application_id <= 0:
            raise ValueError
    except (TypeError, ValueError):
        return jsonify({"error": "Application not found"}), 404

    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute(
            """
            UPDATE applications
            SET status = %s
            WHERE id = %s AND user_id = %s
            """,
            (status, application_id, user_id),
        )
        connection.commit()

        if cursor.rowcount == 0:
            cursor.execute(
                "SELECT id FROM applications WHERE id = %s AND user_id = %s",
                (application_id, user_id),
            )
            if not cursor.fetchone():
                return jsonify({"error": "Application not found"}), 404

        return jsonify({"message": "Status updated successfully"})

    except MySQLError:
        if connection:
            connection.rollback()
        logger.exception("Could not update application")
        return jsonify({"error": "Could not update application right now"}), 500
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


@app.route("/api/jobs/<job_id>", methods=["DELETE"])
@login_required
def delete_job(job_id):
    user_id, _ = ensure_session_user()

    try:
        application_id = int(job_id)
        if application_id <= 0:
            raise ValueError
    except (TypeError, ValueError):
        return jsonify({"error": "Application not found"}), 404

    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute(
            "DELETE FROM applications WHERE id = %s AND user_id = %s",
            (application_id, user_id),
        )
        connection.commit()

        if cursor.rowcount == 0:
            return jsonify({"error": "Application not found"}), 404

        return jsonify({"message": "Application deleted"})

    except MySQLError:
        if connection:
            connection.rollback()
        logger.exception("Could not delete application")
        return jsonify({"error": "Could not delete application right now"}), 500
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


# ---------------------------------------------------------------------------
# ML and job-search APIs (kept from the existing backend)
# ---------------------------------------------------------------------------
@app.route("/api/recommend", methods=["POST"])
def recommend():
    data = request_json_object()
    skills = data.get("skills", "")

    if not isinstance(skills, str):
        return jsonify({"error": "Skills must be text"}), 400
    skills = skills.strip()
    if not skills:
        return jsonify({"error": "Enter your skills"}), 400

    try:
        recommendations = recommend_jobs(skills)
        return jsonify({"recommendations": recommendations})
    except Exception:
        logger.exception("Job recommendation failed")
        return jsonify({"error": "Could not generate recommendations right now"}), 500


@app.route("/api/analyze-resume", methods=["POST"])
def analyze_resume():
    try:
        target_role = ""
        resume_text = ""

        if request.files:
            if "resume" not in request.files:
                return jsonify({"error": "Only resume files are valid for analysis"}), 400

            file = request.files["resume"]
            if not file or not file.filename:
                return jsonify({"error": "No resume file selected"}), 400

            target_role = (request.form.get("role") or "").strip()
            resume_text = extract_text_from_file(file.stream, file.filename)
        else:
            data = request_json_object()
            target_role = data.get("role", "")
            resume_text = data.get("resume_text", "")

        if not isinstance(target_role, str) or not isinstance(resume_text, str):
            return jsonify({"error": "Target role and resume text must be text"}), 400

        target_role = target_role.strip()
        resume_text = resume_text.strip()
        if not resume_text:
            return jsonify({
                "error": "Please provide a resume file (PDF, DOCX, TXT) or paste resume text"
            }), 400

        return jsonify(analyze_resume_for_role(resume_text, target_role))

    except RequestEntityTooLarge:
        raise
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception:
        logger.exception("Failed to analyze resume")
        return jsonify({"error": "Failed to analyze resume right now"}), 500


@app.route("/api/search-jobs", methods=["GET", "POST"])
def search_jobs():
    try:
        if request.method == "POST":
            data = request_json_object()
            fields = {
                "role": data.get("role", ""),
                "location": data.get("location", "Remote"),
                "platform": data.get("platform", "all"),
                "employment_type": data.get("employment_type", "all"),
            }
            if not all(isinstance(value, str) for value in fields.values()):
                return jsonify({"error": "Search parameters must be text"}), 400

            role = fields["role"].strip()
            location = fields["location"].strip()
            platform = fields["platform"].strip().lower()
            employment_type = fields["employment_type"].strip().lower()
        else:
            role = (request.args.get("role") or "").strip()
            location = (request.args.get("location") or "Remote").strip()
            platform = (request.args.get("platform") or "all").strip().lower()
            employment_type = (request.args.get("employment_type") or "all").strip().lower()

        if not role:
            return jsonify({"error": "Role is required for job search"}), 400
        if platform not in {"all", "remoteok", "jobicy", "arbeitnow"}:
            return jsonify({"error": "Invalid job platform"}), 400
        if employment_type not in {"all", "fresher", "internship", "part_time", "freelance"}:
            return jsonify({"error": "Invalid employment type"}), 400

        results = search_role_jobs(
            role=role,
            location=location,
            platform=platform,
            employment_type=employment_type,
        )
        return jsonify(results)

    except Exception:
        logger.exception("Failed to search jobs")
        return jsonify({"error": "Failed to search jobs right now"}), 500


@app.route("/api/interview-questions", methods=["GET"])
def interview_questions():
    topic = (request.args.get("topic") or "").strip().lower()
    level = (request.args.get("level") or "").strip().lower()

    if topic not in INTERVIEW_QUESTIONS:
        return jsonify({"error": "Choose a valid interview topic"}), 400
    if level not in LEVELS:
        return jsonify({"error": "Choose a valid difficulty level"}), 400

    return jsonify({
        "topic": topic,
        "level": level,
        "questions": get_interview_questions(topic, level),
    })


@app.route("/api/dsa-questions", methods=["GET"])
def dsa_questions():
    topic = (request.args.get("topic") or "all").strip().lower()
    difficulty = (request.args.get("difficulty") or "all").strip().lower()

    if topic != "all" and topic not in DSA_TOPICS:
        return jsonify({"error": "Choose a valid DSA topic"}), 400
    if difficulty != "all" and difficulty not in DSA_LEVELS:
        return jsonify({"error": "Choose a valid difficulty level"}), 400

    return jsonify({
        "topic": topic,
        "difficulty": difficulty,
        "questions": get_dsa_questions(topic, difficulty),
    })


# ---------------------------------------------------------------------------
# Health check and error handlers
# ---------------------------------------------------------------------------
@app.errorhandler(413)
def request_entity_too_large(_error):
    return jsonify({"error": "Request body must be 10 MB or smaller"}), 413


@app.route("/api/health", methods=["GET"])
def health_check():
    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute("SELECT 1")
        cursor.fetchone()
        return jsonify({
            "status": "ok",
            "database": "connected",
            "backend": "mysql",
        })
    except MySQLError:
        logger.exception("MySQL health check failed")
        return jsonify({
            "status": "error",
            "database": "disconnected",
            "backend": "mysql",
        }), 503
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


# WSGI entry point for Vercel and other WSGI hosts.
application = app

if __name__ == "__main__":
    app.run(
        debug=not bool(os.getenv("VERCEL")),
        host="0.0.0.0",
        port=int(os.getenv("PORT", "5000")),
    )
    
