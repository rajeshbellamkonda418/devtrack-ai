
import os
import logging
from pathlib import Path

import mysql.connector
from mysql.connector import pooling
from dotenv import load_dotenv

# Project directory
BASE_DIR = Path(__file__).resolve().parent

# Load environment variables
load_dotenv(BASE_DIR / ".env", override=False)

logger = logging.getLogger(__name__)

# Database connection pool
_db_pool = None


def create_db_pool():
    """Create a secure MySQL/TiDB connection pool."""

    global _db_pool

    if _db_pool is not None:
        return _db_pool

    try:
        # Read environment variables
        host = os.getenv("DB_HOST")
        port = int(os.getenv("DB_PORT", "4000"))
        user = os.getenv("DB_USER")
        password = os.getenv("DB_PASSWORD")
        database = os.getenv("DB_NAME", "devtrack_ai")

        ca_path = os.getenv("DB_SSL_CA")

        # Validate configuration
        if not all([host, user, password, database]):
            raise RuntimeError(
                "Database environment variables are missing"
            )

        if not ca_path:
            raise RuntimeError("DB_SSL_CA is missing")

        certificate_path = Path(ca_path)

        if not certificate_path.is_absolute():
            certificate_path = BASE_DIR / certificate_path

        if not certificate_path.is_file():
            raise FileNotFoundError(
                f"CA certificate not found: {certificate_path}"
            )

        # MySQL / TiDB configuration
        config = {
            "pool_name": "devtrack_ai_pool",
            "pool_size": max(
                1, min(int(os.getenv("DB_POOL_SIZE", "2")), 5)
            ),
            "pool_reset_session": True,

            "host": host,
            "port": port,
            "user": user,
            "password": password,
            "database": database,

            "connection_timeout": 15,
            "autocommit": False,

            # Secure TiDB SSL connection
            "ssl_ca": str(certificate_path),
            "ssl_verify_cert": True,
            "ssl_verify_identity": True,
        }

        _db_pool = pooling.MySQLConnectionPool(**config)

        logger.info("MySQL/TiDB connection pool created")

        return _db_pool

    except Exception:
        logger.exception("Database pool initialization failed")
        raise


def get_db_connection():
    """Get a database connection from the pool."""

    pool = create_db_pool()

    return pool.get_connection()
