from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os
from dotenv import load_dotenv

load_dotenv()

# For local development without MySQL, we can default to SQLite or use env vars
# DATABASE_URL = "mysql+pymysql://user:password@localhost/iso_validator"
MYSQL_USER = os.getenv("MYSQL_USER", "root")
MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD", "")
MYSQL_HOST = os.getenv("MYSQL_HOST", "localhost")
MYSQL_DB = os.getenv("MYSQL_DB", "iso_validator")

SQLALCHEMY_DATABASE_URL = f"mysql+pymysql://{MYSQL_USER}:{MYSQL_PASSWORD}@{MYSQL_HOST}/{MYSQL_DB}"

# Fallback to SQLite if MySQL is not configured or fails (for MVP/Demo purposes if user doesn't have MySQL ready)
# Fallback to SQLite if MySQL is not configured or fails
try:
    # Try to import pymysql to ensure driver exists
    import pymysql
    engine = create_engine(SQLALCHEMY_DATABASE_URL)
    testing_connection = engine.connect()
    testing_connection.close()
    print("Combined with MySQL database.")
except Exception as e:
    print(f"MySQL connection failed ({str(e)}), falling back to SQLite for local development.")
    SQLALCHEMY_DATABASE_URL = "sqlite:///./iso_validator.db"
    engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
