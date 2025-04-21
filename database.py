from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Boolean, JSON, ForeignKey, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Database configuration
DB_USER = os.getenv('DB_USER', 'root')
DB_PASSWORD = os.getenv('DB_PASSWORD', '')
DB_HOST = os.getenv('DB_HOST', 'localhost')
DB_PORT = os.getenv('DB_PORT', '3306')
DB_NAME = os.getenv('DB_NAME', 'fraud_detection')

# Create database URL
DATABASE_URL = f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

# Create SQLAlchemy engine
engine = create_engine(DATABASE_URL)

# Create session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Create base class for models
Base = declarative_base()

class User(Base):
    __tablename__ = "users"

    user_id = Column(String(50), primary_key=True)
    email = Column(String(255))
    phone = Column(String(20))
    created_at = Column(DateTime, default=datetime.now)
    last_login = Column(DateTime)
    risk_score = Column(Float, default=0.0)

    # Relationships
    transactions = relationship("Transaction", back_populates="user")
    profile = relationship("UserProfile", back_populates="user", uselist=False)
    alerts = relationship("Alert", back_populates="user")

class Transaction(Base):
    """Transaction model for storing transaction data"""
    __tablename__ = "transactions"

    transaction_id = Column(String(50), primary_key=True)
    user_id = Column(String(50), ForeignKey('users.user_id'))
    amount = Column(Float)
    category = Column(String(100))
    timestamp = Column(DateTime, default=datetime.now)
    ip_address = Column(String(50))
    geolocation = Column(String(255))
    device_id = Column(String(100))
    is_suspicious = Column(Boolean, default=False)
    risk_score = Column(Float, default=0.0)
    verified = Column(Boolean, default=False)
    is_fraud = Column(Boolean, default=False)
    ai_analysis = Column(Text)  # Lưu kết quả phân tích từ OpenAI
    traditional_analysis = Column(JSON)  # Lưu kết quả phân tích truyền thống
    
    # Relationships
    user = relationship("User", back_populates="transactions")

class UserProfile(Base):
    """UserProfile model for storing user behavior patterns"""
    __tablename__ = "user_profiles"

    user_id = Column(String(50), ForeignKey('users.user_id'), primary_key=True)
    common_locations = Column(JSON)  # List of common locations
    common_devices = Column(JSON)    # List of common devices
    common_categories = Column(JSON) # List of common transaction categories
    avg_transaction_amount = Column(Float, default=0.0)
    typical_transaction_hours = Column(JSON)  # List of hours when user typically transacts
    last_updated = Column(DateTime, default=datetime.now)
    
    # Relationships
    user = relationship("User", back_populates="profile")

class Alert(Base):
    """Alert model for storing fraud alerts"""
    __tablename__ = "alerts"

    alert_id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(String(50), ForeignKey('users.user_id'))
    timestamp = Column(DateTime, default=datetime.now)
    risk_score = Column(Float)
    reasons = Column(JSON)  # List of reasons for alert
    transaction_id = Column(String(50), ForeignKey('transactions.transaction_id'))
    transaction_details = Column(JSON)
    status = Column(String(20), default='new')  # new, reviewed, resolved, false_positive
    
    # Relationships
    user = relationship("User", back_populates="alerts")

def get_db():
    """Get database session"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    """Initialize database by creating all tables"""
    Base.metadata.create_all(bind=engine) 