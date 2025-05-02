from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Boolean, JSON, ForeignKey, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime
import os
import argparse
from dotenv import load_dotenv

# Parse command line arguments
load_dotenv()

# Database configuration
DB_USER = os.getenv('DB_USER', 'root')
DB_PASSWORD = os.getenv('DB_PASSWORD', '')
DB_HOST = os.getenv('DB_HOST', 'localhost')
DB_PORT = os.getenv('DB_PORT', '3306')
DB_NAME = os.getenv('DB_NAME', 'fraud_detection')

# Create database URL
DATABASE_URL = f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

# Create SQLAlchemy engine with connection pooling and retry settings
engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,  # Enable connection health checks
    pool_recycle=3600,   # Recycle connections after 1 hour
    pool_timeout=30,     # Wait up to 30 seconds for a connection
    max_overflow=10,     # Allow up to 10 connections above pool_size
    pool_size=5          # Maintain 5 connections in the pool
)

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
    transaction_analyses = relationship("TransactionAnalysis", back_populates="user")
    profile = relationship("UserProfile", back_populates="user", uselist=False)
    alerts = relationship("Alert", back_populates="user")

class Transaction(Base):
    """Transaction model for storing basic transaction data"""
    __tablename__ = "transactions"

    transaction_id = Column(String(50), primary_key=True)
    user_id = Column(String(50), ForeignKey('users.user_id'))
    amount = Column(Float)
    currency = Column(String(10), nullable=False, default='VND')
    description = Column(String(255), nullable=True)
    category = Column(String(100))
    timestamp = Column(DateTime, default=datetime.now)
    ip_address = Column(String(50))
    geolocation = Column(String(255))
    device_id = Column(String(100))
    
    # Relationships
    user = relationship("User", back_populates="transactions")

    def __repr__(self):
        return f"<Transaction(transaction_id='{self.transaction_id}', user_id='{self.user_id}', amount={self.amount}, currency='{self.currency}', description='{self.description}', category='{self.category}', timestamp='{self.timestamp}')>"

class TransactionAnalysis(Base):
    """Transaction analysis model for storing transaction data and fraud detection results"""
    __tablename__ = "transaction_analyses"

    transaction_id = Column(String(50), primary_key=True)
    user_id = Column(String(50), ForeignKey('users.user_id'))
    amount = Column(Float)
    category = Column(String(100))
    timestamp = Column(DateTime, default=datetime.now)
    ip_address = Column(String(50))
    geolocation = Column(String(255))
    device_id = Column(String(100))
    currency = Column(String(10), nullable=False, default='VND')
    description = Column(String(255), nullable=True)
    is_suspicious = Column(Boolean, default=False)
    risk_score = Column(Float, default=0.0)
    ai_analysis = Column(JSON, nullable=True)
    traditional_analysis = Column(JSON, nullable=True)
    verified = Column(Boolean, default=False)
    is_fraud = Column(Boolean, default=False)
    fraud_reasons = Column(JSON, nullable=True)  # List of reasons for fraud detection
    
    # Relationships
    user = relationship("User", back_populates="transaction_analyses")

    def __repr__(self):
        return f"<TransactionAnalysis(transaction_id='{self.transaction_id}', user_id='{self.user_id}', amount={self.amount}, currency='{self.currency}', description='{self.description}', category='{self.category}', timestamp='{self.timestamp}', is_suspicious={self.is_suspicious}, risk_score={self.risk_score})>"

class UserProfile(Base):
    """UserProfile model for storing user behavior patterns"""
    __tablename__ = "user_profiles"

    user_id = Column(String(50), ForeignKey('users.user_id'), primary_key=True)
    common_locations = Column(JSON)  # List of common locations
    common_devices = Column(JSON)    # List of common devices
    common_categories = Column(JSON) # List of common transaction categories
    common_ip_addresses = Column(JSON) # List of common ip addresses
    avg_transaction_amount = Column(Float, default=0.0)
    typical_transaction_hours = Column(JSON)  # List of hours when user typically transacts
    last_updated = Column(DateTime, default=datetime.now)
    
    # Relationships
    user = relationship("User", back_populates="profile")

# class Alert(Base):
#     """Alert model for storing fraud alerts"""
#     __tablename__ = "alerts"

#     alert_id = Column(Integer, primary_key=True, autoincrement=True)
#     user_id = Column(String(50), ForeignKey('users.user_id'))
#     timestamp = Column(DateTime, default=datetime.now)
#     risk_score = Column(Float)
#     reasons = Column(JSON)  # List of reasons for alert
#     transaction_id = Column(String(50), ForeignKey('transaction_analyses.transaction_id'))
#     transaction_details = Column(JSON)
#     status = Column(String(20), default='new')  # new, reviewed, resolved, false_positive
    
#     # Relationships
#     user = relationship("User", back_populates="alerts")

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
