-- Create database if not exists
CREATE DATABASE IF NOT EXISTS fraud_detection;
USE fraud_detection;

-- Create users table
CREATE TABLE IF NOT EXISTS users (
    user_id VARCHAR(50) PRIMARY KEY,
    email VARCHAR(255),
    phone VARCHAR(20),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_login DATETIME,
    risk_score FLOAT DEFAULT 0.0
);

-- Create transactions table
CREATE TABLE IF NOT EXISTS transactions (
    transaction_id VARCHAR(50) PRIMARY KEY,
    user_id VARCHAR(50) NOT NULL,
    amount FLOAT NOT NULL,
    currency VARCHAR(10) NOT NULL DEFAULT 'VND',
    description VARCHAR(255),
    category VARCHAR(100),
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    ip_address VARCHAR(50),
    geolocation VARCHAR(255),
    device_id VARCHAR(100),
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

-- Create transaction_analyses table
CREATE TABLE IF NOT EXISTS transaction_analyses (
    transaction_id VARCHAR(50) PRIMARY KEY,
    user_id VARCHAR(50),
    amount FLOAT NOT NULL,
    currency VARCHAR(10) NOT NULL DEFAULT 'VND',
    description VARCHAR(255),
    category VARCHAR(100) NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    ip_address VARCHAR(50) NOT NULL,
    geolocation VARCHAR(255) NOT NULL,
    device_id VARCHAR(50) NOT NULL,
    is_suspicious TINYINT(1) DEFAULT 0,
    risk_score FLOAT DEFAULT 0.0,
    ai_analysis JSON,
    traditional_analysis JSON,
    verified TINYINT(1) DEFAULT 0,
    is_fraud TINYINT(1) DEFAULT 0,
    fraud_reasons JSON,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

-- Create user_profiles table
CREATE TABLE IF NOT EXISTS user_profiles (
    user_id VARCHAR(50) PRIMARY KEY,
    common_locations JSON,
    common_devices JSON,
    common_categories JSON,
    common_ip_addresses JSON,
    avg_transaction_amount FLOAT DEFAULT 0.0,
    typical_transaction_hours JSON,
    last_updated DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

-- Create alerts table
CREATE TABLE IF NOT EXISTS alerts (
    alert_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id VARCHAR(50),
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    risk_score FLOAT,
    reasons JSON,
    transaction_id VARCHAR(50),
    transaction_details JSON,
    fraud_reasons JSON,
    FOREIGN KEY (user_id) REFERENCES users(user_id),
    FOREIGN KEY (transaction_id) REFERENCES transactions(transaction_id)
);

-- Create indexes for better performance
CREATE INDEX idx_transactions_user_id ON transactions(user_id);
CREATE INDEX idx_transactions_timestamp ON transactions(timestamp);
CREATE INDEX idx_transaction_analyses_user_id ON transaction_analyses(user_id);
CREATE INDEX idx_transaction_analyses_timestamp ON transaction_analyses(timestamp);
CREATE INDEX idx_transaction_analyses_is_fraud ON transaction_analyses(is_fraud);
-- CREATE INDEX idx_alerts_user_id ON alerts(user_id);
-- CREATE INDEX idx_alerts_timestamp ON alerts(timestamp);
-- CREATE INDEX idx_alerts_status ON alerts(status);
