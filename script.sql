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
    user_id VARCHAR(50),
    amount FLOAT,
    category VARCHAR(100),
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    ip_address VARCHAR(50),
    geolocation VARCHAR(255),
    device_id VARCHAR(100),
    is_suspicious BOOLEAN DEFAULT FALSE,
    risk_score FLOAT DEFAULT 0.0,
    verified BOOLEAN DEFAULT FALSE,
    is_fraud BOOLEAN DEFAULT FALSE,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

-- Create user_profiles table
CREATE TABLE IF NOT EXISTS user_profiles (
    user_id VARCHAR(50) PRIMARY KEY,
    common_locations JSON,
    common_devices JSON,
    common_categories JSON,
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
    status VARCHAR(20) DEFAULT 'new',
    FOREIGN KEY (user_id) REFERENCES users(user_id),
    FOREIGN KEY (transaction_id) REFERENCES transactions(transaction_id)
);

-- Create indexes for better performance
CREATE INDEX idx_transactions_user_id ON transactions(user_id);
CREATE INDEX idx_transactions_timestamp ON transactions(timestamp);
CREATE INDEX idx_alerts_user_id ON alerts(user_id);
CREATE INDEX idx_alerts_timestamp ON alerts(timestamp);
CREATE INDEX idx_alerts_status ON alerts(status);

-- Insert sample data (optional)
-- Sample user
INSERT INTO users (user_id, email, phone) VALUES 
('user123', 'user123@example.com', '+1234567890');

-- Sample transaction
INSERT INTO transactions (transaction_id, user_id, amount, category, ip_address, geolocation, device_id) VALUES 
('tx123', 'user123', 150.00, 'Electronics', '192.168.1.1', 'New York, USA', 'device123');

-- Sample user profile
INSERT INTO user_profiles (user_id, common_locations, common_devices, common_categories, avg_transaction_amount, typical_transaction_hours) VALUES 
('user123', 
 '["New York, USA", "Los Angeles, USA"]', 
 '["device123", "device456"]', 
 '["Electronics", "Clothing"]', 
 125.50, 
 '[9, 10, 11, 14, 15, 16]');

-- Sample alert
INSERT INTO alerts (user_id, risk_score, reasons, transaction_id, transaction_details, status) VALUES 
('user123', 
 0.85, 
 '["Unusual location", "High amount"]', 
 'tx123', 
 '{"amount": 150.00, "category": "Electronics", "location": "New York, USA"}', 
 'new'); 