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
    amount DECIMAL(15,2) NOT NULL,
    currency VARCHAR(10) NOT NULL DEFAULT 'VND' COMMENT 'Currency of the transaction (e.g., VND, USD, EUR)',
    description TEXT COMMENT 'Description or details of the transaction',
    category VARCHAR(100) NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    ip_address VARCHAR(45) NOT NULL,
    geolocation JSON NOT NULL,
    device_id VARCHAR(50) NOT NULL,
    is_suspicious BOOLEAN DEFAULT FALSE,
    risk_score FLOAT DEFAULT 0.0,
    ai_analysis JSON,
    traditional_analysis JSON,
    verified BOOLEAN DEFAULT FALSE,
    is_fraud BOOLEAN DEFAULT FALSE,
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
    avg_transaction_amount DECIMAL(15,2) DEFAULT 0.0,
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
    fraud_reasons JSON,
    FOREIGN KEY (user_id) REFERENCES users(user_id),
    FOREIGN KEY (transaction_id) REFERENCES transactions(transaction_id)
);

-- Create indexes for better performance
CREATE INDEX idx_transactions_user_id ON transactions(user_id);
CREATE INDEX idx_transactions_timestamp ON transactions(timestamp);
CREATE INDEX idx_transactions_is_fraud ON transactions(is_fraud);
CREATE INDEX idx_alerts_user_id ON alerts(user_id);
CREATE INDEX idx_alerts_timestamp ON alerts(timestamp);
CREATE INDEX idx_alerts_status ON alerts(status);

INSERT INTO users (user_id, email, phone, created_at, last_login, risk_score) VALUES
('user_1', 'user1@example.com', '0123456789', NOW() - INTERVAL 30 DAY, NOW() - INTERVAL 1 DAY, 0.1),
('user_2', 'user2@example.com', '0123456790', NOW() - INTERVAL 25 DAY, NOW() - INTERVAL 2 DAY, 0.2),
('user_3', 'user3@example.com', '0123456791', NOW() - INTERVAL 20 DAY, NOW() - INTERVAL 3 DAY, 0.3),
('user_4', 'user4@example.com', '0123456792', NOW() - INTERVAL 15 DAY, NOW() - INTERVAL 4 DAY, 0.4),
('user_5', 'user5@example.com', '0123456793', NOW() - INTERVAL 10 DAY, NOW() - INTERVAL 5 DAY, 0.5);

INSERT INTO user_profiles (
    user_id,
    common_locations,
    common_devices,
    common_categories,
    common_ip_addresses,
    avg_transaction_amount,
    typical_transaction_hours,
    last_updated
) VALUES
-- User 1: Regular user with consistent patterns
(
    'user_1',
    '["Vietnam", "Ho Chi Minh City"]',
    '["mobile-android-12345", "desktop-windows-67890"]',
    '["Food & Dining", "Shopping", "Transportation"]',
    '["192.168.1.100", "192.168.1.101"]',
    150000.00,
    '["9", "10", "11", "12", "13", "14", "15", "16", "17", "18"]',
    NOW()
),
-- User 2: High-value customer
(
    'user_2',
    '["Vietnam", "Ha Noi", "Da Nang"]',
    '["mobile-ios-23456", "tablet-ios-78901"]',
    '["Shopping", "Entertainment", "Travel"]',
    '["192.168.1.200", "192.168.1.201", "192.168.1.202"]',
    500000.00,
    '["10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "20"]',
    NOW()
),
-- User 3: International traveler
(
    'user_3',
    '["Vietnam", "Singapore", "Thailand", "Japan"]',
    '["mobile-android-34567", "laptop-mac-89012"]',
    '["Travel", "Shopping", "Food & Dining"]',
    '["192.168.1.300", "192.168.1.301", "192.168.1.302", "192.168.1.303"]',
    300000.00,
    '["8", "9", "10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "20", "21"]',
    NOW()
),
-- User 4: Night owl user
(
    'user_4',
    '["Vietnam", "Ho Chi Minh City"]',
    '["mobile-android-45678", "desktop-linux-90123"]',
    '["Entertainment", "Food & Dining", "Shopping"]',
    '["192.168.1.400", "192.168.1.401"]',
    200000.00,
    '["18", "19", "20", "21", "22", "23", "0", "1", "2"]',
    NOW()
),
-- User 5: Business user
(
    'user_5',
    '["Vietnam", "Ha Noi", "Ho Chi Minh City", "Da Nang"]',
    '["laptop-windows-56789", "mobile-ios-01234"]',
    '["Business", "Transportation", "Food & Dining"]',
    '["192.168.1.500", "192.168.1.501", "192.168.1.502"]',
    250000.00,
    '["7", "8", "9", "10", "11", "12", "13", "14", "15", "16", "17", "18"]',
    NOW()
);
