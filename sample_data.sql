-- Insert sample users
INSERT INTO users (user_id, email, phone, created_at, last_login, risk_score) VALUES
('user_1', 'user1@example.com', '0123456789', NOW() - INTERVAL 30 DAY, NOW() - INTERVAL 1 DAY, 0.1),
('user_2', 'user2@example.com', '0123456790', NOW() - INTERVAL 25 DAY, NOW() - INTERVAL 2 DAY, 0.2),
('user_3', 'user3@example.com', '0123456791', NOW() - INTERVAL 20 DAY, NOW() - INTERVAL 3 DAY, 0.3),
('user_4', 'user4@example.com', '0123456792', NOW() - INTERVAL 15 DAY, NOW() - INTERVAL 4 DAY, 0.4),
('user_5', 'user5@example.com', '0123456793', NOW() - INTERVAL 10 DAY, NOW() - INTERVAL 5 DAY, 0.5);

-- Insert sample data into user_profiles table
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

-- Insert sample transactions
INSERT INTO transaction_analyses (
    transaction_id, user_id, amount, currency, description, category, 
    timestamp, ip_address, geolocation, device_id, is_suspicious, 
    risk_score, verified, is_fraud, ai_analysis, traditional_analysis, 
    fraud_reasons
) VALUES 
-- User 1: Regular shopping transaction
('TX001', 'user_1', 150000, 'VND', 'Shopping at Vincom Mall', 'Shopping', 
'2024-03-15 14:30:00', '192.168.1.100', '{"country": "Vietnam", "city": "Hanoi"}', 
'mobile-ios-1', false, 0.1, true, false, 
'{"fraud_score": 10, "is_suspicious": false}', 
'{"fraud_score": 10, "is_suspicious": false}', 
'[]'),

-- User 1: Food purchase
('TX002', 'user_1', 75000, 'VND', 'Lunch at Lotteria', 'Food', 
'2024-03-15 12:15:00', '192.168.1.100', '{"country": "Vietnam", "city": "Hanoi"}', 
'mobile-ios-1', false, 0.1, true, false,
'{"fraud_score": 5, "is_suspicious": false}',
'{"fraud_score": 5, "is_suspicious": false}',
'[]'),

-- User 1: Electronics purchase
('TX003', 'user_1', 5000000, 'VND', 'iPhone purchase at Apple Store', 'Electronics',
'2024-03-15 15:45:00', '192.168.1.100', '{"country": "Vietnam", "city": "Hanoi"}',
'mobile-ios-1', false, 0.2, true, false,
'{"fraud_score": 20, "is_suspicious": false}',
'{"fraud_score": 20, "is_suspicious": false}',
'[]'),

-- User 1: Grocery shopping
('TX004', 'user_1', 200000, 'VND', 'Grocery shopping at Big C', 'Shopping',
'2024-03-15 16:30:00', '192.168.1.100', '{"country": "Vietnam", "city": "Hanoi"}',
'mobile-ios-1', false, 0.1, true, false,
'{"fraud_score": 10, "is_suspicious": false}',
'{"fraud_score": 10, "is_suspicious": false}',
'[]'),

-- User 1: Restaurant dinner
('TX005', 'user_1', 300000, 'VND', 'Dinner at restaurant', 'Food',
'2024-03-15 19:00:00', '192.168.1.100', '{"country": "Vietnam", "city": "Hanoi"}',
'mobile-ios-1', false, 0.15, true, false,
'{"fraud_score": 15, "is_suspicious": false}',
'{"fraud_score": 15, "is_suspicious": false}',
'[]'),

-- User 1: Hotel booking
('TX006', 'user_1', 1500000, 'VND', 'Hotel booking for weekend trip', 'Travel',
'2024-03-15 20:15:00', '192.168.1.100', '{"country": "Vietnam", "city": "Hanoi"}',
'mobile-ios-1', false, 0.2, true, false,
'{"fraud_score": 20, "is_suspicious": false}',
'{"fraud_score": 20, "is_suspicious": false}',
'[]'),

-- User 1: Late night food
('TX007', 'user_1', 100000, 'VND', 'Late night food delivery', 'Food',
'2024-03-15 23:30:00', '192.168.1.100', '{"country": "Vietnam", "city": "Hanoi"}',
'mobile-ios-1', false, 0.1, true, false,
'{"fraud_score": 10, "is_suspicious": false}',
'{"fraud_score": 10, "is_suspicious": false}',
'[]'),

-- User 1: Online shopping
('TX008', 'user_1', 250000, 'VND', 'Online shopping at Shopee', 'Shopping',
'2024-03-16 00:15:00', '192.168.1.100', '{"country": "Vietnam", "city": "Hanoi"}',
'mobile-ios-1', false, 0.1, true, false,
'{"fraud_score": 10, "is_suspicious": false}',
'{"fraud_score": 10, "is_suspicious": false}',
'[]'),

-- User 1: Flight booking
('TX009', 'user_1', 1000000, 'VND', 'Flight booking to Da Nang', 'Travel',
'2024-03-15 10:00:00', '192.168.1.100', '{"country": "Vietnam", "city": "Hanoi"}',
'mobile-ios-1', false, 0.15, true, false,
'{"fraud_score": 15, "is_suspicious": false}',
'{"fraud_score": 15, "is_suspicious": false}',
'[]'),

-- User 1: Business lunch
('TX010', 'user_1', 350000, 'VND', 'Business lunch with client', 'Food',
'2024-03-15 12:30:00', '192.168.1.100', '{"country": "Vietnam", "city": "Hanoi"}',
'mobile-ios-1', false, 0.1, true, false,
'{"fraud_score": 10, "is_suspicious": false}',
'{"fraud_score": 10, "is_suspicious": false}',
'[]');

-- Insert sample transactions
INSERT INTO transactions (transaction_id, user_id, amount, currency, description, category, timestamp, ip_address, geolocation, device_id) VALUES
('TX001', 'user_1', 150000, 'VND', 'Shopping at Vincom Mall', 'shopping', '2024-03-20 10:30:00', '192.168.1.100', 'Vietnam', 'mobile-ios-1'),
('TX002', 'user_1', 75000, 'VND', 'Lunch at Lotteria', 'food', '2024-03-20 12:15:00', '192.168.1.100', 'Vietnam', 'mobile-ios-1'),
('TX003', 'user_1', 5000000, 'VND', 'iPhone purchase at Apple Store', 'electronics', '2024-03-20 14:45:00', '192.168.1.100', 'Vietnam', 'mobile-ios-1'),
('TX004', 'user_1', 200000, 'VND', 'Grocery shopping at Big C', 'shopping', '2024-03-20 16:20:00', '192.168.1.100', 'Vietnam', 'mobile-ios-1'),
('TX005', 'user_1', 300000, 'VND', 'Dinner at restaurant', 'food', '2024-03-20 19:00:00', '192.168.1.100', 'Vietnam', 'mobile-ios-1'),
('TX006', 'user_1', 1500000, 'VND', 'Hotel booking for weekend trip', 'travel', '2024-03-20 20:30:00', '192.168.1.100', 'Vietnam', 'mobile-ios-1'),
('TX007', 'user_1', 100000, 'VND', 'Late night food delivery', 'food', '2024-03-20 23:45:00', '192.168.1.100', 'Vietnam', 'mobile-ios-1'),
('TX008', 'user_1', 250000, 'VND', 'Online shopping at Shopee', 'shopping', '2024-03-21 09:15:00', '192.168.1.100', 'Vietnam', 'mobile-ios-1'),
('TX009', 'user_1', 1000000, 'VND', 'Flight booking to Da Nang', 'travel', '2024-03-21 11:30:00', '192.168.1.100', 'Vietnam'),
('TX010', 'user_1', 350000, 'VND', 'Business lunch with client', 'food', '2024-03-21 13:00:00', '192.168.1.100', 'Vietnam', 'mobile-ios-1');
