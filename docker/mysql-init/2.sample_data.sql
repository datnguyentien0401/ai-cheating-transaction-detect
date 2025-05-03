-- Insert sample users
INSERT INTO users (user_id, email, phone, created_at, last_login, risk_score) VALUES
('user_1', 'user1@example.com', '0123456789', NOW() - INTERVAL 30 DAY, NOW() - INTERVAL 1 DAY, 0.1);

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
    '["Vietnam"]',
    '["mobile-ios-1"]',
    '["electronics", "travel", "food", "shopping"]',
    '["192.168.1.100"]',
    892500,
    '[9, 10, 11, 12, 13, 14, 16, 19, 20, 23]',
    NOW()
);


-- Insert sample transactions
INSERT INTO transactions (transaction_id, user_id, amount, currency, description, category, timestamp, ip_address, geolocation, device_id) VALUES
('TX001', 'user_1', 150000, 'VND', 'Shopping at Vincom Mall', 'shopping', '2024-03-20 10:30:00', '192.168.1.100', 'Vietnam', 'mobile-ios-1'),
('TX002', 'user_1', 75000, 'VND', 'Lunch at Lotteria', 'food', '2024-03-20 12:15:00', '192.168.1.100', 'Vietnam', 'mobile-ios-1'),
('TX003', 'user_1', 5000000, 'VND', 'iPhone purchase at Apple Store', 'shopping', '2024-03-20 14:45:00', '192.168.1.100', 'Vietnam', 'mobile-ios-1'),
('TX004', 'user_1', 200000, 'VND', 'Grocery shopping at Big C', 'shopping', '2024-03-20 16:20:00', '192.168.1.100', 'Vietnam', 'mobile-ios-1'),
('TX005', 'user_1', 300000, 'VND', 'Dinner at restaurant', 'food', '2024-03-20 19:00:00', '192.168.1.100', 'Vietnam', 'mobile-ios-1'),
('TX006', 'user_1', 1500000, 'VND', 'Buy clothes at Zara', 'clothing', '2024-03-20 20:30:00', '203.160.89.123', 'Vietnam', 'mobile-ios-1'),
('TX007', 'user_1', 100000, 'VND', 'Late night food delivery', 'food', '2024-03-20 23:45:00', '203.160.89.123', 'Vietnam', 'mobile-ios-1'),
('TX008', 'user_1', 250000, 'VND', 'Online shopping at Shopee', 'shopping', '2024-03-21 09:15:00', '203.160.89.123', 'Vietnam', 'mobile-ios-1'),
('TX009', 'user_1', 1000000, 'VND', 'Flight booking to Da Nang', 'transportation', '2024-03-21 11:30:00', '203.160.89.123', 'Vietnam', 'mobile-ios-1'),
('TX010', 'user_1', 350000, 'VND', 'Business lunch with client', 'food', '2024-03-21 13:00:00', '203.160.89.123', 'Vietnam', 'mobile-ios-1');
