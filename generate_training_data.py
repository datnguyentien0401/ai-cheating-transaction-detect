import json
from datetime import datetime, timedelta
import random

def generate_training_data(num_samples=100):
    """Tạo dữ liệu training mẫu cho hệ thống phát hiện gian lận"""
    
    # Danh sách các danh mục giao dịch
    categories = ['electronics', 'food', 'clothing', 'travel', 'entertainment', 'utilities']
    
    # Danh sách các vị trí
    locations = ['Vietnam', 'Singapore', 'Thailand', 'Malaysia', 'Indonesia']
    
    # Danh sách các thiết bị
    devices = ['mobile-android', 'mobile-ios', 'web-chrome', 'web-safari', 'tablet-android']
    
    # Tạo dữ liệu mẫu
    training_data = []
    
    # Tạo thời gian bắt đầu (30 ngày trước)
    start_time = datetime.now() - timedelta(days=30)
    
    for i in range(num_samples):
        # Tạo thời gian ngẫu nhiên trong 30 ngày
        random_days = random.randint(0, 30)
        random_hours = random.randint(0, 23)
        random_minutes = random.randint(0, 59)
        timestamp = start_time + timedelta(days=random_days, hours=random_hours, minutes=random_minutes)
        
        # Tạo số tiền ngẫu nhiên (từ 10,000 đến 10,000,000)
        amount = random.randint(10000, 10000000)
        
        # Xác suất gian lận (20%)
        is_fraud = random.random() < 0.2
        
        # Nếu là giao dịch gian lận, tăng số tiền và thay đổi một số thông tin
        if is_fraud:
            amount *= random.uniform(2, 5)  # Tăng số tiền
            if random.random() < 0.5:
                location = random.choice([loc for loc in locations if loc != 'Vietnam'])  # Vị trí khác
            else:
                location = 'Vietnam'
            device = random.choice([d for d in devices if d != 'mobile-android'])  # Thiết bị khác
        else:
            location = 'Vietnam'
            device = 'mobile-android'
        
        # Tạo dữ liệu giao dịch
        transaction = {
            'user_id': 'user1',
            'amount': amount,
            'category': random.choice(categories),
            'timestamp': timestamp.isoformat(),
            'ip_address': f'192.168.1.{random.randint(1, 255)}',
            'geolocation': location,
            'device_id': f'{device}-{random.randint(1000, 9999)}',
            'is_fraud': is_fraud
        }
        
        training_data.append(transaction)
    
    return training_data

if __name__ == '__main__':
    # Tạo dữ liệu training
    data = generate_training_data(100)
    
    # Lưu vào file JSON
    with open('training_data.json', 'w') as f:
        json.dump({'training_data': data}, f, indent=2)
    
    print(f"Đã tạo {len(data)} mẫu dữ liệu training và lưu vào file training_data.json") 