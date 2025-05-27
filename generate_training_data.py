import numpy as np
import pandas as pd
from datetime import datetime, timedelta
import json
import uuid
from typing import List, Dict
import random

def generate_training_data(num_transactions: int = 1000) -> List[Dict]:
    """
    Generate synthetic training data for model training
    
    Args:
        num_transactions: Number of transactions to generate
        
    Returns:
        List of transaction dictionaries
    """
    # Set random seed for reproducibility
    np.random.seed(42)
    random.seed(42)
    
    # Calculate number of fraudulent transactions (10% of total)
    num_fraud = int(num_transactions * 0.01)
    
    # Generate user IDs
    num_users = 10
    user_ids = [f'user_{i}' for i in range(num_users)]
    
    # Generate normal devices
    normal_devices = ['mobile-ios', 'web-chrome', 'web-safari']
    
    # Generate locations
    locations = [
        'Vietnam', 'USA', 'UK', 'Japan', 'South Korea', 'Taiwan',
        'Singapore', 'Thailand', 'Malaysia', 'Indonesia', 'Philippines'
    ]
    
    # Generate normal categories and their descriptions
    normal_categories = {
        'clothing': [
            'Clothing purchase at Zara',
            'Shopping at H&M',
            'Fashion store payment',
            'Clothing store transaction'
        ],
        'food': [
            'Restaurant payment',
            'Food delivery order',
            'Cafe payment',
            'Grocery shopping'
        ],
        'transportation': [
            'Grab ride payment',
            'Taxi fare',
            'Bus ticket',
            'Train ticket'
        ],
        'shopping': [
            'Online shopping',
            'Supermarket payment',
            'Convenience store',
            'Department store'
        ]
    }
    
    # Generate additional categories for fraudulent transactions
    fraud_categories = {
        'electronics': [
            'Laptop purchase',
            'Smartphone payment', 
            'Gaming console',
            'High-end electronics',
            'Camera equipment',
            'Smart home devices',
            'Audio systems',
            'Tablet purchase'
        ],
        'entertainment': [
            'Gaming credits',
            'Streaming subscription',
            'Online gaming',
            'Digital content',
            'Concert tickets',
            'Movie tickets',
            'Theme park passes',
            'Sports events'
        ],
        'travel': [
            'Flight booking',
            'Hotel reservation', 
            'Tour package',
            'International travel',
            'Cruise booking',
            'Car rental',
            'Travel insurance',
            'Resort booking'
        ],
        'luxury': [
            'Jewelry purchase',
            'Luxury watch',
            'Designer goods',
            'High-end fashion',
            'Art gallery purchase',
            'Antique items',
            'Limited editions',
            'Premium accessories'
        ],
        'investment': [
            'Cryptocurrency purchase',
            'Stock trading',
            'Forex trading', 
            'Investment fund',
            'Gold purchase',
            'Real estate deposit',
            'Bond trading',
            'NFT purchase'
        ],
        'gambling': [
            'Online casino',
            'Sports betting',
            'Lottery tickets',
            'Poker games',
            'Slot machines',
            'Race betting',
            'Bingo games',
            'Fantasy sports'
        ],
        'services': [
            'Web hosting',
            'Software licenses',
            'Cloud storage',
            'VPN services',
            'Domain purchase',
            'Online courses',
            'Consulting fees',
            'Premium memberships'
        ],
        'health': [
            'Medical equipment',
            'Health supplements',
            'Fitness gear',
            'Spa services',
            'Beauty treatments',
            'Dental services',
            'Vision care',
            'Wellness programs'
        ]
    }
    
    # Generate currencies
    currencies = ['VND', 'USD', 'EUR', 'JPY', 'KRW', 'SGD', 'THB', 'TWD']
    
    # Generate transactions
    transactions = []
    start_date = datetime.now() - timedelta(days=30)
    
    # Generate normal transactions
    for i in range(num_transactions - num_fraud):
        # Random user
        user_id = random.choice(user_ids)
        
        # Random category and matching description
        category = random.choice(list(normal_categories.keys()))
        description = random.choice(normal_categories[category])
        
        # Generate transaction
        transaction = {
            'transaction_id': str(uuid.uuid4()),
            'user_id': user_id,
            'amount': round(np.random.uniform(10000, 5000000), 2),  # 10k - 5M VND
            'currency': 'VND',
            'description': description,
            'category': category,
            'timestamp': (start_date + timedelta(
                days=random.randint(0, 30),
                hours=random.randint(8, 23)  # From 8 AM to 11 PM
            )).isoformat(),
            'ip_address': f'203.160.{random.randint(1, 255)}.{random.randint(1, 255)}',
            'geolocation': 'Vietnam',
            'device_id': random.choice(normal_devices),
            'is_fraud': False
        }
        transactions.append(transaction)
    
    # Generate fraudulent transactions
    for i in range(num_fraud):
        # Random user
        user_id = random.choice(user_ids)
        
        # Random category and description (can be from normal or fraud categories)
        all_categories = {**normal_categories, **fraud_categories}
        category = random.choice(list(all_categories.keys()))
        description = random.choice(all_categories[category])
        
        # Generate transaction with random values
        transaction = {
            'transaction_id': str(uuid.uuid4()),
            'user_id': user_id,
            'amount': round(np.random.uniform(1000000, 10000000), 2),  # Higher amounts
            'currency': random.choice(currencies),
            'description': description,
            'category': category,
            'timestamp': (start_date + timedelta(
                days=random.randint(0, 30),
                hours=random.randint(0, 23)  # Any hour
            )).isoformat(),
            'ip_address': f'{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}',
            'geolocation': random.choice(locations),
            'device_id': random.choice([
                'mobile-android',
                'mobile-ios', 
                'web-chrome',
                'web-safari',
                'web-firefox',
                'web-edge',
                'tablet-android',
                'tablet-ios',
                'desktop-windows',
                'desktop-mac',
                'desktop-linux',
                'smart-tv',
                'game-console',
                'unknown-device'
            ]),
            'is_fraud': True
        }
        transactions.append(transaction)
    
    # Shuffle transactions
    random.shuffle(transactions)
    
    return transactions

if __name__ == "__main__":
    # Generate sample data
    data = generate_training_data(100000)
    
    # Save to file
    with open('training_data.json', 'w') as f:
        json.dump({'training_data': data}, f, indent=2)
    
    print(f"Generated {len(data)} transactions")
    print(f"Normal transactions: {len([t for t in data if not t['is_fraud']])}")
    print(f"Fraudulent transactions: {len([t for t in data if t['is_fraud']])}") 