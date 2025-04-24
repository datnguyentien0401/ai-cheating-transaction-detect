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
    num_fraud = int(num_transactions * 0.1)
    
    # Generate user IDs
    num_users = 10
    user_ids = [f'user_{i}' for i in range(num_users)]
    
    # Generate device IDs
    devices = ['mobile-android', 'mobile-ios', 'web-chrome', 'web-safari', 'tablet-android']
    
    # Generate locations
    locations = [
        'Vietnam', 'USA', 'UK', 'Japan', 'South Korea',
        'Singapore', 'Thailand', 'Malaysia', 'Indonesia', 'Philippines'
    ]
    
    # Generate categories
    categories = [
        'Electronics', 'Clothing', 'Food', 'Transportation',
        'Entertainment', 'Home', 'Beauty', 'Education', 'Health', 'Other'
    ]
    
    # Generate currencies
    currencies = ['VND', 'USD', 'EUR', 'JPY', 'KRW', 'SGD', 'THB']
    
    # Generate descriptions
    descriptions = [
        'Restaurant payment',
        'Online shopping',
        'Transport fare',
        'Movie tickets',
        'Electronics purchase',
        'Clothing purchase',
        'Home goods',
        'Beauty products',
        'Course payment',
        'Hotel booking'
    ]
    
    # Generate transactions
    transactions = []
    start_date = datetime.now() - timedelta(days=30)
    
    # First, generate all legitimate transactions
    for _ in range(num_transactions - num_fraud):
        # Generate transaction data
        user_id = random.choice(user_ids)
        # For legitimate transactions, prefer mobile-ios (70% chance)
        device_id = 'mobile-ios' if random.random() < 0.7 else random.choice(devices)
        location = random.choice(locations)
        category = random.choice(categories)
        currency = random.choice(currencies)
        description = random.choice(descriptions)
        
        # Generate amount based on category
        base_amount = random.uniform(100000, 5000000)
        if category == 'Electronics':
            amount = base_amount * random.uniform(1.5, 3.0)
        elif category == 'Food':
            amount = base_amount * random.uniform(0.3, 0.8)
        else:
            amount = base_amount
            
        # Generate timestamp
        timestamp = start_date + timedelta(
            days=random.randint(0, 30),
            hours=random.randint(0, 23),
            minutes=random.randint(0, 59)
        )
        
        # Generate IP address for legitimate transactions (mostly Vietnam IPs)
        if random.random() < 0.8:  # 80% chance of Vietnam IP
            ip_address = f'192.168.{random.randint(1,255)}.{random.randint(1,255)}'
        else:  # 20% chance of other IPs
            ip_address = f'{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}'
        
        # Create legitimate transaction record
        transaction = {
            'transaction_id': f'tx_{uuid.uuid4().hex[:8]}',
            'user_id': user_id,
            'amount': amount,
            'currency': currency,
            'description': description,
            'category': category,
            'timestamp': timestamp,
            'ip_address': ip_address,
            'geolocation': location,
            'device_id': device_id,
            'is_fraud': False,
            'fraud_reasons': []
        }
        
        transactions.append(transaction)
    
    # Then, generate fraudulent transactions
    for _ in range(num_fraud):
        # Generate transaction data
        user_id = random.choice(user_ids)
        # For fraudulent transactions, prefer non-mobile-ios devices (80% chance)
        device_id = random.choice([d for d in devices if d != 'mobile-ios']) if random.random() < 0.8 else 'mobile-ios'
        location = random.choice(locations)
        category = random.choice(categories)
        currency = random.choice(currencies)
        description = random.choice(descriptions)
        
        # Generate amount based on category
        base_amount = random.uniform(100000, 5000000)
        if category == 'Electronics':
            amount = base_amount * random.uniform(1.5, 3.0)
        elif category == 'Food':
            amount = base_amount * random.uniform(0.3, 0.8)
        else:
            amount = base_amount
            
        # Generate timestamp
        timestamp = start_date + timedelta(
            days=random.randint(0, 30),
            hours=random.randint(0, 23),
            minutes=random.randint(0, 59)
        )
        
        # Generate IP address for fraudulent transactions (mostly non-Vietnam IPs)
        if random.random() < 0.7:  # 70% chance of non-Vietnam IP
            # Generate IPs that look like they're from other countries
            ip_address = f'{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}'
        else:  # 30% chance of Vietnam IP
            ip_address = f'192.168.{random.randint(1,255)}.{random.randint(1,255)}'
        
        # Determine fraud reasons
        fraud_reasons = []
        
        # Rule 1: Unusual amount
        if amount > 3000000:  # Very high amount
            fraud_reasons.append('Unusual amount')
            
        # Rule 2: Unusual location
        if location not in ['Vietnam', 'Thailand', 'Singapore']:  # Unusual location
            fraud_reasons.append('Unusual location')
            
        # Rule 3: Unusual time
        if timestamp.hour >= 1 and timestamp.hour <= 5:  # Very early morning
            fraud_reasons.append('Unusual time')
            
        # Rule 4: Unusual currency
        if currency != 'VND':  # Unusual currency
            fraud_reasons.append('Unusual currency')
            
        # Rule 5: Unusual category
        if category in ['Electronics', 'Entertainment'] and amount > 2000000:  # High value luxury items
            fraud_reasons.append('Unusual category')
            
        # Rule 6: Unusual device
        if device_id != 'mobile-ios':  # Non-mobile-ios device
            fraud_reasons.append('Unusual device')
            
        # Rule 7: Unusual IP address
        if not ip_address.startswith('192.168.'):  # Non-Vietnam IP
            fraud_reasons.append('Unusual IP address')
        
        # Ensure at least one fraud reason
        if not fraud_reasons:
            # If no fraud reasons, force one
            if random.random() < 0.5:
                amount = random.uniform(4000000, 10000000)  # Force high amount
                fraud_reasons.append('Unusual amount')
            else:
                device_id = random.choice([d for d in devices if d != 'mobile-ios'])  # Force unusual device
                fraud_reasons.append('Unusual device')
        
        # Create fraudulent transaction record
        transaction = {
            'transaction_id': f'tx_{uuid.uuid4().hex[:8]}',
            'user_id': user_id,
            'amount': amount,
            'currency': currency,
            'description': description,
            'category': category,
            'timestamp': timestamp,
            'ip_address': ip_address,
            'geolocation': location,
            'device_id': device_id,
            'is_fraud': True,
            'fraud_reasons': fraud_reasons
        }
        
        transactions.append(transaction)
    
    # Shuffle transactions to mix legitimate and fraudulent
    random.shuffle(transactions)
    
    return transactions

if __name__ == "__main__":
    # Generate training data
    transactions = generate_training_data(1000)
    
    # Save to JSON file
    with open('training_data.json', 'w') as f:
        json.dump(transactions, f, default=str, indent=2)
    
    print(f"Generated {len(transactions)} transactions")
    print(f"Fraudulent transactions: {sum(1 for t in transactions if t['is_fraud'])}")
    print("Data saved to training_data.json") 