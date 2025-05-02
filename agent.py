import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
from datetime import datetime, timedelta
import pickle
import requests
import logging
from database import get_db, User, Transaction,TransactionAnalysis, UserProfile
from sqlalchemy.orm import Session
import json
import os
from openai import OpenAI
import uuid
from typing import Dict, List, Optional, Tuple

class FraudDetectionSystem:
    # Class constants
    FRAUD_DETECTION_PROMPT = """
    Analyze this transaction for potential fraud. The process includes:

    1. **Historical Data Modeling:** 
       - Compile a list of past transactions with important information such as transaction time, location, transaction amount, transaction type, transaction frequency, and previous transaction contacts.

    2. **Analyze the new transaction to determine fraud probability:**

    * **Analysis based on historical data, account information, and unusual factors:**

        * **Unusual Transaction Characteristics:**
            * **Transaction Value:** Compare current transaction value with average and standard deviation of previous transactions (by product type, quantity). Identify transactions exceeding significant thresholds.
            * **Transaction Type:** Identify transaction types different from the account's usual purchase history.
            * **Products and Prices:** Analyze the rationality between products and prices. High-value product purchases (e.g., luxury items) may be more suspicious than essential items (e.g., food, daily necessities), especially if not consistent with shopping history.
            * **Duplicate Transactions:** Duplicate or similar transactions within a short time period may indicate fraudulent behavior. However, if the quantity is small and value is low, it could be normal behavior. For example, buying a coffee and a pastry at the same time could be normal behavior.
            
        * **Suspicious Transaction Time and Location:**
            * **Transaction Time:** Detect transactions occurring outside the user's usual transaction hours.
            * **Transaction Location:** Identify transactions from locations different from familiar transaction locations.
            * **IP Address and Geographic Location:** Compare the IP address used for the transaction with the user's usual geographic location. Alert transactions from countries or IP ranges with fraud history.
        * **Unusual Behavior and Transaction Frequency:**
            * **Transaction Behavior:** Compare current transaction attributes (value, location, time, device used) with account transaction history to detect notable differences.
            * **Transaction Frequency:** Detect sudden increases in transaction quantity within a short time period, which could indicate testing behavior or automated attacks.
        * **Suspicious Account Information Changes:**
            * **Personal Information:** Monitor unusual changes in account information such as email address, phone number, shipping address, which could indicate account compromise.
            * **Access Device:** Record and compare the device (device ID, operating system) used for transactions with the user's familiar devices.
        * **Context and User Behavior Analysis:**
            * **System Interaction:** Analyze user behavior on the website or application before making transactions (e.g., product review time, pages visited, mouse actions).
            * **VPN/Proxy Usage:** Detect transactions made through VPN or proxy services, especially anonymous proxies or those from suspicious sources.
            * **Continuous Incorrect Input:** Record the number of incorrect sensitive information entries (e.g., password, CVV code) before successful transaction, which could indicate guessing behavior or brute-force attacks.
        * **External Data Sources:**
            * **Blacklists:** Check transaction information (email, phone number, IP address, card number) against verified blacklists of fraudulent entities or activities.
            * **Shared Information:** Leverage information and alerts about new fraud methods from anti-fraud organizations and security communities.
        * **Comprehensive Analysis and Risk Assessment:**
            * **Risk Modeling:** Apply machine learning and statistical models to combine all analysis factors and provide a comprehensive assessment of transaction fraud risk.
            * **History and Behavior Comparison:** Compare current transaction with entire transaction history and user interaction behavior to detect unusual patterns and inconsistencies.
            * **Continuous Learning:** The system should be designed to continuously monitor the results of marked transactions and adjust analysis criteria based on new fraud patterns.
        * **Other Analysis Criteria:** (Add other specific criteria if applicable).

    3. **Calculate Fraud Probability:**
    * **Apply Analysis Algorithms:** Use analysis algorithms (e.g., rule-based, statistical, machine learning) to estimate the probability of a new transaction being fraudulent based on defined analysis criteria.
    * **Criteria Weights:** Note that each analysis criterion may have different weights, reflecting its importance in fraud prediction. These weights can be adjusted based on model performance and in-depth analysis.

    4. **Essential Purchases:** Transactions for essential items such as food, daily necessities, coffee, etc., may be considered with lower fraud probability compared to luxury or non-essential item purchases.

    **Evaluation and Decision:**
       - Provide final overall score as fraud_score indicating fraud suspicion. Summarize and make a decision about whether to proceed or stop the transaction.

    Based on these criteria and ratios, the final score indicates the probability of this transaction being fraudulent. Recommend temporarily stopping the transaction for additional verification.

    Please analyze the following transaction information:
    - Account Information (JSON):
      ```
      {account_info}
      ```
    - Transaction History (JSON):
      ```
      {history_info}
      ```
    - New Transaction (JSON):
      ```
      {transaction_info}
      ```
    And return a response with the following criteria:
     - In English and in JSON format.
     - `fraud_score` will be equal to the average of all `fraud_score` values in `fraud_details`. For example, if fraud_details contains:
       [
         {{"fraud_score": 60, "type": "location_check"}},
         {{"fraud_score": 40, "type": "amount_check"}},
         {{"fraud_score": 80, "type": "device_check"}}
       ]
       Then the final fraud_score will be (60 + 40 + 80) / 3 = 60
     - All data in the response must be related and consistent with each other
     - The types in fraud_details must not be duplicates
    Here is an example:
    {{
      "fraud_score": 60,
      "fraud_decision": true,
      "fraud_reason": "Transaction amount is relatively low but from an unusual device and the IP address does not match the usual patterns.",
      "fraud_details": [
        {{
          "fraud_score": 60,
          "type": "location_check",
          "message": "In usual area"
        }},
        {{
          "fraud_score": 40,
          "type": "amount_check",
          "message": "Amount within normal range"
        }},
        {{
          "fraud_score": 80,
          "type": "device_check",
          "message": "New device detected"
        }}
      ],
      "fraud_suggestions": "Contact user for confirmation and monitor future transactions from this device and IP address.",
      "fraud_alert": true,
      "fraud_alert_message": "Potential fraud activity detected.",
      "fraud_alert_details": "Transaction conducted from an unrecognized device and IP address outside the usual patterns.",
      "fraud_alert_suggestions": "Consider blocking this transaction until further verification."
    }}
    """

    def __init__(self):
        # Thiết lập logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('fraud_detection.log'),
                logging.StreamHandler()  # Thêm handler để log ra console
            ]
        )
        self.logger = logging.getLogger('fraud_detection')
        
        # Load mô hình hoặc tạo mới nếu chưa có
        try:
            model_path = os.path.join(os.path.dirname(__file__), 'fraud_detection_model.pkl')
            if os.path.exists(model_path):
                with open(model_path, 'rb') as f:
                    self.model = pickle.load(f)
            else:
                self.logger.warning(f"Model file not found at {model_path}")
                raise FileNotFoundError("Model file not found")
            # self.scaler = pickle.load(open('scaler.pkl', 'rb'))
            # self.encoder = pickle.load(open('encoder.pkl', 'rb'))
            self.logger.info("Đã tải mô hình phát hiện gian lận từ file")
        except:
            self.logger.info("Khởi tạo mô hình mới")
            self.model = None
            self.scaler = StandardScaler()
            self.encoder = OneHotEncoder(handle_unknown='ignore')
            
        # Giá trị ngưỡng
        self.thresholds = {
            'amount_threshold_factor': 2.0,  # Hệ số so với giá trị trung bình
            'suspicious_hour_start': 1,      # Từ 1 giờ sáng
            'suspicious_hour_end': 5,        # Đến 5 giờ sáng
            'max_transactions_per_hour': 5,  # Số giao dịch tối đa trong 1 giờ
            'anomaly_score_threshold': 0.65   # Ngưỡng điểm bất thường
        }
        
        # Danh sách IP được biết là nguy hiểm từ nguồn bên ngoài
        self.known_bad_ips = self._load_known_bad_ips()
    
    def _load_known_bad_ips(self):
        """Tải danh sách IP đã biết là độc hại từ API AbuseIPDB"""
        try:
            # Sử dụng API AbuseIPDB để lấy danh sách IP độc hại
            # Bạn cần đăng ký tài khoản tại https://www.abuseipdb.com để lấy API key
            api_key = os.getenv('ABUSEIPDB_API_KEY')
            headers = {
                'Key': api_key,
                'Accept': 'application/json'
            }
            
            # Lấy danh sách blacklist IP có điểm tin cậy từ 90% trở lên trong 30 ngày qua
            params = {
                'confidenceMinimum': 90,
                'limit': 100  # Giới hạn số lượng IP trả về
            }
            
            response = requests.get(
                "https://api.abuseipdb.com/api/v2/blacklist",
                headers=headers,
                params=params,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                # Trích xuất danh sách IP từ phản hồi
                ip_list = [item['ipAddress'] for item in data.get('data', [])]
                self.logger.info(f"Đã tải thành công {len(ip_list)} IP độc hại")
                return set(ip_list)
            else:
                self.logger.warning(f"Lỗi khi tải IP độc hại từ API, đọc từ file dự phòng")
                try:
                    with open('ip_data.json', 'r') as f:
                        data = json.loads(f.read())
                        ip_list = [item['ipAddress'] for item in data.get('data', [])]
                        self.logger.info(f"Đã tải {len(ip_list)} IP độc hại từ file")
                        return set(ip_list)
                except Exception as e:
                    self.logger.warning(f"Không thể đọc file ip_data.json: {str(e)}")
                    return set()
        except Exception as e:
            self.logger.warning(f"Không thể tải danh sách IP độc hại: {str(e)}")
            return set()
    
    def _get_user_location_history(self, db: Session, user_id: str):
        """Lấy lịch sử vị trí của người dùng từ database"""
        user_profile = db.query(UserProfile).filter(UserProfile.user_id == user_id).first()
        if user_profile and user_profile.common_locations:
            return user_profile.common_locations
        return []
    
    def _get_user_ip_address_history(self, db: Session, user_id: str):
        """Lấy lịch sử vị trí của người dùng từ database"""
        try:
            self.logger.info(f"Lấy lịch sử IP của user {user_id}")
            
            user_profile = db.query(UserProfile).filter(UserProfile.user_id == user_id).first()
            
            if user_profile and user_profile.common_ip_addresses:
                ip_addresses = user_profile.common_ip_addresses
                self.logger.info(f"Tìm thấy {len(ip_addresses)} IP trong lịch sử")
                self.logger.debug(f"Danh sách IP: {ip_addresses}")
                return ip_addresses
            
            self.logger.info("Không tìm thấy lịch sử IP")
            return []
        except Exception as e:
            self.logger.error(f"Lỗi khi lấy lịch sử IP: {str(e)}", exc_info=True)
            return []
    
    def _get_user_transaction_history(self, db: Session, user_id: str):
        """Lấy lịch sử giao dịch của người dùng từ database"""

        transactions = db.query(Transaction).filter(Transaction.user_id == user_id).order_by(Transaction.timestamp.desc()).limit(100).all()
        self.logger.info(f"Tìm thấy {len(transactions)} giao dịch")

        return [{
            'amount': t.amount,
            'currency': t.currency,
            'description': t.description,
            'category': t.category,
            'timestamp': t.timestamp.isoformat() if isinstance(t.timestamp, datetime) else t.timestamp,
            'geolocation': t.geolocation,
            'device_id': t.device_id,
            'ip_address': t.ip_address
        } for t in transactions]
    
    def _get_average_transaction_amount(self, db: Session, user_id: str):
        """Tính số tiền giao dịch trung bình của người dùng từ database"""
        user_profile = db.query(UserProfile).filter(UserProfile.user_id == user_id).first()
        if user_profile:
            return user_profile.avg_transaction_amount
        return 0
    
    def _get_common_categories(self, db: Session, user_id: str):
        """Lấy các danh mục sản phẩm thường mua của người dùng từ database"""
        user_profile = db.query(UserProfile).filter(UserProfile.user_id == user_id).first()
        if user_profile and user_profile.common_categories:
            return set(user_profile.common_categories)
        return set()
    
    def _get_common_transaction_times(self, db: Session, user_id: str):
        """Lấy thời gian giao dịch thường xuyên của người dùng từ database"""
        user_profile = db.query(UserProfile).filter(UserProfile.user_id == user_id).first()
        if user_profile and user_profile.typical_transaction_hours:
            return user_profile.typical_transaction_hours
        return []
    
    def _get_recent_transactions(self, db: Session, user_id: str, hours=1):
        """Lấy số lượng giao dịch gần đây trong khoảng thời gian chỉ định từ database"""
        cutoff_time = datetime.now() - pd.Timedelta(hours=hours)
        recent = db.query(Transaction).filter(
            Transaction.user_id == user_id,
            Transaction.timestamp >= cutoff_time
        ).all()
        return recent
    
    def _get_user_profile(self, db: Session, user_id: str) -> Optional[Dict]:
        """
        Lấy thông tin profile của user từ database
        """
        try:
            # Lấy user profile từ database
            profile = db.query(UserProfile).filter(UserProfile.user_id == user_id).first()
            self.logger.info(f"Found profile: {profile.__dict__ if profile else None}")
            
            # Return default profile if no profile found
            if not profile:
                return {
                    'common_ip_addresses': [],
                    'common_locations': [],
                    'common_devices': [],
                    'common_categories': [],
                    'avg_transaction_amount': 0.0,
                    'typical_transaction_hours': [],
                    'transactions': []
                }
                
            # Chuyển đổi profile thành dictionary
            return {
                'common_ip_addresses': profile.common_ip_addresses if profile.common_ip_addresses else [],
                'common_locations': profile.common_locations if profile.common_locations else [],
                'common_devices': profile.common_devices if profile.common_devices else [],
                'common_categories': profile.common_categories if profile.common_categories else [],
                'avg_transaction_amount': profile.avg_transaction_amount,
                'typical_transaction_hours': profile.typical_transaction_hours if profile.typical_transaction_hours else [],
                'transactions': self._get_user_transaction_history(db, user_id)
            }
            
        except Exception as e:
            logging.error(f"Error getting user profile: {str(e)}")
            return {
                'common_ip_addresses': [],
                'common_locations': [],
                'common_devices': [],
                'common_categories': [],
                'avg_transaction_amount': 0.0,
                'typical_transaction_hours': [],
                'transactions': []
            }
    
    def _check_ip_address(self, db: Session, user_id: str, ip_address: str) -> Dict:
        """Check if the IP address is suspicious"""
        try:
            self.logger.info(f"Checking IP {ip_address} for user {user_id}")
            
            # Check if IP is in blacklist
            if ip_address in self.known_bad_ips:
                self.logger.warning(f"IP {ip_address} is in the malicious IP list")
                return {
                    'is_suspicious': True,
                    'reason': 'IP is in the known malicious IP list',
                    'risk_score': 0.9
                }
        
            # Get user profile
            common_ips = self._get_user_ip_address_history(db, user_id)
            self.logger.info(f"User's common IPs: {common_ips}")
            
            if ip_address not in common_ips:
                self.logger.warning(f"IP {ip_address} has never appeared in history")
                return {
                    'is_suspicious': True,
                    'reason': f'New IP: {ip_address} has never appeared in history',
                    'risk_score': 0.7
                }
            
            self.logger.info(f"IP {ip_address} is valid")
            return {'is_suspicious': False, 'reason': '', 'risk_score': 0.0}
            
        except Exception as e:
            self.logger.error(f"Error checking IP address: {str(e)}")
            return {'is_suspicious': False, 'reason': '', 'risk_score': 0.0}

    def _check_location(self, db: Session, user_id, geolocation):
        """Check if the location is suspicious"""
        try:
            self.logger.info(f"Checking location {geolocation} for user {user_id}")
            
            # Check if location is in history
            locations = self._get_user_location_history(db, user_id)
            self.logger.info(f"User's common locations: {locations}")
            
            if locations and geolocation not in locations:
                self.logger.warning(f"New location: {geolocation} has never appeared in history")
                return {
                    'is_suspicious': True,
                    'reason': f'New location: {geolocation} has never appeared in history',
                    'risk_score': 0.7
                }
        
            self.logger.info(f"Location {geolocation} is valid")
            return {'is_suspicious': False, 'reason': '', 'risk_score': 0.0}
            
        except Exception as e:
            self.logger.error(f"Error checking location: {str(e)}")
            return {'is_suspicious': False, 'reason': '', 'risk_score': 0.0}
    
    def _check_amount(self, db: Session, user_id, amount):
        """Check if the transaction amount is suspicious"""
        avg_amount = self._get_average_transaction_amount(db, user_id)
        threshold = avg_amount * self.thresholds['amount_threshold_factor']
        
        if amount > threshold and threshold > 0:
            return {
                'is_suspicious': True,
                'reason': f'Amount ({amount}) is higher than normal threshold ({threshold:.2f})',
                'risk_score': min(0.9, (amount / threshold) * 0.5)
            }
        
        return {'is_suspicious': False, 'reason': '', 'risk_score': 0.0}
    
    def _check_category(self, db: Session, user_id, category):
        """Check if the product category is suspicious"""
        common_categories = self._get_common_categories(db, user_id)
        
        if common_categories and category not in common_categories:
            return {
                'is_suspicious': True,
                'reason': f'New product category: {category}',
                'risk_score': 0.5
            }
        
        return {'is_suspicious': False, 'reason': '', 'risk_score': 0.0}
    
    def _check_time(self, db: Session, user_id, timestamp):
        """Check if the transaction time is suspicious"""
        hour = timestamp.hour
        
        # Check if transaction time is in suspicious hours
        if self.thresholds['suspicious_hour_start'] <= hour <= self.thresholds['suspicious_hour_end']:
            # Check if user usually transacts at this hour
            common_hours = self._get_common_transaction_times(db, user_id)
            if hour not in common_hours:
                return {
                    'is_suspicious': True,
                    'reason': f'Transaction at unusual time: {hour}:00',
                    'risk_score': 0.6
                }
        
        return {'is_suspicious': False, 'reason': '', 'risk_score': 0.0}
    
    def _check_frequency(self, db: Session, user_id, timestamp):
        """Check if the transaction frequency is suspicious"""
        recent = self._get_recent_transactions(db, user_id, hours=1)
        
        if len(recent) >= self.thresholds['max_transactions_per_hour']:
            return {
                'is_suspicious': True,
                'reason': f'Unusual number of transactions in 1 hour: {len(recent)}',
                'risk_score': min(0.8, len(recent) / self.thresholds['max_transactions_per_hour'] * 0.4)
            }
        
        return {'is_suspicious': False, 'reason': '', 'risk_score': 0.0}
    
    def _check_device(self, db: Session, user_id, device_id):
        """Check if the device is suspicious"""
        user_profile = db.query(UserProfile).filter(UserProfile.user_id == user_id).first()
        if user_profile and user_profile.common_devices:
            common_devices = user_profile.common_devices
            if device_id not in common_devices:
                return {
                    'is_suspicious': True,
                    'reason': f'New device: {device_id}',
                    'risk_score': 0.6
                }
        
        return {'is_suspicious': False, 'reason': '', 'risk_score': 0.0}
    
    
    def train_model(self, db: Session, transaction_data: list):
        """Huấn luyện mô hình phát hiện gian lận từ dữ liệu giao dịch trong database"""
        if len(transaction_data) < 10:
            self.logger.warning("Không đủ dữ liệu để huấn luyện mô hình")
            return False
        
        try:
            self.logger.info("Bắt đầu huấn luyện mô hình với dữ liệu giao dịch.")
            # Chuẩn bị dữ liệu
            df = pd.DataFrame(transaction_data)
            self.logger.info(f"Số lượng giao dịch: {len(df)}")
            
            # Chuyển đổi timestamp thành giờ
            df['hour'] = pd.to_datetime(df['timestamp']).dt.hour
            
            # Chọn features
            features = ['amount', 'hour', 'currency', 'description', 'category', 'ip_address', 'geolocation', 'device_id']
            X = df[features]
            y = df['is_fraud'] if 'is_fraud' in df.columns else None
            self.logger.info(f"Features được sử dụng: {features}")
            
            # Xác định các cột theo loại
            categorical_features = ['currency', 'description', 'category', 'ip_address', 'geolocation', 'device_id']
            numeric_features = ['amount', 'hour']
            self.logger.info(f"Các features số: {numeric_features}")
            self.logger.info(f"Các features phân loại: {categorical_features}")
            
            # Tạo preprocessor
            preprocessor = ColumnTransformer(
                transformers=[
                    ('num', StandardScaler(), numeric_features),
                    ('cat', OneHotEncoder(handle_unknown='ignore'), categorical_features)
                ])
            
            # Huấn luyện mô hình
            if y is not None:
                self.logger.info("Huấn luyện mô hình với Random Forest.")
                # Supervised learning with Random Forest
                self.model = Pipeline(steps=[
                    ('preprocessor', preprocessor),
                    ('classifier', RandomForestClassifier(n_estimators=100, random_state=42))
                ])
                self.model.fit(X, y)
            else:
                self.logger.info("Huấn luyện mô hình với Isolation Forest.")
                # Unsupervised learning with Isolation Forest
                self.model = Pipeline(steps=[
                    ('preprocessor', preprocessor),
                    ('classifier', IsolationForest(contamination=0.1, random_state=42))
                ])
                self.model.fit(X)
            
            # Lưu mô hình và các transformer
            pickle.dump(self.model, open('fraud_detection_model.pkl', 'wb'))
            self.logger.info("Mô hình đã được huấn luyện và lưu thành công")
            return True
            
        except Exception as e:
            self.logger.error(f"Lỗi khi huấn luyện mô hình: {str(e)}")
            return False
    
    def predict_with_model(self, transaction):
        """Dự đoán rủi ro gian lận bằng mô hình máy học"""
        if self.model is None:
            return 0.5  # Giá trị mặc định nếu chưa có mô hình
        
        try:
            # Chuẩn bị dữ liệu đầu vào
            df = pd.DataFrame([transaction])
            
            # Chuyển đổi timestamp thành giờ
            df['hour'] = pd.to_datetime(df['timestamp']).dt.hour
            
            # Chọn features
            features = ['amount', 'hour', 'currency', 'description', 'category', 'ip_address', 'geolocation', 'device_id']
            X = df[features]
            
            # Thực hiện dự đoán
            if isinstance(self.model.named_steps['classifier'], RandomForestClassifier):
                # Lấy xác suất của lớp dương tính (gian lận)
                self.logger.info("Using RandomForestClassifier for prediction")
                proba = self.model.predict_proba(X)[0][1]
                self.logger.info(f"Predicted fraud probability: {proba}")
                return proba
            else:
                # Isolation Forest trả về điểm bất thường
                self.logger.info("Using IsolationForest for prediction") 
                score = -self.model.decision_function(X)[0]
                normalized_score = score / 2 + 0.5  # Chuẩn hóa về khoảng 0-1
                self.logger.info(f"Raw anomaly score: {score}")
                self.logger.info(f"Normalized anomaly score: {normalized_score}")
                return normalized_score
        except Exception as e:
            self.logger.error(f"Lỗi khi dự đoán với mô hình: {str(e)}")
            return 0.5
    
    def update_user_profile(self, db: Session, user_id: str, transaction_data: dict):
        """Cập nhật hồ sơ người dùng với dữ liệu giao dịch mới vào database"""
        self.logger.info(f"Updating user profile for user {user_id}")
        
        # Tạo hoặc cập nhật user
        user = db.query(User).filter(User.user_id == user_id).first()
        if not user:
            self.logger.info(f"Creating new user record for {user_id}")
            user = User(user_id=user_id)
            db.add(user)
        
        # Tạo transaction mới
        self.logger.info(f"Creating new transaction record for transaction {transaction_data.get('transaction_id')}")
        transaction = Transaction(
            transaction_id=transaction_data.get('transaction_id'),
            user_id=user_id,
            amount=transaction_data.get('amount', 0),
            currency=transaction_data.get('currency', 'VND'),
            description=transaction_data.get('description', ''),
            category=transaction_data.get('category'),
            timestamp=transaction_data.get('timestamp', datetime.now()),
            ip_address=transaction_data.get('ip_address'),
            geolocation=transaction_data.get('geolocation'),
            device_id=transaction_data.get('device_id'),
        )
        db.add(transaction)
        
        # Cập nhật user profile
        profile = db.query(UserProfile).filter(UserProfile.user_id == user_id).first()
        if not profile:
            self.logger.info(f"Creating new user profile for {user_id}")
            profile = UserProfile(user_id=user_id)
            db.add(profile)
        
        # Cập nhật các thông tin profile
        self.logger.info(f"Fetching transaction history for user {user_id}")
        transactions = self._get_user_transaction_history(db, user_id)
        if transactions:
            self.logger.info(f"Found {len(transactions)} transactions for user {user_id}")
            
            # Cập nhật locations
            locations = set(t.get('geolocation') for t in transactions if t.get('geolocation'))
            profile.common_locations = list(locations)
            self.logger.debug(f"Updated common locations: {profile.common_locations}")
            
            # Cập nhật devices
            devices = set(t.get('device_id') for t in transactions if t.get('device_id'))
            profile.common_devices = list(devices)
            self.logger.debug(f"Updated common devices: {profile.common_devices}")
            
            # Cập nhật categories
            categories = set(t.get('category') for t in transactions if t.get('category'))
            profile.common_categories = list(categories)
            self.logger.debug(f"Updated common categories: {profile.common_categories}")
            
            # Cập nhật ip_addresses
            ip_addresses = set(t.get('ip_address') for t in transactions if t.get('ip_address'))
            profile.common_ip_addresses = list(ip_addresses)
            self.logger.debug(f"Updated common IP addresses: {profile.common_ip_addresses}")
                
            # Cập nhật avg_transaction_amount
            profile.avg_transaction_amount = sum(t.get('amount', 0) for t in transactions) / len(transactions)
            self.logger.debug(f"Updated average transaction amount: {profile.avg_transaction_amount}")
            
            # Cập nhật typical_transaction_hours
            hours = [datetime.fromisoformat(t['timestamp']).hour if isinstance(t['timestamp'], str) else t['timestamp'].hour for t in transactions if 'timestamp' in t]
            profile.typical_transaction_hours = list(set(hours))
            self.logger.debug(f"Updated typical transaction hours: {profile.typical_transaction_hours}")
        
        profile.last_updated = datetime.now()
        self.logger.info(f"Committing updates to database for user {user_id}")
        db.commit()
        self.logger.info(f"Successfully updated user profile for {user_id}")
    
    def analyze_transaction(self, db: Session, transaction_data: dict):
        """
        Analyze transaction using traditional rule-based methods
        Returns:
            Dict containing:
            - fraud_score: float (0-100)
            - is_suspicious: bool
            - analysis_details: List[Dict] containing detailed analysis results
            - reasons: List[str] containing reasons for the decision
        """
        self.logger.info(f"Starting ML transaction analysis")
        
        try:
            self.logger.info(f"transaction_data: {transaction_data}")
            # Get transaction information
            user_id = transaction_data['user_id']
            self.logger.info(f"user_id: {user_id}")

            amount = transaction_data['amount']
            currency = transaction_data.get('currency', 'VND')
            category = transaction_data.get('category', '')
            timestamp = transaction_data['timestamp']
            ip_address = transaction_data['ip_address']
            geolocation = transaction_data.get('geolocation', '')
            device_id = transaction_data.get('device_id', '')
            
            self.logger.info(f"Analyzing transaction for user {user_id}: amount={amount} {currency}, category={category}, timestamp={timestamp}")
            self.logger.info(f"Location info: ip={ip_address}, geo={geolocation}, device={device_id}")
            
            # Perform rule-based checks
            results = {
                'geolocation': self._check_location(db, user_id, geolocation),
                'ip_address': self._check_ip_address(db, user_id, ip_address),
                'amount': self._check_amount(db, user_id, amount),
                'category': self._check_category(db, user_id, category),
                'time': self._check_time(db, user_id, timestamp),
                'frequency': self._check_frequency(db, user_id, timestamp),
                'device': self._check_device(db, user_id, device_id)
            }
            
            self.logger.info(f"Rule check results: {results}")
            
            # Calculate risk score from rules
            risk_factors = [r['risk_score'] for r in results.values()]
            rules_risk_score = max(risk_factors) if risk_factors else 0
            
            self.logger.info(f"Rules-based risk score: {rules_risk_score}")
            
            # Get risk score from machine learning model
            model_risk_score = self.predict_with_model(transaction_data)
            
            self.logger.info(f"Model risk score: {model_risk_score}")
            
            # Combine risk scores
            final_risk_score = max(rules_risk_score, model_risk_score)
            is_suspicious = final_risk_score >= self.thresholds['anomaly_score_threshold']
            
            # Collect reasons
            suspicious_reasons = [result['reason'] for result in results.values() if result['reason']]
            suspicious_reasons_str = ', '.join(suspicious_reasons) if suspicious_reasons else ''
            
            # Prepare analysis details
            analysis_details = []
            for check_type, result in results.items():
                if result['is_suspicious']:
                    analysis_details.append({
                        'type': check_type,
                        'fraud_score': result['risk_score'] * 100,  # Convert to 0-100 scale
                        'message': result['reason']
                    })
            
            # Add model prediction to analysis details
            if model_risk_score > 0:
                analysis_details.append({
                    'type': 'ml_model',
                    'fraud_score': model_risk_score * 100,  # Convert to 0-100 scale
                    'message': 'Machine learning model detected potential fraud'
                })
            
            self.logger.info(f"Final analysis: score={final_risk_score}, suspicious={is_suspicious}")
            self.logger.info(f"Suspicious reasons: {suspicious_reasons}")
            
            return {
                'fraud_score': final_risk_score * 100,  # Convert to 0-100 scale
                'is_suspicious': is_suspicious,
                'analysis_details': analysis_details,
                'reasons': suspicious_reasons,
                'suggestions': 'Consider additional verification for high-risk transactions' if is_suspicious else '',
                'alert': {
                    'is_alert': is_suspicious,
                    'message': 'Suspicious transaction detected' if is_suspicious else 'Normal transaction detected',
                    'details': suspicious_reasons_str,
                    'suggestions': 'Verify transaction with user' if is_suspicious else 'Normal transaction'
                }
            }
            
        except Exception as e:
            self.logger.error(f"Error analyzing transaction: {str(e)}")
            return {
                'fraud_score': 0,
                'is_suspicious': False,
                'analysis_details': [],
                'reasons': [f'Error in transaction analysis: {str(e)}'],
                'suggestions': '',
                'alert': {
                    'is_alert': False,
                    'message': '',
                    'details': '',
                    'suggestions': ''
                }
            }
    
    # def send_alert(self, db: Session, user_id: str, analysis_result, transaction_data):
    #     """Gửi cảnh báo cho người dùng nếu phát hiện giao dịch đáng ngờ"""
    #     if not analysis_result['is_suspicious']:
    #         return False
        
    #     try:
    #         # Thông tin cảnh báo
    #         alert_info = {
    #             'user_id': user_id,
    #             'timestamp': datetime.now().isoformat(),
    #             'transaction_id': transaction_data.get('transaction_id', ''),
    #             'risk_score': analysis_result['risk_score'],
    #             'reasons': analysis_result['reasons'],
    #             'transaction_details': {
    #                 'amount': transaction_data.get('amount', 0),
    #                 'currency': transaction_data.get('currency', 'VND'),
    #                 'description': transaction_data.get('description', ''),
    #                 'category': transaction_data.get('category', ''),
    #                 'location': transaction_data.get('geolocation', ''),
    #                 'time': transaction_data.get('timestamp', datetime.now()).isoformat()
    #             }
    #         }
            
    #         # Log thông tin cảnh báo
    #         self.logger.info(f"Gửi cảnh báo: {alert_info}")
            
    #         # Ở đây bạn sẽ kết nối với dịch vụ gửi cảnh báo như SMS, email, push notification
    #         # Ví dụ:
    #         # self._send_email_alert(user_id, alert_info)
    #         # self._send_sms_alert(user_id, alert_info)
    #         # self._send_push_notification(user_id, alert_info)
            
    #         # Tạo alert mới
    #         alert = Alert(
    #             user_id=user_id,
    #             timestamp=datetime.now(),
    #             risk_score=analysis_result['risk_score'],
    #             reasons=json.dumps(analysis_result['reasons']),
    #             transaction_id=transaction_data.get('transaction_id'),
    #             transaction_details=json.dumps(transaction_data.get('transaction_details', {}))
    #         )
    #         db.add(alert)
    #         db.commit()
            
    #         return True
            
    #     except Exception as e:
    #         self.logger.error(f"Lỗi khi gửi cảnh báo: {str(e)}")
    #         return False

    def process_transaction(self, db: Session, transaction_data: dict) -> dict:
        """
        Process a new transaction and return analysis results
        Returns:
            Dict containing combined analysis results from both AI and traditional methods
        """
        try:
            # Get user information
            user_id = transaction_data['user_id']
            self.logger.info(f"Bắt đầu xử lý giao dịch cho user {user_id}")
            self.logger.info(f"Dữ liệu giao dịch: {json.dumps(transaction_data, indent=2, default=str)}")
            
            user_profile = self._get_user_profile(db, user_id)
            
            # Perform AI analysis
            ai_analysis = self.analyze_with_ai(transaction_data, user_profile)
            self.logger.info(f"AI analysis completed: {json.dumps(ai_analysis, indent=2)}")
            
            # Perform traditional analysis
            traditional_analysis = self.analyze_transaction(db, transaction_data)
            self.logger.info(f"Traditional analysis completed: {json.dumps(traditional_analysis, indent=2)}")
            
            # Combine results
            # Use weighted average for fraud score (60% AI, 40% traditional)
            combined_fraud_score = (ai_analysis.get('fraud_score', 0) * 0.6) + (traditional_analysis.get('fraud_score', 0) * 0.4)
            self.logger.info(f"Điểm gian lận kết hợp: {combined_fraud_score:.2f}")
            
            # Transaction is suspicious if either method flags it
            is_suspicious = ai_analysis.get('is_suspicious', False) or traditional_analysis.get('is_suspicious', False)
            self.logger.info(f"Giao dịch đáng ngờ: {is_suspicious}")
            
            # Combine analysis details
            combined_details = []
            
            # Add AI analysis details
            for detail in ai_analysis.get('analysis_details', []):
                detail['source'] = 'ai'
                combined_details.append(detail)
            
            # Add traditional analysis details
            for detail in traditional_analysis.get('analysis_details', []):
                detail['source'] = 'traditional'
                combined_details.append(detail)
            
            # Sort details by fraud score
            combined_details.sort(key=lambda x: x.get('fraud_score', 0), reverse=True)
            self.logger.info(f"Số lượng chi tiết phân tích: {len(combined_details)}")
            
            # Combine reasons
            combined_reasons = list(set(ai_analysis.get('reasons', []) + traditional_analysis.get('reasons', [])))
            self.logger.info(f"Lý do đáng ngờ: {combined_reasons}")
            
            # Create new transaction record
            transactionAnalysis = TransactionAnalysis(
                transaction_id=transaction_data.get('transaction_id', str(uuid.uuid4())),
                user_id=user_id,
                amount=transaction_data['amount'],
                currency=transaction_data.get('currency', 'VND'),
                description=transaction_data.get('description', ''),
                category=transaction_data.get('category', 'unknown'),
                timestamp=transaction_data.get('timestamp', datetime.now()),
                ip_address=transaction_data['ip_address'],
                geolocation=transaction_data.get('geolocation', 'unknown'),
                device_id=transaction_data.get('device_id', 'unknown'),
                is_suspicious=is_suspicious,
                risk_score=combined_fraud_score,
                ai_analysis=ai_analysis,
                traditional_analysis=traditional_analysis,
                fraud_reasons=combined_reasons
            )
            
            db.add(transactionAnalysis)
            db.commit()
            self.logger.info(f"Đã lưu giao dịch analysis vào database với ID: {transactionAnalysis.transaction_id}")
            
            # Create alert if transaction is suspicious
            if is_suspicious:
                self.logger.info("Giao dịch đáng ngờ, tạo cảnh báo")
                # self.send_alert(db, user_id, {
                #     'risk_score': combined_fraud_score,
                #     'reasons': combined_reasons
                # }, transaction_data)
            
            result = {
                'fraud_score': combined_fraud_score,
                'is_suspicious': is_suspicious,
                'analysis_details': combined_details,
                'reasons': combined_reasons,
                'suggestions': ai_analysis.get('suggestions', '') or traditional_analysis.get('suggestions', ''),
                'alert': {
                    'is_alert': is_suspicious,
                    'message': 'Suspicious transaction detected by multiple methods' if is_suspicious else '',
                    'details': {
                        'ai_analysis': ai_analysis.get('alert', {}),
                        'traditional_analysis': traditional_analysis.get('alert', {})
                    },
                    'suggestions': 'Verify transaction with user and consider additional security measures' if is_suspicious else ''
                }
            }
            
            self.logger.info("Hoàn thành xử lý giao dịch")
            return result
            
        except Exception as e:
            self.logger.error(f"Error processing transaction: {str(e)}")
            db.rollback()
            return {
                'fraud_score': 0,
                'is_suspicious': False,
                'analysis_details': [],
                'reasons': [f'Error processing transaction: {str(e)}'],
                'suggestions': '',
                'alert': {
                    'is_alert': False,
                    'message': '',
                    'details': '',
                    'suggestions': ''
                }
            }
        
    def datetime_converter(obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        raise TypeError(f"Object of type {type(obj)} is not JSON serializable")

    def analyze_with_ai(self, transaction_data: Dict, user_profile: Optional[Dict] = None) -> Dict:
        """
        Analyze transaction using OpenAI API
        Returns:
            Dict containing:
            - fraud_score: float (0-100)
            - is_suspicious: bool
            - analysis_details: Dict containing detailed analysis results
            - reasons: List[str] containing reasons for the decision
        """
        try:
            logging.info("Starting AI analysis...")
            logging.info(f"OpenAI Configuration - Base URL: {os.getenv('OPENAI_BASE_URL')}, Model: {os.getenv('OPENAI_MODEL')}")
            
            client = OpenAI(
                api_key=os.getenv('OPENAI_API_KEY'),
                base_url=os.getenv('OPENAI_BASE_URL')
            )
            logging.info("OpenAI client initialized successfully")
            
            # Prepare transaction data
            transaction_info = {
                'amount': transaction_data['amount'],
                'currency': transaction_data.get('currency', 'VND'),
                'description': transaction_data.get('description', ''),
                'category': transaction_data.get('category', 'unknown'),
                'ip_address': transaction_data['ip_address'],
                'device_id': transaction_data.get('device_id', 'unknown'),
                'geolocation': transaction_data.get('geolocation', 'unknown'),
                'timestamp': transaction_data['timestamp'].isoformat() if isinstance(transaction_data['timestamp'], datetime) else transaction_data['timestamp']
            }
            logging.info(f"Transaction info prepared: {json.dumps(transaction_info, indent=2)}")
            
            # Prepare account info
            logging.info("Preparing account info...")
            account_info = {
                'user_id': transaction_data['user_id'],
                'profile': {
                    'common_ip_addresses': user_profile['common_ip_addresses'],
                    'common_locations': user_profile['common_locations'],
                    'common_devices': user_profile['common_devices'],
                    'common_categories': user_profile['common_categories'],
                    'avg_transaction_amount': user_profile['avg_transaction_amount'],
                    'typical_transaction_hours': user_profile['typical_transaction_hours'],
                }
            }
            logging.info(f"Account info prepared: {json.dumps(account_info, indent=2)}")
            
            # Prepare transaction history
            logging.info("Preparing transaction history...")
            history_info = []
            if user_profile and 'transactions' in user_profile:
                history_info = user_profile['transactions']
                logging.info(f"Found {len(history_info)} historical transactions")
            else:
                logging.info("No transaction history found")
            
            
            # Format prompt with actual data
            prompt = self.FRAUD_DETECTION_PROMPT.format(
                account_info=json.dumps(account_info, indent=2),
                history_info=json.dumps(history_info, indent=2),
                transaction_info=json.dumps(transaction_info, indent=2)
            )
            
            logging.info("Prompt prepared successfully")
            
            # Call OpenAI API
            logging.info("Calling OpenAI API...")
            try:
                response = client.chat.completions.create(
                    model=os.getenv('OPENAI_MODEL', 'gpt-4'),
                    messages=[
                        {"role": "system", "content": "You are a financial fraud detection system. Your task is to analyze user financial transactions based on transaction history and the latest transaction to determine if the new transaction is likely fraudulent. You must respond with valid JSON only, no additional text."},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=0.1
                )
                logging.info("OpenAI API call successful")
                logging.info(f"Raw API response: {response}")
            except Exception as api_error:
                logging.error(f"OpenAI API call failed: {str(api_error)}")
                logging.error(f"API Error details: {type(api_error).__name__}")
                raise api_error
            
            # Parse results
            analysis_text = response.choices[0].message.content.strip()
            logging.info(f"Raw AI Analysis text: {analysis_text}")
            
            # Clean the response text
            analysis_text = analysis_text.strip()
            if not analysis_text.startswith('{'):
                # Try to find the first occurrence of a JSON object
                import re
                json_match = re.search(r'\{.*\}', analysis_text, re.DOTALL)
                if json_match:
                    analysis_text = json_match.group(0)
                else:
                    raise ValueError("No valid JSON found in the response")
            
            # Parse the JSON
            try:
                analysis_result = json.loads(analysis_text)
            except json.JSONDecodeError as e:
                logging.error(f"JSON parsing error: {str(e)}")
                logging.error(f"Problematic text: {analysis_text}")
                raise
            
            logging.info(f"Parsed analysis result: {json.dumps(analysis_result, indent=2)}")
            
            # Validate required fields
            required_fields = ['fraud_score', 'fraud_decision', 'fraud_reason', 'fraud_details']
            for field in required_fields:
                if field not in analysis_result:
                    raise ValueError(f"Missing required field: {field}")
            
            # Check data consistency
            avg_score = sum(item.get('fraud_score', 0) for item in analysis_result.get('fraud_details', [])) / len(analysis_result.get('fraud_details', [])) if analysis_result.get('fraud_details') else 0
            if abs(avg_score - analysis_result.get('fraud_score', 0)) > 0.01:  # Allow small rounding errors
                logging.warning(f"Fraud score mismatch: calculated={avg_score}, provided={analysis_result.get('fraud_score', 0)}")
                analysis_result['fraud_score'] = avg_score
            
            # Check for duplicate types
            check_types = [item.get('type') for item in analysis_result.get('fraud_details', [])]
            if len(check_types) != len(set(check_types)):
                logging.warning("Duplicate check types found in fraud_details")
            
            return {
                'fraud_score': analysis_result.get('fraud_score', 0),
                'is_suspicious': analysis_result.get('fraud_decision', False),
                'analysis_details': analysis_result.get('fraud_details', []),
                'reasons': [analysis_result.get('fraud_reason', '')] + [detail.get('message', '') for detail in analysis_result.get('fraud_details', []) if detail.get('message')],
                'suggestions': analysis_result.get('fraud_suggestions', ''),
                'alert': {
                    'is_alert': analysis_result.get('fraud_alert', False),
                    'message': analysis_result.get('fraud_alert_message', ''),
                    'details': analysis_result.get('fraud_alert_details', ''),
                    'suggestions': analysis_result.get('fraud_alert_suggestions', '')
                }
            }
            
        except Exception as e:
            logging.error(f"Error in AI analysis: {str(e)}")
            logging.error(f"Error type: {type(e).__name__}")
            logging.error(f"Error details: {str(e)}")
            if hasattr(e, 'response'):
                logging.error(f"API Response: {e.response}")
            return {
                'fraud_score': 0,
                'is_suspicious': False,
                'analysis_details': [],
                'reasons': [f'Error in AI analysis: {str(e)}'],
                'suggestions': '',
                'alert': {
                    'is_alert': False,
                    'message': '',
                    'details': '',
                    'suggestions': ''
                }
            }

# Ví dụ sử dụng hệ thống
if __name__ == "__main__":
    # Khởi tạo hệ thống
    fraud_system = FraudDetectionSystem()
    
    # Khởi tạo database
    engine = create_engine('postgresql://postgres:postgres@localhost:5432/fraud_detection')
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    db = Session()
    
    try:
        # Ví dụ một giao dịch
        example_transaction = {
            'user_id': '12345',
            'ip_address': '192.168.1.1',
            'geolocation': 'Vietnam',
            'amount': 2000000,
            'category': 'Electronics',
            'timestamp': datetime.now(),
            'device_id': 'mobile-android-12345',
            'transaction_id': 'TX-98765',
            'currency': 'VND',
            'description': 'Purchase of a new laptop'
        }
        
        # Xử lý giao dịch
        result = fraud_system.process_transaction(db, example_transaction)
        
        # In kết quả
        print("Kết quả phân tích:")
        print(f"Đáng ngờ: {result['is_suspicious']}")
        print(f"Điểm rủi ro: {result['fraud_score']:.2f}")
        if result['reasons']:
            print("Lý do:")
            for reason in result['reasons']:
                print(f"- {reason}")
                
    except Exception as e:
        print(f"Lỗi khi xử lý giao dịch: {str(e)}")
    finally:
        db.close()
