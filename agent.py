import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
from datetime import datetime
import pickle
import requests
import logging
from database import get_db, User, Transaction, UserProfile, Alert
from sqlalchemy.orm import Session
import json
import os
from openai import OpenAI
import uuid
from typing import Dict, List, Optional, Tuple

class FraudDetectionSystem:
    def __init__(self):
        # Thiết lập logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            filename='fraud_detection.log'
        )
        self.logger = logging.getLogger('fraud_detection')
        
        # Load mô hình hoặc tạo mới nếu chưa có
        try:
            self.model = pickle.load(open('fraud_detection_model.pkl', 'rb'))
            self.scaler = pickle.load(open('scaler.pkl', 'rb'))
            self.encoder = pickle.load(open('encoder.pkl', 'rb'))
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
            'anomaly_score_threshold': 0.8   # Ngưỡng điểm bất thường
        }
        
        # Danh sách IP được biết là nguy hiểm từ nguồn bên ngoài
        self.known_bad_ips = self._load_known_bad_ips()
    
    def _load_known_bad_ips(self):
        """Tải danh sách IP đã biết là độc hại từ API bên ngoài"""
        try:
            # Đây là ví dụ, trong thực tế bạn sẽ kết nối với API cung cấp danh sách IP độc hại
            response = requests.get("https://example.com/api/malicious-ips", timeout=5)
            if response.status_code == 200:
                return set(response.json()['ips'])
            return set()
        except:
            self.logger.warning("Không thể tải danh sách IP độc hại")
            return set()
    
    def _get_user_location_history(self, db: Session, user_id: str):
        """Lấy lịch sử vị trí của người dùng từ database"""
        user_profile = db.query(UserProfile).filter(UserProfile.user_id == user_id).first()
        if user_profile and user_profile.common_locations:
            return json.loads(user_profile.common_locations)
        return []
    
    def _get_user_transaction_history(self, db: Session, user_id: str):
        """Lấy lịch sử giao dịch của người dùng từ database"""
        transactions = db.query(Transaction).filter(Transaction.user_id == user_id).all()
        return [{
            'amount': t.amount,
            'category': t.category,
            'timestamp': t.timestamp,
            'geolocation': t.geolocation,
            'device_id': t.device_id
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
            return set(json.loads(user_profile.common_categories))
        return set()
    
    def _get_common_transaction_times(self, db: Session, user_id: str):
        """Lấy thời gian giao dịch thường xuyên của người dùng từ database"""
        user_profile = db.query(UserProfile).filter(UserProfile.user_id == user_id).first()
        if user_profile and user_profile.typical_transaction_hours:
            return json.loads(user_profile.typical_transaction_hours)
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
            
            if not profile:
                return None
                
            # Chuyển đổi profile thành dictionary
            return {
                'common_locations': json.loads(profile.common_locations) if profile.common_locations else [],
                'common_devices': json.loads(profile.common_devices) if profile.common_devices else [],
                'common_categories': json.loads(profile.common_categories) if profile.common_categories else [],
                'avg_transaction_amount': profile.avg_transaction_amount,
                'typical_transaction_hours': json.loads(profile.typical_transaction_hours) if profile.typical_transaction_hours else []
            }
            
        except Exception as e:
            logging.error(f"Error getting user profile: {str(e)}")
            return None
    
    def _check_ip_location(self, db: Session, user_id, ip_address, geolocation):
        """Kiểm tra vị trí IP có bất thường không"""
        # Kiểm tra IP có trong danh sách đen không
        if ip_address in self.known_bad_ips:
            return {
                'is_suspicious': True,
                'reason': 'IP nằm trong danh sách IP độc hại đã biết',
                'risk_score': 0.9
            }
        
        # Kiểm tra vị trí có trong lịch sử không
        locations = self._get_user_location_history(db, user_id)
        if locations and geolocation not in locations:
            return {
                'is_suspicious': True,
                'reason': f'Vị trí mới: {geolocation} chưa từng xuất hiện trong lịch sử',
                'risk_score': 0.7
            }
        
        return {'is_suspicious': False, 'reason': '', 'risk_score': 0.0}
    
    def _check_amount(self, db: Session, user_id, amount):
        """Kiểm tra số tiền giao dịch có bất thường không"""
        avg_amount = self._get_average_transaction_amount(db, user_id)
        threshold = avg_amount * self.thresholds['amount_threshold_factor']
        
        if amount > threshold and threshold > 0:
            return {
                'is_suspicious': True,
                'reason': f'Số tiền ({amount}) cao hơn ngưỡng bình thường ({threshold:.2f})',
                'risk_score': min(0.9, (amount / threshold) * 0.5)
            }
        
        return {'is_suspicious': False, 'reason': '', 'risk_score': 0.0}
    
    def _check_category(self, db: Session, user_id, category):
        """Kiểm tra danh mục sản phẩm có bất thường không"""
        common_categories = self._get_common_categories(db, user_id)
        
        if common_categories and category not in common_categories:
            return {
                'is_suspicious': True,
                'reason': f'Danh mục sản phẩm mới: {category}',
                'risk_score': 0.5
            }
        
        return {'is_suspicious': False, 'reason': '', 'risk_score': 0.0}
    
    def _check_time(self, db: Session, user_id, timestamp):
        """Kiểm tra thời gian giao dịch có bất thường không"""
        hour = timestamp.hour
        
        # Kiểm tra giờ giao dịch có trong khoảng đáng ngờ không
        if self.thresholds['suspicious_hour_start'] <= hour <= self.thresholds['suspicious_hour_end']:
            # Kiểm tra xem người dùng có thường xuyên giao dịch vào giờ này không
            common_hours = self._get_common_transaction_times(db, user_id)
            if hour not in common_hours:
                return {
                    'is_suspicious': True,
                    'reason': f'Giao dịch vào thời điểm bất thường: {hour}:00',
                    'risk_score': 0.6
                }
        
        return {'is_suspicious': False, 'reason': '', 'risk_score': 0.0}
    
    def _check_frequency(self, db: Session, user_id, timestamp):
        """Kiểm tra tần suất giao dịch có bất thường không"""
        recent = self._get_recent_transactions(db, user_id, hours=1)
        
        if len(recent) >= self.thresholds['max_transactions_per_hour']:
            return {
                'is_suspicious': True,
                'reason': f'Số lượng giao dịch nhiều bất thường trong 1 giờ: {len(recent)}',
                'risk_score': min(0.8, len(recent) / self.thresholds['max_transactions_per_hour'] * 0.4)
            }
        
        return {'is_suspicious': False, 'reason': '', 'risk_score': 0.0}
    
    def _check_device(self, db: Session, user_id, device_id):
        """Kiểm tra thiết bị có bất thường không"""
        user_profile = db.query(UserProfile).filter(UserProfile.user_id == user_id).first()
        if user_profile and user_profile.common_devices:
            common_devices = json.loads(user_profile.common_devices)
            if device_id not in common_devices:
                return {
                    'is_suspicious': True,
                    'reason': f'Thiết bị mới: {device_id}',
                    'risk_score': 0.6
                }
        
        return {'is_suspicious': False, 'reason': '', 'risk_score': 0.0}
    
    def train_model(self, db: Session, transaction_data: list):
        """Huấn luyện mô hình phát hiện gian lận từ dữ liệu giao dịch trong database"""
        if len(transaction_data) < 10:
            self.logger.warning("Không đủ dữ liệu để huấn luyện mô hình")
            return False
        
        try:
            # Chuẩn bị dữ liệu
            df = pd.DataFrame(transaction_data)
            
            # Chuyển đổi timestamp thành giờ
            df['hour'] = pd.to_datetime(df['timestamp']).dt.hour
            
            # Tách features và target
            features = ['amount', 'hour']
            X = df[features]
            y = df['is_fraud'] if 'is_fraud' in df.columns else None
            
            # Xác định các cột theo loại
            categorical_features = X.select_dtypes(include=['object', 'category']).columns
            numeric_features = ['amount', 'hour']
            
            # Tạo preprocessor
            preprocessor = ColumnTransformer(
                transformers=[
                    ('num', StandardScaler(), numeric_features),
                    ('cat', OneHotEncoder(handle_unknown='ignore'), categorical_features)
                ])
            
            # Huấn luyện mô hình
            if y is not None:
                # Supervised learning with Random Forest
                self.model = Pipeline(steps=[
                    ('preprocessor', preprocessor),
                    ('classifier', RandomForestClassifier(n_estimators=100, random_state=42))
                ])
                self.model.fit(X, y)
            else:
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
            features = ['amount', 'hour']
            X = df[features]
            
            # Thực hiện dự đoán
            if isinstance(self.model.named_steps['classifier'], RandomForestClassifier):
                # Lấy xác suất của lớp dương tính (gian lận)
                proba = self.model.predict_proba(X)[0][1]
                return proba
            else:
                # Isolation Forest trả về điểm bất thường
                score = -self.model.decision_function(X)[0]
                return score / 2 + 0.5  # Chuẩn hóa về khoảng 0-1
                
        except Exception as e:
            self.logger.error(f"Lỗi khi dự đoán với mô hình: {str(e)}")
            return 0.5
    
    def update_user_profile(self, db: Session, user_id: str, transaction_data: dict):
        """Cập nhật hồ sơ người dùng với dữ liệu giao dịch mới vào database"""
        # Tạo hoặc cập nhật user
        user = db.query(User).filter(User.user_id == user_id).first()
        if not user:
            user = User(user_id=user_id)
            db.add(user)
        
        # Tạo transaction mới
        transaction = Transaction(
            transaction_id=transaction_data.get('transaction_id'),
            user_id=user_id,
            amount=transaction_data.get('amount', 0),
            category=transaction_data.get('category'),
            timestamp=transaction_data.get('timestamp', datetime.utcnow()),
            ip_address=transaction_data.get('ip_address'),
            geolocation=transaction_data.get('geolocation'),
            device_id=transaction_data.get('device_id'),
            is_suspicious=transaction_data.get('is_suspicious', False),
            risk_score=transaction_data.get('risk_score', 0.0),
            verified=transaction_data.get('verified', False),
            is_fraud=transaction_data.get('is_fraud', False)
        )
        db.add(transaction)
        
        # Cập nhật user profile
        profile = db.query(UserProfile).filter(UserProfile.user_id == user_id).first()
        if not profile:
            profile = UserProfile(user_id=user_id)
            db.add(profile)
        
        # Cập nhật các thông tin profile
        transactions = self._get_user_transaction_history(db, user_id)
        if transactions:
            # Cập nhật locations
            locations = set(t.get('geolocation') for t in transactions if t.get('geolocation'))
            profile.common_locations = json.dumps(list(locations))
            
            # Cập nhật devices
            devices = set(t.get('device_id') for t in transactions if t.get('device_id'))
            profile.common_devices = json.dumps(list(devices))
            
            # Cập nhật categories
            categories = set(t.get('category') for t in transactions if t.get('category'))
            profile.common_categories = json.dumps(list(categories))
            
            # Cập nhật avg_transaction_amount
            profile.avg_transaction_amount = sum(t.get('amount', 0) for t in transactions) / len(transactions)
            
            # Cập nhật typical_transaction_hours
            hours = [t.get('timestamp', datetime.now()).hour for t in transactions if 'timestamp' in t]
            profile.typical_transaction_hours = json.dumps(list(set(hours)))
        
        profile.last_updated = datetime.now()
        db.commit()
    
    def analyze_transaction(self, db: Session, transaction_data: dict):
        """Phân tích giao dịch và trả về kết quả"""
        try:
            # Lấy thông tin giao dịch
            user_id = transaction_data['user_id']
            amount = transaction_data['amount']
            category = transaction_data.get('category', '')
            timestamp = transaction_data['timestamp']
            ip_address = transaction_data['ip_address']
            geolocation = transaction_data.get('geolocation', '')
            device_id = transaction_data.get('device_id', '')
            
            # Thực hiện các kiểm tra dựa trên quy tắc
            results = {
                'ip_location': self._check_ip_location(db, user_id, ip_address, geolocation),
                'amount': self._check_amount(db, user_id, amount),
                'category': self._check_category(db, user_id, category),
                'time': self._check_time(db, user_id, timestamp),
                'frequency': self._check_frequency(db, user_id, timestamp),
                'device': self._check_device(db, user_id, device_id)
            }
            
            # Tính điểm rủi ro từ các quy tắc
            risk_factors = [r['risk_score'] for r in results.values()]
            rules_risk_score = max(risk_factors) if risk_factors else 0
            
            # Tính điểm rủi ro từ mô hình máy học
            model_risk_score = self.predict_with_model(transaction_data)
            
            # Kết hợp điểm rủi ro
            final_risk_score = max(rules_risk_score, model_risk_score)
            is_suspicious = final_risk_score >= self.thresholds['anomaly_score_threshold']
            
            # Tổng hợp lý do
            suspicious_reasons = [result['reason'] for result in results.values() if result['reason']]
            
            return {
                'is_suspicious': is_suspicious,
                'risk_score': final_risk_score,
                'reasons': suspicious_reasons,
                'details': {
                    'rule_based_score': rules_risk_score,
                    'model_score': model_risk_score,
                    'checks': results
                }
            }
            
        except Exception as e:
            self.logger.error(f"Lỗi khi phân tích giao dịch: {str(e)}")
            return {
                'is_suspicious': True,
                'risk_score': 1.0,
                'reasons': ['Lỗi khi phân tích giao dịch'],
                'details': {}
            }
    
    def send_alert(self, db: Session, user_id: str, analysis_result, transaction_data):
        """Gửi cảnh báo cho người dùng nếu phát hiện giao dịch đáng ngờ"""
        if not analysis_result['is_suspicious']:
            return False
        
        try:
            # Thông tin cảnh báo
            alert_info = {
                'user_id': user_id,
                'timestamp': datetime.now().isoformat(),
                'transaction_id': transaction_data.get('transaction_id', ''),
                'risk_score': analysis_result['risk_score'],
                'reasons': analysis_result['reasons'],
                'transaction_details': {
                    'amount': transaction_data.get('amount', 0),
                    'category': transaction_data.get('category', ''),
                    'location': transaction_data.get('geolocation', ''),
                    'time': transaction_data.get('timestamp', datetime.now()).isoformat()
                }
            }
            
            # Log thông tin cảnh báo
            self.logger.info(f"Gửi cảnh báo: {alert_info}")
            
            # Ở đây bạn sẽ kết nối với dịch vụ gửi cảnh báo như SMS, email, push notification
            # Ví dụ:
            # self._send_email_alert(user_id, alert_info)
            # self._send_sms_alert(user_id, alert_info)
            # self._send_push_notification(user_id, alert_info)
            
            # Tạo alert mới
            alert = Alert(
                user_id=user_id,
                timestamp=datetime.now(),
                risk_score=analysis_result['risk_score'],
                reasons=json.dumps(analysis_result['reasons']),
                transaction_id=transaction_data.get('transaction_id'),
                transaction_details=json.dumps(transaction_data.get('transaction_details', {}))
            )
            db.add(alert)
            db.commit()
            
            return True
            
        except Exception as e:
            self.logger.error(f"Lỗi khi gửi cảnh báo: {str(e)}")
            return False

    def process_transaction(self, db: Session, transaction_data: dict):
        """
        Xử lý giao dịch mới và trả về kết quả phân tích
        """
        try:
            # Lấy thông tin người dùng
            user_id = transaction_data['user_id']
            user_profile = self._get_user_profile(db, user_id)
            
            # Phân tích bằng AI
            ai_analysis = self.analyze_with_ai(transaction_data, user_profile)
            
            # Phân tích bằng các quy tắc truyền thống
            traditional_analysis = self.analyze_transaction(transaction_data, user_profile)
            
            # Kết hợp kết quả
            is_suspicious = ai_analysis['is_suspicious'] or traditional_analysis['is_suspicious']
            risk_score = max(
                self._convert_risk_level_to_score(ai_analysis['risk_level']),
                traditional_analysis['risk_score']
            )
            
            # Tạo giao dịch mới
            transaction = Transaction(
                transaction_id=transaction_data.get('transaction_id', str(uuid.uuid4())),
                user_id=user_id,
                amount=transaction_data['amount'],
                category=transaction_data.get('category', 'unknown'),
                timestamp=transaction_data.get('timestamp', datetime.now()),
                ip_address=transaction_data['ip_address'],
                geolocation=transaction_data.get('geolocation', {}),
                device_id=transaction_data.get('device_id', 'unknown'),
                is_suspicious=is_suspicious,
                risk_score=risk_score,
                ai_analysis=ai_analysis['analysis'],
                traditional_analysis=json.dumps(traditional_analysis)
            )
            
            db.add(transaction)
            db.commit()
            
            # Nếu giao dịch đáng ngờ, tạo cảnh báo
            if is_suspicious:
                self.send_alert(db, user_id, transaction_data, {
                    'ai_analysis': ai_analysis,
                    'traditional_analysis': traditional_analysis
                })
            
            return {
                'is_suspicious': is_suspicious,
                'risk_score': risk_score,
                'reasons': traditional_analysis.get('reasons', []) + [ai_analysis['analysis']],
                'transaction_id': transaction.transaction_id
            }
            
        except Exception as e:
            logging.error(f"Error processing transaction: {str(e)}")
            db.rollback()
            raise

    def _convert_risk_level_to_score(self, risk_level: str) -> float:
        """
        Chuyển đổi mức độ rủi ro thành điểm số
        """
        risk_scores = {
            'low': 0.2,
            'medium': 0.5,
            'high': 0.8
        }
        return risk_scores.get(risk_level.lower(), 0.5)

    def analyze_with_ai(self, transaction_data: Dict, user_profile: Optional[Dict] = None) -> Dict:
        """
        Phân tích giao dịch bằng OpenAI API
        """
        try:
            client = OpenAI(api_key=os.getenv('OPENAI_API_KEY'))
            
            # Chuẩn bị dữ liệu cho prompt
            transaction_info = {
                'amount': transaction_data['amount'],
                'category': transaction_data.get('category', 'unknown'),
                'ip_address': transaction_data['ip_address'],
                'device_id': transaction_data.get('device_id', 'unknown'),
                'timestamp': transaction_data['timestamp'].isoformat() if isinstance(transaction_data['timestamp'], datetime) else transaction_data['timestamp']
            }
            
            if user_profile:
                profile_info = {
                    'common_locations': user_profile.get('common_locations', []),
                    'common_devices': user_profile.get('common_devices', []),
                    'common_categories': user_profile.get('common_categories', []),
                    'avg_transaction_amount': user_profile.get('avg_transaction_amount', 0),
                    'typical_transaction_hours': user_profile.get('typical_transaction_hours', [])
                }
            else:
                profile_info = {}
            
            # Tạo prompt cho OpenAI
            prompt = f"""
            Analyze this transaction for potential fraud:
            
            Transaction Details:
            {json.dumps(transaction_info, indent=2)}
            
            User Profile (if available):
            {json.dumps(profile_info, indent=2)}
            
            Please analyze this transaction and provide:
            1. Risk level (low, medium, high)
            2. Specific reasons for the risk level
            3. Recommended actions
            """
            
            # Gọi OpenAI API
            response = client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "You are a fraud detection expert. Analyze transactions for potential fraud."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3
            )
            
            # Phân tích kết quả
            analysis = response.choices[0].message.content
            
            # Chuyển đổi kết quả thành định dạng phù hợp
            risk_level = "high" if "high" in analysis.lower() else "medium" if "medium" in analysis.lower() else "low"
            
            return {
                'risk_level': risk_level,
                'analysis': analysis,
                'is_suspicious': risk_level in ['medium', 'high']
            }
            
        except Exception as e:
            logging.error(f"Error in AI analysis: {str(e)}")
            return {
                'risk_level': 'unknown',
                'analysis': str(e),
                'is_suspicious': False
            }

# Ví dụ sử dụng hệ thống
if __name__ == "__main__":
    # Khởi tạo hệ thống
    fraud_system = FraudDetectionSystem()
    
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
    }
    
    # Xử lý giao dịch
    result = fraud_system.process_transaction(example_transaction)
    
    # In kết quả
    print("Kết quả phân tích:")
    print(f"Đáng ngờ: {result['is_suspicious']}")
    print(f"Điểm rủi ro: {result['risk_score']:.2f}")
    if result['reasons']:
        print("Lý do:")
        for reason in result['reasons']:
            print(f"- {reason}")