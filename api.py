from flask import Flask, request, jsonify
from flask_cors import CORS
import logging
import json
from datetime import datetime, timedelta
import uuid
import os
import argparse
from agent import FraudDetectionSystem
from database import get_db, init_db, User, TransactionAnalysis, UserProfile, Alert
from dotenv import load_dotenv

# Parse command line arguments
load_dotenv()

# Khởi tạo Flask app
app = Flask(__name__)
CORS(app)  # Cho phép cross-origin requests

# Thiết lập logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('api.log'),
        logging.StreamHandler()  # Thêm handler để log ra console
    ]
)
logger = logging.getLogger('fraud_api')

# Khởi tạo hệ thống phát hiện gian lận
fraud_system = FraudDetectionSystem()

# Initialize database
init_db()

# API endpoint để xử lý giao dịch mới
@app.route('/api/v1/process-transaction', methods=['POST'])
def process_transaction():
    """Process a new transaction and return fraud detection results"""
    try:
        # Get database session
        db = next(get_db())
        
        # Get transaction data from request
        transaction_data = request.json
        logger.info(f"Received transaction data: {json.dumps(transaction_data, indent=2, default=str)}")
        
        # Kiểm tra dữ liệu đầu vào
        required_fields = ['user_id', 'amount', 'ip_address']
        for field in required_fields:
            if field not in transaction_data:
                logger.error(f"Missing required field: {field}")
                return jsonify({
                    'status': 'error',
                    'message': f'Missing required field: {field}'
                }), 400
                    
        # Thêm trường timestamp nếu chưa có
        if 'timestamp' not in transaction_data:
            transaction_data['timestamp'] = datetime.now()
        else:
            # Chuyển đổi chuỗi thành đối tượng datetime
            transaction_data['timestamp'] = datetime.fromisoformat(transaction_data['timestamp'])
        
        # Thêm transaction_id nếu chưa có
        if 'transaction_id' not in transaction_data:
            transaction_data['transaction_id'] = str(uuid.uuid4())

        logger.info(f"Processing transaction with ID: {transaction_data['transaction_id']}")
        analysis_result = fraud_system.process_transaction(db, transaction_data)
        logger.info(f"Analysis result: {json.dumps(analysis_result, indent=2, default=str)}")
        
        # Trả về kết quả
        response = {
            'status': 'success',
            'transaction_id': transaction_data['transaction_id'],
            'data': analysis_result
        }
        
        # Log response
        logger.info(f"Transaction processed: {json.dumps(response, indent=2)}")
        
        return jsonify(response), 200
        
    except Exception as e:
        logger.error(f"Error processing transaction: {str(e)}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': 'Server error while processing transaction',
            'error': str(e)
        }), 500

# API endpoint để huấn luyện mô hình
@app.route('/api/v1/train-model', methods=['POST'])
def train_model():
    """Train the fraud detection model with new transaction data"""
    try:
        # Nhận dữ liệu huấn luyện từ request
        with open('training_data.json', 'r') as f:
            training_data = json.load(f).get('training_data', [])
        
        if not training_data or len(training_data) < 10:
            return jsonify({
                'status': 'error',
                'message': 'Training data must be a list with at least 10 transactions'
            }), 400
        
        # Get database session
        db = next(get_db())

        # Train model
        success = fraud_system.train_model(db, training_data)
        
        if success:
            return jsonify({'message': 'Model trained successfully'}), 200
        else:
            return jsonify({'error': 'Failed to train model'}), 400
            
    except Exception as e:
        logger.error(f"Error training model: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Server error while training model',
            'error': str(e)
        }), 500

# API endpoint để xác nhận giao dịch (sau khi người dùng xác minh)
@app.route('/api/v1/verify-transaction', methods=['POST'])
def verify_transaction():
    """Verify a transaction after user confirmation"""
    try:
        data = request.json
        transaction_id = data.get('transaction_id')
        user_id = data.get('user_id')
        is_legitimate = data.get('is_legitimate', False)
        
        logger.info(f"Verifying transaction {transaction_id} for user {user_id}. Is legitimate: {is_legitimate}")
        
        if not transaction_id or not user_id:
            logger.warning("Missing transaction_id or user_id in request")
            return jsonify({
                'status': 'error',
                'message': 'Missing transaction_id or user_id'
            }), 400
        
        # Get database session
        db = next(get_db())
        
        # Find transaction in database
        transactionAnalysis = db.query(TransactionAnalysis).filter(
            TransactionAnalysis.transaction_id == transaction_id,
            TransactionAnalysis.user_id == user_id
        ).first()
        
        if not transactionAnalysis:
            logger.warning(f"Transaction {transaction_id} not found for user {user_id}")
            return jsonify({
                'status': 'error',
                'message': 'Transaction not found'
            }), 404
        
        logger.info(f"Found transaction {transaction_id}. Updating verification status")
        
        # Update transaction verification status
        transactionAnalysis.verified = True
        if is_legitimate:
            transactionAnalysis.is_fraud = False
            logger.info(f"Transaction {transaction_id} marked as legitimate")
        else:
            transactionAnalysis.is_fraud = True
            logger.info(f"Transaction {transaction_id} marked as fraudulent")

        
        # If transaction is legitimate, update user profile
        if is_legitimate:
            logger.info(f"Updating user profile for legitimate transaction {transaction_id}")
            # Get transaction data for profile update
            transaction_data = {
                'transaction_id': transactionAnalysis.transaction_id,
                'user_id': transactionAnalysis.user_id,
                'amount': transactionAnalysis.amount,
                'currency': transactionAnalysis.currency,
                'description': transactionAnalysis.description,
                'category': transactionAnalysis.category,
                'timestamp': transactionAnalysis.timestamp,
                'ip_address': transactionAnalysis.ip_address,
                'geolocation': transactionAnalysis.geolocation,
                'device_id': transactionAnalysis.device_id,
            }
            
            # Update user profile with verified transaction
            fraud_system.update_user_profile(db, user_id, transaction_data)
            logger.info(f"User profile updated successfully for user {user_id}")
        
        # Update transaction s
        db.commit()

        logger.info(f"Transaction verification completed for {transaction_id}")
        return jsonify({
            'status': 'success',
            'message': 'Transaction verification recorded'
        })
        
    except Exception as e:
        logger.error(f"Error verifying transaction: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': 'Server error while verifying transaction',
            'error': str(e)
        }), 500

# API endpoint để nhận thống kê
# @app.route('/api/v1/statistics', methods=['GET'])
# def get_statistics():
#     try:
#         # Số lượng người dùng
#         user_count = len(fraud_system.user_profiles)
        
#         # Tổng số giao dịch
#         transaction_count = sum(len(profile['transactions']) for profile in fraud_system.user_profiles.values())
        
#         # Số lượng cảnh báo trong 7 ngày qua
#         alerts_count = 0
#         seven_days_ago = datetime.now() - timedelta(days=7)
        
#         # Đọc log để đếm cảnh báo
#         try:
#             with open('fraud_detection.log', 'r') as log_file:
#                 for line in log_file:
#                     if 'Phát hiện giao dịch đáng ngờ' in line:
#                         try:
#                             log_date = datetime.strptime(line.split(' - ')[0], '%Y-%m-%d %H:%M:%S,%f')
#                             if log_date > seven_days_ago:
#                                 alerts_count += 1
#                         except:
#                             pass
#         except FileNotFoundError:
#             pass
        
#         return jsonify({
#             'status': 'success',
#             'statistics': {
#                 'user_count': user_count,
#                 'transaction_count': transaction_count,
#                 'alerts_last_7_days': alerts_count,
#                 'generated_at': datetime.now().isoformat()
#             }
#         })
        
#     except Exception as e:
#         logger.error(f"Error getting statistics: {str(e)}")
#         return jsonify({
#             'status': 'error',
#             'message': 'Server error while getting statistics',
#             'error': str(e)
#         }), 500

@app.route('/api/v1/get_user_profile/<user_id>', methods=['GET'])
def get_user_profile(user_id):
    """Get user profile and transaction history"""
    try:
        # Get database session
        db = next(get_db())
        
        # Get user profile
        profile = db.query(UserProfile).filter(UserProfile.user_id == user_id).first()
        
        if not profile:
            return jsonify({'error': 'User profile not found'}), 404
            
        # Get recent transactions
        transactions = db.query(TransactionAnalysis).filter(
            TransactionAnalysis.user_id == user_id
        ).order_by(TransactionAnalysis.timestamp.desc()).limit(10).all()
        
        # Format response
        response = {
            'user_id': user_id,
            'common_locations': profile.common_locations if profile.common_locations else [],
            'common_devices': profile.common_devices if profile.common_devices else [],
            'common_categories': profile.common_categories if profile.common_categories else [],
            'avg_transaction_amount': profile.avg_transaction_amount,
            'typical_transaction_hours': profile.typical_transaction_hours if profile.typical_transaction_hours else [],
            'recent_transactions': [{
                'transaction_id': t.transaction_id,
                'amount': t.amount,
                'category': t.category,
                'currency': t.currency,
                'description': t.description,
                'ip_address': t.ip_address,
                'geolocation': t.geolocation,
                'device_id': t.device_id,
                'timestamp': t.timestamp.isoformat(),
                'is_suspicious': t.is_suspicious,
                'risk_score': t.risk_score
            } for t in transactions]
        }
        
        return jsonify(response), 200
        
    except Exception as e:
        logging.error(f"Error getting user profile: {str(e)}")
        return jsonify({'error': str(e)}), 500

# @app.route('/api/v1/get_alerts/<user_id>', methods=['GET'])
# def get_alerts(user_id):
#     """Get recent alerts for a user"""
#     try:
#         # Get database session
#         db = next(get_db())
        
#         # Get recent alerts
#         alerts = db.query(Alert).filter(
#             Alert.user_id == user_id
#         ).order_by(Alert.timestamp.desc()).limit(10).all()
        
#         # Format response
#         response = [{
#             'alert_id': a.alert_id,
#             'timestamp': a.timestamp.isoformat(),
#             'risk_score': a.risk_score,
#             'reasons': json.loads(a.reasons),
#             'transaction_id': a.transaction_id,
#             'transaction_details': json.loads(a.transaction_details),
#             'status': a.status
#         } for a in alerts]
        
#         return jsonify(response), 200
        
#     except Exception as e:
#         logging.error(f"Error getting alerts: {str(e)}")
#         return jsonify({'error': str(e)}), 500

# Khởi động server
if __name__ == '__main__':
    # Get port from environment variable or use default
    port = int(os.getenv('PORT', 5001))
    
    # Start Flask app
    app.run(host='0.0.0.0', port=port)
