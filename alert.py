import os
import logging
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from twilio.rest import Client

class NotificationService:
    """
    Dịch vụ gửi thông báo cho người dùng qua các kênh khác nhau
    """
    
    def __init__(self):
        # Thiết lập logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            filename='notification.log'
        )
        self.logger = logging.getLogger('notification_service')
        
        # Khởi tạo tham số cho SendGrid (Email)
        self.sendgrid_api_key = os.environ.get('SENDGRID_API_KEY')
        self.email_from = os.environ.get('EMAIL_FROM', 'alert@yourdomain.com')
        
        # Khởi tạo tham số cho Twilio (SMS)
        self.twilio_account_sid = os.environ.get('TWILIO_ACCOUNT_SID')
        self.twilio_auth_token = os.environ.get('TWILIO_AUTH_TOKEN')
        self.twilio_phone_number = os.environ.get('TWILIO_PHONE_NUMBER')
        
        # Khởi tạo client
        self.sendgrid_client = None
        self.twilio_client = None
        
        if self.sendgrid_api_key:
            try:
                self.sendgrid_client = SendGridAPIClient(self.sendgrid_api_key)
            except Exception as e:
                self.logger.error(f"Không thể khởi tạo SendGrid client: {str(e)}")
        
        if self.twilio_account_sid and self.twilio_auth_token:
            try:
                self.twilio_client = Client(self.twilio_account_sid, self.twilio_auth_token)
            except Exception as e:
                self.logger.error(f"Không thể khởi tạo Twilio client: {str(e)}")
    
    def send_email_alert(self, user_email, alert_data):
        """
        Gửi email cảnh báo giao dịch đáng ngờ
        
        Args:
            user_email (str): Email của người dùng
            alert_data (dict): Dữ liệu cảnh báo
        
        Returns:
            bool: Kết quả gửi email
        """
        if not self.sendgrid_client:
            self.logger.warning("SendGrid client chưa được khởi tạo")
            return False
        
        try:
            # Tạo nội dung email
            transaction_details = alert_data['transaction_details']
            reasons = alert_data.get('reasons', [])
            reasons_text = "\n".join([f"- {reason}" for reason in reasons])
            
            subject = f"CẢNH BÁO: Phát hiện giao dịch đáng ngờ #{alert_data['transaction_id']}"
            
            content = f"""
            <h2>Cảnh báo giao dịch đáng ngờ</h2>
            <p>Hệ thống đã phát hiện một giao dịch có dấu hiệu bất thường:</p>
            
            <h3>Thông tin giao dịch:</h3>
            <ul>
                <li><strong>Mã giao dịch:</strong> {alert_data['transaction_id']}</li>
                <li><strong>Thời gian:</strong> {transaction_details['time']}</li>
                <li><strong>Số tiền:</strong> {transaction_details['amount']:,.0f} VND</li>
                <li><strong>Danh mục:</strong> {transaction_details['category']}</li>
                <li><strong>Vị trí:</strong> {transaction_details['location']}</li>
                <li><strong>Mức độ rủi ro:</strong> {alert_data['risk_score']:.2f} (thang điểm 0-1)</li>
            </ul>
            
            <h3>Lý do cảnh báo:</h3>
            <p>{reasons_text if reasons else "Giao dịch không phù hợp với mẫu hành vi thông thường của bạn."}</p>
            
            <h3>Hành động cần thực hiện:</h3>
            <p>Nếu bạn <strong>không thực hiện</strong> giao dịch này, vui lòng:</p>
            <ol>
                <li>Liên hệ ngay với trung tâm hỗ trợ theo số: <strong>1900 xxxx</strong></li>
                <li>Tạm khóa tài khoản/thẻ của bạn qua ứng dụng</li>
            </ol>
            
            <p>Nếu đây là giao dịch hợp lệ của bạn, vui lòng xác nhận bằng cách nhấn vào đường dẫn sau: 
            <a href="https://yourdomain.com/verify-transaction/{alert_data['transaction_id']}">Xác nhận giao dịch</a></p>
            
            <p>Trân trọng,<br>
            Đội ngũ bảo mật</p>
            """
            
            message = Mail(
                from_email=self.email_from,
                to_emails=user_email,
                subject=subject,
                html_content=content
            )
            
            # Gửi email
            response = self.sendgrid_client.send(message)
            
            if response.status_code >= 200 and response.status_code < 300:
                self.logger.info(f"Đã gửi email cảnh báo thành công đến {user_email}")
                return True
            else:
                self.logger.error(f"Lỗi khi gửi email: {response.status_code}, {response.body}")
                return False
                
        except Exception as e:
            self.logger.error(f"Lỗi khi gửi email cảnh báo: {str(e)}")
            return False
    
    def send_sms_alert(self, phone_number, alert_data):
        """
        Gửi SMS cảnh báo giao dịch đáng ngờ
        
        Args:
            phone_number (str): Số điện thoại của người dùng
            alert_data (dict): Dữ liệu cảnh báo
        
        Returns:
            bool: Kết quả gửi SMS
        """
        if not self.twilio_client or not self.twilio_phone_number:
            self.logger.warning("Twilio client chưa được khởi tạo")
            return False
        
        try:
            # Tạo nội dung SMS
            transaction_details = alert_data['transaction_details']
            
            message_body = (
                f"CẢNH BÁO: Giao dịch đáng ngờ #{alert_data['transaction_id']} "
                f"số tiền {transaction_details['amount']:,.0f} VND tại {transaction_details['category']}. "
                f"Nếu không phải bạn, gọi ngay 1900xxxx hoặc vào ứng dụng để khóa thẻ. "
                f"Xác nhận: https://yourdomain.com/v/{alert_data['transaction_id']}"
            )
            
            # Gửi SMS
            message = self.twilio_client.messages.create(
                body=message_body,
                from_=self.twilio_phone_number,
                to=phone_number
            )
            
            self.logger.info(f"Đã gửi SMS cảnh báo thành công đến {phone_number}, SID: {message.sid}")
            return True
                
        except Exception as e:
            self.logger.error(f"Lỗi khi gửi SMS cảnh báo: {str(e)}")
            return False
    
    def send_push_notification(self, device_token, alert_data):
        """
        Gửi push notification cảnh báo giao dịch đáng ngờ
        
        Args:
            device_token (str): Token của thiết bị người dùng
            alert_data (dict): Dữ liệu cảnh báo
        
        Returns:
            bool: Kết quả gửi thông báo
        """
        try:
            # Đây là phần code để gửi push notification
            # Trong thực tế, bạn sẽ sử dụng Firebase Cloud Messaging hoặc dịch vụ tương tự
            self.logger.info(f"Đã gửi push notification thành công đến {device_token}")
            return True
                
        except Exception as e:
            self.logger.error(f"Lỗi khi gửi push notification: {str(e)}")
            return False
    
    def send_alert(self, user_info, alert_data, alert_level='medium'):
        """
        Gửi cảnh báo qua nhiều kênh dựa trên mức độ cảnh báo
        
        Args:
            user_info (dict): Thông tin của người dùng
            alert_data (dict): Dữ liệu cảnh báo
            alert_level (str): Mức độ cảnh báo (low, medium, high)
        
        Returns:
            dict: Kết quả gửi cảnh báo qua các kênh
        """
        results = {}
        
        try:
            # Kiểm tra thông tin người dùng
            email = user_info.get('email')
            phone = user_info.get('phone')
            device_token = user_info.get('device_token')
            
            # Gửi thông báo dựa trên mức độ cảnh báo
            if alert_level == 'low':
                # Chỉ push notification
                if device_token:
                    results['push'] = self.send_push_notification(device_token, alert_data)
                
            elif alert_level == 'medium':
                # Push notification và email
                if device_token:
                    results['push'] = self.send_push_notification(device_token, alert_data)
                
                if email:
                    results['email'] = self.send_email_alert(email, alert_data)
                
            elif alert_level == 'high':
                # Tất cả các kênh
                if device_token:
                    results['push'] = self.send_push_notification(device_token, alert_data)
                
                if email:
                    results['email'] = self.send_email_alert(email, alert_data)
                
                if phone:
                    results['sms'] = self.send_sms_alert(phone, alert_data)
            
            self.logger.info(f"Đã gửi cảnh báo mức {alert_level}: {results}")
            return results
                
        except Exception as e:
            self.logger.error(f"Lỗi khi gửi cảnh báo: {str(e)}")
            return results


# Ví dụ sử dụng
if __name__ == "__main__":
    # Thiết lập biến môi trường cho testing
    os.environ['SENDGRID_API_KEY'] = 'YOUR_SENDGRID_API_KEY'
    os.environ['TWILIO_ACCOUNT_SID'] = 'YOUR_TWILIO_ACCOUNT_SID'
    os.environ['TWILIO_AUTH_TOKEN'] = 'YOUR_TWILIO_AUTH_TOKEN'
    os.environ['TWILIO_PHONE_NUMBER'] = '+84981067269'
    
    # Khởi tạo dịch vụ thông báo
    notification_service = NotificationService()
    
    # Dữ liệu mẫu
    user_info = {
        'email': 'user@example.com',
        'phone': '+84123456789',
        'device_token': 'device_token_here'
    }
    
    alert_data = {
        'user_id': '12345',
        'transaction_id': 'TX-98765',
        'risk_score': 0.85,
        'reasons': [
            'Giao dịch với số tiền cao bất thường',
            'Vị trí IP mới chưa từng sử dụng trước đây'
        ],
        'transaction_details': {
            'amount': 5000000,
            'category': 'Electronics',
            'location': 'Hanoi, Vietnam',
            'time': '2025-04-18T15:30:45'
        }
    }
    
    # Gửi cảnh báo
    results = notification_service.send_alert(user_info, alert_data, alert_level='high')
    print(results)