# Sử dụng Python 3.9 làm base image
FROM python:3.9-slim

# Thiết lập thư mục làm việc
WORKDIR /app

# Sao chép file requirements.txt vào container
COPY requirements.txt .

# Cài đặt các thư viện phụ thuộc
RUN pip install --no-cache-dir -r requirements.txt

# Sao chép toàn bộ mã nguồn vào container
COPY . .

# Thiết lập biến môi trường
ENV FLASK_APP=app.py
ENV FLASK_ENV=production
ENV PORT=5000

# Mở cổng
EXPOSE 5000

# Khởi động ứng dụng với gunicorn
CMD gunicorn --bind 0.0.0.0:$PORT --workers 4 --threads 2 app:app