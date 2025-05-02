# Sử dụng Python 3.9 làm base image
FROM python:3.9-slim

# Thiết lập thư mục làm việc
WORKDIR /app

# Cài đặt các thư viện phụ thuộc
RUN apt-get update && apt-get install -y \
    gcc \
    python3-dev \
    default-libmysqlclient-dev \
    && rm -rf /var/lib/apt/lists/*

# Sao chép file requirements.txt vào container
COPY requirements.txt .

# Cài đặt các thư viện phụ thuộc
RUN pip install --no-cache-dir -r requirements.txt
# RUN pip install --no-cache-dir "uvicorn[standard]" fastapi python-dotenv pymysql openai

# Sao chép toàn bộ mã nguồn vào container
# COPY . .

# Tạo các thư mục cần thiết
RUN mkdir -p /app/data/models

# Thiết lập biến môi trường
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1
ENV PATH="/root/.local/bin:${PATH}"

# Mở cổng
EXPOSE 8000

# Khởi động ứng dụng với uvicorn
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:8000", "api:app"]