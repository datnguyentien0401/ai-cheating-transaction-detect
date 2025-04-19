# Fraud Detection System

A real-time fraud detection system that uses artificial intelligence to analyze and detect suspicious transactions.

## Features

- **Real-time fraud detection**: Analyze transactions as they occur
- **Advanced machine learning**: Uses Random Forest and Isolation Forest models to detect anomalous patterns
- **User behavior analysis**: Tracks and learns from user transaction behavior
- **Automatic alerts**: Sends alerts when suspicious transactions are detected
- **Transaction verification**: Allows users to verify transactions after receiving alerts
- **Secure data storage**: Uses MySQL database to store transaction data and user profiles

## Technologies Used

- **Python**: Primary programming language
- **Flask**: Web framework for building API
- **SQLAlchemy**: ORM for database interaction
- **MySQL**: Database for data storage
- **Scikit-learn**: Machine learning library for building fraud detection models
- **Pandas & NumPy**: Data processing and analysis

## Installation

1. Clone repository:
   ```
   git clone https://github.com/datnguyentien0401/ai-cheating-transaction-detect.git
   cd ai-cheating-transaction-detect
   ```

2. Create and activate virtual environment:
   ```
   python -m venv venv
   source venv/bin/activate  # On Linux/Mac
   # or
   venv\Scripts\activate  # On Windows
   ```

3. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

4. Configure database:
   - Create a `.env` file with the following information:
     ```
     DB_USER=your_username
     DB_PASSWORD=your_password
     DB_HOST=localhost
     DB_PORT=3306
     DB_NAME=fraud_detection
     ```

5. Initialize database:
   ```
   python -c "from database import init_db; init_db()"
   ```

## Usage

1. Start the server:
   ```
   python api.py
   ```

2. API Endpoints:
   - `POST /api/v1/process-transaction`: Process a new transaction
   - `POST /api/v1/train-model`: Train the model with new data
   - `POST /api/v1/verify-transaction`: Verify a transaction
   - `GET /api/v1/statistics`: Get system statistics
   - `GET /get_user_profile/<user_id>`: Get user profile
   - `GET /get_alerts/<user_id>`: Get user alerts

## Project Structure

- `api.py`: API endpoints and request handling
- `agent.py`: Fraud detection system
- `database.py`: Database models and connection
- `script.mysql`: SQL script to create database
- `.env`: Environment configuration

## Data Model

- **User**: User information
- **Transaction**: Transaction data
- **UserProfile**: User behavior profile
- **Alert**: Fraud alerts
