from flask import Flask, request, jsonify, make_response
from flask_cors import CORS
import os
from datetime import datetime
import json
from guardian_ai import GuardianAI
from guardian_ai import HighPrecisionThreatDetector
from security.middleware import SecurityMiddleware
from security.auth import Authentication
from security.validation import InputValidator
from functools import wraps
import secrets
import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app, supports_credentials=True)

# Initialize security components
security_middleware = SecurityMiddleware(app)
auth = Authentication(os.environ.get('JWT_SECRET', 'your-secret-key'))
validator = InputValidator()

# Initialize GuardianAI
guardian = GuardianAI()

# Load the trained model
MODEL_PATH = os.path.join(os.path.dirname(__file__), 'trained_model.pkl')
if not os.path.exists(MODEL_PATH):
    logger.error(f"Trained model not found at {MODEL_PATH}")
    raise FileNotFoundError(f"Trained model not found at {MODEL_PATH}")

guardian.threat_detector = HighPrecisionThreatDetector(model_path=MODEL_PATH)

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'No authorization token provided'}), 401
        
        token = token.replace('Bearer ', '')
        user_data = auth.verify_session_token(token)
        if not user_data:
            return jsonify({'error': 'Invalid or expired token'}), 401
        
        return f(*args, **kwargs)
    return decorated

@app.route('/api/analyze', methods=['POST'])
# @require_auth  # Temporarily disabled for Streamlit UI
def analyze_threat():
    try:
        # Validate and sanitize input
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        text = data.get('text', '')
        if not text:
            return jsonify({'error': 'No text provided'}), 400
        
        # Sanitize input
        text = validator.sanitize_text(text)
        
        # Prepare features from text
        features = guardian.threat_detector.prepare_features({'text': text})
        
        # Analyze threat
        result = guardian.threat_detector.predict_threat(features, original_text=text)
        
        # Convert result to dict and sanitize
        response = {
            'threat_type': validator.sanitize_text(result.threat_type),
            'specific_threat_name': validator.sanitize_text(result.specific_threat_name),
            'confidence': result.confidence,
            'risk_level': validator.sanitize_text(result.risk_level),
            'model_predictions': validator.sanitize_dict(result.model_predictions),
            'feature_importance': validator.sanitize_dict(result.feature_importance),
            'timestamp': result.timestamp,
            'processing_time': result.processing_time
        }
        
        # Add security headers
        resp = make_response(jsonify(response))
        for key, value in security_middleware.add_security_headers().items():
            resp.headers[key] = value
        
        return resp
    
    except ValueError as e:
        logger.error(f"ValueError during analysis: {str(e)}")
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        logger.error(f"Error during analysis: {str(e)}", exc_info=True)
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        email = data.get('email')
        password = data.get('password')
        
        if not email or not password:
            return jsonify({'error': 'Email and password are required'}), 400
        
        # Validate email format
        if not validator.validate_email(email):
            return jsonify({'error': 'Invalid email format'}), 400
        
        # Check login attempts
        allowed, remaining = auth.check_login_attempts(email)
        if not allowed:
            return jsonify({
                'error': f'Account temporarily locked. Try again in {remaining} minutes'
            }), 429
        
        # TODO: Verify credentials against database
        # For now, using dummy credentials
        if email == 'admin@guardian.ai' and password == 'Admin123!':
            # Generate session token
            token = auth.generate_session_token(email, 'admin')
            auth.reset_failed_attempts(email)
            
            resp = make_response(jsonify({
                'message': 'Login successful',
                'token': token
            }))
            
            # Set secure cookie
            resp.set_cookie(
                'session_id',
                secrets.token_hex(32),
                httponly=True,
                secure=True,
                samesite='Strict',
                max_age=3600
            )
            
            return resp
        else:
            auth.record_failed_attempt(email)
            return jsonify({'error': 'Invalid credentials'}), 401
    
    except Exception as e:
        logger.error(f"Error during login: {str(e)}", exc_info=True)
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    try:
        response = {
            'status': 'healthy',
            'model_loaded': guardian.threat_detector.is_trained
        }
        logger.info(f"Health check response: {response}")
        return jsonify(response)
    except Exception as e:
        logger.error(f"Error during health check: {str(e)}", exc_info=True)
        return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    logger.info("Starting Flask application...")
    app.run(debug=True, host='127.0.0.1', port=5000) 