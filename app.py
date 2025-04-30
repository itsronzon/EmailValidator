import os
import logging
from flask import Flask, render_template, request, jsonify
from email_verifier import EmailVerifier

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "default-dev-key")

# Initialize email verifier
email_verifier = EmailVerifier()

@app.route('/')
def index():
    """Render the main page with the email verification form."""
    return render_template('index.html')

@app.route('/verify', methods=['POST'])
def verify_email():
    """API endpoint to verify an email address."""
    try:
        email = request.form.get('email', '')
        if not email:
            return jsonify({
                'success': False,
                'message': 'Email address is required',
                'results': {}
            }), 400
        
        # Perform email verification
        results = email_verifier.verify_email(email)
        
        return jsonify({
            'success': True,
            'message': 'Verification completed',
            'results': results
        })
    
    except Exception as e:
        logger.exception("Error during email verification")
        return jsonify({
            'success': False,
            'message': f'Error: {str(e)}',
            'results': {}
        }), 500

@app.route('/api/verify', methods=['GET'])
def api_verify_email():
    """API endpoint for programmatic access to email verification."""
    try:
        email = request.args.get('email', '')
        if not email:
            return jsonify({
                'success': False,
                'message': 'Email address is required',
                'results': {}
            }), 400
        
        # Perform email verification
        results = email_verifier.verify_email(email)
        
        return jsonify({
            'success': True,
            'message': 'Verification completed',
            'results': results
        })
    
    except Exception as e:
        logger.exception("Error during email verification")
        return jsonify({
            'success': False,
            'message': f'Error: {str(e)}',
            'results': {}
        }), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)