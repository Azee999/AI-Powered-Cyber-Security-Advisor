from flask import Flask, request, jsonify, send_file
from datetime import datetime
from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
import os
from dotenv import load_dotenv


load_dotenv()

app = Flask(__name__, static_folder='../frontend', static_url_path='')

# Security statistics
security_stats = {
    'total_scans': 0,
    'threats_blocked': {
        'phishing': 0,
        'malware': 0,
        'breached_password': 0
    },
    'last_scan': None
}

def update_stats(threat_type=None):
    security_stats['total_scans'] += 1
    security_stats['last_scan'] = datetime.now().timestamp()
    if threat_type:
        security_stats['threats_blocked'][threat_type] += 1

@app.route('/')
def index():
    return app.send_static_file('index.html')

@app.route('/scan-url', methods=['POST'])
def scan_url():
    data = request.json
    if not data or 'url' not in data:
        return jsonify({"error": "URL is required"}), 400
    
    url = data['url'].lower()
    is_malicious = any(bad in url for bad in ['phishing', 'malware', 'test', 'fake'])
    
    if is_malicious:
        update_stats('phishing')
        return jsonify({
            "is_malicious": True,
            "details": "URL matches known phishing/malware patterns"
        })
    else:
        return jsonify({
            "is_malicious": False,
            "details": "URL appears safe"
        })

@app.route('/analyze-email', methods=['POST'])
def analyze_email():
    data = request.json
    if not data or 'content' not in data:
        return jsonify({"error": "Email content is required"}), 400
    
    content = data['content'].lower()
    is_phishing = False
    reasons = []
    
    # Simple phishing detection logic
    if any(word in content for word in ['urgent', 'immediately', 'verify now']):
        is_phishing = True
        reasons.append("Uses urgent language")
    
    if 'click here' in content and 'http://' in content:
        is_phishing = True
        reasons.append("Contains suspicious links")
    
    if 'dear customer' in content or 'dear user' in content:
        is_phishing = True
        reasons.append("Generic greeting")
    
    if is_phishing:
        update_stats('phishing')
    
    return jsonify({
        "is_phishing": is_phishing,
        "risk_score": 85 if is_phishing else 15,
        "reasons": reasons if reasons else ["No clear phishing indicators"]
    })

@app.route('/check-password', methods=['POST'])
def check_password():
    data = request.json
    if not data or 'password' not in data:
        return jsonify({"error": "Password is required"}), 400
    
    password = data['password']
    common_passwords = [
        "123456", "password", "123456789", 
        "12345", "qwerty", "admin", "welcome"
    ]
    
    if password in common_passwords:
        update_stats('breached_password')
        return jsonify({
            "is_breached": True,
            "breach_count": "millions",
            "reason": "Extremely common password"
        })
    else:
        return jsonify({
            "is_breached": False,
            "reason": "Not found in common breaches"
        })

@app.route('/get-stats')
def stats():
    return jsonify(security_stats)

@app.route('/generate-report')
def generate_report():
    stats = security_stats
    
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    
    content = []
    content.append(Paragraph("Security Report", styles['Title']))
    content.append(Spacer(1, 12))
    
    content.append(Paragraph(f"Total Scans: {stats['total_scans']}", styles['Normal']))
    last_scan = stats['last_scan']
    last_scan_text = "Never" if not last_scan else datetime.fromtimestamp(last_scan).strftime("%Y-%m-%d %H:%M:%S")
    content.append(Paragraph(f"Last Scan: {last_scan_text}", styles['Normal']))
    
    content.append(Paragraph("Threats Detected:", styles['Heading2']))
    for threat, count in stats['threats_blocked'].items():
        content.append(Paragraph(f"{threat.title()}: {count}", styles['Normal']))
    
    doc.build(content)
    buffer.seek(0)
    return send_file(
        buffer,
        as_attachment=True,
        download_name=f"security_report_{datetime.now().date()}.pdf",
        mimetype='application/pdf'
    )

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Resource not found"}), 404

@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": "Internal server error"}), 500

if __name__ == '__main__':
    from waitress import serve
    serve(app, host="0.0.0.0", port=5000)