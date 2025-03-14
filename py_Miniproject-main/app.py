from flask import Flask, render_template, request, session, jsonify, redirect, url_for
from flask_mail import Mail, Message
import random
import json
import nmap
import requests
from bs4 import BeautifulSoup
import threading
import os
import platform
import socket
import psutil
from flask_sqlalchemy import SQLAlchemy
from flask import send_from_directory


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:Aaditi2002@localhost:5432/sign_up'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'your_secret_key'

db = SQLAlchemy(app)

class Signup(db.Model):
    __tablename__ = "signups"
    id = db.Column(db.Integer, primary_key=True)
    gmail = db.Column(db.String(40), unique=True, nullable=False)
    otp = db.Column(db.String(6), nullable=False)

with app.app_context():
    db.create_all()

# Load email configuration from JSON
try:
    with open('config.json', 'r') as f:
        params = json.load(f).get('param', {})
except (FileNotFoundError, json.JSONDecodeError):
    params = {}

app.config.update({
    'MAIL_SERVER': 'smtp.gmail.com',
    'MAIL_PORT': 587,
    'MAIL_USERNAME': params.get('gmail-user', ''),
    'MAIL_PASSWORD': params.get('gmail-password', ''),
    'MAIL_USE_TLS': True,
    'MAIL_USE_SSL': False,
    'MAIL_DEFAULT_SENDER': params.get('gmail-user', '')
})

mail = Mail(app)

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/signup')
def signup():
    return render_template('signup.html')

@app.route('/scanner')
def scanner_page():
    return render_template('scanner.html')

@app.route('/send_otp', methods=['POST'])
def send_otp():
    email = request.form.get('email')
    if not email:
        return jsonify({"message": "Please enter a valid email!", "status": "error"})

    otp_code = str(random.randint(100000, 999999))
    session['otp'] = otp_code
    session['email'] = email

    user = Signup.query.filter_by(gmail=email).first()
    if user:
        user.otp = otp_code
    else:
        user = Signup(gmail=email, otp=otp_code)
        db.session.add(user)

    db.session.commit()

    try:
        msg = Message('Your OTP for Verification', recipients=[email])
        msg.body = f"Your OTP is {otp_code}. It will expire in 1 minute."
        mail.send(msg)
        return jsonify({"message": "OTP Sent Successfully! Check your email.", "status": "success"})
    except Exception as e:
        return jsonify({"message": f"Error sending OTP: {str(e)}", "status": "error"})

@app.route('/validate', methods=['POST'])
def validate():
    email = session.get('email')
    entered_otp = request.form.get('otp')
    if not entered_otp or not email:
        return jsonify({"message": "Please enter the OTP!", "status": "error"})

    user = Signup.query.filter_by(gmail=email).first()
    if user and user.otp == entered_otp:
        session.pop('otp', None)
        return jsonify({"message": "OTP Verified! Signup Successful...", "status": "success", "redirect": url_for('scanner_page')})

    return jsonify({"message": "Invalid OTP, please try again.", "status": "error"})

# System Scanner Function
@app.route("/scan_system", methods=["POST"])
def system_scan():
    system_name = request.form.get("systemName")
    if not system_name:
        return jsonify({"error": "No system name provided"}), 400
    try:
        ip_address = socket.gethostbyname(system_name)
        system_info = {
            "Hostname": system_name,
            "IP Address": ip_address,
            "OS": platform.system(),
            "OS Version": platform.version(),
            "Processor": platform.processor(),
            "Machine": platform.machine(),
            "Running Processes": len(psutil.pids()),
            "Memory Usage": f"{psutil.virtual_memory().percent}%",
            "CPU Usage": f"{psutil.cpu_percent(interval=1)}%"
        }
        return jsonify({"result": system_info})
    except socket.gaierror:
        return jsonify({"error": "Invalid system name or IP address"}), 400

# Network Scanner
@app.route("/start_scan", methods=["POST"])
def start_scan():
    ip = request.form["ipAddress"]
    if not ip:
        return jsonify({"error": "No IP provided"}), 400
    try:
        scanner = nmap.PortScanner()
        scanner.scan(ip, arguments="-T4 -F")
        return jsonify({"result": {"open_ports": list(scanner[ip].all_protocols())} if ip in scanner.all_hosts() else {"status": "No open ports found"}})
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route("/scan_website", methods=["POST"])
def website_scan():
    url = request.form["website"]
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, "html.parser")
        title = soup.title.string if soup.title else "No Title Found"
        headers = response.headers
        missing_headers = [h for h in ["Content-Security-Policy", "X-Frame-Options", "X-XSS-Protection", "Strict-Transport-Security"] if h not in headers]
        return jsonify({"result": {"title": title, "missing_headers": missing_headers}})
    except Exception as e:
        return jsonify({"error": str(e)})
@app.route('/logout')
def logout():
    session.clear()  # Clears all session data
    return redirect(url_for('home'))  # Redirects to home or login page

#fevicon icon 
@app.route('/favicon.ico')
def favicon():
    return send_from_directory("static", "favicon.ico", mimetype="image/x-icon")


if __name__ == "__main__":
    app.run(debug=True)                                                                                                                                    