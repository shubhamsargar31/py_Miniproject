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
import subprocess
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:shubham123@localhost:5432/sign_up'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class Signup(db.Model):
    __tablename__ = "signups"
    id = db.Column(db.Integer, primary_key=True)
    gmail = db.Column(db.String(40), unique=True, nullable=False)
    otp = db.Column(db.String(6), nullable=False)


with app.app_context():
    db.create_all()

app.secret_key = 'your_secret_key'


try:
    with open('config.json', 'r') as f:
        params = json.load(f).get('param', {})
except (FileNotFoundError, json.JSONDecodeError):
    params = {}

# Mail Configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = params.get('gmail-user', '')
app.config['MAIL_PASSWORD'] = params.get('gmail-password', '')
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False

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
        msg = Message('Your OTP for Verification', sender=app.config['MAIL_USERNAME'], recipients=[email])
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

# Scanning Model
scan_results = {}

def is_ip_alive(ip):
    param = "-n 1" if platform.system().lower() == "windows" else "-c 1"
    try:
        result = subprocess.run(
            ["ping", param, ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        return result.returncode == 0
    except Exception:
        return False

def scan_ip(ip):
    scan_results[ip] = "Scanning..."
    try:
        if not is_ip_alive(ip):
            scan_results[ip] = "IP is not reachable!"
            return

        scanner = nmap.PortScanner()
        scanner.scan(ip, arguments="-T4 -F")
        result = {host: {"open_ports": list(scanner[host].all_protocols())} for host in scanner.all_hosts()}
        scan_results[ip] = result
    except Exception as e:
        scan_results[ip] = f"Error: {str(e)}"

def scan_website(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, "html.parser")
        title = soup.title.string if soup.title else "No Title Found"

        headers = response.headers
        security_headers = ["Content-Security-Policy", "X-Frame-Options", "X-XSS-Protection", "Strict-Transport-Security"]
        missing_headers = [header for header in security_headers if header not in headers]

        return {"title": title, "missing_headers": missing_headers}
    except Exception as e:
        return {"error": str(e)}

@app.route("/start_scan", methods=["POST"])
def start_scan():
    ip = request.form.get("ipAddress")
    if not ip:
        return jsonify({"error": "No IP provided"}), 400

    scan_results[ip] = "Scanning..."
    threading.Thread(target=scan_ip, args=(ip,)).start()

    return jsonify({"message": "Scan started", "ip": ip})

@app.route("/get_scan_result/<ip>")
def get_scan_result(ip):
    result = scan_results.get(ip, "No scan found for this IP.")
    return jsonify({"ip": ip, "result": result})

@app.route("/scan_website", methods=["POST"])
def website_scan():
    url = request.form.get("website")
    if not url:
        return jsonify({"error": "No URL provided"}), 400

    result = scan_website(url)
    return jsonify({"result": result})

if __name__ == "__main__":
    app.run(debug=True)
