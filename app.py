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


#Signup Model 
app = Flask(__name__)
app.secret_key = 'your_secret_key'


@app.route('/')
def home():
    return render_template('home.html')

@app.route('/signup')
def signup():
    return render_template('signup.html')

@app.route('/scanner')
def scanner_page():
    return render_template('scanner.html')
    

# Load configuration from JSON
try:
    with open('config.json', 'r') as f:
        params = json.load(f).get('param', {})
except (FileNotFoundError, json.JSONDecodeError):
    params = {}

# Flask-Mail Configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = params.get('gmail-user', '')
app.config['MAIL_PASSWORD'] = params.get('gmail-password', '')
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False

mail = Mail(app)



@app.route('/send_otp', methods=['POST'])
def send_otp():
    email = request.form.get('email')
    if not email:
        return jsonify({"message": " Please enter a valid email!", "status": "error"})

    otp_code = str(random.randint(100000, 999999))
    session['otp'] = otp_code
    session['email'] = email  

    try:
        msg = Message('Your OTP for Verification', sender=app.config['MAIL_USERNAME'], recipients=[email])
        msg.body = f"Your OTP is {otp_code}. It will expire in 1 minute."
        mail.send(msg)
        return jsonify({"message": " OTP Sent Successfully! Check your email.", "status": "success"})
    except Exception as e:
        return jsonify({"message": f" Error sending OTP: {str(e)}", "status": "error"})

@app.route('/validate', methods=['POST'])
def validate():
    entered_otp = request.form.get('otp')
    if not entered_otp:
        return jsonify({"message": " Please enter the OTP!", "status": "error"})

    if 'otp' in session and entered_otp == session['otp']:
        session.pop('otp', None)
        return jsonify({"message": " OTP Verified! Signup Successfull...", "status": "success", "redirect": url_for('scanner_page')})

    return jsonify({"message": "Invalid OTP, please try again.", "status": "error"})






# Scanning model

scan_results = {}

def is_ip_alive(ip):
    param = "-n 1" if platform.system().lower() == "windows" else "-c 1"
    response = os.system(f"ping {param} {ip} > nul 2>&1" if platform.system().lower() == "windows" else f"ping {param} {ip} > /dev/null 2>&1")
    return response == 0

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
    ip = request.form["ipAddress"]
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
    url = request.form["website"]
    if not url:
        return jsonify({"error": "No URL provided"}), 400

    result = scan_website(url)
    return jsonify({"result": result})

if __name__ == "__main__":
    app.run(debug=True)