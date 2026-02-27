from flask import Flask, render_template, request, redirect, url_for, jsonify,flash,session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
# from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
import os
import re
import random
import time
from flask_mail import Mail, Message
# from pyngrok import ngrok ..      
import qrcode
import json
import razorpay
import hmac
import hashlib
from sqlalchemy.orm.attributes import flag_modified
from cryptography.fernet import Fernet

app = Flask(__name__)
app.config['SECRET_KEY'] =os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///candidates.db'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'telugusamiti.iitd@gmail.com'  # Replace with your email
app.config['MAIL_PASSWORD'] = 'milfzqucfhcyupma'         # -----> Replaced with the password of the email
mail = Mail(app)
db = SQLAlchemy(app)
QR_EVENT_FOLDER = 'static/event_qr_codes'
QR_FOOD_FOLDER= 'static/food_qr_codes'
QR_GUEST_FOLDER = 'static/guest_qr_codes'
GUESTS_JSON_FILE = 'static/guests.json'
QR_MAP_FILE='static/qr_map.json'
MAX_GUESTS=3
key_file = open('key.key', 'rb')  # Open the file as wb to read bytes
key = key_file.read()  # The key will be type bytes
key_file.close()
Max_Session_Time=20 * 60
Max_otp_time=90

# Ensure the folder exists
if not os.path.exists(QR_EVENT_FOLDER):
    os.makedirs(QR_EVENT_FOLDER)

if not os.path.exists(QR_FOOD_FOLDER):
    os.makedirs(QR_FOOD_FOLDER)
    
if not os.path.exists(QR_GUEST_FOLDER):
    os.makedirs(QR_GUEST_FOLDER)
    

# User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), unique=True, nullable=False)
    display_name = db.Column(db.String(100), nullable=False)                 # ----> added display name
    password_hash = db.Column(db.String(20), nullable=False)
    payment_status = db.Column(db.Boolean, default=False, nullable=False)
    # guest_list = db.Column(db.JSON, default=list)  # JSON field to store guest list
    
    # # Relationship with guests
    # guests = db.relationship('Guest', backref='user', lazy=True, cascade="all, delete")
    
class Guest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(30), unique=False, nullable=False)  # Optional guest email
    inviter_email = db.Column(db.String(30), nullable=False)
    # user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)  # Unique ID for each scan
    email = db.Column(db.String(30), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)    
    food_scan = db.Column(db.Boolean, default=False, nullable=False)
    event_scan = db.Column(db.Boolean, default=False, nullable=False)

class Guest_Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)  # Unique ID for each scan
    name = db.Column(db.String(100), nullable=False)
    # think of unique or not both email and invited_email
    email = db.Column(db.String(30), unique=False, nullable=False)    
    invited_email= db.Column(db.String(30), unique=False, nullable=False)    
    food_scan = db.Column(db.Boolean, default=False, nullable=False)
    event_scan = db.Column(db.Boolean, default=False, nullable=False)
    
class UserPayment(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)  # Unique ID
    username = db.Column(db.String(30), nullable=False)  # Primary Key
    order_id = db.Column(db.String(100), unique=True,nullable=False)  
    amount = db.Column(db.Integer, nullable=False)  # Amount paid (in paise)
    
class orderpaymentid(db.Model):
    id = db.Column(db.Integer, primary_key=True)  
    order_id = db.Column(db.String(100), nullable=False)  # Unique order ID
    payment_id = db.Column(db.String(100), unique=True, nullable=False)  # Unique payment ID
    payment_status = db.Column(db.Boolean, default=False) 
    
class GuestPayment(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)  # Unique ID
    inviter = db.Column(db.String(30), nullable=False)  
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(30), unique=False, nullable=False)
    order_id = db.Column(db.String(100),nullable=False)  
    amount = db.Column(db.Integer, nullable=False)  # Amount paid (in paise)

# Initialize Database within Application Context
with app.app_context():
    db.create_all()
    
def send_otp(email, otp):
    # msg = Message('Your OTP Code', sender='your_email@gmail.com', recipients=[email])
    # msg.body = f'Welcome to the Telugu community of IIT Delhi!\n\nYour OTP for registration is {otp}.'
    # mail.send(msg)
    msg = Message('మీ OTP కోడ్', sender='telugusamiti.iitd@gmail.com', recipients=[email])
    msg.body = f'ఐఐటిడి తెలుగు కమ్యూనిటీలోకి స్వాగతం!\n\nనమోదు కోసం మీ OTP {otp} .'
    mail.send(msg)

@app.route('/')
def index():
    print("entered..")
    return render_template('home.html')

def generate_and_save_qr_code(user_email,user_name):
    """Generates a QR code with the user's email and saves it to a folder."""
    # Create the QR data (you can customize what you want in the QR code)
    # qr_data = f"Name: {user_name}\nUser: {user_email}"
    qr_data = {
    "NAME": user_name,
    "EMAIL": user_email,
    "PURPOSE": "EVENT"
    }
    fernet = Fernet(key)
    
    # Serialize the data to JSON string and encode to bytes
    qr_data_bytes = json.dumps(qr_data).encode('utf-8')
    event_qr_data = fernet.encrypt(qr_data_bytes)

    # Modify qr_data for food
    qr_data['PURPOSE'] = "FOOD"
    food_qr_data = fernet.encrypt(json.dumps(qr_data).encode('utf-8'))

    # Generate the QR code
    event_qr= qrcode.make(event_qr_data)
    food_qr = qrcode.make(food_qr_data)    

    # Define the filename for the QR code (using user's email)
    qr_filename_event = f"{user_email}_event.png"
    qr_filename_food=f"{user_email}_food.png"
    event_qr_path = os.path.join(QR_EVENT_FOLDER, qr_filename_event)
    food_qr_path = os.path.join(QR_FOOD_FOLDER, qr_filename_food)
    
    # Save the QR code to the file
    food_qr.save(food_qr_path)
    event_qr.save(event_qr_path)
    
    # Create a new Scan record for the user
    new_user = Scan(email=user_email,name = user_name,food_scan=False,event_scan=False) # ----> added display name to the new user
    db.session.add(new_user)
    db.session.commit()
    return 

# has to put some restrictions on passwords
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        display_name = request.form['display_name']          # ----> requested display name
        email = request.form['username']
        password = request.form['password']
        
        if not re.match(r"^[^@]+@([^.]+\.)?iitd\.ac\.in$", email):
            flash('Invalid email format. Please use your IITD email.','error')
            return redirect(url_for('register'))
        
        if not (len(email) >= 9 and re.match(r'^[^@]{3}\d{6}', email) or ("cstaff" in email)):
            flash('Invalid email format. Please use IITD email with kerberos.','error')
            return redirect(url_for('register'))
        
        # Check if the email already exists
        existing_user = User.query.filter_by(username=email).first()
        if existing_user:
            flash('Email already exists','error')
            return redirect(url_for('register'))
        
        # Generate a 6-digit OTP
        otp = random.randint(100000, 999999)
        send_otp(email, otp)

        # Store OTP and email in session
        session['display_name'] = display_name                  # ----> stored display name in session
        session['otp'] = otp
        session['email'] = email
        session['password'] = generate_password_hash(password, method='pbkdf2:sha256')
        session['otp_time'] = time.time()  # Store the current time
        session['attempts'] = 0

        flash('OTP sent to your email. Please verify.')
        return redirect(url_for('verify_otp'))
        
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=email, password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        # flash('Registration successful! Please login.')
        return redirect(url_for('loginpage'))

    return render_template('register.html')

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        entered_otp = request.form['otp']
        
        # early validation – must be 6 digits
        if not entered_otp.isdigit() or len(entered_otp) != 6:
            flash('Invalid OTP format. Please enter a 6‑digit code.','error')
            return render_template('otpverify.html', time_left=0)
        
        # Check if OTP has expired (60 seconds timeout)
        if 'otp_time' in session and time.time() - session['otp_time'] >= Max_otp_time:
            flash('OTP has expired. Please register again.','error')
            # Clear the session data for security
            session.pop('otp', None)
            session.pop('otp_time', None)
            session.pop('attempts', None)
            session['otp_resend_used'] = False
            return redirect(url_for('verify_otp'))

        # Verify OTP
        if 'otp' in session and int(entered_otp) == session['otp']:
            # OTP is correct, register the user
            new_user = User(username=session['email'],display_name = session['display_name'],password_hash=session['password'],payment_status=False) # ----> added display name to the new user
            db.session.add(new_user)
            db.session.commit()

            # Clear session data
            session.pop('otp', None)
            session.pop('email', None)
            session.pop('password', None)
            session.pop('display_name', None) # ----> removed display name from the session
            session.pop('otp_time', None)
            session.pop('attempts', None)


            # flash('Registration successful! Please login.')
            return redirect(url_for('loginpage'))
        else:
            # Increment attempts counter
            session['attempts'] += 1

            # Check if attempts exceeded 3
            if session['attempts'] >= 3:
                # after three wrong tries send user back to registration
                flash('Too many failed attempts. Please register again.','error')
                session.pop('otp', None)
                session.pop('email', None)
                session.pop('password', None)
                session.pop('otp_time', None)
                session.pop('attempts', None)

                return redirect(url_for('register'))

            flash(f"Invalid OTP. You have {3-session['attempts']} attempt(s) left.",'error')
            # Preserve remaining OTP time so resend remains disabled until expiry
            time_left = max(0, int(Max_otp_time - (time.time() - session.get('otp_time', 0)))) if 'otp_time' in session else 0
            return render_template('otpverify.html', time_left=time_left)

        
    # Calculate time remaining for OTP expiration
    time_left = max(0, int(Max_otp_time - (time.time() - session['otp_time']))) if 'otp_time' in session else 0
    if time_left == 0:
        session['otp_resend_used'] = False #---> allowing resend again
        flash("OTP expired. Please resend OTP.",'error')
        return render_template('otpverify.html', time_left=0)


    return render_template('otpverify.html', time_left=time_left)
 
# if the user forgot password
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['username']      # ----> changed reuest.form['email'] to request.form['username'] for consistency (change name="username" in forgot_password.html)
        
        # Check if the email exists in the database
        user = User.query.filter_by(username=email).first()
        if not user:
            flash('Email is not registered or incorrect','error') # ----> changed the message
            return redirect(url_for('forgot_password'))
        
        # Generate a new 6-digit OTP
        otp = random.randint(100000, 999999)
        send_otp(email, otp)
        
        # Store OTP and email in session for verification
        session['reset_otp'] = otp
        session['reset_email'] = email
        session['otp_time'] = time.time()  # Store current time for timeout check
        session['display_name'] = user.display_name                               # ----> stored display name in session
        session['attempts'] = 0
        session['otp_resend_used'] = False


        flash('An OTP has been sent to your email for password reset.')
        return redirect(url_for('verify_reset_otp'))

    return render_template('forgot_password.html')

@app.route('/verify_reset_otp', methods=['GET', 'POST'])
def verify_reset_otp():
    if request.method == 'POST':
        entered_otp = request.form['otp']
        
        # early validation: 6 digits numeric
        if not entered_otp.isdigit() or len(entered_otp) != 6:
            flash('Invalid OTP format. Please enter a 6‑digit code.','error')
            return redirect(url_for('verify_reset_otp'))
        
        # Check if OTP has expired (60 seconds timeout)
        if 'otp_time' in session and time.time() - session['otp_time'] >= Max_otp_time:
            

            session.pop('reset_otp', None)
            session.pop('otp_time', None)
            session['attempts'] = 0
            session['otp_resend_used'] = False

            return redirect(url_for('verify_reset_otp'))

        # Verify the OTP
        if 'reset_otp' in session and int(entered_otp) == session['reset_otp']:
            # OTP is correct, proceed to reset password
            session.pop('reset_otp', None)
            session.pop('otp_time', None)
            session.pop('attempts', None)
            return redirect(url_for('reset_password'))
        else:
            # Increment attempts counter
            session['attempts'] =session.get('attempts', 0) + 1 # ----> after 3 attempts failed, the user is redirected to the forgot password page & when he go back to otp page , and try entering otp once again ,this is showing key error as the session['attempts'] is not present in the session

            # Check if attempts exceeded 3
            if session['attempts'] >= 3:
                # exceed attempts, bounce to forgot password start
                flash('Too many failed attempts. Please try again.','error')
                session.pop('reset_otp', None)
                session.pop('reset_email', None)
                session.pop('otp_time', None)
                session.pop('attempts', None)

                flash('OTP expired. Please resend OTP.','error')
                return redirect(url_for('forgot_password'))


            flash(f"Invalid OTP. You have {3-session["attempts"]} attempt(s) left.","error")
            return redirect(url_for('verify_reset_otp'))
    
    # Calculate time remaining for OTP expiration
    time_left = max(0, int(Max_otp_time - (time.time() - session['otp_time']))) if 'otp_time' in session else 0
    if time_left == 0:
        session['otp_resend_used'] = False #---> allowing resend again
        
        return render_template('change_otp.html', time_left=0)

    
    return render_template('change_otp.html', time_left=time_left)


@app.route('/resend_register_otp', methods=['POST'])
def resend_register_otp():
    """
    Resend Registration OTP (Jio/Hotstar-style UX)
    - Allowed immediately after previous OTP expiry
    - Always generates a fresh OTP
    - Resets timer and attempts
    """

    email = session.get('email')
    if not email:
        return jsonify({"error": "Session expired"}), 400

    # Generate NEW 6-digit OTP
    otp = random.randint(100000, 999999)
    send_otp(email, otp)

    # Reset OTP cycle
    session['otp'] = otp
    session['otp_time'] = time.time()
    session['attempts'] = 0

    return jsonify({"success": True})



@app.route('/resend_reset_otp', methods=['POST'])
def resend_reset_otp():
    
    #Resend Forgot Password OTP
    #Same UX as registration OTP:
    #- No resend while timer is running
    #- Fresh OTP + timer reset

    if 'otp_time' in session:
        elapsed = time.time() - session['otp_time']
        if elapsed < Max_otp_time:
            return jsonify({"error": "Please wait for OTP to expire"}), 400

    email = session.get('reset_email')
    if not email:
        return jsonify({"error": "Session expired"}), 400

    otp = random.randint(100000, 999999)
    send_otp(email, otp)

    session['reset_otp'] = otp
    session['otp_time'] = time.time()
    session['attempts'] = 0

    return jsonify({"success": True})


@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        email = session.get('reset_email')

        if not email:                                    # ---->(To be removed) This should also handle the case when the user intentionally tries to change his/her password without going through the forgot password 
            flash('Session expired. Please try again.')
            return redirect(url_for('forgot_password'))

        if new_password != confirm_password:
            flash('Passwords do not match. Please try again.','error')
            return redirect(url_for('reset_password'))

        # Update the user's password in the database
        user = User.query.filter_by(username=email).first()
        if user:
            if check_password_hash(user.password_hash, new_password):
                flash('Same as old password. Please try again.')
                return redirect(url_for('reset_password'))
            user.password_hash = generate_password_hash(new_password, method='pbkdf2:sha256')
            db.session.commit()

            # Clear session data
            session.pop('reset_email', None)

            flash('Your password has been reset successfully. Please log in.')
            return redirect(url_for('loginpage'))

    return render_template('change_password.html' , display_name = session['display_name']) # ----> added display name to the template

@app.route('/loginpage')
def loginpage():
    return render_template('login.html')

# login_manager = LoginManager(app)
# login_manager.login_view = 'loginpage'

# @login_manager.user_loader
# def load_user(user_id):
#     return User.query.get(int(user_id))

# has to add some features while login whether entering the correct email format or not
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    user = User.query.filter_by(username=username).first()

    if user and check_password_hash(user.password_hash, password):
        # login_user(user)  # Mark the user as logged in
        session.clear()
        session['user_id'] = user.id
        session['username'] = user.username
        session['display_name'] = user.display_name            # ----> added display name to the session
        session['start_time']=time.time()
        # # Check if payment is complete
        if not user.payment_status:
            flash('Payment is pending. Please complete the payment.','error')
            return redirect(url_for('payment'))  # Redirect to payment page
        
        return redirect(url_for('dashboard'))
    else:
        flash('Invalid username or password','error')
        return redirect(url_for('loginpage'))

@app.route('/payment')
# @login_required
def payment():
    if 'user_id' in session: 
        amount=1000
        if session['username'][2]=='z':
            amount=1000
        elif 'cstaff' in session['username']:
            amount=1000
        elif session['username'][2]>='0' and session['username'][2]<='9':
            amount=500
        else:
            amount=750
        return render_template('webhook.html',amount=amount)
    return redirect(url_for('loginpage'))

# RAZORPAY_KEY_ID = "rzp_live_OqKCwpkQmNvFsj"
# RAZORPAY_KEY_SECRET = "d1307n9Xe51otaInCH4OR3Dv"
RAZORPAY_KEY_ID = "rzp_live_wh4j6x4DCRc21Y"
RAZORPAY_KEY_SECRET = "GdaFBXg1C4OkHqLRmESjbuqS"
WEBHOOK_SECRET = "D6HZkCz4in@ThHF" 
@app.route('/create_order', methods=['POST'])
def create_order():
    # data = request.json
    if 'username' in session: 
        data = request.json
        print('data is',data)
        amount = data.get("amount", 100)*100
        phone = data.get("phone", "N/A")  # Get phone number from request
        razorpay_client = razorpay.Client(auth=(RAZORPAY_KEY_ID,RAZORPAY_KEY_SECRET))
        razorpay_client.set_app_details({"title" : "Ugadi", "version" : "1.0"})
        print('amount is ',amount)
        order = razorpay_client.order.create({
            "amount": amount,
            "currency": "INR",
            "payment_capture": "1"  # Auto-capture payment
        })
        print('order is ',order)
        new_payment=UserPayment(username=session['username'],order_id=order['id'],amount=amount)
        db.session.add(new_payment)
        db.session.commit()
        # return jsonify(order)
        return jsonify({
            "order_id": order["id"],
            "amount": order["amount"],
            "name": session.get('display_name', 'User'), 
            "email": session['username'],
            "phone":'+91'+ phone  # Send phone number back to frontend
        })
    return redirect(url_for('loginpage'))

# Secure Webhook API
@app.route("/webhook", methods=["POST"])
def razorpay_webhook():
    print('entering webhook..')
    webhook_data = request.get_data(as_text=True)  # Get raw request body
    received_signature = request.headers.get("X-Razorpay-Signature")  # Razorpay Signature
    if not received_signature:
        return jsonify({"error": "Missing signature"}), 400
    # WEBHOOK_SECRET = os.getenv("RAZORPAY_WEBHOOK_SECRET")  # Load from environment
    # Verify webhook signature
    if not WEBHOOK_SECRET:
        raise ValueError("Webhook secret is missing!")
    generated_signature = hmac.new(
        WEBHOOK_SECRET.encode(),
        webhook_data.encode(),
        hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(generated_signature, received_signature):
        return jsonify({"error": "Invalid signature"}), 403  # Unauthorized

    data = request.json
    print('received payment data :',data)
    
    payment_id = data.get("payload", {}).get("payment", {}).get("entity", {}).get("id")
    order_id = data.get("payload", {}).get("payment", {}).get("entity", {}).get("order_id")
    if not payment_id or not order_id:
        return jsonify({"error": "Invalid webhook data"}), 400

    order_payment = orderpaymentid.query.filter_by(order_id=order_id,payment_id=payment_id).first()
    if not order_payment:
        print('pushing to the table for first time')
        new_order_payment = orderpaymentid(order_id=order_id, payment_id=payment_id,payment_status=False)
        db.session.add(new_order_payment)
        db.session.commit()
    
    if data["event"] == "payment.captured":
        # payment_status_db[payment_id] = "success"
        user_payment=orderpaymentid.query.filter_by(order_id=order_id,payment_id=payment_id).first()
        if user_payment:
            user_payment.payment_status = True  # Mark payment as successful
            db.session.commit()
        else:
            print("No matching user found for payment ID:", payment_id)


    return jsonify({"status": "ok"})

@app.route('/check_payment_status')
def check_payment_status():
    payment_id = request.args.get("payment_id")
    order_payment = orderpaymentid.query.filter_by(payment_id=payment_id).first()
    if not order_payment:
        return jsonify({"status": "error", "message": "Invalid payment ID"}), 400
    user_payment=UserPayment.query.filter_by(order_id=order_payment.order_id).first()
    if not user_payment:
        return jsonify({"status": "error", "message": "Invalid order ID"}), 400
    if order_payment.payment_status:
        user = User.query.filter_by(username=user_payment.username).first()
        if user:
            if user.payment_status is False:
                user.payment_status=True
                db.session.commit()
                generate_and_save_qr_code(user.username,user.display_name)
                return jsonify({"status": "success"})
        else:
            return jsonify({"status": "error", "message": "User not found"}), 404
    else:
        return jsonify({"status": "failure"})
    
@app.route('/dashboard')
def dashboard():
    if 'user_id' in session:
        # checking for session time
        if time.time() - session['start_time']>=Max_Session_Time:
            session.clear()  # Clear session data
            flash('Session expired. Please log in again.')
            return redirect(url_for('loginpage'))
        return render_template('welcome.html', username1=session['username'], display_name=session['display_name']) # ----> added display name to the template
    else:
        return redirect(url_for('index'))


# for changing password after login
@app.route('/change_reset_password', methods=['GET', 'POST'])
def change_reset_password():
    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        email = session.get('username')

        if not email:                                    # ---->(To be removed) This should also handle the case when the user intentionally tries to change his/her password without going through the forgot password 
            flash('Session expired. Please try again.')
            return redirect(url_for('login'))

        if new_password != confirm_password:
            flash('Passwords do not match. Please try again.')
            return redirect(url_for('change_reset_password'))

        # Update the user's password in the database
        user = User.query.filter_by(username=email).first()
        if user:
            if check_password_hash(user.password_hash, new_password):
                flash('Same as old Password. Please try again.')
                return redirect(url_for('change_reset_password'))
            session['new_password']=new_password
            return redirect(url_for('change_password'))

    return render_template('dash_change_password.html' , display_name = session['display_name']) # ----> added display name to the template


@app.route('/change_password')
def change_password():
    if 'user_id' in session:
        # Generate a new 6-digit OTP
        email=session['username']
        otp = random.randint(100000, 999999)
        send_otp(email, otp)
        
        # Store OTP and email in session for verification
        session['change_otp'] = otp
        session['otp_time'] = time.time()  # Store current time for timeout check
        # session['display_name'] = session['display_name']                               # ----> stored display name in session
        session['attempts'] = 0

        flash('An OTP has been sent to your email for password reset.')
        return redirect(url_for('change_password_otp'))
    return redirect(url_for('loginpage')) 

@app.route('/change_password_otp', methods=['GET', 'POST'])
def change_password_otp():
    if request.method == 'POST':
        entered_otp = request.form['otp']
        
        # validate format first
        if not entered_otp.isdigit() or len(entered_otp) != 6:
            flash('Invalid OTP format. Please enter a 6‑digit code.','error')
            return redirect(url_for('change_password_otp'))
        
        # Check if OTP has expired (90 seconds timeout)
        if 'otp_time' in session and time.time() - session['otp_time'] > Max_otp_time:
            flash('OTP has expired. Please try again.','error')
            # Clear session data
            session.pop('change_otp', None)
            # session.pop('reset_email', None)
            session.pop('otp_time', None)
            session.pop('attempts', None)
            session.pop('new_password', None)
            return redirect(url_for('change_reset_password'))  

        # Verify the OTP
        if 'change_otp' in session and int(entered_otp) == session['change_otp']:
            # OTP is correct, proceed to reset password
            email = session.get('username')
            new_password=session['new_password']
            user = User.query.filter_by(username=email).first()
            if user:
                user.password_hash = generate_password_hash(new_password, method='pbkdf2:sha256')
                db.session.commit()
                session.pop('change_otp', None)
                session.pop('otp_time', None)
                session.pop('attempts', None)
                session.pop('new_password', None)
                flash('Your password has been reset successfully')
                return redirect(url_for('dashboard'))
            else:
                # user is not there
                session.pop('change_otp', None)
                # session.pop('reset_email', None)
                session.pop('otp_time', None)
                session.pop('attempts', None)
                session.pop('new_password', None)
                session.clear()
                return redirect(url_for('loginpage'))
        else:
            # Increment attempts counter
            session['attempts'] =session.get('attempts', 0) + 1 # ----> after 3 attempts failed, the user is redirected to the forgot password page & when he go back to otp page , and try entering otp once again ,this is showing key error as the session['attempts'] is not present in the session

            # Check if attempts exceeded 3
            if session['attempts'] >= 3:
                flash('Too many failed attempts. Please try again.','error')
                # Clear the session data for security
                session.pop('change_otp', None)
                # session.pop('reset_email', None)
                session.pop('otp_time', None)
                session.pop('attempts', None)
                session.pop('new_password', None)
                return redirect(url_for('change_reset_password'))

            flash(f'Invalid OTP. You have {3-session['attempts']} attempt(s) left.')
            return redirect(url_for('change_password_otp'))
    
    # Calculate time remaining for OTP expiration
    time_left = max(0, int(Max_otp_time - (time.time() - session['otp_time']))) if 'otp_time' in session else 0
    if time_left == 0:
        session.pop('change_otp', None)
        # session.pop('reset_email', None)
        session.pop('otp_time', None)
        session.pop('attempts', None)
        session.pop('new_password', None)
        return redirect(url_for('change_reset_password'))
    
    return render_template('dash_change_otp.html', time_left=time_left)

@app.route('/sports-form')
def sports_form():
    if 'username' in session:
        username = session['username']
        return render_template('sports_form.html', username=username,display_name = session['display_name'])  # ----> added display name to the template
    return redirect(url_for('loginpage'))  # Redirect to login if the user is not logged in

@app.route('/cultural-form')
def cultural_form():
    if 'username' in session:
        username = session['username']
        return render_template('cultural_form.html', username=username,display_name = session['display_name']) # ----> added display name to the template
    return redirect(url_for('loginpage')) # Redirect to login if the user is not logged in

@app.route('/event-qr')
def event_qr():
    if 'username' in session:
        username = session['username']
        qr_filename = f"{username}_event.png"
        qr_path = os.path.join('event_qr_codes/', qr_filename)
        return render_template('eventQr.html', username=username, qr_code_image_path=qr_path,display_name = session['display_name']) # ----> added display name to the template
    return redirect(url_for('loginpage'))  # Redirect to login if the user is not logged in

@app.route('/food-qr')
def food_qr():
    if 'username' in session:
        username = session['username']
        qr_filename = f"{username}_food.png"
        qr_path = os.path.join('food_qr_codes/', qr_filename)
        return render_template('foodQr.html', username=username, qr_code_image_path=qr_path,display_name = session['display_name']) # ----> added display name to the template
    return redirect(url_for('loginpage'))  # Redirect to login if the user is not logged in

# # Function to save the dictionary to a JSON file
# def save_guest_map_to_file(file_path, data):
#     with open(file_path, 'w') as file:
#         json.dump(data, file)

# # Function to load the dictionary from a JSON file
# def load_guest_map_from_file(file_path):
#     try:
#         with open(file_path, 'r') as file:
#             return json.load(file)
#     except FileNotFoundError:
#         return {}  # Return an empty dictionary if the file doesn't exist

@app.route('/guests')
def guest():
    if 'username' in session:
        username = session['username']
        # Count total number of guests invited across all users
        total_guests_count = Guest.query.count()
        # user = User.query.filter_by(username=username).first()  # Fetch the logged-in user
        previous_guests = [{"name": guest.name, "email": guest.email} for guest in Guest.query.filter_by(inviter_email=username).with_entities(Guest.name, Guest.email).all()]
        return render_template('guests.html', username=username,guest_array=previous_guests,
                               total_guests_count=total_guests_count,display_name = session['display_name']) # ----> added display name to the template
    
    return redirect(url_for('loginpage'))  # Redirect to login if the user is not logged in

@app.route('/invite')
def invite():
    if 'username' in session:
        username = session['username']
        # user = User.query.filter_by(username=username).first()
        # previous_guests = Guest.query.filter_by(inviter_email=username).all()
        guest_count=Guest.query.filter_by(inviter_email=username).count()
        print('max guests are',MAX_GUESTS-guest_count)
        return render_template('invite_guest.html',username=username,display_name = session['display_name'],max_guests=MAX_GUESTS-guest_count) # ----> added display name to the template
    return redirect(url_for('loginpage'))

def send_guest_email(guest_name, guest_email, food_qr_path,event_qr_path, invitee_name):
    """
    Sends an email to the guest with their QR code as an attachment.

    Parameters:
    - guest_name (str): Name of the guest.
    - guest_email (str): Email address of the guest.
    - qr_code_path (str): Path to the QR code image.
    - invitee_name (str): Name of the user who invited the guest.
    """
    try:
        # Create the message
        msg = Message(subject="You're Invited! Your Event QR Code", sender='telugusamiti.iitd@gmail.com',recipients=[guest_email])

        # Email body
        msg.body = f"""
        Hello {guest_name},

        You have been invited to the event by {invitee_name}.
        Please find your QR code attached for entry.

        Best regards,
        Event Management Team
        """

        # Attach the Event QR code image
        with open(event_qr_path, "rb") as qr_file:
            msg.attach(
                filename="event.png",
                content_type="image/png",
                data=qr_file.read()
            )
        
        # Attach the Food QR code image
        with open(food_qr_path, "rb") as qr_food:
            msg.attach(
                filename="food.png",
                content_type="image/png",
                data=qr_food.read()
            )

        # Send the email
        mail.send(msg)
        print(f"Email sent successfully to {guest_email}")
    except Exception as e:
        print(f"Error while sending email: {str(e)}")

def guest_qr_codes(user_email,guest_email,guest_name):
    """Generates a QR code with the user's email and saves it to a folder."""
    # Create the QR data (you can customize what you want in the QR code)
    # qr_data = f"Guest: {guest_name}\nEmail: {guest_email}\nInvited by: {user_email}"
    qr_data = {
    "NAME": guest_name,
    "EMAIL": guest_email,
    "Invited by":user_email,
    "PURPOSE": "EVENT"
    }
    fernet = Fernet(key)
    # Serialize the data to JSON string and encode to bytes
    qr_data_bytes = json.dumps(qr_data).encode('utf-8')
    event_qr_data = fernet.encrypt(qr_data_bytes)
    
    # Modify qr_data for food
    qr_data['PURPOSE'] = "FOOD"
    food_qr_data = fernet.encrypt(json.dumps(qr_data).encode('utf-8'))
    
    # Generate the QR code
    event_qr= qrcode.make(event_qr_data)
    food_qr = qrcode.make(food_qr_data)

    actual_path=QR_GUEST_FOLDER+f"/{user_email}"
    if not os.path.exists(actual_path):
        os.makedirs(actual_path)
    new_path=actual_path+f"/{guest_name}_{guest_email}"
    os.makedirs(new_path)
    event_qr_path = os.path.join(new_path, 'event_qr.png')
    food_qr_path = os.path.join(new_path, 'food_qr.png')
    
    # Save the QR code to the file
    food_qr.save(food_qr_path)
    event_qr.save(event_qr_path)
    # send_guest_email(guest_name, guest_email, food_qr_path,event_qr_path, user_email)
    
    # have to create a guest table in the database
    new_guest = Guest_Scan(name = guest_name,email=guest_email,invited_email=user_email,food_scan=False,event_scan=False) # ----> added display name to the new user
    db.session.add(new_guest)
    db.session.commit()
    
    return None

@app.route('/invite-guest', methods=['GET', 'POST'])
def invite_guest():
    if 'username' not in session:
        return redirect(url_for('loginpage'))  

    username = session['username']
    # user = User.query.filter_by(username=username).first()  # Fetch the logged-in user
    previous_guests = {guest.name.lower() for guest in db.session.query(Guest.name).filter_by(inviter_email=username).all()}

    if request.method == 'POST':
        guest_count = request.form.get('guest_count',1)
        print("guest count is ",guest_count)
        if guest_count:
            guest_name = request.form.get("guest_name_1")
            guest_email = request.form.get("guest_email_1")
            guest_count = int(guest_count)
            new_guests=[]
                
            if not guest_name or not guest_email:
                return render_template('invite_guest.html', username=username, display_name=session['display_name'], 
                                    max_guests=MAX_GUESTS - len(previous_guests), error="Guest name and email cannot be empty!")

            guest_name_lower = guest_name.lower()        
                   
            if guest_name_lower in previous_guests:
                # names should not match with previous names
                return render_template('invite_guest.html', username=username, display_name=session['display_name'],
                                        max_guests=MAX_GUESTS-len(previous_guests),error=f"Guest '{guest_name}' has already been invited!")
                
            # # ✅ Check if the email ends with "iitd.ac.in"
            # if not guest_email.lower().endswith('iitd.ac.in'):
            #     return render_template('invite_guest.html', 
            #                            username=username, 
            #                            display_name=session['display_name'], 
            #                            max_guests=MAX_GUESTS - len(previous_guests), 
            #                            error="Only IITD emails are allowed!")
                        
            # # Clear guest details from previous session 
            # session.pop("guest_details", None)
            
            # storing guest data in the session
            session['guest_details'] = {
                "name": guest_name,
                "email": guest_email,
                "count": guest_count
            }
            
            # Set payment amount based on guest count
            amount = int(guest_count) * 350
            return render_template('guest_payment.html', amount=amount)
            
        return redirect('/guests')
    
    return render_template('invite_guest.html', username=username, display_name=session['display_name'],max_guests=MAX_GUESTS-len(previous_guests))

@app.route('/guest_create_order', methods=['POST'])
def guest_create_order():
    # data = request.json
    if 'username' in session:
        data = request.json
        print('data is',data)
        amount = data.get("amount", 350)*100
        phone = data.get("phone", "N/A")  # Get phone number from request
        razorpay_client = razorpay.Client(auth=(RAZORPAY_KEY_ID,RAZORPAY_KEY_SECRET))
        razorpay_client.set_app_details({"title" : "Ugadi", "version" : "1.0"})
        print('amount is ',amount)
        order = razorpay_client.order.create({
            "amount": amount,
            "currency": "INR",
            "payment_capture": "1"  # Auto-capture payment
        })
        print('order is ',order)
        new_payment=UserPayment(username=session['username'],order_id=order['id'],amount=amount)
        db.session.add(new_payment)
        db.session.commit()
        # return jsonify(order)
        return jsonify({
            "order_id": order["id"],
            "amount": order["amount"],
            "name": session.get('display_name', 'User'), 
            "email": session['username'],
            "phone":'+91'+ phone  # Send phone number back to frontend
        })
    return redirect(url_for('loginpage'))

@app.route('/guest_payment_status')
def guest_payment_status():
    payment_id = request.args.get("payment_id")
    order_payment = orderpaymentid.query.filter_by(payment_id=payment_id).first()
    if not order_payment:
        return jsonify({"status": "error", "message": "Invalid payment ID"}), 400
    user_payment=UserPayment.query.filter_by(order_id=order_payment.order_id).first()
    if not user_payment:
        return jsonify({"status": "error", "message": "Invalid order ID"}), 400
    print(user_payment)
    if order_payment.payment_status:
        # Retrieve guest details from session
        print('entering into the inseriton into database')
        guest_details = session.get("guest_details")
        print(guest_details)
        if guest_details:
            # Check if guest already exists to avoid duplicate insertion
            existing_guest = Guest.query.filter_by(name=guest_details["name"],email=guest_details["email"],inviter_email=session["username"]).first()
            if not existing_guest:
                new_guest=Guest(name=guest_details["name"], email=guest_details["email"], inviter_email=session["username"])
                db.session.add(new_guest)
                db.session.commit()
                
                guest_qr_codes(session["username"],guest_details["email"],guest_details["name"])
                # Clear guest details from session after successful entry
                session.pop("guest_details", None)        
                return jsonify({"status": "success"})
            else:
                session.pop("guest_details", None) 
                return jsonify({"status": "success", "message": "Guest already added"})
        
        return jsonify({"status": "failure"})
    else:
        return jsonify({"status": "failure"})

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('display_name', None)   # ----> removed display name from the session
    session.clear()
    return redirect(url_for('ugadi'))

def scan_qr(qr_code_data):
    fernet = Fernet(key)
    try:
        # Decrypt the QR code data (which is in bytes) back to the original bytes
        temp_data = fernet.decrypt(qr_code_data)
        decrypted_data=json.loads(temp_data.decode('utf-8'))
        purpose=decrypted_data['PURPOSE']
        email=decrypted_data['EMAIL']
        
        if "Invited by" in decrypted_data:
            # he is guest
            invited_user=decrypted_data['Invited by']
            name=decrypted_data['NAME']
            # guest = Guest_Scan.query.filter_by(email=email).first()
            guest = Guest_Scan.query.filter_by(email=email, name=name, invited_email=invited_user).first()
            if guest:
                # think to add a key to indicate he is a guest
                if purpose=='EVENT':
                    if not guest.event_scan:
                        guest.event_scan=True
                        db.session.commit()
                        decrypted_data['STATUS']='VALID QR'
                    else:
                        print('already exists')
                        decrypted_data['STATUS']='QR EXPIRED'
                elif purpose=='FOOD':
                    if not guest.food_scan:
                        guest.food_scan=True
                        db.session.commit()
                        decrypted_data['STATUS']='VALID QR'
                    else:
                        print('already exists')
                        decrypted_data['STATUS']='QR EXPIRED'
                return decrypted_data
        else:
            user = Scan.query.filter_by(email=email).first()
            if user:
                if purpose=='EVENT':
                    if not user.event_scan:
                        user.event_scan=True
                        db.session.commit()
                        decrypted_data['STATUS']='VALID QR'
                    else:
                        print('already exists')
                        decrypted_data['STATUS']='QR EXPIRED'
                elif purpose=='FOOD':
                    if not user.food_scan:
                        user.food_scan=True
                        db.session.commit()
                        decrypted_data['STATUS']='VALID QR'
                    else:
                        print('already exists')
                        decrypted_data['STATUS']='QR EXPIRED'
                return decrypted_data
    except Exception as e:
        return {"error": str('outside QR CODE')}

@app.route('/scan',methods=['POST'])
def scan():
    # print('enterd')
    scanned_data = request.json.get('scanned_data')
    print("Scanned data:", scanned_data)
    decr=scan_qr(scanned_data)
    print(decr)
    # return render_template('finaldata.html',data=decr)
    return jsonify({'processed_data': decr})

ADMIN_USERNAME = "admin@iitdtelugusamiti"
ADMIN_PASSWORD_HASH = generate_password_hash("admin@tsiitd2025")

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if 'admin_logged_in' in session:
        return redirect(url_for('admin_dashboard'))  # Redirect if already logged in

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if username == ADMIN_USERNAME and check_password_hash(ADMIN_PASSWORD_HASH, password):
            session['admin_logged_in'] = True
            flash("Login successful!", "success")
            return redirect('dashboard')
        else:
            flash("Invalid username or password!", "danger")
    return render_template('admin_login.html')

@app.route('/admin/registered_users')
def admin_user():
    if 'admin_logged_in' not in session:
        flash("Unauthorized access! Please log in first.", "danger")
        return redirect(url_for('admin_login'))
    
    users = User.query.all()  # Fetch all registered users from the database
    return render_template("admin_user.html", users=users)

@app.route("/admin/paid_users")
def paid_users():
    if 'admin_logged_in' not in session:
        flash("Unauthorized access! Please log in first.", "danger")
        return redirect(url_for('admin_login'))
    users = User.query.filter_by(payment_status=True).all()  # Fetch only paid users
    return render_template("admin_paid_users.html", users=users)

@app.route("/admin/unpaid_users")
def unpaid_users():
    if 'admin_logged_in' not in session:
        flash("Unauthorized access! Please log in first.", "danger")
        return redirect(url_for('admin_login'))
    users = User.query.filter_by(payment_status=False).all()  # Fetch only paid users
    return render_template("admin_unpaid_users.html", users=users)

def delete_qr_and_scan_entry(user_email):
    """Deletes the user's QR codes and removes their scan entry from the database."""
    
    # Define file paths for the QR codes
    qr_filename_event = f"{user_email}_event.png"
    qr_filename_food=f"{user_email}_food.png"
    event_qr_path = os.path.join(QR_EVENT_FOLDER, qr_filename_event)
    food_qr_path = os.path.join(QR_FOOD_FOLDER, qr_filename_food)
    
    # Delete QR code files if they exist
    for path in [event_qr_path, food_qr_path]:
        if os.path.exists(path):
            os.remove(path)
            print(f"Deleted: {path}")  # Debugging message

    # Remove entry from Scan table
    user_scan_entry = Scan.query.filter_by(email=user_email).first()
    
    if user_scan_entry:
        db.session.delete(user_scan_entry)
        db.session.commit()
        print(f"Deleted scan entry for {user_email}")
        return True  # Successfully deleted entry
    else:
        print(f"No scan entry found for {user_email}")
        return False  # No entry found

@app.route("/admin/update_unpaid/<int:user_id>", methods=["POST"])
def update_unpaid(user_id):
    if 'admin_logged_in' not in session:
        flash("Unauthorized access! Please log in first.", "danger")
        return redirect(url_for('admin_login'))
    
    data = request.get_json()
    password = data.get("password")
    
    if not password or not check_password_hash(ADMIN_PASSWORD_HASH, password):
        return jsonify({"success": False, "message": "Invalid password!"}), 401
    
    user = User.query.filter_by(id=user_id).first()
    if user:
        user.payment_status = False  # Update payment status to True (Paid)
        db.session.commit()
        
         # Call function to delete QR codes and scan entry
        delete_qr_and_scan_entry(user.username)
        
        return jsonify({"success": True, "message": "Payment status updated."})
    return jsonify({"success": False, "message": "User not found."})

@app.route("/admin/update_payment/<int:user_id>", methods=["POST"])
def update_payment(user_id):
    if 'admin_logged_in' not in session:
        flash("Unauthorized access! Please log in first.", "danger")
        return redirect(url_for('admin_login'))
    
    data = request.get_json()
    password = data.get("password")
    # print('password is',password)
    
    if not password or not check_password_hash(ADMIN_PASSWORD_HASH, password):
        return jsonify({"success": False, "message": "Invalid password!"}), 401
    
    user = User.query.filter_by(id=user_id).first()
    if user:
        generate_and_save_qr_code(user.username,user.display_name)
        user.payment_status = True  # Update payment status to True (Paid)
        db.session.commit()
        return jsonify({"success": True, "message": "Payment status updated."})
    return jsonify({"success": False, "message": "User not found."})

@app.route('/admin/scanning')
def admin_scan():
    if 'admin_logged_in' not in session:
        flash("Unauthorized access! Please log in first.", "danger")
        return redirect(url_for('admin_login'))
    return render_template('scannedpage.html')

@app.route('/admin/dashboard')
def admin_dashboard():
    if 'admin_logged_in' not in session:
        flash("Unauthorized access! Please log in first.", "danger")
        return redirect(url_for('admin_login'))
    return render_template('admin_dashboard.html')

# Load data from JSON file
def load_sports_data():
    json_path=os.path.join(os.path.dirname(__file__), "static", "json_files","ugadi", "sports_schedule.json")
    with open(json_path, "r") as file:
        return json.load(file)

# Save data to JSON file
def save_sports_data(data):
    json_path=os.path.join(os.path.dirname(__file__), "static", "json_files","ugadi", "sports_schedule.json")
    with open(json_path, "w") as file:
        json.dump(data, file, indent=2)

# Route to display sports activities
@app.route("/admin/sport_activity")
def admin_sports():
    data = load_sports_data()
    
    return render_template("admin_sports.html", sports=data["sports"])

# Route to add a new match
@app.route("/admin/add_match", methods=["POST"])
def add_match():
    data = load_sports_data()
    
    sport_name = request.form.get("sport")
    match_info = {
        "match": request.form.get("match"),
        "stage": request.form.get("stage"),
        "result": request.form.get("result")
    }
    print(sport_name)
    for sport in data["sports"]:
        if sport["sport"] == sport_name:
            sport["matches"].append(match_info)
            save_sports_data(data)
            break
    else:
        # If the sport doesn't exist, create a new entry
        data["sports"].append({
            "sport": sport_name,
            "matches": [match_info],
            "winner": "TBD",
            "runner_up": "TBD"
        })
        save_sports_data(data)
        
    # print("Updated Data Before Saving:", data)
    # save_sports_data(data)
    # print("Updated Data After Saving:", load_sports_data())  # Verify if it actually saved

            
    return redirect(url_for("admin_sports"))

# Route to update match details
@app.route("/admin/update_match", methods=["POST"])
def update_match():
    data = load_sports_data()

    sport_name = request.form.get("sport")
    old_match = request.form.get("old_match")
    new_match = request.form.get("match")
    new_stage = request.form.get("stage")
    new_result = request.form.get("result")
    print(sport_name)
    for sport in data["sports"]:
        if sport["sport"] == sport_name:
            for match in sport["matches"]:
                if match["match"] == old_match:
                    match["match"] = new_match
                    match["stage"] = new_stage
                    match["result"] = new_result
                    save_sports_data(data)
                    break

    return redirect(url_for("admin_sports"))

@app.route("/admin/remove_match", methods=["POST"])
def remove_match():
    data = load_sports_data()
    
    sport_name = request.form.get("sport")
    match_to_remove = request.form.get("match")
    
    for sport in data["sports"]:
        if sport["sport"] == sport_name:
            sport["matches"] = [match for match in sport.get("matches", []) if match["match"] != match_to_remove]
            
            # If no matches are left, remove the entire sport
            if not sport["matches"]:
                data["sports"].remove(sport)
            save_sports_data(data)
            break
    
    return redirect(url_for("admin_sports"))

@app.route('/admin/guests')
def admin_guests():
    if 'admin_logged_in' not in session:
        flash("Unauthorized access! Please log in first.", "danger")
        return redirect(url_for('admin_login'))

    guests = Guest.query.all()  # Get all guest data
    return render_template('admin_guests.html', guests=guests)

@app.route('/admin/admin_add_guest', methods=['POST'])
def admin_add_guest():
    if 'admin_logged_in' not in session:
        flash("Unauthorized access! Please log in first.", "danger")
        return redirect(url_for('admin_login'))
    
    data = request.get_json()
    password=data.get('password')
    
    # Replace 'your_admin_password' with the actual admin password
    if password != 'admin@tsiitd2025':
        return jsonify({"success": False, "error": "Incorrect password!"})
    
    guest_name = data.get('guest_name')
    guest_email = data.get('guest_email')
    inviter_email = data.get('inviter_email')
    
    if not guest_name or not guest_email or not inviter_email:
        return jsonify({"success": False, "error": "All fields are required!"})
    
    # Check if guest already exists
    existing_guest = Guest.query.filter_by(inviter_email=inviter_email).all()
    for previous_guest in existing_guest:
        if guest_name==previous_guest.name:
            return jsonify({"success": False, "error": "Guest is already invited"})
    
     # Create and save the new guest
    new_guest = Guest(name=guest_name, email=guest_email, inviter_email=inviter_email)
    db.session.add(new_guest)
    db.session.commit()
    
    guest_qr_codes(inviter_email,guest_email,guest_name)     
    
    # Return success response
    return jsonify({
        "success": True,
        "guest": {
            "id": new_guest.id,
            "name": new_guest.name,
            "email": new_guest.email,
            "inviter_email": new_guest.inviter_email
        }
    })
    

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    flash("Logged out successfully!", "success")
    return redirect(url_for('admin_login'))

@app.route('/gallery')                                      # ----> Added gallery route
def gallery():
    return render_template('gallery.html')

@app.route('/faculty')                                      # ----> Added faculty route
def faculty():
    return render_template('faculty.html')

@app.route('/ugadi')                                      # ----> Added Ugadi route
def ugadi():
    return render_template('ugadi.html')

@app.route('/sports')                                      # ----> Added sports route
def sports():
    return render_template('sports.html')

@app.route('/culturals')                                      # ----> Added cultural route
def culturals():
    return render_template('culturals.html')

@app.route('/food')                                      # ----> Added food route
def food():
    return render_template('food.html')

@app.route('/ugadi_gallery')                                      # ----> Added ugadi_gallery route
def ugadi_gallery():
    return render_template('ugadi_gallery.html')

@app.route('/about_ugadi')                                 # ----> Added about_ugadi route
def about_ugadi():
    return render_template('about_ugadi.html')

@app.route('/telugu_history')                                 # ----> Added telugu_history route
def telugu_history():
    return render_template('telugu_history.html')

@app.route('/staff')                                      # ----> Added staff route
def staff():
    return render_template('staff.html')


@app.route('/home_gallery')                                      # ----> Added home gallery route
def home_gallery():
    return render_template('home_gallery.html')

@app.route('/freshers')                                      # ----> Added freshers route
def freshers():
    return render_template('freshers.html')

if __name__ == '__main__':
    # ngrok_tunnel = ngrok.connect(5000)
    # print('Public URL:', ngrok_tunnel.public_url)
    # app.run()
    app.run(debug=True)
