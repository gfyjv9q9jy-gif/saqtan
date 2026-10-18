import os
from flask import Flask, render_template, redirect, url_for, request, flash, abort, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.utils import secure_filename
from fpdf import FPDF
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'saqtan_ultimate_secure_key_2026'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///saqtan_pro.db'
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024
ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg'}

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(50), default='user')
    policies = db.relationship('Policy', backref='owner', lazy=True)

class Policy(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    insurance_type = db.Column(db.String(100), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(50), default='Қаралуда')
    payment_status = db.Column(db.String(50), default='Төленбеді')
    document_path = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_email = db.Column(db.String(150), nullable=False)
    action = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def validate_file_magic_bytes(file_stream):
    header = file_stream.read(512)
    file_stream.seek(0)
    if header.startswith(b'%PDF') or header.startswith(b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A') or header.startswith(b'\xFF\xD8\xFF'):
        return True
    return False

def log_action(email, action):
    log = AuditLog(user_email=email, action=action)
    db.session.add(log)
    db.session.commit()

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        
        if user and bcrypt.check_password_hash(user.password_hash, password):
            login_user(user)
            log_action(user.email, "Жүйеге сәтті кірді")
            return redirect(url_for('dashboard'))
        flash('Қате email немесе құпия сөз!', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        full_name = request.form.get('full_name')
        email = request.form.get('email')
        password = request.form.get('password')
        
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user_count = User.query.count()
        assigned_role = 'admin' if user_count == 0 else 'user'
        
        new_user = User(full_name=full_name, email=email, password_hash=hashed_password, role=assigned_role)
        db.session.add(new_user)
        db.session.commit()
        
        log_action(email, f"Жаңа аккаунт тіркелді (Рөлі: {assigned_role})")
        flash('Тіркелу сәтті өтті!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/dashboard')
@login_required
def dashboard():
    users = []
    audit_logs = []
    selected_type = request.args.get('type', 'Автострахование (КАСКО)')
    
    if current_user.role == 'admin':
        policies = Policy.query.all()
        users = User.query.all()
        audit_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(15).all()
    elif current_user.role == 'manager':
        policies = Policy.query.all()
    else:
        policies = Policy.query.filter_by(user_id=current_user.id).all()
        
    return render_template('dashboard.html', policies=policies, users=users, audit_logs=audit_logs, selected_type=selected_type)

@app.route('/create_policy', methods=['POST'])
@login_required
def create_policy():
    if current_user.role != 'user':
        flash('Тек клиенттер ғана өтінім бере алады.', 'warning')
        return redirect(url_for('dashboard'))
        
    insurance_type = request.form.get('insurance_type')
    amount = request.form.get('amount')
    file = request.files.get('document')
    
    filename = None
    if file and file.filename != '':
        if allowed_file(file.filename) and validate_file_magic_bytes(file.stream):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        else:
            flash('Қауіпсіздік қатесі: Файл форматы жарамсыз немесе зақымдалған!', 'danger')
            return redirect(url_for('dashboard'))
    
    new_policy = Policy(
        user_id=current_user.id,
        insurance_type=insurance_type,
        amount=float(amount),
        document_path=filename
    )
    db.session.add(new_policy)
    db.session.commit()
    
    log_action(current_user.email, f"Жаңа сақтандыру өтінімі берілді: {insurance_type} ({amount} ₸)")
    flash('Сақтандыру өтінімі сәтті жіберілді!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/payment_gateway/<int:policy_id>', methods=['GET', 'POST'])
@login_required
def payment_gateway(policy_id):
    policy = Policy.query.get_or_404(policy_id)
    if request.method == 'POST':
        policy.payment_status = 'Төленді'
        db.session.commit()
        log_action(current_user.email, f"#{policy.id} полисі үшін онлайн төлем жасалды")
        return render_template('payment_success.html', policy=policy)
    return render_template('payment_gateway.html', policy=policy)

@app.route('/download_certificate/<int:policy_id>')
@login_required
def download_certificate(policy_id):
    policy = Policy.query.get_or_404(policy_id)
    
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(200, 10, txt="SAQTAN INSURANCE CORPORATION", ln=1, align="C")
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="Official Electronic Insurance Certificate", ln=1, align="C")
    pdf.ln(10)
    
    pdf.cell(200, 10, txt=f"Policy ID: #{policy.id}", ln=1)
    pdf.cell(200, 10, txt=f"Client ID: {policy.user_id}", ln=1)
    pdf.cell(200, 10, txt=f"Coverage Amount: {policy.amount} KZT", ln=1)
    pdf.cell(200, 10, txt=f"Status: Approved", ln=1)
    pdf.cell(200, 10, txt=f"Payment Status: Paid", ln=1)
    pdf.cell(200, 10, txt=f"Date Issued: {policy.created_at.strftime('%Y-%m-%d %H:%M')}", ln=1)
    
    pdf.ln(20)
    pdf.set_font("Arial", 'I', 10)
    pdf.cell(200, 10, txt="This document is verified and generated securely by Saqtan Insurance System.", ln=1, align="C")
    
    pdf_filename = f"policy_{policy.id}.pdf"
    pdf_path = os.path.join(app.config['UPLOAD_FOLDER'], pdf_filename)
    pdf.output(pdf_path)
    
    log_action(current_user.email, f"#{policy.id} полисінің PDF сертификаты жүктелді")
    return send_from_directory(app.config['UPLOAD_FOLDER'], pdf_filename, as_attachment=True)

@app.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/calculator', methods=['GET', 'POST'])
@login_required
def calculator():
    result = None
    if request.method == 'POST':
        car_price = float(request.form.get('car_price', 0))
        car_year = int(request.form.get('car_year', 2020))
        current_year = 2026
        age = max(0, current_year - car_year)
        depreciation = min(age * 5, 50)
        result = round(car_price * (1 - depreciation / 100), 2)
    return render_template('calculator.html', result=result)

@app.route('/check_policy', methods=['GET', 'POST'])
@login_required
def check_policy():
    policy = None
    not_found = False
    if request.method == 'POST':
        policy_id = request.form.get('policy_id')
        policy = Policy.query.get(policy_id)
        if not policy:
            not_found = True
    return render_template('check_policy.html', policy=policy, not_found=not_found)

@app.route('/update_policy/<int:policy_id>', methods=['POST'])
@login_required
def update_policy(policy_id):
    if current_user.role not in ['admin', 'manager']:
        abort(403)
    policy = Policy.query.get_or_404(policy_id)
    new_status = request.form.get('status')
    if new_status in ['Қаралуда', 'Мақұлданды', 'Қабылданбады']:
        policy.status = new_status
        db.session.commit()
        log_action(current_user.email, f"#{policy.id} өтініш статусы өзгертілді: {new_status}")
        flash('Өтінім статусы өзгертілді!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/update_role/<int:user_id>', methods=['POST'])
@login_required
def update_role(user_id):
    if current_user.role != 'admin':
        abort(403)
    user = User.query.get_or_404(user_id)
    new_role = request.form.get('role')
    if new_role in ['user', 'manager', 'admin']:
        user.role = new_role
        db.session.commit()
        log_action(current_user.email, f"Қолданушының ({user.email}) рөлі ауыстырылды: {new_role}")
        flash('Қолданушы рөлі өзгертілді.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/logout')
@login_required
def logout():
    log_action(current_user.email, "Жүйеден шықты")
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)