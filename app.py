from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from werkzeug.utils import secure_filename
from google.cloud import storage
from pytz import timezone

import os
import uuid
from cryptography.fernet import Fernet
import datetime
import random
import string
import tempfile

# Khởi tạo ứng dụng Flask
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///encryption_app.db'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Giới hạn kích thước file 16MB
app.config['ALLOWED_EXTENSIONS'] = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'doc', 'docx', 'xls', 'xlsx'}
app.config.update(
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USERNAME='phamtruogah@gmail.com',  
    MAIL_PASSWORD='nhfz nwqz vaos waac',     
    MAIL_DEFAULT_SENDER='phamtruogah@gmail.com'  
)
# Cấu hình Google Cloud Storage
app.config['GCS_BUCKET'] = 'data-encryption-bucket-2025'  # Thay bằng tên bucket của bạn
app.config['GCS_CREDENTIALS'] = 'service-account-key.json'  # Đường dẫn đến file key JSON

# Khởi tạo các extension
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
mail = Mail(app)

# Khởi tạo Google Cloud Storage client
storage_client = storage.Client.from_service_account_json(app.config['GCS_CREDENTIALS'])
bucket = storage_client.bucket(app.config['GCS_BUCKET'])

# Tạo và quản lý khóa mã hóa
def generate_key():
    return Fernet.generate_key()

def save_key(key, filename='encryption_key.key'):
    with open(filename, 'wb') as key_file:
        key_file.write(key)

def load_key(filename='encryption_key.key'):
    if not os.path.exists(filename):
        key = generate_key()
        save_key(key, filename)
    with open(filename, 'rb') as key_file:
        return key_file.read()

# Khởi tạo khóa mã hóa
encryption_key = load_key()
cipher_suite = Fernet(encryption_key)

# Định nghĩa models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    registered_on = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)
    files = db.relationship('File', backref='owner', lazy=True)
    otps = db.relationship('OTP', backref='user', lazy=True)

    def __repr__(self):
        return f"User('{self.name}', '{self.email}')"

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(120), nullable=False)  # Tên file trên cloud
    original_filename = db.Column(db.String(120), nullable=False)  # Tên gốc của file
    encrypted = db.Column(db.Boolean, default=True)
    upload_date = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"File('{self.original_filename}', '{self.upload_date}')"

class OTP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    otp_code = db.Column(db.String(6), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)

    def __repr__(self):
        return f"OTP('{self.otp_code}', '{self.expires_at}')"

# Hàm tiện ích
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def encrypt_file(file_path):
    with open(file_path, 'rb') as file:
        file_data = file.read()
    encrypted_data = cipher_suite.encrypt(file_data)
    with open(file_path, 'wb') as file:
        file.write(encrypted_data)

def decrypt_file(file_path):
    with open(file_path, 'rb') as file:
        encrypted_data = file.read()
    decrypted_data = cipher_suite.decrypt(encrypted_data)
    with open(file_path, 'wb') as file:
        file.write(decrypted_data)

def generate_otp(length=6):
    characters = string.digits
    return ''.join(random.choice(characters) for _ in range(length))

# Routes
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email đã được sử dụng. Vui lòng chọn email khác.', 'danger')
            return redirect(url_for('register'))
        
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(name=name, email=email, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        
        flash('Tài khoản của bạn đã được tạo! Bạn có thể đăng nhập ngay bây giờ.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            session['user_id'] = user.id
            flash('Đăng nhập thành công!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Đăng nhập thất bại. Vui lòng kiểm tra email và mật khẩu.', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Bạn đã đăng xuất.', 'info')
    return redirect(url_for('home'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Vui lòng đăng nhập để xem trang này.', 'warning')
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    files = File.query.filter_by(user_id=user.id).all()

    vn_tz = timezone('Asia/Ho_Chi_Minh')
    for f in files:
        # Gắn thêm thuộc tính upload_date_vn để hiển thị giờ VN
        f.upload_date_vn = f.upload_date.replace(tzinfo=timezone('UTC')).astimezone(vn_tz)
    
    return render_template('dashboard.html', user=user, files=files)

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if 'user_id' not in session:
        flash('Vui lòng đăng nhập để tải lên tệp.', 'warning')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('Không tìm thấy file.', 'danger')
            return redirect(request.url)
        
        file = request.files['file']
        if file.filename == '':
            flash('Không có file nào được chọn.', 'danger')
            return redirect(request.url)
        
        if file and allowed_file(file.filename):
            original_filename = secure_filename(file.filename)
            filename = str(uuid.uuid4()) + '_' + original_filename
            
            # Tạo file tạm thời để mã hóa
            with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                file.save(temp_file.name)
                encrypt_file(temp_file.name)
                
                # Tải file đã mã hóa lên Google Cloud Storage
                blob = bucket.blob(f"{session['user_id']}/{filename}")
                blob.upload_from_filename(temp_file.name)
            
            # Xóa file tạm
            os.unlink(temp_file.name)
            
            # Lưu thông tin file vào database
            new_file = File(filename=filename, original_filename=original_filename, user_id=session['user_id'])
            db.session.add(new_file)
            db.session.commit()
            
            flash('File đã được tải lên và mã hóa thành công!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Loại file không được phép.', 'danger')
    
    return render_template('upload.html')

@app.route('/download/<int:file_id>')
def download_file(file_id):
    if 'user_id' not in session:
        flash('Vui lòng đăng nhập để tải xuống tệp.', 'warning')
        return redirect(url_for('login'))
    
    file = File.query.get_or_404(file_id)
    if file.user_id != session['user_id']:
        flash('Bạn không có quyền truy cập file này.', 'danger')
        return redirect(url_for('dashboard'))
    
    # Tạo file tạm để tải dữ liệu từ cloud
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        blob = bucket.blob(f"{session['user_id']}/{file.filename}")
        blob.download_to_filename(temp_file.name)
        
        # Giải mã file
        decrypt_file(temp_file.name)
        
        # Gửi file đã giải mã
        response = send_file(temp_file.name, as_attachment=True, download_name=file.original_filename)
        
        # Xóa file tạm sau khi gửi
        @response.call_on_close
        def cleanup():
            if os.path.exists(temp_file.name):
                os.remove(temp_file.name)
        
        return response

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        
        if not user:
            flash('Email không tồn tại.', 'danger')
            return redirect(url_for('forgot_password'))
        
        otp_code = generate_otp()
        expires_at = datetime.datetime.utcnow() + datetime.timedelta(minutes=10)
        
        otp = OTP(user_id=user.id, otp_code=otp_code, expires_at=expires_at)
        db.session.add(otp)
        db.session.commit()
        
        msg = Message('Mã OTP Đặt Lại Mật Khẩu', recipients=[email])
        msg.body = f'Mã OTP của bạn là: {otp_code}. Mã này có hiệu lực trong 10 phút.'
        mail.send(msg)
        
        flash('Mã OTP đã được gửi đến email của bạn.', 'success')
        return redirect(url_for('reset_password', email=email))
    
    return render_template('forgot_password.html')

@app.route('/reset_password/<email>', methods=['GET', 'POST'])
def reset_password(email):
    user = User.query.filter_by(email=email).first()
    if not user:
        flash('Email không hợp lệ.', 'danger')
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        otp_code = request.form.get('otp')
        new_password = request.form.get('password')
        
        otp = OTP.query.filter_by(user_id=user.id, otp_code=otp_code).order_by(OTP.created_at.desc()).first()
        if not otp or otp.expires_at < datetime.datetime.utcnow():
            flash('Mã OTP không hợp lệ hoặc đã hết hạn.', 'danger')
            return redirect(url_for('reset_password', email=email))
        
        hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
        user.password = hashed_password
        db.session.delete(otp)
        db.session.commit()
        
        flash('Mật khẩu đã được đặt lại thành công. Vui lòng đăng nhập.', 'success')
        return redirect(url_for('login'))
    
    return render_template('reset_password.html', email=email)

# Khởi tạo database một lần duy nhất
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)