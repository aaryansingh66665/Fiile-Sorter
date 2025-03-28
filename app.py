import os
import mimetypes
from flask import Flask, render_template, request, redirect, url_for, send_from_directory, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'jpg', 'jpeg', 'png', 'gif', 'bmp', 'pdf', 'doc', 'docx',
                                    'xls', 'xlsx', 'ppt', 'pptx', 'mp4', 'avi', 'mov', 'wmv',
                                    'mp3', 'wav', 'ogg', 'zip', 'rar', '7z', 'tar', 'gz'}
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB file size limit

# Database & Authentication Setup
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# User Model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def allowed_file(filename):
    """Check if the file has an allowed extension."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/')
def index():
    return render_template('index.html')

# ---- User Authentication Routes ----
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')

        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return redirect(url_for('register'))

        new_user = User(username=username, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created! You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials', 'danger')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', username=current_user.username)

# ---- File Management Routes ----
@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        flash('No file uploaded', 'danger')
        return redirect(url_for('dashboard'))

    file = request.files['file']
    if file.filename == '':
        flash('No selected file', 'warning')
        return redirect(url_for('dashboard'))

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        user_folder = os.path.join(app.config['UPLOAD_FOLDER'], current_user.username)
        os.makedirs(user_folder, exist_ok=True)

        file_path = os.path.join(user_folder, filename)

        # Ensure the file does not already exist
        if os.path.exists(file_path):
            flash('File already exists!', 'warning')
            return redirect(url_for('file_access'))

        file.save(file_path)
        flash('File uploaded successfully!', 'success')
    else:
        flash('Invalid file type!', 'danger')

    return redirect(url_for('file_access'))

@app.route('/file_access')
@login_required
def file_access():
    """Display the user's uploaded files."""
    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], current_user.username)

    # Ensure the user folder exists
    os.makedirs(user_folder, exist_ok=True)

    files = os.listdir(user_folder)

    return render_template('file_access.html', files=files)

@app.route('/download/<filename>')
@login_required
def download_file(filename):
    """Allow users to download their files."""
    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], current_user.username)
    
    file_path = os.path.join(user_folder, filename)
    if not os.path.exists(file_path):
        flash('File not found', 'danger')
        return redirect(url_for('file_access'))

    return send_from_directory(user_folder, filename, as_attachment=True)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
