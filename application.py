import os
import ssl
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

application = Flask(__name__)

application.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'super-secret-key-change-me')

db_url = os.environ.get('DATABASE_URL', 'sqlite:////tmp/app.db')
if db_url.startswith('postgresql://'):
    db_url = db_url.replace('postgresql://', 'postgresql+pg8000://', 1)

application.config['SQLALCHEMY_DATABASE_URI'] = db_url
application.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

if db_url.startswith('postgresql+pg8000'):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    application.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
        'connect_args': {'ssl_context': ctx, 'timeout': 10}
    }

db = SQLAlchemy(application)
login_manager = LoginManager()
login_manager.init_app(application)
login_manager.login_view = 'login'


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


with application.app_context():
    try:
        db.create_all()
    except Exception as e:
        print(f"DB init error: {e}", flush=True)


@application.route('/')
def home():
    return render_template('index.html')


@application.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        user_exists = User.query.filter_by(email=email).first()
        if user_exists:
            flash('Ця електронна пошта вже зареєстрована!', 'danger')
            return redirect(url_for('signup'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, email=email, password_hash=hashed_password)

        db.session.add(new_user)
        db.session.commit()

        flash('Реєстрація успішна! Будь ласка, увійдіть.', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')


@application.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Неправильна пошта або пароль.', 'danger')

    return render_template('login.html')


@application.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', name=current_user.username, email=current_user.email)


@application.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Ви вийшли з системи.', 'info')
    return redirect(url_for('home'))


if __name__ == '__main__':
    application.run(host='0.0.0.0', port=5000)