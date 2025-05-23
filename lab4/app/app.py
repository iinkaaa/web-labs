from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

app = Flask(__name__)
application = app
app.secret_key = 'key' 
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Для доступа к этой странице необходимо авторизоваться'
login_manager.login_message_category = 'warning'

class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    description = db.Column(db.String(200))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    last_name = db.Column(db.String(50))
    first_name = db.Column(db.String(50), nullable=False)
    middle_name = db.Column(db.String(50))
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'))
    role = db.relationship('Role', backref='users')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    users = User.query.all()
    return render_template('index.html', users=users)

@app.route('/counter')
def counter():
    session['visits'] = session.get('visits', 0) + 1
    return render_template('counter.html', visits=session['visits'])

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = request.form.get('remember') == 'on'
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user, remember=remember)
            flash('Вы успешно вошли!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Неверный логин или пароль', 'danger')
    return render_template('login.html',  title='Авторизация')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Вы вышли из системы', 'info')
    return redirect(url_for('index'))

@app.route('/secret')
@login_required
def secret():
    return render_template('secret.html', title='Секретная страница')

@app.route('/users/create', methods=['GET', 'POST'])
@login_required
def create_user():
    roles = Role.query.all()
    
    if request.method == 'POST':
        # Сохраняем ВСЕ данные формы, кроме пароля
        form_data = {
            'username': request.form.get('username', '').strip(),
            'last_name': request.form.get('last_name', '').strip(),
            'first_name': request.form.get('first_name', '').strip(),
            'middle_name': request.form.get('middle_name', '').strip(),
            'role_id': request.form.get('role_id', '')
        }
        
        password = request.form.get('password', '').strip()
        errors = {}
        
        # Валидация логина
        if not form_data['username']:
            errors['username'] = 'Логин обязателен'
        elif len(form_data['username']) < 5:
            errors['username'] = 'Логин должен быть не менее 5 символов'
        elif not form_data['username'].isalnum():
            errors['username'] = 'Логин должен содержать только латинские буквы и цифры'
        
        # Валидация пароля (сообщение, но данные не сохраняем)
        if not password:
            errors['password'] = 'Пароль обязателен'
        else:
            pass_error = validate_password(password)
            if pass_error:
                errors['password'] = pass_error
        
        # Валидация имени
        if not form_data['first_name']:
            errors['first_name'] = 'Обязательное поле'
        
        if errors:
            # # Показываем ошибки для каждого поля
            # for field, message in errors.items():
            #     flash(f"{field}: {message}", 'danger')
            
            # Возвращаем форму с сохранёнными данными
            return render_template('create_user.html',
                                roles=roles,
                                form_data=form_data,
                                errors=errors)
        
        # Если ошибок нет - создаём пользователя
        try:
            user = User(
                username=form_data['username'],
                password_hash=generate_password_hash(password),
                last_name=form_data['last_name'] or None,
                first_name=form_data['first_name'],
                middle_name=form_data['middle_name'] or None,
                role_id=int(form_data['role_id']) if form_data['role_id'] else None
            )
            db.session.add(user)
            db.session.commit()
            flash('Пользователь успешно создан!', 'success')
            return redirect(url_for('index'))
        
        except Exception as e:
            db.session.rollback()
            flash(f'Ошибка базы данных: {str(e)}', 'danger')
            return render_template('create_user.html',
                                roles=roles,
                                form_data=form_data,
                                errors={})

    # GET-запрос - пустая форма
    return render_template('create_user.html',
                         roles=roles,
                         form_data={},
                         errors={})

@app.route('/users/<int:id>')
def view_user(id):
    user = User.query.get_or_404(id)
    return render_template('view_user.html', user=user)

@app.route('/users/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def edit_user(id):
    user = User.query.get_or_404(id)
    if request.method == 'POST':
        user.last_name = request.form.get('last_name')
        user.first_name = request.form.get('first_name')
        user.middle_name = request.form.get('middle_name')
        user.role_id = request.form.get('role_id')

        if not user.first_name:
            flash('Имя обязательно для заполнения', 'danger')
            return redirect(url_for('edit_user', id=id))

        try:
            db.session.commit()
            flash('Данные пользователя обновлены!', 'success')
            return redirect(url_for('index'))
        except Exception as e:
            db.session.rollback()
            flash(f'Ошибка при обновлении: {str(e)}', 'danger')

    roles = Role.query.all()
    return render_template('edit_user.html', user=user, roles=roles)

@app.route('/users/<int:id>/delete', methods=['POST'])
@login_required
def delete_user(id):
    user = User.query.get_or_404(id)
    try:
        db.session.delete(user)
        db.session.commit()
        flash('Пользователь удалён!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Ошибка при удалении: {str(e)}', 'danger')
    return redirect(url_for('index'))

import re

def validate_password(password):
    if len(password) < 8:
        return "Пароль должен быть не менее 8 символов"
    if not re.search(r'[A-ZА-Я]', password):
        return "Пароль должен содержать хотя бы одну заглавную букву"
    if not re.search(r'[a-zа-я]', password):
        return "Пароль должен содержать хотя бы одну строчную букву"
    if not re.search(r'\d', password):
        return "Пароль должен содержать хотя бы одну цифру"
    if ' ' in password:
        return "Пароль не должен содержать пробелов"
    return None

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        old_password = request.form.get('old_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        if not check_password_hash(current_user.password_hash, old_password):
            flash('Неверный старый пароль', 'danger')
        elif new_password != confirm_password:
            flash('Пароли не совпадают', 'danger')
        else:
            error = validate_password(new_password)
            if error:
                flash(error, 'danger')
            else:
                current_user.password_hash = generate_password_hash(new_password)
                db.session.commit()
                flash('Пароль успешно изменён!', 'success')
                return redirect(url_for('index'))
    return render_template('change_password.html')

if __name__ == '__main__':
    app.run(debug=True)