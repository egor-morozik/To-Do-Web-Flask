from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from models import db, User, Task
from forms import RegistrationForm, LoginForm, TaskForm
from config import Config
from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from models import db, User, Task
from forms import RegistrationForm, LoginForm, TaskForm
from config import Config

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'
jwt = JWTManager(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Аккаунт создан! Теперь можно войти.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            return redirect(url_for('tasks'))
        else:
            flash('Неверный email или пароль', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/tasks', methods=['GET', 'POST'])
@login_required
def tasks():
    form = TaskForm()
    if form.validate_on_submit():
        task = Task(title=form.title.data, user_id=current_user.id)
        db.session.add(task)
        db.session.commit()
        return redirect(url_for('tasks'))
    
    tasks = Task.query.filter_by(user_id=current_user.id).all()
    return render_template('tasks.html', tasks=tasks, form=form)

@app.route('/complete/<int:task_id>')
@login_required
def complete_task(task_id):
    task = Task.query.get_or_404(task_id)
    if task.user_id == current_user.id:
        task.completed = not task.completed
        db.session.commit()
    return redirect(url_for('tasks'))

@app.route('/delete/<int:task_id>')
@login_required
def delete_task(task_id):
    task = Task.query.get_or_404(task_id)
    if task.user_id == current_user.id:
        db.session.delete(task)
        db.session.commit()
    return redirect(url_for('tasks'))
    
# 1. Создание API для получения задач
@app.route('/api/tasks', methods=['GET'])
@jwt_required()
def api_get_tasks():
    current_user_id = get_jwt_identity()  # Получаем текущего пользователя через JWT
    tasks = Task.query.filter_by(user_id=current_user_id).all()
    tasks_list = [{"id": task.id, "title": task.title, "completed": task.completed} for task in tasks]
    return jsonify(tasks_list), 200

# 2. Создание API для добавления задачи
@app.route('/api/tasks', methods=['POST'])
@jwt_required()
def api_add_task():
    data = request.get_json()
    title = data.get('title', '')
    if title:
        current_user_id = get_jwt_identity()  # Получаем текущего пользователя через JWT
        new_task = Task(title=title, user_id=current_user_id)
        db.session.add(new_task)
        db.session.commit()
        return jsonify({"id": new_task.id, "title": new_task.title, "completed": new_task.completed}), 201
    return jsonify({"message": "Title is required"}), 400

# 3. Завершение задачи через API
@app.route('/api/tasks/complete/<int:task_id>', methods=['PUT'])
@jwt_required()
def api_complete_task(task_id):
    current_user_id = get_jwt_identity()
    task = Task.query.get_or_404(task_id)
    
    if task.user_id == current_user_id:
        task.completed = not task.completed
        db.session.commit()
        return jsonify({"message": "Task updated", "completed": task.completed}), 200
    return jsonify({"message": "You can only update your own tasks"}), 403

# 4. Удаление задачи через API
@app.route('/api/tasks/delete/<int:task_id>', methods=['DELETE'])
@jwt_required()
def api_delete_task(task_id):
    current_user_id = get_jwt_identity()
    task = Task.query.get_or_404(task_id)
    
    if task.user_id == current_user_id:
        db.session.delete(task)
        db.session.commit()
        return jsonify({"message": "Task deleted"}), 200
    return jsonify({"message": "You can only delete your own tasks"}), 403

# 5. Получение JWT токена (для API)
@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    email = data.get('email', '')
    password = data.get('password', '')
    
    user = User.query.filter_by(email=email).first()
    if user and bcrypt.check_password_hash(user.password, password):
        access_token = create_access_token(identity=user.id)
        return jsonify(access_token=access_token), 200
    return jsonify({"message": "Invalid credentials"}), 401


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
