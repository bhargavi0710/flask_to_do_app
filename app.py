# import os
# from flask import Flask, render_template, redirect, url_for, request, flash
# from flask_wtf import FlaskForm
# from wtforms import StringField, PasswordField, SubmitField, EmailField
# from wtforms.validators import DataRequired, Email, EqualTo, Length
# from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin, current_user
# from flask_bcrypt import Bcrypt
# import firebase_admin
# from firebase_admin import credentials, firestore
# import uuid

# # Initialize Flask
# app = Flask(__name__)
# app.secret_key = 'b7b329c0fbe4f0dbab1b5f7123701ef197e4d3f6d2c391a74a3762fa5a89a19f'  

# # Initialize Firebase Admin SDK
# cred = credentials.Certificate('/etc/secrets/firebase_key.json')

# firebase_admin.initialize_app(cred)
# db = firestore.client()

# # Flask Extensions
# bcrypt = Bcrypt(app)
# login_manager = LoginManager()
# login_manager.init_app(app)
# login_manager.login_view = 'login'


# ### ----- User Class -----
# class User(UserMixin):
#     def __init__(self, id_, username, email, password_hash):
#         self.id = id_
#         self.username = username
#         self.email = email
#         self.password_hash = password_hash


# ### ----- Forms -----
# class RegisterForm(FlaskForm):
#     username = StringField('Username', validators=[DataRequired(), Length(min=3)])
#     email = EmailField('Email', validators=[DataRequired(), Email()])
#     password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
#     confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
#     submit = SubmitField('Register')

# class LoginForm(FlaskForm):
#     username = StringField('Username', validators=[DataRequired()])
#     password = PasswordField('Password', validators=[DataRequired()])
#     submit = SubmitField('Login')


# ### ----- Load User -----
# @login_manager.user_loader
# def load_user(user_id):
#     user_doc = db.collection('users').document(user_id).get()
#     if user_doc.exists:
#         data = user_doc.to_dict()
#         return User(user_id, data['username'], data['email'], data['password'])
#     return None


# ### ----- Routes -----
# @app.route('/')
# @login_required
# def index():
#     tasks_ref = db.collection('tasks').where('user_id', '==', current_user.id)
#     tasks_docs = tasks_ref.stream()
#     tasks = []

#     for doc in tasks_docs:
#         task = doc.to_dict()
#         task['id'] = doc.id
#         tasks.append(task)

#     return render_template('index.html', tasks=tasks)


# @app.route('/register', methods=['GET', 'POST'])
# def register():
#     form = RegisterForm()
#     if form.validate_on_submit():
#         username = form.username.data
#         email = form.email.data
#         password = form.password.data
#         hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

#         # Check if user already exists
#         users_ref = db.collection('users')
#         existing = users_ref.where('username', '==', username).get()
#         if existing:
#             flash('Username already exists.', 'danger')
#             return redirect(url_for('register'))

#         user_id = str(uuid.uuid4())
#         users_ref.document(user_id).set({
#             'username': username,
#             'email': email,
#             'password': hashed_password
#         })

#         flash('Account created! Please log in.', 'success')
#         return redirect(url_for('login'))

#     return render_template('register.html', form=form)


# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     form = LoginForm()
#     if form.validate_on_submit():
#         username = form.username.data
#         password = form.password.data

#         users_ref = db.collection('users')
#         docs = users_ref.where('username', '==', username).get()
#         if docs:
#             doc = docs[0]
#             data = doc.to_dict()
#             if bcrypt.check_password_hash(data['password'], password):
#                 user = User(doc.id, data['username'], data['email'], data['password'])
#                 login_user(user)
#                 flash('Logged in successfully.', 'success')
#                 return redirect(url_for('index'))
#             else:
#                 flash('Incorrect password.', 'danger')
#         else:
#             flash('Username not found.', 'danger')

#     return render_template('login.html', form=form)


# @app.route('/logout')
# @login_required
# def logout():
#     logout_user()
#     flash('You have been logged out.', 'info')
#     return redirect(url_for('login'))


# @app.route('/add', methods=['POST'])
# @login_required
# def add():
#     content = request.form['content']
#     db.collection('tasks').add({
#         'user_id': current_user.id,
#         'content': content,
#         'status': 'Pending'
#     })
#     return redirect(url_for('index'))


# @app.route('/update/<task_id>', methods=['POST'])
# @login_required
# def update(task_id):
#     new_status = request.form['status']
#     task_ref = db.collection('tasks').document(task_id)
#     task = task_ref.get()

#     if task.exists and task.to_dict().get('user_id') == current_user.id:
#         task_ref.update({'status': new_status})

#     return redirect(url_for('index'))


# @app.route('/delete/<task_id>')
# @login_required
# def delete(task_id):
#     task_ref = db.collection('tasks').document(task_id)
#     task = task_ref.get()

#     if task.exists and task.to_dict().get('user_id') == current_user.id:
#         task_ref.delete()

#     return redirect(url_for('index'))


# ### ----- Main Entry -----
# if __name__ == '__main__':
#     app.run(debug=True)


import os
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, EmailField
from wtforms.validators import DataRequired, Email, EqualTo, Length
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin, current_user
from flask_bcrypt import Bcrypt
import firebase_admin
from firebase_admin import credentials, firestore
import uuid
from collections import Counter

# Initialize Flask
app = Flask(__name__)
app.secret_key = 'b7b329c0fbe4f0dbab1b5f7123701ef197e4d3f6d2c391a74a3762fa5a89a19f'  

# Initialize Firebase Admin SDK
cred = credentials.Certificate('/etc/secrets/firebase_key.json')
firebase_admin.initialize_app(cred)
db = firestore.client()

# Flask Extensions
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

### ----- User Class -----
class User(UserMixin):
    def __init__(self, id_, username, email, password_hash):
        self.id = id_
        self.username = username
        self.email = email
        self.password_hash = password_hash

### ----- Forms -----
class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3)])
    email = EmailField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

### ----- Load User -----
@login_manager.user_loader
def load_user(user_id):
    user_doc = db.collection('users').document(user_id).get()
    if user_doc.exists:
        data = user_doc.to_dict()
        return User(user_id, data['username'], data['email'], data['password'])
    return None

### ----- Routes -----
@app.route('/')
@login_required
def index():
    search_query = request.args.get('q', '').lower()
    tasks_ref = db.collection('tasks').where('user_id', '==', current_user.id)
    tasks_docs = tasks_ref.stream()
    
    tasks = []
    for doc in tasks_docs:
        task = doc.to_dict()
        if search_query in task.get('content', '').lower():
            task['id'] = doc.id
            tasks.append(task)

    status_counts = Counter(task['status'] for task in tasks)
    total = len(tasks)
    progress = {
        'Pending': status_counts.get('Pending', 0),
        'Partially Completed': status_counts.get('Partially Completed', 0),
        'Completed': status_counts.get('Completed', 0),
        'Total': total
    }

    return render_template('index.html', tasks=tasks, progress=progress, search_query=search_query)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        users_ref = db.collection('users')
        existing = users_ref.where('username', '==', username).get()
        if existing:
            flash('Username already exists.', 'danger')
            return redirect(url_for('register'))

        user_id = str(uuid.uuid4())
        users_ref.document(user_id).set({
            'username': username,
            'email': email,
            'password': hashed_password
        })

        flash('Account created! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        users_ref = db.collection('users')
        docs = users_ref.where('username', '==', username).get()
        if docs:
            doc = docs[0]
            data = doc.to_dict()
            if bcrypt.check_password_hash(data['password'], password):
                user = User(doc.id, data['username'], data['email'], data['password'])
                login_user(user)
                flash('Logged in successfully.', 'success')
                return redirect(url_for('index'))
            else:
                flash('Incorrect password.', 'danger')
        else:
            flash('Username not found.', 'danger')

    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/add', methods=['POST'])
@login_required
def add():
    content = request.form['content']
    db.collection('tasks').add({
        'user_id': current_user.id,
        'content': content,
        'status': 'Pending'
    })
    return redirect(url_for('index'))

@app.route('/update/<task_id>', methods=['POST'])
@login_required
def update(task_id):
    new_status = request.form['status']
    task_ref = db.collection('tasks').document(task_id)
    task = task_ref.get()

    if task.exists and task.to_dict().get('user_id') == current_user.id:
        task_ref.update({'status': new_status})

    return redirect(url_for('index'))

@app.route('/delete/<task_id>')
@login_required
def delete(task_id):
    task_ref = db.collection('tasks').document(task_id)
    task = task_ref.get()

    if task.exists and task.to_dict().get('user_id') == current_user.id:
        task_ref.delete()

    return redirect(url_for('index'))

### ----- Main Entry -----
if __name__ == '__main__':
    app.run(debug=True)

