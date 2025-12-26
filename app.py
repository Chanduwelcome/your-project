from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from functools import wraps
import os

app = Flask(__name__)
app.secret_key = "your-secret-key-change-this-in-production"


# ------------------------------
# DATABASE INITIALIZATION
# ------------------------------
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  email TEXT UNIQUE NOT NULL,
                  password TEXT NOT NULL)''')
    conn.commit()
    conn.close()

init_db()


# ------------------------------
# LOGIN REQUIRED
# ------------------------------
def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrap


# ------------------------------
# DATASET TREE (TERMINAL STYLE)
# ------------------------------
def get_dataset_tree():
    base_dir = os.getcwd()
    dataset_dir = os.path.join(base_dir, "dataset")

    if not os.path.exists(dataset_dir):
        return "dataset folder not found"

    output = "/app/dataset:\n"

    for item in sorted(os.listdir(dataset_dir)):
        output += f"{item}\n"

    return output


# ------------------------------
# HOME PAGE
# ------------------------------
@app.route('/')
def index():
    return render_template('index.html')


# ------------------------------
# LOGIN PAGE
# ------------------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':

        email = request.form.get('email')
        password = request.form.get('password')

        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE email = ?', (email,))
        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user[3], password):
            session['user_id'] = user[0]
            session['username'] = user[1]
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid email or password", "error")

    return render_template('login.html')


# ------------------------------
# REGISTER PAGE
# ------------------------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':

        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm = request.form.get('confirm_password')

        if password != confirm:
            flash("Passwords do not match", "error")
            return render_template('register.html')

        hashed = generate_password_hash(password)

        try:
            conn = sqlite3.connect('users.db')
            c = conn.cursor()
            c.execute(
                "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                (username, email, hashed)
            )
            conn.commit()
            conn.close()
            flash("Registration successful!", "success")
            return redirect(url_for('login'))

        except sqlite3.IntegrityError:
            flash("Username or email already exists", "error")

    return render_template('register.html')


# ------------------------------
# DASHBOARD (PRINT LIKE TERMINAL)
# ------------------------------
@app.route('/dashboard')
@login_required
def dashboard():

    pod_files = get_dataset_tree()

    return render_template(
        "dashboard.html",
        username=session.get("username"),
        pod_files=pod_files
    )


# ------------------------------
# LOGOUT
# ------------------------------
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


# ------------------------------
# RUN APP (LOCAL ONLY)
# ------------------------------
if __name__ == "__main__":
    app.run(debug=True)
