from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import string
import random
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "super_secret_key_here"

# ---------- Database Setup ----------
def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS urls (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            long_url TEXT NOT NULL,
            short_code TEXT NOT NULL UNIQUE,
            clicks INTEGER DEFAULT 0,
            user_id INTEGER,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# ---------- Helper ----------
def generate_short_code(length=5):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(length))

# ---------- Routes ----------
@app.route('/')
def root():
    if "user_id" not in session:
        return redirect(url_for('login'))
    return redirect(url_for('home'))

@app.route('/home')
def home():
    if "user_id" not in session:
        return redirect(url_for('login'))
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE email = ?', (email,))
        if c.fetchone():
            flash("Email already registered!", "error")
            conn.close()
            return redirect(url_for('signup'))

        hashed_password = generate_password_hash(password)
        c.execute('INSERT INTO users (email, password) VALUES (?, ?)', (email, hashed_password))
        conn.commit()
        conn.close()

        flash("Signup successful! Please log in.", "success")
        return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if "user_id" in session:
        return redirect(url_for('home'))

    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('SELECT id, password FROM users WHERE email = ?', (email,))
        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user[1], password):
            session['user_id'] = user[0]
            session['email'] = email
            flash("Logged in successfully!", "success")
            return redirect(url_for('home'))
        else:
            flash("Invalid email or password", "error")
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("You’ve been logged out.", "info")
    return redirect(url_for('login'))

@app.route('/shorten', methods=['POST'])
def shorten():
    if "user_id" not in session:
        return redirect(url_for('login'))

    long_url = request.form['long_url']

    if not long_url.startswith("http"):
        return "❌ Invalid URL. Include http:// or https://"

    if request.host in long_url:
        return "⚠️ Cannot shorten URL from this website."

    short_code = generate_short_code()
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('INSERT INTO urls (long_url, short_code, user_id) VALUES (?, ?, ?)',
              (long_url, short_code, session['user_id']))
    conn.commit()
    conn.close()

    short_url = request.host_url.rstrip('/') + '/' + short_code
    return render_template('result.html', short_url=short_url)

@app.route('/<short_code>')
def redirect_url(short_code):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT long_url, clicks FROM urls WHERE short_code = ?', (short_code,))
    row = c.fetchone()

    if row:
        long_url, clicks = row
        c.execute('UPDATE urls SET clicks = ? WHERE short_code = ?', (clicks + 1, short_code))
        conn.commit()
        conn.close()
        return redirect(long_url)
    else:
        conn.close()
        return "❌ Short link not found."

@app.route('/history')
def history():
    if "user_id" not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT id, long_url, short_code, clicks FROM urls WHERE user_id = ?', (user_id,))
    urls = c.fetchall()
    conn.close()
    return render_template('history.html', urls=urls)

@app.route('/delete/<int:url_id>', methods=['POST'])
def delete_url(url_id):
    if "user_id" not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('DELETE FROM urls WHERE id = ? AND user_id = ?', (url_id, user_id))
    conn.commit()
    conn.close()
    return redirect(url_for('history'))

# ---------- Profile ----------
@app.route('/profile')
def profile():
    if "user_id" not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    # User info
    c.execute('SELECT email FROM users WHERE id = ?', (user_id,))
    email = c.fetchone()[0]

    # Stats
    c.execute('SELECT COUNT(*) FROM urls WHERE user_id = ?', (user_id,))
    total_urls = c.fetchone()[0]

    c.execute('SELECT SUM(clicks) FROM urls WHERE user_id = ?', (user_id,))
    total_clicks = c.fetchone()[0] or 0

    # Recent URLs
    c.execute('SELECT long_url, short_code, clicks FROM urls WHERE user_id = ? ORDER BY id DESC LIMIT 5', (user_id,))
    urls = c.fetchall()

    conn.close()
    return render_template('profile.html', email=email, total_urls=total_urls, total_clicks=total_clicks, urls=urls)

# ---------- About Us ----------
@app.route('/about')
def about():
    return render_template('about.html')

# ---------- Run ----------
if __name__ == '__main__':
    app.run(debug=True)
