import os
import sqlite3
from flask import Flask, g, request, render_template, flash, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

# Define the path to the database file
DATABASE = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'exam.db')

########################################
# FLASK APPLICATION SETUP
########################################
app = Flask(__name__)
app.secret_key = "a1d76c1f45b9d653bcfe0c0782c928b6aa54e24cc1685e3b839de0f57282b88f"
app.config['DATABASE'] = DATABASE

########################################
# DATABASE CONNECTION & INITIALIZATION
########################################
def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Create tables if they don't exist."""
    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    # Users table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS kullanicilar (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ad TEXT,
        email TEXT UNIQUE,
        sifre TEXT,
        en_yuksek_skor INTEGER DEFAULT 0,
        deneme_sayisi INTEGER DEFAULT 0
    )
    """)

    # Questions table (each question includes a dogru_cevap and secenekler fields)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS sorular (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        soru_metni TEXT NOT NULL,
        dogru_cevap TEXT NOT NULL,
        secenekler TEXT,
        konu TEXT NOT NULL
    )
    """)

    # Answers table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS cevaplar (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        kullanici_id INTEGER,
        soru_id INTEGER,
        verilen_cevap TEXT,
        dogru_mu INTEGER,
        FOREIGN KEY (kullanici_id) REFERENCES kullanicilar(id),
        FOREIGN KEY (soru_id) REFERENCES sorular(id)
    )
    """)

    # Exam results table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS sinavsonuclari (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        kullanici_id INTEGER,
        skor INTEGER,
        tarih TEXT,
        FOREIGN KEY (kullanici_id) REFERENCES kullanicilar(id)
    )
    """)

    connection.commit()
    connection.close()

from werkzeug.security import generate_password_hash, check_password_hash
h = generate_password_hash("123")
print("Generated hash:", h)
print("Check password:", check_password_hash(h, "123"))
print("repr(h)::::::::::::::::::::", repr(h))


########################################
# ROUTES
########################################

@app.route('/')
def index():
    """Redirect to login if not logged in, otherwise to exam selection."""
    if 'user_id' in session:
        for i in session:
            print(f"session[i]: {session[i]}")
        return redirect(url_for('select_exam'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])   
def login():
    """User login."""
    
    if request.method == 'POST':
        email = request.form['email'].strip()
        sifre = request.form['sifre'].strip()
        conn = get_db_connection()
        user = conn.execute("SELECT * FROM kullanicilar WHERE email = ?", (email,)).fetchone()
        conn.close()

        # Debug: print the retrieved user record
        print("DEBUG: Retrieved user:", user)
        if user:
            print("DEBUG: Stored password hash:", repr(user['sifre']))
            # Test if the password matches:
            match = check_password_hash(user['sifre'], sifre)
            print("DEBUG: check_password_hash returns:", match)
        else:
            print("DEBUG: No user found for email:", email)

        if user and check_password_hash(user['sifre'], sifre):
            session['user_id'] = user['id']
            print(f"session['user_id'] : {session['user_id'] }")
            session['user_name'] = user['ad']
            flash("Giriş başarılı!", "success")
            return redirect(url_for('select_exam'))
        else:
            error = "E-posta veya şifre hatalı"
            return render_template('login.html', error=error)
    else:
        return render_template('login.html')


@app.route('/logout')
def logout():
    """Logs out the user and renders a confirmation page."""
    session.pop('user_id', None)
    session.pop('user_name', None)
    flash("Çıkış yaptınız.", "info")
    return render_template('logout.html')


@app.route('/select_exam', methods=['GET'])
def select_exam():
    """Exam subject selection page."""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('select_exam.html')

@app.route('/exam/<subject>', methods=['GET', 'POST'])
def exam(subject):
    """Display exam questions for a given subject and process submitted answers."""
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Only allow valid subjects
    if subject not in ['Python', 'Java', 'Javascript']:
        flash("Geçersiz sınav konusu.", "danger")
        return redirect(url_for('select_exam'))

    if request.method == 'GET':
        conn = get_db_connection()
        sorular = conn.execute("SELECT * FROM sorular WHERE konu = ?", (subject,)).fetchall()
        for i in sorular:
            print(f"sorular:::::::::::::::::::::::::::::{dict(i)}")
        conn.close()
        # Debug: print number of questions loaded
        print(f"GET: Loaded {len(sorular)} questions for subject {subject}")
        return render_template('exam.html', sorular=sorular, subject=subject)

    elif request.method == 'POST':
        conn = get_db_connection()
        sorular = conn.execute("SELECT * FROM sorular WHERE konu = ?", (subject,)).fetchall()
        dogru_sayisi = 0  # Reset the correct answer count

        # Debug: Print number of questions processed
        print(f"POST: Processing {len(sorular)} questions for subject {subject}")

        for soru in sorular:
            # Get the submitted answer for each question; default to an empty string if not provided
            verilen_cevap = request.form.get(f"cevap_{soru['id']}", "").strip()
            print(f"verilen_cevap:::::::::: {verilen_cevap}")
            # Trim the stored correct answer from the database
            correct_answer = soru['dogru_cevap'].strip()

            # Debug: Print submitted and correct answers
            print(f"Question {soru['id']}: Submitted '{verilen_cevap}' | Correct '{correct_answer}'")

            if verilen_cevap == correct_answer:
                dogru_mu = 1
                dogru_sayisi += 1
            else:
                dogru_mu = 0

            conn.execute(
                "INSERT INTO cevaplar (kullanici_id, soru_id, verilen_cevap, dogru_mu) VALUES (?, ?, ?, ?)",
                (session['user_id'], soru['id'], verilen_cevap, dogru_mu)
            )

        # Debug: Print total correct count
        print("Total correct answers:", dogru_sayisi)

        toplam_skor = dogru_sayisi
        conn.execute(
            "INSERT INTO sinavsonuclari (kullanici_id, skor, tarih) VALUES (?, ?, datetime('now'))",
            (session['user_id'], toplam_skor)
        )

        # Update the user's attempt count and best score
        user = conn.execute("SELECT * FROM kullanicilar WHERE id = ?", (session['user_id'],)).fetchone()
        yeni_deneme = user['deneme_sayisi'] + 1
        yeni_en_yuksek = user['en_yuksek_skor']
        if toplam_skor > user['en_yuksek_skor']:
            yeni_en_yuksek = toplam_skor

        conn.execute(
            "UPDATE kullanicilar SET deneme_sayisi = ?, en_yuksek_skor = ? WHERE id = ?",
            (yeni_deneme, yeni_en_yuksek, session['user_id'])
        )

        # 1) Record the user’s final score in sinavsonuclari
        conn.execute("""
            INSERT INTO sinavsonuclari (kullanici_id, skor, tarih)
            VALUES (?, ?, datetime('now'))
        """, (session['user_id'], toplam_skor))

        # 2) Update the user’s personal best if needed
        user = conn.execute("""
            SELECT en_yuksek_skor
            FROM kullanicilar
            WHERE id = ?
        """, (session['user_id'],)).fetchone()

        current_best = user['en_yuksek_skor'] if user else 0
        if toplam_skor > current_best:
            conn.execute("""
                UPDATE kullanicilar
                SET en_yuksek_skor = ?
                WHERE id = ?
            """, (toplam_skor, session['user_id']))



        conn.commit()
        conn.close()
        return redirect(url_for('result', skor=toplam_skor, subject=subject))

@app.route('/result')
def result():
    """Exam result page."""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    skor = request.args.get('skor', 0, type=int)
    subject = request.args.get('subject', '')
    return render_template('result.html', skor=skor, subject=subject)

@app.context_processor
def inject_scores():
    conn = get_db_connection()
    # 1) Query the all-time best
    row = conn.execute("SELECT MAX(skor) AS max_skor FROM sinavsonuclari").fetchone()
    top_score = row["max_skor"] if row and row["max_skor"] is not None else 0

    # 2) Query the current user’s best
    user_best = 0
    if 'user_id' in session:
        user_row = conn.execute(
            "SELECT en_yuksek_skor FROM kullanicilar WHERE id = ?",
            (session['user_id'],)
        ).fetchone()
        if user_row:
            user_best = user_row['en_yuksek_skor'] or 0

    conn.close()
    return {
        'top_score': top_score,
        'user_best': user_best
    }


########################################
# RUN THE APPLICATION
########################################
if __name__ == '__main__':
    # For development: delete existing DB to force reinitialization (or comment out after schema update)
    if not os.path.exists(DATABASE):
        init_db()
    app.run(debug=True)
