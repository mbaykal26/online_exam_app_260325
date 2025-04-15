import os
import sqlite3
from flask import Flask, g, request, render_template, flash, redirect, url_for, session, jsonify, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import random
from flask import send_from_directory
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from flask import make_response, send_file

# Define the path to the database file
DATABASE = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'exam.db')

########################################
# FLASK APPLICATION SETUP
########################################
app = Flask(__name__)
app.secret_key = "a1d76c1f45b9d653bcfe0c0782c928b6aa54e24cc1685e3b839de0f57282b88f"
app.config['DATABASE'] = DATABASE


# Mail configuration (use your SMTP provider here)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'muratbaykal@gmail.com'
app.config['MAIL_PASSWORD'] = 'fgeh mjan punh zelv'  # Use app password, not real password
app.config['MAIL_DEFAULT_SENDER'] = 'muratbaykal@gmail.com'

mail = Mail(app)

s = URLSafeTimedSerializer(app.secret_key)

# Configure upload folder (inside static for easy serving)
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static', 'uploads')
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Allowed file extensions
ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx'}


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

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
        deneme_sayisi INTEGER DEFAULT 0,
        email_confirmed INTEGER DEFAULT 0,
        rolId INTEGER DEFAULT 2
    )
    """)

    # Questions table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS sorular (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        soru_metni TEXT NOT NULL,
        dogru_cevap TEXT NOT NULL,
        secenek1 TEXT NOT NULL,
        secenek2 TEXT NOT NULL,
        secenek3 TEXT NOT NULL,
        secenek4 TEXT NOT NULL,
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

    # Blog Comments table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS blog_comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        blog_post_id INTEGER,
        user_id INTEGER,
        comment TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (blog_post_id) REFERENCES blog_posts(id),
        FOREIGN KEY (user_id) REFERENCES kullanicilar(id)
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

    # Blog posts table, now with an "approved" column (default 0 means not approved yet)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS blog_posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        content TEXT,
        filename TEXT,
        filetype TEXT,
        posted_by INTEGER,
        approved INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)    # Build a multi-row INSERT statement from the data list
    
    #2. Create a cursor and execute a query to fetch all columns from 'sorular'
    query = "SELECT * FROM sorular"
    cursor.execute(query)
    
    # 3. Fetch all results
    data = cursor.fetchall()  # This will return a list of tuples  
    
    values = []
    new_data = []
    for q, correct, false_opts, topic in data:
        # Split the false options into a list and trim extra whitespace
        options = [opt.strip() for opt in false_opts.split(";")]
        # Add the correct answer to the list
        options.append(correct)
        # Shuffle so the correct answer appears in a random position
        random.shuffle(options)
        # Create a tuple: (question, dogru_cevap, option1, option2, option3, option4, topic)
        new_tuple = (q, correct, options[0], options[1], options[2], options[3], topic)
        new_data.append(new_tuple)

    print("new_data::::::::::::::::::::::::::::::", new_data)

    for row in new_data:
        # Unpack all seven fields and escape single quotes by replacing them with two single quotes
        q, correct, opt1, opt2, opt3, opt4, topic = (s.replace("'", "''") for s in row)
        values.append(f"('{q}', '{correct}', '{opt1}', '{opt2}', '{opt3}', '{opt4}', '{topic}')")

    # Construct the multi-row INSERT statement for 6 columns
    insert_stmt = ("INSERT INTO sorular (soru_metni, dogru_cevap, secenek1, secenek2, secenek3, secenek4, konu) VALUES " +
                ", ".join(values) + ";")
    print(insert_stmt)
    cursor.execute(insert_stmt)

    connection.commit()
    connection.close()

########################################
# EMAIL CONFIRMATION HELPER FUNCTIONS
########################################
def generate_confirmation_token(email):
    return s.dumps(email, salt='email-confirm')

def confirm_token(token, expiration=3600):
    try:
        email = s.loads(token, salt='email-confirm', max_age=expiration)
    except Exception:
        return False
    return email

def send_email(to, subject, template):
    msg = Message(subject, recipients=[to], html=template)
    mail.send(msg)

@app.route('/confirm_email/<token>')
def confirm_email(token):
    email = confirm_token(token)
    if not email:
        flash("Doğrulama bağlantısı geçersiz veya süresi dolmuş.", "danger")
        return redirect(url_for('login'))

    conn = get_db_connection()
    user = conn.execute("SELECT * FROM kullanicilar WHERE email = ?", (email,)).fetchone()
    if not user:
        flash("Kullanıcı bulunamadı.", "danger")
        conn.close()
        return redirect(url_for('register'))

    # Use dictionary indexing since sqlite3.Row does not support .get()
    if user['email_confirmed']:
        flash("E-posta adresiniz zaten onaylanmış.", "info")
    else:
        conn.execute("UPDATE kullanicilar SET email_confirmed = 1 WHERE email = ?", (email,))
        conn.commit()
        flash("E-posta adresiniz başarıyla onaylandı!", "success")
    conn.close()
    return redirect(url_for('login'))



from werkzeug.security import generate_password_hash, check_password_hash
h = generate_password_hash("123")
print("Generated hash:", h)
print("Check password:", check_password_hash(h, "123"))
print("repr(h)::::::::::::::::::::", repr(h))

########################################
# ROUTES
########################################

def get_comments(post_id):
    conn = get_db_connection()
    comments = conn.execute(
        """
        SELECT bc.id, bc.comment, bc.user_id, bc.created_at,
               COALESCE(u.ad, 'Anonymous') AS author_name
        FROM blog_comments bc
        LEFT JOIN kullanicilar u ON bc.user_id = u.id
        WHERE bc.blog_post_id = ?
        ORDER BY bc.created_at ASC
        """,
        (post_id,)
    ).fetchall()
    conn.close()
    return comments

@app.context_processor
def utility_processor():
    """
    Expose get_comments in Jinja templates 
    so you can call get_comments(post.id) directly.
    """
    return dict(get_comments=get_comments)



#LOGIN###############################################################
@app.route('/')
def index():
    """Redirect to login if not logged in, otherwise to exam selection."""
    if 'user_id' in session:
        for i in session:
            print(f"session[i]: {session[i]}")
        return redirect(url_for('select_exam'))
    return render_template('index.html')


@app.route('/view_file/<path:filename>')
def view_file(filename):
    full_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    # Specify the appropriate mimetype for DOCX files
    # For docx, the mimetype is typically 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
    mimetype = None
    ext = filename.rsplit('.', 1)[1].lower()
    if ext == 'pdf':
        mimetype = 'application/pdf'
    elif ext in ['doc', 'docx']:
        mimetype = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
    elif ext in ['png', 'jpg', 'jpeg', 'gif']:
        # Let send_file auto-detect for images or you can   specify image/jpeg etc.
        mimetype = None
    elif ext == 'txt':
        mimetype = 'text/plain'
    else:
        mimetype = None

    response = make_response(send_file(full_path, as_attachment=False, mimetype=mimetype))
    # Force inline content disposition; note many browsers will still prompt download if no viewer exists
    response.headers['Content-Disposition'] = f'inline; filename="{filename}"'
    return response

#LOGIN###############################################################

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login."""
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        sifre = request.form['sifre'].strip()
        conn = get_db_connection()
        user = conn.execute("SELECT * FROM kullanicilar WHERE email = ?", (email,)).fetchone()
        conn.close()
        print("DEBUG: Retrieved user:", user)
        if user:
            print("DEBUG: Stored password hash:", repr(user['sifre']))
            if check_password_hash(user['sifre'], sifre):
                # Check if the email is confirmed
                if not user['email_confirmed']:
                    flash("Lütfen önce e-posta adresinizi onaylayın.", "warning")
                    return render_template('login.html', error="E-posta henüz onaylanmamış.")
                # Set session variables since the user is now confirmed.
                session['user_id'] = user['id']
                session['user_name'] = user['ad']
                session['rolId'] = user['rolId']
                flash("<strong>Giriş başarılı!</strong> Hoşgeldin, <strong>" + user['ad'] + "</strong>! Başarı dolu bir deneyim seni bekliyor.", "success")
                return redirect(url_for('select_exam'))
            else:
                error = "E-posta veya şifre hatalı"
                return render_template('login.html', error=error)
        else:
            error = "E-posta veya şifre hatalı"
            return render_template('login.html', error=error)
    return render_template('login.html')


#LOGOUT #################################
@app.route('/logout')
def logout():
    """Logs out the user and renders a confirmation page."""
    session.pop('user_id', None)
    session.pop('user_name', None)
    #flash("Çıkış yaptınız.", "info")
    return render_template('logout.html')
##LOGOUT##################################

#USER REGISTRATION###############################################################
@app.route('/register', methods=['GET', 'POST'])
def register():
    """Register a new user and send a confirmation email."""
    if request.method == 'POST':
        name = request.form['name'].strip()
        email = request.form['email'].strip().lower()
        sifre = request.form['sifre'].strip()

        if not name or not email or not sifre:
            flash("<strong>Lütfen tüm alanları doldurun.</strong>", "danger")
            return render_template('register.html')

        conn = get_db_connection()
        # Check case-insensitively for existing email
        existing = conn.execute("SELECT * FROM kullanicilar WHERE LOWER(email) = ?", (email,)).fetchone()
        if existing:
            flash("<strong>Bu e-posta adresi zaten kayıtlı.</strong>", "warning")
            conn.close()
            return render_template('register.html')

        hashed_password = generate_password_hash(sifre)
        # Ensure the user is inserted with email_confirmed = 0 (not confirmed)
        cursor = conn.execute(
            "INSERT INTO kullanicilar (ad, email, sifre, rolId, email_confirmed) VALUES (?, ?, ?, ?, ?)",
            (name, email, hashed_password, 2, 0)
        )
        conn.commit()
        new_user_id = cursor.lastrowid
        conn.close()

        # Generate the confirmation token and URL.
        token = generate_confirmation_token(email)
        confirm_url = url_for('confirm_email', token=token, _external=True)
        # Render the email template (activate.html) with the confirm URL.
        html = render_template('activate.html', confirm_url=confirm_url, name=name)
        send_email(email, "Lütfen E-posta Adresinizi Doğrulayın", html)

        # Flash a striking message; do not log the user in automatically.
        flash(f"<strong>Kayıt başarılı!</strong> Hoşgeldin, <strong>{name}</strong>! Lütfen e-posta adresinize gönderilen doğrulama bağlantısını kontrol edin.", "success")
        return redirect(url_for('login'))
    return render_template('register.html')

#USER REGISTRATION###############################################################


#LOGIN REGISTRATION###############################################################

from functools import wraps

def roles_required(*allowed_roles):
    """
    Decorator to ensure the user has one of the specified rolIds.
    For example, @roles_required(1) restricts access to users with rolId=1.
    """
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            # Check if user is logged in
            if 'user_id' not in session:
                #flash("Bu işlemi yapmak için giriş yapmalısınız.", "danger")
                return redirect(url_for('login'))

            # Get the user's role from the database
            conn = get_db_connection()
            user = conn.execute("SELECT rolId FROM kullanicilar WHERE id = ?", (session['user_id'],)).fetchone()
            conn.close()

            # If no user or the user's role is not in allowed_roles, deny access
            if not user or user['rolId'] not in allowed_roles:
                #flash("Bu işlemi yapmak için yetkiniz yok.", "danger")
                return redirect(url_for('blog'))

            return f(*args, **kwargs)
        return wrapper
    return decorator
#ROLES REQUIREMENT ENDS ###############################################################


#SELECT EXAM###############################################################
@app.route('/select_exam', methods=['GET'])
def select_exam():
    """Exam subject selection page."""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('select_exam.html')
#SELECT EXAM###############################################################


#EXAM###############################################################
@app.route('/exam/<subject>', methods=['GET', 'POST'])
def exam(subject):
    """Display exam questions for a given subject and process submitted answers."""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if subject not in ['Python', 'Java', 'JavaScript', 'C', 'C++', 'Golang', 'C#', 'SQL', 'HTML', 'CSS']:
        #flash("Geçersiz sınav konusu.", "danger")
        return redirect(url_for('select_exam'))
    if request.method == 'GET':
        conn = get_db_connection()
        sorular = conn.execute("SELECT * FROM sorular WHERE konu = ?", (subject,)).fetchall()
        for i in sorular:
            print(f"sorular:::::::::::::::::::::::::::::{dict(i)}")
        conn.close()
        print(f"GET: Loaded {len(sorular)} questions for subject {subject}")
        return render_template('exam.html', sorular=sorular, subject=subject)
    elif request.method == 'POST':
        conn = get_db_connection()
        sorular = conn.execute("SELECT * FROM sorular WHERE konu = ?", (subject,)).fetchall()
        dogru_sayisi = 0
        print(f"POST: Processing {len(sorular)} questions for subject {subject}")
        for soru in sorular:
            verilen_cevap = request.form.get(f"cevap_{soru['id']}", "").strip()
            print(f"verilen_cevap:::::::::: {verilen_cevap}")
            correct_answer = soru['dogru_cevap'].strip()
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
        print("Total correct answers:", dogru_sayisi)
        toplam_skor = dogru_sayisi
        conn.execute(
            "INSERT INTO sinavsonuclari (kullanici_id, skor, tarih) VALUES (?, ?, datetime('now'))",
            (session['user_id'], toplam_skor)
        )
        user = conn.execute("SELECT * FROM kullanicilar WHERE id = ?", (session['user_id'],)).fetchone()
        yeni_deneme = user['deneme_sayisi'] + 1
        yeni_en_yuksek = user['en_yuksek_skor']
        if toplam_skor > user['en_yuksek_skor']:
            yeni_en_yuksek = toplam_skor
        conn.execute(
            "UPDATE kullanicilar SET deneme_sayisi = ?, en_yuksek_skor = ? WHERE id = ?",
            (yeni_deneme, yeni_en_yuksek, session['user_id'])
        )
        conn.execute("""
            INSERT INTO sinavsonuclari (kullanici_id, skor, tarih)
            VALUES (?, ?, datetime('now'))
        """, (session['user_id'], toplam_skor))
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
#EXAM ENDS ###############################################################

#RESULTS###############################################################
@app.route('/result')
def result():
    """Exam result page."""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    skor = request.args.get('skor', 0, type=int)
    subject = request.args.get('subject', '')
    return render_template('result.html', skor=skor, subject=subject)
#RESULTS ENDS ###############################################################

@app.context_processor
def inject_scores():
    conn = get_db_connection()
    row = conn.execute("SELECT MAX(skor) AS max_skor FROM sinavsonuclari").fetchone()
    top_score = row["max_skor"] if row and row["max_skor"] is not None else 0
    user_best = 0
    user_role_id = None

    if 'user_id' in session:
        user_row = conn.execute(
            "SELECT en_yuksek_skor, rolId FROM kullanicilar WHERE id = ?",
            (session['user_id'],)
        ).fetchone()
        if user_row:
            user_best = user_row['en_yuksek_skor'] or 0
            user_role_id = user_row['rolId']

    conn.close()
    return {
        'top_score': top_score,
        'user_best': user_best,
        'user_role_id': user_role_id  # <-- role ID for use in templates
    }
    

########################################
# BLOG ROUTES
########################################

@app.route('/blog')
def blog():
    """Display all blog posts with optional filtering."""
    q = request.args.get('q', '').strip()
    conn = get_db_connection()
    if q:
        posts = conn.execute(
            """
            SELECT
                bp.id,
                bp.title,
                bp.content,
                bp.filename,
                bp.filetype,
                bp.created_at,
                bp.posted_by AS author_id,
                COALESCE(u.ad, 'Anonymous') AS author_name
            FROM blog_posts bp
            LEFT JOIN kullanicilar u ON bp.posted_by = u.id
            WHERE (bp.title LIKE ? OR bp.content LIKE ?) AND bp.approved = 1
            ORDER BY bp.created_at DESC
            """,
            ('%' + q + '%', '%' + q + '%')
        ).fetchall()
    else:
        posts = conn.execute(
            """
            SELECT
                bp.id,
                bp.title,
                bp.content,
                bp.filename,
                bp.filetype,
                bp.created_at,
                bp.posted_by AS author_id,
                COALESCE(u.ad, 'Anonymous') AS author_name
            FROM blog_posts bp
            LEFT JOIN kullanicilar u ON bp.posted_by = u.id
            WHERE bp.approved = 1
            ORDER BY bp.created_at DESC
            """
        ).fetchall()
    conn.close()
    return render_template(
        'blog.html',
        posts=posts,
        q=q,
        user_role_id=session.get('rolId')
    )



#BLOG ENDS ###############################################################

#NEW BLOG POST###############################################################
@app.route('/blog/new', methods=['GET', 'POST'])
@roles_required(1, 2)  # Allow both role 1 and role 2 to add posts
def new_blog_post():
    """Create a new blog post with an optional file upload."""
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        uploaded_file = request.files.get('file')
        filename = None
        filetype = None

        if uploaded_file and allowed_file(uploaded_file.filename):
            filename = secure_filename(uploaded_file.filename)
            uploaded_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            ext = filename.rsplit('.', 1)[1].lower()
            if ext == 'pdf':
                filetype = 'pdf'
            elif ext == 'docx':
                filetype = 'document'
            elif ext == 'txt':
                filetype = 'txt'
            else:
                filetype = 'image'

        # Get the posting user's id from the session
        posted_by = session.get('user_id')

        conn = get_db_connection()
        conn.execute(
            "INSERT INTO blog_posts (title, content, filename, filetype, posted_by, approved) VALUES (?, ?, ?, ?, ?, ?)",
            (title, content, filename, filetype, posted_by, 0)  # approved is 0 (pending)
        )
        conn.commit()
        conn.close()
        flash("Blog post created successfully! It is pending moderator approval.", "success")
        return redirect(url_for('blog'))
    return render_template('new_blog_post.html')



##NEW BLOG POST ENDS ###############################################################

####### UPDATE THE ARTICLE #######
####### UPDATE THE ARTICLE #######
@app.route('/blog/edit/<int:post_id>', methods=['GET', 'POST'])
@roles_required(1,2)  # Allow both admin (rolId == 1) and regular users (rolId == 2) to access if they are the author.
def update_blog_yazisi(post_id):
    """Update an existing blog post. After updating, set approved to 0 so the post must be re-moderated."""
    conn = get_db_connection()
    post = conn.execute("SELECT * FROM blog_posts WHERE id = ?", (post_id,)).fetchone()
    if post is None:
        flash("Blog yazısı bulunamadı.", "danger")
        conn.close()
        return redirect(url_for('blog'))
    
    # Get the current user's ID and role
    current_user_id = session.get('user_id')
    current_role = session.get('rolId')
    
    # Allow update only if the current user is admin or is the author of this post.
    if not (current_role == 1 or current_user_id == post['posted_by']):
        flash("Bu yazıyı düzenleme yetkiniz yok.", "danger")
        conn.close()
        return redirect(url_for('blog'))

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        file = request.files.get('file')
        # Preserve existing file details by default
        filename = post['filename']
        filetype = post['filetype']

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            ext = filename.rsplit('.', 1)[1].lower()
            print("DEBUG (edit): Uploaded file extension is:", ext)  # Debug print
            if ext == 'pdf':
                filetype = 'pdf'
            elif ext in ['doc', 'docx']:
                filetype = 'document'
            elif ext == 'txt':
                filetype = 'txt'
            else:
                filetype = 'image'

        # Update the post and also reset 'approved' to 0 so that the post is sent for moderation again.
        conn.execute(
            "UPDATE blog_posts SET title = ?, content = ?, filename = ?, filetype = ?, approved = 0 WHERE id = ?",
            (title, content, filename, filetype, post_id)
        )
        conn.commit()
        conn.close()
        flash("Blog yazısı güncellendi. Lütfen moderatör onayı bekleyiniz.", "success")
        return redirect(url_for('blog'))

    conn.close()
    return render_template('update_blog_yazisi.html', post=post)


######################################### update blog post route ##########################################


######## DELETE THE ARTICLE #######
@app.route('/blog/delete/<int:post_id>', methods=['GET', 'POST'])
@roles_required(1,2)  # Only rolId=1 can access
def delete_blog_post(post_id):
    """Belirli bir blog yazısını silmek için route."""
    conn = get_db_connection()
    post = conn.execute("SELECT * FROM blog_posts WHERE id = ?", (post_id,)).fetchone()
    if post is None:
        flash("Blog yazısı bulunamadı.", "danger")
        conn.close()
        return redirect(url_for('blog'))
    
    # Get the current user's ID and role.
    current_user_id = session.get('user_id')
    current_role = session.get('rolId')
    
    # Allow deletion if the user is an admin (role 1) OR if the user is the author.
    if not (current_role == 1 or current_user_id == post['posted_by']):
        flash("Bu işlemi yapmak için yetkiniz yok.", "danger")
        conn.close()
        return redirect(url_for('blog'))

    if request.method == 'POST':
        # Eğer dosya yüklenmişse, dosyayı sistemden de silebiliriz.
        if post['filename']:
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], post['filename'])
            if os.path.exists(filepath):
                os.remove(filepath)
        conn.execute("DELETE FROM blog_posts WHERE id = ?", (post_id,))
        conn.commit()
        conn.close()
        flash("Blog yazısı silindi.", "success")
        return redirect(url_for('blog'))

    conn.close()
    return render_template('delete_blog_yazisi.html', post=post)
######################################### delete blog post route ##########################################

#BLOG POST DETAIL###############################################################
@app.route('/blog/<int:post_id>')
def blog_post_detail(post_id):
    """Display the full details of a specific blog post."""
    conn = get_db_connection()
    post = conn.execute("SELECT * FROM blog_posts WHERE id = ?", (post_id,)).fetchone()
    conn.close()
    if post is None:
        flash("Blog yazısı bulunamadı.", "danger")
        return redirect(url_for('blog'))
    return render_template('blog_post_detail.html', post=post)
#BLOG POST DETAIL ENDS ###############################################################

#MODERATOR ROUTE ######################################################
@app.route('/blog/moderate')
@roles_required(1)  # Only administrators can moderate posts.
def moderate_blog_posts():
    """Display all blog posts that are pending approval."""
    conn = get_db_connection()
    pending_posts = conn.execute(
        """
        SELECT
            bp.id,
            bp.title,
            bp.content,
            bp.filename,
            bp.filetype,
            bp.created_at,
            bp.posted_by AS author_id,
            u.ad AS posted_by
        FROM blog_posts bp
        LEFT JOIN kullanicilar u ON bp.posted_by = u.id
        WHERE bp.approved = 0
        ORDER BY bp.created_at DESC
        """
    ).fetchall()
    conn.close()
    return render_template('moderate.html', posts=pending_posts)


# APPROVE ROOTE ###################################
@app.route('/blog/approve/<int:post_id>', methods=['POST'])
@roles_required(1)
def approve_post(post_id):
    """Approve a blog post so that it goes live."""
    conn = get_db_connection()
    conn.execute("UPDATE blog_posts SET approved = 1 WHERE id = ?", (post_id,))
    conn.commit()
    conn.close()
    flash("Blog yazısı onaylandı.", "success")
    return redirect(url_for('moderate_blog_posts'))


##################  COMMENT SECTIONS  #################################################
@app.route('/blog/<int:post_id>/comments', methods=['POST'])
def add_comment(post_id):
    """
    Add a new comment to the specified blog post.
    Requires the user be logged in.
    """
    if 'user_id' not in session:
        flash("Yorum yapmak için giriş yapmalısınız.", "danger")
        return redirect(url_for('login'))

    new_comment = request.form.get('comment', '').strip()
    if not new_comment:
        flash("Yorum boş olamaz.", "warning")
        return redirect(url_for('blog_post_detail', post_id=post_id))

    conn = get_db_connection()
    conn.execute(
        "INSERT INTO blog_comments (blog_post_id, user_id, comment) VALUES (?, ?, ?)",
        (post_id, session['user_id'], new_comment)
    )
    conn.commit()
    conn.close()

    flash("Yorumunuz başarıyla eklendi.", "success")
    return redirect(url_for('blog_post_detail', post_id=post_id))




#  EDIT A COMMENT ######################################################
@app.route('/blog/comment/<int:comment_id>/edit', methods=['GET', 'POST'])
def edit_comment(comment_id):
    """Edit an existing comment."""
    conn = get_db_connection()
    comment = conn.execute("SELECT * FROM blog_comments WHERE id = ?", (comment_id,)).fetchone()
    if not comment:
        flash("Yorum bulunamadı.", "danger")
        conn.close()
        return redirect(url_for('blog'))

    # Only allow editing if the current user is the author of the comment.
    if session.get('user_id') != comment['user_id']:
        flash("Bu yorumu düzenleme yetkiniz yok.", "danger")
        conn.close()
        return redirect(url_for('blog_post_detail', post_id=comment['blog_post_id']))

    if request.method == 'POST':
        new_comment_text = request.form.get('comment')
        if not new_comment_text or new_comment_text.strip() == "":
            flash("Yorum boş bırakılamaz.", "warnin g")
            conn.close()
            return redirect(url_for('edit_comment', comment_id=comment_id))
        conn.execute(
            "UPDATE blog_comments SET comment = ? WHERE id = ?",
            (new_comment_text.strip(), comment_id)
        )
        conn.commit()
        conn.close()
        flash("Yorum güncellendi.", "success")
        return redirect(url_for('blog_post_detail', post_id=comment['blog_post_id']))

    conn.close()
    return render_template('edit_comment.html', comment=comment)


########### DELETE A COMMENT  #########################
@app.route('/blog/comment/delete/<int:comment_id>', methods=['POST'])
def delete_comment(comment_id):
    """
    Delete a specific comment if the user is the comment's author 
    or an admin.
    """
    if 'user_id' not in session:
        flash("Bu işlemi yapmak için giriş yapmalısınız.", "danger")
        return redirect(url_for('login'))

    conn = get_db_connection()
    comment = conn.execute(
        "SELECT * FROM blog_comments WHERE id = ?", 
        (comment_id,)
    ).fetchone()

    if not comment:
        conn.close()
        flash("Yorum bulunamadı.", "danger")
        return redirect(url_for('blog'))

    # Ensure the user is the comment author or an admin
    if comment['user_id'] != session['user_id'] and session.get('rolId') != 1:
        conn.close()
        flash("Bu yorumu silmeye yetkiniz yok.", "danger")
        return redirect(url_for('blog'))

    # Otherwise, delete
    conn.execute("DELETE FROM blog_comments WHERE id = ?", (comment_id,))
    conn.commit()
    conn.close()
    flash("Yorum silindi.", "success")

    # After deletion, redirect back to the post’s detail page
    return redirect(url_for('blog_post_detail', post_id=comment['blog_post_id']))


##############GAME ENDPOINT ###################
@app.route('/game')
def game():
    return render_template('game.html')


#hakkımda###############################################################
@app.route('/about')
def about():
    """Display the About page."""
    return render_template('about.html')
#hakkımda ENDS ###############################################################

###### TEMPERATURE READING ##############################################################
current_temperature = None

@app.route('/update_temp', methods=['GET', 'POST'])
def update_temp():
    global current_temperature
    if request.method == 'POST':
        data = request.get_json()
        if not data or "temperature" not in data:
            return jsonify({"error": "Temperature data not provided"}), 400
        current_temperature = data["temperature"]
        # Optionally, you can flash a message or log the update.
        print("Received temperature:", current_temperature)
        return jsonify({"status": "success", "temperature": current_temperature}), 200
    else:
        # For GET requests, display the current temperature on an HTML page.
        return render_template("temperature.html", temperature=current_temperature)
# TEMPERATURE READING #######################################################################

########################################
# RUN THE APPLICATION
########################################
if __name__ == '__main__':
    if not os.path.exists(DATABASE):
        init_db()
    app.run(debug=True)


# import random
# import sqlite3
# import os
# from programming_questions import data
# #Adjust the DATABASE path if necessary
# DATABASE = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'exam.db')

# def get_db_connection():
#     conn = sqlite3.connect(DATABASE)
#     conn.row_factory = sqlite3.Row
#     return conn

# values = []

# data_css = [
#     (
#         "What does CSS stand for?",
#         "Cascading Style Sheets.",
#         "Creative Style Sheets.;Computer Style Sheets.;Colorful Style Sheets.",
#         "CSS"
#     ),
#     (
#         "What is the primary purpose of CSS?",
#         "To style and layout web pages.",
#         "To structure the content of web pages.;To add interactivity to web pages.;To manage website data.",
#         "CSS"
#     ),
#     (
#         "Where should you place the link to an external CSS file in an HTML document?",
#         "Inside the <head> tag.",
#         "Inside the <body> tag.;At the end of the document.;Inside a <footer> tag.",
#         "CSS"
#     ),
#     (
#         "How do you apply inline CSS to an element?",
#         "By using the style attribute.",
#         "By using the class attribute.;By linking a stylesheet.;By using a JavaScript function.",
#         "CSS"
#     ),
#     (
#         "Which property is used to change the text color of an element in CSS?",
#         "color",
#         "text-color.;font-color.;background-color.",
#         "CSS"
#     ),
#     (
#         "Which property is used to change the background color of an element?",
#         "background-color",
#         "color.;border-color.;text-color.",
#         "CSS"
#     ),
#     (
#         "How do you add a comment in a CSS file?",
#         "/* Comment */",
#         "// Comment.;<!-- Comment -->;# Comment",
#         "CSS"
#     ),
#     (
#         "Which property controls the space between an element's border and its content?",
#         "padding",
#         "margin.;border-spacing.;outline.",
#         "CSS"
#     ),
#     (
#         "Which property controls the space outside an element's border?",
#         "margin",
#         "padding.;border.;spacing.",
#         "CSS"
#     ),
#     (
#         "How do you set the font size of an element?",
#         "font-size",
#         "text-size.;font-style.;size.",
#         "CSS"
#     ),
#     (
#         "Which property is used to specify the typeface for text?",
#         "font-family",
#         "font-type.;text-family.;typeface.",
#         "CSS"
#     ),
#     (
#         "How do you center a block element horizontally?",
#         "margin: 0 auto;",
#         "text-align: center.;padding: auto.;display: center;",
#         "CSS"
#     ),
#     (
#         "Which property is used to adjust the spacing between letters?",
#         "letter-spacing",
#         "word-spacing.;font-spacing.;line-spacing.",
#         "CSS"
#     ),
#     (
#         "Which property is used to set the space between lines of text?",
#         "line-height",
#         "font-size.;letter-spacing.;word-spacing.",
#         "CSS"
#     ),
#     (
#         "How do you create rounded corners for an element?",
#         "Using the border-radius property.",
#         "Using the corner-radius property.;Using the outline property.;Using the box-shadow property.",
#         "CSS"
#     ),
#     (
#         "Which property is used to add a shadow effect to an element’s box?",
#         "box-shadow",
#         "text-shadow.;filter.;background-shadow.",
#         "CSS"
#     ),
#     (
#         "How can you display elements side by side?",
#         "By using display: inline-block; or a flex container (display: flex;).",
#         "By using display: block.;By using display: none.;By using vertical-align only.",
#         "CSS"
#     ),
#     (
#         "Which property is used to set up a flex container?",
#         "display: flex;",
#         "display: block.;display: grid.;display: inline;",
#         "CSS"
#     ),
#     (
#         "How do you align items vertically within a flex container?",
#         "Using the align-items property.",
#         "Using the justify-content property.;Using align-content.;Using vertical-align.",
#         "CSS"
#     ),
#     (
#         "Which property allows flex items to wrap onto multiple lines?",
#         "flex-wrap",
#         "flex-flow.;flex-direction.;wrap-items.",
#         "CSS"
#     ),
#     (
#         "How do you set a linear gradient as a background?",
#         "background: linear-gradient(direction, color-stop1, color-stop2, ...);",
#         "background: radial-gradient(...);background: gradient(...);background: line(...);",
#         "CSS"
#     ),
#     (
#         "How do you set a radial gradient as a background?",
#         "background: radial-gradient(shape, size, start-color, ..., last-color);",
#         "background: linear-gradient(...);background: circular-gradient(...);background: gradient(...);",
#         "CSS"
#     ),
#     (
#         "Which property controls the vertical stacking order of elements?",
#         "z-index",
#         "order.;stack-index.;depth.",
#         "CSS"
#     ),
#     (
#         "What does the opacity property do?",
#         "Controls the transparency of an element.",
#         "Sets the element's size.;Changes the element's position.;Alters the element's color.",
#         "CSS"
#     ),
#     (
#         "Which unit is relative to the font-size of the element?",
#         "em",
#         "px.;rem.;%",
#         "CSS"
#     ),
#     (
#         "Which unit is relative to the viewport’s width?",
#         "vw",
#         "vh.;px.;em.",
#         "CSS"
#     ),
#     (
#         "What does the float property do?",
#         "Positions an element to the left or right and allows text to wrap around it.",
#         "Centers an element.;Hides the element.;Applies a CSS grid layout.",
#         "CSS"
#     ),
#     (
#         "How do you clear floated elements?",
#         "Using the clear property (e.g., clear: both;).",
#         "Using float: none.;Using display: block.;Using margin auto.",
#         "CSS"
#     ),
#     (
#         "Which property sets the maximum width of an element?",
#         "max-width",
#         "width.;min-width.;container-width.",
#         "CSS"
#     ),
#     (
#         "Which pseudo-class is used to style an element when a user hovers over it?",
#         ":hover",
#         ":active.;:focus.;:visited.",
#         "CSS"
#     ),
#     (
#         "Which pseudo-class applies styles to links that have been visited?",
#         ":visited",
#         ":active.;:hover.;:link.",
#         "CSS"
#     ),
#     (
#         "How do you remove the default underline from a hyperlink?",
#         "text-decoration: none;",
#         "font-weight: none.;text-style: none.;underline: false;",
#         "CSS"
#     ),
#     (
#         "Which property controls the spacing between words?",
#         "word-spacing",
#         "letter-spacing.;line-spacing.;text-spacing.",
#         "CSS"
#     ),
#     (
#         "How do you select all elements on a page in CSS?",
#         "Using the universal selector: *",
#         "Using the html selector.;Using the body selector.;Using the global selector.",
#         "CSS"
#     ),
#     (
#         "Which property is used to change the cursor style when hovering over an element?",
#         "cursor",
#         "pointer.;mouse.;hand.",
#         "CSS"
#     ),
#     (
#         "How do you specify a fallback font in a font-family declaration?",
#         "By listing fonts separated by commas (e.g., font-family: Arial, sans-serif;).",
#         "By using a fallback-font property.;By using an if-else statement.;By setting a default in the @font-face rule.",
#         "CSS"
#     ),
#     (
#         "Which property aligns text within an element?",
#         "text-align",
#         "vertical-align.;align-text.;text-position.",
#         "CSS"
#     ),
#     (
#         "What does 'display: inline-block;' do?",
#         "It makes an element inline while preserving block-level properties like width and height.",
#         "It makes an element behave as a block element.;It hides the element.;It makes an element float.",
#         "CSS"
#     ),
#     (
#         "Which property adds a transition effect between CSS property changes?",
#         "transition",
#         "animation.;transform.;motion.",
#         "CSS"
#     ),
#     (
#         "How do you specify the duration of a CSS transition?",
#         "Using the transition-duration property.",
#         "Using the animation-duration property.;Using the transition-time property.;Using the speed property.",
#         "CSS"
#     ),
#     (
#         "What does the transform property allow you to do?",
#         "Apply transformations such as rotate, scale, skew, or translate to an element.",
#         "Change the element's color.;Adjust the element's opacity.;Set an element's margins.",
#         "CSS"
#     ),
#     (
#         "Which property defines the origin for a transformation in CSS?",
#         "transform-origin",
#         "transform-point.;origin.;position-origin.",
#         "CSS"
#     ),
#     (
#         "How do you define a CSS animation?",
#         "Using the @keyframes rule.",
#         "Using the animation property alone.;Using the transition property.;Using the animate() function.",
#         "CSS"
#     ),
#     (
#         "Which property controls the duration of a CSS animation?",
#         "animation-duration",
#         "animation-timing.;animation-speed.;transition-duration.",
#         "CSS"
#     ),
#     (
#         "Which property defines an element's positioning scheme in CSS?",
#         "position",
#         "location.;float.;display.",
#         "CSS"
#     ),
#     (
#         "What does 'position: fixed;' do?",
#         "It fixes an element relative to the viewport so it stays in place during scrolling.",
#         "It positions an element relative to its container.;It makes an element scrollable.;It hides the element.",
#         "CSS"
#     ),
#     (
#         "Which property in a CSS grid layout sets the spacing between grid items?",
#         "gap",
#         "grid-gap.;margin.;padding.",
#         "CSS"
#     ),
#     (
#         "What does 'box-sizing: border-box;' do?",
#         "It makes an element's width and height include padding and border.",
#         "It excludes padding and border from the element's size.;It resets the element's box model to default.;It hides the element's border.",
#         "CSS"
#     ),
#     (
#         "Which property controls the order of flex items within a container?",
#         "order",
#         "flex-order.;item-order.;align-order.",
#         "CSS"
#     ),
#     (
#         "What is the effect of 'justify-content: space-between;' in a flex container?",
#         "It distributes the extra space evenly between the items.",
#         "It centers the items.;It aligns items to the left.;It places all items at the start.",
#         "CSS"
#     )
# ]

# # You can later extend your master data list as follows:
# # data.extend(data_css)



# data += data_css

# for row in data:
#     soru_metni, dogru_cevap, false_opts, konu = row
#     # Split the false options into a list and remove extra spaces.
#     options = [opt.strip() for opt in false_opts.split(';')]
#     # Append the correct answer into the options list.
#     options.append(dogru_cevap)
#     # Randomly shuffle so the correct answer appears in one of the four positions.
#     random.shuffle(options)
#     # Take the first four options.
#     secenek1, secenek2, secenek3, secenek4 = options[:4]
#     # Escape any single quotes to prevent SQL errors.
#     soru_metni = soru_metni.replace("'", "''")
#     dogru_cevap = dogru_cevap.replace("'", "''")
#     secenek1 = secenek1.replace("'", "''")
#     secenek2 = secenek2.replace("'", "''")
#     secenek3 = secenek3.replace("'", "''")
#     secenek4 = secenek4.replace("'", "''")
#     konu = konu.replace("'", "''")
#     values.append(f"('{soru_metni}', '{dogru_cevap}', '{secenek1}', '{secenek2}', '{secenek3}', '{secenek4}', '{konu}')")

# insert_stmt = ("INSERT INTO sorular (soru_metni, dogru_cevap, secenek1, secenek2, secenek3, secenek4, konu) VALUES " +
#                ", ".join(values) + ";")

# print("Executing query:")
# print(insert_stmt)

# conn = get_db_connection()
# cursor = conn.cursor()
# cursor.execute(insert_stmt)
# conn.commit()
# conn.close()
