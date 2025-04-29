import os
from flask import Flask, render_template, redirect, request, url_for, session
from flask_mysqldb import MySQL, MySQLdb
from flask_mail import Mail
import bcrypt
from dotenv import load_dotenv
import email_verification
from werkzeug.utils import secure_filename

load_dotenv()

app = Flask(__name__)

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'jihaannaswa'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'flaskdb_new'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
mysql = MySQL(app)

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEBUG'] = True
email_verification.mail.init_app(app)

email_verification.mysql = mysql

app.secret_key = "017#!NaswaJia)!!"
app.register_blueprint(email_verification.email_bp)

app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # Maksimum 2MB

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/welcome')
def welcome():
    return render_template("welcome.html")


@app.route('/')
def home():
    return redirect(url_for('welcome'))


@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == 'GET':
        return render_template("register.html")

    nama = request.form['nama']
    alamat = request.form['alamat']
    email = request.form['email']
    phone = request.form['phone']
    password = request.form['password']

    if len(password) < 6:
        error = "Password minimal 6 karakter."
        return render_template("register.html", error=error)

    hash_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    session['pending_register'] = {
        'nama': nama,
        'alamat': alamat,
        'email': email,
        'phone': phone,
        'password': hash_password.decode('utf-8')
    }

    return redirect(url_for('email_bp.verify_email'))


@app.route('/login', methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        email = request.form['email']
        password = request.form['password'].encode('utf-8')

        cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cur.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cur.fetchone()
        cur.close()

        if user and bcrypt.checkpw(password, user['password'].encode('utf-8')):
            session['id_user'] = user['id_user']
            session['nama'] = user['nama']
            session['email'] = user['email']
            session['role'] = user.get('role')

            if not user.get('role'):
                return redirect(url_for('choose_role'))

            if user['role'] == 'pembeli':
                return redirect(url_for('home_buyer'))
            elif user['role'] == 'penjual':
                return redirect(url_for('home_seller'))
            else:
                return redirect(url_for('home'))

        else:
            error = "Gagal login. Cek kembali email atau password Anda."

    return render_template("login.html", error=error)


@app.route('/profile', methods=["GET", "POST"])
def profile():
    if 'id_user' not in session:
        return redirect(url_for('login'))

    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("SELECT * FROM profile WHERE id_user = %s", (session['id_user'],))
    profile = cur.fetchone()

    if request.method == "POST":
        nama = request.form['nama']
        nama_lengkap = request.form['nama_lengkap']
        no_telp = request.form['no_telp']
        email = request.form['email']
        alamat = request.form['alamat']
        payment = request.form['payment']

        foto = request.files.get('foto')
        filename = profile['foto'] if profile and profile.get('foto') else None

        if foto and allowed_file(foto.filename):
            ext = foto.filename.rsplit('.', 1)[1].lower()
            filename = f"user_{session['id_user']}.{ext}"
            foto.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        if profile:
            cur.execute("""
                UPDATE profile SET 
                nama=%s, nama_lengkap=%s, no_telp=%s, email=%s, alamat=%s, payment=%s, foto=%s
                WHERE id_user=%s
            """, (nama, nama_lengkap, no_telp, email, alamat, payment, filename, session['id_user']))
        else:
            cur.execute("""
                INSERT INTO profile 
                (nama, nama_lengkap, no_telp, email, alamat, payment, foto, id_user)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (nama, nama_lengkap, no_telp, email, alamat, payment, filename, session['id_user']))

        mysql.connection.commit()
        cur.close()
        return redirect(url_for('profile_changed'))

    cur.close()
    return render_template("profile.html", profile=profile)


@app.route('/logout')
def logout():
    session.clear()
    return render_template("welcome.html")


@app.route('/choose-role', methods=["GET", "POST"])
def choose_role():
    if 'id_user' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        role = request.form['role']

        cur = mysql.connection.cursor()
        cur.execute("UPDATE users SET role=%s WHERE id_user=%s", (role, session['id_user']))
        mysql.connection.commit()
        cur.close()

        session['role'] = role

        if role == 'pembeli':
            return redirect(url_for('home_buyer'))
        elif role == 'penjual':
            return redirect(url_for('home_seller'))

    return render_template('choose_role.html')


@app.route('/home-buyer')
def home_buyer():
    if session.get('role') == 'pembeli':
        return render_template('home_buyer.html')
    return redirect(url_for('home'))


@app.route('/home-seller')
def home_seller():
    if session.get('role') == 'penjual':
        return render_template('home_seller.html')
    return redirect(url_for('home'))


@app.route('/profile-changed')
def profile_changed():
    return render_template("profile_changed.html")


if __name__ == '__main__':
    app.run(debug=True)