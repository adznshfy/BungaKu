from flask import Blueprint, render_template, request, session, redirect, url_for, flash
from flask_mail import Mail, Message
from random import randint
from flask_mysqldb import MySQL, MySQLdb

email_bp = Blueprint('email_bp', __name__)
mail = Mail()
mysql = None  # ini akan di-set dari app.py


@email_bp.route('/verify-email')
def verify_email():
    if 'pending_register' not in session:
        return redirect(url_for('register'))

    email = session['pending_register']['email']
    otp = randint(100000, 999999)
    session['otp'] = otp

    msg = Message(subject='Kode OTP Verifikasi', sender='naswajihaan@gmail.com', recipients=[email])
    msg.body = f"Kode OTP kamu adalah: {otp}"
    mail.send(msg)

    return render_template("verify.html", email=email)


@email_bp.route('/validate-otp', methods=["POST"])
def validate_otp():
    try:
        user_otp = int(request.form['otp'])
    except ValueError:
        flash("OTP tidak valid. Masukkan angka 6 digit.")
        return redirect(url_for('email_bp.verify_email'))

    if user_otp == session.get('otp'):
        data = session.pop('pending_register')

        cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

        # Simpan ke tabel users
        cur.execute("""
            INSERT INTO users (nama, alamat, email, phone, password, role)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (data['nama'], data['alamat'], data['email'], data['phone'], data['password'], None))

        mysql.connection.commit()

        cur.execute("SELECT LAST_INSERT_ID() as id_user")
        id_user = cur.fetchone()['id_user']

        cur.execute("""
            INSERT INTO profile (nama, email, alamat, no_telp, id_user)
            VALUES (%s, %s, %s, %s, %s)
        """, (data['nama'], data['email'], data['alamat'], data['phone'], id_user))

        mysql.connection.commit()
        cur.close()

        session['id_user'] = id_user
        session['nama'] = data['nama']
        session['email'] = data['email']

        return redirect(url_for('choose_role'))

    flash("OTP salah. Silakan coba lagi.")
    return redirect(url_for('email_bp.verify_email'))
