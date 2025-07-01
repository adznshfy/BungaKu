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

    msg = Message(subject='Kode OTP Verifikasi', sender='bungaku2425@gmail.com', recipients=[email])
    msg.body = f"Kode OTP kamu adalah: {otp}"
    mail.send(msg)

    return render_template("verify.html", email=email)


@email_bp.route('/validate-otp', methods=["POST"])
def validate_otp():
    try:
        user_otp = int(request.form['otp'])
    except ValueError:
        flash("OTP tidak valid. Masukkan angka 6 digit.", "error")
        return redirect(url_for('email_bp.verify_email'))

    if user_otp == session.get('otp'):
        data = session.pop('pending_register')
        
        nama = data['nama']
        alamat = data['alamat']
        email = data['email']
        phone = data['phone']
        password = data['password']

        cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        try:
            # 1. Buat entri di tabel 'profile'
            cur.execute("""
                INSERT INTO profile (nama, alamat, no_telp) 
                VALUES (%s, %s, %s)
            """, (nama, alamat, phone))
            
            profile_id = cur.lastrowid

            # Karena 'pembeli' sekarang memiliki id_level = 4
            buyer_level_id = 4
            
            # 2. Buat entri di tabel 'users'
            cur.execute("""
                INSERT INTO users (email, password, id_level, id_profile) 
                VALUES (%s, %s, %s, %s)
            """, (email, password, buyer_level_id, profile_id))

            user_id = cur.lastrowid
            mysql.connection.commit()

            # Set session untuk user yang baru login
            session['id_user'] = user_id
            session['nama'] = nama
            session['email'] = email
            session['id_level'] = buyer_level_id
            session['id_profile'] = profile_id

            flash(f"Registrasi berhasil! Selamat datang, {nama}!", "success")
            return redirect(url_for('home_buyer'))

        except Exception as e:
            mysql.connection.rollback()
            flash(f"Terjadi kesalahan saat registrasi: {e}", "error")
            return redirect(url_for('register'))
        finally:
            cur.close()

    flash("OTP salah. Silakan coba lagi.", "error")
    return redirect(url_for('email_bp.verify_email'))