from itertools import product
import os
import time
from flask import Flask, jsonify, render_template, redirect, request, url_for, session, flash
from flask_mysqldb import MySQL, MySQLdb
from flask_mail import Mail, Message
import bcrypt
from dotenv import load_dotenv
import email_verification
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash
from datetime import datetime, timedelta
import pandas as pd
from flask import Response
import io
from io import StringIO, BytesIO
from functools import wraps
import csv
from weasyprint import HTML
import json
from decimal import Decimal
import re
from markupsafe import Markup
import secrets

load_dotenv()

app = Flask(__name__)

def markdown_link_filter(text):
    if not text:
        return ''
    # Pola regex untuk menemukan [Teks](URL)
    link_pattern = re.compile(r'\[Lihat Produk: (.*?)\]\((.*?)\)')
    # Ganti pola dengan tag <a> HTML
    linked_text = link_pattern.sub(r'<a href="\2" target="_blank" class="chat-product-link">Lihat Produk: <strong>\1</strong></a>', text)
    # Gunakan Markup agar HTML tidak di-escape oleh Jinja2
    return Markup(linked_text)

app.jinja_env.filters['markdown_link'] = markdown_link_filter

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'bungaku'
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
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.errorhandler(413)
def too_large(e):
    flash("File terlalu besar. Maksimum 2MB.", "error")
    return redirect(request.url)

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'id_user' not in session or session.get('id_level') != 1:
            flash('Anda harus login sebagai Admin untuk mengakses halaman ini.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

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

    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("SELECT email FROM users WHERE email = %s", (email,))
    existing_user = cur.fetchone()
    cur.close()
    if existing_user:
        error = "Email ini sudah terdaftar. Silakan gunakan email lain atau login."
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
        cur.execute("""
            SELECT u.id_user, u.password, u.id_level, u.id_profile, p.nama, u.email, u.is_active
            FROM users u
            JOIN profile p ON u.id_profile = p.id_profile
            WHERE u.email = %s
        """, (email,))
        user = cur.fetchone()
        cur.close()

        if user:
            if user['is_active'] == 0:
                error = "Akun anda sedang di tangguhkan"
            
            elif bcrypt.checkpw(password, user['password'].encode('utf-8')):
                session['id_user'] = user['id_user']
                session['id_profile'] = user['id_profile']
                session['id_level'] = user['id_level']
                session['nama'] = user['nama']
                session['email'] = user['email']

                flash(f"Selamat datang kembali, {user['nama']}!", "success")
                
                id_level = user['id_level']
                if id_level == 1: # Admin
                    return redirect(url_for('admin_dashboard'))
                elif id_level == 2: # Pengelola
                    return redirect(url_for('dashboard_pengelola'))
                elif id_level == 5: # Pemimpin
                    return redirect(url_for('dashboard_pimpinan'))
                elif id_level == 3: # Penjual
                    return redirect(url_for('dashboard_penjual'))
                else: # Pembeli (level 4) atau default
                    return redirect(url_for('home_buyer'))
            else:
                # Jika password salah untuk user yang aktif.
                error = "Gagal login. Cek kembali email atau password Anda."
        else:
            # Jika user dengan email tersebut tidak ditemukan.
            error = "Gagal login. Cek kembali email atau password Anda."
            
    return render_template("login.html", error=error)


@app.route('/profile', methods=["GET", "POST"])
def profile():
    if 'id_user' not in session:
        flash("Silakan login untuk melihat profil Anda.", "warning")
        return redirect(url_for('login'))

    profile_id = session['id_profile']
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    cur.execute("SELECT * FROM profile WHERE id_profile = %s", (profile_id,))
    profile_data = cur.fetchone()

    if request.method == "POST":
        nama = request.form['nama']
        no_telp = request.form['no_telp']
        alamat = request.form['alamat']
        foto = request.files.get('foto')

        foto_filename = profile_data['foto'] if profile_data else None

        if foto and foto.filename != '':
            if allowed_file(foto.filename):
                ext = foto.filename.rsplit('.', 1)[1].lower()
                new_filename = f"profile_{profile_id}_{int(time.time())}.{ext}"
                foto_filename = secure_filename(new_filename)
                
                foto.save(os.path.join(app.config['UPLOAD_FOLDER'], foto_filename))
                
                old_photo = profile_data['foto'] if profile_data else None
                if old_photo and old_photo != foto_filename:
                    old_photo_path = os.path.join(app.config['UPLOAD_FOLDER'], old_photo)
                    if os.path.exists(old_photo_path):
                        os.remove(old_photo_path)
            else:
                flash("Jenis file gambar tidak diizinkan.", "error")
                return redirect(url_for('profile'))

        cur.execute("""
            UPDATE profile SET nama=%s, no_telp=%s, alamat=%s, foto=%s
            WHERE id_profile=%s
        """, (nama, no_telp, alamat, foto_filename, profile_id))
        mysql.connection.commit()

        session['nama'] = nama
        
        flash("Profil Anda berhasil diperbarui!", "success")
        cur.close()
        return redirect(url_for('profile'))

    cur.close()
    return render_template("profile.html", profile=profile_data, id_level=session.get('id_level'))


@app.route('/registrasi-penjual', methods=['GET'])
def registrasi_penjual():
    if session.get('id_level') != 4:
        flash("Anda sudah terdaftar sebagai penjual atau aksi tidak diizinkan.", "warning")
        return redirect(url_for('profile'))
    
    return render_template('registrasi_penjual.html')

@app.route('/proses-registrasi-penjual', methods=['POST'])
def proses_registrasi_penjual():
    if session.get('id_level') != 4:
        return redirect(url_for('home_buyer'))

    nama_toko = request.form['nama_toko']
    username_toko = request.form['username_toko'].lower().strip()
    no_hp_toko = request.form['no_hp_toko']
    alamat_toko = request.form['alamat_toko']
    deskripsi_toko = request.form['deskripsi_toko']
    user_id = session['id_user']
    pembayaran_list = request.form.getlist('pembayaran')
    pengiriman_list = request.form.getlist('pengiriman')

    # --- 2. BLOK VALIDASI WAJIB ISI ---
    errors = []
    if not nama_toko: errors.append("Nama Toko")
    if not username_toko: errors.append("Username Toko")
    if not no_hp_toko: errors.append("Nomor HP Penjual")
    if not alamat_toko: errors.append("Alamat Toko")
    if not deskripsi_toko: errors.append("Deskripsi Toko")
    if not pembayaran_list: errors.append("Metode Pembayaran (minimal pilih satu)")
    if not pengiriman_list: errors.append("Opsi Pengiriman (minimal pilih satu)")
    
    # Validasi khusus untuk file
    if 'foto_toko' not in request.files or request.files['foto_toko'].filename == '':
        errors.append("Foto Toko")

    # Jika list 'errors' ada isinya, berarti ada data yang kosong
    if errors:
        error_message = "Lengkapin data dulu! Field berikut wajib diisi: " + ", ".join(errors) + "."
        flash(error_message, "error")
        return redirect(url_for('registrasi_penjual'))
    # --- AKHIR BLOK VALIDASI ---

    # --- 3. Lanjutan: Validasi Username Unik ---
    cur_check = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur_check.execute("SELECT id_toko FROM toko WHERE username_toko = %s", (username_toko,))
    if cur_check.fetchone():
        flash(f"Username toko '{username_toko}' sudah digunakan. Silakan pilih yang lain.", "error")
        cur_check.close()
        return redirect(url_for('registrasi_penjual'))
    cur_check.close()

    # --- 4. Proses Upload Foto Toko ---
    foto_filename = None
    foto_file = request.files['foto_toko']
    if allowed_file(foto_file.filename):
        ext = foto_file.filename.rsplit('.', 1)[1].lower()
        new_filename = f"toko_{user_id}_{int(time.time())}.{ext}"
        foto_filename = secure_filename(new_filename)
        foto_file.save(os.path.join(app.config['UPLOAD_FOLDER'], foto_filename))
    else:
        flash("Jenis file gambar tidak diizinkan (hanya png, jpg, jpeg, gif).", "error")
        return redirect(url_for('registrasi_penjual'))

    # --- 5. Gabungkan list checkbox menjadi satu string ---
    metode_pembayaran_str = ",".join(pembayaran_list)
    metode_pengiriman_str = ",".join(pengiriman_list)
    
    # --- 6. Simpan semua data ke database ---
    cur = mysql.connection.cursor()
    try:
        cur.execute("""
            INSERT INTO toko (nama_toko, username_toko, no_hp_toko, deskripsi_toko, alamat_toko, foto_toko, metode_pembayaran, metode_pengiriman, id_user)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (nama_toko, username_toko, no_hp_toko, deskripsi_toko, alamat_toko, foto_filename, metode_pembayaran_str, metode_pengiriman_str, user_id))

        cur.execute("UPDATE users SET id_level = 3 WHERE id_user = %s", (user_id,))
        
        mysql.connection.commit()

        session['id_level'] = 3
        flash(f"Selamat! Toko '{nama_toko}' Anda berhasil dibuat.", "success")
        
        return redirect(url_for('dashboard_penjual'))

    except Exception as e:
        mysql.connection.rollback()
        flash(f"Terjadi kesalahan saat membuat toko: {e}", "error")
        return redirect(url_for('registrasi_penjual'))
    finally:
        cur.close()

@app.route('/logout')
def logout():
    session.clear()
    flash("Anda telah berhasil logout.", "info")
    return redirect(url_for('welcome'))

# Tambahkan fungsi ini di app.py
@app.route('/set-pin', methods=['GET', 'POST'])
def set_pin():
    if 'id_user' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        pin1 = request.form['pin1']
        pin2 = request.form['pin2']

        # Validasi
        if not pin1.isdigit() or len(pin1) != 6:
            flash("PIN harus terdiri dari 6 angka.", "error")
            return redirect(url_for('set_pin'))
        if pin1 != pin2:
            flash("PIN dan konfirmasi PIN tidak cocok.", "error")
            return redirect(url_for('set_pin'))

        # Hash PIN sebelum disimpan
        pin_hash = bcrypt.hashpw(pin1.encode('utf-8'), bcrypt.gensalt())

        user_id = session['id_user']
        cur = mysql.connection.cursor()
        cur.execute("UPDATE users SET pin_hash = %s WHERE id_user = %s", (pin_hash, user_id))
        mysql.connection.commit()
        cur.close()

        flash("PIN Keamanan Anda berhasil diperbarui!", "success")
        return redirect(url_for('profile'))

    return render_template('set_pin.html')

@app.route('/ganti-password', methods=['GET', 'POST'])
def ganti_password():
    if 'id_user' not in session:
        flash("Anda harus login untuk mengakses halaman ini.", "warning")
        return redirect(url_for('login'))

    if request.method == 'POST':
        old_password = request.form['old_password']
        new_password = request.form['new_password']
        confirm_new_password = request.form['confirm_new_password']

        if new_password != confirm_new_password:
            flash("Password baru dan konfirmasi password tidak cocok.", "error")
            return redirect(url_for('ganti_password'))
        
        if len(new_password) < 6:
            flash("Password baru minimal harus 6 karakter.", "error")
            return redirect(url_for('ganti_password'))

        user_id = session['id_user']
        cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cur.execute("SELECT password FROM users WHERE id_user = %s", (user_id,))
        user = cur.fetchone()

        if user and bcrypt.checkpw(old_password.encode('utf-8'), user['password'].encode('utf-8')):
            new_hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
            
            cur.execute("UPDATE users SET password = %s WHERE id_user = %s", 
                        (new_hashed_password.decode('utf-8'), user_id))
            mysql.connection.commit()
            cur.close()
            
            flash("Password Anda berhasil diubah.", "success")
            return redirect(url_for('profile')) # Arahkan kembali ke profil setelah sukses
        else:
            cur.close()
            flash("Password lama yang Anda masukkan salah.", "error")
            return redirect(url_for('ganti_password'))

    # Jika metodenya GET, tampilkan halaman formulirnya
    return render_template('ganti_password.html')

def send_reset_email(user):
    token = secrets.token_urlsafe(32)
    expiry = datetime.utcnow() + timedelta(hours=1) # Token berlaku 1 jam

    cur = mysql.connection.cursor()
    cur.execute("UPDATE users SET reset_token = %s, reset_token_expiry = %s WHERE id_user = %s", (token, expiry, user['id_user']))
    mysql.connection.commit()
    cur.close()

    # Buat link reset
    reset_url = url_for('reset_password', token=token, _external=True)

    # Kirim email
    msg = Message('Link Reset Password - BungaKu',
                  sender=os.getenv('MAIL_USERNAME'),
                  recipients=[user['email']])
    msg.body = f'''Untuk mereset password Anda, silakan kunjungi link berikut:
{reset_url}

Jika Anda tidak merasa meminta reset password, abaikan email ini.
Link ini akan kedaluwarsa dalam 1 jam.
'''
    email_verification.mail.send(msg)

@app.route('/request-reset', methods=['GET', 'POST'])
def request_reset():
    if request.method == 'POST':
        email = request.form['email']
        cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cur.fetchone()
        cur.close()

        if user:
            send_reset_email(user) # Panggil fungsi helper
        
        # Pesan ini ditampilkan baik user ada atau tidak, demi keamanan
        flash('Jika email Anda terdaftar, link untuk mereset password telah dikirim.', 'info')
        return redirect(url_for('login'))

    return render_template('request_reset.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    # CARI USER DENGAN TOKEN VALID DAN GUNAKAN UTC_TIMESTAMP()
    cur.execute("SELECT * FROM users WHERE reset_token = %s AND reset_token_expiry > UTC_TIMESTAMP()", (token,))
    user = cur.fetchone()

    if not user:
        cur.close()
        flash('Token reset password tidak valid atau sudah kedaluwarsa.', 'error')
        return redirect(url_for('request_reset'))

    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Password dan konfirmasi password tidak cocok.', 'error')
            return redirect(url_for('reset_password', token=token))
        
        if len(password) < 6:
            flash('Password minimal 6 karakter.', 'error')
            return redirect(url_for('reset_password', token=token))

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        cur.execute("""
            UPDATE users SET password = %s, reset_token = NULL, reset_token_expiry = NULL
            WHERE id_user = %s
        """, (hashed_password.decode('utf-8'), user['id_user']))
        mysql.connection.commit()
        cur.close()

        flash('Password Anda telah berhasil direset! Silakan login.', 'success')
        return redirect(url_for('login'))

    cur.close()
    return render_template('reset_password.html', token=token)
# Ganti fungsi home_buyer yang lama dengan yang ini di app.py

# Ganti seluruh fungsi home_buyer() Anda dengan kode ini
@app.route("/home-buyer")
def home_buyer():
    # --- PENJAGA BARU ---
    # Hanya pembeli (4) dan penjual (3) yang boleh masuk
    if 'id_user' not in session or session.get('id_level') not in [3, 4]:

        # Arahkan petinggi ke dashboard mereka masing-masing jika mencoba akses
        id_level = session.get('id_level')
        if id_level == 1: return redirect(url_for('admin_dashboard'))
        if id_level == 2: return redirect(url_for('dashboard_pengelola'))
        if id_level == 5: return redirect(url_for('dashboard_pimpinan'))

        # Jika tidak ada sesi, arahkan ke login
        flash("Halaman ini tidak tersedia untuk peran Anda.", "error")
        return redirect(url_for('login'))
    # --- AKHIR PENJAGA ---

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    
    cursor.execute("SELECT * FROM categories ORDER BY name ASC")
    categories = cursor.fetchall()
    
    cursor.execute("""
        SELECT 
            p.id, p.name, p.description, p.id_user, 
            t.nama_toko, t.username_toko,
            c.name as category_name, c.slug as category_slug,
            (SELECT nama_file_gambar FROM product_images WHERE id_produk = p.id ORDER BY id ASC LIMIT 1) as main_image,
            (SELECT MIN(harga) FROM product_variations WHERE id_produk = p.id) as min_price
        FROM products p
        JOIN users u ON p.id_user = u.id_user
        JOIN toko t ON u.id_user = t.id_user
        LEFT JOIN categories c ON p.id_kategori = c.id
        WHERE p.is_active = 1
    """)
    produk = cursor.fetchall()
    cursor.close()

    return render_template("home_buyer.html", produk=produk, categories=categories)

@app.route('/category/<string:slug>')
def products_by_category(slug):
    if 'id_user' not in session or session.get('id_level') not in [3, 4]:
        return redirect(url_for('login'))

    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    # Ambil detail kategori yang aktif berdasarkan slug
    cur.execute("SELECT * FROM categories WHERE slug = %s", (slug,))
    active_category = cur.fetchone()

    if not active_category:
        flash("Kategori tidak ditemukan.", "error")
        return redirect(url_for('home_buyer'))

    # Ambil semua kategori untuk navigasi
    cur.execute("SELECT * FROM categories ORDER BY name ASC")
    all_categories = cur.fetchall()

    # Ambil semua produk yang termasuk dalam kategori ini
    cur.execute("""
        SELECT 
            p.id, p.name, p.description, p.id_user, 
            t.nama_toko, t.username_toko,
            (SELECT nama_file_gambar FROM product_images WHERE id_produk = p.id ORDER BY id ASC LIMIT 1) as main_image,
            (SELECT MIN(harga) FROM product_variations WHERE id_produk = p.id) as min_price
        FROM products p
        JOIN users u ON p.id_user = u.id_user
        JOIN toko t ON u.id_user = t.id_user
        WHERE p.is_active = 1 AND p.id_kategori = %s
    """, (active_category['id'],))
    produk_in_category = cur.fetchall()
    cur.close()

    # Kita bisa menggunakan template home_buyer.html lagi
    return render_template("home_buyer.html", 
                           produk=produk_in_category, 
                           categories=all_categories,
                           active_category=active_category)

@app.route('/dashboard-penjual')
def dashboard_penjual():
    if session.get('id_level') != 3:
        flash("Halaman ini hanya untuk penjual.", "error")
        return redirect(url_for('home_buyer'))

    user_id = session['id_user']
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    # 1. Ambil Informasi Toko
    cur.execute("SELECT * FROM toko WHERE id_user = %s", (user_id,))
    toko_info = cur.fetchone()
    if not toko_info:
        flash("Silakan lengkapi data toko Anda terlebih dahulu.", "warning")
        cur.close()
        return redirect(url_for('registrasi_penjual'))

    # 2. Ambil Daftar Produk
    cur.execute("""
    SELECT 
        p.id, p.name,p.is_active,
        (SELECT nama_file_gambar FROM product_images WHERE id_produk = p.id ORDER BY id ASC LIMIT 1) as main_image,
        (SELECT MIN(harga) FROM product_variations WHERE id_produk = p.id AND is_active = 1) as min_price,
        (SELECT SUM(stok) FROM product_variations WHERE id_produk = p.id AND is_active = 1) as total_stock
    FROM products p
    WHERE p.id_user = %s
    ORDER BY p.id DESC
    """, (user_id,))
    daftar_produk = cur.fetchall()

    # 3. Mengambil Pesanan yang Masuk (tidak ada perubahan di sini)
    cur.execute("""
        SELECT t.*, p.nama as nama_pembeli 
        FROM transaksi t
        JOIN users u ON t.id_user = u.id_user
        JOIN profile p ON u.id_profile = p.id_profile
        WHERE t.id_transaksi IN (
            SELECT DISTINCT ti.id_transaksi 
            FROM transaksi_items ti 
            JOIN products p ON ti.id_produk = p.id 
            WHERE p.id_user = %s
        ) AND t.status = 'diproses'
        ORDER BY t.tanggal_pesanan ASC
    """, (user_id,))
    pesanan_masuk = cur.fetchall()

    for pesanan in pesanan_masuk:
        cur.execute("""
            SELECT ti.kuantitas, ti.harga_saat_beli, p.name as product_name
            FROM transaksi_items ti
            JOIN products p ON ti.id_produk = p.id
            WHERE ti.id_transaksi = %s AND p.id_user = %s
        """, (pesanan['id_transaksi'], user_id))
        pesanan['detail_items'] = cur.fetchall()
        
        cur.execute("""
        SELECT r.*, p.nama as nama_pembeli
        FROM retur_barang r
        JOIN users u ON r.id_pembeli = u.id_user
        JOIN profile p ON u.id_profile = p.id_profile
        WHERE r.id_transaksi IN (
            SELECT DISTINCT ti.id_transaksi
            FROM transaksi_items ti
            JOIN products pr ON ti.id_produk = pr.id
            WHERE pr.id_user = %s
        )
        ORDER BY r.tanggal_ajuan DESC
    """, (user_id,))
    daftar_retur = cur.fetchall()

    # 5. Parsing (membongkar) JSON item yang diretur menjadi list Python
    for retur in daftar_retur:
        if retur.get('item_diretur'):
            try:
                # Muat string JSON dari DB menjadi list/dictionary
                retur['item_diretur_list'] = json.loads(retur['item_diretur'])
            except (json.JSONDecodeError, TypeError):
                # Jika ada error atau data kosong, buat list kosong
                retur['item_diretur_list'] = []
        else:
            retur['item_diretur_list'] = []

    cur.close()

    return render_template("dashboard_penjual.html", 
                           toko=toko_info, 
                           produk=daftar_produk, 
                           pesanan_masuk=pesanan_masuk,
                           daftar_retur=daftar_retur)

@app.route('/data-penjualan')
def data_penjualan():
    # Keamanan: Pastikan hanya penjual yang bisa akses
    if 'id_user' not in session or session.get('id_level') != 3:
        flash("Halaman ini hanya untuk penjual.", "error")
        return redirect(url_for('home_buyer'))

    user_id = session['id_user']
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    # 1. Ambil KPI Utama (Key Performance Indicators)
    cur.execute("""
        SELECT 
            SUM(ti.harga_saat_beli * ti.kuantitas) as total_pendapatan,
            COUNT(DISTINCT t.id_transaksi) as total_pesanan,
            SUM(ti.kuantitas) as item_terjual
        FROM transaksi_items ti
        JOIN products p ON ti.id_produk = p.id
        JOIN transaksi t ON ti.id_transaksi = t.id_transaksi
        WHERE p.id_user = %s AND t.status IN ('selesai', 'retur_selesai')
    """, (user_id,))
    kpi = cur.fetchone()

    # 2. Ambil data untuk Diagram Garis (Penjualan 30 Hari Terakhir)
    cur.execute("""
        SELECT DATE(t.tanggal_pesanan) as tanggal, SUM(ti.harga_saat_beli * ti.kuantitas) as pendapatan_harian
        FROM transaksi_items ti
        JOIN products p ON ti.id_produk = p.id
        JOIN transaksi t ON ti.id_transaksi = t.id_transaksi
        WHERE p.id_user = %s AND t.status IN ('selesai', 'retur_selesai') AND t.tanggal_pesanan >= CURDATE() - INTERVAL 30 DAY
        GROUP BY DATE(t.tanggal_pesanan)
        ORDER BY tanggal ASC
    """, (user_id,))
    penjualan_harian = cur.fetchall()
    line_chart_labels = [item['tanggal'].strftime('%d %b') for item in penjualan_harian]
    line_chart_data = [float(item['pendapatan_harian']) for item in penjualan_harian]

    # 3. Ambil data untuk Diagram Batang (Top 5 Produk Terlaris)
    cur.execute("""
        SELECT p.name, SUM(ti.kuantitas) as total_terjual
        FROM transaksi_items ti
        JOIN products p ON ti.id_produk = p.id
        JOIN transaksi t ON ti.id_transaksi = t.id_transaksi
        WHERE p.id_user = %s AND t.status IN ('selesai', 'retur_selesai')
        GROUP BY p.id
        ORDER BY total_terjual DESC
        LIMIT 5
    """, (user_id,))
    top_produk = cur.fetchall()
    bar_chart_labels = [item['name'] for item in top_produk]
    bar_chart_data = [item['total_terjual'] for item in top_produk]

    cur.close()

    return render_template('data_penjualan.html', 
                           kpi=kpi,
                           line_chart_labels=line_chart_labels,
                           line_chart_data=line_chart_data,
                           bar_chart_labels=bar_chart_labels,
                           bar_chart_data=bar_chart_data)


@app.route('/download-laporan-penjualan')
def download_laporan_penjualan():
    # Keamanan: Pastikan hanya penjual yang bisa akses
    if 'id_user' not in session or session.get('id_level') != 3:
        return redirect(url_for('home_buyer'))

    user_id = session['id_user']
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    
    # Ambil data transaksi yang lebih detail untuk laporan
    cur.execute("""
        SELECT 
            t.id_transaksi,
            t.tanggal_pesanan,
            p.name as nama_produk,
            pv.nama_varian,
            ti.kuantitas,
            ti.harga_saat_beli,
            (ti.kuantitas * ti.harga_saat_beli) as subtotal
        FROM transaksi_items ti
        JOIN transaksi t ON ti.id_transaksi = t.id_transaksi
        JOIN products p ON ti.id_produk = p.id
        LEFT JOIN product_variations pv ON ti.id_varian = pv.id
        WHERE p.id_user = %s AND t.status IN ('selesai', 'retur_selesai')
        ORDER BY t.tanggal_pesanan DESC
    """, (user_id,))
    data = cur.fetchall()
    cur.close()

    # Buat file Excel menggunakan Pandas
    df = pd.DataFrame(data)
    output = io.BytesIO()
    # Gunakan 'with' untuk memastikan writer tertutup dengan benar
    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        df.to_excel(writer, sheet_name='Laporan Penjualan', index=False)
    output.seek(0)
    
    return Response(output, 
                    mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    headers={"Content-Disposition": "attachment;filename=laporan_penjualan_toko_anda.xlsx"})

@app.route('/edit-toko', methods=['GET'])
def edit_toko():
    if session.get('id_level') != 3:
        return redirect(url_for('home_buyer'))

    user_id = session['id_user']
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("SELECT * FROM toko WHERE id_user = %s", (user_id,))
    toko_data = cur.fetchone()
    cur.close()

    if not toko_data:
        return redirect(url_for('dashboard_penjual'))

    # --- INI BAGIAN YANG DIPERBAIKI ---
    # Ambil data string dari database
    pembayaran_str = toko_data.get('metode_pembayaran')
    pengiriman_str = toko_data.get('metode_pengiriman')

    # Jika stringnya ada isinya, baru di-split. Jika tidak (None/NULL), buat list kosong.
    toko_data['list_pembayaran'] = pembayaran_str.split(',') if pembayaran_str else []
    toko_data['list_pengiriman'] = pengiriman_str.split(',') if pengiriman_str else []
    # ------------------------------------
    
    return render_template('edit_toko.html', toko=toko_data)

# Ganti fungsi update_toko() (jika sudah ada) dengan yang ini
@app.route('/update-toko', methods=['POST'])
def update_toko():
    # Penjaga keamanan
    if session.get('id_level') != 3:
        return redirect(url_for('home_buyer'))

    # Ambil semua data dari form yang dikirim
    user_id = session['id_user']
    nama_toko = request.form['nama_toko']
    no_hp_toko = request.form['no_hp_toko']
    deskripsi_toko = request.form['deskripsi_toko']
    alamat_toko = request.form['alamat_toko']
    pembayaran_list = request.form.getlist('pembayaran')
    pengiriman_list = request.form.getlist('pengiriman')

    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    # Ambil nama file foto & banner yang LAMA dari database untuk jaga-jaga jika mau dihapus
    cur.execute("SELECT foto_toko, banner_toko FROM toko WHERE id_user = %s", (user_id,))
    file_data = cur.fetchone()
    foto_filename = file_data.get('foto_toko')
    banner_filename = file_data.get('banner_toko')

    # --- Proses FOTO TOKO / LOGO (jika ada file baru diupload) ---
    if 'foto_toko' in request.files and request.files['foto_toko'].filename != '':
        foto_file = request.files['foto_toko']
        if allowed_file(foto_file.filename):
            # Hapus foto lama jika ada
            if foto_filename:
                old_photo_path = os.path.join(app.config['UPLOAD_FOLDER'], foto_filename)
                if os.path.exists(old_photo_path):
                    os.remove(old_photo_path)
            
            # Simpan foto baru dengan nama unik
            ext = foto_file.filename.rsplit('.', 1)[1].lower()
            new_filename = f"toko_{user_id}_{int(time.time())}.{ext}"
            foto_filename = secure_filename(new_filename)
            foto_file.save(os.path.join(app.config['UPLOAD_FOLDER'], foto_filename))
        else:
            flash("Jenis file logo/foto tidak diizinkan.", "error")
            return redirect(url_for('edit_toko'))

    # --- Proses BANNER TOKO (jika ada file baru diupload) ---
    if 'banner_toko' in request.files and request.files['banner_toko'].filename != '':
        banner_file = request.files['banner_toko']
        if allowed_file(banner_file.filename):
            # Hapus banner lama jika ada
            if banner_filename:
                old_banner_path = os.path.join(app.config['UPLOAD_FOLDER'], banner_filename)
                if os.path.exists(old_banner_path):
                    os.remove(old_banner_path)
            
            # Simpan banner baru dengan nama unik
            ext = banner_file.filename.rsplit('.', 1)[1].lower()
            new_banner_filename = f"banner_{user_id}_{int(time.time())}.{ext}"
            banner_filename = secure_filename(new_banner_filename)
            banner_file.save(os.path.join(app.config['UPLOAD_FOLDER'], banner_filename))
        else:
            flash("Jenis file banner tidak diizinkan.", "error")
            return redirect(url_for('edit_toko'))

    # Gabungkan list checkbox menjadi string untuk disimpan ke DB
    metode_pembayaran_str = ",".join(pembayaran_list)
    metode_pengiriman_str = ",".join(pengiriman_list)
    
    # Query UPDATE ke database dengan semua data baru
    cur.execute("""
        UPDATE toko 
        SET nama_toko=%s, no_hp_toko=%s, deskripsi_toko=%s, alamat_toko=%s, 
            foto_toko=%s, banner_toko=%s, 
            metode_pembayaran=%s, metode_pengiriman=%s
        WHERE id_user=%s
    """, (nama_toko, no_hp_toko, deskripsi_toko, alamat_toko, 
          foto_filename, banner_filename, 
          metode_pembayaran_str, metode_pengiriman_str, user_id))
    mysql.connection.commit()
    cur.close()

    flash("Profil toko berhasil diperbarui!", "success")
    return redirect(url_for('dashboard_penjual'))

@app.route('/proses-pesanan/<int:transaksi_id>', methods=['POST'])
def proses_pesanan(transaksi_id):
    if session.get('id_level') != 3:
        flash("Aksi tidak diizinkan.", "error")
        return redirect(url_for('home_buyer'))

    nomor_resi = request.form.get('nomor_resi')
    if not nomor_resi:
        flash("Nomor resi wajib diisi.", "error")
        return redirect(url_for('dashboard_penjual'))

    cur = mysql.connection.cursor()
    cur.execute("UPDATE transaksi SET status = 'dikirim', nomor_resi = %s WHERE id_transaksi = %s", (nomor_resi, transaksi_id,))
    mysql.connection.commit()
    cur.close()

    flash(f"Pesanan #{transaksi_id} telah ditandai sebagai 'Dikirim' dengan resi {nomor_resi}.", "success")
    return redirect(url_for('dashboard_penjual'))

@app.route('/produk/<int:product_id>')
def product_detail(product_id):
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    
    # 1. Ambil data produk & toko
    cur.execute("""
        SELECT p.*, t.nama_toko, t.username_toko
        FROM products p
        JOIN users u ON p.id_user = u.id_user
        JOIN toko t ON u.id_user = t.id_user
        WHERE p.id = %s
    """, (product_id,))
    product = cur.fetchone()
    if not product:
        flash("Produk tidak ditemukan.", "error")
        cur.close()
        return redirect(url_for('home_buyer'))
    
    is_owner = session.get('id_user') == product.get('id_user')
    if not product['is_active'] and not is_owner:
        flash("Produk ini sedang tidak tersedia.", "error")
        cur.close()
        return redirect(url_for('home_buyer'))
    
    is_in_wishlist = False
    if 'id_user' in session:
        cur.execute("SELECT id FROM wishlist WHERE id_user = %s AND id_produk = %s", (session['id_user'], product_id))
        if cur.fetchone():
            is_in_wishlist = True
        
    # 2. Ambil gambar & varian
    cur.execute("SELECT * FROM product_images WHERE id_produk = %s", (product_id,))
    images = cur.fetchall()
    
    # [PERBAIKAN ADA DI SINI] Hanya mengambil varian dengan is_active = 1
    cur.execute("SELECT * FROM product_variations WHERE id_produk = %s AND is_active = 1 ORDER BY harga ASC", (product_id,))
    variations = cur.fetchall()

    # 3. Ambil SEMUA ulasan
    cur.execute("""
        SELECT r.*, prof.nama as nama_pembeli, prof.foto as foto_pembeli
        FROM product_ratings r
        JOIN users u ON r.id_user = u.id_user
        JOIN profile prof ON u.id_profile = prof.id_profile
        WHERE r.id_produk = %s ORDER BY r.tanggal_rating DESC
    """, (product_id,))
    reviews = cur.fetchall()
    
    # 4. Hitung ringkasan rating (rata-rata & total)
    cur.execute("SELECT AVG(rating) as avg_rating, COUNT(id) as total_ratings FROM product_ratings WHERE id_produk = %s", (product_id,))
    rating_summary = cur.fetchone()

    # 5. Hitung JUMLAH untuk setiap bintang (5, 4, 3, 2, 1)
    cur.execute("""
        SELECT rating, COUNT(id) as count 
        FROM product_ratings 
        WHERE id_produk = %s 
        GROUP BY rating
    """, (product_id,))
    rating_counts_raw = cur.fetchall()
    rating_counts = {item['rating']: item['count'] for item in rating_counts_raw}

    cur.close()
    
    return render_template('product_detail.html', 
                           product=product, 
                           images=images, 
                           variations=variations, 
                           reviews=reviews, 
                           rating_summary=rating_summary,
                           rating_counts=rating_counts,
                           is_in_wishlist=is_in_wishlist)
    
# Tambahkan fungsi baru ini di app.py

@app.route('/get-reviews/<int:product_id>')
def get_reviews(product_id):
    # Ambil filter rating dari parameter URL, contoh: /get-reviews/1?rating=5
    rating_filter = request.args.get('rating', type=int)

    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    # Kita butuh info produk untuk form balasan penjual
    cur.execute("SELECT id_user FROM products WHERE id = %s", (product_id,))
    product = cur.fetchone()

    # Siapkan query dasar
    query = """
        SELECT r.*, prof.nama as nama_pembeli, prof.foto as foto_pembeli
        FROM product_ratings r
        JOIN users u ON r.id_user = u.id_user
        JOIN profile prof ON u.id_profile = prof.id_profile
        WHERE r.id_produk = %s
    """
    params = [product_id]

    # Jika ada filter rating, tambahkan kondisi ke query
    if rating_filter and rating_filter in [1, 2, 3, 4, 5]:
        query += " AND r.rating = %s"
        params.append(rating_filter)
    
    query += " ORDER BY r.tanggal_rating DESC"
    
    cur.execute(query, tuple(params))
    reviews = cur.fetchall()
    cur.close()

    # Render HANYA bagian daftar ulasan menjadi sebuah string HTML
    html_reviews = render_template('_reviews_list.html', reviews=reviews, product=product)

    # Kembalikan sebagai JSON
    return jsonify({'html': html_reviews})
    
@app.route('/chat/initiate/penjual/<int:penjual_id>')
def initiate_chat(penjual_id):
    if 'id_user' not in session:
        flash("Anda harus login untuk memulai percakapan.", "error")
        return redirect(url_for('login'))

    pembeli_id = session['id_user']

    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    
    # Cek apakah percakapan sudah ada
    cur.execute("SELECT id FROM percakapan WHERE id_pembeli = %s AND id_penjual = %s", (pembeli_id, penjual_id))
    percakapan = cur.fetchone()

    if percakapan:
        id_percakapan = percakapan['id']
    else:
        # Jika belum ada, buat percakapan baru
        cur.execute("""
            INSERT INTO percakapan (id_pembeli, id_penjual) VALUES (%s, %s)
        """, (pembeli_id, penjual_id))
        mysql.connection.commit()
        id_percakapan = cur.lastrowid
    
    cur.close()
    return redirect(url_for('chat_room', percakapan_id=id_percakapan))


@app.route('/chat/room/<int:percakapan_id>', methods=['GET', 'POST'])
def chat_room(percakapan_id):
    if 'id_user' not in session:
        return redirect(url_for('login'))

    user_id = session['id_user']
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    # Keamanan: Pastikan user adalah bagian dari percakapan
    percakapan = cur.execute("SELECT * FROM percakapan WHERE id = %s AND (id_pembeli = %s OR id_penjual = %s)", 
                (percakapan_id, user_id, user_id))
    percakapan = cur.fetchone()

    if not percakapan:
        flash("Anda tidak memiliki akses ke percakapan ini.", "error")
        cur.close()
        return redirect(url_for('inbox'))

    if request.method == 'POST':
        isi_pesan = request.form.get('isi_pesan')
        id_pesan_balasan = request.form.get('id_pesan_balasan') # Ambil ID balasan
        
        # Jika id balasan kosong, simpan sebagai NULL
        if not id_pesan_balasan:
            id_pesan_balasan = None

        if isi_pesan:
            cur.execute("""
                INSERT INTO pesan_chat (id_percakapan, id_pengirim, isi_pesan, id_pesan_balasan) 
                VALUES (%s, %s, %s, %s)
            """, (percakapan_id, user_id, isi_pesan, id_pesan_balasan))
            # Update tanggal terakhir percakapan
            cur.execute("UPDATE percakapan SET tanggal_update_terakhir = NOW() WHERE id = %s", (percakapan_id,))
            mysql.connection.commit()
        return redirect(url_for('chat_room', percakapan_id=percakapan_id))

    # Ambil semua pesan dalam percakapan
    daftar_pesan = cur.execute("""
        SELECT pc.*, p.nama as nama_pengirim 
        FROM pesan_chat pc JOIN users u ON pc.id_pengirim = u.id_user
        JOIN profile p ON u.id_profile = p.id_profile
        WHERE pc.id_percakapan = %s ORDER BY pc.tanggal_kirim ASC
    """, (percakapan_id,))
    daftar_pesan = cur.fetchall()
    
    pesan_dict = {p['id']: p for p in daftar_pesan}

    # Tentukan info lawan bicara
    lawan_bicara_id = percakapan['id_penjual'] if user_id == percakapan['id_pembeli'] else percakapan['id_pembeli']
    cur.execute("""
        SELECT u.id_level, p.nama, p.foto, t.nama_toko, t.foto_toko 
        FROM users u 
        LEFT JOIN profile p ON u.id_profile = p.id_profile 
        LEFT JOIN toko t ON u.id_user = t.id_user 
        WHERE u.id_user = %s
    """, (lawan_bicara_id,))
    lawan_bicara_raw = cur.fetchone()
    
    lawan_bicara_info = {
        'nama': lawan_bicara_raw['nama_toko'] if lawan_bicara_raw['id_level'] == 3 else lawan_bicara_raw['nama'],
        'foto': lawan_bicara_raw['foto_toko'] if lawan_bicara_raw['id_level'] == 3 else lawan_bicara_raw['foto']
    }
        
    id_penjual_chat = percakapan['id_penjual']
    cur.execute("""
        SELECT id, name, (SELECT nama_file_gambar FROM product_images WHERE id_produk = p.id ORDER BY id ASC LIMIT 1) as main_image
        FROM products p
        WHERE id_user = %s AND is_active = 1
    """, (id_penjual_chat,))
    seller_products = cur.fetchall()

    cur.close()
    return render_template('chat_room.html', 
                           percakapan=percakapan, 
                           pesan=daftar_pesan, 
                           pesan_dict=pesan_dict,
                           lawan_bicara=lawan_bicara_info,
                           seller_products=seller_products)


@app.route('/inbox')
def inbox():
    if 'id_user' not in session:
        return redirect(url_for('login'))
        
    user_id = session['id_user']
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    # Ambil semua percakapan yang melibatkan user ini
    cur.execute("""
        SELECT 
            p.id, 
            p.tanggal_update_terakhir,
            CASE 
                WHEN p.id_pembeli = %s THEN t.nama_toko 
                ELSE pembeli_prof.nama 
            END as nama_lawan_bicara,
            CASE 
                WHEN p.id_pembeli = %s THEN t.foto_toko 
                ELSE pembeli_prof.foto 
            END as foto_lawan_bicara,
            (SELECT isi_pesan FROM pesan_chat WHERE id_percakapan = p.id ORDER BY tanggal_kirim DESC LIMIT 1) as pesan_terakhir
        FROM percakapan p
        JOIN users pembeli ON p.id_pembeli = pembeli.id_user
        JOIN profile pembeli_prof ON pembeli.id_profile = pembeli_prof.id_profile
        JOIN users penjual ON p.id_penjual = penjual.id_user
        JOIN toko t ON penjual.id_user = t.id_user
        WHERE p.id_pembeli = %s OR p.id_penjual = %s
        ORDER BY p.tanggal_update_terakhir DESC
    """, (user_id, user_id, user_id, user_id))
    daftar_percakapan = cur.fetchall()
    cur.close()
    
    return render_template('inbox.html', daftar_percakapan=daftar_percakapan)

@app.route('/wishlist/toggle/<int:product_id>', methods=['POST'])
def wishlist_toggle(product_id):
    if 'id_user' not in session:
        flash("Anda harus login untuk menggunakan wishlist.", "error")
        return redirect(url_for('login'))

    user_id = session['id_user']
    cur = mysql.connection.cursor()
    
    # Cek apakah item sudah ada di wishlist
    cur.execute("SELECT id FROM wishlist WHERE id_user = %s AND id_produk = %s", (user_id, product_id))
    item = cur.fetchone()

    if item:
        # Jika ada, hapus dari wishlist
        cur.execute("DELETE FROM wishlist WHERE id_user = %s AND id_produk = %s", (user_id, product_id))
        flash('Produk telah dihapus dari wishlist.', 'info')
    else:
        # Jika tidak ada, tambahkan ke wishlist
        cur.execute("INSERT INTO wishlist (id_user, id_produk) VALUES (%s, %s)", (user_id, product_id))
        flash('Produk berhasil ditambahkan ke wishlist!', 'success')
    
    mysql.connection.commit()
    cur.close()
    return redirect(request.referrer or url_for('home_buyer'))


@app.route('/wishlist')
def wishlist():
    if 'id_user' not in session:
        flash("Anda harus login untuk melihat wishlist.", "error")
        return redirect(url_for('login'))

    user_id = session['id_user']
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    
    # Ambil semua produk dalam wishlist pengguna beserta detailnya
    cur.execute("""
        SELECT 
            p.id, p.name, t.nama_toko, t.username_toko,
            (SELECT nama_file_gambar FROM product_images WHERE id_produk = p.id ORDER BY id ASC LIMIT 1) as main_image,
            (SELECT MIN(harga) FROM product_variations WHERE id_produk = p.id AND is_active = 1) as min_price
        FROM wishlist w
        JOIN products p ON w.id_produk = p.id
        JOIN users u ON p.id_user = u.id_user
        JOIN toko t ON u.id_user = t.id_user
        WHERE w.id_user = %s
        ORDER BY w.added_on DESC
    """, (user_id,))
    wishlist_items = cur.fetchall()
    cur.close()

    return render_template('wishlist.html', items=wishlist_items)

# Tambahkan ini di app.py

@app.route('/search')
def search():
    # Ambil kata kunci dari URL (?q=...)
    query = request.args.get('q', '')
    
    # Siapkan untuk query ke database
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    search_term = f"%{query}%" # Tambahkan wildcard % untuk pencarian parsial

    # Query untuk mencari produk berdasarkan nama atau deskripsi
    cur.execute("""
        SELECT 
            p.id, p.name, t.nama_toko, t.username_toko,
            (SELECT nama_file_gambar FROM product_images WHERE id_produk = p.id ORDER BY id ASC LIMIT 1) as main_image,
            (SELECT MIN(harga) FROM product_variations WHERE id_produk = p.id AND is_active = 1) as min_price
        FROM products p
        JOIN users u ON p.id_user = u.id_user
        JOIN toko t ON u.id_user = t.id_user
        WHERE p.is_active = 1 AND (p.name LIKE %s OR p.description LIKE %s)
    """, (search_term, search_term))
    
    search_results = cur.fetchall()
    cur.close()

    # Kirim hasil pencarian ke template baru
    return render_template('search_results.html', results=search_results, query=query)   

# Tambahkan route baru ini di app.py
@app.route('/toggle-product-active/<int:product_id>', methods=['POST'])
def toggle_product_active_seller(product_id):
    # Keamanan: pastikan yang akses adalah penjual
    if session.get('id_level') != 3:
        flash("Aksi tidak diizinkan.", "error")
        return redirect(url_for('home_buyer'))

    user_id = session['id_user']
    cur = mysql.connection.cursor()

    # Keamanan tambahan: pastikan produk ini milik penjual yang sedang login
    cur.execute("SELECT id FROM products WHERE id = %s AND id_user = %s", (product_id, user_id))
    product = cur.fetchone()

    if product:
        # Jika produk ada dan milik user, ubah status is_active
        cur.execute("UPDATE products SET is_active = NOT is_active WHERE id = %s", (product_id,))
        mysql.connection.commit()
        flash("Status produk berhasil diubah.", "success")
    else:
        flash("Produk tidak ditemukan atau Anda tidak memiliki izin.", "error")

    cur.close()
    # Kembali ke dashboard penjual atau halaman edit
    return redirect(request.referrer or url_for('dashboard_penjual'))

@app.route('/add-product', methods=['GET', 'POST'])
def add_product():
    # Penjaga Keamanan
    if session.get('id_level') != 3:
        flash("Hanya penjual yang dapat menambah produk.", "error")
        return redirect(url_for('home_buyer'))

    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    
    if request.method == 'POST':
        cur = mysql.connection.cursor()
        try:
            # 1. Ambil data utama produk
            name = request.form['name']
            description = request.form['description']
            id_kategori = request.form.get('id_kategori')
            seller_id = session['id_user']

            # 2. Simpan data utama ke tabel 'products'
            cur.execute("INSERT INTO products (name, description, id_user, id_kategori) VALUES (%s, %s, %s, %s)",
                       (name, description, seller_id, id_kategori))
            
            # 3. Ambil ID dari produk yang BARU SAJA dibuat
            product_id = cur.lastrowid

            # 4. Proses dan simpan FOTO produk (bisa lebih dari satu)
            images = request.files.getlist('images')
            for image_file in images:
                if image_file and allowed_file(image_file.filename):
                    image_filename = secure_filename(image_file.filename)
                    # Buat nama file lebih unik untuk menghindari duplikat
                    ext = image_filename.rsplit('.', 1)[1].lower()
                    new_filename = f"product_{product_id}_{int(time.time())}_{images.index(image_file)}.{ext}"
                    image_file.save(os.path.join(app.config['UPLOAD_FOLDER'], new_filename))
                    # Simpan nama file ke tabel 'product_images'
                    cur.execute("INSERT INTO product_images (id_produk, nama_file_gambar) VALUES (%s, %s)",
                               (product_id, new_filename))

            # 5. Proses dan simpan VARIAN produk
            # Kita siapkan untuk 3 varian seperti di form
            for i in range(1, 4):
                varian_name = request.form.get(f'variation_name_{i}')
                price = request.form.get(f'price_{i}')
                stock = request.form.get(f'stock_{i}')

                # Hanya simpan jika nama varian, harga, dan stok diisi
                if varian_name and price and stock:
                    cur.execute("""
                        INSERT INTO product_variations (id_produk, nama_varian, harga, stok) 
                        VALUES (%s, %s, %s, %s)
                    """, (product_id, varian_name, price, stock))

            # 6. Jika semua berhasil, commit ke database
            mysql.connection.commit()
            flash("Produk baru berhasil ditambahkan!", "success")
            return redirect(url_for('dashboard_penjual'))

        except Exception as e:
            # Jika ada error di tengah jalan, batalkan semua perubahan
            mysql.connection.rollback()
            flash(f"Terjadi kesalahan saat menambah produk: {e}", "error")
            print(f"ERROR add_product: {e}") # untuk debug di terminal
        finally:
            cur.close()
            
    cur.execute("SELECT * FROM categories ORDER BY name ASC")
    categories = cur.fetchall()
    cur.close()

    return render_template('add_product.html',categories=categories)

# GANTI TOTAL FUNGSI edit_product ANDA DENGAN YANG INI
@app.route('/edit-product/<int:product_id>', methods=['GET', 'POST'])
def edit_product(product_id):
    if session.get('id_level') != 3:
        flash("Hanya penjual yang dapat mengedit produk.", "error")
        return redirect(url_for('home_buyer'))

    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    
    cur.execute("SELECT * FROM products WHERE id = %s AND id_user = %s", (product_id, session['id_user']))
    produk = cur.fetchone()
    if not produk:
        flash("Produk tidak ditemukan atau Anda tidak berizin.", "error")
        cur.close()
        return redirect(url_for('dashboard_penjual'))

    if request.method == 'POST':
        try:
            name = request.form['name']
            description = request.form['description']
            id_kategori = request.form.get('id_kategori')
            cur.execute("UPDATE products SET name = %s, description = %s, id_kategori = %s WHERE id = %s", 
                        (name, description, id_kategori, product_id))

            images_to_delete_ids = request.form.getlist('delete_images')
            if images_to_delete_ids:
                for img_id in images_to_delete_ids:
                    cur.execute("SELECT nama_file_gambar FROM product_images WHERE id = %s", (img_id,))
                    file_to_delete = cur.fetchone()
                    if file_to_delete:
                        os.remove(os.path.join(app.config['UPLOAD_FOLDER'], file_to_delete['nama_file_gambar']))
                    cur.execute("DELETE FROM product_images WHERE id = %s", (img_id,))

            new_images = request.files.getlist('images')
            for image_file in new_images:
                if image_file and allowed_file(image_file.filename):
                    image_filename = secure_filename(image_file.filename)
                    ext = image_filename.rsplit('.', 1)[1].lower()
                    new_filename = f"product_{product_id}_{int(time.time())}_{new_images.index(image_file)}.{ext}"
                    image_file.save(os.path.join(app.config['UPLOAD_FOLDER'], new_filename))
                    cur.execute("INSERT INTO product_images (id_produk, nama_file_gambar) VALUES (%s, %s)", (product_id, new_filename))

            # [FIX] STRATEGI BARU: Nonaktifkan semua varian lama, bukan dihapus
            cur.execute("UPDATE product_variations SET is_active = 0 WHERE id_produk = %s", (product_id,))
            
            # Kemudian masukkan kembali varian dari form (otomatis akan aktif karena default di DB adalah 1)
            for i in range(1, 4):
                varian_name = request.form.get(f'variation_name_{i}')
                price = request.form.get(f'price_{i}')
                stock = request.form.get(f'stock_{i}')
                if varian_name and price and stock:
                    cur.execute("""
                        INSERT INTO product_variations (id_produk, nama_varian, harga, stok) 
                        VALUES (%s, %s, %s, %s)
                    """, (product_id, varian_name, price, stock))

            mysql.connection.commit()
            flash("Produk berhasil diperbarui!", "success")
            return redirect(url_for('dashboard_penjual'))
        except Exception as e:
            mysql.connection.rollback()
            flash(f"Terjadi kesalahan saat memperbarui produk: {e}", "error")
            return redirect(url_for('edit_product', product_id=product_id))
        finally:
            cur.close()

    # Bagian GET Method (menampilkan data)
    
    cur.execute("SELECT * FROM products WHERE id = %s AND id_user = %s", (product_id, session['id_user']))
    produk = cur.fetchone()
    
    cur.execute("SELECT * FROM product_images WHERE id_produk = %s", (product_id,))
    images = cur.fetchall()
    # [FIX] Hanya ambil varian yang aktif untuk ditampilkan di form edit
    cur.execute("SELECT * FROM product_variations WHERE id_produk = %s AND is_active = 1", (product_id,))
    variations = cur.fetchall()
    cur.execute("SELECT * FROM vouchers WHERE id_produk = %s", (product_id,))
    vouchers = cur.fetchall()
    
    cur.execute("SELECT * FROM categories ORDER BY name ASC")
    categories = cur.fetchall()
    cur.close()
    
    return render_template('edit_product.html', produk=produk, images=images, variations=variations, vouchers=vouchers, categories=categories)

@app.route('/tambah-voucher/<int:product_id>', methods=['POST'])
def tambah_voucher(product_id):
    if session.get('id_level') != 3:
        flash("Aksi tidak diizinkan.", "error")
        return redirect(url_for('home_buyer'))

    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    
    cur.execute("SELECT id_user FROM products WHERE id = %s", (product_id,))
    product = cur.fetchone()

    if not product or product['id_user'] != session['id_user']:
        flash("Anda tidak berhak menambahkan voucher untuk produk ini.", "error")
        cur.close()
        return redirect(url_for('dashboard_penjual'))
        
    kode_voucher = request.form.get('kode_voucher')
    jenis_diskon = request.form.get('jenis_diskon')
    nilai_diskon = request.form.get('nilai_diskon')
    tgl_kadaluarsa = request.form.get('tgl_kadaluarsa')

    if not kode_voucher or not jenis_diskon or not nilai_diskon:
        flash("Kode, jenis, dan nilai voucher wajib diisi.", "error")
        cur.close()
        return redirect(url_for('edit_product', product_id=product_id))

    if not tgl_kadaluarsa:
        tgl_kadaluarsa = None

    try:
        # [FIX] Menggunakan 'id_produk' sesuai nama kolom di database Anda
        cur.execute("""
            INSERT INTO vouchers (id_produk, kode_voucher, jenis_diskon, nilai_diskon, tgl_kadaluarsa)
            VALUES (%s, %s, %s, %s, %s)
        """, (product_id, kode_voucher, jenis_diskon, nilai_diskon, tgl_kadaluarsa))
        mysql.connection.commit()
        flash("Voucher baru berhasil ditambahkan!", "success")
    except Exception as e:
        mysql.connection.rollback()
        flash(f"Gagal menambahkan voucher: {e}", "error")
    finally:
        cur.close()

    return redirect(url_for('edit_product', product_id=product_id))

# Hapus produk
@app.route('/delete-product/<int:product_id>', methods=['POST'])
def delete_product(product_id):
    if session.get('id_level') != 3: # ID Penjual adalah 3
        flash("Hanya penjual yang dapat menambah produk.", "error")
        return redirect(url_for('home_buyer'))

    cursor = mysql.connection.cursor()
    cursor.execute("DELETE FROM products WHERE id = %s AND id_user = %s", (product_id, session['id_user']))
    mysql.connection.commit()
    cursor.close()
    flash("Produk berhasil dihapus!", "success")
    return redirect(url_for('dashboard_penjual'))

@app.route('/balas-rating/<int:rating_id>', methods=['POST'])
def reply_to_rating(rating_id):
    # Keamanan: Pastikan user adalah penjual
    if session.get('id_level') != 3:
        return redirect(url_for('home_buyer'))

    balasan = request.form['balasan']
    
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    # Keamanan: Pastikan penjual ini adalah pemilik produk dari rating yg akan dibalas
    cur.execute("""
        SELECT p.id_user, r.id_produk FROM product_ratings r
        JOIN products p ON r.id_produk = p.id
        WHERE r.id = %s
    """, (rating_id,))
    rating_info = cur.fetchone()

    if rating_info and rating_info['id_user'] == session['id_user']:
        # Update balasan di database
        cur.execute("UPDATE product_ratings SET balasan_penjual = %s, tanggal_balasan = NOW() WHERE id = %s", (balasan, rating_id))
        mysql.connection.commit()
        flash("Ulasan berhasil dibalas.", "success")
    else:
        flash("Aksi tidak diizinkan.", "error")
        
    cur.close()
    return redirect(url_for('product_detail', product_id=rating_info['id_produk']))

@app.route('/update-status-retur/<int:retur_id>', methods=['POST'])
def update_status_retur(retur_id):
    # Keamanan dasar
    if 'id_user' not in session or session.get('id_level') != 3:
        flash("Aksi tidak diizinkan.", "error")
        return redirect(url_for('home_buyer'))

    action = request.form.get('action')
    user_id = session['id_user']

    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    
    # Keamanan tambahan: Pastikan retur ini milik penjual yang sedang login
    cur.execute("""
        SELECT r.id_retur, r.id_transaksi FROM retur_barang r
        JOIN transaksi_items ti ON r.id_transaksi = ti.id_transaksi
        JOIN products p ON ti.id_produk = p.id
        WHERE r.id_retur = %s AND p.id_user = %s
        LIMIT 1
    """, (retur_id, user_id))
    retur = cur.fetchone()

    if not retur:
        flash("Retur tidak ditemukan atau Anda tidak memiliki izin.", "error")
        cur.close()
        return redirect(url_for('dashboard_penjual'))

    # Logika berdasarkan aksi
    if action == 'setujui':
        cur.execute("UPDATE retur_barang SET status_retur = 'Disetujui' WHERE id_retur = %s", (retur_id,))
        cur.execute("UPDATE transaksi SET status = 'retur_disetujui' WHERE id_transaksi = %s", (retur['id_transaksi'],))
        flash("Permintaan retur telah disetujui.", "success")

    elif action == 'tolak':
        cur.execute("UPDATE retur_barang SET status_retur = 'Ditolak' WHERE id_retur = %s", (retur_id,))
        # Langsung ubah status transaksi utama menjadi 'selesai'
        cur.execute("UPDATE transaksi SET status = 'selesai' WHERE id_transaksi = %s", (retur['id_transaksi'],))
        flash("Permintaan retur telah ditolak. Pesanan ini sekarang dianggap selesai.", "warning")

    elif action == 'kirim_ulang':
        nomor_resi_baru = request.form.get('nomor_resi_baru')
        if not nomor_resi_baru:
            flash("Nomor resi baru wajib diisi.", "error")
            return redirect(url_for('dashboard_penjual'))
        
        cur.execute("""
            UPDATE retur_barang 
            SET status_retur = 'Dikirim Ulang', nomor_resi_baru = %s, tanggal_kirim_ulang = NOW() 
            WHERE id_retur = %s
        """, (nomor_resi_baru, retur_id))
        flash("Informasi pengiriman ulang berhasil disimpan.", "success")

    mysql.connection.commit()
    cur.close()
    return redirect(url_for('dashboard_penjual'))

@app.route('/toko/<string:shop_username>')
def shop_detail(shop_username):
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    
    # 1. Ambil info toko berdasarkan username
    cur.execute("SELECT * FROM toko WHERE username_toko = %s", (shop_username,))
    toko = cur.fetchone()
    
    if not toko:
        flash("Toko tidak ditemukan.", "error")
        return redirect(url_for('home_buyer'))
    
    # 2. Ambil semua produk dari toko tersebut
    cur.execute("""
        SELECT 
            p.*,
            (SELECT nama_file_gambar FROM product_images WHERE id_produk = p.id ORDER BY id ASC LIMIT 1) as main_image,
            (SELECT MIN(harga) FROM product_variations WHERE id_produk = p.id) as min_price
        FROM products p WHERE p.id_user = %s
    """, (toko['id_user'],))
    produk_toko = cur.fetchall()
    
    cur.close()
    return render_template('shop_detail.html', toko=toko, produk=produk_toko)

# Ini adalah route beli_produk yang sudah saya berikan sebelumnya
# Pastikan ini ada di app.py Anda
@app.route("/beli-produk/<int:product_id>", methods=["POST"])
def beli_produk(product_id):
    if 'id_user' not in session:
        flash("Anda harus login untuk berbelanja.", "error")
        return redirect(url_for('login'))

    quantity = 1 # Misalnya kuantitas default 1 untuk tombol "Beli"

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    try:
        # 1. Ambil detail produk (dengan kunci FOR UPDATE untuk mencegah masalah stok)
        cursor.execute("SELECT * FROM products WHERE id = %s FOR UPDATE", (product_id,))
        product = cursor.fetchone()

        if not product:
            flash("Produk tidak ditemukan.", "error")
            mysql.connection.rollback()
            return redirect(url_for('home_buyer'))

        if product['stock'] < quantity:
            flash(f"Stok {product['name']} tidak cukup. Tersedia: {product['stock']}.", "error")
            mysql.connection.rollback()
            return redirect(url_for('home_buyer'))

        # Dapatkan ID penjual dari produk. Jika id_user di products NULL, ini akan jadi None.
        seller_id = product.get('id_user') # Akan jadi None jika kolom id_user di products NULL

        product_price = product['price']
        total_price = product_price * quantity
        buyer_id = session['id_user']

        # 2. Masukkan ke tabel transaksi
        # Karena id_penjual sekarang NULLABLE di DB, ini akan berhasil meski seller_id adalah None
        cursor.execute("""
            INSERT INTO transaksi (id_user, id_produk, id_penjual, jumlah, price_at_purchase, total_harga, status)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (buyer_id, product_id, seller_id, quantity, product_price, total_price, 'completed'))

        # 3. Update stok produk
        new_stock = product['stock'] - quantity
        cursor.execute("UPDATE products SET stock = %s WHERE id = %s", (new_stock, product_id))

        mysql.connection.commit()
        flash(f"Berhasil membeli {quantity}x {product['name']}!", "success")
        return redirect(url_for('home_buyer'))

    except MySQLdb.Error as e:
        mysql.connection.rollback()
        flash(f"Terjadi kesalahan saat transaksi: {e}", "error")
        print(f"Database error in beli_produk: {e}") # Untuk debugging Anda
        return redirect(url_for('home_buyer'))
    finally:
        cursor.close()

@app.route("/riwayat")
def riwayat():
    if 'id_user' not in session:
        flash("Anda harus login untuk melihat riwayat.", "error")
        return redirect(url_for('login'))

    user_id = session['id_user']
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    try:
        # Query utama yang sudah diperbaiki dengan subquery EXISTS
        cur.execute("""
            SELECT 
                t.*,
                r.status_retur,
                r.id_retur,
                (EXISTS (
                    SELECT 1 FROM product_ratings pr 
                    WHERE pr.id_user = t.id_user 
                    AND pr.id_produk IN (SELECT ti.id_produk FROM transaksi_items ti WHERE ti.id_transaksi = t.id_transaksi)
                )) AS has_rated
            FROM transaksi t
            LEFT JOIN retur_barang r ON t.id_transaksi = r.id_transaksi
            WHERE t.id_user = %s 
            ORDER BY t.tanggal_pesanan DESC
        """, (user_id,))
        orders = cur.fetchall()

        # Loop untuk mengambil detail item per pesanan
        for order in orders:
            cur.execute("""
                SELECT 
                    ti.kuantitas, ti.harga_saat_beli, ti.id_produk,
                    p.name as product_name,
                    (SELECT nama_file_gambar FROM product_images WHERE id_produk = ti.id_produk ORDER BY id ASC LIMIT 1) as product_image
                FROM transaksi_items ti
                JOIN products p ON ti.id_produk = p.id
                WHERE ti.id_transaksi = %s
            """, (order['id_transaksi'],))
            
            order['detail_items'] = cur.fetchall()

        return render_template("riwayat.html", orders=orders)

    except Exception as e:
        print(f"ERROR DI FUNGSI RIWAYAT: {e}")
        flash("Terjadi kesalahan saat memuat riwayat.", "error")
        return redirect(request.referrer or url_for('home_buyer'))
    finally:
        cur.close()
        
@app.route('/filter-riwayat/<status>')
def filter_riwayat(status):
    if 'id_user' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    user_id = session['id_user']
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    # Siapkan query dasar yang sama dengan fungsi riwayat() utama
    query = """
        SELECT 
            t.*,
            r.status_retur,
            r.id_retur,
            (EXISTS (
                SELECT 1 FROM product_ratings pr 
                WHERE pr.id_user = t.id_user 
                AND pr.id_produk IN (SELECT ti.id_produk FROM transaksi_items ti WHERE ti.id_transaksi = t.id_transaksi)
            )) AS has_rated
        FROM transaksi t
        LEFT JOIN retur_barang r ON t.id_transaksi = r.id_transaksi
        WHERE t.id_user = %s
    """
    params = [user_id]

    if status == 'diretur':
        query += " AND t.status IN ('mengajukan_retur', 'retur_disetujui', 'retur_ditolak', 'retur_selesai')"
    elif status != 'semua':
        query += " AND t.status = %s"
        params.append(status)
    
    query += " ORDER BY t.tanggal_pesanan DESC"

    cur.execute(query, tuple(params))
    orders = cur.fetchall()

    # Ambil detail item untuk setiap pesanan (logika ini tidak berubah)
    for order in orders:
        cur.execute("""
            SELECT 
                ti.kuantitas, ti.harga_saat_beli, ti.id_produk,
                p.name as product_name,
                (SELECT nama_file_gambar FROM product_images WHERE id_produk = ti.id_produk ORDER BY id ASC LIMIT 1) as product_image
            FROM transaksi_items ti
            JOIN products p ON ti.id_produk = p.id
            WHERE ti.id_transaksi = %s
        """, (order['id_transaksi'],))
        order['detail_items'] = cur.fetchall()
    
    cur.close()

    return render_template('_riwayat_list.html', orders=orders)


@app.route('/add-to-cart/<int:product_id>', methods=['POST'])
def add_to_cart(product_id):
    # Keamanan: Pastikan user sudah login
    if 'id_user' not in session:
        flash("Anda harus login untuk berbelanja.", "error")
        return redirect(url_for('login'))

    # 1. Ambil ID varian yang dipilih dari form yang dikirim oleh JavaScript
    variation_id = request.form.get('selected_variation_id')

    # Validasi: Jika tidak ada varian yang dipilih, jangan lanjutkan
    if not variation_id:
        flash("Silakan pilih varian produk terlebih dahulu.", "error")
        return redirect(url_for('product_detail', product_id=product_id))

    quantity = 1 # Untuk sekarang, kita buat kuantitasnya 1 setiap kali klik

    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    
    # 2. Ambil detail dari VARIAN yang dipilih (untuk cek harga & stok)
    cur.execute("SELECT * FROM product_variations WHERE id = %s", (variation_id,))
    variation = cur.fetchone()

    # 3. Ambil detail PRODUK UTAMA (untuk dapat nama & gambar)
    cur.execute("""
        SELECT p.*, 
               (SELECT nama_file_gambar FROM product_images WHERE id_produk = p.id ORDER BY id ASC LIMIT 1) as main_image
        FROM products p WHERE p.id = %s
    """, (product_id,))
    product = cur.fetchone()
    cur.close()

    if not variation or not product:
        flash("Produk atau varian tidak ditemukan.", "error")
        return redirect(url_for('home_buyer'))

    # 4. Cek stok berdasarkan stok VARIAN, bukan produk utama
    if variation['stok'] < quantity:
        flash(f"Maaf, stok untuk varian '{variation['nama_varian']}' tidak cukup.", "error")
        return redirect(url_for('product_detail', product_id=product_id))

    # Inisialisasi keranjang jika belum ada
    if 'cart' not in session:
        session['cart'] = []

    # Cek apakah varian yang sama sudah ada di keranjang
    found_in_cart = False
    for item in session['cart']:
        # Kunci sekarang adalah 'variation_id'
        if item['variation_id'] == int(variation_id):
            item['quantity'] += quantity
            found_in_cart = True
            break

    # Jika belum ada, tambahkan item baru ke keranjang
    if not found_in_cart:
        session['cart'].append({
            'product_id': product_id,
            'variation_id': int(variation_id),
            'product_name': product['name'],
            'variation_name': variation['nama_varian'],
            'price': float(variation['harga']),
            'image': product.get('main_image'),
            'quantity': quantity,
            'stock_available': variation['stok'] # Simpan info stok varian
        })

    session.modified = True # Wajib ada agar session tersimpan
    flash(f"Produk '{product['name']} - {variation['nama_varian']}' berhasil ditambahkan ke keranjang!", "success")
    return redirect(url_for('cart'))

# Pastikan fungsi cart() Anda di app.py seperti ini

@app.route('/cart')
def cart():
    # Keamanan, pastikan user sudah login
    if 'id_user' not in session:
        flash("Anda harus login untuk melihat keranjang.", "error")
        return redirect(url_for('login'))

    # Ambil item dari session, jika tidak ada, buat list kosong
    cart_items = session.get('cart', [])

    # INI BAGIAN YANG DIPERBAIKI:
    # Hitung total harga dengan mengalikan harga satuan dengan kuantitas untuk setiap item
    total_cart_price = sum(item['price'] * item['quantity'] for item in cart_items)
    
    # Kirim data ke template
    return render_template('cart.html', cart_items=cart_items, total_cart_price=total_cart_price)

# Tambahkan/ganti fungsi ini di app.py

@app.route('/update-cart/<int:variation_id>', methods=['POST'])
def update_cart(variation_id):
    if 'cart' not in session:
        return redirect(url_for('cart'))

    new_quantity = int(request.form['quantity'])
    
    for item in session['cart']:
        if item['variation_id'] == variation_id:
            if new_quantity > 0 and new_quantity <= item['stock_available']:
                item['quantity'] = new_quantity
            elif new_quantity > item['stock_available']:
                flash(f"Kuantitas melebihi stok yang tersedia ({item['stock_available']})", "error")
            break
            
    session.modified = True
    return redirect(url_for('cart'))

@app.route('/remove-from-cart/<int:variation_id>', methods=['POST'])
def remove_from_cart(variation_id):
    if 'cart' in session:
        # Buat ulang list keranjang tanpa item yang mau dihapus
        session['cart'] = [item for item in session['cart'] if item['variation_id'] != variation_id]
        session.modified = True
        flash("Produk berhasil dihapus dari keranjang.", "success")
        
    return redirect(url_for('cart'))

@app.route('/checkout')
def checkout():
    if 'id_user' not in session:
        flash("Anda harus login untuk melanjutkan.", "error")
        return redirect(url_for('login'))

    # --- INI BAGIAN LOGIKA YANG DIPERBAIKI ---
    # Prioritaskan item "Beli Sekarang" jika ada, jika tidak baru ambil dari keranjang.
    # Kita juga tandai sumbernya (source) untuk digunakan nanti.
    source = 'buy_now'
    items_for_checkout = session.get('buy_now_item', [])

    if not items_for_checkout:
        source = 'cart'
        items_for_checkout = session.get('cart', [])
        
    if not items_for_checkout:
        flash("Keranjang Anda kosong.", "info")
        return redirect(url_for('home_buyer'))
    # --- AKHIR PERBAIKAN LOGIKA ---

    user_id = session['id_user']
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    
    # Ambil semua alamat tersimpan milik pengguna
    cur.execute("SELECT * FROM user_addresses WHERE id_user = %s ORDER BY is_utama DESC, id DESC", (user_id,))
    addresses = cur.fetchall()

    # Ambil info toko dari item pertama di keranjang (asumsi 1 toko per checkout)
    first_product_id = items_for_checkout[0]['product_id']
    cur.execute("""
        SELECT t.metode_pengiriman, t.metode_pembayaran 
        FROM toko t JOIN products p ON t.id_user = p.id_user 
        WHERE p.id = %s
    """, (first_product_id,))
    toko_methods = cur.fetchone()
    
    # Ambil semua voucher yang aktif
    cur.execute("SELECT * FROM vouchers WHERE tgl_kadaluarsa IS NULL OR tgl_kadaluarsa >= CURDATE()")
    vouchers = cur.fetchall()
    cur.close()

    # Ubah string dari DB menjadi list
    shipping_options = toko_methods['metode_pengiriman'].split(',') if toko_methods and toko_methods['metode_pengiriman'] else []
    payment_options = toko_methods['metode_pembayaran'].split(',') if toko_methods and toko_methods['metode_pembayaran'] else []

    # Hitung subtotal produk
    subtotal = sum(item['price'] * item['quantity'] for item in items_for_checkout)
    
    return render_template('checkout.html', 
                           cart_items=items_for_checkout, # Gunakan variabel baru ini
                           addresses=addresses,
                           shipping_options=shipping_options,
                           payment_options=payment_options,
                           subtotal=subtotal,
                           vouchers=vouchers,
                           checkout_source=source)
    
@app.route('/beli-sekarang', methods=['POST'])
def beli_sekarang():
    # Keamanan & Validasi Dasar
    if 'id_user' not in session:
        flash("Anda harus login untuk berbelanja.", "error")
        return redirect(url_for('login'))

    product_id = request.form.get('product_id')
    variation_id = request.form.get('selected_variation_id')

    if not variation_id:
        flash("Silakan pilih varian produk terlebih dahulu.", "error")
        return redirect(url_for('product_detail', product_id=product_id))

    # Ambil detail produk dan varian dari database
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("SELECT * FROM product_variations WHERE id = %s", (variation_id,))
    variation = cur.fetchone()
    cur.execute("""
        SELECT p.*, 
               (SELECT nama_file_gambar FROM product_images WHERE id_produk = p.id ORDER BY id ASC LIMIT 1) as main_image
        FROM products p WHERE p.id = %s
    """, (product_id,))
    product = cur.fetchone()
    cur.close()

    if not variation or not product:
        flash("Produk atau varian tidak ditemukan.", "error")
        return redirect(url_for('home_buyer'))

    # Buat item tunggal untuk "Beli Sekarang"
    buy_now_item = [{
        'product_id': int(product_id),
        'variation_id': int(variation_id),
        'product_name': product['name'],
        'variation_name': variation['nama_varian'],
        'price': float(variation['harga']),
        'image': product.get('main_image'),
        'quantity': 1, # Beli sekarang selalu dimulai dengan kuantitas 1
        'stock_available': variation['stok']
    }]

    # Simpan item ini di session dengan kunci yang BERBEDA dari keranjang utama
    session['buy_now_item'] = buy_now_item
    session.modified = True

    # Langsung arahkan ke halaman checkout
    return redirect(url_for('checkout'))
    
@app.route('/add-address', methods=['POST'])
def add_address():
    if 'id_user' not in session:
        return redirect(url_for('login'))

    nama_penerima = request.form['nama_penerima']
    no_hp = request.form['no_hp']
    alamat_lengkap = request.form['alamat_lengkap']
    is_utama = 'is_utama' in request.form
    user_id = session['id_user']
    
    cur = mysql.connection.cursor()
    if is_utama:
        cur.execute("UPDATE user_addresses SET is_utama = FALSE WHERE id_user = %s", (user_id,))
    
    cur.execute("""
        INSERT INTO user_addresses (id_user, nama_penerima, no_hp, alamat_lengkap, is_utama)
        VALUES (%s, %s, %s, %s, %s)
    """, (user_id, nama_penerima, no_hp, alamat_lengkap, is_utama))
    
    mysql.connection.commit()
    cur.close()
    flash("Alamat baru berhasil ditambahkan.", "success")
    return redirect(url_for('checkout'))

@app.route('/set-primary-address/<int:address_id>', methods=['POST'])
def set_primary_address(address_id):
    if 'id_user' not in session:
        return redirect(url_for('login'))
        
    user_id = session['id_user']
    cur = mysql.connection.cursor()
    cur.execute("UPDATE user_addresses SET is_utama = FALSE WHERE id_user = %s", (user_id,))
    cur.execute("UPDATE user_addresses SET is_utama = TRUE WHERE id = %s AND id_user = %s", (address_id, user_id))
    mysql.connection.commit()
    cur.close()
    
    return redirect(url_for('checkout'))

# Tambahkan fungsi baru ini di app.py
@app.route('/apply-voucher', methods=['POST'])
def apply_voucher():
    if 'id_user' not in session:
        return jsonify({'success': False, 'message': 'Silakan login.'})
            
    kode = request.form.get('kode_voucher')
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("SELECT * FROM vouchers WHERE kode_voucher = %s AND (tgl_kadaluarsa IS NULL OR tgl_kadaluarsa >= CURDATE())", (kode,))
    voucher = cur.fetchone()
    cur.close()
    
    if voucher:
        return jsonify({
            'success': True, 
            'jenis': voucher['jenis_diskon'], 
            'nilai': float(voucher['nilai_diskon']),
            'keterangan': voucher['keterangan']
        })
    else:
        return jsonify({'success': False, 'message': 'Voucher tidak valid atau sudah kadaluarsa.'})

@app.route('/detail-transaksi-penjual/<int:transaksi_id>')
def detail_transaksi_penjual(transaksi_id):
    # Keamanan: Pastikan yang login adalah penjual atau pengelola
    if 'id_user' not in session or session.get('id_level') not in [2, 3]:
        flash("Aksi tidak diizinkan.", "error")
        return redirect(url_for('home_buyer'))

    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    
    # Ambil detail transaksi utama dan data pembeli
    cur.execute("""
        SELECT t.*, p.nama as nama_pembeli, p.no_telp, p.alamat
        FROM transaksi t
        JOIN users u ON t.id_user = u.id_user
        JOIN profile p ON u.id_profile = p.id_profile
        WHERE t.id_transaksi = %s
    """, (transaksi_id,))
    transaksi = cur.fetchone()

    if not transaksi:
        flash("Transaksi tidak ditemukan.", "error")
        cur.close()
        return redirect(url_for('dashboard_penjual'))

    # Ambil detail item dalam transaksi tersebut
    cur.execute("""
        SELECT ti.*, p.name as product_name
        FROM transaksi_items ti
        JOIN products p ON ti.id_produk = p.id
        WHERE ti.id_transaksi = %s
    """, (transaksi_id,))
    transaksi['items'] = cur.fetchall()
    cur.close()

    return render_template('detail_transaksi_penjual.html', transaksi=transaksi)

@app.route('/pembayaran/<int:transaksi_id>')
def pembayaran(transaksi_id):
    if 'id_user' not in session:
        return redirect(url_for('login'))

    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    # PERBAIKAN ADA DI SINI: 'WHERE id =' diubah menjadi 'WHERE id_transaksi ='
    cur.execute("SELECT *, UNIX_TIMESTAMP(expiry_time) as expiry_unix FROM transaksi WHERE id_transaksi = %s AND id_user = %s", (transaksi_id, session['id_user']))
    transaksi = cur.fetchone()
    cur.close()

    if not transaksi:
        flash("Transaksi tidak ditemukan. Mungkin ID tidak cocok atau bukan milik Anda.", "error")
        return redirect(url_for('riwayat'))

    # 2. Jika ditemukan, baru cek statusnya
    if transaksi['status'] != 'menunggu_pembayaran':
        flash(f"Transaksi ini sudah dalam status '{transaksi['status']}' dan tidak bisa dibayar lagi.", "error")
        return redirect(url_for('riwayat'))

    return render_template('pembayaran.html', transaksi=transaksi)

# GANTI SELURUH FUNGSI proses_pembayaran ANDA DENGAN INI

@app.route('/proses-pembayaran/<int:transaksi_id>', methods=['POST'])
def proses_pembayaran(transaksi_id):
    if 'id_user' not in session:
        return redirect(url_for('login'))
        
    pin_input = request.form['pin']
    user_id = session['id_user']
    
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    
    # Ambil hash PIN user dari DB
    cur.execute("SELECT pin_hash FROM users WHERE id_user = %s", (user_id,))
    user = cur.fetchone()
    
    # Ambil info transaksi
    # PERBAIKAN ADA DI SINI: 'WHERE id =' diubah menjadi 'WHERE id_transaksi ='
    cur.execute("SELECT * FROM transaksi WHERE id_transaksi = %s", (transaksi_id,))
    transaksi = cur.fetchone()
    
    if not user or not user['pin_hash'] or not transaksi:
        flash("Terjadi kesalahan.", "error")
        cur.close()
        return redirect(url_for('home_buyer'))
    
    # Cek apakah PIN cocok
    if bcrypt.checkpw(pin_input.encode('utf-8'), user['pin_hash'].encode('utf-8')):
        # PIN Benar! Update status transaksi menjadi 'diproses'
        cur.execute("UPDATE transaksi SET status = 'diproses' WHERE id_transaksi = %s", (transaksi_id,))
        mysql.connection.commit()
        cur.close()
        flash("Pembayaran berhasil!", "success") # Pesan flash bisa lebih singkat
        return redirect(url_for('pembayaran_berhasil', transaksi_id=transaksi_id)) 
    else:
        # PIN Salah
        cur.close()
        flash("PIN yang Anda masukkan salah!", "error")
        return redirect(url_for('pembayaran', transaksi_id=transaksi_id))
    
# Tambahkan fungsi baru ini di app.py
@app.route('/pembayaran-berhasil/<int:transaksi_id>')
def pembayaran_berhasil(transaksi_id):
    return render_template('pembayaran_berhasil.html', transaksi_id=transaksi_id)

@app.route('/confirm-purchase', methods=['POST'])
def confirm_purchase():
    if 'id_user' not in session:
        return redirect(url_for('login'))

    # Tentukan sumber item (Beli Sekarang atau Keranjang)
    items_to_purchase = session.get('buy_now_item', [])
    session_key_to_clear = 'buy_now_item'
    if not items_to_purchase:
        items_to_purchase = session.get('cart', [])
        session_key_to_clear = 'cart'
    
    if not items_to_purchase:
        flash("Tidak ada item untuk dibeli.", "error")
        return redirect(url_for('home_buyer'))

    # Ambil data dari form
    shipping_method = request.form.get('shipping') 
    payment_method = request.form.get('payment')
    kode_voucher = request.form.get('kode_voucher_terpilih')
    user_id = session['id_user']
    
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    try:
        # Cek apakah user sudah punya PIN
        cur.execute("SELECT pin_hash FROM users WHERE id_user = %s", (user_id,))
        user_pin = cur.fetchone()
        if not user_pin or not user_pin['pin_hash']:
            flash("Anda harus mengatur PIN Keamanan di halaman profil sebelum melanjutkan checkout.", "error")
            cur.close()
            return redirect(url_for('profile'))

        # === BLOK KALKULASI TOTAL HARGA YANG BENAR ===
        
        # 1. Hitung Subtotal Produk
        subtotal_produk = sum(float(item['price']) * int(item['quantity']) for item in items_to_purchase)

        # 2. Hitung Biaya Pengiriman (logika disamakan dengan di frontend)
        shipping_cost = 0
        if shipping_method:
            if 'JNE' in shipping_method: shipping_cost = 15000
            elif 'J&T' in shipping_method: shipping_cost = 16000
            elif 'SiCepat' in shipping_method: shipping_cost = 18000
            elif 'GoSend' in shipping_method: shipping_cost = 20000

        # 3. Biaya Layanan (tetap)
        service_fee = 1000

        # 4. Hitung Diskon Voucher (jika ada)
        discount_amount = 0
        id_voucher_terpakai = None
        if kode_voucher:
            cur.execute("SELECT * FROM vouchers WHERE kode_voucher = %s AND (tgl_kadaluarsa IS NULL OR tgl_kadaluarsa >= CURDATE())", (kode_voucher,))
            voucher = cur.fetchone()
            if voucher:
                id_voucher_terpakai = voucher['id']
                if voucher['jenis_diskon'] == 'gratis_ongkir':
                    discount_amount = min(shipping_cost, float(voucher['nilai_diskon']))
                elif voucher['jenis_diskon'] == 'persen':
                    discount_amount = (subtotal_produk * float(voucher['nilai_diskon'])) / 100
                elif voucher['jenis_diskon'] == 'nominal':
                    discount_amount = float(voucher['nilai_diskon'])

        # 5. Hitung Grand Total
        grand_total = (subtotal_produk + shipping_cost + service_fee) - discount_amount

        # === AKHIR BLOK KALKULASI ===

        # Buat record transaksi utama dengan harga yang sudah benar.
        # Catatan: Pastikan tabel `transaksi` Anda memiliki kolom-kolom berikut:
        # subtotal_produk, biaya_pengiriman, biaya_layanan, diskon, id_voucher_terpakai
        cur.execute("""
            INSERT INTO transaksi (id_user, total_harga, status, expiry_time, metode_pengiriman, metode_pembayaran, subtotal_produk, biaya_pengiriman, biaya_layanan, diskon, id_voucher_terpakai)
            VALUES (%s, %s, %s, NOW() + INTERVAL 24 HOUR, %s, %s, %s, %s, %s, %s, %s)
        """, (user_id, grand_total, 'menunggu_pembayaran', shipping_method, payment_method, subtotal_produk, shipping_cost, service_fee, discount_amount, id_voucher_terpakai))
        
        transaksi_id = cur.lastrowid

        # Proses item dan potong stok
        for item in items_to_purchase:
            cur.execute("SELECT stok FROM product_variations WHERE id = %s FOR UPDATE", (item['variation_id'],))
            varian = cur.fetchone()
            if varian['stok'] < item['quantity']:
                raise Exception(f"Stok untuk produk {item['product_name']} tidak mencukupi.")
            
            cur.execute("UPDATE product_variations SET stok = stok - %s WHERE id = %s", (item['quantity'], item['variation_id']))
            
            cur.execute("""
                INSERT INTO transaksi_items (id_transaksi, id_produk, id_varian, kuantitas, harga_saat_beli)
                VALUES (%s, %s, %s, %s, %s)
            """, (transaksi_id, item['product_id'], item['variation_id'], item['quantity'], item['price']))

        mysql.connection.commit()
        session.pop(session_key_to_clear, None)
        
        flash("Pesanan berhasil dibuat! Silakan selesaikan pembayaran.", "info")
        return redirect(url_for('pembayaran', transaksi_id=transaksi_id))

    except Exception as e:
        mysql.connection.rollback()
        flash(f"Terjadi kesalahan saat memproses pesanan: {e}", "error")
        return redirect(url_for('cart'))
    finally:
        cur.close()

# Fungsi untuk konfirmasi penerimaan
@app.route('/terima-pesanan/<int:transaksi_id>', methods=['POST'])
def terima_pesanan(transaksi_id):
    if 'id_user' not in session:
        return redirect(url_for('login'))

    cur = mysql.connection.cursor()
    # Update status menjadi 'selesai'
    cur.execute("UPDATE transaksi SET status = 'selesai' WHERE id_transaksi = %s AND id_user = %s", 
                (transaksi_id, session['id_user']))
    mysql.connection.commit()
    cur.close()

    flash("Terima kasih telah mengonfirmasi pesanan Anda!", "success")
    # Arahkan ke halaman pemberian rating
    return redirect(url_for('beri_rating', transaksi_id=transaksi_id))

@app.route('/ajukan-retur/<int:transaksi_id>', methods=['GET', 'POST'])
def ajukan_retur(transaksi_id):
    if 'id_user' not in session:
        return redirect(url_for('login'))

    user_id = session['id_user']
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    # Ambil data transaksi untuk memastikan milik user dan statusnya 'dikirim'
    cur.execute("""
        SELECT * FROM transaksi WHERE id_transaksi = %s AND id_user = %s AND status = 'dikirim'
    """, (transaksi_id, user_id))
    transaksi = cur.fetchone()

    if not transaksi:
        flash("Transaksi tidak ditemukan atau tidak dapat diretur.", "error")
        cur.close()
        return redirect(url_for('riwayat'))

    if request.method == 'POST':
        item_ids_diretur = request.form.getlist('items_diretur')
        alasan = request.form['alasan_retur']

        if not item_ids_diretur:
            flash("Pilih minimal satu item untuk diretur.", "error")
            return redirect(url_for('ajukan_retur', transaksi_id=transaksi_id))

        # Ambil detail item yang dipilih untuk disimpan sebagai JSON
        cur.execute(f"""
            SELECT id_produk, kuantitas, harga_saat_beli, p.name as product_name 
            FROM transaksi_items ti JOIN products p ON ti.id_produk = p.id 
            WHERE id_transaksi = %s AND ti.id_produk IN ({','.join(['%s'] * len(item_ids_diretur))})
        """, (transaksi_id, *item_ids_diretur))
        items_detail = cur.fetchall()
        
        # --- PERBAIKAN DIMULAI DI SINI ---
        # Loop melalui setiap item dan konversi nilai Decimal ke float
        for item in items_detail:
            if 'harga_saat_beli' in item and isinstance(item['harga_saat_beli'], Decimal):
                item['harga_saat_beli'] = float(item['harga_saat_beli'])
        # --- AKHIR PERBAIKAN ---

        # Sekarang, items_detail aman untuk di-serialize
        items_json = json.dumps(items_detail)

        # Buat entri baru di tabel retur_barang
        cur.execute("""
            INSERT INTO retur_barang (id_transaksi, id_pembeli, alasan_retur, item_diretur)
            VALUES (%s, %s, %s, %s)
        """, (transaksi_id, user_id, alasan, items_json))

        # Update status transaksi utama menjadi 'mengajukan_retur'
        cur.execute("UPDATE transaksi SET status = 'mengajukan_retur' WHERE id_transaksi = %s", (transaksi_id,))
        
        mysql.connection.commit()
        cur.close()
        
        flash("Pengajuan retur Anda telah berhasil dikirim dan akan segera diproses oleh penjual.", "success")
        return redirect(url_for('riwayat'))

    # Untuk GET request, ambil detail item dari transaksi untuk ditampilkan di form
    cur.execute("""
        SELECT ti.id_produk, ti.kuantitas, p.name as product_name
        FROM transaksi_items ti
        JOIN products p ON ti.id_produk = p.id
        WHERE ti.id_transaksi = %s
    """, (transaksi_id,))
    transaksi['detail_items'] = cur.fetchall()
    cur.close()
    
    return render_template('form_retur.html', transaksi=transaksi)

# Fungsi untuk MENAMPILKAN halaman rating
@app.route('/beri-rating/<int:transaksi_id>', methods=['GET'])
def beri_rating(transaksi_id):
    if 'id_user' not in session:
        return redirect(url_for('login'))

    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    # Ambil semua item dari transaksi yang sudah selesai ini
    cur.execute("""
        SELECT ti.*, p.name as product_name
        FROM transaksi_items ti
        JOIN products p ON ti.id_produk = p.id
        WHERE ti.id_transaksi = %s
    """, (transaksi_id,))
    items_to_rate = cur.fetchall()
    cur.close()

    return render_template('beri_rating.html', items=items_to_rate, transaksi_id=transaksi_id)

# Fungsi untuk MENYIMPAN rating dari form
@app.route('/simpan-rating/<int:transaksi_id>', methods=['POST'])
def simpan_rating(transaksi_id):
    if 'id_user' not in session:
        return redirect(url_for('login'))

    try:
        cur = mysql.connection.cursor()
        user_id = session['id_user']

        for product_id_key, rating in request.form.items():
            if product_id_key.startswith('rating_'):
                real_product_id = product_id_key.split('_')[1]
                komentar = request.form.get(f'komentar_{real_product_id}', '')
                
                # Proses upload file media
                media_filename = None
                media_file = request.files.get(f'media_{real_product_id}')
                if media_file and media_file.filename != '':
                    if allowed_file(media_file.filename): # Pastikan fungsi allowed_file ada
                        ext = media_file.filename.rsplit('.', 1)[1].lower()
                        new_filename = f"rating_{user_id}_{real_product_id}_{int(time.time())}.{ext}"
                        media_filename = secure_filename(new_filename)
                        media_file.save(os.path.join(app.config['UPLOAD_FOLDER'], media_filename))
                    else:
                        flash("Jenis file media tidak diizinkan.", "error")

                # Simpan ke database dengan kolom media_file yang baru
                cur.execute("""
                    INSERT INTO product_ratings (id_produk, id_user, rating, komentar, media_file)
                    VALUES (%s, %s, %s, %s, %s)
                """, (real_product_id, user_id, rating, komentar, media_filename))

        mysql.connection.commit()
        cur.close()
        flash("Ulasan Anda berhasil disimpan. Terima kasih!", "success")

    except Exception as e:
        flash(f"Terjadi kesalahan saat menyimpan ulasan: {e}", "error")
        print(f"Error simpan_rating: {e}") # Untuk debug

    return redirect(url_for('riwayat'))

@app.route('/terima-barang-retur/<int:retur_id>', methods=['POST'])
def terima_barang_retur(retur_id):
    if 'id_user' not in session:
        return redirect(url_for('login'))

    user_id = session['id_user']
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    # Keamanan: Pastikan retur ini milik user yang sedang login
    cur.execute("SELECT id_transaksi FROM retur_barang WHERE id_retur = %s AND id_pembeli = %s", (retur_id, user_id))
    retur = cur.fetchone()

    if not retur:
        flash("Aksi tidak diizinkan.", "error")
        cur.close()
        return redirect(url_for('riwayat'))
    
    # Update status di tabel retur dan transaksi
    cur.execute("UPDATE retur_barang SET status_retur = 'Selesai' WHERE id_retur = %s", (retur_id,))
    cur.execute("UPDATE transaksi SET status = 'retur_selesai' WHERE id_transaksi = %s", (retur['id_transaksi'],))
    
    mysql.connection.commit()
    cur.close()
    
    flash("Terima kasih telah mengonfirmasi. Proses retur telah selesai.", "success")
    return redirect(url_for('riwayat'))

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    cur.execute("SELECT COUNT(id_user) as user_count FROM users WHERE id_level IN (3, 4)")
    user_count = cur.fetchone()['user_count']

    cur.execute("SELECT COUNT(id) as product_count FROM products")
    product_count = cur.fetchone()['product_count']

    cur.execute("SELECT COUNT(id_transaksi) as order_count FROM transaksi WHERE status = 'selesai'")
    order_count = cur.fetchone()['order_count']

    cur.execute("SELECT SUM(total_harga) AS total_revenue FROM transaksi WHERE status = 'selesai'")
    revenue_data = cur.fetchone()
    total_revenue = revenue_data['total_revenue'] if revenue_data and revenue_data['total_revenue'] else 0
    
    cur.close()

    return render_template("admin/dashboard_admin.html",
                           user_count=user_count,
                           product_count=product_count,
                           order_count=order_count,
                           total_revenue=total_revenue)
    
@app.route('/admin/users')
@admin_required
def admin_users():
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("""
        SELECT u.id_user, p.nama, u.email, p.no_telp, l.level_name, u.is_active
        FROM users u
        JOIN profile p ON u.id_profile = p.id_profile
        JOIN levels l ON u.id_level = l.id_level
        ORDER BY u.id_user ASC
    """)
    user_list = cur.fetchall()
    cur.close()
    return render_template('admin/users.html', users=user_list)

@app.route('/admin/users/add', methods=['GET', 'POST'])
@admin_required
def admin_add_user():
    if request.method == 'POST':
        nama = request.form['nama']
        email = request.form['email']
        password = request.form['password']
        id_level = request.form['id_level']
        alamat = request.form.get('alamat', '')
        no_telp = request.form.get('no_telp', '')

        if not all([nama, email, password, id_level]):
            flash("Nama, Email, Password, dan Peran wajib diisi.", "error")
            return redirect(url_for('admin_add_user'))
        
        hashed_password = generate_password_hash(password)
        
        cur = mysql.connection.cursor()
        try:
            cur.execute("INSERT INTO profile (nama, alamat, no_telp) VALUES (%s, %s, %s)",
                       (nama, alamat, no_telp))
            id_profile_baru = cur.lastrowid

            cur.execute("""
                INSERT INTO users (email, password, id_level, id_profile)
                VALUES (%s, %s, %s, %s)
            """, (email, hashed_password, id_level, id_profile_baru))
            
            mysql.connection.commit()
            flash("Pengguna baru berhasil ditambahkan.", "success")
        except Exception as e:
            mysql.connection.rollback()
            flash(f"Gagal menambahkan pengguna: {e}", "error")
        finally:
            cur.close()
        
        return redirect(url_for('admin_users'))

    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("SELECT id_level, level_name FROM levels")
    levels = cur.fetchall()
    cur.close()
    return render_template('admin/add_user.html', levels=levels)

@app.route('/admin/users/edit/<int:user_id>', methods=['GET', 'POST'])
@admin_required
def admin_edit_user(user_id):
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    if request.method == 'POST':
        nama = request.form['nama']
        email = request.form['email']
        id_level = request.form['id_level']
        no_telp = request.form.get('no_telp', '')
        new_password = request.form.get('new_password')
        id_profile = request.form['id_profile']

        cur.execute("UPDATE profile SET nama = %s, no_telp = %s WHERE id_profile = %s",
                   (nama, no_telp, id_profile))

        if new_password:
            hashed_password = generate_password_hash(new_password)
            cur.execute("UPDATE users SET email = %s, id_level = %s, password = %s WHERE id_user = %s",
                       (email, id_level, hashed_password, user_id))
        else:
            cur.execute("UPDATE users SET email = %s, id_level = %s WHERE id_user = %s",
                       (email, id_level, user_id))

        mysql.connection.commit()
        cur.close()
        flash("Data pengguna berhasil diperbarui.", "success")
        return redirect(url_for('admin_users'))

    cur.execute("""
        SELECT u.id_user, u.email, u.id_level, u.id_profile, p.nama, p.no_telp
        FROM users u JOIN profile p ON u.id_profile = p.id_profile
        WHERE u.id_user = %s
    """, (user_id,))
    user_data = cur.fetchone()
    
    cur.execute("SELECT id_level, level_name FROM levels")
    levels = cur.fetchall()
    cur.close()
    
    return render_template('admin/edit_user.html', user=user_data, levels=levels)

@app.route('/admin/users/toggle_active/<int:user_id>', methods=['POST'])
@admin_required
def admin_toggle_user_active(user_id):
    cur = mysql.connection.cursor()
    cur.execute("UPDATE users SET is_active = NOT is_active WHERE id_user = %s", (user_id,))
    mysql.connection.commit()
    cur.close()
    flash("Status pengguna berhasil diubah.", "success")
    return redirect(url_for('admin_users'))

@app.route('/admin/products')
@admin_required
def admin_products():
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("""
        SELECT p.id, p.name, p.is_active, t.nama_toko
        FROM products p
        JOIN users u ON p.id_user = u.id_user
        LEFT JOIN toko t ON u.id_user = t.id_user
        ORDER BY p.id DESC
    """)
    product_list = cur.fetchall()
    cur.close()
    return render_template('admin/products.html', products=product_list)

@app.route('/admin/products/toggle_active/<int:product_id>', methods=['POST'])
@admin_required
def admin_toggle_product_active(product_id):
    cur = mysql.connection.cursor()
    cur.execute("UPDATE products SET is_active = NOT is_active WHERE id = %s", (product_id,))
    mysql.connection.commit()
    cur.close()
    flash("Status produk berhasil diubah.", "success")
    return redirect(url_for('admin_products'))

@app.route('/admin/export/users')
@admin_required
def admin_export_users():
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("""
        SELECT u.id_user, p.nama, u.email, p.no_telp, l.level_name, 
               CASE WHEN u.is_active = 1 THEN 'Aktif' ELSE 'Tidak Aktif' END as status
        FROM users u
        JOIN profile p ON u.id_profile = p.id_profile
        JOIN levels l ON u.id_level = l.id_level
    """)
    users = cur.fetchall()
    cur.close()

    si = StringIO()
    cw = csv.writer(si)
    
    if users:
        headers = list(users[0].keys())
        cw.writerow(headers)
        for user in users:
            cw.writerow(list(user.values()))

    output = si.getvalue()
    si.close()
    
    response = Response(output, mimetype="text/csv")
    response.headers["Content-Disposition"] = "attachment; filename=daftar_pengguna.csv"
    return response

@app.route('/dashboard-pengelola')
def dashboard_pengelola():
    if 'id_user' not in session or session.get('id_level') != 2:
        flash("Halaman ini hanya untuk Pengelola.", "error")
        return redirect(url_for('login'))

    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("""
        SELECT 
            aduan.*, 
            prof.nama as user_name,
            t.nama_toko 
        FROM pengaduan aduan
        JOIN users u ON aduan.id_pelapor = u.id_user
        JOIN profile prof ON u.id_profile = prof.id_profile
        LEFT JOIN toko t ON u.id_user = t.id_user
        ORDER BY aduan.status ASC, aduan.tanggal_lapor DESC
    """)
    daftar_pengaduan = cur.fetchall()
    cur.close()
    
    return render_template('dashboard_pengelola.html', complaints=daftar_pengaduan)

# GANTI TOTAL FUNGSI detail_pengaduan ANDA DENGAN YANG INI
@app.route('/pengaduan/<int:complaint_id>', methods=['GET', 'POST'])
def detail_pengaduan(complaint_id):
    # Penjaga keamanan: Pastikan yang login adalah pengelola (level 2)
    if 'id_user' not in session or session.get('id_level') != 2:
        flash("Halaman ini hanya untuk Pengelola.", "error")
        return redirect(url_for('login'))

    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    # --- Bagian untuk memproses form (POST) ---
    if request.method == 'POST':
        # Ambil data dari form yang dikirim
        tanggapan_baru = request.form.get('tanggapan')
        status_baru = request.form.get('status')

        # 1. Jika ada isi balasan, simpan ke tabel tanggapan_pengaduan
        if tanggapan_baru:
            cur.execute("""
                INSERT INTO tanggapan_pengaduan (id_pengaduan, id_pengirim, peran_pengirim, isi_tanggapan)
                VALUES (%s, %s, 'pengelola', %s)
            """, (complaint_id, session['id_user'], tanggapan_baru))
        
        # 2. Selalu update status di tabel pengaduan utama
        cur.execute("UPDATE pengaduan SET status = %s WHERE id = %s", (status_baru, complaint_id))
        
        mysql.connection.commit()
        flash("Aksi berhasil disimpan dan tanggapan telah dikirim.", "success")
        cur.close()
        return redirect(url_for('detail_pengaduan', complaint_id=complaint_id))

    # --- Bagian untuk menampilkan halaman (GET) ---
    # 1. Ambil detail pengaduan utama
    cur.execute("""
        SELECT 
            aduan.*, 
            prof.nama as user_name,
            t.nama_toko,
            trans.metode_pembayaran,
            trans.total_harga
        FROM pengaduan aduan
        JOIN users u ON aduan.id_pelapor = u.id_user
        JOIN profile prof ON u.id_profile = prof.id_profile
        LEFT JOIN transaksi trans ON aduan.id_transaksi = trans.id_transaksi
        LEFT JOIN toko t ON u.id_user = t.id_user
        WHERE aduan.id = %s
    """, (complaint_id,))
    complaint = cur.fetchone()

    if not complaint:
        flash("Pengaduan tidak ditemukan.", "error")
        cur.close()
        return redirect(url_for('dashboard_pengelola'))
    
    id_penjual_terkait = None
    if complaint.get('id_transaksi'):
        # Cari penjual berdasarkan produk di dalam transaksi
        cur.execute("""
            SELECT p.id_user FROM products p
            JOIN transaksi_items ti ON p.id = ti.id_produk
            WHERE ti.id_transaksi = %s
            LIMIT 1
        """, (complaint['id_transaksi'],))
        penjual = cur.fetchone()
        if penjual:
            id_penjual_terkait = penjual['id_user']

    # 2. Ambil SEMUA riwayat percakapan untuk pengaduan ini
    cur.execute("""
        SELECT t.*, p.nama as nama_pengirim
        FROM tanggapan_pengaduan t
        JOIN users u ON t.id_pengirim = u.id_user
        JOIN profile p ON u.id_profile = p.id_profile
        WHERE t.id_pengaduan = %s 
        ORDER BY t.tanggal_kirim ASC
    """, (complaint_id,))
    riwayat_tanggapan = cur.fetchall()
    cur.close()

    # 3. Kirim data pengaduan dan riwayat tanggapan ke template
    return render_template('detail_pengaduan.html', complaint=complaint, tanggapan=riwayat_tanggapan, id_penjual_terkait=id_penjual_terkait)
        
@app.route('/chat-internal/<int:pengaduan_id>', methods=['GET', 'POST'])
def chat_internal(pengaduan_id):
    if 'id_user' not in session:
        return redirect(url_for('login'))

    user_id = session['id_user']
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    
    # --- QUERY YANG DIPERBAIKI ADA DI SINI ---
    # Query ini sekarang secara akurat mencari ID penjual terkait pengaduan
    cur.execute("""
        SELECT 
            pgn.id, 
            pgn.subjek,
            pgn.id_transaksi,
            (SELECT p.id_user 
             FROM products p 
             JOIN transaksi_items ti ON p.id = ti.id_produk 
             WHERE ti.id_transaksi = pgn.id_transaksi 
             LIMIT 1) AS id_penjual
        FROM pengaduan pgn
        WHERE pgn.id = %s
    """, (pengaduan_id,))
    pengaduan_info = cur.fetchone()

    # Keamanan: Hanya pengelola (level 2) atau penjual terkait yang bisa masuk
    # Dengan query yang benar, pengecekan ini akan berfungsi
    if not pengaduan_info or (session.get('id_level') != 2 and user_id != pengaduan_info.get('id_penjual')):
        flash("Anda tidak memiliki akses ke percakapan ini.", "error")
        cur.close()
        return redirect(url_for('home_buyer'))

    if request.method == 'POST':
        isi_pesan = request.form.get('isi_pesan')
        if isi_pesan:
            peran = 'pengelola' if session.get('id_level') == 2 else 'penjual'
            cur.execute("""
                INSERT INTO chat_internal (id_pengaduan, id_pengirim, peran_pengirim, isi_pesan)
                VALUES (%s, %s, %s, %s)
            """, (pengaduan_id, user_id, peran, isi_pesan))
            mysql.connection.commit()
        return redirect(url_for('chat_internal', pengaduan_id=pengaduan_id))

    # Ambil riwayat chat internal (logika ini tidak berubah)
    cur.execute("""
        SELECT ci.*, p.nama as nama_pengirim FROM chat_internal ci
        JOIN users u ON ci.id_pengirim = u.id_user
        JOIN profile p ON u.id_profile = p.id_profile
        WHERE ci.id_pengaduan = %s ORDER BY ci.tanggal_kirim ASC
    """, (pengaduan_id,))
    daftar_chat = cur.fetchall()
    cur.close()
    
    return render_template('chat_internal.html', pengaduan=pengaduan_info, daftar_chat=daftar_chat)

@app.route('/kirim-pengaduan', methods=['GET', 'POST'])
def kirim_pengaduan():
    if 'id_user' not in session or session.get('id_level') not in [3, 4]:
        flash("Anda harus login sebagai pembeli atau penjual untuk mengirim pengaduan.", "error")
        return redirect(url_for('login'))

    id_transaksi = request.args.get('id_transaksi', None)

    if request.method == 'POST':
        id_pelapor = session['id_user']
        subjek = request.form['subjek']
        isi_pengaduan = request.form['isi_pengaduan']
        id_transaksi_from_form = request.form.get('id_transaksi')
        peran = 'penjual' if session.get('id_level') == 3 else 'pembeli'

        cur = mysql.connection.cursor()
        cur.execute("""
            INSERT INTO pengaduan (id_pelapor, id_transaksi, peran_pelapor, subjek, isi_pengaduan)
            VALUES (%s, %s, %s, %s, %s)
        """, (id_pelapor, id_transaksi_from_form, peran, subjek, isi_pengaduan))
        mysql.connection.commit()
        cur.close()

        flash("Pengaduan Anda telah berhasil dikirim.", "success")
        return redirect(url_for('home_buyer'))

    return render_template('kirim_pengaduan.html', id_transaksi=id_transaksi)

# Tambahkan 2 fungsi baru ini di app.py

@app.route('/riwayat-pengaduan')
def riwayat_pengaduan():
    if 'id_user' not in session:
        return redirect(url_for('login'))

    user_id = session['id_user']
    user_level = session.get('id_level')
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    
    # --- LOGIKA BARU DENGAN PERCABANGAN BERDASARKAN PERAN ---
    if user_level == 3:
        cur.execute("""
            SELECT DISTINCT pgn.id, pgn.subjek, pgn.status, pgn.tanggal_lapor 
            FROM pengaduan pgn
            WHERE 
                pgn.id_pelapor = %s 
                OR pgn.id_transaksi IN (
                    SELECT DISTINCT ti.id_transaksi
                    FROM transaksi_items ti
                    JOIN products p ON ti.id_produk = p.id
                    WHERE p.id_user = %s
                )
            ORDER BY pgn.tanggal_lapor DESC
        """, (user_id, user_id)) # Perhatikan: user_id digunakan dua kali
    else: # Jika yang login adalah Pembeli (atau peran lain)
        # Gunakan query sederhana yang lama
        cur.execute("""
            SELECT id, subjek, status, tanggal_lapor 
            FROM pengaduan 
            WHERE id_pelapor = %s 
            ORDER BY tanggal_lapor DESC
        """, (user_id,))

    daftar_pengaduan = cur.fetchall()
    cur.close()
    
    # Template yang digunakan tetap sama
    return render_template('riwayat_pengaduan.html', complaints=daftar_pengaduan)

@app.route('/detail-pengaduan-user/<int:pengaduan_id>', methods=['GET', 'POST'])
def detail_pengaduan_user(pengaduan_id):
    if 'id_user' not in session:
        return redirect(url_for('login'))

    user_id = session['id_user']
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    # Ambil detail pengaduan utama, pastikan ini milik user yg login
    cur.execute("SELECT * FROM pengaduan WHERE id = %s AND id_pelapor = %s", (pengaduan_id, user_id))
    pengaduan = cur.fetchone()

    if not pengaduan:
        flash("Pengaduan tidak ditemukan atau Anda tidak memiliki akses.", "error")
        cur.close()
        return redirect(url_for('riwayat_pengaduan'))

    if request.method == 'POST':
        isi_balasan = request.form.get('isi_balasan')
        if isi_balasan:
            peran = 'penjual' if session.get('id_level') == 3 else 'pembeli'
            cur.execute("""
                INSERT INTO tanggapan_pengaduan (id_pengaduan, id_pengirim, peran_pengirim, isi_tanggapan)
                VALUES (%s, %s, %s, %s)
            """, (pengaduan_id, user_id, peran, isi_balasan))
            # Ubah status menjadi 'Diproses' setiap kali user membalas
            cur.execute("UPDATE pengaduan SET status = 'Diproses' WHERE id = %s", (pengaduan_id,))
            mysql.connection.commit()
            flash("Balasan Anda telah terkirim.", "success")
        cur.close()
        return redirect(url_for('detail_pengaduan_user', pengaduan_id=pengaduan_id))

    # Ambil seluruh riwayat percakapan untuk pengaduan ini
    cur.execute("""
        SELECT t.*, p.nama as nama_pengirim
        FROM tanggapan_pengaduan t
        JOIN users u ON t.id_pengirim = u.id_user
        JOIN profile p ON u.id_profile = p.id_profile
        WHERE t.id_pengaduan = %s 
        ORDER BY t.tanggal_kirim ASC
    """, (pengaduan_id,))
    riwayat_tanggapan = cur.fetchall()
    cur.close()
    
    return render_template('detail_pengaduan_user.html', pengaduan=pengaduan, tanggapan=riwayat_tanggapan)

@app.route('/dashboard-pimpinan')
def dashboard_pimpinan():
    if 'id_user' not in session or session.get('id_level') != 5:
        flash("Halaman ini hanya untuk Pimpinan.", "error")
        return redirect(url_for('login'))

    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    cur.execute("SELECT SUM(total_harga) as total_pendapatan FROM transaksi WHERE status = 'selesai'")
    total_pendapatan = cur.fetchone()['total_pendapatan'] or 0

    cur.execute("SELECT COUNT(id_transaksi) as total_transaksi FROM transaksi")
    total_transaksi = cur.fetchone()['total_transaksi'] or 0

    cur.execute("SELECT COUNT(id_user) as total_pengguna FROM users WHERE id_level IN (3,4)")
    total_pengguna = cur.fetchone()['total_pengguna'] or 0

    cur.execute("SELECT COUNT(id) as total_produk FROM products")
    total_produk = cur.fetchone()['total_produk'] or 0
    
    kpi_data = {
        'total_pendapatan': total_pendapatan,
        'total_transaksi': total_transaksi,
        'total_pengguna': total_pengguna,
        'total_produk': total_produk
    }

    cur.execute("""
        SELECT DATE(tanggal_pesanan) as tanggal, SUM(total_harga) as pendapatan_harian
        FROM transaksi WHERE status = 'selesai' AND tanggal_pesanan >= CURDATE() - INTERVAL 7 DAY
        GROUP BY DATE(tanggal_pesanan) ORDER BY tanggal ASC;
    """)
    penjualan_harian = cur.fetchall()
    chart_labels = [item['tanggal'].strftime('%d %b') for item in penjualan_harian]
    chart_data = [float(item['pendapatan_harian']) for item in penjualan_harian]

    cur.execute("""
        SELECT p.name, SUM(ti.kuantitas) as total_terjual FROM transaksi_items ti
        JOIN products p ON ti.id_produk = p.id JOIN transaksi t ON ti.id_transaksi = t.id_transaksi
        WHERE t.status = 'selesai' GROUP BY p.name ORDER BY total_terjual DESC LIMIT 5;
    """)
    top_produk = cur.fetchall()

    cur.execute("""
        SELECT t.nama_toko, AVG(pr.rating) as rata_rating, COUNT(pr.id) as jumlah_ulasan
        FROM product_ratings pr JOIN products p ON pr.id_produk = p.id
        JOIN toko t ON p.id_user = t.id_user GROUP BY t.nama_toko
        ORDER BY rata_rating DESC, jumlah_ulasan DESC LIMIT 5;
    """)
    top_toko = cur.fetchall()
    cur.close()

    return render_template('dashboard_pimpinan.html', 
                           kpi=kpi_data,
                           chart_labels=chart_labels,
                           chart_data=chart_data,
                           top_produk=top_produk,
                           top_toko=top_toko)

@app.route('/download-excel')
def download_excel():
    if 'id_user' not in session or session.get('id_level') != 5:
        return redirect(url_for('login'))
        
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("""
        SELECT id_transaksi, id_user, total_harga, status, metode_pengiriman, metode_pembayaran, tanggal_pesanan
        FROM transaksi WHERE status = 'selesai'
    """)
    data = cur.fetchall()
    cur.close()

    df = pd.DataFrame(data)
    output = io.BytesIO()
    writer = pd.ExcelWriter(output, engine='xlsxwriter')
    df.to_excel(writer, sheet_name='Laporan Penjualan', index=False)
    writer.close()
    output.seek(0)
    
    return Response(output, mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    headers={"Content-Disposition": "attachment;filename=laporan_penjualan.xlsx"})

@app.route('/download-pdf')
def download_pdf():
    if 'id_user' not in session or session.get('id_level') != 5:
        flash("Aksi tidak diizinkan.", "error")
        return redirect(url_for('login'))

    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    
    cur.execute("""
        SELECT id_transaksi, total_harga, metode_pengiriman, metode_pembayaran, tanggal_pesanan
        FROM transaksi WHERE status = 'selesai'
    """)
    data_transaksi = cur.fetchall()
    
    total_pendapatan = sum(item['total_harga'] for item in data_transaksi)
    
    cur.close()

    tanggal_sekarang = datetime.now().strftime("%d %B %Y, %H:%M:%S")
    
    html_string = render_template('laporan_pdf.html', 
                                  data=data_transaksi, 
                                  total_pendapatan=total_pendapatan,
                                  tanggal_dibuat=tanggal_sekarang)
                                  
    pdf_file = HTML(string=html_string).write_pdf()
    
    return Response(pdf_file,
                    mimetype="application/pdf",
                    headers={"Content-Disposition": "attachment;filename=laporan_penjualan.pdf"})

if __name__ == '__main__':
    app.run(debug=True)