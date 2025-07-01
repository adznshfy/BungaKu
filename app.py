from itertools import product
import os
import time
from flask import Flask, jsonify, render_template, redirect, request, url_for, session, flash
from flask_mysqldb import MySQL, MySQLdb
from flask_mail import Mail
import bcrypt
from dotenv import load_dotenv
import email_verification
from werkzeug.utils import secure_filename
from admin import admin_bp

load_dotenv()

app = Flask(__name__)

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
app.register_blueprint(admin_bp)

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

    # Check if email already exists
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
        # Query dengan JOIN untuk mengambil data dari users dan profile
        cur.execute("""
            SELECT u.id_user, u.password, u.id_level, u.id_profile, p.nama, u.email
            FROM users u
            JOIN profile p ON u.id_profile = p.id_profile
            WHERE u.email = %s
        """, (email,))
        user = cur.fetchone()
        cur.close()

        if user and bcrypt.checkpw(password, user['password'].encode('utf-8')):
            session['id_user'] = user['id_user']
            session['id_profile'] = user['id_profile']
            session['id_level'] = user['id_level']
            session['nama'] = user['nama']
            session['email'] = user['email']

            flash(f"Selamat datang kembali, {user['nama']}!", "success")
            
            id_level = user['id_level']
            if id_level == 1: # Admin
                return redirect(url_for('management_bp.dashboard_admin'))
            elif id_level == 2: # Pengelola
                return redirect(url_for('dashboard_pengelola'))
            elif id_level == 5: # Pemimpin
                return redirect(url_for('management_bp.dashboard_pemimpin'))
            elif id_level == 3: # Penjual
                return redirect(url_for('dashboard_penjual'))
            else: # Pembeli (level 4) atau default
                return redirect(url_for('home_buyer')) # Arahkan semua ke dashboard utama
        else:
            error = "Gagal login. Cek kembali email atau password Anda."
    return render_template("login.html", error=error)


@app.route('/profile', methods=["GET", "POST"])
def profile():
    if 'id_user' not in session:
        flash("Silakan login untuk melihat profil Anda.", "warning")
        return redirect(url_for('login'))

    profile_id = session['id_profile']
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    # Ambil data profil saat ini untuk ditampilkan atau untuk Cek file foto lama
    cur.execute("SELECT * FROM profile WHERE id_profile = %s", (profile_id,))
    profile_data = cur.fetchone()

    if request.method == "POST":
        # Ambil data dari form yang dikirim
        nama = request.form['nama']
        no_telp = request.form['no_telp']
        alamat = request.form['alamat']
        foto = request.files.get('foto') # Ambil file foto

        foto_filename = profile_data['foto'] if profile_data else None

        # Cek jika ada file foto baru yang di-upload
        if foto and foto.filename != '':
            if allowed_file(foto.filename): # Gunakan fungsi yang sudah ada di app.py
                # Buat nama file unik untuk menghindari konflik
                ext = foto.filename.rsplit('.', 1)[1].lower()
                new_filename = f"profile_{profile_id}_{int(time.time())}.{ext}"
                foto_filename = secure_filename(new_filename)
                
                # Simpan file baru
                foto.save(os.path.join(app.config['UPLOAD_FOLDER'], foto_filename))
                
                # Hapus file foto lama jika ada dan berbeda dari yang baru
                old_photo = profile_data['foto'] if profile_data else None
                if old_photo and old_photo != foto_filename:
                    old_photo_path = os.path.join(app.config['UPLOAD_FOLDER'], old_photo)
                    if os.path.exists(old_photo_path):
                        os.remove(old_photo_path)
            else:
                flash("Jenis file gambar tidak diizinkan.", "error")
                return redirect(url_for('profile'))

        # Update data ke database
        cur.execute("""
            UPDATE profile SET nama=%s, no_telp=%s, alamat=%s, foto=%s
            WHERE id_profile=%s
        """, (nama, no_telp, alamat, foto_filename, profile_id))
        mysql.connection.commit()

        # Update nama di session agar langsung tampil di layout
        session['nama'] = nama
        
        flash("Profil Anda berhasil diperbarui!", "success")
        cur.close()
        return redirect(url_for('profile'))

    # Jika method adalah GET, cukup tampilkan halaman dengan data yang sudah diambil
    cur.close()
    return render_template("profile.html", profile=profile_data, id_level=session.get('id_level'))

# Tambahkan dua fungsi ini di app.py

@app.route('/registrasi-penjual', methods=['GET'])
def registrasi_penjual():
    # Penjaga: Pastikan hanya pembeli (level 4) yang bisa akses halaman ini
    if session.get('id_level') != 4:
        flash("Anda sudah terdaftar sebagai penjual atau aksi tidak diizinkan.", "warning")
        return redirect(url_for('profile'))
    
    # Cukup tampilkan halaman formulirnya
    return render_template('registrasi_penjual.html')

# Ganti seluruh fungsi proses_registrasi_penjual yang lama dengan yang ini

@app.route('/proses-registrasi-penjual', methods=['POST'])
def proses_registrasi_penjual():
    if session.get('id_level') != 4:
        return redirect(url_for('home_buyer'))

    # --- 1. Ambil semua data dari form ---
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

# Ganti fungsi home_buyer yang lama dengan yang ini di app.py

# Ganti seluruh fungsi home_buyer() Anda dengan kode ini
@app.route("/home-buyer")
def home_buyer():
    # --- PENJAGA BARU ---
    # Hanya pembeli (4) dan penjual (3) yang boleh masuk
    if 'id_user' not in session or session.get('id_level') not in [3, 4]:
        flash("Halaman ini tidak tersedia untuk peran Anda.", "error")

        # Arahkan petinggi ke dashboard mereka masing-masing jika mencoba akses
        id_level = session.get('id_level')
        if id_level == 1: return redirect(url_for('dashboard_admin'))
        if id_level == 2: return redirect(url_for('dashboard_pengelola'))
        if id_level == 5: return redirect(url_for('dashboard_pemimpin'))

        # Jika tidak ada sesi, arahkan ke login
        return redirect(url_for('login'))
    # --- AKHIR PENJAGA ---

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("""
        SELECT 
            p.id, p.name, p.description, p.id_user, 
            t.nama_toko, t.username_toko,
            (SELECT nama_file_gambar FROM product_images WHERE id_produk = p.id ORDER BY id ASC LIMIT 1) as main_image,
            (SELECT MIN(harga) FROM product_variations WHERE id_produk = p.id) as min_price
        FROM products p
        JOIN users u ON p.id_user = u.id_user
        JOIN toko t ON u.id_user = t.id_user
    """)
    produk = cursor.fetchall()
    cursor.close()

    return render_template("home_buyer.html", produk=produk)

@app.route('/home-seller')
def home_seller():
    # Hak akses untuk penjual (level 3)
    if session.get('id_level') != 3:
        flash("Hanya penjual yang dapat mengakses halaman ini.", "error")
        return redirect(url_for('home_buyer'))
    return render_template('home_seller.html')

# Menampilkan produk berdasarkan penjual yang login
# Ganti fungsi seller_product() yang lama dengan ini di app.py

# Ganti seluruh fungsi dashboard_penjual yang lama dengan yang ini

# Ganti seluruh fungsi dashboard_penjual() Anda dengan kode ini
# GANTI TOTAL FUNGSI dashboard_penjual ANDA DENGAN YANG INI
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
        p.id, p.name,
        (SELECT nama_file_gambar FROM product_images WHERE id_produk = p.id ORDER BY id ASC LIMIT 1) as main_image,
        -- [FIX] Hanya mengambil harga minimal dari varian yang aktif
        (SELECT MIN(harga) FROM product_variations WHERE id_produk = p.id AND is_active = 1) as min_price,
        -- [FIX] Hanya menjumlahkan stok dari varian yang aktif
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

    cur.close()

    return render_template("dashboard_penjual.html", 
                           toko=toko_info, 
                           produk=daftar_produk, 
                           pesanan_masuk=pesanan_masuk)

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
                           rating_counts=rating_counts)

@app.route('/add-product', methods=['GET', 'POST'])
def add_product():
    # Penjaga Keamanan
    if session.get('id_level') != 3:
        flash("Hanya penjual yang dapat menambah produk.", "error")
        return redirect(url_for('home_buyer'))

    if request.method == 'POST':
        cur = mysql.connection.cursor()
        try:
            # 1. Ambil data utama produk
            name = request.form['name']
            description = request.form['description']
            seller_id = session['id_user']

            # 2. Simpan data utama ke tabel 'products'
            cur.execute("INSERT INTO products (name, description, id_user) VALUES (%s, %s, %s)",
                       (name, description, seller_id))
            
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

    return render_template('add_product.html')

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
            cur.execute("UPDATE products SET name = %s, description = %s WHERE id = %s", (name, description, product_id))

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
    cur.execute("SELECT * FROM product_images WHERE id_produk = %s", (product_id,))
    images = cur.fetchall()
    # [FIX] Hanya ambil varian yang aktif untuk ditampilkan di form edit
    cur.execute("SELECT * FROM product_variations WHERE id_produk = %s AND is_active = 1", (product_id,))
    variations = cur.fetchall()
    cur.execute("SELECT * FROM vouchers WHERE id_produk = %s", (product_id,))
    vouchers = cur.fetchall()
    cur.close()
    
    return render_template('edit_product.html', produk=produk, images=images, variations=variations, vouchers=vouchers)

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

# Route untuk melihat riwayat pembelian
# GANTI TOTAL FUNGSI RIWAYAT ANDA DENGAN YANG INI
# GANTI TOTAL FUNGSI RIWAYAT DI APP.PY ANDA DENGAN YANG INI

@app.route("/riwayat")
def riwayat():
    if 'id_user' not in session:
        flash("Anda harus login untuk melihat riwayat.", "error")
        return redirect(url_for('login'))

    user_id = session['id_user']
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    try:
        cur.execute("SELECT * FROM transaksi WHERE id_user = %s ORDER BY tanggal_pesanan DESC", (user_id,))
        orders = cur.fetchall()

        for order in orders:
            cur.execute("""
                SELECT 
                    ti.kuantitas, ti.harga_saat_beli,
                    p.name as product_name,
                    (SELECT nama_file_gambar FROM product_images WHERE id_produk = ti.id_produk ORDER BY id ASC LIMIT 1) as product_image
                FROM transaksi_items ti
                JOIN products p ON ti.id_produk = p.id
                WHERE ti.id_transaksi = %s
            """, (order['id_transaksi'],))
            
            # Menggunakan nama baru 'detail_items'
            order['detail_items'] = cur.fetchall()

        return render_template("riwayat.html", orders=orders)

    except Exception as e:
        print(f"ERROR DI FUNGSI RIWAYAT: {e}")
        flash("Terjadi kesalahan saat memuat riwayat.", "error")
        return redirect(url_for('home_buyer'))
    finally:
        cur.close()
        
@app.route('/filter-riwayat/<status>')
def filter_riwayat(status):
    # Keamanan, pastikan user sudah login
    if 'id_user' not in session:
        # Untuk AJAX request, lebih baik mengembalikan error daripada redirect
        return jsonify({'error': 'Unauthorized'}), 401

    user_id = session['id_user']
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    # Siapkan query dasar
    query = """
        SELECT * FROM transaksi 
        WHERE id_user = %s
    """
    params = [user_id]

    # Jika statusnya BUKAN 'semua', tambahkan filter status ke query
    if status != 'semua':
        query += " AND status = %s"
        params.append(status)
    
    # Tambahkan urutan
    query += " ORDER BY tanggal_pesanan DESC"

    cur.execute(query, tuple(params))
    orders = cur.fetchall()

    # Ambil detail item untuk setiap order (logika ini sama seperti di fungsi riwayat utama)
    for order in orders:
        cur.execute("""
            SELECT 
                ti.kuantitas, ti.harga_saat_beli,
                p.name as product_name,
                (SELECT nama_file_gambar FROM product_images WHERE id_produk = ti.id_produk ORDER BY id ASC LIMIT 1) as product_image
            FROM transaksi_items ti
            JOIN products p ON ti.id_produk = p.id
            WHERE ti.id_transaksi = %s
        """, (order['id_transaksi'],))
        order['detail_items'] = cur.fetchall()
    
    cur.close()

    # Render HANYA template potongan, bukan layout penuh
    return render_template('_riwayat_list.html', orders=orders)

@app.route("/produk")
def list_produk():
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM products WHERE stock > 0") # Filter by stock
    produk = cursor.fetchall()
    cursor.close()
    return render_template("produk.html", produk=produk)

@app.route('/edit-profile')
def edit_profile():
    return render_template("edit_profile.html")

@app.route('/profile-changed')
def profile_changed():
    return render_template("profile_changed.html")

# --- Fitur Keranjang Belanja Baru ---

# Ganti fungsi add_to_cart yang lama dengan yang ini di app.py

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

# GANTI SELURUH FUNGSI PEMBAYARAN ANDA DENGAN INI

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
    # Kita hanya perlu menampilkan halaman sederhana
    # transaksi_id bisa digunakan jika Anda ingin menampilkan nomor pesanan di halaman ini
    return render_template('pembayaran_berhasil.html', transaksi_id=transaksi_id)

# GANTI SELURUH FUNGSI confirm_purchase() ANDA DENGAN INI
@app.route('/confirm-purchase', methods=['POST'])
def confirm_purchase():
    if 'id_user' not in session:
        return redirect(url_for('login'))

    # --- INI BAGIAN LOGIKA YANG DIPERBAIKI ---
    # Logika yang sama seperti di checkout() untuk menentukan sumber item
    items_to_purchase = session.get('buy_now_item', [])
    session_key_to_clear = 'buy_now_item'

    if not items_to_purchase:
        items_to_purchase = session.get('cart', [])
        session_key_to_clear = 'cart'
    
    if not items_to_purchase:
        return redirect(url_for('home_buyer'))
    # --- AKHIR PERBAIKAN LOGIKA ---

    shipping_method = request.form.get('shipping') 
    payment_method = request.form.get('payment')
    user_id = session['id_user']
    
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    try:
        cur.execute("SELECT pin_hash FROM users WHERE id_user = %s", (user_id,))
        user_pin = cur.fetchone()
        if not user_pin or not user_pin['pin_hash']:
            flash("Anda harus mengatur PIN Keamanan di halaman profil sebelum melanjutkan checkout.", "error")
            cur.close()
            return redirect(url_for('checkout'))

        # Hitung total harga dari items_to_purchase
        total_price = sum(item['price'] * item['quantity'] for item in items_to_purchase)

        # Buat record transaksi utama
        cur.execute("""
            INSERT INTO transaksi (id_user, total_harga, status, expiry_time, metode_pengiriman, metode_pembayaran)
            VALUES (%s, %s, %s, NOW() + INTERVAL 24 HOUR, %s, %s)
        """, (user_id, total_price, 'menunggu_pembayaran', shipping_method, payment_method))
        
        transaksi_id = cur.lastrowid

        # Pindahkan item dari items_to_purchase ke 'transaksi_items' dan potong stok
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
        # Hapus session yang benar setelah berhasil
        session.pop(session_key_to_clear, None)
        
        flash("Pesanan berhasil dibuat! Silakan selesaikan pembayaran.", "info")
        return redirect(url_for('pembayaran', transaksi_id=transaksi_id))

    except Exception as e:
        mysql.connection.rollback()
        flash(f"Terjadi kesalahan: {e}", "error")
        # Jika gagal, kembali ke keranjang biasa
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

@app.route('/admin/dashboard')
def dashboard_admin():
    # ... (kode di dalam fungsi ini tidak perlu diubah) ...
    if 'loggedin' not in session or session.get('id_level') != 1:
        flash('Anda harus login sebagai Admin.', 'warning')
        return redirect(url_for('management_bp.login_khusus'))
    return f"<h1>Dashboard Admin untuk {session.get('nama')}</h1>"


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

@app.route('/pengaduan/<int:complaint_id>', methods=['GET', 'POST'])
def detail_pengaduan(complaint_id):
    if 'id_user' not in session or session.get('id_level') != 2:
        flash("Halaman ini hanya untuk Pengelola.", "error")
        return redirect(url_for('login'))

    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    if request.method == 'POST':
        tanggapan = request.form['tanggapan']
        status_baru = request.form['status']
        cur.execute("""
            UPDATE pengaduan 
            SET tanggapan_pengelola = %s, status = %s, tanggal_tanggapan = NOW()
            WHERE id = %s
        """, (tanggapan, status_baru, complaint_id))
        mysql.connection.commit()
        flash("Balasan berhasil dikirim dan status telah diperbarui.", "success")
        cur.close()
        return redirect(url_for('dashboard_pengelola'))

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
    cur.close()

    if not complaint:
        flash("Pengaduan tidak ditemukan.", "error")
        return redirect(url_for('dashboard_pengelola'))

    return render_template('detail_pengaduan.html', complaint=complaint)
        
# Tambahkan fungsi baru ini di dalam file app.py

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

if __name__ == '__main__':
    app.run(debug=True)