from flask import Blueprint, render_template, request, redirect, url_for, session, flash, Response
from flask_mysqldb import MySQLdb
from werkzeug.security import generate_password_hash
from functools import wraps
import csv
from io import StringIO

# Inisialisasi Blueprint
admin_bp = Blueprint('admin_bp', __name__,
                     template_folder='templates',
                     static_folder='static')

# Variabel ini akan diisi dari app.py utama
mysql = None

# ====================================================================
# DECORATOR: Untuk mengecek apakah yang login adalah ADMIN (id_level=1)
# ====================================================================
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'id_user' not in session or session.get('id_level') != 1:
            flash('Anda harus login sebagai Admin untuk mengakses halaman ini.', 'error')
            return redirect(url_for('login')) # Arahkan ke halaman login utama
        return f(*args, **kwargs)
    return decorated_function

# ====================================================================
# DASHBOARD ADMIN
# ====================================================================
@admin_bp.route('/dashboard')
@admin_required
def dashboard():
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    # Jumlah Pengguna (Pembeli & Penjual)
    cur.execute("SELECT COUNT(id_user) as user_count FROM users WHERE id_level IN (3, 4)")
    user_count = cur.fetchone()['user_count']

    # Jumlah Produk
    cur.execute("SELECT COUNT(id) as product_count FROM products")
    product_count = cur.fetchone()['product_count']

    # Jumlah Transaksi Selesai
    cur.execute("SELECT COUNT(id_transaksi) as order_count FROM transaksi WHERE status = 'selesai'")
    order_count = cur.fetchone()['order_count']

    # Total Pendapatan
    cur.execute("SELECT SUM(total_harga) AS total_revenue FROM transaksi WHERE status = 'selesai'")
    revenue_data = cur.fetchone()
    total_revenue = revenue_data['total_revenue'] if revenue_data and revenue_data['total_revenue'] else 0
    
    cur.close()

    return render_template("admin/dashboard_admin.html",
                           user_count=user_count,
                           product_count=product_count,
                           order_count=order_count,
                           total_revenue=total_revenue)

# ====================================================================
# MANAJEMEN PENGGUNA (CRUD)
# ====================================================================
@admin_bp.route('/users')
@admin_required
def users():
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    # Ambil semua data user kecuali password, join dengan level dan profile
    cur.execute("""
        SELECT u.id_user, p.nama, u.email, p.no_telp, l.nama_level, u.is_active
        FROM users u
        JOIN profile p ON u.id_profile = p.id_profile
        JOIN level l ON u.id_level = l.id_level
        ORDER BY u.id_user ASC
    """)
    user_list = cur.fetchall()
    cur.close()
    return render_template('admin/users.html', users=user_list)

@admin_bp.route('/users/add', methods=['GET', 'POST'])
@admin_required
def add_user():
    if request.method == 'POST':
        # 1. Ambil data dari form
        nama = request.form['nama']
        email = request.form['email']
        password = request.form['password']
        id_level = request.form['id_level']
        alamat = request.form.get('alamat', '') # Opsional
        no_telp = request.form.get('no_telp', '') # Opsional

        # 2. Validasi dasar
        if not all([nama, email, password, id_level]):
            flash("Nama, Email, Password, dan Peran wajib diisi.", "error")
            return redirect(url_for('admin_bp.add_user'))
        
        # Enkripsi password
        hashed_password = generate_password_hash(password)
        
        cur = mysql.connection.cursor()
        try:
            # 3. Buat entri di tabel 'profile' terlebih dahulu
            cur.execute("INSERT INTO profile (nama, alamat, no_telp) VALUES (%s, %s, %s)",
                       (nama, alamat, no_telp))
            id_profile_baru = cur.lastrowid

            # 4. Buat entri di tabel 'users' dengan id_profile yang baru dibuat
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
        
        return redirect(url_for('admin_bp.users'))

    # Ambil daftar level untuk dropdown di form
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("SELECT id_level, nama_level FROM level")
    levels = cur.fetchall()
    cur.close()
    return render_template('admin/add_user.html', levels=levels)

@admin_bp.route('/users/edit/<int:user_id>', methods=['GET', 'POST'])
@admin_required
def edit_user(user_id):
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    if request.method == 'POST':
        # Ambil data dari form
        nama = request.form['nama']
        email = request.form['email']
        id_level = request.form['id_level']
        no_telp = request.form.get('no_telp', '')
        new_password = request.form.get('new_password')
        id_profile = request.form['id_profile']

        # Update tabel profile
        cur.execute("UPDATE profile SET nama = %s, no_telp = %s WHERE id_profile = %s",
                   (nama, no_telp, id_profile))

        # Jika admin mengisi password baru, update passwordnya
        if new_password:
            hashed_password = generate_password_hash(new_password)
            cur.execute("UPDATE users SET email = %s, id_level = %s, password = %s WHERE id_user = %s",
                       (email, id_level, hashed_password, user_id))
        else: # Jika tidak, update data lain tanpa menyentuh password
            cur.execute("UPDATE users SET email = %s, id_level = %s WHERE id_user = %s",
                       (email, id_level, user_id))

        mysql.connection.commit()
        cur.close()
        flash("Data pengguna berhasil diperbarui.", "success")
        return redirect(url_for('admin_bp.users'))

    # GET Method: Tampilkan data user yang akan di-edit
    cur.execute("""
        SELECT u.id_user, u.email, u.id_level, u.id_profile, p.nama, p.no_telp
        FROM users u JOIN profile p ON u.id_profile = p.id_profile
        WHERE u.id_user = %s
    """, (user_id,))
    user_data = cur.fetchone()
    
    cur.execute("SELECT id_level, nama_level FROM level")
    levels = cur.fetchall()
    cur.close()
    
    return render_template('admin/edit_user.html', user=user_data, levels=levels)

@admin_bp.route('/users/toggle_active/<int:user_id>', methods=['POST'])
@admin_required
def toggle_user_active(user_id):
    cur = mysql.connection.cursor()
    # Logika soft delete: membalik status is_active (jika 1 jadi 0, jika 0 jadi 1)
    cur.execute("UPDATE users SET is_active = NOT is_active WHERE id_user = %s", (user_id,))
    mysql.connection.commit()
    cur.close()
    flash("Status pengguna berhasil diubah.", "success")
    return redirect(url_for('admin_bp.users'))

# ====================================================================
# MANAJEMEN PRODUK
# ====================================================================
@admin_bp.route('/products')
@admin_required
def products():
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("""
        SELECT 
            p.id, p.name, p.is_active, 
            t.nama_toko,
            (SELECT SUM(stok) FROM product_variations WHERE id_produk = p.id) as total_stock,
            (SELECT MIN(harga) FROM product_variations WHERE id_produk = p.id) as min_price
        FROM products p
        JOIN toko t ON p.id_user = t.id_user
        ORDER BY p.id DESC
    """)
    product_list = cur.fetchall()
    cur.close()
    return render_template('admin/products.html', products=product_list)

@admin_bp.route('/products/toggle_active/<int:product_id>', methods=['POST'])
@admin_required
def toggle_product_active(product_id):
    # Logika soft delete untuk produk
    cur = mysql.connection.cursor()
    cur.execute("UPDATE products SET is_active = NOT is_active WHERE id = %s", (product_id,))
    mysql.connection.commit()
    cur.close()
    flash("Status produk berhasil diubah.", "success")
    return redirect(url_for('admin_bp.products'))


# ====================================================================
# FITUR EKSPOR DATA
# ====================================================================
@admin_bp.route('/export/users')
@admin_required
def export_users():
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("""
        SELECT u.id_user, p.nama, u.email, p.no_telp, l.nama_level, 
               CASE WHEN u.is_active = 1 THEN 'Aktif' ELSE 'Tidak Aktif' END as status
        FROM users u
        JOIN profile p ON u.id_profile = p.id_profile
        JOIN level l ON u.id_level = l.id_level
    """)
    users = cur.fetchall()
    cur.close()

    si = StringIO()
    cw = csv.writer(si)
    
    if users:
        # Tulis header
        headers = list(users[0].keys())
        cw.writerow(headers)
        # Tulis data
        for user in users:
            cw.writerow(list(user.values()))

    output = si.getvalue()
    si.close()
    
    response = Response(output, mimetype="text/csv")
    response.headers["Content-Disposition"] = "attachment; filename=daftar_pengguna.csv"
    return response