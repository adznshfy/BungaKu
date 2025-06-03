import os
import time
from flask import Flask, render_template, redirect, request, url_for, session, flash
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
app.config['MYSQL_PASSWORD'] = '' # Ensure this is correct, might be 'root' or have a password
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
            # Future: elif user['role'] == 'admin': return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('home'))
        else:
            error = "Gagal login. Cek kembali email atau password Anda."
    return render_template("login.html", error=error)

@app.route('/profile', methods=["GET", "POST"])
def profile():
    if 'id_user' not in session:
        flash("Silakan login untuk melihat profil Anda.", "warning")
        return redirect(url_for('login'))

    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("SELECT * FROM profile WHERE id_user = %s", (session['id_user'],))
    profile_data = cur.fetchone()

    if request.method == "POST":
        nama = request.form['nama']
        nama_lengkap = request.form.get('nama_lengkap') # Use .get for optional fields
        no_telp = request.form['no_telp']
        email = request.form['email']
        alamat = request.form['alamat']
        payment = request.form.get('payment') # Use .get for optional fields

        foto = request.files.get('foto')
        filename = profile_data['foto'] if profile_data and profile_data.get('foto') else None

        if foto and foto.filename != '':
            if allowed_file(foto.filename):
                ext = foto.filename.rsplit('.', 1)[1].lower()
                filename = f"user_{session['id_user']}.{ext}"
                foto.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            else:
                flash("Jenis file gambar tidak diizinkan.", "error")
                return render_template("profile.html", profile=profile_data)

        if profile_data:
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
        flash("Profil Anda berhasil diperbarui!", "success")
        return redirect(url_for('profile_changed'))

    cur.close()
    return render_template("profile.html", profile=profile_data)

@app.route('/logout')
def logout():
    session.clear()
    flash("Anda telah berhasil logout.", "info")
    return redirect(url_for('welcome'))

@app.route('/choose-role', methods=["GET", "POST"])
def choose_role():
    if 'id_user' not in session:
        flash("Silakan login untuk memilih peran.", "warning")
        return redirect(url_for('login'))

    if request.method == 'POST':
        role = request.form['role']
        cur = mysql.connection.cursor()
        cur.execute("UPDATE users SET role=%s WHERE id_user=%s", (role, session['id_user']))
        mysql.connection.commit()
        cur.close()
        session['role'] = role

        if role == 'pembeli':
            flash("Anda sekarang adalah pembeli.", "success")
            return redirect(url_for('home_buyer'))
        elif role == 'penjual':
            flash("Anda sekarang adalah penjual.", "success")
            return redirect(url_for('home_seller'))
    return render_template('choose_role.html')

@app.route("/home-buyer")
def home_buyer():
    if 'id_user' not in session or session.get('role') != 'pembeli':
        flash("Anda harus login sebagai pembeli untuk melihat produk.", "error")
        return redirect(url_for('login'))

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("""
        SELECT p.*
        FROM products p
        WHERE p.stock > 0
    """)
    produk = cursor.fetchall()
    cursor.close()
    return render_template("home_buyer.html", produk=produk)

@app.route('/home-seller')
def home_seller():
    if 'id_user' not in session or session.get('role') != 'penjual':
        flash("Anda harus login sebagai penjual.", "error")
        return redirect(url_for('login'))
    return render_template('home_seller.html')

# Menampilkan produk berdasarkan penjual yang login
@app.route('/seller-product')
def seller_product():
    if 'id_user' not in session or session.get('role') != 'penjual':
        flash("Anda harus login sebagai penjual untuk melihat produk Anda.", "error")
        return redirect(url_for('login'))

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM products WHERE id_user = %s", (session['id_user'],))
    daftar_produk = cursor.fetchall()
    cursor.close()
    return render_template('seller_products.html', daftar_produk=daftar_produk)

# Tambah produk
@app.route('/add-product', methods=['GET', 'POST'])
def add_product():
    if 'id_user' not in session or session.get('role') != 'penjual':
        flash("Anda harus login sebagai penjual untuk menambah produk.", "error")
        return redirect(url_for('login'))

    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        price = request.form['price']
        stock = request.form['stock']
        image = None
        seller_id = session['id_user']

        if 'image' in request.files and request.files['image'].filename != '':
            image_file = request.files['image']
            if allowed_file(image_file.filename):
                image = secure_filename(image_file.filename)
                image_path = os.path.join(app.config['UPLOAD_FOLDER'], image)
                image_file.save(image_path)
            else:
                flash("Jenis file gambar tidak diizinkan.", "error")
                return render_template('add_product.html')

        cursor = mysql.connection.cursor()
        cursor.execute("INSERT INTO products (name, description, price, stock, image, id_user) VALUES (%s, %s, %s, %s, %s, %s)",
                       (name, description, price, stock, image, seller_id))
        mysql.connection.commit()
        cursor.close()
        flash("Produk berhasil ditambahkan!", "success")
        return redirect(url_for('seller_product'))

    return render_template('add_product.html')

# Edit produk
@app.route('/edit-product/<int:product_id>', methods=['GET', 'POST'])
def edit_product(product_id):
    if 'id_user' not in session or session.get('role') != 'penjual':
        flash("Anda tidak memiliki izin untuk mengedit produk ini.", "error")
        return redirect(url_for('login'))

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM products WHERE id = %s AND id_user = %s", (product_id, session['id_user']))
    produk = cursor.fetchone()

    if not produk:
        flash("Produk tidak ditemukan atau Anda tidak memiliki izin untuk mengeditnya.", "error")
        cursor.close()
        return redirect(url_for('seller_product'))

    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        price = request.form['price']
        stock = request.form['stock']
        current_image = produk.get('image')

        if 'image' in request.files and request.files['image'].filename != '':
            image_file = request.files['image']
            if allowed_file(image_file.filename):
                image = secure_filename(image_file.filename)
                image_path = os.path.join(app.config['UPLOAD_FOLDER'], image)
                image_file.save(image_path)
                current_image = image
            else:
                flash("Jenis file gambar tidak diizinkan.", "error")
                return render_template('edit_product.html', produk=produk)

        cursor.execute("""
            UPDATE products SET name=%s, description=%s, price=%s, stock=%s, image=%s
            WHERE id=%s AND id_user=%s
        """, (name, description, price, stock, current_image, product_id, session['id_user']))
        mysql.connection.commit()
        cursor.close()
        flash("Produk berhasil diperbarui!", "success")
        return redirect(url_for('seller_product'))

    cursor.close()
    return render_template('edit_product.html', produk=produk)

# Hapus produk
@app.route('/delete-product/<int:product_id>', methods=['POST'])
def delete_product(product_id):
    if 'id_user' not in session or session.get('role') != 'penjual':
        flash("Anda tidak memiliki izin untuk menghapus produk ini.", "error")
        return redirect(url_for('login'))

    cursor = mysql.connection.cursor()
    cursor.execute("DELETE FROM products WHERE id = %s AND id_user = %s", (product_id, session['id_user']))
    mysql.connection.commit()
    cursor.close()
    flash("Produk berhasil dihapus!", "success")
    return redirect(url_for('seller_product'))

# Ini adalah route beli_produk yang sudah saya berikan sebelumnya
# Pastikan ini ada di app.py Anda
@app.route("/beli-produk/<int:product_id>", methods=["POST"])
def beli_produk(product_id):
    if 'id_user' not in session or session.get('role') != 'pembeli':
        flash("Anda harus login sebagai pembeli untuk melakukan transaksi.", "error")
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
@app.route("/riwayat")
def riwayat():
    # 1. Memastikan pengguna adalah pembeli dan sudah login
    if 'id_user' not in session or session.get('role') != 'pembeli':
        flash("Anda harus login sebagai pembeli untuk melihat riwayat pembelian.", "error")
        return redirect(url_for("login"))

    user_id = session['id_user'] # Mengambil ID pengguna (pembeli) yang sedang login

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    try:
        cursor.execute("""
            SELECT t.*, p.name AS product_name, p.image AS product_image
            FROM transaksi t
            JOIN products p ON t.id_produk = p.id
            WHERE t.id_user = %s
            ORDER BY t.tanggal DESC
        """, (user_id,))

        data = cursor.fetchall() # Mengambil semua baris hasil query sebagai list of dictionaries

        return render_template("riwayat.html", transaksi=data)

    except MySQLdb.Error as e:
        # Menangani error database (jika ada masalah saat query)
        flash(f"Terjadi kesalahan saat mengambil riwayat: {e}", "error")
        print(f"Database error in riwayat: {e}") # Pesan error ini akan muncul di terminal Flask Anda
        return redirect(url_for('home_buyer')) # Kembali ke halaman pembeli jika ada error
    finally:
        # Memastikan cursor database selalu ditutup
        cursor.close()

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

@app.route('/add-to-cart/<int:product_id>', methods=['POST'])
def add_to_cart(product_id):
    if 'id_user' not in session or session.get('role') != 'pembeli':
        flash("Anda harus login sebagai pembeli untuk menambahkan produk ke keranjang.", "error")
        return redirect(url_for('login'))

    quantity = 1 # Default quantity, bisa diubah jika ada input quantity di form

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM products WHERE id = %s", (product_id,))
    product = cursor.fetchone()
    cursor.close()

    if not product:
        flash("Produk tidak ditemukan.", "error")
        return redirect(url_for('home_buyer'))

    if product['stock'] < quantity:
        flash(f"Maaf, stok {product['name']} tidak cukup. Tersedia: {product['stock']}.", "error")
        return redirect(url_for('home_buyer'))

    # Inisialisasi keranjang jika belum ada di session
    if 'cart' not in session:
        session['cart'] = []

    # Cek apakah produk sudah ada di keranjang
    found_in_cart = False
    for item in session['cart']:
        if item['product_id'] == product_id:
            item['quantity'] += quantity
            item['total_item_price'] = item['quantity'] * product['price']
            found_in_cart = True
            break

    if not found_in_cart:
        session['cart'].append({
            'product_id': product_id,
            'name': product['name'],
            'price': float(product['price']),
            'image': product.get('image'),
            'quantity': quantity,
            'stock_available': product['stock'], # Simpan info stok yang tersedia
            'total_item_price': quantity * float(product['price'])
        })

    session.modified = True # Penting agar Flask tahu session telah diubah
    flash(f"{quantity}x {product['name']} berhasil ditambahkan ke keranjang!", "success")
    return redirect(url_for('cart'))

@app.route('/cart')
def cart():
    if 'id_user' not in session or session.get('role') != 'pembeli':
        flash("Anda harus login sebagai pembeli untuk melihat keranjang Anda.", "error")
        return redirect(url_for('login'))

    cart_items = session.get('cart', [])
    total_cart_price = sum(float(item['total_item_price']) for item in cart_items)
    return render_template('cart.html', cart_items=cart_items, total_cart_price=total_cart_price)

@app.route('/update-cart/<int:product_id>', methods=['POST'])
def update_cart(product_id):
    if 'id_user' not in session or session.get('role') != 'pembeli':
        flash("Anda harus login sebagai pembeli.", "error")
        return redirect(url_for('login'))

    new_quantity = int(request.form['quantity'])
    if new_quantity <= 0:
        return redirect(url_for('remove_from_cart', product_id=product_id))

    cart_items = session.get('cart', [])
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT stock FROM products WHERE id = %s", (product_id,))
    product_stock_info = cursor.fetchone()
    cursor.close()

    if not product_stock_info:
        flash("Produk tidak ditemukan.", "error")
        return redirect(url_for('cart'))

    available_stock = product_stock_info['stock']

    for item in cart_items:
        if item['product_id'] == product_id:
            if new_quantity > available_stock:
                flash(f"Stok {item['name']} tidak cukup untuk kuantitas {new_quantity}. Tersedia: {available_stock}.", "error")
                return redirect(url_for('cart'))
            item['quantity'] = new_quantity
            item['total_item_price'] = item['quantity'] * float(item['price'])
            break

    session['cart'] = cart_items
    session.modified = True
    flash("Kuantitas produk berhasil diperbarui.", "success")
    return redirect(url_for('cart'))

@app.route('/remove-from-cart/<int:product_id>', methods=['POST'])
def remove_from_cart(product_id):
    if 'id_user' not in session or session.get('role') != 'pembeli':
        flash("Anda harus login sebagai pembeli.", "error")
        return redirect(url_for('login'))

    if 'cart' in session:
        session['cart'] = [item for item in session['cart'] if item['product_id'] != product_id]
        session.modified = True
        flash("Produk berhasil dihapus dari keranjang.", "success")
    return redirect(url_for('cart'))

@app.route('/checkout')
def checkout():
    if 'id_user' not in session or session.get('role') != 'pembeli':
        flash("Anda harus login sebagai pembeli untuk melanjutkan checkout.", "error")
        return redirect(url_for('login'))

    cart_items = session.get('cart', [])
    if not cart_items:
        flash("Keranjang Anda kosong. Silakan tambahkan produk terlebih dahulu.", "info")
        return redirect(url_for('home_buyer'))

    total_cart_price = sum(float(item['total_item_price']) for item in cart_items)
    return render_template('checkout.html', cart_items=cart_items, total_cart_price=total_cart_price)

# Anda bisa menambahkan route untuk konfirmasi pembelian di halaman checkout
# Misalnya, setelah pengguna mengklik "Selesaikan Pembelian" di halaman checkout
@app.route('/confirm-purchase', methods=['POST'])
def confirm_purchase():
    if 'id_user' not in session or session.get('role') != 'pembeli':
        flash("Anda harus login sebagai pembeli untuk menyelesaikan pembelian.", "error")
        return redirect(url_for('login'))

    cart_items = session.get('cart', [])
    if not cart_items:
        flash("Keranjang Anda kosong.", "info")
        return redirect(url_for('home_buyer'))

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    try:
        for item in cart_items:
            product_id = item['product_id']
            quantity = item['quantity']

            # Ambil detail produk (dengan kunci FOR UPDATE)
            cursor.execute("SELECT * FROM products WHERE id = %s FOR UPDATE", (product_id,))
            product = cursor.fetchone()

            if not product:
                flash(f"Produk '{item['name']}' tidak ditemukan. Pembelian dibatalkan.", "error")
                mysql.connection.rollback()
                return redirect(url_for('cart'))

            if product['stock'] < quantity:
                flash(f"Stok {product['name']} tidak cukup untuk kuantitas {quantity}. Tersedia: {product['stock']}. Pembelian dibatalkan.", "error")
                mysql.connection.rollback()
                return redirect(url_for('cart'))

            seller_id = product.get('id_user')
            product_price = product['price']
            total_item_price = product_price * quantity
            buyer_id = session['id_user']

            # Masukkan ke tabel transaksi
            cursor.execute("""
                INSERT INTO transaksi (id_user, id_produk, id_penjual, jumlah, price_at_purchase, total_harga, status)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (buyer_id, product_id, seller_id, quantity, product_price, total_item_price, 'completed'))

            # Update stok produk
            new_stock = product['stock'] - quantity
            cursor.execute("UPDATE products SET stock = %s WHERE id = %s", (new_stock, product_id))

        mysql.connection.commit()
        session.pop('cart', None) # Kosongkan keranjang setelah pembelian berhasil
        flash("Pembelian Anda berhasil diproses! Cek riwayat transaksi.", "success")
        return redirect(url_for('riwayat'))

    except MySQLdb.Error as e:
        mysql.connection.rollback()
        flash(f"Terjadi kesalahan saat memproses pembelian: {e}", "error")
        print(f"Database error in confirm_purchase: {e}")
        return redirect(url_for('cart'))
    finally:
        cursor.close()

if __name__ == '__main__':
    app.run(debug=True)