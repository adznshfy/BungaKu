from flask import Flask, render_template, redirect, request, url_for, session
from flask_mysqldb import MySQL, MySQLdb
import bcrypt

app = Flask(__name__)
app.config['MYSQL_HOST'] = 'localhost'
app.config['MUSQL_USER'] = 'jihaa'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'flaskdb'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
mysql = MySQL(app)

@app.route('/')
def home():
        return render_template("home.html")

@app.route('/register', methods=["GET","POST"])
def register():
    if request.method == 'GET':
        return render_template("register.html")
    else:
        nim = request.form['nim']
        nama = request.form['nama']
        email = request.form['email']
        programstudi = request.form['programstudi']
        password = request.form['password'].encode('utf-8')
        hash_password = bcrypt.hashpw(password, bcrypt.gensalt())
        
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO users (nim,nama,email,programstudi,password) VALUES (%s,%s,%s,%s,%s)",(nim,nama,email,programstudi,hash_password,))
        mysql.connection.commit()
        session['nama'] = nama
        session['email'] = email
        return redirect(url_for("home"))
    
@app.route('/login',methods=["GET","POST"])
def login():
    if request.method == "POST":
        nim = request.form['nim']
        email = request.form['email']
        password = request.form['password'].encode('utf-8')
        
        cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cur.execute("SELECT * FROM users WHERE email=%s",(email,))
        user = cur.fetchone()
        cur.close()
        
        if len(user) > 0:
            if bcrypt.hashpw(password, user['password'].encode('utf-8')) == user['password'].encode('utf-8'):
               session[email] = user['email']
               return render_template("home.html")
        else:
            return "Error password or user not found"
    else:
        return render_template("login.html")
    

@app.route('/logout')
def logout():
    session.clear()
    return render_template("home.html")

@app.route('/member')
def member():
    cur = mysql.connection.cursor()
    cur.execute("SELECT nim, nama, email, programstudi FROM users")
    member = cur.fetchall()
    cur.close()
    
    return render_template('member.html', member=member)

    
@app.route('/profile', methods=["GET", "POST"])
def profile():
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("SELECT id_divisi, nama_divisi FROM divisi")
    divisi = cur.fetchall()

    if request.method == 'POST':
        nama = request.form['nama']
        nama_lengkap = request.form['nama_lengkap']
        nim = request.form['nim']
        alamat = request.form['alamat']
        no_telp = request.form['no_telp']
        id_divisi = request.form['id_divisi']
        email = request.form['email']
        payment = request.form['payment']

        cur.execute("""INSERT INTO profile 
            (nama, nama_lengkap, nim, alamat, no_telp, id_divisi, email, payment)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
            (nama, nama_lengkap, nim, alamat, no_telp, id_divisi, email, payment)
        )
        mysql.connection.commit()
        return redirect(url_for("edit_success"))

    return render_template("profile.html", divisi=divisi)

@app.route("/edit_profile", methods=["GET", "POST"])
def edit_profile():
    if 'id_user' not in session:
        return redirect(url_for("login"))

    id_user = session['id_user']
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    cur.execute("SELECT id_profile FROM users WHERE id_user = %s", (id_user,))
    user_data = cur.fetchone()

    if not user_data or not user_data['id_profile']:
        return redirect(url_for("profile"))

    id_profile = user_data['id_profile']

    if request.method == "POST":

        cur.execute("""
            UPDATE profile SET ...
            WHERE id_profile = %s
        """, (..., id_profile))
        mysql.connection.commit()

        return redirect(url_for("edit_success"))

    cur.execute("SELECT * FROM profile WHERE id_profile = %s", (id_profile,))
    profile = cur.fetchone()

    return render_template("edit_profile.html", profile=profile, divisi=divisi) # type: ignore


@app.route("/edit_success")
def edit_success():
    return render_template("edit_success.html")

                           
if __name__ == '__main__':
    app.secret_key = "017#!NaswaJia)!!"
    app.run(debug=True)