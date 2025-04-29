import smtplib

try:
    server = smtplib.SMTP("smtp.gmail.com", 587)
    server.starttls()
    server.login("naswajihaan@gmail.com", "app_password_di_sini")
    print("Koneksi ke SMTP Gmail berhasil!")
except Exception as e:
    print("Gagal konek SMTP:", e)
