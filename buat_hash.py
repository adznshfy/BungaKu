# buat_hash.py
import bcrypt

# Password untuk pemimpin
password_polos = b'pemimpin123' 
# (sisa kode sama)

# Membuat hash yang valid
hash_valid = bcrypt.hashpw(password_polos, bcrypt.gensalt())

print("--- HASH BARU UNTUK PENGELOLA ---")
print(hash_valid.decode('utf-8'))
print("---------------------------------")