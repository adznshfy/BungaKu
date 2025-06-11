from flask import Blueprint, render_template, session, redirect, url_for, request, flash

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")

# Route: Dashboard
@admin_bp.route("/dashboard")
def admin_dashboard():
    if "user_id" not in session or session.get("role") != "admin":
        return redirect(url_for("login"))
    return render_template("admin_dashboard.html")

# Route: Kelola Pengguna
@admin_bp.route("/users")
def admin_users():
    if "user_id" not in session or session.get("role") != "admin":
        return redirect(url_for("login"))
    return render_template("admin_users.html", users=dummy_users, profile={})

# Route: Edit Pengguna
@admin_bp.route("/users/edit/<int:id>", methods=["GET", "POST"])
def admin_edit_user(id):
    if "user_id" not in session or session.get("role") != "admin":
        return redirect(url_for("login"))
    
    user = next((u for u in dummy_users if u["id"] == id), None)
    if not user:
        flash("Pengguna tidak ditemukan.")
        return redirect(url_for("admin.admin_users"))

    if request.method == "POST":
        user["name"] = request.form["name"]
        user["username"] = request.form["username"]
        user["email"] = request.form["email"]
        user["phone_number"] = request.form["phone_number"]
        user["role"] = request.form["role"]
        flash("Data pengguna berhasil diupdate.")
        return redirect(url_for("admin.admin_users"))
    
    return render_template("admin_users.html", users=dummy_users, user=user, profile={})

# Route: Hapus Pengguna
@admin_bp.route("/users/delete/<int:id>")
def admin_delete_user(id):
    global dummy_users
    dummy_users = [u for u in dummy_users if u["id"] != id]
    flash("Pengguna berhasil dihapus.")
    return redirect(url_for("admin.admin_users"))

# Route: Kelola Produk
@admin_bp.route("/products")
def admin_products():
    if "user_id" not in session or session.get("role") != "admin":
        return redirect(url_for("login"))
    return render_template("admin_products.html", products=dummy_products, profile={})

# Route: Edit Produk
@admin_bp.route("/products/edit/<int:id>", methods=["GET", "POST"])
def admin_edit_product(id):
    if "user_id" not in session or session.get("role") != "admin":
        return redirect(url_for("login"))

    product = next((p for p in dummy_products if p["id"] == id), None)
    if not product:
        flash("Produk tidak ditemukan.")
        return redirect(url_for("admin.admin_products"))

    if request.method == "POST":
        product["name"] = request.form["name"]
        product["price"] = float(request.form["price"])
        product["stock"] = int(request.form["stock"])
        product["category"] = request.form["category"]
        flash("Produk berhasil diupdate.")
        return redirect(url_for("admin.admin_products"))

    return render_template("admin_products.html", products=dummy_products, product=product, profile={})

# Route: Hapus Produk
@admin_bp.route("/products/delete/<int:id>")
def admin_delete_product(id):
    global dummy_products
    dummy_products = [p for p in dummy_products if p["id"] != id]
    flash("Produk berhasil dihapus.")
    return redirect(url_for("admin.admin_products"))

# Route: Kelola Pesanan
@admin_bp.route("/orders")
def admin_orders():
    if "user_id" not in session or session.get("role") != "admin":
        return redirect(url_for("login"))
    return render_template("admin_orders.html")

# Route: Update Status Pesanan
@admin_bp.route("/orders/update/<int:id>", methods=["POST"])
def admin_update_order(id):
    status = request.form["status"]
    return redirect(url_for("admin.admin_orders"))
