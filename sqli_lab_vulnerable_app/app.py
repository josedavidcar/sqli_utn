from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import os
from pathlib import Path
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "db" / "lab.db"

app = Flask(__name__)

# V-04 corregida: SECRET_KEY desde variable de entorno
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-key-temporal-segura")

# V-08 corregida: protección CSRF
csrf = CSRFProtect(app)


# ---------------------------------------------------------------
# Conexión a la base de datos
# ---------------------------------------------------------------
def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# ---------------------------------------------------------------
# Inicialización de la base de datos con datos de prueba
# ---------------------------------------------------------------
def init_db():
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id       INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT    NOT NULL UNIQUE,
        password TEXT    NOT NULL,
        role     TEXT    NOT NULL
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS books (
        id       INTEGER PRIMARY KEY AUTOINCREMENT,
        title    TEXT NOT NULL,
        author   TEXT NOT NULL,
        category TEXT NOT NULL
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS audit_log (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        event      TEXT NOT NULL,
        username   TEXT,
        detail     TEXT,
        timestamp  DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # V-03 corregida: contraseñas con hash
    cur.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] == 0:
        users = [
            ("admin", generate_password_hash("Admin123"), "admin"),
            ("analyst", generate_password_hash("Analyst123"), "user"),
            ("student", generate_password_hash("Student123"), "user"),
        ]
        cur.executemany(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            users
        )

    cur.execute("SELECT COUNT(*) FROM books")
    if cur.fetchone()[0] == 0:
        books = [
            ("Secure Coding Fundamentals", "J. Howard", "security"),
            ("Flask Web Patterns", "A. Miller", "development"),
            ("Practical SQL", "A. DeBarros", "database"),
            ("Threat Modeling Essentials", "M. Silva", "security"),
            ("Performance Testing Handbook", "R. Jones", "qa"),
            ("OWASP Testing Guide", "OWASP Team", "security"),
            ("Clean Code", "R. Martin", "development"),
            ("The Web Application Hacker", "Stuttard", "security"),
        ]
        cur.executemany(
            "INSERT INTO books (title, author, category) VALUES (?, ?, ?)",
            books
        )

    conn.commit()
    conn.close()


def log_event(event, username=None, detail=None):
    conn = get_connection()
    conn.execute(
        "INSERT INTO audit_log (event, username, detail) VALUES (?, ?, ?)",
        (event, username, detail)
    )
    conn.commit()
    conn.close()


# ---------------------------------------------------------------
# Rutas
# ---------------------------------------------------------------

@app.route("/")
def index():
    if session.get("username"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = get_connection()
        try:
            # V-01 corregida: consulta parametrizada
            user = conn.execute(
                "SELECT id, username, password, role FROM users WHERE username = ?",
                (username,)
            ).fetchone()
        except Exception:
            flash("Error interno en la base de datos.", "error")
            conn.close()
            return render_template("login.html")

        conn.close()

        # V-03 corregida: validar con hash
        if user and check_password_hash(user["password"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            log_event("LOGIN_OK", user["username"])
            flash("Inicio de sesión exitoso.", "success")
            return redirect(url_for("dashboard"))

        log_event("LOGIN_FAIL", username, "Credenciales inválidas")
        flash("Credenciales incorrectas.", "error")

    return render_template("login.html")


@app.route("/dashboard")
def dashboard():
    if not session.get("username"):
        flash("Debe iniciar sesión primero.", "error")
        return redirect(url_for("login"))

    return render_template(
        "dashboard.html",
        username=session.get("username"),
        role=session.get("role")
    )


@app.route("/search", methods=["GET", "POST"])
def search():
    if not session.get("username"):
        flash("Debe iniciar sesión primero.", "error")
        return redirect(url_for("login"))

    books = []

    if request.method == "POST":
        term = request.form.get("term", "").strip()
        like_term = f"%{term}%"

        conn = get_connection()
        try:
            # V-02 corregida: consulta parametrizada
            books = conn.execute("""
                SELECT id, title, author, category
                FROM books
                WHERE title LIKE ?
                   OR author LIKE ?
                   OR category LIKE ?
            """, (like_term, like_term, like_term)).fetchall()
        except Exception:
            flash("Error interno en la base de datos.", "error")
        conn.close()

    # V-06 corregida: ya no se envía raw_query al template
    return render_template("search.html", books=books)


@app.route("/admin")
def admin():
    if not session.get("username"):
        flash("Debe iniciar sesión primero.", "error")
        return redirect(url_for("login"))

    if session.get("role") != "admin":
        flash("No tiene permisos para acceder al panel de administración.", "error")
        log_event("ACCESS_DENIED", session.get("username"), "Intento de acceso a /admin")
        return redirect(url_for("dashboard"))

    conn = get_connection()

    # V-03 reforzada: no mostrar contraseñas en panel admin
    users = conn.execute(
        "SELECT id, username, role FROM users ORDER BY id"
    ).fetchall()

    logs = conn.execute(
        "SELECT * FROM audit_log ORDER BY id DESC LIMIT 20"
    ).fetchall()

    conn.close()

    return render_template("admin.html", users=users, logs=logs)


@app.route("/logout")
def logout():
    if session.get("username"):
        log_event("LOGOUT", session.get("username"))
    session.clear()
    flash("Sesión cerrada.", "success")
    return redirect(url_for("login"))


# ---------------------------------------------------------------
# Ejecución
# ---------------------------------------------------------------
if __name__ == "__main__":
    init_db()

    # V-05 corregida: debug desactivado o controlado por variable
    debug_mode = os.environ.get("FLASK_DEBUG", "False").lower() == "true"

    app.run(host="0.0.0.0", port=5000, debug=debug_mode)