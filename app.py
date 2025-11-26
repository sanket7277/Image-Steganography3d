from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime
from werkzeug.utils import secure_filename
import os

from steganography import (
    prepare_payload,
    encode_lsb,
    decode_lsb,
    parse_payload
)
from PIL import Image

# --------------------------
# App Config
# --------------------------
app = Flask(__name__)
app.config['SECRET_KEY'] = "supersecretkey"
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///steganography.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Render safe upload directory
UPLOAD_FOLDER = "/tmp/uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# --------------------------
# Models
# --------------------------
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    history = db.relationship("History", backref="user", lazy=True)


class History(db.Model):
    __tablename__ = "history"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    action = db.Column(db.String(10), nullable=False)
    file_name = db.Column(db.String(200), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


# --------------------------
# Flask Login Loader
# --------------------------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ========================================================================
# ROUTES
# ========================================================================

@app.route("/")
def home():
    if not current_user.is_authenticated:
        return redirect(url_for("login"))
    return render_template("home.html")


@app.route("/features")
def features():
    return render_template("features.html")


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


# ==========================================================
# ENCODE
# ==========================================================
@app.route("/encode", methods=["GET", "POST"])
@login_required
def encode():
    if request.method == "POST":
        cover_image = request.files.get("cover_image")
        password = request.form.get("password")
        payload_type = request.form.get("payload_type")

        if not cover_image or not password:
            flash("Please provide a cover image and a password.", "danger")
            return redirect(request.url)

        try:
            filename = secure_filename(cover_image.filename)
            cover_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            cover_image.save(cover_path)

            payload = None

            if payload_type == "text":
                secret_text = request.form.get("secret_text")
                if not secret_text:
                    flash("Please enter a secret message.", "danger")
                    return redirect(request.url)

                payload = prepare_payload(
                    kind="text",
                    text=secret_text,
                    password=password
                )

            elif payload_type in ["image", "3d", "video"]:
                secret_file = request.files.get("secret_file")
                if not secret_file:
                    flash("Please upload a file.", "danger")
                    return redirect(request.url)

                secret_path = os.path.join(
                    app.config["UPLOAD_FOLDER"],
                    secure_filename(secret_file.filename)
                )
                secret_file.save(secret_path)

                ext = secret_file.filename.rsplit('.', 1)[1].lower()
                blob = open(secret_path, "rb").read()

                payload = prepare_payload(
                    kind="file",
                    blob=blob,
                    file_ext=ext,
                    password=password
                )

            else:
                flash("Invalid payload type.", "danger")
                return redirect(request.url)

            stego_filename = "stego_" + filename
            stego_path = os.path.join(app.config["UPLOAD_FOLDER"], stego_filename)

            encode_lsb(cover_path, payload, stego_path)

            new_log = History(
                user_id=current_user.id,
                action="encode",
                file_name=stego_filename
            )
            db.session.add(new_log)
            db.session.commit()

            flash("Data hidden successfully!", "success")
            return render_template("index.html", stego_image=stego_filename)

        except Exception as e:
            flash(f"Error: {str(e)}", "danger")
            return redirect(request.url)

    return render_template("index.html")


# ==========================================================
# DECODE
# ==========================================================
@app.route("/decode", methods=["POST", "GET"])
@login_required
def decode():
    if request.method == "POST":
        stego_image = request.files.get("stego_image")
        password = request.form.get("password")

        if not stego_image or not password:
            flash("Please provide a stego image and password.", "danger")
            return redirect(request.url)

        try:
            filename = secure_filename(stego_image.filename)
            stego_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            stego_image.save(stego_path)

            payload = decode_lsb(stego_path)
            decoded = parse_payload(payload, password)

            new_log = History(
                user_id=current_user.id,
                action="decode",
                file_name=filename
            )
            db.session.add(new_log)
            db.session.commit()

            if decoded["kind"] == "text":
                return render_template("extract.html", extracted_text=decoded["text"])

            elif decoded["kind"] == "file":
                ext = decoded["file_ext"]
                blob = decoded["blob"]

                output_filename = f"decoded_file.{ext}"
                output_path = os.path.join(app.config["UPLOAD_FOLDER"], output_filename)

                with open(output_path, "wb") as f:
                    f.write(blob)

                return render_template("extract.html", extracted_file=output_filename)

        except Exception as e:
            flash(f"Error: {str(e)}", "danger")
            return redirect(request.url)

    return render_template("extract.html")


# ==========================================================
# AUTH
# ==========================================================
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]

        if User.query.filter_by(email=email).first():
            flash("Email already registered. Please login.", "warning")
            return redirect(url_for("login"))

        hashed_pw = bcrypt.generate_password_hash(password).decode("utf-8")
        new_user = User(username=username, email=email, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()

        flash("Account created! Login now.", "success")
        return redirect(url_for("login"))

    return render_template("signup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        user = User.query.filter_by(email=email).first()

        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for("home"))

        flash("Invalid credentials.", "danger")

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out!", "info")
    return redirect(url_for("login"))


# ==========================================================
# HISTORY
# ==========================================================
@app.route("/history")
@login_required
def history():
    logs = History.query.filter_by(user_id=current_user.id).order_by(
        History.timestamp.desc()
    ).all()
    return render_template("history.html", logs=logs)


# ==========================================================
# Serve uploaded files
# ==========================================================
@app.route("/uploads/<filename>")
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


# ==========================================================
# DB Init + Run
# ==========================================================
with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run()
