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

UPLOAD_FOLDER = "static/uploads"
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
# Flask Login
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
        payload_type = request.form.get("payload_type")   # text, image, 3d, video, file

        if not cover_image or not password:
            flash("Please provide a cover image and a password.", "danger")
            return redirect(request.url)

        try:
            # Save cover image
            filename = secure_filename(cover_image.filename)
            cover_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            cover_image.save(cover_path)

            payload = None

            # ------------------------------------------------------------
            # TEXT PAYLOAD
            # ------------------------------------------------------------
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

            # ------------------------------------------------------------
            # IMAGE PAYLOAD
            # ------------------------------------------------------------
            elif payload_type == "image":
                secret_image = request.files.get("secret_file")
                if not secret_image:
                    flash("Please select an image file.", "danger")
                    return redirect(request.url)

                secret_path = os.path.join(
                    app.config["UPLOAD_FOLDER"],
                    secure_filename(secret_image.filename)
                )
                secret_image.save(secret_path)

                ext = secret_image.filename.rsplit('.', 1)[1].lower()
                secret_blob = open(secret_path, 'rb').read()

                payload = prepare_payload(
                    kind="file",
                    blob=secret_blob,
                    file_ext=ext,
                    password=password
                )

            # ------------------------------------------------------------
            # 3D MODEL PAYLOAD
            # ------------------------------------------------------------
            elif payload_type == "3d":
                secret_3d = request.files.get("secret_file")
                if not secret_3d:
                    flash("Please upload a 3D model file.", "danger")
                    return redirect(request.url)

                secret_path = os.path.join(
                    app.config["UPLOAD_FOLDER"],
                    secure_filename(secret_3d.filename)
                )
                secret_3d.save(secret_path)

                ext = secret_3d.filename.rsplit('.', 1)[1].lower()
                allowed_3d = ["obj", "stl", "fbx", "gltf", "glb", "dae", "3ds"]

                if ext not in allowed_3d:
                    flash("Invalid 3D model format.", "danger")
                    return redirect(request.url)

                blob = open(secret_path, "rb").read()

                payload = prepare_payload(
                    kind="file",
                    blob=blob,
                    file_ext=ext,
                    password=password
                )

            # ------------------------------------------------------------
            # VIDEO PAYLOAD
            # ------------------------------------------------------------
            elif payload_type == "video":
                secret_video = request.files.get("secret_file")
                if not secret_video:
                    flash("Please upload a video file.", "danger")
                    return redirect(request.url)

                secret_path = os.path.join(
                    app.config["UPLOAD_FOLDER"],
                    secure_filename(secret_video.filename)
                )
                secret_video.save(secret_path)

                ext = secret_video.filename.rsplit('.', 1)[1].lower()
                allowed_video = ["mp4", "avi", "mkv", "mov", "webm"]

                if ext not in allowed_video:
                    flash("Invalid video format.", "danger")
                    return redirect(request.url)

                blob = open(secret_path, "rb").read()

                payload = prepare_payload(
                    kind="file",
                    blob=blob,
                    file_ext=ext,
                    password=password
                )

            else:
                flash("Invalid payload type selected.", "danger")
                return redirect(request.url)

            # ------------------------------------------------------------
            # ENCODE USING LSB
            # ------------------------------------------------------------
            stego_filename = "stego_" + filename
            stego_path = os.path.join(app.config["UPLOAD_FOLDER"], stego_filename)

            encode_lsb(cover_path, payload, stego_path)

            # Save history log
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
            flash(f"An error occurred: {str(e)}", "danger")
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

            # decode payload bytes
            payload = decode_lsb(stego_path)
            decoded = parse_payload(payload, password)

            # Save log
            new_log = History(
                user_id=current_user.id,
                action="decode",
                file_name=filename
            )
            db.session.add(new_log)
            db.session.commit()

            # ------------------------------------------------------------
            # TEXT
            # ------------------------------------------------------------
            if decoded["kind"] == "text":
                return render_template("extract.html", extracted_text=decoded["text"])

            # ------------------------------------------------------------
            # GENERIC FILE
            # (image / 3d model / video / anything)
            # ------------------------------------------------------------
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
# AUTH ROUTES
# ==========================================================

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash("Email already registered. Please login.", "warning")
            return redirect(url_for("login"))

        hashed_pw = bcrypt.generate_password_hash(password).decode("utf-8")
        new_user = User(username=username, email=email, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()

        flash("Account created! Please login.", "success")
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
            flash(f"Welcome, {user.username}!", "success")
            return redirect(url_for("home"))

        flash("Invalid email or password.", "danger")

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out.", "info")
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
# RUN APP
# ==========================================================
with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run()
