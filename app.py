from flask import Flask, render_template, request, redirect, url_for, session, flash
from cryptography.fernet import Fernet
import hashlib
import time

app = Flask(__name__)

# Secret key for sessions (for demo purpose, this is hard-coded)
app.secret_key = "super_secret_key_for_sessions_change_me"


# ------------- Security Helpers -------------

def hash_password(password: str) -> str:
    """Return SHA-256 hash of the given password."""
    return hashlib.sha256(password.encode()).hexdigest()


# Generate a symmetric encryption key for Fernet
ENCRYPTION_KEY = Fernet.generate_key()
cipher = Fernet(ENCRYPTION_KEY)


# ------------- In-memory 'Database' -------------

# Pre-registered voters with hashed passwords
voters = {
    "voter1": {"password_hash": hash_password("pass1"), "has_voted": False},
    "voter2": {"password_hash": hash_password("pass2"), "has_voted": False},
    "voter3": {"password_hash": hash_password("pass3"), "has_voted": False},
}

# Candidates list
candidates = ["Alice", "Bob", "Charlie"]

# Encrypted ballots list (each entry is ciphertext bytes)
encrypted_ballots = []

# Admin password hash
ADMIN_PASSWORD_HASH = hash_password("admin123")


# ------------- Routes -------------

@app.route("/")
def index():
    """Home redirects to login or voting page depending on session."""
    if "user" in session and session.get("role") == "voter":
        return redirect(url_for("vote"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    """Voter login."""
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"].strip()

        if username in voters and hash_password(password) == voters[username]["password_hash"]:
            session["user"] = username
            session["role"] = "voter"
            flash("Login successful!", "success")
            return redirect(url_for("vote"))
        else:
            flash("Invalid voter username or password.", "error")

    return render_template("login.html")


@app.route("/logout")
def logout():
    """Logout current user (voter or admin)."""
    session.clear()
    flash("Logged out successfully.", "success")
    return redirect(url_for("login"))


@app.route("/vote", methods=["GET", "POST"])
def vote():
    """Voting page for logged-in voters."""
    if "user" not in session or session.get("role") != "voter":
        return redirect(url_for("login"))

    username = session["user"]

    # Check if this voter already voted
    already_voted = voters[username]["has_voted"]

    if request.method == "POST" and not already_voted:
        selected_candidate = request.form.get("candidate")

        if selected_candidate not in candidates:
            flash("Please select a valid candidate.", "error")
        else:
            timestamp = int(time.time())
            # Create a ballot string
            ballot = f"user={username}|candidate={selected_candidate}|time={timestamp}"
            # Encrypt the ballot
            encrypted = cipher.encrypt(ballot.encode())
            encrypted_ballots.append(encrypted)

            # Mark voter as voted
            voters[username]["has_voted"] = True

            flash("Your vote has been securely encrypted and stored.", "success")
            return redirect(url_for("vote"))

    return render_template("vote.html", candidates=candidates, voted=voters[username]["has_voted"])


@app.route("/admin", methods=["GET", "POST"])
def admin_login():
    """Admin login for accessing results."""
    if request.method == "POST":
        password = request.form["password"].strip()

        if hash_password(password) == ADMIN_PASSWORD_HASH:
            session["admin"] = True
            flash("Admin login successful.", "success")
            return redirect(url_for("results"))
        else:
            flash("Invalid admin password.", "error")

    return render_template("admin_login.html")


@app.route("/results")
def results():
    """Decrypt ballots and show final result (admin only)."""
    if not session.get("admin"):
        return redirect(url_for("admin_login"))

    # Count votes
    counts = {c: 0 for c in candidates}

    for ct in encrypted_ballots:
        try:
            ballot_plain = cipher.decrypt(ct).decode()
        except Exception:
            # Tampered or invalid ballot skipped
            continue

        # ballot format: user=...|candidate=...|time=...
        parts = ballot_plain.split("|")
        candidate_part = [p for p in parts if p.startswith("candidate=")][0]
        candidate_name = candidate_part.split("=", 1)[1]

        if candidate_name in counts:
            counts[candidate_name] += 1

    max_votes = max(counts.values()) if counts else 0
    winners = [c for c, v in counts.items() if v == max_votes and max_votes > 0]

    return render_template("results.html", counts=counts, winners=winners, max_votes=max_votes)


if __name__ == "__main__":
    # Debug=True is only for development/demo
    app.run(debug=True)
