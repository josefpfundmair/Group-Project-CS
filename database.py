import sqlite3
import hashlib
import re
import os
from datetime import date

# ---------------------------------------
# PERSISTENT DATABASE PATH FOR STREAMLIT
# ---------------------------------------

DB_DIR = ".streamlit"
DB_PATH = os.path.join(DB_DIR, "gym_app.db")

# Ensure folder exists
os.makedirs(DB_DIR, exist_ok=True)

def get_db():
    """Open a connection to the persistent SQLite DB."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = 1")
    return conn


# ---------------------------------------
# CREATE TABLES
# ---------------------------------------

def create_tables():
    conn = get_db()
    cur = conn.cursor()

    # ----------------------
    # Users
    # ----------------------
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    """)

    # ----------------------
    # Profiles
    # ----------------------
    cur.execute("""
        CREATE TABLE IF NOT EXISTS profiles (
            user_id INTEGER UNIQUE,
            age INTEGER,
            weight REAL,
            height REAL,
            username TEXT,
            allergies TEXT,
            training_type TEXT,
            diet_preferences TEXT,
            gender TEXT,
            goal TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)

    # Add missing columns safely
    for col in ["username", "allergies", "training_type", "diet_preferences", "gender", "goal"]:
        try:
            cur.execute(f"ALTER TABLE profiles ADD COLUMN {col} TEXT")
        except sqlite3.OperationalError:
            pass

    # ----------------------
    # Daily Nutrition Summary
    # ----------------------
    cur.execute("""
        CREATE TABLE IF NOT EXISTS nutrition_daily (
            user_id INTEGER NOT NULL,
            date TEXT NOT NULL,
            total_calories REAL,
            total_protein REAL,
            target_calories REAL,
            target_protein REAL,
            PRIMARY KEY (user_id, date),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
    """)

    # ----------------------
    # Daily Workout Tracking
    # ----------------------
    cur.execute("""
        CREATE TABLE IF NOT EXISTS workout_daily (
            user_id INTEGER NOT NULL,
            date TEXT NOT NULL,
            sessions INTEGER DEFAULT 0,
            total_volume REAL,
            PRIMARY KEY (user_id, date),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
    """)

    # ----------------------
    # Favourite Recipes
    # ----------------------
    cur.execute("""
        CREATE TABLE IF NOT EXISTS favourite_recipes (
            user_id INTEGER,
            recipe_id INTEGER,
            PRIMARY KEY (user_id, recipe_id),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)

    # ----------------------
    # Meal Log — stored daily
    # ----------------------
    cur.execute("""
        CREATE TABLE IF NOT EXISTS meal_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            date TEXT NOT NULL,
            meal_name TEXT,
            recipe_name TEXT,
            calories REAL,
            protein REAL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)

    conn.commit()
    conn.close()


# ---------------------------------------
# AUTH + VALIDATION
# ---------------------------------------

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def validate_password_strength(password: str):
    """Check password rules."""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one digit."
    if not re.search(r"[^A-Za-z0-9]", password):
        return False, "Password must contain at least one special character."
    return True, ""


def is_valid_email(email: str) -> bool:
    return re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email) is not None


# ---------------------------------------
# USER MANAGEMENT
# ---------------------------------------

def register_user(email: str, password: str):
    conn = get_db()
    cur = conn.cursor()

    try:
        cur.execute(
            "INSERT INTO users (email, password_hash) VALUES (?, ?)",
            (email, hash_password(password)),
        )
        user_id = cur.lastrowid

        # Create empty profile
        cur.execute("""
            INSERT INTO profiles (
                user_id, age, weight, height, username,
                allergies, training_type, diet_preferences,
                gender, goal
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (user_id, None, None, None, None, None, None, None, "Male", "Maintain"))

        conn.commit()
        conn.close()
        return True, "Account created.", user_id

    except sqlite3.IntegrityError:
        conn.close()
        return False, "An account with this email already exists.", None


def verify_user(email: str, password: str):
    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT id, password_hash FROM users WHERE email = ?", (email,))
    row = cur.fetchone()
    conn.close()

    if row is None:
        return None

    user_id, stored_hash = row
    return user_id if stored_hash == hash_password(password) else None


def reset_password(email: str, new_password: str):
    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT id FROM users WHERE email = ?", (email,))
    row = cur.fetchone()

    if row is None:
        conn.close()
        return False, "No account found with this email."

    cur.execute(
        "UPDATE users SET password_hash = ? WHERE email = ?",
        (hash_password(new_password), email),
    )

    conn.commit()
    conn.close()
    return True, "Password updated successfully."


# ---------------------------------------
# PROFILE FUNCTIONS
# ---------------------------------------

def get_profile(user_id: int):
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        SELECT age, weight, height,
               username, allergies, training_type, diet_preferences,
               gender, goal
        FROM profiles WHERE user_id = ?
    """, (user_id,))

    row = cur.fetchone()
    conn.close()

    if row:
        return {
            "age": row[0],
            "weight": row[1],
            "height": row[2],
            "username": row[3],
            "allergies": row[4],
            "training_type": row[5],
            "diet_preferences": row[6],
            "gender": row[7] or "Male",
            "goal": row[8] or "Maintain",
        }

    return {
        "age": None,
        "weight": None,
        "height": None,
        "username": None,
        "allergies": None,
        "training_type": None,
        "diet_preferences": None,
        "gender": "Male",
        "goal": "Maintain",
    }


def update_profile(user_id: int, age: int, weight: float, height: float,
                   username: str, allergies: str, training_type: str,
                   diet_preferences: str, gender: str, goal: str):

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        UPDATE profiles
        SET age = ?, weight = ?, height = ?,
            username = ?, allergies = ?,
            training_type = ?, diet_preferences = ?,
            gender = ?, goal = ?
        WHERE user_id = ?
    """, (age, weight, height, username, allergies, training_type,
          diet_preferences, gender, goal, user_id))

    conn.commit()
    conn.close()


def is_profile_complete(profile: dict) -> bool:
    """Check if required fields are filled."""
    if not profile.get("username"):
        return False
    if not profile.get("age") or profile["age"] <= 0:
        return False
    if not profile.get("weight") or profile["weight"] <= 0:
        return False
    if not profile.get("height") or profile["height"] <= 0:
        return False
    if profile.get("training_type") in (None, "", "Not set"):
        return False
    if profile.get("diet_preferences") in (None, "", "Not set"):
        return False
    if profile.get("gender") not in ("Male", "Female"):
        return False
    if profile.get("goal") not in ("Cut", "Maintain", "Bulk"):
        return False

    return True


# ---------------------------------------
# FAVOURITE RECIPES
# ---------------------------------------

def add_favourite_recipe(user_id: int, recipe_id: int):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        INSERT OR IGNORE INTO favourite_recipes (user_id, recipe_id)
        VALUES (?, ?)
    """, (user_id, recipe_id))
    conn.commit()
    conn.close()


def remove_favourite_recipe(user_id: int, recipe_id: int):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        DELETE FROM favourite_recipes
        WHERE user_id = ? AND recipe_id = ?
    """, (user_id, recipe_id))
    conn.commit()
    conn.close()


def get_favourite_recipes(user_id: int):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT recipe_id
        FROM favourite_recipes
        WHERE user_id = ?
    """, (user_id,))
    rows = cur.fetchall()
    conn.close()
    return [r[0] for r in rows]


# ---------------------------------------
# MEAL LOG (DAILY RESET)
# ---------------------------------------

def log_meal(user_id: int, meal_name: str, recipe_name: str, calories: float, protein: float):
    today = date.today().isoformat()

    conn = get_db()
    cur = conn.cursor()

    # Delete older entries for this user
    cur.execute("""
        DELETE FROM meal_log
        WHERE user_id = ? AND date != ?
    """, (user_id, today))

    # Insert today's meal
    cur.execute("""
        INSERT INTO meal_log (user_id, date, meal_name, recipe_name, calories, protein)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (user_id, today, meal_name, recipe_name, calories, protein))

    conn.commit()
    conn.close()


def get_today_meals(user_id: int):
    today = date.today().isoformat()

    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT meal_name, recipe_name, calories, protein
        FROM meal_log
        WHERE user_id = ? AND date = ?
    """, (user_id, today))

    rows = cur.fetchall()
    conn.close()

    return [
        {
            "meal_name": r[0],
            "recipe_name": r[1],
            "calories": r[2],
            "protein": r[3],
        }
        for r in rows
    ]
