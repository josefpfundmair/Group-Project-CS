import streamlit as st

# =========================================================
# BASIC PAGE SETUP  (MUST BE FIRST STREAMLIT COMMAND)
# =========================================================

# Configure the overall Streamlit page: title, layout, and sidebar behavior.
# This must be called before any other Streamlit commands.
st.set_page_config(
    page_title="UniFit Coach",
    layout="wide",
    initial_sidebar_state="expanded",
)

# =========================================================
# IMPORTS
# =========================================================

import sqlite3   # Lightweight embedded database used to persist users and profiles.
import hashlib   # Used for hashing passwords (security).
import re        # Regular expressions for validating email and password strength.
import pandas as pd  # Data handling and simple charting in the Progress page.
import base64    # Used for encoding images as base64 for embedding in HTML.

from openai import OpenAI  # OpenAI client for the Pumpfessor Joe chatbot.

# Local modules that implement individual app features / pages.
import workout_planner
import workout_calendar
import calorie_tracker
import nutrition_advisory
import calories_nutrition
from nutrition_advisory import load_and_prepare_data, DATA_URL


# Primary green used to match the university branding.
PRIMARY_GREEN = "#007A3D"  # HSG-like green

# Initialize OpenAI client (expects OPENAI_API_KEY in environment variables).
client = OpenAI()


# =========================================================
# IMAGE HELPERS
# =========================================================

def get_base64_of_image(path: str) -> str:
    """
    Read a local image file and return it as a base64-encoded string.
    This is used to embed images (e.g. background) directly into HTML/CSS.
    """
    with open(path, "rb") as f:
        return base64.b64encode(f.read()).decode()


def load_logo(path: str) -> str:
    """
    Try to load a logo image and return it as base64-encoded string.
    If the file does not exist, return an empty string.
    This allows the app to fail gracefully if the asset is missing.
    """
    try:
        with open(path, "rb") as img:
            return base64.b64encode(img.read()).decode()
    except FileNotFoundError:
        return ""


# Pre-load images and encode them as base64 for inline use in CSS/HTML.
# These files are expected to be located in the same directory as app.py.
BACKGROUND_IMAGE = get_base64_of_image("background_pitch.jpg")
LOGO_IMAGE = load_logo("unifit_logo.png")
PUMPFESSOR_IMAGE = load_logo("pumpfessorjoe.png")  # Pumpfessor Joe avatar


# =========================================================
# GLOBAL CSS (APP THEME)
# =========================================================
# This global CSS block:
# - Defines the main layout spacing and container width
# - Styles buttons, sidebar, headers, inputs, and code blocks
# - Enforces a consistent visual design based on PRIMARY_GREEN
# The styles are injected using st.markdown with unsafe_allow_html=True.

st.markdown(
    f"""
    <style>
    /* main app container: full-width layout (overridden on login page) */
    .block-container {{
        padding-top: 2rem;
        padding-bottom: 2rem;
        max-width: 100% !important;
        margin: 0 auto !important;
        padding-left: 2rem;
        padding-right: 2rem;
    }}

    /* white header bar */
    [data-testid="stHeader"] {{
        background-color: #FFFFFF !important;
        color: {PRIMARY_GREEN};
        box-shadow: none !important;
    }}

    /* generic buttons in main area */
    .stButton > button {{
        border-radius: 999px;
        background-color: {PRIMARY_GREEN};
        color: #ffffff;
        border: 1px solid {PRIMARY_GREEN};
        padding: 0.5rem 1rem;
        font-weight: 600;
    }}
    .stButton > button:hover {{
        background-color: #005c2d;
        border-color: #005c2d;
        color: #ffffff;
    }}

    /* sidebar background */
    [data-testid="stSidebar"] {{
        background: #f5f7f6;
        border-right: 1px solid rgba(0, 0, 0, 0.05);
    }}

    /* default text */
    p, span, label, .stMarkdown, .stText, .stCaption {{
        color: {PRIMARY_GREEN};
    }}

    /* headings */
    h1, h2, h3, h4 {{
        color: {PRIMARY_GREEN};
    }}

    /* rounded cards (containers with border=True) */
    div[data-testid="stVerticalBlock"] > div > div[style*="border-radius: 0.5rem"] {{
        border-radius: 1rem !important;
    }}

    /* number inputs */
    div[data-testid="stNumberInput"] input {{
        background-color: #ffffff !important;
        color: {PRIMARY_GREEN} !important;
        border-radius: 999px !important;
        border: 1px solid {PRIMARY_GREEN} !important;
        padding: 0.25rem 0.75rem !important;
    }}
    div[data-testid="stNumberInput"] input:focus {{
        outline: none !important;
        border: 2px solid {PRIMARY_GREEN} !important;
        box-shadow: 0 0 0 1px rgba(0, 122, 61, 0.25);
        background-color: #ffffff !important;
        color: {PRIMARY_GREEN} !important;
    }}
    div[data-testid="stNumberInput"] button {{
        background-color: #ffffff !important;
        color: {PRIMARY_GREEN} !important;
        border-radius: 999px !important;
        border: 1px solid {PRIMARY_GREEN} !important;
    }}
    div[data-testid="stNumberInput"] button:hover {{
        background-color: {PRIMARY_GREEN} !important;
        color: #ffffff !important;
        border-color: {PRIMARY_GREEN} !important;
    }}

    /* text & password inputs */
    div[data-testid="stTextInput"] input,
    div[data-testid="stPasswordInput"] input {{
        background-color: #ffffff !important;
        color: {PRIMARY_GREEN} !important;
        border-radius: 999px !important;
        border: 1px solid {PRIMARY_GREEN} !important;
        padding: 0.4rem 0.75rem !important;
    }}
    div[data-testid="stTextInput"] input::placeholder,
    div[data-testid="stPasswordInput"] input::placeholder {{
        color: rgba(0, 122, 61, 0.6) !important;
    }}
    div[data-testid="stTextInput"] input:focus,
    div[data-testid="stPasswordInput"] input:focus {{
        outline: none !important;
        border: 2px solid {PRIMARY_GREEN} !important;
        box-shadow: 0 0 0 1px rgba(0, 122, 61, 0.25);
        background-color: #ffffff !important;
        color: {PRIMARY_GREEN} !important;
    }}

    /* code blocks – white background instead of black */
    div[data-testid="stCodeBlock"] pre,
    div[data-testid="stCodeBlock"] {{
        background-color: #FFFFFF !important;
        color: {PRIMARY_GREEN} !important;
        border-radius: 0.75rem !important;
    }}
    </style>
    """,
    unsafe_allow_html=True,
)


# =========================================================
# DATABASE + SECURITY
# =========================================================

def get_db():
    """
    Open a connection to the SQLite database file (gym_app.db).
    Enables foreign key constraints to maintain referential integrity.
    """
    conn = sqlite3.connect("gym_app.db")
    conn.execute("PRAGMA foreign_keys = 1")
    return conn


def create_tables():
    """
    Create (if not existing) the 'users' and 'profiles' tables and ensure
    that newly added columns ('gender', 'goal') exist.
    This function is idempotent and can be called on each app start.
    """
    conn = get_db()
    cur = conn.cursor()

    # Create users table: stores login credentials.
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
        """
    )

    # Create profiles table: stores all user-related fitness and nutrition data.
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS profiles (
            user_id INTEGER UNIQUE,
            age INTEGER,
            weight REAL,
            height REAL,
            username TEXT,
            allergies TEXT,
            training_type TEXT,
            diet_preferences TEXT,
            gender TEXT DEFAULT 'Male',
            goal TEXT DEFAULT 'Maintain',
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        """
    )

    # Backward-compatibility: ensure that newer columns exist for old DBs.
    # Each ALTER TABLE is wrapped in a try/except because SQLite raises an
    # OperationalError if the column already exists.
    additional_cols = [
        "gender TEXT DEFAULT 'Male'",
        "goal TEXT DEFAULT 'Maintain'",
    ]
    for col_def in additional_cols:
        try:
            cur.execute(f"ALTER TABLE profiles ADD COLUMN {col_def}")
        except sqlite3.OperationalError:
            # column already exists, ignore
            pass

    conn.commit()
    conn.close()


def hash_password(password: str) -> str:
    """
    Hash a password using SHA256.
    Note: For a production system, use a salted password hashing library (e.g. bcrypt).
    """
    return hashlib.sha256(password.encode()).hexdigest()


def validate_password_strength(password: str):
    """
    Validate password against a simple strength policy using regex:
    - minimum length
    - at least one lowercase, uppercase, digit, and special character.
    Returns (bool, message) where bool indicates validity and message explains the issue.
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one digit."
    if not re.search(r"[^A-Za-z0-9]", password):
        return False, "Password must contain at least one special character (e.g. !, ?, #, @)."
    return True, ""


def is_valid_email(email: str) -> bool:
    """
    Basic email format validation using a regular expression.
    It checks that there is one '@', no spaces, and at least one dot in the domain.
    """
    pattern = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
    return re.match(pattern, email) is not None


# =========================================================
# AUTHENTICATION LOGIC
# =========================================================

def register_user(email: str, password: str):
    """
    Register a new user with the given email and password.
    - Inserts into 'users' with a hashed password.
    - Creates an empty profile entry for that user.
    Returns (ok, msg, user_id) where:
      ok: bool, msg: human-readable message, user_id: new user's ID or None.
    """
    conn = get_db()
    cur = conn.cursor()

    try:
        cur.execute(
            "INSERT INTO users (email, password_hash) VALUES (?, ?)",
            (email, hash_password(password)),
        )
        user_id = cur.lastrowid

        # Initialize an empty profile row for the new user using defaults.
        cur.execute(
            """
            INSERT INTO profiles (
                user_id, age, weight, height,
                username, allergies, training_type, diet_preferences,
                gender, goal
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (user_id, None, None, None, None, None, None, None, "Male", "Maintain"),
        )

        conn.commit()
        conn.close()
        return True, "Account created.", user_id
    except sqlite3.IntegrityError:
        # Triggered when a user with the same email already exists (UNIQUE constraint).
        conn.close()
        return False, "An account with this email already exists.", None


def verify_user(email: str, password: str):
    """
    Verify a user's login credentials.
    - Fetches the stored password hash and compares it with the hash of the input.
    Returns user_id if the credentials are valid, otherwise None.
    """
    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT id, password_hash FROM users WHERE email = ?", (email,))
    row = cur.fetchone()
    conn.close()

    if row is None:
        return None

    user_id, stored_hash = row
    if stored_hash == hash_password(password):
        return user_id
    return None


def reset_password(email: str, new_password: str):
    """
    Reset a user's password (demo implementation).
    - Directly updates the password hash for the given email if user exists.
    Note: No email verification is implemented (not secure for production).
    Returns (ok, message).
    """
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


# =========================================================
# PROFILE DB ACCESS
# =========================================================

def get_profile(user_id: int):
    """
    Retrieve the profile for the given user_id.
    Returns a dictionary with all profile fields.
    If no profile exists, returns a dictionary with default values.
    """
    conn = get_db()
    cur = conn.cursor()

    cur.execute(
        """
        SELECT age, weight, height,
               username, allergies, training_type, diet_preferences,
               gender, goal
        FROM profiles WHERE user_id = ?
        """,
        (user_id,),
    )
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

    # Fallback if profile row is missing: provide default values.
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


def update_profile(
    user_id: int,
    age: int,
    weight: float,
    height: float,
    username: str,
    allergies: str,
    training_type: str,
    diet_preferences: str,
    gender: str,
    goal: str,
):
    """
    Update the profile record for a given user_id with new values.
    All fields are updated in a single SQL UPDATE statement.
    """
    conn = get_db()
    cur = conn.cursor()

    cur.execute(
        """
        UPDATE profiles
        SET age = ?, weight = ?, height = ?,
            username = ?, allergies = ?,
            training_type = ?, diet_preferences = ?,
            gender = ?, goal = ?
        WHERE user_id = ?
        """,
        (
            age,
            weight,
            height,
            username,
            allergies,
            training_type,
            diet_preferences,
            gender,
            goal,
            user_id,
        ),
    )
    conn.commit()
    conn.close()


def is_profile_complete(profile: dict) -> bool:
    """
    Check whether a profile contains all required fields for enabling the app pages.
    The profile is considered complete if:
    - username, age, weight, height, training_type, diet_preferences are set
    - gender is 'Male' or 'Female'
    - goal is one of 'Cut', 'Maintain', 'Bulk'
    This gate is used to restrict access to Trainer, Nutrition, etc. until the
    user provides sufficient information.
    """
    if not profile.get("username") or profile["username"].strip() == "":
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


# =========================================================
# AUTHENTICATION UI
# =========================================================

def show_login_page():
    """
    Render the login page UI:
    - Centered layout with email and password fields
    - Handles login logic and redirects to profile on success
    - Provides buttons to navigate to registration and password reset modes.
    Uses Streamlit columns and session_state to manage app state.
    """
    col_left, col_center, col_right = st.columns([1, 2, 1])

    with col_center:
        st.title("Login")
        st.caption("Log in to your UniFit Coach dashboard.")

        with st.container(border=True):
            email = st.text_input("Email")
            password = st.text_input("Password", type="password")

            if st.button("Login", use_container_width=True):
                # Basic input validation
                if not email or not password:
                    st.error("Please enter both email and password.")
                else:
                    # Attempt to verify user credentials against the DB
                    user_id = verify_user(email, password)
                    if user_id:
                        # Persist authentication in session_state
                        st.session_state.logged_in = True
                        st.session_state.user_id = user_id
                        st.session_state.user_email = email
                        st.session_state.current_page = "Profile"
                        # Keep page selection in URL query params for deep-linking
                        st.query_params["page"] = "profile"
                        st.rerun()
                    else:
                        st.error("Invalid email or password.")

        st.write("---")
        st.write("Do not have an account yet?")
        if st.button("Create a new account", use_container_width=True):
            # Switch to registration mode
            st.session_state.login_mode = "register"
            st.rerun()

        st.write("")
        if st.button("Forgot password?", use_container_width=True):
            # Switch to reset password mode
            st.session_state.login_mode = "reset"
            st.rerun()


def show_register_page():
    """
    Render the registration page UI:
    - Collects email and password
    - Validates email format and password strength
    - On success, creates a new user and initial profile, logs them in,
      and routes them to the Profile page.
    """
    col_left, col_center, col_right = st.columns([1, 2, 1])

    with col_center:
        st.title("Register")
        st.caption("Create an account for UniFit Coach.")

        with st.container(border=True):
            email = st.text_input("Email")
            password = st.text_input("Password", type="password")

            # Explain password requirements to the user.
            st.markdown(
                """
                **Password must contain:**
                - at least 8 characters  
                - at least one lowercase letter  
                - at least one uppercase letter  
                - at least one digit  
                - at least one special character (e.g. `!`, `?`, `#`, `@`)
                """,
                unsafe_allow_html=False,
            )

            if st.button("Register", use_container_width=True):
                # Validate input presence and format
                if not email or not password:
                    st.error("Please enter both email and password.")
                elif not is_valid_email(email):
                    st.error("Please enter a valid email address.")
                else:
                    # Validate password strength using regex-based checks
                    ok_pw, msg_pw = validate_password_strength(password)
                    if not ok_pw:
                        st.error(msg_pw)
                    else:
                        # Attempt to create new user in DB
                        ok, msg, user_id = register_user(email, password)
                        if ok:
                            # Auto-login and prompt to complete profile
                            st.session_state.logged_in = True
                            st.session_state.user_id = user_id
                            st.session_state.user_email = email
                            st.session_state.current_page = "Profile"
                            st.success("Account created. Please complete your profile to unlock all applications.")
                            st.query_params["page"] = "profile"
                            st.rerun()
                        else:
                            st.error(msg)

        st.write("---")
        if st.button("Back to login", use_container_width=True):
            # Back to login mode
            st.session_state.login_mode = "login"
            st.rerun()


def show_reset_password_page():
    """
    Render the password reset page UI (demo):
    - Allows the user to set a new password directly given an email.
    - Validates email, matches password confirmation, and enforces password policy.
    - Uses the reset_password() helper to update the DB.
    """
    col_left, col_center, col_right = st.columns([1, 2, 1])

    with col_center:
        st.title("Reset password")
        st.caption(
            "For demo purposes, you can reset your password by entering your email and a new password."
        )

        with st.container(border=True):
            email = st.text_input("Email")
            new_pw = st.text_input("New password", type="password")
            confirm_pw = st.text_input("Confirm new password", type="password")

            if st.button("Reset password", use_container_width=True):
                # Validate form fields
                if not email or not new_pw or not confirm_pw:
                    st.error("Please fill out all fields.")
                elif new_pw != confirm_pw:
                    st.error("Passwords do not match.")
                elif not is_valid_email(email):
                    st.error("Please enter a valid email address.")
                else:
                    # Enforce password strength policy
                    ok_pw, msg_pw = validate_password_strength(new_pw)
                    if not ok_pw:
                        st.error(msg_pw)
                    else:
                        ok, msg = reset_password(email, new_pw)
                        if ok:
                            st.success(msg)
                            # Return to login on success
                            st.session_state.login_mode = "login"
                            st.rerun()
                        else:
                            st.error(msg)

        st.write("---")
        if st.button("Back to login", use_container_width=True):
            st.session_state.login_mode = "login"
            st.rerun()


# =========================================================
# APP PAGES
# =========================================================

def show_profile_page():
    """
    Display and edit the user's profile.
    - Presents input fields for age, weight, height, username, gender, goal,
      training style, diet preferences, and allergies.
    - Saves changes back to the database.
    - Shows a read-only summary of current profile data and a profile
      completeness progress bar.
    Uses session_state.user_id to load and save user-specific data.
    """
    user_id = st.session_state.user_id
    profile = get_profile(user_id)

    st.header("Profile")
    st.write("Basic information that can be used by the trainer and nutrition logic later.")
    st.divider()

    with st.container():
        with st.container(border=True):
            st.subheader("Your data")

            # Two-column layout for personal data & preferences.
            c1, c2 = st.columns(2)

            with c1:
                # Age input
                age = st.number_input(
                    "Age (years)",
                    min_value=0,
                    max_value=120,
                    value=profile["age"] if profile["age"] is not None else 0,
                    step=1,
                )

                # Height input
                height = st.number_input(
                    "Height (cm)",
                    min_value=0.0,
                    max_value=300.0,
                    value=profile["height"] if profile["height"] is not None else 0.0,
                    step=0.5,
                )

                # Username input
                username = st.text_input(
                    "Username",
                    value=profile["username"] or "",
                    max_chars=30,
                )

                # Gender selector
                gender = st.selectbox(
                    "Gender",
                    ["Male", "Female"],
                    index=0 if profile["gender"] == "Male" else 1,
                )

            with c2:
                # Weight input
                weight = st.number_input(
                    "Weight (kg)",
                    min_value=0.0,
                    max_value=500.0,
                    value=profile["weight"] if profile["weight"] is not None else 0.0,
                    step=0.5,
                )

                # Training style selector with fallback to "Not set" if unknown.
                training_options = [
                    "Not set",
                    "Strength",
                    "Hypertrophy",
                    "Endurance",
                    "Mixed",
                ]
                current_training = profile["training_type"] or "Not set"
                if current_training not in training_options:
                    current_training = "Not set"
                training_type = st.selectbox(
                    "Preferred training style",
                    training_options,
                    index=training_options.index(current_training),
                )

                # Diet preference selector with similar fallback behavior.
                diet_options = [
                    "Not set",
                    "No preference",
                    "High protein",
                    "Vegetarian",
                    "Vegan",
                    "Low carb",
                    "Mediterranean",
                ]
                current_diet = profile["diet_preferences"] or "Not set"
                if current_diet not in diet_options:
                    current_diet = "Not set"
                diet_preferences = st.selectbox(
                    "Diet preference",
                    diet_options,
                    index=diet_options.index(current_diet),
                )

                # Goal selector
                goal_options = ["Cut", "Maintain", "Bulk"]
                current_goal = profile["goal"] or "Maintain"
                if current_goal not in goal_options:
                    current_goal = "Maintain"
                goal = st.selectbox(
                    "Goal",
                    goal_options,
                    index=goal_options.index(current_goal),
                )

            # Free-text allergies field (optional)
            allergies = st.text_area(
                "Allergies (optional)",
                value=profile["allergies"] or "",
                help="For example: peanuts, lactose, gluten.",
            )

            if st.button("Save profile", use_container_width=True):
                # Persist profile data to DB.
                update_profile(
                    user_id,
                    int(age),
                    float(weight),
                    float(height),
                    username.strip() or None,
                    allergies.strip() or None,
                    training_type,
                    diet_preferences,
                    gender,
                    goal,
                )
                st.success("Profile saved.")

    st.divider()
    st.subheader("Current profile data")

    # Reload profile from DB to reflect any recent changes.
    profile = get_profile(user_id)

    # Simple read-only summary of profile in text form.
    st.write(f"**Username:** {profile['username'] or 'Not set'}")
    st.write(f"**Age:** {profile['age'] or 'Not set'} years")
    st.write(f"**Weight:** {profile['weight'] or 'Not set'} kg")
    st.write(f"**Height:** {profile['height'] or 'Not set'} cm")
    st.write(f"**Gender:** {profile['gender']}")
    st.write(f"**Goal:** {profile['goal']}")
    st.write(f"**Training style:** {profile['training_type'] or 'Not set'}")
    st.write(f"**Diet preference:** {profile['diet_preferences'] or 'Not set'}")
    st.write(f"**Allergies:** {profile['allergies'] or 'None noted'}")

    # Compute a simple completeness metric based on filled fields.
    fields_for_completeness = [
        profile["username"],
        profile["age"],
        profile["weight"],
        profile["height"],
        profile["training_type"],
        profile["diet_preferences"],
        profile["gender"],
        profile["goal"],
    ]
    filled_fields = sum(
        1 for v in fields_for_completeness if v not in (None, 0, 0.0, "", "Not set")
    )
    completeness = filled_fields / len(fields_for_completeness)

    st.write("")
    st.write("Profile completeness:")
    st.progress(completeness)


def show_trainer_page():
    """
    Display the Trainer page.
    - Uses tabs for 'Workout builder' and 'Training calendar'.
    - Delegates the actual content rendering to the workout_planner.main()
      and workout_calendar.main() functions from the respective modules.
    """
    st.header("Trainer")
    st.write("Build your personalized workout and see your training calendar.")
    st.divider()

    with st.container():
        with st.container(border=True):
            tabs = st.tabs(["Workout builder", "Training calendar"])

            with tabs[0]:
                # Workout builder module (logic implemented externally).
                workout_planner.main()

            with tabs[1]:
                # Training calendar module.
                workout_calendar.main()


def show_calorie_tracker_page():
    """
    Display the Calorie tracker page.
    - Delegates content rendering to the calorie_tracker.main() function.
    """
    st.header("Calorie tracker")
    st.divider()

    with st.container():
        with st.container(border=True):
            calorie_tracker.main()


def show_calories_nutrition_page():
    """
    Display the Calories & Nutrition page.
    - Delegates content rendering to the calories_nutrition.main() function.
    """
    st.header("Calories and nutrition")
    st.divider()

    with st.container():
        with st.container(border=True):
            calories_nutrition.main()


def show_nutrition_page():
    """
    Display the Nutrition adviser page.
    - Delegates content rendering to the nutrition_advisory.main() function.
    """
    st.header("Nutrition adviser")
    st.divider()

    with st.container():
        with st.container(border=True):
            nutrition_advisory.main()


def show_progress_page():
    """
    Display the Progress page.
    - Currently shows a placeholder bar chart using static data.
    - Intended to be replaced by real progress data (e.g., from workouts
      or calorie tracking) in future iterations.
    Demonstrates simple visualization via st.bar_chart.
    """
    st.header("Progress")
    st.divider()

    with st.container():
        with st.container(border=True):
            st.subheader("Demo progress (to be replaced with real data)")

            st.write(
                "This simple chart is a placeholder. "
                "Later, your team can replace it with real workout or calorie data."
            )

            # Example static dataset for demonstration.
            data = {
                "Week": ["Week 1", "Week 2", "Week 3", "Week 4"],
                "Workouts": [2, 3, 4, 3],
            }
            df = pd.DataFrame(data).set_index("Week")

            # Quick bar chart provided by Streamlit.
            st.bar_chart(df)

            st.info("Your teammates can plug real data into this chart later.")


# =========================================================
# PUMPFESSOR JOE – SIDEBAR CHATBOT
# =========================================================

def build_user_context(user_id: int) -> str:
    """
    Construct a compact textual representation of the user's profile
    to provide context for the Pumpfessor Joe chatbot.
    This context is injected as a system-level message in the OpenAI prompt.
    """
    if not user_id:
        return "No user profile available."

    profile = get_profile(user_id)
    parts = [
        f"Age: {profile.get('age')}",
        f"Weight: {profile.get('weight')} kg",
        f"Height: {profile.get('height')} cm",
        f"Gender: {profile.get('gender')}",
        f"Goal: {profile.get('goal')}",
        f"Preferred training style: {profile.get('training_type')}",
        f"Diet preference: {profile.get('diet_preferences')}",
        f"Allergies: {profile.get('allergies')}",
    ]
    # Join profile attributes into a single string separated by " | ".
    return " | ".join(str(p) for p in parts)


def ask_pumpfessor(question: str, user_id: int, history: list[dict]) -> str:
    """
    Query the OpenAI Chat Completions API to obtain a response from
    'Pumpfessor Joe', the in-app strength and nutrition coach.
    - Builds a prompt with:
      * A system role describing Pumpfessor Joe's behavior and scope.
      * A system message including user-specific context (profile).
      * The recent conversation history (up to the last 10 messages).
      * The user's current question.
    - Uses the 'gpt-4.1-mini' model for lower latency and cost.
    Returns the assistant's response text, or an error message on failure.
    """
    user_context = build_user_context(user_id)

    system_prompt = (
        "You are Pumpfessor Joe, the strict but fair AI strength and nutrition coach "
        "for the UniFit Coach app. You base your answers on the user's profile and goals. "
        "Be clear, concise, and practical. Focus on strength training, hypertrophy, "
        "calorie and protein guidance, and habit-building. Do not give medical advice."
    )

    # Initialize the message list with system instructions and user context.
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "system", "content": f"User context: {user_context}"},
    ]

    # Append a truncated version of recent chat history to maintain continuity.
    for msg in history[-10:]:
        if msg["role"] in ("user", "assistant"):
            messages.append({"role": msg["role"], "content": msg["content"]})

    # Finally, add the current user question.
    messages.append({"role": "user", "content": question})

    try:
        # Call OpenAI chat completions endpoint.
        response = client.chat.completions.create(
            model="gpt-4.1-mini",
            messages=messages,
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        # Return a user-friendly error message if the API call fails.
        return f"Pumpfessor Joe encountered an error while generating a response: {e}"


def show_pumpfessor_sidebar():
    """
    Render the Pumpfessor Joe chatbot UI in the sidebar:
    - Displays an avatar (if available) and a title.
    - Shows the last few chat turns between the user and Pumpfessor Joe.
    - Provides a text input and 'Send' button for new questions.
    - Uses session_state.pumpfessor_messages to persist conversation history.
    On sending a question, the app calls ask_pumpfessor() and appends the response.
    """
    st.sidebar.write("---")
    with st.sidebar.container():
        # Title for the chatbot
        st.sidebar.markdown(
            """
            <div style="text-align:center; font-weight:700; margin-bottom:0.5rem;">
                Pumpfessor Joe
            </div>
            """,
            unsafe_allow_html=True,
        )

        # Display avatar if the image is available.
        if PUMPFESSOR_IMAGE:
            st.sidebar.markdown(
                f"""
                <div style="text-align:center; margin-bottom:0.75rem;">
                    <img src="data:image/png;base64,{PUMPFESSOR_IMAGE}"
                         style="width:130px; border-radius:8px; display:block; margin:0 auto;">
                </div>
                """,
                unsafe_allow_html=True,
            )

        # Initialize chat history in session state if not present.
        if "pumpfessor_messages" not in st.session_state:
            st.session_state.pumpfessor_messages = []

        # Render a short version of recent chat history (last 6 messages).
        for msg in st.session_state.pumpfessor_messages[-6:]:
            if msg["role"] == "user":
                st.sidebar.markdown(f"**You:** {msg['content']}")
            else:
                st.sidebar.markdown(f"**Pumpfessor Joe:** {msg['content']}")

        # Input box for new user question.
        user_input = st.sidebar.text_input("Ask a question", key="pumpfessor_input")

        if st.sidebar.button("Send", use_container_width=True):
            q = user_input.strip()
            if q:
                # Add user message to history
                st.session_state.pumpfessor_messages.append(
                    {"role": "user", "content": q}
                )
                # Get assistant answer from OpenAI
                answer = ask_pumpfessor(
                    q,
                    st.session_state.get("user_id", 0),
                    st.session_state.pumpfessor_messages,
                )
                # Add assistant reply to history
                st.session_state.pumpfessor_messages.append(
                    {"role": "assistant", "content": answer}
                )
                # Rerun to update the sidebar display
                st.rerun()  # updated from st.experimental_rerun()


# =========================================================
# PAGE SLUG HELPERS (FOR URL)
# =========================================================

def slug_for_page(page_name: str) -> str:
    """
    Map internal page names to URL slugs.
    Used when writing 'page' query parameter to the URL to support deep-linking.
    """
    mapping = {
        "Profile": "profile",
        "Trainer": "trainer",
        "Calorie tracker": "calorie-tracker",
        "Calories & Nutrition": "calories-nutrition",
        "Nutrition adviser": "nutrition-adviser",
        "Progress": "progress",
    }
    return mapping.get(page_name, "profile")


def page_for_slug(slug: str) -> str:
    """
    Inverse mapping of slug_for_page().
    Translates a URL slug back into an internal page name.
    Used when reading the 'page' query parameter from the URL.
    """
    mapping = {
        "profile": "Profile",
        "trainer": "Trainer",
        "calorie-tracker": "Calorie tracker",
        "calories-nutrition": "Calories & Nutrition",
        "nutrition-adviser": "Nutrition adviser",
        "progress": "Progress",
    }
    return mapping.get(slug, "Profile")


# =========================================================
# MAIN APP
# =========================================================

def main():
    """
    Main entry point of the Streamlit app.
    - Initializes the database schema.
    - Manages global authentication state (logged_in, login_mode, current_page).
    - Synchronizes the current page with URL query parameters.
    - Renders either:
        * Authentication views (login/register/reset) when not logged in, or
        * The logged-in app with sidebar navigation, Pumpfessor Joe chatbot,
          and the selected main page.
    - Enforces profile completeness before allowing access to functional pages.
    """
    create_tables()

    # Initialize essential session_state keys with defaults.
    if "logged_in" not in st.session_state:
        st.session_state.logged_in = False
    if "login_mode" not in st.session_state:
        st.session_state.login_mode = "login"
    if "current_page" not in st.session_state:
        st.session_state.current_page = "Profile"

    # Synchronize current page from URL query params if present.
    params = st.query_params
    if "page" in params:
        slug = params["page"]
        st.session_state.current_page = page_for_slug(slug)

    # ===============================================
    # NOT LOGGED IN: SHOW AUTH PAGES WITH GLASS UI
    # ===============================================
    if not st.session_state.logged_in:
        # Use a full-screen background image and a semi-transparent
        # content block ("glass" effect) for the unauthenticated view.
        st.markdown(
            f"""
            <style>
            [data-testid="stAppViewContainer"] {{
                background-image: url("data:image/jpg;base64,{BACKGROUND_IMAGE}");
                background-size: cover;
                background-position: center;
                background-repeat: no-repeat;
            }}

            .block-container {{
                background-color: rgba(255, 255, 255, 0.75);
                border-radius: 1rem;
                padding-top: 2rem;
                padding-bottom: 2rem;
                max-width: 750px !important;
                margin: 6rem auto !important;
                padding-left: 2rem;
                padding-right: 2rem;
            }}
            </style>
            """,
            unsafe_allow_html=True,
        )

        st.title("UniFit Coach")
        st.caption("Train smarter. Eat better. Stay consistent.")
        st.divider()

        # Render the correct auth subpage based on login_mode.
        mode = st.session_state.login_mode
        if mode == "login":
            show_login_page()
        elif mode == "register":
            show_register_page()
        elif mode == "reset":
            show_reset_password_page()
        return

    # ===============================================
    # LOGGED IN: NORMAL WHITE BACKGROUND
    # ===============================================
    st.markdown(
        """
        <style>
        [data-testid="stAppViewContainer"] {
            background-image: none !important;
            background-color: #ffffff !important;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

    user_id = st.session_state.user_id
    profile = get_profile(user_id)
    profile_complete = is_profile_complete(profile)

    # --------------- SIDEBAR ---------------
    # Display the app logo or a fallback title in the sidebar.
    if LOGO_IMAGE:
        st.sidebar.markdown(
            f"""
            <div style="padding-top:0.25rem; padding-bottom:0.5rem; text-align:center;">
                <img src="data:image/png;base64,{LOGO_IMAGE}"
                     style="width:240px; display:block; margin:0 auto;">
            </div>
            """,
            unsafe_allow_html=True,
        )
    else:
        st.sidebar.markdown("### UniFit Coach")

    # Prominent menu heading in sidebar.
    st.sidebar.markdown(
        f"""
        <div style='
            font-size:1.2rem;
            font-weight:700;
            margin:1rem 0 0.5rem 0;
            padding-left:0.4rem;
            border-left:4px solid {PRIMARY_GREEN};
        '>
            Menu
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Show which user is logged in.
    if "user_email" in st.session_state and st.session_state.user_email:
        st.sidebar.caption(f"Logged in as: {st.session_state.user_email}")
        st.sidebar.write("---")

    # Sidebar navigation: the Profile button is always available.
    if st.sidebar.button("Profile"):
        st.session_state.current_page = "Profile"
        st.query_params["page"] = slug_for_page("Profile")

    # Only show functional pages if the profile is complete.
    if profile_complete:
        if st.sidebar.button("Trainer"):
            st.session_state.current_page = "Trainer"
            st.query_params["page"] = slug_for_page("Trainer")
        if st.sidebar.button("Calorie tracker"):
            st.session_state.current_page = "Calorie tracker"
            st.query_params["page"] = slug_for_page("Calorie tracker")
        if st.sidebar.button("Calories and nutrition"):
            st.session_state.current_page = "Calories & Nutrition"
            st.query_params["page"] = slug_for_page("Calories & Nutrition")
        if st.sidebar.button("Nutrition adviser"):
            st.session_state.current_page = "Nutrition adviser"
            st.query_params["page"] = slug_for_page("Nutrition adviser")
        if st.sidebar.button("Progress"):
            st.session_state.current_page = "Progress"
            st.query_params["page"] = slug_for_page("Progress")
    else:
        # Hint for user: they must complete their profile first.
        st.sidebar.caption("Complete your profile to unlock the applications.")

    # Render Pumpfessor Joe chatbot under the navigation buttons.
    show_pumpfessor_sidebar()

    st.sidebar.write("---")
    if st.sidebar.button("Log out"):
        # Reset all auth-related session state and query params.
        st.session_state.logged_in = False
        st.session_state.user_id = None
        st.session_state.user_email = None
        st.session_state.login_mode = "login"
        st.query_params.clear()  # clear query params for a clean URL
        st.rerun()

    # --------------- MAIN LAYOUT ---------------
    # Main app header and welcome text (top of every logged-in page).
    st.title("UniFit Coach")
    st.caption("Train smarter. Eat better. Stay consistent.")
    if "user_email" in st.session_state and st.session_state.user_email:
        st.write(f"Welcome back, **{st.session_state.user_email}**")
    st.divider()

    page = st.session_state.current_page

    # Enforce profile completion for all pages except Profile.
    if not profile_complete:
        allowed_pages = ["Profile"]
        if page not in allowed_pages:
            st.session_state.current_page = "Profile"
            st.warning("Please complete your profile before accessing the applications.")
            st.rerun()

    # Route to the appropriate page rendering function based on current_page.
    if page == "Profile":
        show_profile_page()
    elif page == "Trainer":
        show_trainer_page()
    elif page == "Calorie tracker":
        show_calorie_tracker_page()
    elif page == "Nutrition adviser":
        show_nutrition_page()
    elif page == "Progress":
        show_progress_page()
    elif page == "Calories & Nutrition":
        show_calories_nutrition_page()


# ---- FINAL CSS OVERRIDES (sidebar buttons etc.) ----
# This CSS block refines button behavior:
# - Ensures main-page buttons are green with white text.
# - Customizes sidebar layout to center elements and style navigation buttons
#   differently (white background, green text).
# - Uses attribute selectors to distinguish between main area and sidebar buttons.

st.markdown(
    f"""
    <style>

    /* ==========================================================
       GLOBAL BUTTONS (Used inside the main page)
       These include: Login, Register, Save Profile, Trainer actions, etc.
       All should use white text on green background.
    ========================================================== */
    div.stButton > button {{
        color: #ffffff !important;
        font-weight: 600 !important;
    }}
    div.stButton > button * {{
        color: #ffffff !important;
    }}

    /* Override Streamlit default button hover/active behavior */
    div.stButton > button:hover,
    div.stButton > button:active,
    div.stButton > button:focus {{
        color: #ffffff !important;
    }}
    div.stButton > button:hover *,
    div.stButton > button:active *,
    div.stButton > button:focus * {{
        color: #ffffff !important;
    }}


    /* ==========================================================
       SIDEBAR LAYOUT → FULL CENTERING OF ALL CONTENT
    ========================================================== */

    /* Make the whole sidebar a vertical flexbox & center everything */
    section[data-testid="stSidebar"] > div:first-child {{
        display: flex !important;
        flex-direction: column !important;
        align-items: center !important;    /* horizontal center */
        justify-content: flex-start !important;
    }}

    /* Center each button block within the sidebar */
    section[data-testid="stSidebar"] div.stButton {{
        display: flex !important;
        justify-content: center !important;
        width: 100% !important;
        margin-bottom: 0.45rem !important;
    }}

    /* ==========================================================
       SIDEBAR BUTTONS (Navigation Menu)
       These must stay green-text on white background.
    ========================================================== */
    section[data-testid="stSidebar"] div.stButton > button {{
        width: 230px !important;               /* Sidebar button width */
        background-color: #ffffff !important;
        color: {PRIMARY_GREEN} !important;
        border: 1px solid {PRIMARY_GREEN} !important;
        padding: 0.55rem 0.75rem !important;
        text-align: center !important;
        border-radius: 999px !important;       /* pill shape */
        font-weight: 600 !important;
    }}

    /* Ensure text inside sidebar buttons stays green */
    section[data-testid="stSidebar"] div.stButton > button * {{
        color: {PRIMARY_GREEN} !important;
    }}

    /* Sidebar button hover → green background, white text */
    section[data-testid="stSidebar"] div.stButton > button:hover,
    section[data-testid="stSidebar"] div.stButton > button:active,
    section[data-testid="stSidebar"] div.stButton > button:focus {{
        background-color: {PRIMARY_GREEN} !important;
        color: #ffffff !important;
    }}
    section[data-testid="stSidebar"] div.stButton > button:hover *,
    section[data-testid="stSidebar"] div.stButton > button:active *,
    section[data-testid="stSidebar"] div.stButton > button:focus * {{
        color: #ffffff !important;
    }}

    </style>
    """,
    unsafe_allow_html=True,
)

if __name__ == "__main__":
    """
    Script entry point:
    - Lazily loads the recipes DataFrame into session_state (once per session).
    - Then calls main() to run the Streamlit app.
    The recipe data is used by the nutrition adviser module.
    """
    # Load recipes DataFrame once at app start
    if "recipes_df" not in st.session_state:
        # Show a spinner while loading larger external data.
        with st.spinner("Loading recipe data..."):
            st.session_state.recipes_df = load_and_prepare_data(DATA_URL)

    # Start the main application flow.
    main()
