# IMPORTS
import random            # Python's built-in module for randomness
import pandas as pd      # Pandas for reading / processing the CSV exercise database
import streamlit as st   # Streamlit for the web UI

# GLOBAL CONSTANTS
# Primary brand color used consistently in headings, buttons, etc.
# This is used in several HTML/CSS snippets to keep the visual style uniform.
PRIMARY_COLOR = "#007A3D"  # UniFit Coach green

# DATA LOADING
@st.cache_data
def load_exercises(csv_path: str):
    """
    Load and clean the exercise database from a CSV file.
    Parameters
    csv_path : str
        Path to the CSV file that holds all exercises.
    Returns
    pandas.DataFrame
        A cleaned DataFrame where:
        - column names are normalized
        - obviously invalid rows are removed
    """
    # Read the CSV file.
    # - encoding="latin1" accepts many special characters from Excel exports
    # - sep=None, engine="python" lets pandas auto-detect separator (',' or ';')
    df = pd.read_csv(csv_path, encoding="latin1", sep=None, engine="python")
    # Normalize column names by stripping extra spaces.
    # Example: " Exercise " -> "Exercise"
    df.columns = [c.strip() for c in df.columns]
    # Strip whitespace from string values in every column that holds text.
    for col in df.columns:
        if df[col].dtype == "object":
            # Convert to string and remove leading/trailing spaces, e.g. "  Chest "
            df[col] = df[col].astype(str).str.strip()

    # Map potentially different column names to a unified schema.
    # For example, "Exercise Name", "Exercise", "Exercises" -> "Exercise"
    rename = {}
    for c in df.columns:
        name = c.lower()
        # Any column that starts with "exercise..." is treated as "Exercise"
        if name.startswith("exercise"):
            rename[c] = "Exercise"
        # Any column that starts with "equipment..." becomes "Equipment Required"
        elif name.startswith("equipment"):
            rename[c] = "Equipment Required"
        # Any column that starts with "muscle..." becomes "Muscle Group"
        elif name.startswith("muscle"):
            rename[c] = "Muscle Group"
        # Any column that starts with "link..." becomes "Link"
        elif name.startswith("link"):
            rename[c] = "Link"
    # Apply the renaming dictionary to the DataFrame
    df = df.rename(columns=rename)
    # Drop rows where we are missing the exercise name OR the muscle group.
    # These rows are considered invalid for building workouts.
    df = df.dropna(subset=["Exercise", "Muscle Group"])
    # Some messy CSVs may literally contain the string "nan".
    # We additionally filter those out.
    df = df[df["Exercise"].str.lower() != "nan"]
    df = df[df["Muscle Group"].str.lower() != "nan"]
    # Because of @st.cache_data, Streamlit caches this result. The CSV is not
    # re-read every time the app reruns, which keeps things fast.
    return df

# MUSCLE INFERENCE (used when SELECTING exercises, not for soreness UI)
def infer_muscles_from_title(title, all_muscles):
    """
    Infer which muscle groups to focus on based on the workout title
    (e.g. "Push Day", "Pull Day").
    This function is used for the "AI logic" that chooses the most relevant
    exercises out of the whole database.
    Parameters
    title : str
        Name of the workout type (e.g. "Push Day").
    all_muscles : list-like
        List of all muscle groups that exist in the database.
    Returns
    list[str]
        List of muscle groups that should be prioritized.
    """
    # To simplify matching, work with lowercase strings
    title = title.lower()
    # Mapping from keywords inside the workout title -> preferred muscle groups
    mapping = {
        "push": ["Chest", "Shoulders", "Traps", "Triceps"],
        "pull": ["Lats", "Upper Back", "Lower Back", "Forearms", "Biceps"],
        "legs": ["Quads", "Hamstrings", "Calves", "Glutes", "Adductor"],
        "upper": [
            "Chest", "Shoulders", "Traps", "Lats", "Upper Back",
            "Lower Back", "Forearms", "Biceps", "Triceps",
        ],
        "lower": ["Quads", "Hamstrings", "Calves", "Glutes", "Adductor"],
        "arms": ["Biceps", "Triceps", "Forearms"],
        "chest": ["Chest"],
        "back": ["Lats", "Upper Back", "Lower Back"],
        "shoulder": ["Shoulders"],
        "glute": ["Glutes"],
        "core": ["Abs", "Core"],
        "abs": ["Abs", "Core"],
        # In case we have cardio entries in the database
        "cardio": ["Cardio"],
    }
    # Collect muscle groups whose keyword is contained in the title
    found = set()
    for key, muscles in mapping.items():
        if key in title:
            # Keep only muscle names that actually exist in the database
            found.update([m for m in muscles if m in all_muscles])
    # If nothing is detected (e.g. user entered a custom name),
    # we just take the first three muscle groups from the database
    if not found:
        return all_muscles[:3]
    return list(found)

# SORENESS OPTIONS PER WORKOUT TYPE (UI helper, not scoring logic)
def get_soreness_options(title: str) -> list[str]:
    """
    Decide which muscle groups the user can mark as "sore" depending
    on the selected workout type.
    This function is only used for the UI multi-select options. It does not
    affect how exercises are scored, except indirectly via
    `apply_soreness_adjustment`.
    Parameters
    --
    title : str
        Name of the workout type (e.g. "Push Day").
    Returns
    --
    list[str]
        List of muscle groups that should be offered as "sore" options.
    """
    # Define building-block muscle groups
    push_groups = ["Chest", "Shoulders", "Traps", "Triceps"]
    pull_groups = ["Lats", "Upper Back", "Lower Back", "Forearms", "Biceps"]
    leg_groups = ["Quads", "Hamstrings", "Calves", "Glutes", "Adductor"]
    abs_groups = ["Abs"]
    # Map workout titles to the muscle groups that may be sore
    mapping = {
        "push day": push_groups,
        "pull day": pull_groups,
        "leg day": leg_groups,
        "lower body": leg_groups,
        "upper body": push_groups + pull_groups,
        "full body": push_groups + pull_groups + leg_groups + abs_groups,
        # Cardio does not target a classic muscle group in this DB
        "cardio": [],
    }
    # Normalize the title (lowercase and strip spaces) for matching
    key = title.lower().strip()
    # Get the base list of muscle groups; if title is unknown, we get []
    base = mapping.get(key, [])
    # Remove duplicates while preserving the original order
    seen = set()
    result = []
    for m in base:
        if m not in seen:
            seen.add(m)
            result.append(m)
    return result
    
# "AI" WORKOUT LOGIC – scoring + rep scheme
def compute_num_exercises(minutes, intensity):
    """
    Roughly estimate how many exercises should be in the workout,
    based on available time and chosen intensity.
    Idea:
    - Base: ~1 exercise per 8 minutes
    - More intense workouts can contain slightly more exercises
    - Always clamp to a reasonable range
    """
    # Base count: about 1 exercise for every 8 minutes
    base = max(3, min(10, round(minutes / 8)))
    # Adjust this number depending on intensity
    if intensity == "Light":
        # Slightly fewer exercises for light sessions
        return max(3, int(base * 0.8))
    if intensity == "Moderate":
        # No change for moderate intensity
        return base
    # "Max effort" -> a bit more volume, but capped at 12 exercises
    return min(12, int(base * 1.2))
def score_exercise(row, targets):
    """
    Give each exercise a numeric score used for sorting and selection.
    The score is based on:
    - whether the exercise's primary muscle group is in the `targets` list
    - a bit of randomness to avoid always picking the exact same exercises
    Parameters
    row : pandas.Series
        One row of the DataFrame representing a single exercise.
    targets : list[str]
        Muscle groups that we want to prioritize.
    Returns
    float
        The final score for this exercise.
    """
    # Muscle group of this particular exercise
    mg = row["Muscle Group"]
    score = 0.0
    # Reward exercises that train one of the target muscle groups
    if mg in targets:
        score += 6.0
    # Add small random noise so the workout varies between runs
    score += random.uniform(-1, 1)
    return score
def sets_reps_rest(intensity):
    """
    Decide on a (sets, reps, rest) scheme for a given workout intensity.
    Parameters
    intensity : str
        "Light", "Moderate", or "Max effort".
    Returns
    tuple
        (sets: int, reps: str, rest: str)
    """
    if intensity == "Light":
        return 2, "12–15", "45–60 sec"
    if intensity == "Moderate":
        return 3, "8–12", "60–90 sec"
    # "Max effort"
    return 4, "6–10", "90–120 sec"
def apply_soreness_adjustment(exercises, sore_muscles):
    """
    Adjust the workout based on sore muscle groups.
    Rule:
    - For each sore muscle group, remove at most ONE exercise for that group
      from the planned workout.
    Parameters
    exercises : list[dict]
        List of exercise dictionaries that make up the planned workout.
    sore_muscles : list[str]
        Muscle groups the user marked as sore.
    Returns
    list[dict]
        Possibly shorter list of exercises after soreness adjustment.
    """
    # If the user did not report any soreness, we return the list unchanged.
    if not sore_muscles:
        return exercises
    # Use a set for quick membership checks
    sore_muscles = set(sore_muscles)
    # Keep track of whether we've already removed one exercise for each sore group
    removed_for = {m: False for m in sore_muscles}
    final_exercises = []
    for ex in exercises:
        # Muscle group of the current exercise
        mg = ex["muscle"]
        # If this muscle is sore and we haven't removed an exercise for it yet,
        # we skip this one (do not append to final_exercises).
        if mg in removed_for and not removed_for[mg]:
            removed_for[mg] = True
            continue
        # Otherwise we keep the exercise
        final_exercises.append(ex)
    return final_exercises
def build_workout_plan(df, title, minutes, sore_muscles, intensity):
    """
    Build a structured workout plan.
    Parameters
    df : pandas.DataFrame
        Cleaned exercise DataFrame.
    title : str
        Workout type selected by the user (e.g. "Push Day").
    minutes : int
        Total time the user has available.
    sore_muscles : list[str]
        Muscle groups the user marked as sore.
    intensity : str
        "Light", "Moderate", or "Max effort".
    Returns
    list[dict]
        A list of exercise dictionaries. Each dictionary will contain:
        - name, muscle, equipment, sets, reps, rest, link
    """
    # Special handling for CARDIO WORKOUT
    # For cardio, we just choose a single exercise and give it the full time.
    if title.lower().strip() == "cardio":
        # Filter the DataFrame to only cardio exercises.
        # This assumes the muscle group column uses something containing "cardio".
        df_cardio = df[df["Muscle Group"].str.contains("cardio", case=False, na=False)]
        # If the DB has no cardio entries, we cannot build a plan
        if df_cardio.empty:
            return []
        # Randomly pick ONE cardio exercise
        row = df_cardio.sample(1).iloc[0]
        # Build a single-exercise workout where the "reps" field shows minutes
        exercises = [
            {
                "name": row["Exercise"],
                "muscle": row["Muscle Group"],
                "equipment": row.get("Equipment Required", "–"),
                "sets": 1,
                "reps": f"{minutes} minutes",
                "rest": "As needed",
                "link": row.get("Link", ""),
            }
        ]
        # Cardio version ignores soreness adjustments
        return exercises
    # NORMAL (RESISTANCE) WORKOUT FLOW
    # List of all available muscle groups in the database
    all_muscles = sorted(df["Muscle Group"].unique())
    # Decide which muscles to focus on given the workout title
    targets = infer_muscles_from_title(title, all_muscles)
    # Safety: if for some reason the DataFrame is empty, return no workout
    if df.empty:
        return []
    # Work on a copy so the original DataFrame remains unmodified
    df = df.copy()
    # Compute a "score" for each exercise row using the targets + randomness
    df["score"] = df.apply(lambda r: score_exercise(r, targets), axis=1)
    # Sort so that highest scores come first
    df = df.sort_values("score", ascending=False)
    # Decide how many exercises we want for this session
    num = min(compute_num_exercises(minutes, intensity), len(df))
    # Get recommended sets, reps, and rest based on intensity
    sets, reps, rest = sets_reps_rest(intensity)
    # Build a list of exercise dictionaries from the top-scoring rows
    exercises = []
    for _, r in df.head(num).iterrows():
        exercises.append(
            {
                "name": r["Exercise"],
                "muscle": r["Muscle Group"],
                "equipment": r.get("Equipment Required", "–"),
                "sets": sets,
                "reps": reps,
                "rest": rest,
                "link": r.get("Link", ""),
            }
        )
    # Apply soreness rule AFTER constructing the list:
    # one fewer exercise per sore muscle group
    exercises = apply_soreness_adjustment(exercises, sore_muscles)
    return exercises
    
# FLASHCARD VIEW (MAIN WORKOUT EXECUTION UI)
def show_flashcards():
    """
    Display the current exercise as a "flashcard" and provide navigation
    buttons to move between exercises.
    Session state variables used
    - st.session_state.workout     : list of exercise dicts
    - st.session_state.current_card: integer index of the current exercise
    - st.session_state.finished    : boolean, True when workout is done
    """
    state = st.session_state
    # List containing the whole workout (created in main())
    exercises = state.workout
    # Index of the currently displayed exercise
    idx = state.current_card
    # Total number of exercises in the workout
    total = len(exercises)
    # Current exercise dictionary
    ex = exercises[idx]
    # Header section at the top of the page (progress)
    # Text: "Exercise X of Y"
    st.write(f"### Exercise {idx + 1} of {total}")
    # Visual progress bar: percentage of exercises reached so far
    st.progress((idx + 1) / total)
    # Flashcard with details of the current exercise
    # We use HTML within st.markdown to get more control over styling
    st.markdown(
        f"""
<div style="padding:25px; border-radius:22px; background:white;
            box-shadow:0 6px 14px rgba(0,0,0,0.12); margin-top:20px;">
  <h2 style="color:{PRIMARY_COLOR}; margin-top:0;">{ex['name']}</h2>
  <ul style="font-size:16px; line-height:1.7;">
    <li><b>Muscle trained:</b> {ex['muscle']}</li>
    <li><b>Equipment needed:</b> {ex['equipment']}</li>
    <li><b>Your goal:</b> {ex['sets']} sets × {ex['reps']} reps</li>
    <li><b>Rest between sets:</b> {ex['rest']}</li>
  </ul>
  {f'<a href="{ex["link"]}" target="_blank" style="color:{PRIMARY_COLOR}; font-weight:bold;">Video exercise demonstration</a>'
      if isinstance(ex["link"], str) and ex["link"].startswith("http") else ""}
</div>
""",
        unsafe_allow_html=True,
    )
    # Flags for first/last exercise to control which buttons are shown
    is_first = idx == 0
    is_last = idx == total - 1
    # Navigation buttons
    # Previous on the far left (wider), spacer, next/complete on far right.
    col_prev, col_spacer, col_next = st.columns([4, 1, 2])
    # LEFT COLUMN: "Previous Exercise" button (hidden on first exercise)
    with col_prev:
        if not is_first:
            # Use a non-breaking space between "Previous" and "Exercise"
            # so Streamlit doesn't wrap them on two lines.
            prev_label = "👈 Previous\u00A0Exercise"
            if st.button(prev_label):
                # Decrease the index and re-run app to show the previous exercise
                state.current_card -= 1
                st.rerun()
    # RIGHT COLUMN: either "Next Exercise" or "Complete workout" on the last card
    with col_next:
        next_label = "Complete workout 👉" if is_last else "Next Exercise 👉"
        if st.button(next_label):
            if is_last:
                # Last exercise: mark workout as finished so we show the summary
                state.finished = True
            else:
                # Otherwise just move to the next exercise
                state.current_card += 1

            # Trigger a rerun so the UI updates
            st.rerun()
            
# COMPLETION / SUMMARY SCREEN
def show_completion():
    """
    Show a summary page once the workout is finished.
    Uses st.session_state.workout to list all exercises that were performed.
    """
    state = st.session_state
    # Heading and congratulation message
    st.markdown(
        f"<h2 style='color:{PRIMARY_COLOR};'>Workout Completed! 🎉</h2>",
        unsafe_allow_html=True,
    )
    st.success("Joe the Pumpfessor is proud of you! 💪🔥")
    st.write("### Your full workout summary:")
    # Loop over all exercises that were part of the workout
    for ex in state.workout:
        st.markdown(
            f"""
<div style="padding:18px; border-radius:16px; border:2px solid {PRIMARY_COLOR};
            background:#F4FFF7; margin:10px 0;">
  <h4 style='color:{PRIMARY_COLOR}; margin-top:0;'>{ex['name']}</h4>
  <p><b>Muscle:</b> {ex['muscle']}</p>
  <p><b>Equipment:</b> {ex['equipment']}</p>
  <p><b>Sets/Reps:</b> {ex['sets']} × {ex['reps']}</p>
  <p><b>Rest:</b> {ex['rest']}</p>
  {f'<a href="{ex["link"]}" target="_blank">Video exercise demonstration</a>'
      if isinstance(ex["link"], str) and ex["link"].startswith("http") else ""}
</div>
""",
            unsafe_allow_html=True,
        )
    # Button to go back to the workout builder (start screen)
    if st.button("Back to workout builder ↩️"):
        # Remove workout-related values from session_state so we reset the flow
        for key in ["workout", "current_card", "finished"]:
            if key in state:
                del state[key]
        st.rerun()
        
# MAIN ENTRY POINT
def main():
    """
    Entry point used by the main Streamlit app (e.g. from app.py).
    Responsibilities
    - Load the exercise database.
    - Decide which screen to show:
        * workout flashcards (if a workout is ongoing),
        * completion summary (if user just finished),
        * or the workout builder form (initial state).
    """
    state = st.session_state
    # Load the exercise CSV.
    # IMPORTANT: the CSV must live in the same folder as app.py
    df = load_exercises("CS Workout Exercises Database CSV.csv")
    # Determine which view to show based on session_state
    # If a workout already exists and is not finished, show the flashcards.
    if "workout" in state and not state.get("finished", False):
        show_flashcards()
        return
    # If the workout is marked as finished, show the completion summary.
    if state.get("finished", False):
        show_completion()
        return
    # If we reach this point, no workout is in progress.
    # We show the workout builder form.
    st.subheader("Build a workout with Pumpfessor Joe")
    st.caption("Answer a few questions and get a suggested workout plan.")
    # Workout type selector
    workout_options = [
        "Push Day",
        "Pull Day",
        "Leg Day",
        "Full Body",
        "Upper Body",
        "Lower Body",
        "Cardio",
    ]
    title = st.selectbox("Choose your workout type:", workout_options, index=0)
    # Time available slider
    minutes = st.slider("How many minutes do you have?", 15, 120, 45, 5)
    # Save meta information about the current workout in session state.
    # Other parts of the app (e.g. a calorie tracker) can also read this.
    st.session_state["current_workout"] = {
        "title": title,
        "minutes": minutes,
    }
    # Soreness selection
    st.markdown(
        f"<p style='color:{PRIMARY_COLOR};'><b>Are you sore anywhere?</b></p>",
        unsafe_allow_html=True,
    )
    # Inject CSS so selected tags in the multiselect appear in green.
    st.markdown(
        f"""
        <style>
        .stMultiSelect [data-baseweb="tag"] {{
            background-color: {PRIMARY_COLOR} !important;
            color: white !important;
        }}
        .stMultiSelect [data-baseweb="tag"] span {{
            color: white !important;
        }}
        </style>
        """,
        unsafe_allow_html=True,
    )
    # Compute the list of soreness options for this specific workout type
    soreness_options = get_soreness_options(title)
    if not soreness_options:
        # For some workouts (e.g. Cardio) there are no muscle options
        st.caption("No sore muscle selection for this workout type.")
        sore_groups = []
    else:
        # Multiselect widget allows the user to choose the sore muscle groups
        sore_groups = st.multiselect(
            "Select sore muscle groups:",
            options=soreness_options,
        )
    # Intensity selection
    intensity = st.selectbox(
        "Intensity:",
        ["Light", "Moderate", "Max effort"],
        index=1,  # default to "Moderate"
    )
    # Generate Workout button
    if st.button("Generate Workout"):
        # Build the workout plan based on the chosen parameters
        workout = build_workout_plan(df, title, minutes, sore_groups, intensity)
        if not workout:
            # If we could not find any matching exercises,
            # show a warning so the user can try different settings.
            st.warning(
                "No suitable exercises found. Try changing time, intensity, or soreness selection."
            )
        else:
            # Save workout & flashcard state into session_state,
            # then rerun to switch to the flashcard view.
            state.workout = workout
            state.current_card = 0
            state.finished = False
            st.rerun()
