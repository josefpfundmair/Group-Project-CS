# workout_calendar.py
import calendar
import datetime
import streamlit as st
from streamlit import session_state as state
PRIMARY_COLOR = "#007A3D"
# Weekday labels matching datetime.weekday() (Mon=0..Sun=6)
WEEKDAYS = [
    ("Monday", 0),
    ("Tuesday", 1),
    ("Wednesday", 2),
    ("Thursday", 3),
    ("Friday", 4),
    ("Saturday", 5),
    ("Sunday", 6),
]
# Workout types shown in the dropdown
WORKOUT_TYPES = [
    "Push day",
    "Pull day",
    "Leg day",
    "Full body",
    "Lower body",
    "Cardio",
]
def _init_state():
    """
    Ensure required keys exist in Streamlit session_state.
    This is called once at the start of main() so all other functions
    can safely assume the keys are there.
    """
    # Dict: date string "YYYY-MM-DD" -> {"minutes": int, "type": str}
    if "workout_logs" not in state:
        state.workout_logs = {}
    # The date the user is currently editing in the calendar
    if "selected_date" not in state:
        state.selected_date = datetime.date.today()
def _render_month(year: int, month: int):
    """
    Render one month grid with clickable days and workout summaries.
    The layout is:
      - a title (e.g. "December 2025")
      - a header row (Mo, Tu, ...)
      - several rows of 7 columns (one per day)
    """
    # Calendar with weeks starting on Monday (0)
    cal = calendar.Calendar(firstweekday=0)
    month_name = calendar.month_name[month]
    # Month title
    st.markdown(f"#### {month_name} {year}")
    # Weekday header row (short labels like "Mo", "Tu", ...)
    header_cols = st.columns(7)
    for col, (name, _) in zip(header_cols, WEEKDAYS):
        col.markdown(
            f"<div style='text-align:center; font-size:13px; "
            f"color:#555; font-weight:600;'>{name[:2]}</div>",
            unsafe_allow_html=True,
        )
    # cal.monthdatescalendar returns weeks; each week is 7 date objects
    for week in cal.monthdatescalendar(year, month):
        # Create 7 equal-width columns for this week
        cols = st.columns(7)
        # Pair each column with a date
        for col, date_obj in zip(cols, week):
            # Some date objects may belong to previous/next month;
            # those are just "padding" to complete the week row.
            if date_obj.month != month:
                with col:
                    st.write("")  # keep grid spacing but show nothing
                continue
            date_str = date_obj.isoformat()  # "YYYY-MM-DD"
            # Retrieve any saved workout for this date
            log = state.workout_logs.get(date_str)
            # Check if this is the date currently selected in state
            is_selected = state.selected_date == date_obj
            day_label = str(date_obj.day)
            with col:
                # Display "Selected" flag above the button for the active day
                if is_selected:
                    st.markdown(
                        f"<div style='text-align:center; font-size:11px; "
                        f"color:{PRIMARY_COLOR};'>Selected</div>",
                        unsafe_allow_html=True,
                    )
                # Main day button: clicking it updates selected_date
                # use_container_width=True makes it fill the column
                if st.button(
                    day_label,
                    key=f"day-btn-{date_str}",  # key must be unique per button
                    use_container_width=True,
                ):
                    state.selected_date = date_obj
                # If we have data for this day, show a one-line summary under the button
                if log:
                    minutes = log.get("minutes")
                    wtype = log.get("type")
                    st.caption(f"{minutes} min – {wtype}")
def main():
    """
    Main UI: calendars + workout form + recent workouts.
    This function wires everything together and is meant to be called
    from your Streamlit entry point.
    """
    _init_state()
    # Short instructions at the top
    st.subheader("Workout log calendar")
    st.caption(
        "Log your past workouts in a calendar view. "
        "Click on a date to add or edit the workout for that day."
    )
    st.info(
        "You always see the current month plus the previous two months (3 months of past workouts)."
    )
    st.divider()
    
    # Calendar section: compute which months to render
    today = datetime.date.today()
    # Convert (year, month) into a single integer "month index":
    # This makes going back N months just basic integer arithmetic.
    base_index = today.year * 12 + (today.month - 1)
    months_to_show = 3  # current month + 2 previous
    for offset in range(months_to_show):
        # offset=0 -> current month, 1 -> previous month, 2 -> two months ago
        idx = base_index - offset
        year = idx // 12                # reconstruct year from index
        month = (idx % 12) + 1          # reconstruct month (1..12)
        _render_month(year, month)
        st.write("")  # vertical spacing between month blocks
    st.divider()

    # Workout form for the currently selected day
    selected_date: datetime.date = state.selected_date
    # Human-readable date, e.g. "Monday, 01 December 2025"
    selected_str = selected_date.strftime("%A, %d %B %Y")
    st.markdown(f"### Log workout for {selected_str}")
    # Key used in workout_logs dict
    date_key = selected_date.isoformat()
    # Retrieve previous values (if any) for this day
    existing_log = state.workout_logs.get(date_key, {})
    existing_minutes = existing_log.get("minutes", 0)
    existing_type = existing_log.get("type", WORKOUT_TYPES[0])
    # Two-column layout: left = duration, right = workout type
    col_minutes, col_type = st.columns([1, 1])
    with col_minutes:
        minutes = st.number_input(
            "Workout length (minutes)",
            min_value=0,
            max_value=600,
            step=5,
            value=int(existing_minutes),  # prefill with existing value
            help="How long did you train on this day?",
            key="minutes_input",
        )
    with col_type:
        # If saved type not in WORKOUT_TYPES (list changed), fall back to first entry
        if existing_type not in WORKOUT_TYPES:
            existing_type = WORKOUT_TYPES[0]
        workout_type = st.selectbox(
            "Workout type",
            options=WORKOUT_TYPES,
            index=WORKOUT_TYPES.index(existing_type),  # preselect existing
            help="What kind of workout did you do?",
            key="workout_type_select",
        )
    # Save / update entry when button is pressed
    if st.button("Save workout", type="primary"):
        # Overwrite or create log entry for this date
        state.workout_logs[date_key] = {
            "minutes": int(minutes),
            "type": workout_type,
        }
        st.success(f"Saved workout for {selected_str}.")

    # Recent workouts list (optional)
    # Only show list if there is at least one log
    if state.workout_logs:
        st.markdown("#### Recent logged workouts")
        # state.workout_logs is a dict; we sort by key (date string) in reverse
        # order so the newest dates appear first. ISO date strings sort correctly.
        items = sorted(state.workout_logs.items(), key=lambda x: x[0], reverse=True)
        # Limit to last 10 entries so the list does not get too long
        for d_str, log in items[:10]:
            d_obj = datetime.date.fromisoformat(d_str)
            # e.g. "07 Dec 2025 (Sun)"
            label = d_obj.strftime("%d %b %Y (%a)")
            st.write(f"- **{label}**: {log['minutes']} min – {log['type']}")
