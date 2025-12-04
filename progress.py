import streamlit as st
import pandas as pd
import datetime as dt
from database import get_db   # falls dein DB-Modul anders heißt → anpassen


# ---------------------------------------------------------
#                  MAIN ENTRY POINT
# ---------------------------------------------------------

def show_progress_page():
    """Rendert die komplette Progress-Seite."""
    user_id = st.session_state.get("user_id", None)

    if not user_id:
        st.error("No user logged in. Please login first.")
        return

    st.header("📈 Progress")
    st.caption("Track your training consistency and nutrition alignment with your goal.")
    st.divider()

    # ---------------------------------------------------------
    # Filter / Zeitraum
    # ---------------------------------------------------------
    col1, col2 = st.columns(2)
    with col1:
        period = st.selectbox(
            "Time period",
            ["Last 7 days", "Last 30 days", "Last 90 days"],
            index=1
        )

    with col2:
        st.write("")  # Platzhalter für später (Custom Date Range)

    days = {"Last 7 days": 7, "Last 30 days": 30, "Last 90 days": 90}[period]
    today = dt.date.today()
    start_date = today - dt.timedelta(days=days)

    # ---------------------------------------------------------
    # Daten laden
    # ---------------------------------------------------------
    conn = get_db()

    nutrition_df = pd.read_sql_query(
        """
        SELECT date, total_calories, total_protein, target_calories, target_protein
        FROM nutrition_daily
        WHERE user_id = ?
          AND date >= ?
        ORDER BY date ASC
        """,
        conn,
        params=(user_id, start_date.isoformat()),
    )

    workout_df = pd.read_sql_query(
        """
        SELECT date, sessions, total_volume
        FROM workout_daily
        WHERE user_id = ?
          AND date >= ?
        ORDER BY date ASC
        """,
        conn,
        params=(user_id, start_date.isoformat()),
    )

    conn.close()

    # ---------------------------------------------------------
    # Wenn noch keine Daten da sind
    # ---------------------------------------------------------
    if nutrition_df.empty and workout_df.empty:
        st.info("No progress data yet. Log some workouts and nutrition to see your trends.")
        return

    # ---------------------------------------------------------
    # KPIs
    # ---------------------------------------------------------

    with st.container(border=True):
        st.subheader("Overview")

        c1, c2, c3, c4 = st.columns(4)

        # Workouts total
        total_sessions = workout_df["sessions"].sum() if not workout_df.empty else 0
        c1.metric("Workouts", int(total_sessions))

        # Avg calories
        if not nutrition_df.empty:
            avg_cal = int(nutrition_df["total_calories"].mean())
            avg_prot = int(nutrition_df["total_protein"].mean())
        else:
            avg_cal = avg_prot = "-"

        c2.metric("Avg daily calories", avg_cal)
        c3.metric("Avg daily protein (g)", avg_prot)

        # Training volume
        if not workout_df.empty:
            avg_vol = int(workout_df["total_volume"].mean())
        else:
            avg_vol = "-"

        c4.metric("Avg training volume", avg_vol)

    # ---------------------------------------------------------
    # Charts Section
    # ---------------------------------------------------------

    with st.container(border=True):
        st.subheader("Details")

        tab1, tab2 = st.tabs(["Calories", "Training"])

        # ---------------- CALORIES TAB ----------------
        with tab1:
            st.subheader("Calories over time")

            if nutrition_df.empty:
                st.caption("No nutrition data yet.")
            else:
                df_plot = nutrition_df.set_index("date")[["total_calories"]]
                st.line_chart(df_plot)

                # Optional: Zielkalorien anzeigen, falls vorhanden
                if "target_calories" in nutrition_df.columns and nutrition_df["target_calories"].notna().any():
                    st.metric("Target calories (avg)", int(nutrition_df["target_calories"].mean()))

            st.divider()

            st.subheader("Protein intake")
            if nutrition_df.empty:
                st.caption("No nutrition data yet.")
            else:
                df_plot2 = nutrition_df.set_index("date")[["total_protein"]]
                st.line_chart(df_plot2)

        # ---------------- TRAINING TAB ----------------
        with tab2:
            st.subheader("Training volume (daily)")
            if workout_df.empty:
                st.caption("No training data yet.")
            else:
                df_plot = workout_df.set_index("date")[["total_volume"]]
                st.bar_chart(df_plot)

            st.divider()

            st.subheader("Training frequency")
            if workout_df.empty:
                st.caption("No training data yet.")
            else:
                weekly_freq = (
                    workout_df.assign(week=lambda x: pd.to_datetime(x["date"]).dt.isocalendar().week)
                             .groupby("week")["sessions"]
                             .sum()
                )
                st.bar_chart(weekly_freq)


# ---------------------------------------------------------
# ENDE progress.py
# ---------------------------------------------------------
