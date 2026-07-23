import streamlit as st

st.title("Windows Monitoring Dashboard")

st.metric(
    "Processes",
    150
)

st.metric(
    "Alerts",
    12
)

st.metric(
    "Services",
    230
)

st.success("Monitoring Active")