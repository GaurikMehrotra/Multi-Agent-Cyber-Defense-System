"""Dashboard uses the authenticated API; it has no direct tool permissions."""

import os

import httpx
import streamlit as st

st.set_page_config(page_title="Defensive Lab SOC", layout="wide")
st.title("Multi-Agent Cyber Defense — SIMULATION ONLY")
st.warning(
    "Only explicitly authorized isolated lab assets may be verified. No real response enforcement."
)
key = st.sidebar.text_input("API key", type="password")
base = os.getenv("API_URL", "http://127.0.0.1:8000")


def request(method, route, body=None):
    response = httpx.request(
        method, base + route, headers={"X-API-Key": key}, json=body, timeout=15
    )
    if response.is_error:
        st.error(f"API {response.status_code}: {response.text}")
        return None
    return response.json()


if st.sidebar.button("STOP ALL INVESTIGATIONS", type="primary"):
    request("POST", "/stop")
if st.sidebar.button("Admin: resume"):
    request("POST", "/resume")
if key:
    health = request("GET", "/health")
    st.write("Runtime", health)
    cases = request("GET", "/cases")
    st.subheader("Alert / case queue")
    st.dataframe(cases or [])
    case_id = st.text_input("Case ID")
    if case_id:
        case = request("GET", "/cases/" + case_id)
        if case:
            st.subheader("Evidence, hypotheses, plan and agent trace")
            st.json(case)
            if st.button("Approve exact plan (admin, simulated only)"):
                st.json(request("POST", "/cases/" + case_id + "/approve"))
            with st.expander("Admin override — approval still required"):
                action = st.selectbox(
                    "Action",
                    ["escalate", "observe", "quarantine_host", "block_ip", "disable_account"],
                )
                reason = st.text_input("Reason (at least 10 characters)")
                if st.button("Propose override") and case.get("report", {}).get("plan"):
                    plan = {**case["report"]["plan"], "action": action}
                    st.json(
                        request(
                            "POST",
                            "/cases/" + case_id + "/override",
                            {"plan": plan, "reason": reason},
                        )
                    )
    st.subheader("Simulated network")
    st.json(request("GET", "/network"))
