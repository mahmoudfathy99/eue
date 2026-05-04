import streamlit as st
import re

# ========== Page Config ==========
st.set_page_config(
    page_title="SQL Injection Detector",
    page_icon="🛡️",
    layout="centered"
)

# ========== CSS ==========
st.markdown("""
<style>
    .attack { background-color: #ff4b4b22; border-left: 4px solid #ff4b4b; padding: 1rem; border-radius: 8px; }
    .safe   { background-color: #21c35422; border-left: 4px solid #21c354; padding: 1rem; border-radius: 8px; }
</style>
""", unsafe_allow_html=True)

# ========== Title ==========
st.title("🛡️ SQL Injection Detector")
st.markdown("Enter any SQL query to check if it's **malicious** or **safe**.")
st.divider()

# ========== SQL Injection Keywords ==========
SQL_PATTERNS = [
    r"(\bOR\b|\bAND\b)\s+['\"0-9]",
    r"--",
    r";",
    r"\bUNION\b",
    r"\bSELECT\b.*\bFROM\b",
    r"\bDROP\b",
    r"\bINSERT\b",
    r"\bDELETE\b",
    r"\bUPDATE\b.*\bSET\b",
    r"\bEXEC\b|\bEXECUTE\b",
    r"xp_",
    r"SLEEP\s*\(",
    r"BENCHMARK\s*\(",
    r"'\s*OR\s*'",
    r"1\s*=\s*1",
    r"admin'--",
]

def detect_sqli(query):
    query_upper = query.upper()
    matches = []
    for pattern in SQL_PATTERNS:
        if re.search(pattern, query_upper, re.IGNORECASE):
            matches.append(pattern)
    score = len(matches)
    return score, matches

# ========== Load Model (Optional) ==========
try:
    import joblib
    model = joblib.load("model.pkl")
    model_loaded = True
except:
    model_loaded = False

# ========== Input ==========
query = st.text_area(
    "🔍 Enter SQL Query:",
    placeholder="e.g.  SELECT * FROM users WHERE id = 1",
    height=120
)

# ========== Examples ==========
st.markdown("**Quick Examples:**")
col1, col2, col3 = st.columns(3)

with col1:
    if st.button("✅ Safe Query"):
        query = "SELECT * FROM users WHERE id = 5"
        st.session_state["query"] = query

with col2:
    if st.button("🚨 UNION Attack"):
        query = "' UNION SELECT * FROM users--"
        st.session_state["query"] = query

with col3:
    if st.button("🚨 OR Attack"):
        query = "' OR '1'='1"
        st.session_state["query"] = query

st.divider()

# ========== Predict ==========
if st.button("🔍 Check Query", type="primary", use_container_width=True):
    if not query.strip():
        st.warning("⚠️ Please enter a query first.")
    else:
        score, matches = detect_sqli(query)

        if model_loaded:
            prediction = model.predict([query])[0]
            is_attack = bool(prediction)
        else:
            is_attack = score >= 2

        st.markdown("### Result:")

        if is_attack:
            st.markdown(f"""
            <div class='attack'>
                <h3>🚨 SQL INJECTION DETECTED!</h3>
                <p>This query contains <b>{score}</b> suspicious pattern(s).</p>
            </div>
            """, unsafe_allow_html=True)

            if matches:
                st.markdown("**Suspicious Patterns Found:**")
                for m in matches:
                    st.code(m)
        else:
            st.markdown("""
            <div class='safe'>
                <h3>✅ Query looks Safe</h3>
                <p>No SQL injection patterns detected.</p>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("---")
        st.markdown(f"**Query analyzed:** `{query}`")
        if not model_loaded:
            st.info("ℹ️ Running in rule-based mode. Load model.pkl for ML predictions.")

# ========== Footer ==========
st.divider()
st.markdown("🎓 Cybersecurity ML Project | SQL Injection Detection")