import streamlit as st
from analyzer import PasswordSecurityAssessment

st.set_page_config(
    page_title="Secure Password Analyzer",
    page_icon="🛡️",
    layout="centered"
)

st.title("🛡️ Secure Password Assessment System")
st.caption("Real-time security evaluation utilizing Shannon Entropy, Pattern Recognition, and k-Anonymity Breach Lookups.")

@st.cache_resource
def get_engine():
    return PasswordSecurityAssessment()

engine = get_engine()

st.sidebar.title("🔐 Security Architecture")
st.sidebar.markdown("""
**Privacy Controls:**
* **Zero Persistence:** Passwords exist purely in volatile RAM while analyzing. No inputs are stored or logged.
* **k-Anonymity (HIBP API):** Only the first 5 characters of the SHA-1 hash leave the local environment to check breach databases.
* **Masked Inputs:** Native browser masking prevents over-the-shoulder shoulder surfing.
""")
st.sidebar.divider()
st.sidebar.markdown("**Project Lead:** Dhanakodi")

password_input = st.text_input(
    label="Enter Password to Analyze:",
    type="password",
    placeholder="Type a password or passphrase...",
    help="Your input is processed strictly in-memory and will never be logged."
)

if password_input:
    results = engine.generate_assessment(password_input)
    score = results["score"]

    st.divider()

    st.subheader("1. Composite Security Score")
    
    if score >= 80:
        st.success(f"### Score: {score} / 100 (Strong)")
    elif score >= 50:
        st.warning(f"### Score: {score} / 100 (Moderate)")
    else:
        st.error(f"### Score: {score} / 100 (Weak / High Risk)")

    st.progress(score / 100)

    st.subheader("2. Quantitative Metrics")
    col1, col2, col3 = st.columns(3)
    
    col1.metric("Information Entropy", f"{results['entropy']['entropy_bits']} bits")
    col2.metric("Character Length", f"{results['entropy']['length']} chars")
    col3.metric("Offline Crack Time", results['crack_time'])

    st.subheader("3. Common Password & Breach Assessment")
    breach_info = results["breach_data"]
    
    if breach_info.get("is_breached"):
        st.error(f"⚠️ **Compromised Credential:** Found in known data breaches **{breach_info['breach_count']:,}** times!")
    else:
        st.success("✅ **No Known Breaches:** Not identified in the HaveIBeenPwned hash range lookup.")

    st.subheader("4. Weakness & Vulnerability Analysis")
    vulnerabilities = results["vulnerabilities"]
    
    if vulnerabilities:
        for vuln in vulnerabilities:
            st.error(f"❌ {vuln}")
    else:
        st.success("✅ No structural patterns or length deficiencies detected.")

    st.subheader("5. Recommendations & Improvement Plan")
    recommendations = results.get("recommendations", ["No specific recommendations generated."])
    for rec in recommendations:
        st.info(rec)

else:
    st.info("👆 Enter a password above to generate the full security evaluation.")