import streamlit as st
import joblib
from urllib.parse import urlparse
from predict_url import extract_features

# Load the trained phishing model
model = joblib.load("model/phishing_model.pkl")

# Page configuration
st.set_page_config(
    page_title="Phishing URL Detector",
    page_icon="🛡️",
    layout="wide"
)

# Title and subtitle
st.markdown(
    "<h1 style='text-align: center; color: #4CAF50;'>🛡️ Phishing URL Detector</h1>",
    unsafe_allow_html=True
)
st.markdown(
    "<p style='text-align: center;'>Check if a website is trustworthy or a potential threat!</p>",
    unsafe_allow_html=True
)

# Initialize session state
if "url_input" not in st.session_state:
    st.session_state.url_input = ""
if "prediction_result" not in st.session_state:
    st.session_state.prediction_result = None
if "predicted_url" not in st.session_state:
    st.session_state.predicted_url = None

# Input form
with st.form(key="url_form"):
    url = st.text_input(
        "🔗 Enter a URL to check",
        value=st.session_state.url_input,
        placeholder="e.g. https://login-secure-paypal.com",
        key="url_input_field"
    )
    submit = st.form_submit_button("🔍 Scan URL")

# Handle submission
# Handle submission
if submit and url:
    # Ensure scheme is present
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url  # Add http for parsing

    parsed = urlparse(url)

    # Invalid if no domain or no dot, or path is missing
    if (
        not parsed.netloc
        or '.' not in parsed.netloc
        or parsed.netloc == "localhost"
        or parsed.netloc.replace('.', '').isalpha() is False
        or parsed.path in ['', '/']
    ):
        st.error("❌ Please enter a full URL, including the path (e.g., https://example.com/path).")
    else:
        # Warn if HTTP
        if parsed.scheme == "http":
            st.warning("⚠️ This URL uses HTTP which is not secure. Prefer HTTPS whenever possible.")

        try:
            # Extract features and predict
            features = extract_features(url)
            prediction = model.predict(features)[0]

            # Update session state
            st.session_state.predicted_url = url
            st.session_state.prediction_result = prediction
            st.session_state.url_input = ""  # clear input
        except Exception as e:
            st.error(f"⚠️ Error while analyzing the URL: {e}")


# Show prediction result
if st.session_state.prediction_result is not None and st.session_state.predicted_url:
    url = st.session_state.predicted_url
    result = st.session_state.prediction_result

    st.markdown(f"<h4 style='text-align: center;'>🔍 URL Scanned: <code>{url}</code></h4>", unsafe_allow_html=True)

    if result == 1:
        # SAFE
        st.markdown("""
        <div style="
            background-color: #eaffea;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 4px 10px rgba(0,0,0,0.1);
            border-left: 6px solid #43a047;
            text-align: center;
        ">
        <h2 style='color: #2e7d32; font-size: 28px;'>🟢 Safe Website Detected</h2>
        <p style='color: #222222; font-size: 17px;'>
            This website does not show any signs of phishing or malicious behavior.
        </p>
        <p style='color: #222222; font-size: 16px; font-weight: 500;'>
            👍 You can proceed, but always double-check the domain for typos or lookalike tricks.
        </p>
        </div>
        """, unsafe_allow_html=True)
    else:
        # PHISHING
        st.markdown("""
        <div style="
            background-color: #ffeaea;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 4px 10px rgba(0,0,0,0.1);
            border-left: 6px solid #e53935;
            text-align: center;
        ">
        <h2 style='color: #d32f2f; font-size: 28px;'>🔴 Potential Phishing Threat!</h2>
        <p style='color: #333333; font-size: 17px;'>
            This website exhibits <strong>multiple indicators</strong> of phishing.
        </p>
        <p style='color: #333333; font-size: 16px; font-weight: 500;'>
            ⚠️ <strong>Warning:</strong> Do not enter passwords, download files, or share personal data on this site.
        </p>
        </div>
        """, unsafe_allow_html=True)

# Divider
st.markdown("---")
st.subheader("📘 How to Identify Phishing URLs")

# Tips in columns
col1, col2 = st.columns(2)

with col1:
    st.markdown("""
- 🔗 Suspicious subdomains (e.g. `login.verify-bank.com`)
- ❌ Fake HTTPS or no padlock
- 🧬 Misspelled domains (`gooogle.com`, `faceboook.net`)
- 🧲 Pop-ups or automatic redirects
- 📧 Asking for private info via email
    """)

with col2:
    st.markdown("""
- 🔢 Numeric IPs in URL (`http://192.168.1.1/login`)
- 🔍 Very new or unindexed domain
- ⚠️ Messages with threats or urgency
- 🔐 Login forms on unknown sites
- 🧾 No contact or privacy info
    """)

# Expandable safety tips
with st.expander("💡 Online Safety Tips"):
    st.markdown("""
- Always double-check URLs before logging in.
- Avoid clicking on unknown links from emails or SMS.
- Enable 2FA on important accounts.
- Use antivirus & browser protection.
- Report suspicious links to your provider.
    """)
