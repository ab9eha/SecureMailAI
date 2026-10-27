
import re
from datetime import datetime
from urllib.parse import urlparse

import pandas as pd
import streamlit as st


# --------------------------------------------------
# PAGE CONFIGURATION
# --------------------------------------------------

st.set_page_config(
    page_title="SecureMail AI | Phishing Detector",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# --------------------------------------------------
# CUSTOM STYLING
# --------------------------------------------------

st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');

    html, body, [class*="css"] {
        font-family: 'Inter', sans-serif;
    }

    .stApp {
        background: #0b1120;
        color: #e5e7eb;
    }

    [data-testid="stSidebar"] {
        background: #111827;
        border-right: 1px solid #263247;
    }

    .hero {
        padding: 28px 30px;
        border: 1px solid #29364d;
        border-radius: 18px;
        background: linear-gradient(125deg, #152238, #101827 70%);
        margin-bottom: 22px;
    }

    .hero h1 {
        font-size: 35px;
        font-weight: 800;
        color: #f8fafc;
        margin: 0;
    }

    .hero p {
        color: #a8b6cb;
        margin: 9px 0 0 0;
        font-size: 15px;
    }

    .eyebrow {
        color: #60a5fa;
        font-size: 11px;
        font-weight: 800;
        letter-spacing: 2px;
        text-transform: uppercase;
        margin-bottom: 10px;
    }

    .metric-card {
        background: #111c2e;
        border: 1px solid #29364d;
        border-radius: 14px;
        padding: 19px;
        min-height: 115px;
    }

    .metric-label {
        font-size: 12px;
        color: #9aabc2;
        margin-bottom: 10px;
    }

    .metric-value {
        font-size: 27px;
        font-weight: 800;
        color: #f8fafc;
    }

    .metric-note {
        font-size: 11px;
        color: #91a4bd;
        margin-top: 5px;
    }

    .section-heading {
        color: #f1f5f9;
        font-size: 19px;
        font-weight: 700;
        margin-top: 22px;
        margin-bottom: 12px;
    }

    .result-card {
        background: #111c2e;
        border: 1px solid #29364d;
        border-radius: 15px;
        padding: 22px;
        margin-top: 12px;
        margin-bottom: 14px;
    }

    .risk-pill {
        display: inline-block;
        border-radius: 30px;
        padding: 6px 13px;
        font-size: 12px;
        font-weight: 800;
        letter-spacing: 0.6px;
    }

    .risk-low {
        background: #12372e;
        color: #6ee7b7;
    }

    .risk-medium {
        background: #423416;
        color: #fcd34d;
    }

    .risk-high {
        background: #48271b;
        color: #fdba74;
    }

    .risk-critical {
        background: #4c1d2b;
        color: #fda4af;
    }

    .muted {
        color: #9aabc2;
        font-size: 13px;
    }

    .info-panel {
        padding: 16px 18px;
        background: #111c2e;
        border: 1px solid #29364d;
        border-radius: 12px;
        margin: 10px 0;
    }

    .footer {
        text-align: center;
        color: #7f91aa;
        border-top: 1px solid #263247;
        padding-top: 20px;
        margin-top: 42px;
        font-size: 12px;
    }

    .footer strong {
        color: #cbd5e1;
    }

    div[data-testid="stMetric"] {
        background: #111c2e;
        border: 1px solid #29364d;
        padding: 14px;
        border-radius: 12px;
    }

    .stButton > button {
        border-radius: 9px;
        font-weight: 700;
        min-height: 43px;
    }

    </style>
    """,
    unsafe_allow_html=True,
)


# --------------------------------------------------
# PHISHING DETECTION ENGINE
# --------------------------------------------------

RULES = [
    {
        "name": "Urgent or threatening language",
        "description": "Pressure to act immediately or face consequences.",
        "pattern": (
            r"\b(urgent|immediately|act now|final warning|"
            r"account suspended|account will be closed|"
            r"within 24 hours|limited time|expire today|"
            r"verify now|action required)\b"
        ),
        "points": 15,
    },
    {
        "name": "Credential request",
        "description": "A request for passwords, login details, or verification codes.",
        "pattern": (
            r"\b(password|passcode|login credentials|"
            r"one[- ]time password|otp|verification code|"
            r"security code|sign in to verify)\b"
        ),
        "points": 25,
    },
    {
        "name": "Sensitive information request",
        "description": "A request for confidential personal or identity information.",
        "pattern": (
            r"\b(social security number|national id|"
            r"identity number|date of birth|personal information|"
            r"identity documents|bank details)\b"
        ),
        "points": 15,
    },
    {
        "name": "Financial pressure",
        "description": "Payment, transfer, refund, or financial urgency.",
        "pattern": (
            r"\b(wire transfer|gift card|payment required|"
            r"outstanding invoice|claim your refund|"
            r"confirm your payment|send money|bank account|"
            r"crypto wallet|cryptocurrency)\b"
        ),
        "points": 15,
    },
    {
        "name": "Suspicious attachment language",
        "description": "An attachment may be used to deliver harmful content.",
        "pattern": (
            r"\b(open the attachment|enable macros|"
            r"download the attached file|attached invoice|"
            r"attached document|run this file)\b"
        ),
        "points": 10,
    },
    {
        "name": "Impersonation indicators",
        "description": "Language commonly used to imitate a trusted organisation.",
        "pattern": (
            r"\b(IT support|help desk|security team|"
            r"CEO request|payroll department|"
            r"Microsoft support|bank security team)\b"
        ),
        "points": 8,
    },
]


def extract_urls(text):
    """Extract HTTP, HTTPS, and www-style links."""
    pattern = r"""(?i)\b(?:https?://|www\.)[^\s<>"']+"""
    matches = re.findall(pattern, text)

    cleaned = []
    for url in matches:
        url = url.rstrip(".,;:!?)\"]}")
        if url and url not in cleaned:
            cleaned.append(url)

    return cleaned


def inspect_url(url):
    """Apply simple, offline URL warning heuristics."""
    findings = []
    normalised = url if url.startswith(("http://", "https://")) else "https://" + url

    try:
        parsed = urlparse(normalised)
        host = (parsed.hostname or "").lower()

        if not host:
            return ["Could not parse the hostname."]

        if parsed.scheme == "http":
            findings.append("Uses unencrypted HTTP.")

        if parsed.username or parsed.password:
            findings.append("Contains user information in the URL.")

        if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", host):
            findings.append("Uses an IP address instead of a regular domain name.")

        if host.startswith("xn--") or ".xn--" in host:
            findings.append("Contains an internationalised domain label that warrants review.")

        if host.count(".") >= 4:
            findings.append("Has an unusually deep subdomain structure.")

        if len(url) > 100:
            findings.append("Unusually long URL.")

        suspicious_words = (
            "login", "verify", "secure", "update",
            "account", "password", "wallet", "confirm"
        )

        if any(word in url.lower() for word in suspicious_words):
            findings.append("Contains a login, verification, or account-related keyword.")

        shorteners = {
            "bit.ly", "tinyurl.com", "t.co", "is.gd",
            "cutt.ly", "rb.gy", "shorturl.at"
        }

        if host in shorteners:
            findings.append("Uses a URL-shortening service, which hides the final destination.")

    except ValueError:
        findings.append("URL format could not be reliably interpreted.")

    return findings


def analyze_email(sender, subject, body):
    """Return a transparent rule-based assessment."""
    full_text = "\n".join([sender, subject, body]).strip()
    lower_text = full_text.lower()

    findings = []
    score = 0

    for rule in RULES:
        if re.search(rule["pattern"], lower_text, flags=re.IGNORECASE):
            findings.append({
                "Indicator": rule["name"],
                "Details": rule["description"],
                "Points": rule["points"],
            })
            score += rule["points"]

    urls = extract_urls(full_text)

    for url in urls:
        url_findings = inspect_url(url)

        for finding in url_findings:
            findings.append({
                "Indicator": "URL warning",
                "Details": f"{url} — {finding}",
                "Points": 10,
            })
            score += 10

    if re.search(r"\b(dear customer|dear user|valued customer)\b", lower_text):
        findings.append({
            "Indicator": "Generic greeting",
            "Details": "A generic greeting may be worth checking in context.",
            "Points": 5,
        })
        score += 5

    if sender:
        email_match = re.search(
            r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}",
            sender
        )

        if not email_match:
            findings.append({
                "Indicator": "Unverified sender format",
                "Details": "The sender field does not contain a recognisable email address.",
                "Points": 5,
            })
            score += 5

    # Cap score so multiple matching rules cannot exceed 100.
    score = min(score, 100)

    if score >= 70:
        level = "Critical"
        recommendation = "Do not interact with links or attachments. Verify through an independent, trusted channel."
        risk_class = "risk-critical"
    elif score >= 45:
        level = "High"
        recommendation = "Treat this message as suspicious. Verify the sender independently before taking action."
        risk_class = "risk-high"
    elif score >= 20:
        level = "Medium"
        recommendation = "Review the sender and any links carefully. Do not provide sensitive information without verification."
        risk_class = "risk-medium"
    else:
        level = "Low"
        recommendation = "Few configured warning indicators were detected. This does not prove the email is safe."
        risk_class = "risk-low"

    return {
        "score": score,
        "level": level,
        "recommendation": recommendation,
        "risk_class": risk_class,
        "findings": findings,
        "urls": urls,
    }


# --------------------------------------------------
# SIDEBAR
# --------------------------------------------------

with st.sidebar:
    st.markdown("## 🛡️ SecureMail AI")
    st.caption("Email threat triage")
    st.divider()

    page = st.radio(
        "NAVIGATION",
        ["Email Analyzer", "How It Works", "About"],
        label_visibility="visible",
    )

    st.divider()

    st.markdown("**ANALYSIS ENGINE**")
    st.caption("Offline rule-based detection")
    st.caption("No email is sent to an external analysis service by this app.")

    st.divider()

    st.markdown("**DEVELOPER**")
    st.write("Abeeha Zeeshan")
    st.caption("AI & Cybersecurity Portfolio Project")


# --------------------------------------------------
# PAGE: EMAIL ANALYZER
# --------------------------------------------------

if page == "Email Analyzer":

    st.markdown(
        """
        <div class="hero">
            <div class="eyebrow">AI & CYBERSECURITY LAB</div>
            <h1>SecureMail AI</h1>
            <p>Analyse suspicious emails, inspect warning indicators, and assess phishing risk.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    col1, col2, col3 = st.columns(3)

    with col1:
        st.markdown(
            """
            <div class="metric-card">
                <div class="metric-label">DETECTION APPROACH</div>
                <div class="metric-value">Rule-based</div>
                <div class="metric-note">Transparent heuristic checks</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col2:
        st.markdown(
            """
            <div class="metric-card">
                <div class="metric-label">INPUT</div>
                <div class="metric-value">Email text</div>
                <div class="metric-note">Sender, subject and message body</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col3:
        st.markdown(
            """
            <div class="metric-card">
                <div class="metric-label">OUTPUT</div>
                <div class="metric-value">Risk report</div>
                <div class="metric-note">Score, indicators and recommendations</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown('<div class="section-heading">Email inspection</div>', unsafe_allow_html=True)
    st.caption("Paste a message below. You can also load an example to test the detector.")

    examples = {
        "Choose an example": {
            "sender": "",
            "subject": "",
            "body": "",
        },
        "Suspicious account warning": {
            "sender": "security-alert@example.test",
            "subject": "URGENT: Account suspended",
            "body": (
                "Dear customer, your account will be closed within 24 hours. "
                "Verify now and enter your password and verification code at "
                "http://192.0.2.10/login to restore access."
            ),
        },
        "Possible payment scam": {
            "sender": "billing@example.test",
            "subject": "Outstanding invoice - payment required",
            "body": (
                "Action required immediately. Confirm your payment and send "
                "the wire transfer today. Open the attachment for the invoice."
            ),
        },
        "Ordinary message": {
            "sender": "colleague@example.com",
            "subject": "Meeting notes",
            "body": (
                "Hello, here are the notes from our meeting. "
                "Please let me know if you would like any changes. "
                "Thank you."
            ),
        },
    }

    example_choice = st.selectbox(
        "Load a sample email",
        list(examples.keys()),
    )

    selected_example = examples[example_choice]

    # Only update values when a sample is explicitly selected.
    if "previous_example" not in st.session_state:
        st.session_state.previous_example = "Choose an example"

    if example_choice != st.session_state.previous_example:
        st.session_state.email_sender = selected_example["sender"]
        st.session_state.email_subject = selected_example["subject"]
        st.session_state.email_body = selected_example["body"]
        st.session_state.previous_example = example_choice

    with st.form("email_analysis_form"):
        sender = st.text_input(
            "Sender email address",
            key="email_sender",
            placeholder="sender@example.com",
        )

        subject = st.text_input(
            "Email subject",
            key="email_subject",
            placeholder="Enter the email subject",
        )

        body = st.text_area(
            "Email body",
            key="email_body",
            placeholder="Paste the email content here...",
            height=220,
        )

        submitted = st.form_submit_button(
            "Analyse email",
            type="primary",
            use_container_width=True,
        )

    if submitted:
        if not sender.strip() and not subject.strip() and not body.strip():
            st.warning("Enter an email sender, subject, or message body first.")
        else:
            result = analyze_email(sender, subject, body)
            st.session_state.analysis_result = result
            st.session_state.analysis_input = {
                "sender": sender,
                "subject": subject,
                "body": body,
            }
            st.session_state.analysis_time = datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )

    if "analysis_result" in st.session_state:
        result = st.session_state.analysis_result
        input_data = st.session_state.analysis_input

        st.divider()
        st.markdown(
            '<div class="section-heading">Analysis results</div>',
            unsafe_allow_html=True,
        )

        score_col, level_col = st.columns([1, 2])

        with score_col:
            st.metric("Risk score", f"{result['score']}/100")
            st.progress(result["score"] / 100)

        with level_col:
            st.markdown(
                f"""
                <div class="result-card">
                    <span class="risk-pill {result['risk_class']}">
                        {result['level'].upper()} RISK
                    </span>
                    <p style="color:#e5e7eb; margin-top:14px;">
                        {result['recommendation']}
                    </p>
                </div>
                """,
                unsafe_allow_html=True,
            )

        st.markdown(
            '<div class="section-heading">Detected indicators</div>',
            unsafe_allow_html=True,
        )

        if result["findings"]:
            findings_df = pd.DataFrame(result["findings"])
            st.dataframe(
                findings_df,
                use_container_width=True,
                hide_index=True,
            )
        else:
            st.success(
                "No configured warning indicators were detected. "
                "This is not proof that the email is legitimate."
            )

        st.markdown(
            '<div class="section-heading">Extracted links</div>',
            unsafe_allow_html=True,
        )

        if result["urls"]:
            for index, url in enumerate(result["urls"], start=1):
                st.code(f"{index}. {url}", language=None)
        else:
            st.info("No URLs were found in the provided text.")

        # Build a downloadable report from the current analysis.
        report = {
            "analysis_time": st.session_state.analysis_time,
            "sender": input_data["sender"],
            "subject": input_data["subject"],
            "risk_score": result["score"],
            "risk_level": result["level"],
            "recommendation": result["recommendation"],
            "urls_found": "; ".join(result["urls"]),
            "indicators": "; ".join(
                item["Indicator"] for item in result["findings"]
            ),
        }

        report_df = pd.DataFrame([report])

        st.markdown(
            '<div class="section-heading">Export report</div>',
            unsafe_allow_html=True,
        )

        download_col1, download_col2 = st.columns(2)

        with download_col1:
            st.download_button(
                "Download CSV report",
                data=report_df.to_csv(index=False).encode("utf-8"),
                file_name="securemail_analysis.csv",
                mime="text/csv",
                use_container_width=True,
            )

        with download_col2:
            report_text = (
                "SECUREMAIL AI — EMAIL ANALYSIS REPORT\n"
                "======================================\n"
                f"Analysis time: {report['analysis_time']}\n"
                f"Sender: {report['sender']}\n"
                f"Subject: {report['subject']}\n"
                f"Risk score: {report['risk_score']}/100\n"
                f"Risk level: {report['risk_level']}\n\n"
                f"Recommendation:\n{report['recommendation']}\n\n"
                f"Indicators:\n{report['indicators'] or 'None detected'}\n\n"
                f"Extracted URLs:\n{report['urls_found'] or 'None found'}\n\n"
                "Note: This report is based on offline rule-based heuristics.\n"
                "It is not a guarantee of email safety or maliciousness.\n"
            )

            st.download_button(
                "Download TXT report",
                data=report_text,
                file_name="securemail_analysis.txt",
                mime="text/plain",
                use_container_width=True,
            )

    st.markdown(
        """
        <div class="info-panel">
            <strong>Important limitation</strong>
            <p class="muted">
                This educational prototype uses manually defined rules rather than
                a trained machine-learning model. It does not visit links, scan
                attachments, verify sender identity, or check live threat
                intelligence. Risk scores are heuristic indicators, not calibrated
                probabilities. Never use the result alone to decide whether an
                email is safe.
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )


# --------------------------------------------------
# PAGE: HOW IT WORKS
# --------------------------------------------------

elif page == "How It Works":

    st.markdown(
        """
        <div class="hero">
            <div class="eyebrow">METHODOLOGY</div>
            <h1>How SecureMail AI Works</h1>
            <p>A transparent, educational approach to identifying common phishing signals.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    steps = [
        (
            "01 — Input",
            "The user provides an email sender, subject and body.",
        ),
        (
            "02 — Text inspection",
            "The engine searches for configured patterns associated with urgency, credential requests, financial pressure, and other warning signs.",
        ),
        (
            "03 — URL inspection",
            "Links are extracted and checked for selected structural indicators. The tool does not open links or establish whether a website is malicious.",
        ),
        (
            "04 — Risk scoring",
            "Matched indicators contribute points to a heuristic score capped at 100. The score is not a probability.",
        ),
        (
            "05 — Reporting",
            "The app displays findings, a risk category, practical precautions and downloadable reports.",
        ),
    ]

    for title, description in steps:
        st.markdown(
            f"""
            <div class="info-panel">
                <strong>{title}</strong>
                <p class="muted">{description}</p>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.subheader("Risk categories")

    risk_df = pd.DataFrame(
        [
            {"Score": "0–19", "Category": "Low", "Meaning": "Few configured indicators matched."},
            {"Score": "20–44", "Category": "Medium", "Meaning": "Review the message carefully."},
            {"Score": "45–69", "Category": "High", "Meaning": "Several warning indicators matched."},
            {"Score": "70–100", "Category": "Critical", "Meaning": "Multiple or high-impact indicators matched."},
        ]
    )

    st.dataframe(risk_df, use_container_width=True, hide_index=True)

    st.warning(
        "These thresholds are illustrative and have not been validated against "
        "a labelled email dataset. They should not be interpreted as measured "
        "detection accuracy."
    )


# --------------------------------------------------
# PAGE: ABOUT
# --------------------------------------------------

elif page == "About":

    st.markdown(
        """
        <div class="hero">
            <div class="eyebrow">PROJECT PROFILE</div>
            <h1>About SecureMail AI</h1>
            <p>An educational email security project focused on phishing awareness and explainable detection rules.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.subheader("Project overview")

    st.write(
        "SecureMail AI is a cybersecurity portfolio project designed to help "
        "users review suspicious email text and recognise common phishing signals. "
        "It combines rule-based text inspection, simple URL heuristics, transparent "
        "risk scoring and report export in a Streamlit interface."
    )

    st.subheader("Technologies")

    tech_col1, tech_col2, tech_col3 = st.columns(3)

    with tech_col1:
        st.markdown("**Python**")
        st.caption("Detection logic and text processing")

    with tech_col2:
        st.markdown("**Pandas**")
        st.caption("Structured findings and report export")

    with tech_col3:
        st.markdown("**Streamlit**")
        st.caption("Interactive web dashboard")

    st.subheader("Developer")

    st.markdown(
        """
        <div class="result-card">
            <div class="eyebrow">CREATED BY</div>
            <h2 style="margin:0; color:#f8fafc;">Abeeha Zeeshan</h2>
            <p style="color:#a8b6cb;">
                Student developer exploring artificial intelligence,
                cybersecurity, and practical security tools.
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.subheader("Scope and responsible use")

    st.write(
        "This project is for learning, demonstration and security awareness. "
        "It is not a replacement for a professional email security gateway, "
        "trained phishing classifier, incident response process, or security "
        "team. The current implementation does not validate sender authenticity "
        "or query external reputation services."
    )


# --------------------------------------------------
# FOOTER
# --------------------------------------------------

st.markdown(
    """
    <div class="footer">
        <strong>SecureMail AI</strong> · Email Phishing Detection Prototype
        <br>
        Developed by Abeeha Zeeshan
        <br>
        Educational use only · Rule-based results are not a guarantee of safety
    </div>
    """,
    unsafe_allow_html=True,
)
