
# 🛡️ SecureMail AI

**An educational email phishing detection dashboard built with Python and Streamlit.**

[🚀 Live Demo](YOUR_STREAMLIT_APP_URL)

SecureMail AI analyses email text for common phishing indicators, including urgent language, credential requests, financial pressure, suspicious URL patterns, and attachment-related warnings.

## 🌐 Live Application

Try the application online:

**[Open SecureMail AI](YOUR_STREAMLIT_APP_URL)**

> Replace `YOUR_STREAMLIT_APP_URL` with your actual Streamlit Community Cloud URL after deployment.

## ✨ Features

- Interactive email analysis dashboard
- Sender, subject, and email body inspection
- Rule-based phishing risk scoring
- Low, Medium, High, and Critical risk categories
- URL extraction and basic URL warning checks
- Explanations of detected indicators
- Downloadable CSV and TXT reports
- Sample emails for testing
- Methodology and project information pages

## 🧰 Technologies

- Python
- Streamlit
- Pandas
- Regular expressions
- URL parsing

## ⚙️ Run Locally

1. Clone this repository:

   ```bash
   git clone https://github.com/YOUR-GITHUB-USERNAME/SecureMailAI.git
   ```

2. Open the project folder:

   ```bash
   cd SecureMailAI
   ```

3. Create a virtual environment:

   ```bash
   python -m venv .venv
   ```

4. Install dependencies on Windows:

   ```powershell
   .\.venv\Scripts\python.exe -m pip install -r requirements.txt
   ```

5. Run the application:

   ```powershell
   .\.venv\Scripts\python.exe -m streamlit run app.py
   ```

## 🔍 How It Works

1. **Input:** Enter the email sender, subject, and body.
2. **Inspection:** The application checks for predefined phishing-related patterns.
3. **URL analysis:** Links are extracted and checked for selected structural warning signs.
4. **Risk scoring:** Matched indicators contribute to a heuristic score capped at 100.
5. **Reporting:** Review the findings and download the analysis report.

## ⚠️ Limitations

SecureMail AI is an educational, rule-based prototype. It is not a trained machine-learning classifier or a production email security system.

- Risk scores are heuristic indicators, not probabilities.
- The app does not visit URLs or scan attachments.
- It does not verify sender authenticity or SPF/DKIM/DMARC.
- It does not query live threat-intelligence services.
- False positives and false negatives are possible.

**Never rely on this tool alone to decide whether an email is safe.**

## 👩‍💻 Developer

**Abeeha Zeeshan**

Created as an educational portfolio project exploring cybersecurity, phishing awareness, and practical security tools.

## 📄 License

For educational and portfolio use. Add an open-source license if you decide to distribute the project under specific reuse terms.
