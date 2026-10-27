
# SecureMail AI 🛡️

**An educational email phishing detection dashboard built with Python and Streamlit.**

SecureMail AI analyses email text for common phishing indicators, including urgent language, credential requests, financial pressure, suspicious URL patterns, and attachment-related warnings.

## Features

- Interactive email analysis dashboard
- Sender, subject, and body inspection
- Rule-based phishing risk scoring
- Low, Medium, High, and Critical risk categories
- URL extraction and basic structural warnings
- Explanations for detected indicators
- Downloadable CSV and TXT reports
- Sample emails for testing
- Methodology and limitations page

## Technologies

- Python
- Streamlit
- Pandas
- Regular expressions
- URL parsing

## Run locally

1. Clone or download this repository.
2. Open the project folder in VS Code.
3. Create a virtual environment:

   ```bash
   python -m venv .venv
   ```

4. Install the dependencies:

   ```bash
   .venv\Scripts\python.exe -m pip install -r requirements.txt
   ```

5. Start the application:

   ```bash
   .venv\Scripts\python.exe -m streamlit run app.py
   ```

## How it works

The application searches email text for predefined warning patterns, extracts links, applies simple URL heuristics, and calculates a capped heuristic score. It displays matched indicators and practical recommendations.

## Important limitations

This is an educational, rule-based prototype, not a trained machine-learning classifier or production email security product. The score is not a probability. The application does not open links, scan attachments, verify sender authenticity, inspect SPF/DKIM/DMARC, or query live threat intelligence. False positives and false negatives are possible.

Do not use the score alone to determine whether an email is safe.

## Developer

**Abeeha Zeeshan**

Created as an educational project exploring cybersecurity, phishing awareness, and interactive security tooling.

## License

This project is intended for educational and portfolio use. Add a suitable open-source license if you decide to distribute it publicly.
