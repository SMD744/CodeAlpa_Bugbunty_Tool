# CodeAlpa_Bugbunty_Tool
Automated bug bounty scanner for web apps. Scans for XSS, SQLi, logic flaws, misconfigurations, and more.

# 🛡️ Bug Bounty Automation Tool

A powerful, easy-to-use Python-based **bug bounty scanner** designed to help identify common web vulnerabilities, security misconfigurations, and **logic flaws**.

Developed during my **CodeAlpha Internship**, this tool provides both **TXT** and **HTML** reporting, making it ideal for pentesters, bug bounty hunters, and developers.

---

⚠️ Caution & Ethics
This tool is intended for ethical security testing only. Please:

Always obtain explicit permission before scanning any systems or websites.

Avoid any intrusive actions that may disrupt services.

Use responsibly and respect privacy and data laws.

Remember that unauthorized scanning or exploitation is illegal and unethical.

By using this tool, you agree to abide by all applicable laws and ethical guidelines.




## 🚀 Features

- ✅ Detects common vulnerabilities:
  - **SQL Injection**
  - **Cross-Site Scripting (XSS)**
  - **Open Redirects**
  - **CORS Misconfigurations**

- 🔐 Checks for security misconfigurations:
  - Missing **security headers**
  - Sensitive or **exposed admin panels**
  - SSL **certificate info** and expiry
- 📄 Generates detailed reports in `.txt` or `.html` format


---

## 🧠 How It Works

The tool performs a series of **automated scans** on a target URL, such as:

1. **Live check** (host availability)
2. **Header analysis** (for missing best-practice headers)
3. **Sensitive path detection** (`/admin`, `/login`, etc.)
4. **Security vulnerability testing**:
   - Injection attacks (SQLi)
   - XSS injection
   - Open redirect flaws
5. **SSL certificate parsing**
6. **Report generation** with detailed results

---

### 📦 Requirements
- Python 3.x
- `requests` package (`pip install requests`)

---

### 🐍 Setup with a Python Virtual Environment (Recommended)

Using a virtual environment helps keep your project dependencies isolated and avoids conflicts with other Python projects on your system.

#### 1. Create a virtual environment

```bash
python3 -m venv venv(name of your virtual environment)
cd venv
cd bin
source activate

install request
pip install requests

````Run the bug bounty tool````
python bugbunty.py testphp.vulnweb.com   


Deactivate the virtual environment when done
deactivate

📄 Run the tool:
python bugbunty.py testphp.vulnweb.com

Replace testphp.vulnweb.com with your target URL
Defualt is txt file butt you can choose to show result aat html by

python bugbunty.py testphp.vulnweb.com --report html


📁 Example Output
The tool generates a file like:
bugbounty_report_tstphp.vulnweb.com_20250808_153045.html

Which includes:

-Missing security headers

-Exposed admin/login pages

-Potential vulnerabilities with affected URLs

-SSL issuer & expiration

📌 Sample Scan Command
python bugbunty.py testphp.vulnweb.com --report html

run
firefox (the output generated)
this is will open fireforx and display the outcome

✅ Ideal For
-Bug bounty hunters

-Security researchers

-Ethical hackers

-Developers performing security testing

-Students learning offensive security

🙌 Acknowledgments
Built with ❤️ during the CodeAlpha Internship
Inspired by real-world bug bounty practices







⚠
