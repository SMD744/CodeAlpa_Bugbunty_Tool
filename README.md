

# CodeAlpa\_Bugbunty\_Tool

Automated bug bounty scanner for web apps. Scans for XSS, SQLi, logic flaws, misconfigurations, and more.

# 🛡️ Bug Bounty Automation Tool

A powerful, easy-to-use Python-based **bug bounty scanner** designed to help identify common web vulnerabilities, security misconfigurations, and **logic flaws**.

Developed during my **CodeAlpha Internship**, this tool provides both **TXT** and **HTML** reporting, making it ideal for pentesters, bug bounty hunters, and developers.

---

⚠️ Caution & Ethics
Please use this tool responsibly and only on websites you own or have permission to test.
This tool was made for:
Learning
Ethical hacking
Bug bounty programs with consent

❗ Do NOT:
Use it on websites without permission
Attempt to exploit real vulnerabilities
Run it against live production systems without authorization
Unauthorized use is illegal and unethical.

👨‍💻 Who Is This Tool For?

* Bug bounty hunters (legal hackers who report bugs for rewards)
* Cybersecurity students
* Ethical hackers
* Developers doing security testing on their own sites

🌐 Test Websites for Bug Bounty / Ethical Hacking
http://testphp.vulnweb.com
http://bwapp.hackme.cloud
http://xvwa.hackme.cloud
https://google-gruyere.appspot.co
https://juice-shop.herokuapp.com
https://demo.testfire.net
https://hackyourselffirst.troyhunt.com
https://vapi.ov
https://xss-game.appspot.com

---

## 🚀 Features

* ✅ Detects common vulnerabilities:

  * **SQL Injection**
  * **Cross-Site Scripting (XSS)**
  * **Open Redirects**
  * **CORS Misconfigurations**

* 🔐 Checks for security misconfigurations:

  * Missing **security headers**
  * Sensitive or **exposed admin panels**
  * SSL **certificate info** and expiry

* 📄 Generates detailed reports in `.txt` or `.html` format

---

### 🧠 How It Works

When you run the tool, it performs a series of automated tests to check the security of a website. Here’s what each step does and why it’s important:

1. **Host Availability Check**
   The tool first tries to connect to the website to see if it’s online and reachable. If the site is down or the address is incorrect, the scan stops here since no further checks can be done.

2. **Header Security Analysis**
   Websites send security headers as part of their HTTP response. These headers help protect users against attacks like clickjacking or content injection. The tool checks if important headers like `Content-Security-Policy` or `Strict-Transport-Security` are missing, which might indicate weaker security.

3. **Detection of Sensitive/Admin Paths**
   Many websites have special URLs for logging in or administration (like `/admin`, `/login`). These paths can sometimes be exposed accidentally. The tool scans common sensitive paths to see if they exist and are accessible, which might allow unauthorized access.

4. **Scanning for Vulnerabilities:**
   The tool tries to find common security flaws by sending specific test requests:

   * **SQL Injection (SQLi):** Attempts to manipulate database queries by injecting special characters or commands through URL parameters.
   * **Cross-Site Scripting (XSS):** Checks if the website improperly displays user input that could allow attackers to run malicious scripts.
   * **Open Redirects:** Tests if the site redirects users to untrusted external websites, which attackers can exploit in phishing attacks.

5. **CORS Configuration Validation**
   CORS (Cross-Origin Resource Sharing) controls how resources on a website can be requested from other domains. The tool checks if the site’s CORS settings are too open, which can lead to unauthorized data access from malicious sites.

6. **SSL Certificate Info (for HTTPS Sites)**
   If the website uses HTTPS, the tool retrieves details about its SSL certificate, like who issued it and when it expires. This helps verify if the site’s encrypted connection is properly configured and trustworthy.

7. **Report Generation (TXT / HTML)**
   After all tests complete, the tool compiles the findings into a detailed report. You can choose between a simple text file or a formatted HTML report that’s easier to read and share.

---

### 📦 Requirements

* Python 3.x
* `requests` package (`pip install requests`)

---

### 🐍 Setup with a Python Virtual Environment (Recommended)

Using a virtual environment helps keep your project dependencies isolated and avoids conflicts with other Python projects on your system.

#### 1. Create a virtual environment

```bash
python3 -m venv venv  # create virtual environment named 'venv'
source venv/bin/activate  # activate the virtual environment
pip install requests  # install required package
```

#### 2. Run the bug bounty tool

```bash
python Bugbunty.py testphp.vulnweb.com
```

Replace `testphp.vulnweb.com` with your target URL.

To generate an HTML report instead of plain text:

```bash
python Bugbunty.py testphp.vulnweb.com --report html
```

---

### 📁 Example Output

The tool generates a file like:
`bugbounty_report_testphp.vulnweb.com_20250808_153045.html`

Which includes:

* Missing security headers
* Exposed admin/login pages
* Potential vulnerabilities with affected URLs
* SSL issuer & expiration

---

📌 Sample Scan Command

```bash
python Bugbunty.py testphp.vulnweb.com --report html
firefox bugbounty_report_testphp.vulnweb.com_20250808_153045.html  # Open report in Firefox
```

---

✅ Ideal For

* Bug bounty hunters
* Security researchers
* Ethical hackers
* Developers performing security testing
* Students learning offensive security

---

🙌 Acknowledgments

Built with ❤️ during the CodeAlpha Internship
Inspired by real-world bug bounty practices

---


IMPORTANT: This tool is intended only for ethical use — to test web applications you own or have explicit permission to assess.

Unauthorized use of this tool on websites or systems without proper authorization is illegal and unethical. The author does not take any responsibility for misuse, damage, or legal consequences arising from unauthorized scanning or exploitation attempts.

By using this tool, you agree to use it responsibly and in compliance with all applicable laws and policies.
