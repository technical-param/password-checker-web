# Password Checker — Web

A web-based password strength and breach-checking tool.  
Created by **Param — Cyber Security Enthusiast**

---

## Features
- Strength scoring (0–10 scale) based on:
  - Uppercase, lowercase, numbers, special characters
  - Length, entropy
  - Avoiding repeated/sequence numbers and dictionary words
- Automatic [HaveIBeenPwned](https://haveibeenpwned.com/) leak database check
- Suggestions and tips displayed for each password
- Simple Flask web app with HTML/CSS

---

## Installation & Usage

```bash
# clone repo
git clone https://github.com/technical-param/password-checker-web.git
cd password-checker-web

# create virtual env (optional)
python3 -m venv venv
source venv/bin/activate

# install requirements
pip install -r requirements.txt

# run
python app.py
