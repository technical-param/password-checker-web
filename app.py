#!/usr/bin/env python3
from flask import Flask, render_template, request
import math, re, hashlib, difflib, requests

app = Flask(__name__)

# --- small built-in lists ---
BUILTIN_COMMON = {
    "123456", "password", "12345678", "qwerty", "abc123", "monkey", "letmein",
    "dragon", "111111", "baseball", "iloveyou", "trustno1", "1234567", "sunshine",
    "princess", "admin", "welcome", "football", "qazwsx", "password1"
}
BUILTIN_DICT = {"password", "admin", "user", "login", "welcome", "love", "secret",
                "master", "hello", "service", "system", "pass", "qwerty"}

LEET_MAP = str.maketrans("430157@$!", "aeloistas")
KEYBOARD_PATTERNS = ["qwerty", "asdfgh", "zxcvbn", "1qaz2wsx", "qazwsx", "password"]

# ---------- Password strength logic ----------
def estimate_charset_size(pw: str) -> int:
    has_lower = any(c.islower() for c in pw)
    has_upper = any(c.isupper() for c in pw)
    has_digit = any(c.isdigit() for c in pw)
    has_symbol = any((not c.isalnum()) for c in pw)
    size = 0
    if has_lower: size += 26
    if has_upper: size += 26
    if has_digit: size += 10
    if has_symbol: size += 32
    if any(ord(c) > 127 for c in pw): size += 500
    return max(size, 1)

def entropy_bits(pw: str) -> float:
    return len(pw) * math.log2(estimate_charset_size(pw))

def contains_dictionary_word_fuzzy(pw: str, dictionary:set, threshold:float = 0.78):
    low = pw.lower()
    for w in dictionary:
        if w in low:
            return True, w, 1.0
    leet_rev = low.translate(LEET_MAP)
    for w in dictionary:
        if w in leet_rev:
            return True, w, 0.95
    for w in dictionary:
        ratio = difflib.SequenceMatcher(None, low, w).ratio()
        if ratio >= threshold:
            return True, w, ratio
    return False, "", 0.0

def detect_repeat_patterns(pw: str):
    if re.search(r'(.)\1{3,}', pw):
        return True, "repeated characters"
    return False, ""

def detect_repeated_numbers(pw: str) -> bool:
    return re.search(r'(\d)\1{2,}', pw) is not None

def detect_numeric_sequence(pw: str) -> bool:
    return bool(re.search(r"(0123|1234|2345|3456|4567|5678|6789|9876|8765|7654)", pw))

def detect_keyboard_pattern(pw: str) -> bool:
    low = pw.lower()
    return any(pat in low for pat in KEYBOARD_PATTERNS)

def score_password_raw(pw: str):
    if not pw: return 0, ["empty password"], 0.0
    reasons = []
    ent = entropy_bits(pw)
    base_score = min(ent/4*10, 60)
    cats = sum([any(c.islower() for c in pw),
                any(c.isupper() for c in pw),
                any(c.isdigit() for c in pw),
                any((not c.isalnum()) for c in pw)])
    length_bonus = 12 if len(pw)>=16 else 8 if len(pw)>=12 else 4 if len(pw)>=8 else 0
    penalties = 0

    if not any(c.islower() for c in pw): penalties+=10; reasons.append("missing lowercase")
    if not any(c.isupper() for c in pw): penalties+=10; reasons.append("missing uppercase")
    if not any(c.isdigit() for c in pw): penalties+=10; reasons.append("missing digit")
    if not any((not c.isalnum()) for c in pw): penalties+=10; reasons.append("missing special")

    if pw.lower() in BUILTIN_COMMON: penalties+=70; reasons.append("common password")
    dict_found, w, _ = contains_dictionary_word_fuzzy(pw, BUILTIN_DICT)
    if dict_found: penalties+=25; reasons.append(f"dictionary word '{w}'")
    if detect_repeat_patterns(pw)[0]: penalties+=20; reasons.append("repeated pattern")
    if detect_repeated_numbers(pw): penalties+=15; reasons.append("repeated numbers")
    if detect_numeric_sequence(pw): penalties+=15; reasons.append("numeric sequence")
    if detect_keyboard_pattern(pw): penalties+=18; reasons.append("keyboard pattern")
    if len(pw)<6: penalties+=30; reasons.append("too short")

    raw = base_score + (cats*5) + length_bonus - penalties
    return max(0,min(100,int(raw))), reasons, ent

def map_to_10(raw: int):
    val = max(0, min(10, int(round(raw/10.0))))
    label = ["Very Weak","Weak","Weak","Fair","Fair","Good","Good","Strong","Strong","Excellent","Excellent"][val]
    return val,label

def check_pwned(password: str) -> int:
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    resp = requests.get(url, timeout=8)
    for line in resp.text.splitlines():
        h,c = line.split(":")
        if h==suffix: return int(c)
    return 0

def tips(pw,reasons,raw,breach):
    t=[]
    if len(pw)<12: t.append("Use at least 12 characters.")
    if breach and breach>0: t.append(f"⚠ Found in {breach} breaches. Never reuse it.")
    if "missing uppercase" in reasons or "missing lowercase" in reasons:
        t.append("Mix uppercase and lowercase letters.")
    if "missing digit" in reasons: t.append("Add numbers.")
    if "missing special" in reasons: t.append("Add special characters (!,@,#,$, etc.)")
    if raw<50: t.append("Consider a passphrase or password manager.")
    t.append("Enable MFA for important accounts.")
    return t

# ---------- Routes ----------
@app.route('/', methods=['GET','POST'])
def index():
    result=None
    if request.method=='POST':
        pw=request.form.get('password','')
        raw,reasons,ent=score_password_raw(pw)
        breach=None
        try:
            breach=check_pwned(pw)
            if breach>0: raw=0; reasons.append("found in breaches")
        except: reasons.append("leak-check failed")
        score10,label=map_to_10(raw)
        result={"pw":pw,"score":score10,"label":label,"reasons":reasons,
                "entropy":round(ent,1),"breach":breach,"tips":tips(pw,reasons,raw,breach)}
    return render_template('index.html',result=result)

if __name__=="__main__":
    app.run(debug=True,host="0.0.0.0",port=5000)
