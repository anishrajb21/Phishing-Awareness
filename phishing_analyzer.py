"""
=============================================================================
 PHISHING AWARENESS ANALYSIS SYSTEM
 Industrial Training / Cybersecurity Internship - Project 3
=============================================================================

 What this program does
 ----------------------
 It reads a sample email or message, looks for the warning signs that
 phishing messages usually contain, adds up a risk score, and prints a
 report explaining every red flag it found and what the user should do.

 This is a DEFENSIVE, EDUCATIONAL tool. It only analyses text that is given
 to it. It does not send email, does not visit any website, does not check
 whether a link is genuinely malicious, and cannot be used to create a
 phishing message. Every example inside it is fictional.

 IMPORTANT
 ---------
 This is a rule-based awareness aid, not a security product. A LOW score
 does NOT prove a message is safe. When in doubt, verify with the sender
 through a channel you already trust, and report it to your IT team.

 Run it with:  python phishing_analyzer.py
=============================================================================
"""

import re
import sys


# ---------------------------------------------------------------------------
# SECTION 1: THE DETECTION RULES
#
# All the "knowledge" of the program lives here as dictionaries and lists,
# separate from the logic. To improve detection you edit this section only.
# ---------------------------------------------------------------------------

# Suspicious words and phrases, grouped by the trick they are trying to pull.
# Each group has a weight: how many risk points one match is worth.
KEYWORD_CATEGORIES = {
    "Urgency pressure": {
        "weight": 2,
        "maximum": 6,
        "critical": False,
        "explanation": ("Phishing works by rushing you. If you stop and think, "
                        "you notice the problem, so the message invents a deadline."),
        "terms": [
            "urgent", "urgently", "immediately", "act now", "right away",
            "within 24 hours", "within 48 hours", "expires today",
            "expire soon", "last warning", "final notice", "time sensitive",
            "click immediately", "respond immediately", "don't delay",
            "limited time", "hurry",
        ],
    },
    "Request for sensitive information": {
        "weight": 4,
        "maximum": 12,
        "critical": True,
        "explanation": ("Real banks, IT teams and service providers never ask "
                        "for passwords, OTPs or full card details by email or "
                        "message. Anyone who does is an attacker."),
        "terms": [
            "password", "your password", "otp", "one time password",
            "one-time password", "pin number", "cvv", "atm pin",
            "bank account", "account number", "credit card", "debit card",
            "card details", "net banking", "confirm your identity",
            "verify your identity", "aadhaar", "social security number",
            "login credentials", "update your payment", "billing information",
        ],
    },
    "Account threat": {
        "weight": 3,
        "maximum": 9,
        "critical": False,
        "explanation": ("Threatening to close, suspend or lock your account "
                        "creates fear, which pushes people into clicking "
                        "without checking."),
        "terms": [
            "account suspended", "account has been suspended",
            "account will be closed", "account locked", "account blocked",
            "suspend your account", "terminate your account",
            "unusual activity", "suspicious activity detected",
            "unauthorized login", "unauthorised login", "security alert",
            "your account has been compromised", "avoid deactivation",
            "permanently deleted", "legal action",
        ],
    },
    "Verification bait": {
        "weight": 3,
        "maximum": 9,
        "critical": False,
        "explanation": ("'Verify your account' is the single most common "
                        "phishing hook. The link leads to a fake login page "
                        "built to capture whatever you type."),
        "terms": [
            "verify your account", "verify your email", "verify now",
            "validate your account", "reactivate your account",
            "confirm your account", "update your account",
            "re-enter your details", "restore access", "unlock your account",
        ],
    },
    "Too-good-to-be-true offer": {
        "weight": 3,
        "maximum": 9,
        "critical": False,
        "explanation": ("Unexpected prizes, refunds and lottery wins are bait. "
                        "You cannot win a competition you never entered."),
        "terms": [
            "congratulations", "you have won", "you've won", "winner",
            "lottery", "prize", "claim your reward", "claim now",
            "free gift", "cash prize", "you are selected",
            "selected winner", "refund is pending", "tax refund",
            "inheritance", "unclaimed funds", "risk free", "100% free",
            "guaranteed income", "work from home earn",
        ],
    },
    "Secrecy or bypassing procedure": {
        "weight": 3,
        "maximum": 6,
        "critical": False,
        "explanation": ("Asking you to keep a request quiet or to skip normal "
                        "procedure is a hallmark of Business Email Compromise "
                        "fraud, where an attacker impersonates a manager."),
        "terms": [
            "keep this confidential", "do not tell", "don't tell anyone",
            "between us", "do not discuss", "without informing",
            "handle this personally", "do not contact",
        ],
    },
    "Unusual payment request": {
        "weight": 5,
        "maximum": 10,
        "critical": True,
        "explanation": ("Requests for gift cards, wire transfers or "
                        "cryptocurrency are almost always fraud. These payment "
                        "methods are chosen because they cannot be reversed or "
                        "traced once sent."),
        "terms": [
            "wire transfer", "gift card", "gift cards", "bitcoin",
            "cryptocurrency payment", "process this payment",
            "payment required", "outstanding invoice", "transfer funds",
            "change of bank details", "update the bank account",
        ],
    },
}

# Link-shortening services hide the true destination until you click.
URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc",
]

# Well-known brand names that attackers most often imitate.
# (Used only to spot imitation - none of these companies are involved here.)
COMMONLY_IMPERSONATED_BRANDS = [
    "paypal", "amazon", "netflix", "microsoft", "google", "apple",
    "facebook", "instagram", "whatsapp", "linkedin", "dhl", "fedex",
    "hdfc", "icici", "sbi", "axis", "paytm", "flipkart", "irctc",
]

# Free email providers. Legitimate for personal mail, but a warning sign
# when the message claims to come from a bank or a company IT department.
FREE_EMAIL_PROVIDERS = [
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
    "mail.com", "protonmail.com", "yandex.com", "rediffmail.com",
]

# Top-level domains that appear far more often in abuse reports than in
# legitimate corporate email.
SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".buzz", ".click",
    ".country", ".zip", ".review", ".work", ".loan", ".date", ".win",
]

# Path fragments that suggest a fake login or payment page.
SUSPICIOUS_URL_PATHS = [
    "login", "signin", "sign-in", "verify", "verification", "secure",
    "account", "update", "confirm", "webscr", "billing", "unlock",
    "password", "auth", "wallet",
]

# Common misspellings seen in phishing mail. Real corporate mail is proofread.
COMMON_MISSPELLINGS = [
    "acount", "accont", "verifiy", "verfiy", "recieve", "recieved",
    "seccurity", "securty", "urgnt", "informations", "kindly do the needful",
    "your's", "immediatly", "suspicius", "suspend ed", "dear costumer",
    "valued costumer", "pls", "plz", "thankyou",
]

# Greetings that show the sender does not actually know who you are.
GENERIC_GREETINGS = [
    "dear customer", "dear user", "dear valued customer", "dear account holder",
    "dear sir/madam", "dear sir or madam", "dear member", "dear client",
    "hello user", "attention customer", "dear email user",
]

# Risk score bands
SUSPICIOUS_THRESHOLD = 6      # score 6-19   -> SUSPICIOUS
PHISHING_THRESHOLD = 20       # score 20+ WITH a critical indicator
                              #              -> LIKELY PHISHING

LINE = "=" * 66


# ---------------------------------------------------------------------------
# SECTION 2: SMALL HELPER FUNCTIONS
# ---------------------------------------------------------------------------

def edit_distance(first_word, second_word):
    """
    Count how many single-character edits turn one word into another.

    'paypal' vs 'paypa1' is a distance of 1, so the second is very likely
    an imitation of the first. This is how the program spots lookalike
    domains such as 'arnazon' (r + n made to look like an m).
    """
    previous_row = list(range(len(second_word) + 1))

    for i in range(1, len(first_word) + 1):
        current_row = [i]
        for j in range(1, len(second_word) + 1):
            if first_word[i - 1] == second_word[j - 1]:
                cost = 0
            else:
                cost = 1
            current_row.append(min(previous_row[j] + 1,        # deletion
                                   current_row[j - 1] + 1,     # insertion
                                   previous_row[j - 1] + cost))  # substitution
        previous_row = current_row

    return previous_row[-1]


def get_domain(url):
    """
    Pull the domain out of a URL using basic string handling.
    'https://secure.example-bank.xyz/login?id=9' -> 'secure.example-bank.xyz'
    """
    working = url.lower()

    for prefix in ("https://", "http://", "ftp://"):
        if working.startswith(prefix):
            working = working[len(prefix):]

    # Anything after the @ sign is the real destination (see the @ check below)
    if "@" in working:
        working = working.split("@")[-1]

    # Cut off the path, query string and fragment
    for separator in ("/", "?", "#"):
        working = working.split(separator)[0]

    # Remove any port number, e.g. example.com:8080
    working = working.split(":")[0]

    if working.startswith("www."):
        working = working[4:]

    return working


def get_registered_domain(domain):
    """
    Return roughly the 'real' owner part of a domain.
    'login.secure.example.com' -> 'example.com'
    This is simplified; a production tool would use the Public Suffix List.
    """
    parts = domain.split(".")
    if len(parts) >= 2:
        return parts[-2] + "." + parts[-1]
    return domain


# ---------------------------------------------------------------------------
# SECTION 3: EXTRACTION AND ANALYSIS FUNCTIONS
# ---------------------------------------------------------------------------

def extract_urls(message_text):
    """
    Find every web address in the message using a regular expression.

    The pattern looks for http://, https:// or a bare www. address and
    grabs everything up to the next space or closing quote.
    """
    pattern = r"(?:https?://|www\.)[^\s\"'<>\)\]]+"
    found = re.findall(pattern, message_text, re.IGNORECASE)

    # Strip trailing punctuation that belongs to the sentence, not the URL
    cleaned = []
    for url in found:
        while len(url) > 0 and url[-1] in ".,;:!?":
            url = url[:-1]
        if url not in cleaned:
            cleaned.append(url)

    return cleaned


def check_keywords(message_text):
    """
    Look for suspicious words and phrases.

    Returns a list of dictionaries, one per category that matched, holding
    the category name, the exact terms found, the points scored and the
    explanation of why that category matters.

    Note the rule from the brief: a single keyword is NOT enough to call
    something phishing. This function only reports what it finds - the
    scoring function decides how much it counts for.
    """
    lowered = message_text.lower()
    findings = []

    for category_name, category in KEYWORD_CATEGORIES.items():
        matched_terms = []
        for term in category["terms"]:
            if term in lowered:
                matched_terms.append(term)

        if len(matched_terms) > 0:
            points = len(matched_terms) * category["weight"]
            if points > category["maximum"]:
                points = category["maximum"]

            findings.append({
                "category": category_name,
                "terms": matched_terms,
                "points": points,
                "critical": category["critical"],
                "explanation": category["explanation"],
            })

    return findings


def analyze_urls(urls):
    """
    Inspect each URL for structural warning signs.

    IMPORTANT: every check here is an INDICATOR, not proof. A shortened link
    is not automatically malicious - plenty of legitimate newsletters use
    them. Equally, a perfectly normal-looking URL can still be dangerous.
    Structure analysis narrows down what deserves a closer look; it never
    settles the question.
    """
    results = []

    for url in urls:
        domain = get_domain(url)
        registered = get_registered_domain(domain)
        flags = []
        points = 0
        critical = False

        # --- 1. An IP address instead of a domain name -------------------
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain):
            flags.append("Uses a raw IP address instead of a domain name - "
                         "legitimate companies use named domains.")
            points = points + 5
            critical = True

        # --- 2. The @ trick ----------------------------------------------
        # Everything before an @ in a URL is ignored by the browser, so
        # http://paypal.com@evil.example/ actually goes to evil.example.
        if "@" in url.split("//")[-1].split("/")[0]:
            flags.append("Contains an '@' symbol in the address - the browser "
                         "ignores everything before it and goes to the domain "
                         "written AFTER it.")
            points = points + 5
            critical = True

        # --- 3. URL shortener --------------------------------------------
        for shortener in URL_SHORTENERS:
            if domain == shortener or domain.endswith("." + shortener):
                flags.append("Shortened link (" + shortener + ") - the real "
                             "destination is hidden until you click.")
                points = points + 3
                break

        # --- 4. Brand name in the wrong place ----------------------------
        # A real PayPal link has paypal.com as the registered domain. A fake
        # one puts the brand in a subdomain or path: paypal.secure-login.xyz
        for brand in COMMONLY_IMPERSONATED_BRANDS:
            if brand in domain and not registered.startswith(brand + "."):
                flags.append("The brand name '" + brand + "' appears in the "
                             "address, but the site is actually owned by '"
                             + registered + "'.")
                points = points + 5
                critical = True
                break

        # --- 5. Lookalike / typosquatted domain --------------------------
        # Guard: only compare words of 5+ characters, and allow a bigger
        # difference only for longer brands. Without this, short unrelated
        # names collide by accident - 'bit' (as in bit.ly) is just two edits
        # away from 'sbi', which is not an imitation at all. Known
        # shorteners are skipped for the same reason.
        domain_word = registered.split(".")[0]
        is_shortener = any(domain == short or domain.endswith("." + short)
                           for short in URL_SHORTENERS)
        # Each hyphen-separated part is checked too, so a padded domain such
        # as 'paypa1-secure-verify' is still caught on its 'paypa1' part.
        domain_parts = [domain_word] + domain_word.split("-")
        lookalike_found = False
        for part in domain_parts:
            if lookalike_found:
                break
            for brand in COMMONLY_IMPERSONATED_BRANDS:
                if is_shortener or len(brand) < 5 or len(part) < 5:
                    continue
                allowed = 1 if len(brand) <= 6 else 2
                distance = edit_distance(part, brand)
                if 0 < distance <= allowed and abs(len(part) - len(brand)) <= 2:
                    flags.append("'" + part + "' is only " + str(distance)
                                 + " character(s) away from '" + brand
                                 + "' - a classic lookalike domain.")
                    points = points + 5
                    critical = True
                    lookalike_found = True
                    break

        # --- 6. Too many subdomains --------------------------------------
        subdomain_count = domain.count(".")
        if subdomain_count >= 3:
            flags.append("Unusually deep subdomain structure (" + domain
                         + ") - often used to make a fake address look long "
                           "and official.")
            points = points + 2

        # --- 7. Suspicious top-level domain ------------------------------
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                flags.append("Ends in '" + tld + "', a domain ending that is "
                             "cheap to register and heavily abused.")
                points = points + 3
                break

        # --- 8. Hyphen-stuffed domain ------------------------------------
        if registered.count("-") >= 2:
            flags.append("The domain contains several hyphens, a common way "
                         "of padding a fake address with reassuring words.")
            points = points + 2

        # --- 9. Login-style path -----------------------------------------
        path = url.lower().split(domain)[-1] if domain in url.lower() else ""
        for suspicious_path in SUSPICIOUS_URL_PATHS:
            if suspicious_path in path:
                flags.append("The link points to a '" + suspicious_path
                             + "' page, so it is asking you to sign in or "
                               "confirm something.")
                points = points + 2
                break

        # --- 10. No encryption -------------------------------------------
        if url.lower().startswith("http://"):
            flags.append("Uses http:// rather than https:// - anything typed "
                         "on that page travels unencrypted.")
            points = points + 2

        # --- 11. Very long or noisy address ------------------------------
        if len(url) > 90:
            flags.append("The address is unusually long, which helps hide the "
                         "real domain from someone skim-reading it.")
            points = points + 1

        results.append({
            "url": url,
            "domain": domain,
            "flags": flags,
            "points": points,
            "critical": critical,
        })

    return results


def check_link_mismatch(message_text):
    """
    Find links whose visible text does not match where they actually go.

    Two formats are handled:
      HTML      <a href="http://evil.example">www.yourbank.example</a>
      Markdown  [www.yourbank.example](http://evil.example)

    This is one of the strongest single indicators of phishing, because
    there is almost no innocent reason to display one address and link to
    a completely different one.
    """
    findings = []

    html_links = re.findall(r"<a[^>]*href=[\"']([^\"']+)[\"'][^>]*>(.*?)</a>",
                            message_text, re.IGNORECASE | re.DOTALL)
    markdown_links = re.findall(r"\[([^\]]+)\]\(([^)]+)\)", message_text)

    pairs = []
    for href, display in html_links:
        pairs.append((display.strip(), href.strip()))
    for display, href in markdown_links:
        pairs.append((display.strip(), href.strip()))

    for display_text, actual_url in pairs:
        # Only a problem if the visible text is itself an address
        looks_like_url = ("http" in display_text.lower()
                          or "www." in display_text.lower()
                          or re.search(r"\w+\.(com|net|org|in|co|io|xyz)",
                                       display_text.lower()) is not None)
        if not looks_like_url:
            continue

        display_domain = get_registered_domain(get_domain(display_text))
        actual_domain = get_registered_domain(get_domain(actual_url))

        if display_domain != actual_domain and display_domain != "":
            findings.append({
                "display": display_text,
                "actual": actual_url,
                "explanation": ("The link shows '" + display_domain
                                + "' but actually goes to '" + actual_domain
                                + "'. Hiding the true destination is "
                                  "deliberate deception."),
                "points": 8,
                "critical": True,
            })

    return findings


def check_sender(sender_name, sender_address, reply_to, message_text):
    """
    Examine the sender details, when they have been supplied.

    Returns a list of red flags about who the message claims to be from.
    """
    findings = []

    if sender_address is None or sender_address.strip() == "":
        return findings

    address = sender_address.lower().strip()

    if "@" not in address:
        findings.append({
            "flag": "Sender address is malformed",
            "detail": address,
            "explanation": "'" + address + "' is not a valid email address.",
            "points": 3,
            "critical": False,
        })
        return findings

    local_part = address.split("@")[0]
    sender_domain = address.split("@")[-1]
    registered = get_registered_domain(sender_domain)
    domain_word = registered.split(".")[0]
    body_and_name = ((sender_name or "") + " " + message_text).lower()

    # --- Free email account claiming to be a company ----------------------
    if sender_domain in FREE_EMAIL_PROVIDERS:
        for brand in COMMONLY_IMPERSONATED_BRANDS + ["bank", "support team",
                                                     "it department", "helpdesk"]:
            if brand in body_and_name:
                findings.append({
                    "flag": "Company message sent from a free email account",
                    "detail": address,
                    "explanation": ("The message presents itself as official, "
                                    "but it was sent from a free "
                                    + sender_domain + " account. A real "
                                    "organisation sends mail from its own "
                                    "domain."),
                    "points": 6,
                    "critical": True,
                })
                break

    # --- Lookalike sender domain ------------------------------------------
    for brand in COMMONLY_IMPERSONATED_BRANDS:
        # Same length guard as in analyze_urls - see the comment there.
        if len(brand) >= 5 and len(domain_word) >= 5:
            allowed = 1 if len(brand) <= 6 else 2
        else:
            allowed = 0
        distance = edit_distance(domain_word, brand)
        if 0 < distance <= allowed and abs(len(domain_word) - len(brand)) <= 2:
            findings.append({
                "flag": "Sender domain imitates a known brand",
                "detail": sender_domain,
                "explanation": ("'" + domain_word + "' is only " + str(distance)
                                + " character(s) different from '" + brand
                                + "'. Attackers register lookalike domains so "
                                  "the address passes a quick glance."),
                "points": 6,
                "critical": True,
            })
            break
        if brand in sender_domain and not registered.startswith(brand + "."):
            findings.append({
                "flag": "Brand name used in a domain it does not own",
                "detail": sender_domain,
                "explanation": ("The address contains '" + brand + "' but the "
                                "domain is really '" + registered + "'."),
                "points": 6,
                "critical": True,
            })
            break

    # --- Reply-To pointing somewhere else ---------------------------------
    if reply_to is not None and reply_to.strip() != "" and "@" in reply_to:
        reply_domain = get_registered_domain(reply_to.lower().split("@")[-1])
        if reply_domain != registered:
            findings.append({
                "flag": "Reply-To address differs from the sender address",
                "detail": sender_address + "  ->  " + reply_to,
                "explanation": ("Your reply would go to '" + reply_domain
                                + "', not to the apparent sender. This is how "
                                  "attackers collect responses while "
                                  "displaying a trusted 'From' address."),
                "points": 5,
                "critical": True,
            })

    # --- Display name does not match the real address ---------------------
    if sender_name is not None and sender_name.strip() != "":
        name_lower = sender_name.lower()
        for brand in COMMONLY_IMPERSONATED_BRANDS:
            if brand in name_lower and brand not in registered:
                findings.append({
                    "flag": "Display name does not match the real address",
                    "detail": sender_name + " <" + address + ">",
                    "explanation": ("The message displays '" + sender_name
                                    + "' but the real address belongs to '"
                                    + registered + "'. Display names can be "
                                      "set to anything at all."),
                    "points": 6,
                    "critical": True,
                })
                break

    # --- Executive impersonation from an outside account ------------------
    # Classic Business Email Compromise: the display name claims to be a
    # senior person, but the mail comes from a free consumer account rather
    # than from the company domain.
    executive_titles = ["ceo", "cfo", "coo", "chairman", "president",
                        "managing director", "director", "head of finance",
                        "vice president"]
    if sender_name is not None and sender_domain in FREE_EMAIL_PROVIDERS:
        for title in executive_titles:
            if title in sender_name.lower():
                findings.append({
                    "flag": "Senior staff impersonation from an outside account",
                    "detail": sender_name + " <" + address + ">",
                    "explanation": ("The sender presents themselves as a "
                                    "company leader but is writing from a "
                                    "personal " + sender_domain + " account. "
                                    "This is the standard setup for Business "
                                    "Email Compromise fraud."),
                    "points": 8,
                    "critical": True,
                })
                break

    # --- Random-looking local part ----------------------------------------
    digit_count = sum(1 for character in local_part if character.isdigit())
    if len(local_part) >= 10 and digit_count >= 5:
        findings.append({
            "flag": "Sender username looks auto-generated",
            "detail": local_part,
            "explanation": ("'" + local_part + "' looks machine-generated, "
                            "which is typical of disposable accounts created "
                            "in bulk for spam campaigns."),
            "points": 3,
            "critical": False,
        })

    return findings


def check_writing_style(message_text):
    """
    Look at grammar, spelling and formatting.

    Professional organisations proofread their mail. Sloppy writing is a
    weak indicator on its own - some phishing is well written and some
    genuine mail is badly written - but it adds useful weight alongside
    the stronger signals.
    """
    findings = []
    lowered = message_text.lower()

    # --- Generic greeting --------------------------------------------------
    for greeting in GENERIC_GREETINGS:
        if greeting in lowered:
            findings.append({
                "flag": "Generic greeting instead of your name",
                "detail": greeting,
                "explanation": ("A company you hold an account with knows your "
                                "name. '" + greeting + "' suggests a mass "
                                "mailing to addresses the sender knows nothing "
                                "about."),
                "points": 2,
                "critical": False,
            })
            break

    # --- Misspellings ------------------------------------------------------
    found_misspellings = []
    for word in COMMON_MISSPELLINGS:
        if word in lowered:
            found_misspellings.append(word)

    if len(found_misspellings) > 0:
        points = len(found_misspellings) * 2
        if points > 6:
            points = 6
        findings.append({
            "flag": "Spelling or phrasing errors",
            "detail": ", ".join(found_misspellings),
            "explanation": ("Official communication is proofread. Errors like "
                            "these suggest the message was written quickly or "
                            "by someone imitating an organisation."),
            "points": points,
            "critical": False,
        })

    # --- Shouting in capitals ---------------------------------------------
    words = re.findall(r"\b[A-Za-z]{4,}\b", message_text)
    if len(words) >= 8:
        shouted = [word for word in words if word.isupper()]
        if len(shouted) / len(words) > 0.2:
            findings.append({
                "flag": "Excessive use of CAPITAL LETTERS",
                "detail": str(len(shouted)) + " words fully capitalised",
                "explanation": ("Shouting in capitals is an emotional pressure "
                                "tactic, not standard business style."),
                "points": 2,
                "critical": False,
            })

    # --- Excessive punctuation --------------------------------------------
    if re.search(r"[!?]{3,}", message_text):
        findings.append({
            "flag": "Excessive exclamation or question marks",
            "detail": "found '!!!' or '???'",
            "explanation": ("Heavy punctuation is used to manufacture alarm or "
                            "excitement."),
            "points": 1,
            "critical": False,
        })

    # --- Attachment lure ---------------------------------------------------
    attachment_pattern = r"\b[\w\-]+\.(exe|scr|zip|rar|iso|js|vbs|bat|docm|xlsm|html)\b"
    attachments = re.findall(r"\b([\w\-]+\.(?:exe|scr|zip|rar|iso|js|vbs|bat|docm|xlsm|html))\b",
                             message_text, re.IGNORECASE)
    if len(attachments) > 0:
        findings.append({
            "flag": "Reference to a high-risk attachment type",
            "detail": ", ".join(attachments),
            "explanation": ("File types like these can run code on your "
                            "computer. Opening one from an unexpected message "
                            "is how most malware infections begin."),
            "points": 5,
            "critical": True,
        })

    return findings


# ---------------------------------------------------------------------------
# SECTION 4: SCORING AND CLASSIFICATION
# ---------------------------------------------------------------------------

def detect_red_flags(message):
    """
    Run every check and gather the results into one dictionary.

    'message' is a dictionary with the keys:
        sender_name, sender_address, reply_to, subject, body
    Only 'body' is required; the rest can be empty strings.
    """
    subject = message.get("subject", "") or ""
    body = message.get("body", "") or ""
    full_text = subject + "\n" + body

    urls = extract_urls(full_text)

    return {
        "urls": urls,
        "keyword_findings": check_keywords(full_text),
        "url_findings": analyze_urls(urls),
        "mismatch_findings": check_link_mismatch(full_text),
        "sender_findings": check_sender(message.get("sender_name", ""),
                                        message.get("sender_address", ""),
                                        message.get("reply_to", ""),
                                        full_text),
        "style_findings": check_writing_style(full_text),
    }


def count_critical_indicators(analysis):
    """
    Count the HIGH-CONFIDENCE indicators.

    Soft signals (urgency words, a generic greeting, bad spelling) appear in
    plenty of clumsy but genuine marketing email. Critical indicators are the
    ones that are very hard to explain innocently:

      - a request for a password, OTP or bank details
      - a request for gift cards, a wire transfer or cryptocurrency
      - a link whose visible text hides a different destination
      - a lookalike or brand-abusing domain, a raw IP address, or the @ trick
      - a sender impersonating a brand or a senior colleague
      - a Reply-To pointing to a different organisation
      - a dangerous attachment type

    Requiring at least one of these before calling something phishing is what
    stops a pile of harmless buzzwords from producing a false accusation.
    """
    count = 0
    for finding in analysis["keyword_findings"]:
        if finding.get("critical"):
            count = count + 1
    for finding in analysis["url_findings"]:
        if finding.get("critical"):
            count = count + 1
    for finding in analysis["mismatch_findings"]:
        if finding.get("critical"):
            count = count + 1
    for finding in analysis["sender_findings"]:
        if finding.get("critical"):
            count = count + 1
    for finding in analysis["style_findings"]:
        if finding.get("critical"):
            count = count + 1
    return count


def calculate_risk_score(analysis):
    """
    Add up the points from every check and turn the total into a
    classification.

    Design rule from the project brief: no single keyword may decide the
    outcome. Two separate conditions must both be satisfied before a message
    is called phishing - a high total score AND at least one critical
    indicator. A message can also be classified as phishing if it trips
    several critical indicators at once, since that combination is conclusive
    on its own.

        LIKELY PHISHING   score >= 20 with 1+ critical indicator,
                          or 3+ critical indicators
        SUSPICIOUS        score >= 6
        LIKELY LEGITIMATE score below 6

    Returns the score, the risk level, the classification and the number of
    critical indicators.
    """
    score = 0

    for finding in analysis["keyword_findings"]:
        score = score + finding["points"]
    for finding in analysis["url_findings"]:
        score = score + finding["points"]
    for finding in analysis["mismatch_findings"]:
        score = score + finding["points"]
    for finding in analysis["sender_findings"]:
        score = score + finding["points"]
    for finding in analysis["style_findings"]:
        score = score + finding["points"]

    critical_count = count_critical_indicators(analysis)

    if (score >= PHISHING_THRESHOLD and critical_count >= 1) or critical_count >= 3:
        classification = "LIKELY PHISHING"
        risk_level = "HIGH"
    elif score >= SUSPICIOUS_THRESHOLD:
        classification = "SUSPICIOUS"
        risk_level = "MEDIUM"
    else:
        classification = "LIKELY LEGITIMATE"
        risk_level = "LOW"

    return score, risk_level, classification, critical_count


def count_red_flags(analysis):
    """Count how many individual warning signs were found."""
    total = len(analysis["keyword_findings"])
    total = total + len(analysis["mismatch_findings"])
    total = total + len(analysis["sender_findings"])
    total = total + len(analysis["style_findings"])
    for url_result in analysis["url_findings"]:
        total = total + len(url_result["flags"])
    return total


def build_recommendation(classification):
    """Return the advice lines that match the classification."""
    if classification == "LIKELY PHISHING":
        return [
            "Do NOT click any link or open any attachment in this message.",
            "Do NOT reply, and do not provide any personal information.",
            "Report it to your IT or security team, then delete it.",
            "If it claims to be from an organisation you use, contact them "
            "using a phone number or website you already trust - never the "
            "contact details inside the message.",
        ]
    elif classification == "SUSPICIOUS":
        return [
            "Treat this message with caution until you can confirm it.",
            "Do not enter credentials through any link it contains.",
            "Verify the request with the sender through a channel you already "
            "trust, such as calling a known number.",
            "If you cannot verify it, report it to your IT team.",
        ]
    else:
        return [
            "No strong phishing indicators were found in this message.",
            "This is NOT a guarantee of safety - stay alert anyway.",
            "Still check the sender and hover over links before clicking.",
            "If the message asks for anything sensitive or unexpected, verify "
            "it independently regardless of this result.",
        ]


# ---------------------------------------------------------------------------
# SECTION 5: THE REPORT
# ---------------------------------------------------------------------------

def generate_report(message, analysis, score, risk_level, classification,
                    critical_count=0):
    """Build the full text report as a list of lines."""
    lines = []
    flag_count = count_red_flags(analysis)

    lines.append("")
    lines.append(LINE)
    lines.append(" PHISHING ANALYSIS REPORT")
    lines.append(LINE)

    if message.get("subject"):
        lines.append(" Subject        : " + message["subject"])
    if message.get("sender_name") or message.get("sender_address"):
        sender_line = (message.get("sender_name", "") + " <"
                       + message.get("sender_address", "") + ">").strip()
        lines.append(" From           : " + sender_line)
    if message.get("reply_to"):
        lines.append(" Reply-To       : " + message["reply_to"])

    lines.append(" Risk Score     : " + str(score) + " points")
    lines.append(" Risk Level     : " + risk_level)
    lines.append(" Classification : " + classification)
    lines.append(" Red Flags      : " + str(flag_count) + " detected ("
                 + str(critical_count) + " high-confidence)")
    lines.append("-" * 66)

    # --- Suspicious keywords ----------------------------------------------
    lines.append("")
    lines.append(" SUSPICIOUS KEYWORDS AND PHRASES")
    if len(analysis["keyword_findings"]) == 0:
        lines.append("   None detected.")
    else:
        for finding in analysis["keyword_findings"]:
            lines.append("   [!] " + finding["category"]
                         + "  (+" + str(finding["points"]) + ")")
            lines.append("       Found : " + ", ".join(finding["terms"]))
            lines.append("       Why   : " + finding["explanation"])

    # --- URLs --------------------------------------------------------------
    lines.append("")
    lines.append(" URLS FOUND IN THE MESSAGE")
    if len(analysis["urls"]) == 0:
        lines.append("   No links found.")
    else:
        for url_result in analysis["url_findings"]:
            status = "SUSPICIOUS" if len(url_result["flags"]) > 0 else "no structural flags"
            lines.append("   Link  : " + url_result["url"])
            lines.append("   Domain: " + url_result["domain"]
                         + "   [" + status + ", +" + str(url_result["points"]) + "]")
            for flag in url_result["flags"]:
                lines.append("       [!] " + flag)
        lines.append("   Note: URL structure is an INDICATOR, not proof. A")
        lines.append("   clean-looking link can still be dangerous, and an odd")
        lines.append("   one can be harmless.")

    # --- Link mismatches ---------------------------------------------------
    if len(analysis["mismatch_findings"]) > 0:
        lines.append("")
        lines.append(" HIDDEN LINK DESTINATIONS")
        for finding in analysis["mismatch_findings"]:
            lines.append("   [!] Displayed : " + finding["display"])
            lines.append("       Actual    : " + finding["actual"])
            lines.append("       Why       : " + finding["explanation"])

    # --- Sender ------------------------------------------------------------
    if len(analysis["sender_findings"]) > 0:
        lines.append("")
        lines.append(" SENDER RED FLAGS")
        for finding in analysis["sender_findings"]:
            lines.append("   [!] " + finding["flag"]
                         + "  (+" + str(finding["points"]) + ")")
            lines.append("       Detail : " + finding["detail"])
            lines.append("       Why    : " + finding["explanation"])

    # --- Writing style -----------------------------------------------------
    if len(analysis["style_findings"]) > 0:
        lines.append("")
        lines.append(" WRITING STYLE AND FORMATTING")
        for finding in analysis["style_findings"]:
            lines.append("   [!] " + finding["flag"]
                         + "  (+" + str(finding["points"]) + ")")
            lines.append("       Detail : " + finding["detail"])
            lines.append("       Why    : " + finding["explanation"])

    # --- Verdict -----------------------------------------------------------
    lines.append("")
    lines.append("-" * 66)
    lines.append(" VERDICT")
    if classification == "LIKELY PHISHING":
        lines.append("   Several independent warning signs appear together in")
        lines.append("   this message. That combination - not any single word -")
        lines.append("   is what makes it untrustworthy. Do not act on it.")
    elif classification == "SUSPICIOUS":
        lines.append("   This message shows some warning signs but not enough")
        lines.append("   to be conclusive. It may be legitimate marketing, or")
        lines.append("   it may be a carefully written attack. Verify before")
        lines.append("   acting on it.")
    else:
        lines.append("   No significant phishing indicators were found. The")
        lines.append("   message does not pressure you, does not ask for")
        lines.append("   sensitive data, and its links look ordinary. This is")
        lines.append("   reassuring but NOT a guarantee.")

    lines.append("")
    lines.append(" RECOMMENDED ACTION")
    for advice in build_recommendation(classification):
        lines.append("   -> " + advice)

    lines.append(LINE)
    lines.append("")
    return lines


def analyze_message(message):
    """Convenience wrapper: analyse a message and return everything."""
    analysis = detect_red_flags(message)
    score, risk_level, classification, critical = calculate_risk_score(analysis)
    return {
        "analysis": analysis,
        "score": score,
        "risk_level": risk_level,
        "classification": classification,
        "critical_count": critical,
        "red_flag_count": count_red_flags(analysis),
    }


def print_report(message):
    """Analyse a message and print the report to the screen."""
    result = analyze_message(message)
    lines = generate_report(message, result["analysis"], result["score"],
                            result["risk_level"], result["classification"],
                            result["critical_count"])
    for line in lines:
        print(line)
    return result


# ---------------------------------------------------------------------------
# SECTION 6: THE RED FLAG CHECKLIST
# ---------------------------------------------------------------------------

PHISHING_CHECKLIST = [
    ("Sender", [
        "Do I actually recognise this sender?",
        "Was I expecting this message?",
        "Does the real email address match the display name?",
        "Is the domain spelled exactly right, letter by letter?",
        "Would this organisation really email me from this address?",
    ]),
    ("Pressure", [
        "Is the message creating urgency or a deadline?",
        "Is it threatening to suspend, close or fine me?",
        "Is it trying to make me act before I think?",
        "Is it asking me to keep the request secret?",
    ]),
    ("The ask", [
        "Is it requesting a password, OTP, PIN or card details?",
        "Is it asking me to make a payment or change bank details?",
        "Is it asking me to buy gift cards or send cryptocurrency?",
        "Would a legitimate organisation ever ask for this by email?",
    ]),
    ("Links and attachments", [
        "Where does the link really go when I hover over it?",
        "Does the displayed text match the real destination?",
        "Is the domain one I trust, or just one that mentions a brand?",
        "Is the link shortened, an IP address, or unusually long?",
        "Was I expecting this attachment, and is the file type safe?",
    ]),
    ("Content", [
        "Are there spelling, grammar or formatting problems?",
        "Does it greet me generically instead of by name?",
        "Is the offer or warning unexpected or too good to be true?",
        "Does the tone match how this sender normally writes?",
    ]),
    ("Before acting", [
        "Can I independently verify this through a channel I already trust?",
        "Have I checked with a colleague or my IT team?",
        "If I am wrong about this, what is the worst that happens?",
        "Am I sure enough to bet my account on it?",
    ]),
]


def print_checklist():
    """Print the reusable awareness checklist."""
    print("")
    print(LINE)
    print(" PHISHING RED FLAG CHECKLIST")
    print(" Use this whenever a message feels even slightly unusual.")
    print(LINE)
    for section_name, questions in PHISHING_CHECKLIST:
        print("")
        print(" " + section_name.upper())
        for question in questions:
            print("   [ ] " + question)
    print("")
    print(" GOLDEN RULE: if you are unsure, do not click. Verify first.")
    print(" Reporting a real message by mistake costs nothing. Clicking a")
    print(" phishing link can cost your organisation everything.")
    print(LINE)
    print("")


# ---------------------------------------------------------------------------
# SECTION 7: TRAINING EXAMPLES
#
# All names, domains and details below are FICTIONAL and exist only for
# training. They are written to be analysed, never to be sent to anyone.
# ---------------------------------------------------------------------------

EXAMPLE_MESSAGES = [
    {
        "label": "Example 1 - Legitimate internal message",
        "expected": "LIKELY LEGITIMATE",
        "sender_name": "Priya Nair",
        "sender_address": "priya.nair@northwind-demo.example",
        "reply_to": "",
        "subject": "Notes from Tuesday's project review",
        "body": (
            "Hi Arjun,\n\n"
            "Thanks for presenting yesterday. I have uploaded the slides and "
            "the meeting notes to our shared drive, in the folder we set up "
            "last month.\n\n"
            "Could you add your section on testing before Friday? No rush if "
            "you are busy, next week works too.\n\n"
            "The internal wiki page is here if you need the template: "
            "https://wiki.northwind-demo.example/projects/testing-template\n\n"
            "Best regards,\n"
            "Priya Nair\n"
            "Project Lead, Northwind Demo Ltd"
        ),
    },
    {
        "label": "Example 2 - Suspicious marketing message",
        "expected": "SUSPICIOUS",
        "sender_name": "Rewards Team",
        "sender_address": "offers@shopdeals-demo.example",
        "reply_to": "",
        "subject": "Congratulations! Your exclusive reward is waiting",
        "body": (
            "Dear Customer,\n\n"
            "Congratulations! You have been selected for a free gift from our "
            "annual customer appreciation programme.\n\n"
            "Claim your reward before this limited time offer expires today:\n"
            "http://bit.ly/demo-reward-claim\n\n"
            "Thankyou for shopping with us.\n\n"
            "The Rewards Team"
        ),
    },
    {
        "label": "Example 3 - Clear phishing attempt",
        "expected": "LIKELY PHISHING",
        "sender_name": "PayPal Security",
        "sender_address": "security.alert99281@gmail.com",
        "reply_to": "recovery-desk@paypa1-secure.xyz",
        "subject": "URGENT: Your account has been suspended - verify now",
        "body": (
            "Dear Valued Customer,\n\n"
            "We have detected unusual activity on your acount. For your "
            "protection your account has been suspended IMMEDIATELY.\n\n"
            "You must verify your account within 24 hours or it will be "
            "permanently deleted. Please confirm your identity by entering "
            "your password, bank account number and the OTP sent to your "
            "phone.\n\n"
            "Click here to restore access NOW:\n"
            '<a href="http://paypa1-secure-verify.xyz/login/confirm.php?id=8891">'
            'https://www.paypal.com/account</a>\n\n'
            "Failure to act will result in legal action!!!\n\n"
            "PayPal Seccurity Department"
        ),
    },
    {
        "label": "Example 4 - Business Email Compromise attempt",
        "expected": "LIKELY PHISHING",
        "sender_name": "Rajesh Menon (CEO)",
        "sender_address": "r.menon.ceo4471@mail.com",
        "reply_to": "",
        "subject": "Urgent - confidential task",
        "body": (
            "Are you at your desk?\n\n"
            "I need you to process this payment urgently before the end of "
            "the day. It is time sensitive and I am going into meetings.\n\n"
            "Please keep this confidential for now - do not discuss it with "
            "the finance team until I announce it.\n\n"
            "I need you to purchase gift cards worth 50,000 and send me the "
            "codes. I will reimburse you immediately.\n\n"
            "Sent from my iPhone"
        ),
    },
]


def run_all_examples():
    """Analyse every training example and print each report."""
    for example in EXAMPLE_MESSAGES:
        print("")
        print("#" * 66)
        print(" " + example["label"])
        print(" Expected classification: " + example["expected"])
        print("#" * 66)
        result = print_report(example)
        match = "MATCH" if result["classification"] == example["expected"] else "MISMATCH"
        print(" [" + match + "] Program returned: " + result["classification"]
              + " (score " + str(result["score"]) + ")")
        print("")


def run_example_summary():
    """Print a one-line summary for every example - useful for a demo."""
    print("")
    print(LINE)
    print(" TRAINING EXAMPLE SUMMARY")
    print(LINE)
    for example in EXAMPLE_MESSAGES:
        result = analyze_message(example)
        match = "PASS" if result["classification"] == example["expected"] else "FAIL"
        print(" [" + match + "] score " + str(result["score"]).rjust(3)
              + " | " + result["classification"].ljust(18)
              + " | " + result["red_flag_count"].__str__().rjust(2) + " flags"
              + " | " + example["label"])
    print(LINE)
    print("")


# ---------------------------------------------------------------------------
# SECTION 8: MAIN PROGRAM
# ---------------------------------------------------------------------------

def read_multiline(prompt):
    """
    Read several lines of text until the user types END on its own line.
    Emails are multi-line, so a single input() call is not enough.
    """
    print(prompt)
    print("(Type END on a line by itself when you have finished.)")
    collected = []
    while True:
        try:
            line = input()
        except EOFError:
            break
        if line.strip().upper() == "END":
            break
        collected.append(line)
    return "\n".join(collected)


def analyze_user_message():
    """Let the user paste their own message for analysis."""
    print("")
    print(LINE)
    print(" ANALYSE YOUR OWN MESSAGE")
    print(" Paste a message you have received. Nothing is sent anywhere -")
    print(" the analysis happens entirely on this computer.")
    print(LINE)

    sender_name = input("Sender display name (press Enter to skip): ").strip()
    sender_address = input("Sender email address (press Enter to skip): ").strip()
    reply_to = input("Reply-To address (press Enter to skip): ").strip()
    subject = input("Subject line (press Enter to skip): ").strip()
    body = read_multiline("Message body:")

    if body.strip() == "" and subject.strip() == "":
        print("  ! No message content entered. Returning to the menu.\n")
        return

    message = {
        "sender_name": sender_name,
        "sender_address": sender_address,
        "reply_to": reply_to,
        "subject": subject,
        "body": body,
    }
    print_report(message)


def choose_example():
    """Let the user pick one training example to analyse in detail."""
    print("")
    print(" Available training examples:")
    for index, example in enumerate(EXAMPLE_MESSAGES, start=1):
        print("   " + str(index) + ". " + example["label"])
    choice = input(" Choose an example (1-" + str(len(EXAMPLE_MESSAGES)) + "): ").strip()

    if not choice.isdigit() or not (1 <= int(choice) <= len(EXAMPLE_MESSAGES)):
        print("  ! Invalid choice. Returning to the menu.\n")
        return

    example = EXAMPLE_MESSAGES[int(choice) - 1]
    print("")
    print("--- Message being analysed ---")
    print(example["body"])
    print("--- End of message ---")
    print_report(example)


def print_menu():
    print(LINE)
    print(" PHISHING AWARENESS ANALYSIS SYSTEM")
    print(" Cybersecurity Project 3 - educational use only")
    print(LINE)
    print(" 1. Analyse one of the training examples")
    print(" 2. Analyse your own message")
    print(" 3. Run all training examples")
    print(" 4. Show the summary table of all examples")
    print(" 5. Show the phishing red flag checklist")
    print(" 6. Exit")
    print(LINE)


def main():
    print("")
    print(" Reminder: this tool spots WARNING SIGNS in text you give it.")
    print(" A low score does not prove a message is safe. Always verify")
    print(" unexpected requests through a channel you already trust.")
    print("")

    running = True
    while running:
        print_menu()
        choice = input("Choose an option (1-6): ").strip()

        if choice == "1":
            choose_example()
        elif choice == "2":
            analyze_user_message()
        elif choice == "3":
            run_all_examples()
        elif choice == "4":
            run_example_summary()
        elif choice == "5":
            print_checklist()
        elif choice == "6":
            running = False
        else:
            print("  ! '" + choice + "' is not a valid option. "
                  "Please choose 1 to 6.\n")

    print("")
    print(" Stay alert. When in doubt, verify before you click. Goodbye!")
    print("")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--examples":
        run_all_examples()
    elif len(sys.argv) > 1 and sys.argv[1] == "--summary":
        run_example_summary()
    elif len(sys.argv) > 1 and sys.argv[1] == "--checklist":
        print_checklist()
    else:
        main()
