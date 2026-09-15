# Phishing Awareness Analysis System
### Industrial Training / Cybersecurity Internship — Project 3
**Language:** Python 3 — standard library only (`re` and `sys`), no external packages

> **Educational scope.** This is a defensive awareness tool. It analyses text that is pasted into it and explains the warning signs it finds. It does not send email, does not visit any website, does not test whether a link is genuinely malicious, and contains nothing that could be used to build a phishing campaign. Every name, domain and address in the examples is fictional.

---

## 1. Files in this project

| File | Purpose |
|---|---|
| `phishing_analyzer.py` | The complete program |
| `test_phishing.py` | 55 automated test cases |
| `README_phishing.md` | This report |

**How to run:**

```bash
python phishing_analyzer.py             # interactive menu
python phishing_analyzer.py --examples  # analyse all four training examples
python phishing_analyzer.py --summary   # one-line summary of each example
python phishing_analyzer.py --checklist # print the awareness checklist
python test_phishing.py                 # run all 55 test cases
```

---

## 2. Project explanation

The program takes a message — optionally with sender details, a Reply-To address and a subject line — and runs it through six independent groups of checks. Each check that fires produces a **red flag**: a short name, the exact detail found, a plain-English explanation of why it matters, and a number of risk points.

The points are added into a **risk score**, the score plus the type of flags decides a **classification**, and a report prints everything with a recommended action.

The menu offers six options:

1. Analyse one of the four training examples
2. Analyse your own pasted message
3. Run all training examples
4. Show the summary table
5. Show the phishing red flag checklist
6. Exit

All the detection knowledge — keyword lists, brand names, suspicious domain endings, misspellings — sits in dictionaries and lists at the top of the file, separate from the logic. Improving detection means editing data, not rewriting code.

---

## 3. Detection methodology

Six analysis functions run over every message.

### 3.1 `extract_urls()` — finding the links
A regular expression pulls out anything beginning with `http://`, `https://` or `www.`, then trailing sentence punctuation is stripped so that `https://example.com/page.` does not become a URL ending in a full stop.

### 3.2 `check_keywords()` — suspicious language
Keywords are grouped into seven categories by the psychological trick they use, rather than kept in one flat list. This matters, because *which* category fires tells you what kind of attack you are looking at.

| Category | Points each | Cap | Critical? |
|---|---|---|---|
| Urgency pressure | 2 | 6 | No |
| Account threat | 3 | 9 | No |
| Verification bait | 3 | 9 | No |
| Too-good-to-be-true offer | 3 | 9 | No |
| Secrecy or bypassing procedure | 3 | 6 | No |
| **Request for sensitive information** | 4 | 12 | **Yes** |
| **Unusual payment request** | 5 | 10 | **Yes** |

Each category is capped so that a message stuffed with twenty urgency words cannot run away with the score.

### 3.3 `analyze_urls()` — link structure
Eleven structural checks per URL: raw IP address instead of a domain, the `@` trick, URL shorteners, a brand name in a domain it does not own, lookalike/typosquatted domains, excessive subdomains, abused top-level domains, hyphen-stuffed domains, login-style paths, plain `http://`, and unusually long addresses.

Lookalike detection uses an **edit distance** function: `paypa1` is one character-edit away from `paypal`, so it is flagged. Each hyphen-separated part of the domain is checked too, which is how `paypa1-secure-verify.xyz` is caught on its `paypa1` segment.

> **URL analysis is an indicator, not proof.** A link with a clean structure can still lead to a compromised site, and an odd-looking link can be entirely harmless. Structure analysis tells you what deserves a closer look; it never settles the question. The program prints this caveat in every report containing links.

### 3.4 `check_link_mismatch()` — hidden destinations
Handles both HTML anchors and markdown links. If the *visible* text is itself an address but points to a different registered domain, that is flagged as critical. There is almost no innocent reason to display one address and link to another.

Crucially, the check only fires when the display text looks like a URL. A link reading "Click here" has nothing to compare against, so it is not flagged — that distinction avoids a large class of false positives.

### 3.5 `check_sender()` — who it claims to be from
Six checks: a free email account (gmail, yahoo, …) sending what claims to be corporate mail; a sender domain imitating a known brand; a brand name in a domain it does not own; a Reply-To pointing to a different organisation; a display name that does not match the real address; and an auto-generated-looking username. There is also a dedicated **Business Email Compromise** check: a display name claiming a senior title (CEO, CFO, Director) combined with a free consumer email account.

### 3.6 `check_writing_style()` — grammar and formatting
Generic greetings, common misspellings, excessive capitals, excessive punctuation, and references to high-risk attachment types (`.exe`, `.scr`, `.js`, `.docm`, …).

These are deliberately **low-weight**. Plenty of phishing is well written and plenty of genuine email is not, so poor writing supports a conclusion but never drives one.

---

## 4. Risk-scoring methodology

### Two conditions, not one

The project brief requires that no single keyword classify a message as phishing. The program enforces this with a rule that is stricter than a plain threshold:

```
LIKELY PHISHING    score >= 20 AND at least 1 critical indicator
                   OR 3 or more critical indicators
SUSPICIOUS         score >= 6
LIKELY LEGITIMATE  score below 6
```

**Critical indicators** are the flags that are hard to explain innocently:

- a request for a password, OTP or bank details
- a request for gift cards, a wire transfer or cryptocurrency
- a link whose visible text hides a different destination
- a lookalike domain, brand abuse, a raw IP address, or the `@` trick
- a sender impersonating a brand or a senior colleague
- a Reply-To pointing to a different organisation
- a reference to a dangerous attachment type

**Why this design matters.** A promotional email can easily contain "congratulations", "free gift", "claim now", "limited time", "expires today" and a `bit.ly` link. That is a score in the twenties from nothing but marketing noise. Under a plain threshold it would be branded phishing — a false accusation. Requiring a critical indicator means it is correctly reported as **SUSPICIOUS: worth checking, not proven malicious.** Training example 2 is exactly this case.

The reverse also holds: example 4 contains **no links at all**, which defeats any URL-based detector, but its combination of gift-card request, secrecy, urgency and a CEO writing from a personal account produces three critical indicators and a correct phishing verdict.

### Why failing safe matters in both directions

An over-sensitive detector trains people to ignore warnings, which is worse than no detector. An under-sensitive one misses attacks. The three-band output — with "SUSPICIOUS" meaning *verify before acting* rather than *this is an attack* — reflects how a real security team actually triages reported mail.

---

## 5. Red Flag Checklist

A reusable checklist that employees or students can apply to any message. Printed by menu option 5 or `--checklist`.

**Sender**
- [ ] Do I actually recognise this sender?
- [ ] Was I expecting this message?
- [ ] Does the real email address match the display name?
- [ ] Is the domain spelled exactly right, letter by letter?
- [ ] Would this organisation really email me from this address?

**Pressure**
- [ ] Is the message creating urgency or a deadline?
- [ ] Is it threatening to suspend, close or fine me?
- [ ] Is it trying to make me act before I think?
- [ ] Is it asking me to keep the request secret?

**The ask**
- [ ] Is it requesting a password, OTP, PIN or card details?
- [ ] Is it asking me to make a payment or change bank details?
- [ ] Is it asking me to buy gift cards or send cryptocurrency?
- [ ] Would a legitimate organisation ever ask for this by email?

**Links and attachments**
- [ ] Where does the link really go when I hover over it?
- [ ] Does the displayed text match the real destination?
- [ ] Is the domain one I trust, or just one that mentions a brand?
- [ ] Is the link shortened, an IP address, or unusually long?
- [ ] Was I expecting this attachment, and is the file type safe?

**Content**
- [ ] Are there spelling, grammar or formatting problems?
- [ ] Does it greet me generically instead of by name?
- [ ] Is the offer or warning unexpected or too good to be true?
- [ ] Does the tone match how this sender normally writes?

**Before acting**
- [ ] Can I independently verify this through a channel I already trust?
- [ ] Have I checked with a colleague or my IT team?
- [ ] If I am wrong about this, what is the worst that happens?
- [ ] Am I sure enough to bet my account on it?

> **Golden rule:** if you are unsure, do not click. Verify first. Reporting a real message by mistake costs nothing. Clicking a phishing link can cost your organisation everything.

---

## 6 & 7. Example messages and expected results

All four are fictional and built into the program.

| # | Example | Score | Critical | Flags | Classification |
|---|---|---|---|---|---|
| 1 | Legitimate internal message | 0 | 0 | 0 | LIKELY LEGITIMATE |
| 2 | Suspicious marketing message | 22 | 0 | 6 | SUSPICIOUS |
| 3 | Clear phishing attempt | 87 | 6 | 18 | LIKELY PHISHING |
| 4 | Business Email Compromise | 30 | 3 | 4 | LIKELY PHISHING |

### Example 1 — legitimate internal message
A colleague sends meeting notes with a link to an internal wiki on the company's own domain. **Reasoning:** no urgency, no request for anything sensitive, addressed to a named person, signed with a real name and role, sender domain matches the organisation, and the single link is on a first-party domain with an ordinary path. Nothing fires — score 0.

### Example 2 — suspicious marketing message
An unexpected "you have been selected for a free gift" email with a shortened link. **Reasoning:** it trips a genuine cluster of soft flags — an unexpected prize, a "limited time" deadline, a generic "Dear Customer" greeting, a spelling slip ("Thankyou"), and a `bit.ly` link hiding its destination. But it never asks for credentials or payment, the sender is not impersonating anyone, and no link deception is present. **Zero critical indicators, so it is correctly held at SUSPICIOUS rather than accused.** This is the single most important example in the set, because it demonstrates the scoring design working as intended.

### Example 3 — clear phishing attempt
A fake "PayPal Security" account-suspension notice. **Reasoning:** almost every category fires at once — urgency ("within 24 hours"), account threat ("suspended", "permanently deleted", "legal action"), verification bait, and a direct request for password, bank account number and OTP. The link *displays* `paypal.com` but actually goes to `paypa1-secure-verify.xyz` — a lookalike domain with a digit `1` replacing the letter `l`, an abused `.xyz` ending, hyphen padding, a `/login` path and no HTTPS. The sender is a free Gmail account with an auto-generated username, the display name says "PayPal Security", and the Reply-To points to yet another domain. Spelling errors ("acount", "Seccurity") and `!!!` complete the picture.

### Example 4 — Business Email Compromise
A "CEO" asks an employee to quietly buy gift cards. **Reasoning:** there are **no links at all**, so URL analysis contributes nothing — yet the message is still caught. The gift-card request is a critical indicator, the display name claims a senior title while the address is a free `mail.com` account with an auto-generated username, the request demands secrecy from the finance team, and it applies time pressure. This example exists to show that link-based detection alone is not enough.

---

## 8. Test cases

`test_phishing.py` contains **55 tests, all passing**, in ten groups.

| Group | What it proves |
|---|---|
| Helpers | Edit distance and domain parsing are correct |
| URL extraction | Finds http/https/www links, strips trailing punctuation, finds none in plain text |
| Keyword detection | Categories fire correctly, credential requests are marked critical, per-category caps hold |
| URL analysis | IP addresses, the `@` trick, shorteners, lookalikes, brand abuse and bad TLDs are caught; ordinary URLs produce zero flags |
| Link mismatch | HTML and markdown mismatches caught; matching links and "Click here" text are not flagged |
| Sender analysis | Reply-To mismatch, display-name mismatch, BEC impersonation and auto-generated usernames detected; a normal corporate sender is clean |
| Writing style | Greetings, misspellings, dangerous attachments and `!!!` detected; normal writing is clean |
| Scoring rules | An empty message scores 0; **one keyword alone is never phishing**; a high score with no critical indicator stays SUSPICIOUS; critical indicators escalate correctly |
| Training examples | All four land in their expected band |
| **False positives** | A personal email, a genuine password-reset notice and a normal newsletter are all **not** flagged |
| Report generation | Every required section is present; the "safe" report still warns against complacency |
| Edge cases | Missing fields, a 5,000-word message, URL-only text, a malformed sender address and Unicode text all handled without crashing |

Two tests deserve particular mention. `test_shortener_is_not_called_a_lookalike` is a **regression test**: during development, `bit.ly` was being flagged as an imitation of `sbi`, because "bit" is two character-edits from "sbi". The fix was a length guard requiring at least five characters before comparing, plus a stricter edit-distance limit for short brands. The test locks that fix in place.

`test_legitimate_password_reset_is_not_auto_condemned` guards the rule from the brief directly: a real password-reset email mentions "password", and must not be condemned for it.

---

## 9. Sample program output

### Summary table (`--summary`)

```
==================================================================
 TRAINING EXAMPLE SUMMARY
==================================================================
 [PASS] score   0 | LIKELY LEGITIMATE  |  0 flags | Example 1 - Legitimate internal message
 [PASS] score  22 | SUSPICIOUS         |  6 flags | Example 2 - Suspicious marketing message
 [PASS] score  87 | LIKELY PHISHING    | 18 flags | Example 3 - Clear phishing attempt
 [PASS] score  30 | LIKELY PHISHING    |  4 flags | Example 4 - Business Email Compromise attempt
==================================================================
```

### Full report for Example 3 (abridged)

```
==================================================================
 PHISHING ANALYSIS REPORT
==================================================================
 Subject        : URGENT: Your account has been suspended - verify now
 From           : PayPal Security <security.alert99281@gmail.com>
 Reply-To       : recovery-desk@paypa1-secure.xyz
 Risk Score     : 87 points
 Risk Level     : HIGH
 Classification : LIKELY PHISHING
 Red Flags      : 18 detected (6 high-confidence)
------------------------------------------------------------------

 SUSPICIOUS KEYWORDS AND PHRASES
   [!] Request for sensitive information  (+12)
       Found : password, your password, otp, bank account, account number,
               confirm your identity
       Why   : Real banks, IT teams and service providers never ask for
               passwords, OTPs or full card details by email or message.
               Anyone who does is an attacker.
   [!] Account threat  (+9)
       Found : account has been suspended, unusual activity,
               permanently deleted, legal action
       Why   : Threatening to close, suspend or lock your account creates
               fear, which pushes people into clicking without checking.
   ... (urgency and verification-bait categories also fired)

 URLS FOUND IN THE MESSAGE
   Link  : http://paypa1-secure-verify.xyz/login/confirm.php?id=8891
   Domain: paypa1-secure-verify.xyz   [SUSPICIOUS, +14]
       [!] 'paypa1' is only 1 character(s) away from 'paypal' - a classic
           lookalike domain.
       [!] Ends in '.xyz', a domain ending that is cheap to register and
           heavily abused.
       [!] The domain contains several hyphens, a common way of padding a
           fake address with reassuring words.
       [!] The link points to a 'login' page, so it is asking you to sign
           in or confirm something.
       [!] Uses http:// rather than https:// - anything typed on that page
           travels unencrypted.
   Note: URL structure is an INDICATOR, not proof.

 HIDDEN LINK DESTINATIONS
   [!] Displayed : https://www.paypal.com/account
       Actual    : http://paypa1-secure-verify.xyz/login/confirm.php?id=8891
       Why       : The link shows 'paypal.com' but actually goes to
                   'paypa1-secure-verify.xyz'. Hiding the true destination
                   is deliberate deception.

 SENDER RED FLAGS
   [!] Display name does not match the real address  (+6)
       Detail : PayPal Security <security.alert99281@gmail.com>
       Why    : The message displays 'PayPal Security' but the real address
                belongs to 'gmail.com'. Display names can be set to anything.
   [!] Reply-To address differs from the sender address  (+5)
   [!] Company message sent from a free email account  (+6)
   [!] Sender username looks auto-generated  (+3)

 WRITING STYLE AND FORMATTING
   [!] Generic greeting instead of your name  (+2)
   [!] Spelling or phrasing errors  (+4)   Detail : acount, seccurity
   [!] Excessive exclamation or question marks  (+1)

------------------------------------------------------------------
 VERDICT
   Several independent warning signs appear together in this message.
   That combination - not any single word - is what makes it
   untrustworthy. Do not act on it.

 RECOMMENDED ACTION
   -> Do NOT click any link or open any attachment in this message.
   -> Do NOT reply, and do not provide any personal information.
   -> Report it to your IT or security team, then delete it.
   -> If it claims to be from an organisation you use, contact them using
      a phone number or website you already trust - never the contact
      details inside the message.
==================================================================
```

---

## 10. Cybersecurity concepts demonstrated

**Social engineering.** Phishing attacks the person, not the software. Every keyword category in this program maps to a persuasion technique: **authority** (impersonating a bank or a CEO), **urgency** (24-hour deadlines), **fear** (account suspension, legal action), **greed** (prizes and refunds), and **isolation** (keep this confidential). Recognising the technique is more durable than memorising specific scam wordings.

**The human layer.** Technical controls stop most attacks; phishing succeeds precisely because it bypasses them and targets the person at the keyboard. This is why awareness training is a security control in its own right.

**Threat identification and triage.** The three-band output mirrors how a security operations team handles reported mail: confirmed bad, needs a human look, probably fine. Not every alert is an incident.

**Indicators of compromise.** Lookalike domains, suspicious TLDs, mismatched Reply-To headers and URL structure are all IoCs — observable artefacts that suggest malicious activity without proving it.

**Defence in depth.** No single check carries the verdict. Six independent analyses are combined, so an attacker who defeats one (writing in perfect English, say) still trips the others.

**Signal versus noise, and the cost of false positives.** A detector that cries wolf gets ignored, which makes the organisation *less* safe. The critical-indicator rule exists specifically to protect the credibility of the HIGH verdict.

**Business Email Compromise.** The FBI consistently ranks BEC among the costliest categories of cybercrime. Example 4 shows why it is hard to catch: no malware, no links, no attachments — just a plausible request from a plausible person.

**Typosquatting and homoglyphs.** Registering `paypa1.com` (digit one) or `arnazon.com` (r + n resembling m) exploits the fact that people read the shape of a word rather than each letter.

**Verification through a trusted channel.** The single most valuable habit in the whole project: never use the contact details inside a suspicious message to check whether that message is real.

**Reporting culture.** The recommendations always include reporting to IT, because one reported phish protects every other employee.

---

## 11. Limitations of automated phishing detection

**This tool is an awareness aid, not a security product. A LOW score does not prove a message is safe.**

1. **Rule-based detection only catches what it has been told about.** The keyword lists are finite. An attacker who avoids every listed phrase — or writes in a language the lists do not cover — passes straight through.

2. **Attackers adapt to filters.** Once a keyword is known to trigger detection, campaigns stop using it. This is an arms race, and static lists always lag behind.

3. **No link is ever actually checked.** The program analyses URL *structure* only. It cannot tell whether a page is a credential-harvesting clone, and it has no access to reputation feeds or blocklists. A perfectly ordinary URL on a legitimate but **compromised** website is invisible to it.

4. **Well-crafted phishing scores low.** A short, grammatical, unhurried message from a genuinely compromised colleague's real account — the most dangerous kind of phishing there is — would produce almost no flags.

5. **False positives are unavoidable.** Legitimate marketing uses urgency and prizes. Real password-reset emails mention passwords. Real IT notices mention account verification. The scoring design reduces this problem but cannot eliminate it.

6. **Headers are not verified.** A real email client can check SPF, DKIM and DMARC records, which cryptographically test whether the sender is authorised to use that domain. This program only sees the text it is given, and the "From" line in text is trivially forged.

7. **No attachment is opened or scanned.** Filenames are noticed; file contents are not examined.

8. **Spelling is a weak and biased signal.** Non-native but entirely legitimate business English can score badly, while professional criminal operations proofread carefully.

9. **No context about the recipient.** The program cannot know whether you actually bank with a given institution, whether you were expecting a delivery, or whether this sender has written to you before — all of which a human judges instantly.

10. **Image-based and QR-code phishing is invisible.** Attackers increasingly put the entire message in an image or a QR code, leaving no text to analyse at all.

**The conclusion a security team would draw: automated detection reduces volume, but the trained human remains the last line of defence. That is precisely why awareness projects like this one exist.**

---

## 12. Suggestions for future improvements

1. **Verify email authentication** by parsing real message headers and checking SPF, DKIM and DMARC results, which would make sender spoofing far harder to hide.
2. **Integrate a reputation feed** such as Google Safe Browsing or PhishTank so links can be checked against known-bad lists rather than judged on structure alone.
3. **Add homoglyph and punycode detection** for domains using Cyrillic or Greek characters that render identically to Latin ones (`раypal.com` with a Cyrillic *а*).
4. **Machine-learning classification** trained on a labelled corpus such as the Enron and Nazario phishing datasets, compared side by side against the rule-based engine to show the trade-off between accuracy and explainability.
5. **Parse real `.eml` files** so messages can be analysed exactly as received, headers included, instead of being pasted as plain text.
6. **Expand beyond English** with keyword sets for Hindi, Kannada and other languages, since regional-language phishing is growing quickly.
7. **Attachment analysis** — inspect file types and macro presence in a safe, isolated environment.
8. **A whitelist of known-good sender domains** for the organisation, to cut false positives on routine internal mail.
9. **A web interface** using Flask, with a colour-coded report and hover-to-reveal link destinations, making it usable in a live awareness workshop.
10. **A quiz mode** that shows a message, asks the user to classify it, then reveals the program's analysis — turning the tool from an analyser into a genuine training exercise.
11. **Batch analysis with statistics** over a folder of messages, producing the kind of trend report a security team would present to management.
12. **A one-click reporting workflow** that formats a flagged message for submission to an internal security team, reinforcing the reporting habit the checklist promotes.
