"""
=============================================================================
 TEST CASES for phishing_analyzer.py
=============================================================================

 These tests prove that each detection rule works, that the four training
 examples land in the right band, and - just as importantly - that ordinary
 harmless email is NOT flagged.

 Every address and domain used below is fictional.

 Run with:  python test_phishing.py
=============================================================================
"""

import unittest

from phishing_analyzer import (
    extract_urls,
    check_keywords,
    analyze_urls,
    check_link_mismatch,
    check_sender,
    check_writing_style,
    detect_red_flags,
    calculate_risk_score,
    count_critical_indicators,
    count_red_flags,
    analyze_message,
    generate_report,
    edit_distance,
    get_domain,
    get_registered_domain,
    EXAMPLE_MESSAGES,
    PHISHING_CHECKLIST,
)


def build(body, subject="", name="", address="", reply_to=""):
    """Small helper so the tests read cleanly."""
    return {
        "sender_name": name,
        "sender_address": address,
        "reply_to": reply_to,
        "subject": subject,
        "body": body,
    }


class TestHelpers(unittest.TestCase):
    """The small utility functions."""

    def test_edit_distance(self):
        self.assertEqual(edit_distance("paypal", "paypal"), 0)
        self.assertEqual(edit_distance("paypal", "paypa1"), 1)
        self.assertEqual(edit_distance("amazon", "arnazon"), 2)

    def test_get_domain(self):
        self.assertEqual(get_domain("https://www.example.com/login?id=3"),
                         "example.com")
        self.assertEqual(get_domain("http://sub.site.example.co:8080/path"),
                         "sub.site.example.co")

    def test_get_registered_domain(self):
        self.assertEqual(get_registered_domain("login.secure.example.com"),
                         "example.com")


class TestUrlExtraction(unittest.TestCase):
    """extract_urls() must find links and ignore sentence punctuation."""

    def test_finds_http_and_https(self):
        urls = extract_urls("Go to https://a.example and http://b.example now")
        self.assertEqual(len(urls), 2)

    def test_finds_bare_www(self):
        self.assertIn("www.example.com", extract_urls("visit www.example.com"))

    def test_strips_trailing_full_stop(self):
        urls = extract_urls("See https://example.com/page.")
        self.assertEqual(urls[0], "https://example.com/page")

    def test_no_urls_in_plain_text(self):
        self.assertEqual(extract_urls("Just a normal sentence."), [])


class TestKeywordDetection(unittest.TestCase):
    """check_keywords() must group matches by category."""

    def test_detects_urgency(self):
        findings = check_keywords("Please act now, this is urgent")
        categories = [f["category"] for f in findings]
        self.assertIn("Urgency pressure", categories)

    def test_detects_credential_request_as_critical(self):
        findings = check_keywords("Send us your password and OTP")
        credential = [f for f in findings
                      if f["category"] == "Request for sensitive information"]
        self.assertEqual(len(credential), 1)
        self.assertTrue(credential[0]["critical"])

    def test_clean_message_has_no_keyword_findings(self):
        self.assertEqual(check_keywords("Lunch at one o'clock?"), [])

    def test_points_are_capped_per_category(self):
        # Many urgency terms at once must not run away with the score
        text = ("urgent immediately act now right away hurry last warning "
                "final notice expires today limited time don't delay")
        findings = check_keywords(text)
        urgency = [f for f in findings if f["category"] == "Urgency pressure"][0]
        self.assertLessEqual(urgency["points"], 6)


class TestUrlAnalysis(unittest.TestCase):
    """analyze_urls() structural checks."""

    def test_ip_address_is_critical(self):
        result = analyze_urls(["http://192.168.10.55/login"])[0]
        self.assertTrue(result["critical"])

    def test_at_symbol_trick_detected(self):
        result = analyze_urls(["http://paypal.com@tricky.example/"])[0]
        self.assertTrue(result["critical"])
        self.assertTrue(any("@" in flag for flag in result["flags"]))

    def test_shortener_detected(self):
        result = analyze_urls(["http://bit.ly/abc123"])[0]
        self.assertTrue(any("Shortened" in flag for flag in result["flags"]))

    def test_shortener_is_not_called_a_lookalike(self):
        # Regression test: 'bit' is 2 edits from 'sbi' but is not an imitation
        result = analyze_urls(["http://bit.ly/abc123"])[0]
        self.assertFalse(any("lookalike" in flag for flag in result["flags"]))

    def test_lookalike_domain_detected(self):
        result = analyze_urls(["http://paypa1-secure-verify.xyz/login"])[0]
        self.assertTrue(any("lookalike" in flag for flag in result["flags"]))
        self.assertTrue(result["critical"])

    def test_brand_in_subdomain_detected(self):
        result = analyze_urls(["http://amazon.verify-account.example/signin"])[0]
        self.assertTrue(result["critical"])

    def test_suspicious_tld_detected(self):
        result = analyze_urls(["http://offers.example.xyz/claim"])[0]
        self.assertTrue(any(".xyz" in flag for flag in result["flags"]))

    def test_ordinary_url_has_no_flags(self):
        result = analyze_urls(["https://wiki.northwind-demo.example/notes"])[0]
        self.assertEqual(result["flags"], [])
        self.assertEqual(result["points"], 0)


class TestLinkMismatch(unittest.TestCase):
    """Displayed text must match the real destination."""

    def test_html_mismatch_detected(self):
        text = ('<a href="http://evil.example/login">'
                'https://www.mybank.example</a>')
        findings = check_link_mismatch(text)
        self.assertEqual(len(findings), 1)
        self.assertTrue(findings[0]["critical"])

    def test_markdown_mismatch_detected(self):
        text = "[www.mybank.example](http://evil.example)"
        self.assertEqual(len(check_link_mismatch(text)), 1)

    def test_matching_link_is_not_flagged(self):
        text = '<a href="https://example.com/page">https://example.com/page</a>'
        self.assertEqual(check_link_mismatch(text), [])

    def test_plain_words_as_link_text_are_not_flagged(self):
        # "Click here" is not itself an address, so there is nothing to compare
        text = '<a href="https://example.com/page">Click here</a>'
        self.assertEqual(check_link_mismatch(text), [])


class TestSenderAnalysis(unittest.TestCase):
    """check_sender() rules."""

    def test_missing_sender_returns_nothing(self):
        self.assertEqual(check_sender("", "", "", "some text"), [])

    def test_reply_to_mismatch_detected(self):
        findings = check_sender("Support", "help@company.example",
                                "collect@elsewhere.example", "hello")
        flags = [f["flag"] for f in findings]
        self.assertIn("Reply-To address differs from the sender address", flags)

    def test_display_name_mismatch_detected(self):
        findings = check_sender("Netflix Billing", "random@unrelated.example",
                                "", "your account")
        self.assertTrue(any(f["critical"] for f in findings))

    def test_executive_impersonation_detected(self):
        findings = check_sender("Rajesh Menon (CEO)", "rm4471@mail.com",
                                "", "urgent payment")
        flags = [f["flag"] for f in findings]
        self.assertIn("Senior staff impersonation from an outside account", flags)

    def test_auto_generated_username_detected(self):
        findings = check_sender("", "security99281554@gmail.com", "", "hello")
        flags = [f["flag"] for f in findings]
        self.assertIn("Sender username looks auto-generated", flags)

    def test_normal_corporate_sender_is_clean(self):
        findings = check_sender("Priya Nair", "priya.nair@northwind-demo.example",
                                "", "Meeting notes attached")
        self.assertEqual(findings, [])


class TestWritingStyle(unittest.TestCase):
    """Grammar, spelling and formatting checks."""

    def test_generic_greeting_detected(self):
        findings = check_writing_style("Dear Customer, your order shipped")
        flags = [f["flag"] for f in findings]
        self.assertIn("Generic greeting instead of your name", flags)

    def test_misspellings_detected(self):
        findings = check_writing_style("Please verifiy your acount")
        flags = [f["flag"] for f in findings]
        self.assertIn("Spelling or phrasing errors", flags)

    def test_dangerous_attachment_detected(self):
        findings = check_writing_style("Open the attached invoice_2024.exe now")
        self.assertTrue(any(f["critical"] for f in findings))

    def test_excessive_punctuation_detected(self):
        findings = check_writing_style("Act now!!! Your account is at risk")
        flags = [f["flag"] for f in findings]
        self.assertIn("Excessive exclamation or question marks", flags)

    def test_normal_writing_is_clean(self):
        text = "Hi Arjun, thanks for the update. I will review it on Friday."
        self.assertEqual(check_writing_style(text), [])


class TestScoringRules(unittest.TestCase):
    """The scoring and classification logic."""

    def test_empty_message_scores_zero(self):
        analysis = detect_red_flags(build(""))
        score, level, classification, critical = calculate_risk_score(analysis)
        self.assertEqual(score, 0)
        self.assertEqual(classification, "LIKELY LEGITIMATE")

    def test_one_keyword_alone_is_not_phishing(self):
        # The brief requires that a single keyword never decides the outcome
        analysis = detect_red_flags(build("This is urgent, please reply."))
        score, level, classification, critical = calculate_risk_score(analysis)
        self.assertNotEqual(classification, "LIKELY PHISHING")

    def test_high_score_without_critical_indicator_is_only_suspicious(self):
        # Lots of soft marketing buzzwords, nothing conclusive
        text = ("Congratulations! You have won a free gift. Claim your reward "
                "today, limited time offer, hurry, expires today!")
        analysis = detect_red_flags(build(text))
        score, level, classification, critical = calculate_risk_score(analysis)
        self.assertEqual(critical, 0)
        self.assertEqual(classification, "SUSPICIOUS")

    def test_critical_indicators_push_to_phishing(self):
        text = ("Dear Customer, your acount has been suspended. Verify your "
                "account within 24 hours or it will be permanently deleted. "
                "Enter your password and OTP at "
                "http://paypa1-secure-verify.xyz/login")
        analysis = detect_red_flags(build(text))
        score, level, classification, critical = calculate_risk_score(analysis)
        self.assertGreaterEqual(critical, 1)
        self.assertEqual(classification, "LIKELY PHISHING")
        self.assertEqual(level, "HIGH")

    def test_red_flag_count_matches_findings(self):
        analysis = detect_red_flags(EXAMPLE_MESSAGES[2])
        self.assertGreater(count_red_flags(analysis), 5)
        self.assertGreater(count_critical_indicators(analysis), 0)


class TestTrainingExamples(unittest.TestCase):
    """Each built-in example must land in its expected band."""

    def test_example_1_legitimate(self):
        result = analyze_message(EXAMPLE_MESSAGES[0])
        self.assertEqual(result["classification"], "LIKELY LEGITIMATE")
        self.assertEqual(result["red_flag_count"], 0)

    def test_example_2_suspicious(self):
        result = analyze_message(EXAMPLE_MESSAGES[1])
        self.assertEqual(result["classification"], "SUSPICIOUS")

    def test_example_3_phishing(self):
        result = analyze_message(EXAMPLE_MESSAGES[2])
        self.assertEqual(result["classification"], "LIKELY PHISHING")
        self.assertEqual(result["risk_level"], "HIGH")

    def test_example_4_business_email_compromise(self):
        # Note: this one has NO links at all, yet is still caught
        result = analyze_message(EXAMPLE_MESSAGES[3])
        self.assertEqual(result["classification"], "LIKELY PHISHING")
        self.assertEqual(result["analysis"]["urls"], [])

    def test_all_examples_match_their_label(self):
        for example in EXAMPLE_MESSAGES:
            result = analyze_message(example)
            self.assertEqual(result["classification"], example["expected"],
                             "Mismatch on: " + example["label"])


class TestFalsePositives(unittest.TestCase):
    """Ordinary messages must NOT be accused of being phishing."""

    def test_plain_personal_email(self):
        message = build("Hi, are we still on for dinner on Saturday?",
                        subject="Weekend", name="Meera",
                        address="meera@northwind-demo.example")
        self.assertEqual(analyze_message(message)["classification"],
                         "LIKELY LEGITIMATE")

    def test_legitimate_password_reset_is_not_auto_condemned(self):
        # Mentions 'password' once, which must not be enough on its own
        message = build("You asked to reset your password. If this was not "
                        "you, ignore this email.",
                        subject="Password reset",
                        address="noreply@northwind-demo.example")
        self.assertNotEqual(analyze_message(message)["classification"],
                            "LIKELY PHISHING")

    def test_normal_newsletter_with_a_link(self):
        message = build("This month's engineering newsletter is out. Read it "
                        "at https://blog.northwind-demo.example/march",
                        address="news@northwind-demo.example")
        self.assertEqual(analyze_message(message)["classification"],
                         "LIKELY LEGITIMATE")


class TestReportGeneration(unittest.TestCase):
    """The report must be complete and must never invent a verdict."""

    def test_report_contains_all_required_sections(self):
        result = analyze_message(EXAMPLE_MESSAGES[2])
        text = "\n".join(generate_report(EXAMPLE_MESSAGES[2],
                                         result["analysis"], result["score"],
                                         result["risk_level"],
                                         result["classification"],
                                         result["critical_count"]))
        for heading in ["PHISHING ANALYSIS REPORT", "Risk Score",
                        "Classification", "SUSPICIOUS KEYWORDS",
                        "URLS FOUND", "VERDICT", "RECOMMENDED ACTION"]:
            self.assertIn(heading, text)

    def test_safe_report_still_warns_against_complacency(self):
        result = analyze_message(EXAMPLE_MESSAGES[0])
        text = "\n".join(generate_report(EXAMPLE_MESSAGES[0],
                                         result["analysis"], result["score"],
                                         result["risk_level"],
                                         result["classification"],
                                         result["critical_count"]))
        self.assertIn("NOT a guarantee", text)


class TestChecklist(unittest.TestCase):
    """The awareness checklist must be usable."""

    def test_checklist_has_sections_and_questions(self):
        self.assertGreaterEqual(len(PHISHING_CHECKLIST), 5)
        for section_name, questions in PHISHING_CHECKLIST:
            self.assertGreater(len(questions), 2)
            for question in questions:
                self.assertTrue(question.endswith("?"))


class TestEdgeCases(unittest.TestCase):
    """Unusual input must not crash the analyser."""

    def test_missing_fields(self):
        result = analyze_message({"body": "hello"})
        self.assertIn("classification", result)

    def test_very_long_message(self):
        result = analyze_message(build("word " * 5000))
        self.assertEqual(result["classification"], "LIKELY LEGITIMATE")

    def test_message_of_only_urls(self):
        result = analyze_message(build("http://1.2.3.4/login http://bit.ly/x"))
        self.assertGreater(result["score"], 0)

    def test_malformed_sender_address(self):
        findings = check_sender("Someone", "not-an-email", "", "hello")
        self.assertEqual(len(findings), 1)

    def test_unicode_message(self):
        result = analyze_message(build("नमस्ते, यह एक सामान्य संदेश है।"))
        self.assertEqual(result["classification"], "LIKELY LEGITIMATE")


if __name__ == "__main__":
    unittest.main(verbosity=2)
