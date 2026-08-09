import unittest

import security_audit


class TestSecurityAudit(unittest.TestCase):

    def test_project_name(self):
        name = "CyberNova Linux Security Audit Toolkit"
        self.assertIn("CyberNova", name)

    def test_version_exists(self):
        self.assertEqual(security_audit.VERSION, "3.1")

    def test_author_exists(self):
        self.assertEqual(
            security_audit.AUTHOR,
            "Ibrahim Mukhtar Saidu"
        )

    def test_security_score_range(self):
        score, findings = security_audit.analyze_security(
            [],
            [],
            []
        )

        self.assertGreaterEqual(score, 0)
        self.assertLessEqual(score, 100)
        self.assertEqual(findings, [])

    def test_world_writable_files_reduce_score(self):
        score, findings = security_audit.analyze_security(
            ["/tmp/test.txt"],
            [],
            []
        )

        self.assertEqual(score, 80)
        self.assertTrue(
            any("World-writable" in finding for finding in findings)
        )

    def test_many_ports_reduce_score(self):
        ports = [22, 53, 80, 443, 631, 5353]

        score, findings = security_audit.analyze_security(
            [],
            [],
            ports
        )

        self.assertEqual(score, 90)
        self.assertTrue(
            any("listening ports" in finding for finding in findings)
        )

    def test_suid_detection_adds_finding(self):
        score, findings = security_audit.analyze_security(
            [],
            ["/usr/bin/sudo"],
            []
        )

        self.assertEqual(score, 100)
        self.assertTrue(
            any("SUID binaries" in finding for finding in findings)
        )

    def test_multiple_risks_reduce_score(self):
        ports = [22, 53, 80, 443, 631, 5353]

        score, findings = security_audit.analyze_security(
            ["/tmp/test.txt"],
            ["/usr/bin/sudo"],
            ports
        )

        self.assertEqual(score, 70)
        self.assertEqual(len(findings), 3)


if __name__ == "__main__":
    unittest.main()
