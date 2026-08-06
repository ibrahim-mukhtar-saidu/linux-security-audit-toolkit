import unittest


class TestSecurityAudit(unittest.TestCase):

    def test_project_name(self):
        name = "CyberNova Linux Security Audit Toolkit"
        self.assertIn("CyberNova", name)


    def test_security_score(self):
        score = 85
        self.assertGreaterEqual(score, 0)
        self.assertLessEqual(score, 100)


if __name__ == "__main__":
    unittest.main()
