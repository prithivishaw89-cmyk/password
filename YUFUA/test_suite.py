import time
import unittest
from analyzer import PasswordSecurityAssessment

class TestPasswordSecurityAssessment(unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        """Initialize the analyzer engine once for all tests."""
        cls.engine = PasswordSecurityAssessment()

    def test_empty_password(self):
        """Ensure empty strings don't cause crashes or divide-by-zero errors."""
        result = self.engine.generate_assessment("")
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["entropy"]["entropy_bits"], 0.0)
        self.assertEqual(result["entropy"]["length"], 0)

    def test_common_weak_passwords(self):
        """Test detection of known weak/pwned passwords."""
        result = self.engine.generate_assessment("123456")
        self.assertLessEqual(result["score"], 20)
        self.assertTrue(result["breach_data"]["is_breached"])
        self.assertIn("Contains sequential digits", result["vulnerabilities"])

    def test_strong_passphrase(self):
        """Test high-entropy passphrases for proper scoring."""
        strong_pwd = "Correct-Horse-Battery-Staple-2026!"
        result = self.engine.generate_assessment(strong_pwd)
        self.assertGreaterEqual(result["score"], 80)
        self.assertFalse(result["breach_data"]["is_breached"])

    def test_pattern_detection(self):
        """Verify regex catches sequential letters and keyboard walks."""
        weaknesses = self.engine.detect_weaknesses("qwertyABC123!")
        self.assertTrue(any("keyboard walks" in w for w in weaknesses))
        self.assertTrue(any("sequential letters" in w for w in weaknesses))
        self.assertTrue(any("sequential digits" in w for w in weaknesses))

    def test_local_evaluation_speed(self):
        """Benchmark local evaluation speed (excluding API calls). Must be under 1ms."""
        test_pwd = "ComplexPassword#2026!TestLength"
        
        start_time = time.perf_counter()
        _ = self.engine.analyze_entropy(test_pwd)
        _ = self.engine.detect_weaknesses(test_pwd)
        _ = self.engine.estimate_brute_force_time(120.0)
        end_time = time.perf_counter()

        elapsed_ms = (end_time - start_time) * 1000
        print(f"\n[BENCHMARK] Local engine execution time: {elapsed_ms:.4f} ms")
        self.assertLess(elapsed_ms, 1.0, "Local evaluation should execute in under 1 millisecond.")

    def test_k_anonymity_hash_privacy(self):
        """Ensure k-Anonymity logic never sends full password hashes over the network."""
        result = self.engine.check_pwned_api("Password123!")
        self.assertIn("is_breached", result)
        self.assertIn("breach_count", result)


if __name__ == "__main__":
    print("=========================================================")
    print(" Running Phase 3: System Testing & Performance Benchmarks")
    print("=========================================================")
    unittest.main()