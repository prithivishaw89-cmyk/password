import math
import re
import hashlib
import requests

class PasswordSecurityAssessment:
    def __init__(self):
        # Regular expressions for predictable pattern identification
        self.patterns = {
            'sequential_digits': r'(012|123|234|345|456|567|678|789|890|987|876|765|654|543|432|321|210)',
            'sequential_letters': r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)',
            'keyboard_walks': r'(qwerty|asdfgh|zxcvbn|qwertz|azerty)',
            'repeating_chars': r'(.)\1{2,}',  # Same character repeated 3+ times consecutively
        }

    def analyze_entropy(self, password: str) -> dict:
        """Calculates mathematical entropy: E = L * log2(R)"""
        if not password:
            return {"entropy_bits": 0.0, "pool_size": 0, "length": 0}

        pool_size = 0
        if re.search(r'[a-z]', password): pool_size += 26
        if re.search(r'[A-Z]', password): pool_size += 26
        if re.search(r'[0-9]', password): pool_size += 10
        if re.search(r'[^a-zA-Z0-9]', password): pool_size += 32

        length = len(password)
        entropy = length * math.log2(pool_size) if pool_size > 0 else 0.0

        return {
            "entropy_bits": round(entropy, 2),
            "pool_size": pool_size,
            "length": length
        }

    def detect_weaknesses(self, password: str) -> list:
        """Scans for structural weaknesses and predictable patterns."""
        vulnerabilities = []
        pwd_lower = password.lower()

        # Pattern scanning
        for pattern_name, regex in self.patterns.items():
            if re.search(regex, pwd_lower):
                vulnerabilities.append(f"Contains {pattern_name.replace('_', ' ')}")

        # Length and complexity requirements
        if len(password) < 12:
            vulnerabilities.append("Length is under 12 characters (recommended minimum: 12-16+)")
        if not re.search(r'[A-Z]', password):
            vulnerabilities.append("Missing uppercase letters")
        if not re.search(r'[a-z]', password):
            vulnerabilities.append("Missing lowercase letters")
        if not re.search(r'[0-9]', password):
            vulnerabilities.append("Missing numerical digits")
        if not re.search(r'[^a-zA-Z0-9]', password):
            vulnerabilities.append("Missing special symbols")

        return vulnerabilities

    def generate_recommendations(self, vulnerabilities: list, is_breached: bool) -> list:
        """Generates dynamic improvement suggestions based on identified weaknesses."""
        suggestions = []
        if is_breached:
            suggestions.append("🚨 **Immediate Action:** Change this password everywhere. It appears in known data leaks.")
        if any("under 12 characters" in v for v in vulnerabilities):
            suggestions.append("💡 **Increase Length:** Use a passphrase with 4+ random words (e.g., `correct-horse-battery-staple`).")
        if any("sequential" in v or "walks" in v for v in vulnerabilities):
            suggestions.append("💡 **Eliminate Patterns:** Avoid keyboard patterns like `qwerty` or consecutive sequences like `123`.")
        if any("Missing" in v for v in vulnerabilities):
            suggestions.append("💡 **Diversify Characters:** Mix upper/lowercase letters, digits, and special characters.")
        
        if not suggestions:
            suggestions.append("✨ **Great Job:** Your password structure follows security best practices!")
            
        return suggestions

    def check_pwned_api(self, password: str) -> dict:
        """Queries HaveIBeenPwned API using k-Anonymity (SHA-1 hash prefixing)."""
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix, suffix = sha1_hash[:5], sha1_hash[5:]
        url = f"https://api.pwnedpasswords.com/range/{prefix}"

        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                hashes = (line.split(':') for line in response.text.splitlines())
                for h_suffix, count in hashes:
                    if h_suffix == suffix:
                        return {"is_breached": True, "breach_count": int(count)}
            return {"is_breached": False, "breach_count": 0}
        except requests.RequestException:
            return {"is_breached": False, "breach_count": 0, "error": "API unreachable"}

    def estimate_brute_force_time(self, entropy_bits: float) -> str:
        """Estimates crack time assuming a 10 billion hashes/sec offline GPU attack."""
        if entropy_bits == 0:
            return "Instantaneous"
        
        combinations = 2 ** entropy_bits
        guesses_per_sec = 10_000_000_000  # 10 billion/sec (GPU cluster)
        seconds = combinations / guesses_per_sec

        if seconds < 1: return "< 1 second (Instant)"
        if seconds < 60: return f"{int(seconds)} seconds"
        if seconds < 3600: return f"{int(seconds // 60)} minutes"
        if seconds < 86400: return f"{int(seconds // 3600)} hours"
        if seconds < 31536000: return f"{int(seconds // 86400)} days"
        if seconds < 3153600000: return f"{int(seconds // 31536000)} years"
        return "Centuries / Practically Unbreakable"

    def generate_assessment(self, password: str) -> dict:
        """Aggregates metrics, breach checks, recommendations, and scoring into a single report."""
        entropy_data = self.analyze_entropy(password)
        vulnerabilities = self.detect_weaknesses(password)
        breach_data = self.check_pwned_api(password)
        crack_time = self.estimate_brute_force_time(entropy_data["entropy_bits"])
        recommendations = self.generate_recommendations(vulnerabilities, breach_data.get("is_breached", False))

        # Security Score Calculation (0 to 100)
        score = min(100, int((entropy_data["entropy_bits"] / 80) * 100))
        if breach_data.get("is_breached"):
            score = max(0, score - 50)  # Significant penalty for leaked passwords
        score -= len(vulnerabilities) * 5
        score = max(0, min(100, score))

        return {
            "score": score,
            "entropy": entropy_data,
            "vulnerabilities": vulnerabilities,
            "breach_data": breach_data,
            "crack_time": crack_time,
            "recommendations": recommendations
        }