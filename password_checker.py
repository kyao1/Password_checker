"""
password_checker.py
-------------------
A command-line tool to evaluate password strength based on
common security requirements used in the industry.

Author : Konan Yao
GitHub : github.com/kyao1
"""

import re
import sys


# ── Scoring rules ─────────────────────────────────────────────────────────────

CHECKS = [
    {
        "id":      "length_8",
        "label":   "At least 8 characters",
        "test":    lambda p: len(p) >= 8,
        "points":  1,
    },
    {
        "id":      "length_12",
        "label":   "At least 12 characters (recommended)",
        "test":    lambda p: len(p) >= 12,
        "points":  1,
    },
    {
        "id":      "uppercase",
        "label":   "Contains uppercase letter (A-Z)",
        "test":    lambda p: bool(re.search(r"[A-Z]", p)),
        "points":  1,
    },
    {
        "id":      "lowercase",
        "label":   "Contains lowercase letter (a-z)",
        "test":    lambda p: bool(re.search(r"[a-z]", p)),
        "points":  1,
    },
    {
        "id":      "digit",
        "label":   "Contains a number (0-9)",
        "test":    lambda p: bool(re.search(r"\d", p)),
        "points":  1,
    },
    {
        "id":      "special",
        "label":   "Contains special character (!@#$%^&*...)",
        "test":    lambda p: bool(re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?`~]", p)),
        "points":  2,   # worth more — strongest signal
    },
    {
        "id":      "no_spaces",
        "label":   "No spaces",
        "test":    lambda p: " " not in p,
        "points":  1,
    },
    {
        "id":      "no_repeat",
        "label":   "No repeated characters 3+ times in a row (e.g. 'aaa')",
        "test":    lambda p: not bool(re.search(r"(.)\1{2,}", p)),
        "points":  1,
    },
    {
        "id":      "no_common",
        "label":   "Not a common password",
        "test":    lambda p: p.lower() not in COMMON_PASSWORDS,
        "points":  2,
    },
]

MAX_SCORE = sum(c["points"] for c in CHECKS)

COMMON_PASSWORDS = {
    "password", "123456", "password1", "12345678", "qwerty",
    "abc123", "letmein", "monkey", "1234567", "dragon",
    "111111", "baseball", "iloveyou", "trustno1", "sunshine",
    "master", "welcome", "shadow", "superman", "michael",
    "password123", "admin", "root", "passw0rd", "hello",
}


# ── Strength label ────────────────────────────────────────────────────────────

def get_strength(score: int, max_score: int) -> tuple[str, str]:
    """Return (label, advice) based on score percentage."""
    pct = score / max_score

    if pct < 0.35:
        return "WEAK", "This password would be cracked almost instantly. Improve it now."
    elif pct < 0.60:
        return "FAIR", "Better, but still vulnerable. Add more variety."
    elif pct < 0.80:
        return "GOOD", "Decent password. A few more improvements would make it strong."
    elif pct < 1.0:
        return "STRONG", "Strong password! Only minor improvements possible."
    else:
        return "VERY STRONG", "Excellent password. This meets all security requirements."


# ── Display helpers ───────────────────────────────────────────────────────────

def color(text: str, code: str) -> str:
    """Wrap text in ANSI color code (terminal only)."""
    return f"\033[{code}m{text}\033[0m"

STRENGTH_COLORS = {
    "WEAK":        "91",   # red
    "FAIR":        "93",   # yellow
    "GOOD":        "94",   # blue
    "STRONG":      "92",   # green
    "VERY STRONG": "92",   # green
}

def strength_bar(score: int, max_score: int, width: int = 30) -> str:
    filled = round((score / max_score) * width)
    bar = "█" * filled + "░" * (width - filled)
    return f"[{bar}] {score}/{max_score}"


# ── Core checker ──────────────────────────────────────────────────────────────

def check_password(password: str) -> dict:
    """
    Run all checks against a password.
    Returns a results dict with score, strength label, and per-check details.
    """
    results = []
    total_score = 0

    for check in CHECKS:
        passed = check["test"](password)
        if passed:
            total_score += check["points"]
        results.append({
            "label":  check["label"],
            "passed": passed,
            "points": check["points"],
        })

    strength, advice = get_strength(total_score, MAX_SCORE)

    return {
        "password":    password,
        "score":       total_score,
        "max_score":   MAX_SCORE,
        "strength":    strength,
        "advice":      advice,
        "checks":      results,
    }


def print_report(result: dict) -> None:
    """Pretty-print the analysis report to the terminal."""
    pw = result["password"]
    masked = pw[0] + "*" * (len(pw) - 2) + pw[-1] if len(pw) > 2 else "***"

    print()
    print("=" * 50)
    print(f"  PASSWORD STRENGTH REPORT")
    print(f"  Password : {masked}  ({len(pw)} characters)")
    print("=" * 50)

    print("\n  REQUIREMENTS CHECK\n")
    for c in result["checks"]:
        icon = color("✔", "92") if c["passed"] else color("✘", "91")
        pts  = f"(+{c['points']}pt)" if c["passed"] else f"     "
        print(f"  {icon}  {c['label']:<50} {pts}")

    print()
    label  = result["strength"]
    bar    = strength_bar(result["score"], result["max_score"])
    clabel = color(label, STRENGTH_COLORS[label])

    print(f"  SCORE   : {bar}")
    print(f"  RATING  : {clabel}")
    print(f"  VERDICT : {result['advice']}")
    print("=" * 50)
    print()


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    print("\n  ╔══════════════════════════════════╗")
    print("  ║   PASSWORD STRENGTH CHECKER      ║")
    print("  ║   by Konan Achille Yao            ║")
    print("  ╚══════════════════════════════════╝")

    # Allow passing password as CLI argument or prompt interactively
    if len(sys.argv) > 1:
        passwords = sys.argv[1:]
    else:
        passwords = []
        print("\n  Enter passwords to check (type 'quit' to exit)\n")
        while True:
            try:
                pw = input("  > Enter password: ").strip()
            except (KeyboardInterrupt, EOFError):
                print("\n  Exiting. Stay secure!")
                break
            if pw.lower() in ("quit", "exit", "q"):
                print("\n  Exiting. Stay secure!")
                break
            if pw:
                result = check_password(pw)
                print_report(result)

    for pw in passwords:
        result = check_password(pw)
        print_report(result)


if __name__ == "__main__":
    main()
