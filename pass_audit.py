#!/usr/bin/env python3
"""
Password Strength & Policy Auditor

Educational tool for evaluating password strength using basic security rules,
estimated entropy, common-password checks, and secure password generation.

Do not provide real passwords through command-line arguments on shared systems.
Use this only for passwords you own or for authorized educational testing.
"""

import argparse
import math
import re
import secrets
import string
from getpass import getpass


COMMON_PASSWORDS = {
    "password",
    "password123",
    "123456",
    "12345678",
    "123456789",
    "1234567890",
    "qwerty",
    "qwerty123",
    "admin",
    "admin123",
    "welcome",
    "welcome123",
    "letmein",
    "iloveyou",
    "india123",
    "college123",
    "student123",
    "mvjcollege",
    "football",
    "monkey",
    "dragon",
}


POLICIES = {
    "basic": {
        "min_length": 8,
        "require_lower": True,
        "require_upper": True,
        "require_digit": True,
        "require_symbol": False,
        "min_entropy": 40,
    },
    "college": {
        "min_length": 10,
        "require_lower": True,
        "require_upper": True,
        "require_digit": True,
        "require_symbol": True,
        "min_entropy": 55,
    },
    "enterprise": {
        "min_length": 14,
        "require_lower": True,
        "require_upper": True,
        "require_digit": True,
        "require_symbol": True,
        "min_entropy": 70,
    },
}


def character_pool_size(password):
    """Estimate the size of the character pool used in a password."""
    pool = 0

    if any(char.islower() for char in password):
        pool += 26
    if any(char.isupper() for char in password):
        pool += 26
    if any(char.isdigit() for char in password):
        pool += 10
    if any(char in string.punctuation for char in password):
        pool += len(string.punctuation)

    return pool


def estimate_entropy(password):
    """
    Estimate password entropy in bits using:
    entropy = length × log2(character_pool_size)

    This is an estimate only; real password strength is also affected by
    predictable words, patterns, and password reuse.
    """
    pool = character_pool_size(password)

    if not password or pool == 0:
        return 0.0

    return len(password) * math.log2(pool)


def has_repeated_characters(password, repeat_count=3):
    """Detect three or more identical characters in a row, e.g. aaa or 111."""
    pattern = rf"(.)\1{{{repeat_count - 1},}}"
    return bool(re.search(pattern, password))


def has_common_sequence(password):
    """Detect simple predictable sequences."""
    lowered = password.lower()

    sequences = [
        "0123", "1234", "2345", "3456", "4567", "5678", "6789", "7890",
        "abcd", "bcde", "cdef", "defg", "efgh", "fghi", "ghij",
        "qwer", "wert", "erty", "tyui", "yuiop",
        "asdf", "sdfg", "dfgh", "fghj", "ghjk",
        "zxcv", "xcvb", "cvbn",
    ]

    return any(sequence in lowered for sequence in sequences)


def contains_common_word(password):
    """Detect weak words commonly used in passwords."""
    weak_words = [
        "password",
        "admin",
        "welcome",
        "student",
        "college",
        "india",
        "love",
        "hello",
        "user",
        "login",
    ]

    lowered = password.lower()
    return any(word in lowered for word in weak_words)


def check_policy(password, policy_name):
    """Audit a password against a selected policy and return findings."""
    policy = POLICIES[policy_name]
    findings = []
    suggestions = []

    has_lower = any(char.islower() for char in password)
    has_upper = any(char.isupper() for char in password)
    has_digit = any(char.isdigit() for char in password)
    has_symbol = any(char in string.punctuation for char in password)

    if len(password) < policy["min_length"]:
        findings.append(
            f"Too short: {len(password)} characters "
            f"(minimum: {policy['min_length']})."
        )
        suggestions.append(
            f"Use at least {policy['min_length']} characters."
        )

    if policy["require_lower"] and not has_lower:
        findings.append("Missing lowercase letters.")
        suggestions.append("Add lowercase letters, such as a-z.")

    if policy["require_upper"] and not has_upper:
        findings.append("Missing uppercase letters.")
        suggestions.append("Add uppercase letters, such as A-Z.")

    if policy["require_digit"] and not has_digit:
        findings.append("Missing digits.")
        suggestions.append("Add numbers, such as 0-9.")

    if policy["require_symbol"] and not has_symbol:
        findings.append("Missing symbols.")
        suggestions.append("Add a symbol, such as !, @, #, or %.")

    if password.lower() in COMMON_PASSWORDS:
        findings.append("Password is in the common-password list.")
        suggestions.append("Avoid passwords that are widely known or easily guessed.")

    if contains_common_word(password):
        findings.append("Contains a predictable common word.")
        suggestions.append("Avoid obvious words such as password, admin, or college.")

    if has_repeated_characters(password):
        findings.append("Contains repeated characters, such as aaa or 111.")
        suggestions.append("Avoid repeated character patterns.")

    if has_common_sequence(password):
        findings.append("Contains a predictable sequence, such as 1234 or qwer.")
        suggestions.append("Avoid keyboard and number sequences.")

    entropy = estimate_entropy(password)

    if entropy < policy["min_entropy"]:
        findings.append(
            f"Estimated entropy is low: {entropy:.1f} bits "
            f"(target: {policy['min_entropy']} bits)."
        )
        suggestions.append(
            "Increase length and use a less predictable mix of characters."
        )

    return {
        "policy": policy_name,
        "entropy": entropy,
        "findings": findings,
        "suggestions": suggestions,
        "length": len(password),
        "has_lower": has_lower,
        "has_upper": has_upper,
        "has_digit": has_digit,
        "has_symbol": has_symbol,
    }


def calculate_score(result):
    """Calculate a 0-100 score based on policy compliance and entropy."""
    score = 100

    score -= min(len(result["findings"]) * 12, 72)

    if result["entropy"] < 30:
        score -= 20
    elif result["entropy"] < 50:
        score -= 10

    return max(0, min(score, 100))


def strength_label(score):
    """Convert the numeric score to a readable strength category."""
    if score >= 85:
        return "Strong"
    if score >= 65:
        return "Moderate"
    if score >= 40:
        return "Weak"
    return "Very Weak"


def print_report(result):
    """Display a readable audit report without printing the password itself."""
    score = calculate_score(result)
    label = strength_label(score)

    print("\n" + "=" * 55)
    print("PASSWORD AUDIT REPORT")
    print("=" * 55)
    print(f"Policy:             {result['policy'].title()}")
    print(f"Password length:    {result['length']}")
    print(f"Estimated entropy:  {result['entropy']:.1f} bits")
    print(f"Security score:     {score}/100")
    print(f"Strength rating:    {label}")
    print("-" * 55)

    print("Character checks:")
    print(f"  Lowercase letters: {'Yes' if result['has_lower'] else 'No'}")
    print(f"  Uppercase letters: {'Yes' if result['has_upper'] else 'No'}")
    print(f"  Digits:            {'Yes' if result['has_digit'] else 'No'}")
    print(f"  Symbols:           {'Yes' if result['has_symbol'] else 'No'}")

    if not result["findings"]:
        print("\nResult: Password satisfies all selected policy checks.")
    else:
        print("\nIssues found:")
        for finding in result["findings"]:
            print(f"  - {finding}")

        print("\nSuggestions:")
        for suggestion in dict.fromkeys(result["suggestions"]):
            print(f"  - {suggestion}")

    print("=" * 55)


def generate_password(length, use_symbols=True):
    """Generate a cryptographically secure random password."""
    if length < 8:
        raise ValueError("Password length must be at least 8 characters.")

    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    digits = string.digits
    symbols = "!@#$%^&*()-_=+"

    required_groups = [lowercase, uppercase, digits]
    if use_symbols:
        required_groups.append(symbols)

    password_chars = [secrets.choice(group) for group in required_groups]
    allowed_chars = "".join(required_groups)

    remaining_length = length - len(password_chars)
    password_chars.extend(
        secrets.choice(allowed_chars) for _ in range(remaining_length)
    )

    secrets.SystemRandom().shuffle(password_chars)
    return "".join(password_chars)


def audit_password_interactively(policy):
    """Prompt safely for a password so it is not shown on-screen."""
    print("Enter a password to audit.")
    print("The password will not be printed or saved by this program.")
    password = getpass("Password: ")

    if not password:
        print("No password entered. Exiting.")
        return

    result = check_policy(password, policy)
    print_report(result)


def main():
    parser = argparse.ArgumentParser(
        description="Password Strength & Policy Auditor"
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    check_parser = subparsers.add_parser(
        "check",
        help="Audit a password securely using an interactive prompt."
    )
    check_parser.add_argument(
        "--policy",
        choices=POLICIES.keys(),
        default="college",
        help="Password policy to apply. Default: college"
    )

    generate_parser = subparsers.add_parser(
        "generate",
        help="Generate a secure random password."
    )
    generate_parser.add_argument(
        "--length",
        type=int,
        default=16,
        help="Length of generated password. Default: 16"
    )
    generate_parser.add_argument(
        "--no-symbols",
        action="store_true",
        help="Generate without special symbols."
    )

    args = parser.parse_args()

    if args.command == "check":
        audit_password_interactively(args.policy)

    elif args.command == "generate":
        try:
            password = generate_password(
                length=args.length,
                use_symbols=not args.no_symbols
            )
            print("\nGenerated secure password:")
            print(password)
            print("\nStore it in a trusted password manager.")
        except ValueError as error:
            print(f"Error: {error}")


if __name__ == "__main__":
    main()