# Password Strength & Policy Auditor

A Python command-line tool that evaluates password strength using password-policy checks, estimated entropy, predictable-pattern detection, and secure password generation.

> Educational project only. Do not enter real passwords on shared computers or public systems.

## Features

- Checks password length
- Detects lowercase, uppercase, digits, and symbols
- Detects common weak passwords
- Detects predictable words such as `password`, `admin`, and `college`
- Detects repeated characters such as `aaa` and `111`
- Detects simple sequences such as `1234`, `abcd`, and `qwer`
- Estimates password entropy
- Supports multiple password policies
- Generates cryptographically secure random passwords
- Uses interactive password entry, so passwords are not displayed in the terminal

## Policies

| Policy | Minimum length | Lowercase | Uppercase | Digit | Symbol | Entropy target |
|---|---:|---|---|---|---|---:|
| Basic | 8 | Yes | Yes | Yes | No | 40 bits |
| College | 10 | Yes | Yes | Yes | Yes | 55 bits |
| Enterprise | 14 | Yes | Yes | Yes | Yes | 70 bits |

## Requirements

- Python 3.10 or later
- No external Python packages are required

## Installation

Clone the repository:

```bash
git clone [https://github.com/YOUR-GITHUB-USERNAME/password-strength-auditor.git](https://github.com/YOUR-GITHUB-USERNAME/password-strength-auditor.git)
cd password-strength-auditor
```

## Usage

Audit a password using the college policy:

```bash
python pass_audit.py check --policy college
```

Audit a password using the enterprise policy:

```bash
python pass_audit.py check --policy enterprise
```

Generate a secure 16-character password:

```bash
python pass_audit.py generate --length 16
```

Generate a secure password without symbols:

```bash
python pass_audit.py generate --length 20 --no-symbols
```

## Example Output

```text
=======================================================
PASSWORD AUDIT REPORT
=======================================================
Policy:             College
Password length:    10
Estimated entropy:  50.5 bits
Security score:     64/100
Strength rating:    Weak
-------------------------------------------------------
Character checks:
  Lowercase letters: Yes
  Uppercase letters: Yes
  Digits:            Yes
  Symbols:           No

Issues found:
  - Missing symbols.
  - Contains a predictable sequence, such as 1234 or qwer.
  - Estimated entropy is low: 50.5 bits (target: 55 bits).

Suggestions:
  - Add a symbol, such as !, @, #, or %.
  - Avoid keyboard and number sequences.
  - Increase length and use a less predictable mix of characters.
=======================================================
```

## Security Notes

- This project does not store passwords.
- Password input uses Python's `getpass`, so typed characters are hidden in the terminal.
- Passwords should never be passed directly as command-line arguments because command history and process lists can expose them.
- The entropy estimate is educational and approximate. A long but predictable password can still be weak.
- Future versions may add a Have I Been Pwned k-anonymity breach check. SHA-1 would be used only for the API lookup process, not as a password-storage method.

## Future Improvements

- [ ] Load policies from YAML or JSON configuration files
- [ ] Add unit tests with `pytest`
- [ ] Add a common-password file with 10,000+ entries
- [ ] Add Have I Been Pwned k-anonymity API integration
- [ ] Export audit reports to JSON
- [ ] Add a Streamlit web interface
- [ ] Package the project for installation with `pip`

## Author

Your Name — Third-year ECE student and cybersecurity learner.