"""PhishTriage - quick, safe triage of a suspicious raw email (.eml) file."""
import email
import re
import sys
from email import policy
from urllib.parse import urlparse

# Matches anything that starts with http:// or https:// up to a space, quote or bracket
URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)


def defang(text):
    """Make a URL unclickable: http -> hxxp and every '.' -> '[.]'."""
    return re.sub(r"^http", "hxxp", text, flags=re.IGNORECASE).replace(".", "[.]")


def main():
    # 1. Make sure the user passed exactly one file to analyse
    if len(sys.argv) != 2:
        sys.exit("Usage: python phish_triage.py <email_file.eml>")

    # 2. Open the raw email and parse it into a structured message object
    try:
        with open(sys.argv[1], "rb") as f:
            msg = email.message_from_binary_file(f, policy=policy.default)
    except OSError as err:
        sys.exit(f"Error: could not read file - {err}")

    # 3. Print the key headers an analyst checks first (spoofing clues live here)
    print("=== HEADERS ===")
    for header in ("Subject", "From", "To", "Return-Path"):
        print(f"{header + ':':<13} {msg.get(header, 'N/A')}")

    # 4. Walk every part of the email: collect body text and attachment names
    body_text, attachments = "", []
    for part in msg.walk():
        if part.get_filename():
            attachments.append(part.get_filename())
        elif part.get_content_type() in ("text/plain", "text/html"):
            body_text += part.get_content()

    # 5. Find unique links (order kept), strip trailing punctuation, print defanged
    print("\n=== LINKS (defanged) ===")
    links = dict.fromkeys(u.rstrip(".,;:!)") for u in URL_PATTERN.findall(body_text))
    for url in links:
        print(f"- {defang(url)}  (domain: {defang(urlparse(url).netloc)})")
    if not links:
        print("None found")

    # 6. List attachment names only - never open them on your own machine!
    print("\n=== ATTACHMENTS ===")
    for name in attachments:
        print(f"- {name}")
    if not attachments:
        print("None found")


if __name__ == "__main__":
    main()
