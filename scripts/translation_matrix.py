"""Choose the Translate All job matrix for full runs or one language resume."""

import argparse
import json


LANGUAGES = (
    ("Afrikaans", "af"),
    ("German", "de"),
    ("Greek", "el"),
    ("Spanish", "es"),
    ("French", "fr"),
    ("Hindi", "hi"),
    ("Italian", "it"),
    ("Japanese", "ja"),
    ("Korean", "ko"),
    ("Polish", "pl"),
    ("Portuguese", "pt"),
    ("Serbian", "sr"),
    ("Swahili", "sw"),
    ("Turkish", "tr"),
    ("Ukrainian", "uk"),
    ("Vietnamese", "vi"),
    ("Chinese", "zh"),
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--only", default="", help="Resume only this language branch")
    args = parser.parse_args()
    matches = [(name, code) for name, code in LANGUAGES if not args.only or code == args.only]
    if not matches:
        parser.error(f"unknown language branch: {args.only}")
    print("matrix=" + json.dumps({"include": [
        {"name": name, "language": name, "branch": code} for name, code in matches
    ]}, separators=(",", ":")))


if __name__ == "__main__":
    main()
