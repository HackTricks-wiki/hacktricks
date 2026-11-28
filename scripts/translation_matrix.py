"""Choose the Translate All job matrix for full runs or one language resume."""

import argparse
import json
from html.parser import HTMLParser
from pathlib import Path


TRANSLATION_LOCALES = {"pt": "Brazilian Portuguese", "zh": "Simplified Chinese"}


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


MENU_LABELS = {
    "af": "Afrikaans", "de": "Deutsch", "el": "Ελληνικά", "en": "English",
    "es": "Español", "fr": "Français", "hi": "हिन्दी", "it": "Italiano",
    "ja": "日本語", "ko": "한국어", "pl": "Polski", "pt": "Português (Brasil)",
    "sr": "Српски", "sw": "Kiswahili", "tr": "Türkçe", "uk": "Українська",
    "vi": "Tiếng Việt", "zh": "简体中文",
}
MENU_LANGUAGE_TAGS = {"pt": "pt-BR", "zh": "zh-Hans"}


class LanguageMenu(HTMLParser):
    def __init__(self):
        super().__init__()
        self.options = []
        self.option = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "a" and attrs.get("role") == "menuitem" and "hreflang" in attrs:
            self.option = (attrs, [])

    def handle_data(self, data):
        if self.option is not None:
            self.option[1].append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self.option is not None:
            self.options.append(self.option)
            self.option = None


def check_menu(html):
    menu = LanguageMenu()
    menu.feed(html)
    menu.close()
    expected_codes = {"en", *(code for _, code in LANGUAGES)}
    if MENU_LABELS.keys() != expected_codes:
        raise ValueError("Update the native menu labels to match the translation matrix")
    codes = [attrs.get("id") for attrs, _ in menu.options]
    if len(codes) != len(expected_codes) or set(codes) != expected_codes:
        raise ValueError("The language menu must contain each configured locale exactly once")
    for attrs, parts in menu.options:
        code = attrs["id"]
        tag = MENU_LANGUAGE_TAGS.get(code, code)
        label = "".join(parts).strip()
        # Flags may precede the text. They are Unicode regional indicators.
        label = label.lstrip("".join(chr(point) for point in range(0x1F1E6, 0x1F200))).strip()
        if label != MENU_LABELS[code]:
            raise ValueError(f"The language menu is missing the native label for {code}")
        if (attrs.get("href"), attrs.get("lang"), attrs.get("hreflang")) != (f"/{code}/", tag, tag):
            raise ValueError(f"The language menu has a mismatched destination or language tag for {code}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--only", default="", help="Resume only this language branch")
    action.add_argument("--check-menu", type=Path, help="Verify the theme's native-language menu")
    args = parser.parse_args()
    if args.check_menu:
        try:
            check_menu(args.check_menu.read_text(encoding="utf-8"))
        except ValueError as exc:
            parser.error(str(exc))
        return
    matches = [(name, code) for name, code in LANGUAGES if not args.only or code == args.only]
    if not matches:
        parser.error(f"unknown language branch: {args.only}")
    print("matrix=" + json.dumps({"include": [
        {"name": name, "language": TRANSLATION_LOCALES.get(code, name), "branch": code} for name, code in matches
    ]}, separators=(",", ":")))


if __name__ == "__main__":
    main()
