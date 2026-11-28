"""Verify that mdBook renders the localized missing-page copy."""

from html.parser import HTMLParser
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from render_localized_error import ERROR_TEXT, localize_rendered_error_page, localized_error_markdown
from translation_matrix import LANGUAGES, MENU_LABELS, MENU_LANGUAGE_TAGS


class ErrorLinks(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = {}

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "a" and "hreflang" in attrs:
            self.links[attrs["hreflang"]] = attrs.get("href")


class ErrorPageTests(unittest.TestCase):
    def test_every_edition_has_translated_copy_and_a_home_link(self):
        locales = {"en", *(code for _, code in LANGUAGES)}
        self.assertEqual(locales, set(ERROR_TEXT))
        for branch, (heading, description, label) in ERROR_TEXT.items():
            with self.subTest(branch=branch):
                page = localized_error_markdown(branch)
                self.assertIn(f"# {heading}\n", page)
                self.assertIn(description, page)
                self.assertIn(f"[{label}](/{branch}/)", page)
                if branch != "en":
                    self.assertNotIn(ERROR_TEXT["en"][0], page)

    @unittest.skipUnless(shutil.which("mdbook"), "mdBook is required to verify the rendered error page")
    def test_mdbook_renders_fallback_language_links_and_localized_content(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / "src"
            source.mkdir()
            (source / "SUMMARY.md").write_text("# Summary\n\n- [Guide](guide.md)\n", encoding="utf-8")
            (source / "guide.md").write_text("# Guide\n", encoding="utf-8")
            for locale in ("en", "pt", "ja"):
                with self.subTest(locale=locale):
                    (root / "book.toml").write_text(f'[book]\ntitle = "Guide"\nlanguage = "{locale}"\n')
                    (source / "404.md").write_text(localized_error_markdown(locale), encoding="utf-8")
                    subprocess.run(["mdbook", "build", str(root)], check=True, capture_output=True)
                    page = localize_rendered_error_page((root / "book/404.html").read_text(encoding="utf-8"), locale)
                    heading, description, return_label = ERROR_TEXT[locale]
                    self.assertIn(f'<html lang="{MENU_LANGUAGE_TAGS.get(locale, locale)}"', page)
                    self.assertIn(f"<title>{heading} - Guide</title>", page)
                    self.assertIn(f">{heading}</a></h1>", page)
                    self.assertIn(f"<p>{description}</p>", page)
                    self.assertIn(f'<a href="/{locale}/">{return_label}</a>', page)
                    if locale == "en":
                        parser = ErrorLinks()
                        parser.feed(page)
                        self.assertEqual(parser.links, {
                            MENU_LANGUAGE_TAGS.get(branch, branch): f"/{branch}/"
                            for branch in MENU_LABELS
                        })


if __name__ == "__main__":
    unittest.main()
