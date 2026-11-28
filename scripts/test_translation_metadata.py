"""Check generated language metadata and localized book navigation."""

import json
from pathlib import Path
import re
import tempfile
import unittest
from xml.etree import ElementTree

from seo_postprocess import generate_language_sitemap, update_document


class TranslationMetadataTests(unittest.TestCase):
    languages = ["en", "pt", "zh"]
    site = "https://example.org"

    def test_locale_metadata_and_menu_links_keep_the_branch_urls(self):
        theme = Path("theme/index.hbs").read_text(encoding="utf-8")
        page = Path("guide/getting-started.html")
        for branch, tag, og_tag in (("pt", "pt-BR", "pt_BR"), ("zh", "zh-Hans", "zh_CN")):
            with self.subTest(branch=branch):
                html = update_document(
                    theme.replace("{{ language }}", branch),
                    self.site, branch, page, self.languages, "en", "Book", "2025-01-01",
                )
                self.assertIn(f'<html lang="{tag}"', html)
                self.assertIn(f'<meta property="og:locale" content="{og_tag}">', html)
                self.assertIn(f'hreflang="{tag}" href="{self.site}/{branch}/{page}"', html)
                self.assertIn(f'id="{branch}" href="/{branch}/{page}" hreflang="{tag}"', html)
                structured = re.search(r'<script type="application/ld\+json">(.*?)</script>', html)[1]
                records = json.loads(structured)
                self.assertTrue(any(item.get("inLanguage") == tag for item in records))
                companion_links = re.findall(r'<a data-companion-book href="([^"]+)"', html)
                self.assertEqual(len(companion_links), 2)
                self.assertTrue(all(link.endswith(f"/{branch}/") for link in companion_links))

    def test_sitemap_uses_the_same_locale_tags_and_urls(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "guide.html").write_text("<html></html>", encoding="utf-8")
            generate_language_sitemap(root, self.site, "pt", self.languages, "en")
            tree = ElementTree.parse(root / "sitemap.xml")
            links = tree.findall(".//{http://www.w3.org/1999/xhtml}link")
        self.assertEqual(
            {link.get("hreflang"): link.get("href") for link in links},
            {
                "en": f"{self.site}/en/guide.html",
                "pt-BR": f"{self.site}/pt/guide.html",
                "zh-Hans": f"{self.site}/zh/guide.html",
                "x-default": f"{self.site}/en/guide.html",
            },
        )


if __name__ == "__main__":
    unittest.main()
