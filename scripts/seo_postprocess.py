import argparse
import html
import os
import re
from datetime import datetime, timezone
from pathlib import Path
import xml.etree.ElementTree as ET


DEFAULT_LANGUAGES = [
    "af",
    "zh",
    "es",
    "en",
    "fr",
    "de",
    "el",
    "hi",
    "it",
    "ja",
    "ko",
    "pl",
    "pt",
    "sr",
    "sw",
    "tr",
    "uk",
]

SKIP_HTML = {"404.html", "print.html", "toc.html"}
SEO_START = "<!-- HT_SEO_START -->"
SEO_END = "<!-- HT_SEO_END -->"


def parse_args():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    pages = subparsers.add_parser("pages")
    pages.add_argument("--book-dir", required=True)
    pages.add_argument("--site-url", required=True)
    pages.add_argument("--lang", required=True)
    pages.add_argument("--default-lang", default="en")
    pages.add_argument("--languages", default=",".join(DEFAULT_LANGUAGES))
    pages.add_argument("--site-name", default="HackTricks")

    index_cmd = subparsers.add_parser("index")
    index_cmd.add_argument("--site-url", required=True)
    index_cmd.add_argument("--languages", required=True)
    index_cmd.add_argument("--output", required=True)

    return parser.parse_args()


def parse_languages(raw):
    langs = []
    for item in raw.split(","):
        code = item.strip()
        if re.fullmatch(r"[a-z]{2}", code):
            langs.append(code)
    return sorted(set(langs))


def iter_html_files(book_dir):
    for html_file in sorted(Path(book_dir).rglob("*.html")):
        if html_file.name in SKIP_HTML:
            continue
        yield html_file


def canonical_url(site_url, lang, rel_path):
    return f"{site_url.rstrip('/')}/{lang}/{rel_path.as_posix()}"


def clean_text(fragment):
    fragment = re.sub(r"<script\b[^>]*>.*?</script>", " ", fragment, flags=re.I | re.S)
    fragment = re.sub(r"<style\b[^>]*>.*?</style>", " ", fragment, flags=re.I | re.S)
    fragment = re.sub(r"<[^>]+>", " ", fragment)
    fragment = html.unescape(fragment)
    fragment = re.sub(r"\s+", " ", fragment).strip()
    return fragment


def trim_description(text, fallback):
    text = text or fallback
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) <= 160:
        return text
    cut = text[:157]
    if " " in cut:
        cut = cut.rsplit(" ", 1)[0]
    return cut + "..."


def extract_description(document, fallback):
    main_match = re.search(r"<main\b[^>]*>(.*?)</main>", document, flags=re.I | re.S)
    scope = main_match.group(1) if main_match else document

    for pattern in (r"<p\b[^>]*>(.*?)</p>", r"<li\b[^>]*>(.*?)</li>", r"<h[12]\b[^>]*>(.*?)</h[12]>"):
        for match in re.finditer(pattern, scope, flags=re.I | re.S):
            text = clean_text(match.group(1))
            if len(text) >= 40:
                return trim_description(text, fallback)

    return trim_description(clean_text(scope), fallback)


def build_seo_block(site_url, lang, rel_path, languages, default_lang):
    current_url = canonical_url(site_url, lang, rel_path)
    lines = [SEO_START, f'<link rel="canonical" href="{html.escape(current_url, quote=True)}">']

    for alt_lang in languages:
        alt_url = canonical_url(site_url, alt_lang, rel_path)
        lines.append(
            f'<link rel="alternate" hreflang="{alt_lang}" href="{html.escape(alt_url, quote=True)}">'
        )

    default_url = canonical_url(site_url, default_lang, rel_path)
    lines.append(f'<link rel="alternate" hreflang="x-default" href="{html.escape(default_url, quote=True)}">')
    lines.append(SEO_END)
    return "\n        ".join(lines)


def update_document(document, site_url, lang, rel_path, languages, default_lang, site_name):
    title_match = re.search(r"<title>(.*?)</title>", document, flags=re.I | re.S)
    page_title = clean_text(title_match.group(1)) if title_match else site_name
    fallback_description = f"{site_name}: {page_title}"
    description = extract_description(document, fallback_description)
    seo_block = build_seo_block(site_url, lang, rel_path, languages, default_lang)

    document = re.sub(
        r"\s*<!-- HT_SEO_START -->.*?<!-- HT_SEO_END -->\s*",
        "\n",
        document,
        flags=re.S,
    )

    if re.search(r'<meta\s+name="description"\s+content="[^"]*"\s*/?>', document, flags=re.I):
        document = re.sub(
            r'(<meta\s+name="description"\s+content=")[^"]*("\s*/?>)',
            r"\1" + html.escape(description, quote=True) + r"\2",
            document,
            count=1,
            flags=re.I,
        )
    elif title_match:
        document = document.replace(
            title_match.group(0),
            title_match.group(0) + f'\n        <meta name="description" content="{html.escape(description, quote=True)}">',
            1,
        )

    document = re.sub(r"</head>", f"        {seo_block}\n    </head>", document, count=1, flags=re.I)
    return document


def generate_language_sitemap(book_dir, site_url, lang, languages, default_lang):
    ET.register_namespace("", "http://www.sitemaps.org/schemas/sitemap/0.9")
    ET.register_namespace("xhtml", "http://www.w3.org/1999/xhtml")

    urlset = ET.Element("{http://www.sitemaps.org/schemas/sitemap/0.9}urlset")

    for html_file in iter_html_files(book_dir):
        rel_path = html_file.relative_to(book_dir)
        url = ET.SubElement(urlset, "{http://www.sitemaps.org/schemas/sitemap/0.9}url")
        ET.SubElement(url, "{http://www.sitemaps.org/schemas/sitemap/0.9}loc").text = canonical_url(
            site_url, lang, rel_path
        )
        lastmod = datetime.fromtimestamp(html_file.stat().st_mtime, tz=timezone.utc).date().isoformat()
        ET.SubElement(url, "{http://www.sitemaps.org/schemas/sitemap/0.9}lastmod").text = lastmod

        for alt_lang in languages:
            ET.SubElement(
                url,
                "{http://www.w3.org/1999/xhtml}link",
                {
                    "rel": "alternate",
                    "hreflang": alt_lang,
                    "href": canonical_url(site_url, alt_lang, rel_path),
                },
            )

        ET.SubElement(
            url,
            "{http://www.w3.org/1999/xhtml}link",
            {
                "rel": "alternate",
                "hreflang": "x-default",
                "href": canonical_url(site_url, default_lang, rel_path),
            },
        )

    tree = ET.ElementTree(urlset)
    output = Path(book_dir) / "sitemap.xml"
    tree.write(output, encoding="utf-8", xml_declaration=True)


def process_pages(args):
    book_dir = Path(args.book_dir)
    languages = parse_languages(args.languages)

    for html_file in iter_html_files(book_dir):
        rel_path = html_file.relative_to(book_dir)
        content = html_file.read_text(encoding="utf-8")
        updated = update_document(
            content,
            args.site_url,
            args.lang,
            rel_path,
            languages,
            args.default_lang,
            args.site_name,
        )
        html_file.write_text(updated, encoding="utf-8")

    generate_language_sitemap(book_dir, args.site_url, args.lang, languages, args.default_lang)


def generate_sitemap_index(args):
    ET.register_namespace("", "http://www.sitemaps.org/schemas/sitemap/0.9")
    sitemapindex = ET.Element("{http://www.sitemaps.org/schemas/sitemap/0.9}sitemapindex")
    now = datetime.now(timezone.utc).date().isoformat()

    for lang in parse_languages(args.languages):
        sitemap = ET.SubElement(sitemapindex, "{http://www.sitemaps.org/schemas/sitemap/0.9}sitemap")
        ET.SubElement(sitemap, "{http://www.sitemaps.org/schemas/sitemap/0.9}loc").text = (
            f"{args.site_url.rstrip('/')}/{lang}/sitemap.xml"
        )
        ET.SubElement(sitemap, "{http://www.sitemaps.org/schemas/sitemap/0.9}lastmod").text = now

    ET.ElementTree(sitemapindex).write(args.output, encoding="utf-8", xml_declaration=True)


def main():
    args = parse_args()
    if args.command == "pages":
        process_pages(args)
    elif args.command == "index":
        generate_sitemap_index(args)


if __name__ == "__main__":
    main()
