import argparse
import html
import json
import re
import subprocess
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
NOINDEX_HTML = {"404.html", "print.html", "toc.html"}
SEO_START = "<!-- HT_SEO_START -->"
SEO_END = "<!-- HT_SEO_END -->"
SITE_DESCRIPTIONS = {
    "HackTricks": (
        "HackTricks is a cybersecurity knowledge base with practical pentesting, red team, "
        "web, cloud, binary exploitation, and privilege escalation techniques."
    ),
}
SITE_ALTERNATE_NAMES = {
    "HackTricks": ["HT", "HackTricks Wiki"],
}
SITE_SAME_AS = {
    "HackTricks": [
        "https://github.com/HackTricks-wiki/hacktricks",
        "https://www.linkedin.com/company/hacktricks",
        "https://twitter.com/hacktricks_live",
    ],
}
LANGUAGE_LOCALES = {
    "af": "af_ZA",
    "de": "de_DE",
    "el": "el_GR",
    "en": "en_US",
    "es": "es_ES",
    "fr": "fr_FR",
    "hi": "hi_IN",
    "it": "it_IT",
    "ja": "ja_JP",
    "ko": "ko_KR",
    "pl": "pl_PL",
    "pt": "pt_PT",
    "sr": "sr_RS",
    "sw": "sw_KE",
    "tr": "tr_TR",
    "uk": "uk_UA",
    "zh": "zh_CN",
}
DESCRIPTION_SKIP_PATTERNS = (
    "hacktricks logos",
    "learn & practice",
    "learn and practice",
    "hacktricks training",
    "full hacktricks training catalog",
)
LANGUAGE_MENU_LINK_RE = re.compile(
    r'(?P<prefix><a\s+id="(?P<lang>[a-z]{2})"\s+href=")/[a-z]{2}/[^"]*(?P<suffix>"\s+hreflang="(?P=lang)")',
    flags=re.I,
)


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
    index_cmd.add_argument("--languages", default=",".join(DEFAULT_LANGUAGES))
    index_cmd.add_argument("--output", required=True)

    return parser.parse_args()


def parse_languages(raw):
    supported = set(DEFAULT_LANGUAGES)
    langs = []
    for item in raw.split(","):
        code = item.strip()
        if re.fullmatch(r"[a-z]{2}", code) and code in supported:
            langs.append(code)
    return sorted(set(langs))


def iter_html_files(book_dir):
    for html_file in sorted(Path(book_dir).rglob("*.html")):
        if html_file.name in SKIP_HTML:
            continue
        yield html_file


def canonical_url(site_url, lang, rel_path):
    return f"{site_url.rstrip('/')}/{lang}/{rel_path.as_posix()}"


def asset_url(site_url, lang, asset_path):
    return f"{site_url.rstrip('/')}/{lang}/{asset_path.lstrip('/')}"


def social_image_url(site_url):
    return f"{site_url.rstrip('/')}/en/images/HACKTRICKS-logo.svg"


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


def is_low_value_description(text):
    lowered = text.lower()
    if any(pattern in lowered for pattern in DESCRIPTION_SKIP_PATTERNS):
        return True
    return len(re.sub(r"[\W_]+", "", text)) < 40


def extract_description(document, fallback):
    main_match = re.search(r"<main\b[^>]*>(.*?)</main>", document, flags=re.I | re.S)
    scope = main_match.group(1) if main_match else document

    for pattern in (r"<p\b[^>]*>(.*?)</p>", r"<li\b[^>]*>(.*?)</li>", r"<h[12]\b[^>]*>(.*?)</h[12]>"):
        for match in re.finditer(pattern, scope, flags=re.I | re.S):
            text = clean_text(match.group(1))
            if len(text) >= 40 and not is_low_value_description(text):
                return trim_description(text, fallback)

    return trim_description(clean_text(scope), fallback)


def homepage_description(site_name):
    return SITE_DESCRIPTIONS.get(site_name, f"{site_name}: practical cybersecurity guides and references.")


def is_homepage(rel_path):
    return rel_path.as_posix() == "index.html"


def source_path_for_html(book_dir, rel_path):
    repo_root = Path(book_dir).resolve().parent
    if rel_path.name == "index.html":
        source_rel = Path("src") / rel_path.parent / "README.md"
    else:
        source_rel = Path("src") / rel_path.with_suffix(".md")
    source_path = repo_root / source_rel
    return source_path if source_path.exists() else None


def git_lastmod(source_path):
    try:
        output = subprocess.check_output(
            ["git", "log", "-1", "--format=%cs", "--", str(source_path)],
            cwd=source_path.parent,
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return None
    return output or None


def page_lastmod(book_dir, rel_path, html_file):
    source_path = source_path_for_html(book_dir, rel_path)
    if source_path:
        lastmod = git_lastmod(source_path)
        if lastmod:
            return lastmod
    return datetime.fromtimestamp(html_file.stat().st_mtime, tz=timezone.utc).date().isoformat()


def humanize_slug(value):
    value = value.replace(".html", "").replace("-", " ").replace("_", " ").strip()
    value = re.sub(r"\s+", " ", value)
    return value.title() if value else "Home"


def breadcrumb_items(site_url, lang, rel_path):
    items = [{"name": "Home", "url": canonical_url(site_url, lang, Path("index.html"))}]
    if is_homepage(rel_path):
        return items

    if rel_path.name == "index.html":
        directory_parts = list(rel_path.parent.parts)
        page_name = None
    else:
        directory_parts = [] if rel_path.parent == Path(".") else list(rel_path.parent.parts)
        page_name = rel_path.name

    for idx, part in enumerate(directory_parts):
        crumb_rel = Path(*directory_parts[: idx + 1], "index.html")
        items.append({"name": humanize_slug(part), "url": canonical_url(site_url, lang, crumb_rel)})

    if page_name:
        items.append({"name": humanize_slug(page_name), "url": canonical_url(site_url, lang, rel_path)})

    return items


def build_structured_data(site_url, lang, rel_path, title, description, site_name, image_url, languages, lastmod):
    current_url = canonical_url(site_url, lang, rel_path)
    site_root = site_url.rstrip("/")
    data = []

    if is_homepage(rel_path):
        data.extend(
            [
                {
                    "@context": "https://schema.org",
                    "@type": "Organization",
                    "@id": f"{site_root}/#organization",
                    "name": site_name,
                    "alternateName": SITE_ALTERNATE_NAMES.get(site_name, []),
                    "url": site_root,
                    "description": homepage_description(site_name),
                    "logo": {"@type": "ImageObject", "url": image_url},
                    "sameAs": SITE_SAME_AS.get(site_name, []),
                },
                {
                    "@context": "https://schema.org",
                    "@type": "WebSite",
                    "@id": f"{site_root}/#website",
                    "url": site_root,
                    "name": site_name,
                    "alternateName": SITE_ALTERNATE_NAMES.get(site_name, []),
                    "description": homepage_description(site_name),
                    "inLanguage": languages,
                    "publisher": {"@id": f"{site_root}/#organization"},
                },
            ]
        )

    data.extend(
        [
            {
            "@context": "https://schema.org",
            "@type": "WebPage",
            "@id": f"{current_url}#webpage",
            "url": current_url,
            "name": title,
            "description": description,
            "inLanguage": lang,
            "dateModified": lastmod,
            "isPartOf": {"@id": f"{site_root}/#website"},
            "about": {"@id": f"{site_root}/#organization"},
            "primaryImageOfPage": {"@type": "ImageObject", "url": image_url},
            },
            {
            "@context": "https://schema.org",
            "@type": "BreadcrumbList",
            "itemListElement": [
                {
                    "@type": "ListItem",
                    "position": index,
                    "name": item["name"],
                    "item": item["url"],
                }
                for index, item in enumerate(breadcrumb_items(site_url, lang, rel_path), start=1)
            ],
            },
        ]
    )

    return data


def build_seo_block(site_url, lang, rel_path, languages, default_lang, title, description, site_name, lastmod):
    current_url = canonical_url(site_url, lang, rel_path)
    image_url = social_image_url(site_url)
    structured_data = json.dumps(
        build_structured_data(site_url, lang, rel_path, title, description, site_name, image_url, languages, lastmod),
        ensure_ascii=False,
        separators=(",", ":"),
    )
    lines = [SEO_START, f'<link rel="canonical" href="{html.escape(current_url, quote=True)}">']

    for alt_lang in languages:
        alt_url = canonical_url(site_url, alt_lang, rel_path)
        lines.append(
            f'<link rel="alternate" hreflang="{alt_lang}" href="{html.escape(alt_url, quote=True)}">'
        )

    default_url = canonical_url(site_url, default_lang, rel_path)
    lines.append(f'<link rel="alternate" hreflang="x-default" href="{html.escape(default_url, quote=True)}">')
    lines.extend(
        [
            f'<meta property="og:site_name" content="{html.escape(site_name, quote=True)}">',
            f'<meta property="og:title" content="{html.escape(title, quote=True)}">',
            f'<meta property="og:description" content="{html.escape(description, quote=True)}">',
            f'<meta property="og:url" content="{html.escape(current_url, quote=True)}">',
            f'<meta property="og:type" content="website">',
            f'<meta property="og:image" content="{html.escape(image_url, quote=True)}">',
            f'<meta property="og:image:secure_url" content="{html.escape(image_url, quote=True)}">',
            f'<meta property="og:image:type" content="image/svg+xml">',
            f'<meta property="og:image:alt" content="{html.escape(site_name, quote=True)}">',
            f'<meta property="og:locale" content="{html.escape(LANGUAGE_LOCALES.get(lang, lang), quote=True)}">',
            f'<meta name="twitter:card" content="summary_large_image">',
            f'<meta name="twitter:title" content="{html.escape(title, quote=True)}">',
            f'<meta name="twitter:description" content="{html.escape(description, quote=True)}">',
            f'<meta name="twitter:image" content="{html.escape(image_url, quote=True)}">',
            '<script type="application/ld+json">' + structured_data + "</script>",
        ]
    )
    lines.append(SEO_END)
    return "\n        ".join(lines)


def update_language_menu_links(document, rel_path, languages):
    allowed_languages = set(languages)
    target_path = html.escape(rel_path.as_posix(), quote=True)

    def replace(match):
        lang = match.group("lang")
        if lang not in allowed_languages:
            return match.group(0)
        return f'{match.group("prefix")}/{lang}/{target_path}{match.group("suffix")}'

    return LANGUAGE_MENU_LINK_RE.sub(replace, document)


def update_document(document, site_url, lang, rel_path, languages, default_lang, site_name, lastmod):
    title_match = re.search(r"<title>(.*?)</title>", document, flags=re.I | re.S)
    page_title = clean_text(title_match.group(1)) if title_match else site_name
    fallback_description = f"{site_name}: {page_title}"
    description = homepage_description(site_name) if is_homepage(rel_path) else extract_description(document, fallback_description)
    seo_block = build_seo_block(
        site_url, lang, rel_path, languages, default_lang, page_title, description, site_name, lastmod
    )

    document = re.sub(
        r"\s*<!-- HT_SEO_START -->.*?<!-- HT_SEO_END -->\s*",
        "\n",
        document,
        flags=re.S,
    )

    if re.search(r'<meta\s+name="description"\s+content="[^"]*"\s*/?>', document, flags=re.I):
        document = re.sub(
            r'(<meta\s+name="description"\s+content=")[^"]*("\s*/?>)',
            lambda match: match.group(1) + html.escape(description, quote=True) + match.group(2),
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

    document = re.sub(
        r"</head>",
        lambda match: f"        {seo_block}\n    {match.group(0)}",
        document,
        count=1,
        flags=re.I,
    )
    document = update_language_menu_links(document, rel_path, languages)
    return document


def update_noindex_document(document, rel_path, languages):
    if re.search(r'<meta\s+name="robots"\s+content="[^"]*"\s*/?>', document, flags=re.I):
        document = re.sub(
            r'(<meta\s+name="robots"\s+content=")[^"]*("\s*/?>)',
            lambda match: match.group(1) + "noindex, follow" + match.group(2),
            document,
            count=1,
            flags=re.I,
        )
    else:
        document = re.sub(
            r"</title>",
            '</title>\n        <meta name="robots" content="noindex, follow">',
            document,
            count=1,
            flags=re.I,
        )
    return update_language_menu_links(document, rel_path, languages)


def process_noindex_pages(book_dir, languages):
    for html_file in Path(book_dir).rglob("*.html"):
        if html_file.name not in NOINDEX_HTML:
            continue
        rel_path = html_file.relative_to(book_dir)
        content = html_file.read_text(encoding="utf-8")
        updated = update_noindex_document(content, rel_path, languages)
        if updated != content:
            html_file.write_text(updated, encoding="utf-8")


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
        ET.SubElement(url, "{http://www.sitemaps.org/schemas/sitemap/0.9}lastmod").text = page_lastmod(
            book_dir, rel_path, html_file
        )

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
        lastmod = page_lastmod(book_dir, rel_path, html_file)
        updated = update_document(
            content,
            args.site_url,
            args.lang,
            rel_path,
            languages,
            args.default_lang,
            args.site_name,
            lastmod,
        )
        html_file.write_text(updated, encoding="utf-8")

    process_noindex_pages(book_dir, languages)
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
