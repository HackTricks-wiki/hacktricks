"""Write mdBook's missing-page Markdown for the requested edition."""

import argparse
import html
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import tomllib

from seo_postprocess import update_noindex_document
from translation_matrix import MENU_LABELS, MENU_LANGUAGE_TAGS


ERROR_TEXT = {
    "af": ("Bladsy nie gevind nie", "Hierdie bladsy is dalk geskuif of verwyder.", "Terug na die boek"),
    "de": ("Seite nicht gefunden", "Diese Seite wurde möglicherweise verschoben oder entfernt.", "Zurück zum Buch"),
    "el": ("Η σελίδα δεν βρέθηκε", "Αυτή η σελίδα ενδέχεται να έχει μετακινηθεί ή αφαιρεθεί.", "Επιστροφή στο βιβλίο"),
    "en": ("Page not found", "This page may have moved or been removed.", "Return to the book"),
    "es": ("Página no encontrada", "Es posible que esta página se haya movido o eliminado.", "Volver al libro"),
    "fr": ("Page introuvable", "Cette page a peut-être été déplacée ou supprimée.", "Revenir au livre"),
    "hi": ("पृष्ठ नहीं मिला", "हो सकता है कि इस पृष्ठ का पता बदल गया हो या इसे हटा दिया गया हो।", "पुस्तक पर लौटें"),
    "it": ("Pagina non trovata", "Questa pagina potrebbe essere stata spostata o rimossa.", "Torna al libro"),
    "ja": ("ページが見つかりません", "このページは移動または削除された可能性があります。", "本に戻る"),
    "ko": ("페이지를 찾을 수 없습니다", "이 페이지는 이동했거나 삭제되었을 수 있습니다.", "책으로 돌아가기"),
    "pl": ("Nie znaleziono strony", "Ta strona mogła zostać przeniesiona lub usunięta.", "Wróć do książki"),
    "pt": ("Página não encontrada", "Esta página pode ter sido movida ou removida.", "Voltar ao livro"),
    "sr": ("Страница није пронађена", "Ова страница је можда премештена или уклоњена.", "Повратак на књигу"),
    "sw": ("Ukurasa haujapatikana", "Huenda ukurasa huu umehamishwa au kuondolewa.", "Rudi kwenye kitabu"),
    "tr": ("Sayfa bulunamadı", "Bu sayfa taşınmış veya kaldırılmış olabilir.", "Kitaba dön"),
    "uk": ("Сторінку не знайдено", "Можливо, цю сторінку переміщено або видалено.", "Повернутися до книги"),
    "vi": ("Không tìm thấy trang", "Có thể trang này đã được di chuyển hoặc xóa.", "Quay lại sách"),
    "zh": ("找不到页面", "此页面可能已被移动或删除。", "返回手册"),
}


def localized_error_markdown(language):
    heading, description, return_label = ERROR_TEXT[language]
    page = f"# {heading}\n\n{description}\n\n[{return_label}](/{language}/)\n"
    if language == "en":
        links = []
        for branch, label in MENU_LABELS.items():
            tag = MENU_LANGUAGE_TAGS.get(branch, branch)
            links.append(f'<a href="/{branch}/" lang="{tag}" hreflang="{tag}">{label}</a>')
        page += "\n## Languages\n\n" + " · ".join(links) + "\n"
    return page


def localize_rendered_error_page(page, language):
    heading = html.escape(ERROR_TEXT[language][0])
    page = re.sub(
        r"(<title>)Page not found(?= - |</title>)",
        lambda match: match[1] + heading,
        page,
        count=1,
    )
    tag = MENU_LANGUAGE_TAGS.get(language, language)
    return re.sub(r'(<html\b[^>]*?\s+lang=")[^"]*(")', rf'\g<1>{tag}\2', page, count=1)


def render_error_assets(destination):
    """Render only 404 pages in an isolated book with a placeholder chapter."""
    with Path("book.toml").open("rb") as resource:
        config = tomllib.load(resource)
    title = config["book"]["title"]
    renderer = config["output"]["html"]
    assets = {
        key: renderer.get(key, [])
        for key in ("additional-css", "additional-js")
    }
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        source = root / "src"
        source.mkdir()
        (source / "SUMMARY.md").write_text("# Summary\n\n- [Home](home.md)\n", encoding="utf-8")
        (source / "home.md").write_text("# Home\n", encoding="utf-8")
        for path in ("theme/index.hbs", "theme/toc.js.hbs", *assets["additional-css"], *assets["additional-js"]):
            target = root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)
        asset_config = "".join(f"{key} = {json.dumps(paths)}\n" for key, paths in assets.items())
        for language in sorted(ERROR_TEXT):
            (root / "book.toml").write_text(
                f'[book]\ntitle = {json.dumps(title)}\nlanguage = "{language}"\n\n'
                f'[output.html]\nsite-url = "/{language}/"\nhash-files = false\n'
                f'{asset_config}',
                encoding="utf-8",
            )
            (source / "404.md").write_text(localized_error_markdown(language), encoding="utf-8")
            subprocess.run(["mdbook", "build", str(root)], check=True, capture_output=True)
            path = Path("404.html")
            page = localize_rendered_error_page((root / "book" / path).read_text(encoding="utf-8"), language)
            page = update_noindex_document(page, path, ERROR_TEXT)
            target = destination / language / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(page, encoding="utf-8")
        shutil.copyfile(destination / "en/404.html", destination / "404.html")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--language", choices=sorted(ERROR_TEXT))
    mode.add_argument("--publish-dir", type=Path, help="Render all localized 404 pages into this directory")
    parser.add_argument("--rendered", action="store_true", help="Localize the generated HTML title and language tag")
    args = parser.parse_args()
    if args.publish_dir:
        render_error_assets(args.publish_dir)
    elif args.rendered:
        path = Path("book/404.html")
        page = localize_rendered_error_page(path.read_text(encoding="utf-8"), args.language)
        path.write_text(page, encoding="utf-8")
    else:
        Path("src/404.md").write_text(localized_error_markdown(args.language), encoding="utf-8")


if __name__ == "__main__":
    main()
