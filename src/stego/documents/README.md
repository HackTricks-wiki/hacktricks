# Стеганографія в документах

{{#include ../../banners/hacktricks-training.md}}

Багато форматів документів є структурованими контейнерами, а не окремими потоками даних:<sup>[[1]](#references)</sup><sup>[[3]](#references)</sup>

- PDF (вбудовані файли, потоки)
- Office OOXML (`.docx/.xlsx/.pptx` — це ZIP-архіви)
- Застарілі документи RTF і OLE/Compound File Binary. RTF зберігає керувальні слова та групи у текстовому форматі, тоді як складені файли OLE мають ієрархію об’єктів сховища та потоків, подібну до файлової системи; обидва формати потребують спеціалізованої перевірки на наявність прихованих або вбудованих даних.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup>

## PDF

### Техніка

Файли PDF можуть містити об’єкти, потоки, JavaScript і вбудовані файли. Під час аналізу зазвичай виконують такі завдання:

- Вилучення вбудованих вкладень.
- Розгортання потоків об’єктів, щоб спростити перевірку об’єктів.
- Виявлення JavaScript, вбудованих зображень і незвичних потоків.<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

### Швидкі перевірки

```bash
pdfinfo file.pdf
pdfdetach -list file.pdf
pdfdetach -saveall file.pdf
qpdf --qdf --object-streams=disable file.pdf out.pdf
```

Комбінація `--qdf --object-streams=disable` створює читабельніше представлення та видаляє object streams, що спрощує ручний аналіз.<sup>[[2]](#references)</sup> Потім знайдіть в `out.pdf` підозрілі об’єкти та рядки.

## Office OOXML

### Методика

Файли Office Open XML (`.docx`, `.xlsx` і `.pptx`) використовують Open Packaging Conventions: пакет на основі ZIP, що складається з частин і XML-файлів зв’язків.<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup> Розглядайте пакет як граф зв’язків і перевіряйте медіафайли, зовнішні зв’язки та незвичні користувацькі частини.

На практиці:

- Документ — це дерево каталогів із XML-файлів і ресурсів.
- Файли зв’язків `_rels/` можуть вказувати на зовнішні ресурси або приховані частини.
- Вбудовані дані часто містяться в `word/media/`, користувацьких XML-частинах або незвичних зв’язках.

### Швидкі перевірки

```bash
7z l file.docx
7z x file.docx -oout
```

Потім перевірте:

- `word/document.xml`
- `word/_rels/` на наявність зовнішніх зв’язків
- вбудовані медіафайли в `word/media/`

## References

- [1] [Посібник Poppler pdfdetach](https://manpages.debian.org/trixie/poppler-utils/pdfdetach.1.en.html)
- [2] [Документація qpdf — режим QDF і потоки об’єктів](https://qpdf.readthedocs.io/en/stable/cli.html#qdf-mode)
- [3] [Microsoft Learn — основи Open Packaging Conventions](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/opc/open-packaging-conventions-overview)
- [4] [ECMA-376 — формати файлів Office Open XML](https://ecma-international.org/publications-and-standards/standards/ecma-376/)
- [5] [Microsoft Open Specifications — вступ до формату Compound File Binary](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/50708a61-81d9-49c8-ab9c-43c98a795242)
- [6] [Microsoft Open Specifications — довідник зі специфікації RTF](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxrtfcp/85c0b884-a960-4d1a-874e-53eeee527ca6)
{{#include ../../banners/hacktricks-training.md}}
