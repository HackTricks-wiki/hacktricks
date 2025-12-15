# Document Steganography

{{#include ../../banners/hacktricks-training.md}}

Документи часто є просто контейнерами:

- PDF (вбудовані файли, потоки)
- Office OOXML (`.docx/.xlsx/.pptx` є ZIP-архівами)
- RTF / OLE — застарілі формати

## PDF

### Техніка

PDF — це структурований контейнер з об'єктами, потоками та опціональними вбудованими файлами. У CTFs часто потрібно:

- Витягти вбудовані вкладення
- Декомпресувати/розгорнути потоки об'єктів, щоб можна було шукати вміст
- Виявити приховані об'єкти (JS, вбудовані зображення, підозрілі потоки)

### Швидкі перевірки
```bash
pdfinfo file.pdf
pdfdetach -list file.pdf
pdfdetach -saveall file.pdf
qpdf --qdf --object-streams=disable file.pdf out.pdf
```
Потім перевірте `out.pdf` на наявність підозрілих об'єктів/рядків.

## Office OOXML

### Техніка

Розглядайте OOXML як ZIP + XML-граф зв'язків; payloads часто ховаються в медіа, зв'язках або незвичайних кастомних частинах.

OOXML files are ZIP containers. That means:

- The document is a directory tree of XML and assets.
- The `_rels/` relationship files can point to external resources or hidden parts.
- Embedded data frequently lives in `word/media/`, custom XML parts, or unusual relationships.

### Швидкі перевірки
```bash
7z l file.docx
7z x file.docx -oout
```
Потім перевірте:

- `word/document.xml`
- `word/_rels/` для зовнішніх зв'язків
- вбудовані медіафайли у `word/media/`

{{#include ../../banners/hacktricks-training.md}}
