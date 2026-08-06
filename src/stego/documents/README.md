# Стеганографія в документах

{{#include ../../banners/hacktricks-training.md}}

Документи часто є лише контейнерами:

- PDF (вбудовані файли, потоки)
- Office OOXML (`.docx/.xlsx/.pptx` — це ZIP-архіви)
- RTF / застарілі формати OLE

## PDF

### Техніка

PDF — це структурований контейнер з об'єктами, потоками та необов'язково вбудованими файлами. У CTF часто потрібно:

- Витягнути вбудовані вкладення
- Розпакувати/вирівняти потоки об'єктів, щоб можна було шукати вміст
- Виявити приховані об'єкти (JS, вбудовані зображення, нетипові потоки)

### Швидкі перевірки
```bash
pdfinfo file.pdf
pdfdetach -list file.pdf
pdfdetach -saveall file.pdf
qpdf --qdf --object-streams=disable file.pdf out.pdf
```
Потім виконайте пошук підозрілих об’єктів/рядків у `out.pdf`.

## Office OOXML

### Technique

Розглядайте OOXML як ZIP + XML граф взаємозв’язків; payloads часто приховані в media, relationships або незвичних custom parts.

Файли OOXML є ZIP-контейнерами. Це означає:

- Документ є деревом каталогів XML і assets.
- Файли зв’язків у `_rels/` можуть вказувати на зовнішні ресурси або приховані частини.
- Вбудовані дані часто містяться в `word/media/`, custom XML parts або незвичних relationships.

### Швидкі перевірки
```bash
7z l file.docx
7z x file.docx -oout
```
Потім перевірте:

- `word/document.xml`
- `word/_rels/` на наявність зовнішніх зв’язків
- вбудовані медіафайли в `word/media/`


{{#include ../../banners/hacktricks-training.md}}
