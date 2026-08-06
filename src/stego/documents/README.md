# Belge Steganografisi

{{#include ../../banners/hacktricks-training.md}}

Belgeler çoğu zaman yalnızca kapsayıcılardır:

- PDF (gömülü dosyalar, stream'ler)
- Office OOXML (`.docx/.xlsx/.pptx` ZIP'tir)
- RTF / OLE legacy formatları

## PDF

### Technique

PDF; objects, stream'ler ve isteğe bağlı gömülü dosyalar içeren yapılandırılmış bir kapsayıcıdır. CTF'lerde genellikle şunları yapmanız gerekir:

- Gömülü attachment'ları çıkarmak
- İçeriği arayabilmek için object stream'lerini decompress/flatten etmek
- Gizli object'leri (JS, gömülü images, olağandışı stream'ler) belirlemek

### Hızlı kontroller
```bash
pdfinfo file.pdf
pdfdetach -list file.pdf
pdfdetach -saveall file.pdf
qpdf --qdf --object-streams=disable file.pdf out.pdf
```
Ardından `out.pdf` içinde şüpheli nesneleri/dizeleri arayın.

## Office OOXML

### Teknik

OOXML'i bir ZIP + XML ilişki grafiği olarak ele alın; payload'lar genellikle media, relationships veya sıra dışı custom parts içinde gizlenir.

OOXML dosyaları ZIP container'larıdır. Bu şu anlama gelir:

- Belge, XML ve asset'lerden oluşan bir directory tree'dir.
- `_rels/` relationship dosyaları external resources veya gizli parts'a işaret edebilir.
- Embedded data sıklıkla `word/media/`, custom XML parts veya alışılmadık relationships içinde bulunur.

### Hızlı kontroller
```bash
7z l file.docx
7z x file.docx -oout
```
Ardından şunları inceleyin:

- `word/document.xml`
- harici ilişkiler için `word/_rels/`
- `word/media/` içindeki gömülü medya


{{#include ../../banners/hacktricks-training.md}}
