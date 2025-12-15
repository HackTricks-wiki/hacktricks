# Document Steganography

{{#include ../../banners/hacktricks-training.md}}

Belgeler genellikle yalnızca kapsayıcıdır:

- PDF (gömülü dosyalar, akışlar)
- Office OOXML (`.docx/.xlsx/.pptx` ZIP arşivleridir)
- RTF / OLE eski formatlar

## PDF

### Teknik

PDF, nesneler, akışlar ve isteğe bağlı gömülü dosyalar içeren yapılandırılmış bir kapsayıcıdır. CTF'lerde genellikle şunlara ihtiyaç duyarsınız:

- Gömülü ekleri çıkarmak
- Nesne akışlarını dekomprese/flatten ederek içerikte arama yapabilmek
- Gizli nesneleri tespit etmek (JS, gömülü görseller, olağandışı akışlar)

### Hızlı kontroller
```bash
pdfinfo file.pdf
pdfdetach -list file.pdf
pdfdetach -saveall file.pdf
qpdf --qdf --object-streams=disable file.pdf out.pdf
```
Sonra `out.pdf` içinde şüpheli nesneler/karakter dizileri arayın.

## Office OOXML

### Teknik

OOXML'i bir ZIP + XML ilişki grafiği olarak ele alın; payloads genellikle media, relationships veya sıra dışı özel parçalarda gizlenir.

OOXML dosyaları ZIP kapsayıcılarıdır. Bu demektir ki:

- Belge, XML ve varlıklardan oluşan bir dizin ağacıdır.
- `_rels/` ilişki dosyaları dış kaynaklara veya gizli parçalara işaret edebilir.
- Gömülü veriler sıklıkla `word/media/`, özel XML parçaları veya alışılmadık ilişkiler içinde bulunur.

### Hızlı kontroller
```bash
7z l file.docx
7z x file.docx -oout
```
Sonra inceleyin:

- `word/document.xml`
- `word/_rels/` harici ilişkiler için
- `word/media/` içindeki gömülü medya

{{#include ../../banners/hacktricks-training.md}}
