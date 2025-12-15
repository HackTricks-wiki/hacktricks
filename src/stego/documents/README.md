# Steganografia ya Nyaraka

{{#include ../../banners/hacktricks-training.md}}

Nyaraka mara nyingi ni vyombo tu:

- PDF (faili zilizoambatishwa, streams)
- Office OOXML (`.docx/.xlsx/.pptx` are ZIPs)
- RTF / OLE miundo ya zamani

## PDF

### Mbinu

PDF ni chombo kilichopangwa chenye vitu (objects), streams, na faili za kuambatisha za hiari. Katika CTFs mara nyingi utahitaji:

- Toa viambatisho vilivyoambatishwa
- Dekomesha/kufanya gorofa object streams ili uweze kutafuta yaliyomo
- Tambua vitu vilivyofichwa (JS, picha zilizowekwa, streams zisizo za kawaida)

### Ukaguzi wa haraka
```bash
pdfinfo file.pdf
pdfdetach -list file.pdf
pdfdetach -saveall file.pdf
qpdf --qdf --object-streams=disable file.pdf out.pdf
```
Kisha tafuta ndani ya `out.pdf` kwa ajili ya vitu/mistari vinavyoshukiwa.

## Office OOXML

### Mbinu

Chukulia OOXML kama grafu ya mahusiano ya ZIP + XML; payloads mara nyingi zinaficha katika media, mahusiano, au sehemu maalum zisizo za kawaida.

OOXML files are ZIP containers. Hii inamaanisha:

- Hati ni mti wa saraka wa XML na rasilimali.
- Faili za `_rels/` za mahusiano zinaweza kuonyesha rasilimali za nje au sehemu zilizofichwa.
- Data iliyowekwa ndani mara nyingi iko katika `word/media/`, sehemu za XML maalum, au mahusiano yasiyo ya kawaida.

### Ukaguzi wa haraka
```bash
7z l file.docx
7z x file.docx -oout
```
Kisha chunguza:

- `word/document.xml`
- `word/_rels/` kwa mahusiano ya nje
- media zilizowekwa ndani ya `word/media/`

{{#include ../../banners/hacktricks-training.md}}
