# PDF-lêeranalise

{{#include ../../../banners/hacktricks-training.md}}

**Vir verdere besonderhede, kyk:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/)

Die PDF-formaat is bekend vir sy kompleksiteit en potensiaal om data te verberg, wat dit 'n fokuspunt maak vir CTF forensiese uitdagings. Dit kombineer teks-elemente met binêre voorwerpe, wat gecomprimeer of geënkripteer kan wees, en kan skripte in tale soos JavaScript of Flash insluit. Om die PDF-struktuur te verstaan, kan 'n mens na Didier Stevens se [inleidende materiaal](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/) verwys, of gereedskap soos 'n teksredigeerder of 'n PDF-spesifieke redigeerder soos Origami gebruik.

Vir diepgaande verkenning of manipulasie van PDFs, is gereedskap soos [qpdf](https://github.com/qpdf/qpdf) en [Origami](https://github.com/mobmewireless/origami-pdf) beskikbaar. Verborge data binne PDFs kan verborge wees in:

- Onsigbare lae
- XMP-metadataformaat deur Adobe
- Inkrementele generasies
- Teks met dieselfde kleur as die agtergrond
- Teks agter beelde of oorvleuelende beelde
- Nie-vertande kommentaar

Vir pasgemaakte PDF-analise kan Python-biblioteke soos [PeepDF](https://github.com/jesparza/peepdf) gebruik word om op maat gemaakte parsingskripte te skep. Verder is die PDF se potensiaal vir verborge datastoor so groot dat hulpbronne soos die NSA-gids oor PDF-risiko's en teenmaatreëls, hoewel nie meer op sy oorspronklike plek gehos te word nie, steeds waardevolle insigte bied. 'n [kopie van die gids](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) en 'n versameling van [PDF-formaat truuks](https://github.com/corkami/docs/blob/master/PDF/PDF.md) deur Ange Albertini kan verdere leesstof oor die onderwerp bied.

{{#include ../../../banners/hacktricks-training.md}}
