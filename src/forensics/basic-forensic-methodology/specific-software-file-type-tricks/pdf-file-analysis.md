# PDF-Dateianalyse

{{#include ../../../banners/hacktricks-training.md}}

**Für weitere Details siehe:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/)

Das PDF-Format ist bekannt für seine Komplexität und das Potenzial, Daten zu verbergen, was es zu einem Schwerpunkt für CTF-Forensik-Herausforderungen macht. Es kombiniert Text-Elemente mit binären Objekten, die komprimiert oder verschlüsselt sein können, und kann Skripte in Sprachen wie JavaScript oder Flash enthalten. Um die PDF-Struktur zu verstehen, kann man auf Didier Stevens' [einführendes Material](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/) zurückgreifen oder Werkzeuge wie einen Texteditor oder einen PDF-spezifischen Editor wie Origami verwenden.

Für eine eingehende Untersuchung oder Manipulation von PDFs stehen Werkzeuge wie [qpdf](https://github.com/qpdf/qpdf) und [Origami](https://github.com/mobmewireless/origami-pdf) zur Verfügung. Versteckte Daten innerhalb von PDFs können in folgenden Bereichen verborgen sein:

- Unsichtbare Ebenen
- XMP-Metadatenformat von Adobe
- Inkrementelle Generationen
- Text in der gleichen Farbe wie der Hintergrund
- Text hinter Bildern oder überlappenden Bildern
- Nicht angezeigte Kommentare

Für benutzerdefinierte PDF-Analysen können Python-Bibliotheken wie [PeepDF](https://github.com/jesparza/peepdf) verwendet werden, um maßgeschneiderte Parsing-Skripte zu erstellen. Darüber hinaus ist das Potenzial von PDFs zur Speicherung versteckter Daten so groß, dass Ressourcen wie der NSA-Leitfaden zu PDF-Risiken und Gegenmaßnahmen, obwohl nicht mehr an seinem ursprünglichen Standort gehostet, weiterhin wertvolle Einblicke bieten. Eine [Kopie des Leitfadens](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) und eine Sammlung von [PDF-Format-Tricks](https://github.com/corkami/docs/blob/master/PDF/PDF.md) von Ange Albertini können weitere Lektüre zu diesem Thema bieten.

{{#include ../../../banners/hacktricks-training.md}}
