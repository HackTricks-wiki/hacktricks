# Stego

{{#include ../banners/hacktricks-training.md}}

Dieser Abschnitt konzentriert sich darauf, **versteckte Daten** in Bildern, Audio, Videos, Dokumenten, Archiven und Texten **zu finden und zu extrahieren**. Steganografie verbirgt die Existenz einer Kommunikation, indem Daten in andere Daten eingebettet werden.<sup>[[1]](#references)</sup>

Wenn du nach kryptografischen Angriffen suchst, gehe zum Abschnitt **Crypto**.

## Einstiegspunkt

Betrachte Steganografie als forensisches Problem: Identifiziere den tatsächlichen Container, untersuche gezielt aussagekräftige Bereiche (Metadaten, angehängte Daten, eingebettete Dateien) und wende erst danach Techniken zur Extraktion auf Inhaltsebene an.

### Workflow & triage

Ein strukturierter Workflow, der die Identifizierung des Containers, die Untersuchung von Metadaten und Strings, das Carving und formatspezifische Verzweigungen priorisiert.

{{#ref}}
workflow/README.md
{{#endref}}

### Bilder

Hier findet sich der Großteil der CTF-Stego-Aufgaben: LSB/Bit-Ebenen (PNG/BMP), ungewöhnliche Chunks oder Dateiformate, JPEG-Tools und Tricks mit mehreren GIF-Frames.

{{#ref}}
images/README.md
{{#endref}}

### Audio

Spektrogramm-Nachrichten, LSB-Einbettung in Samples und Töne der Telefontastatur (DTMF) sind wiederkehrende Muster.

{{#ref}}
audio/README.md
{{#endref}}

### Text

Wenn Text normal dargestellt wird, sich aber unerwartet verhält, solltest du Unicode-Homoglyphen, Zero-Width-Zeichen oder eine auf Leerzeichen basierende Kodierung in Betracht ziehen.

{{#ref}}
text/README.md
{{#endref}}

### Dokumente

PDFs und Office-Dateien sind zuerst einmal Container; Angriffe drehen sich meist um eingebettete Dateien/Streams, Objekt- und Beziehungsgraphen sowie die ZIP-Extraktion.

{{#ref}}
documents/README.md
{{#endref}}

### Steganografie in Malware und bei der Payload-Auslieferung

Bei der Payload-Auslieferung können gültig wirkende Dateien wie GIF- oder PNG-Bilder verwendet werden, die durch Marker begrenzte Text-Payloads enthalten, anstatt Daten in Pixeln zu verbergen.

{{#ref}}
malware-and-network/README.md
{{#endref}}

## References

- [1] [NIST CSRC-Glossar – Steganografie](https://csrc.nist.gov/glossary/term/steganography)
{{#include ../banners/hacktricks-training.md}}
