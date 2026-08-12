# Stego

{{#include ../banners/hacktricks-training.md}}

Dieser Abschnitt konzentriert sich auf das **Finden und Extrahieren versteckter Daten** aus Bildern, Audio, Video, Dokumenten, Archiven und Text. Steganografie verbirgt die Existenz einer Kommunikation, indem Daten in andere Daten eingebettet werden.<sup>[[1]](#references)</sup>

Wenn du nach kryptografischen Angriffen suchst, gehe zum Abschnitt **Crypto**.

## Entry Point

Betrachte Steganografie als Forensikproblem: Identifiziere den tatsächlichen Container, untersuche Orte mit hoher Signalstärke (Metadaten, angehängte Daten, eingebettete Dateien) und wende erst danach Techniken zur Extraktion auf Inhaltsebene an.

### Workflow & Triage

Ein strukturierter Workflow, der die Identifizierung des Containers, die Untersuchung von Metadaten und Strings, Carving sowie formatspezifische Verzweigungen priorisiert.

{{#ref}}
workflow/README.md
{{#endref}}

### Images

Hier findet sich der größte Teil der CTF-Stego-Fälle: LSB/Bit-Planes (PNG/BMP), ungewöhnliche Chunk-/Dateiformate, JPEG-Tools und Tricks mit mehrteiligen GIFs.

{{#ref}}
images/README.md
{{#endref}}

### Audio

Spektrogramm-Nachrichten, LSB-Einbettung in Samples und Töne von Telefontastaturen (DTMF) sind wiederkehrende Muster.

{{#ref}}
audio/README.md
{{#endref}}

### Text

Wenn Text normal dargestellt wird, sich aber unerwartet verhält, solltest du Unicode-Homoglyphen, Zero-Width-Zeichen oder auf Whitespace basierende Codierung in Betracht ziehen.

{{#ref}}
text/README.md
{{#endref}}

### Documents

PDFs und Office-Dateien sind in erster Linie Container; Angriffe drehen sich normalerweise um eingebettete Dateien/Streams, Objekt-/Beziehungsgraphen und die ZIP-Extraktion.

{{#ref}}
documents/README.md
{{#endref}}

### Malware and delivery-style steganography

Bei der Payload-Zustellung können Dateien verwendet werden, die gültig aussehen, etwa GIF- oder PNG-Bilder, die markerbegrenzte Text-Payloads enthalten, anstatt Daten in Pixeln zu verstecken.

{{#ref}}
malware-and-network/README.md
{{#endref}}

## References

- [1] [NIST CSRC Glossar - Steganografie](https://csrc.nist.gov/glossary/term/steganography)
{{#include ../banners/hacktricks-training.md}}
