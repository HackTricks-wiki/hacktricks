# Stego

{{#include ../banners/hacktricks-training.md}}

Dieser Abschnitt konzentriert sich auf das **Auffinden und Extrahieren versteckter Daten** aus Dateien (Bildern/Audio/Video/Dokumenten/Archiven) sowie auf textbasierte Steganografie.

Wenn du nach kryptografischen Angriffen suchst, gehe zum Abschnitt **Crypto**.

## Einstiegspunkt

Betrachte Steganografie als Forensikproblem: Identifiziere den tatsächlichen Container, untersuche Orte mit hoher Signalwirkung (Metadaten, angehängte Daten, eingebettete Dateien) und wende erst danach Techniken zur inhaltlichen Extraktion an.

### Workflow & Triage

Ein strukturierter Workflow, der die Identifizierung des Containers, die Untersuchung von Metadaten/Strings, Carving und formatspezifische Verzweigungen priorisiert.

{{#ref}}
workflow/README.md
{{#endref}}

### Bilder

Hier findet sich der größte Teil der CTF-Stego-Aufgaben: LSB/Bit-Ebenen (PNG/BMP), Besonderheiten von Chunks/Dateiformaten, JPEG-Tools und Tricks mit mehrteiligen GIFs.

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

### Dokumente

PDFs und Office-Dateien sind in erster Linie Container; Angriffe drehen sich normalerweise um eingebettete Dateien/Streams, Objekt-/Beziehungsgraphen und die ZIP-Extraktion.

{{#ref}}
documents/README.md
{{#endref}}

### Malware- und auslieferungsbezogene Steganografie

Die Payload-Auslieferung verwendet häufig echt wirkende Dateien (z. B. GIF/PNG), die durch Marker begrenzte Text-Payloads enthalten, anstatt Daten auf Pixelebene zu verstecken.

{{#ref}}
malware-and-network/README.md
{{#endref}}

{{#include ../banners/hacktricks-training.md}}
