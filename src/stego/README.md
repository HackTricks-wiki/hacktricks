# Stego

{{#include ../banners/hacktricks-training.md}}

Dieser Abschnitt konzentriert sich auf das Auffinden und Extrahieren versteckter Daten aus Dateien (Bilder/Audio/Video/Dokumente/Archive) und aus textbasierter Steganographie.

Wenn du wegen kryptographischer Angriffe hier bist, gehe zum Abschnitt **Crypto**.

## Einstiegspunkt

Betrachte Steganographie als ein forensisches Problem: identifiziere den realen Container, zähle relevante Stellen auf (Metadaten, angehängte Daten, eingebettete Dateien) und wende erst dann inhaltliche Extraktionstechniken an.

### Workflow & triage

Ein strukturierter Workflow, der die Container-Identifikation, Metadaten/String-Inspektion, Carving und format-spezifische Verzweigungen priorisiert.
{{#ref}}
workflow/README.md
{{#endref}}

### Bilder

Wo die meiste CTF stego zu finden ist: LSB/bit-planes (PNG/BMP), Chunk-/Dateiformat-Anomalien, JPEG-Tools und Tricks mit animierten GIFs.
{{#ref}}
images/README.md
{{#endref}}

### Audio

Spectrogram-Nachrichten, sample LSB embedding und Telefon-Tastenton-Signale (DTMF) sind wiederkehrende Muster.
{{#ref}}
audio/README.md
{{#endref}}

### Text

Wenn Text normal dargestellt wird, sich aber unerwartet verhält, denke an Unicode-Homoglyphen, Zero-Width-Zeichen oder whitespace-basierte Kodierung.
{{#ref}}
text/README.md
{{#endref}}

### Dokumente

PDFs und Office-Dateien sind in erster Linie Container; Angriffe drehen sich meist um eingebettete Dateien/Streams, Objekt-/Beziehungsgraphen und ZIP-Extraktion.
{{#ref}}
documents/README.md
{{#endref}}

### Malware und delivery-orientierte Steganographie

Die Zustellung von Payloads nutzt häufig legitim aussehende Dateien (z. B. GIF/PNG), die marker-abgegrenzte Text-Payloads enthalten, statt Pixel-Level-Verstecken.
{{#ref}}
malware-and-network/README.md
{{#endref}}

{{#include ../banners/hacktricks-training.md}}
