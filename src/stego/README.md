# Stego

{{#include ../banners/hacktricks-training.md}}

Hierdie afdeling fokus op **die opspoor en uittrekking van verborge data** uit lêers (beelde/klank/video/dokumente/argiewe) en uit teksgebaseerde steganography.

As jy hier is vir kriptografiese aanvalle, gaan na die **Crypto** afdeling.

## Ingangspunt

Behandel steganography as 'n forensics-probleem: identifiseer die werklike container, tel hoë-signaal lokasies op (metadata, appended data, embedded files), en eers dan pas content-level uittrektegnieke toe.

### Werksvloei & triage

'n Gestruktureerde werksvloei wat container-identifikasie, metadata/string-inspeksie, carving, en formaat-spesifieke takke prioritiseer.
{{#ref}}
workflow/README.md
{{#endref}}

### Beelde

Waar meeste CTF stego voorkom: LSB/bit-planes (PNG/BMP), chunk/file-format vreemdhede, JPEG tooling, en multi-frame GIF-truuks.
{{#ref}}
images/README.md
{{#endref}}

### Klank

Spectrogram-boodskappe, sample LSB embedding, en telefoon-kieser-tone (DTMF) is herhalende patrone.
{{#ref}}
audio/README.md
{{#endref}}

### Teks

As teks normaal vertoon maar onverwags optree, oorweeg Unicode-homoglyphs, zero-width characters, of whitespace-gebaseerde kodering.
{{#ref}}
text/README.md
{{#endref}}

### Dokumente

PDFs en Office-lêers is eerstens houers; aanvalle draai gewoonlik om embedded files/streams, object/relationship graphs, en ZIP-uittrekking.
{{#ref}}
documents/README.md
{{#endref}}

### Malware en delivery-style steganography

Payload-aflewering gebruik dikwels geldig-voorkomende lêers (bv. GIF/PNG) wat marker-delimited teks payloads dra, eerder as pixel-level verberging.
{{#ref}}
malware-and-network/README.md
{{#endref}}

{{#include ../banners/hacktricks-training.md}}
