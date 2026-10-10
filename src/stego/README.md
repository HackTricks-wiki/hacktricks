# Stego

{{#include ../banners/hacktricks-training.md}}

Hierdie afdeling fokus op **die vind en onttrekking van versteekte data** uit beelde, oudio, video, dokumente, argiewe en teks. Steganografie verberg die bestaan van ’n kommunikasie deur data binne ander data in te sluit.<sup>[[1]](#references)</sup>

As jy hier is vir kriptografiese aanvalle, gaan na die **Crypto**-afdeling.

## Beginpunt

Benader steganografie as ’n forensiese probleem: identifiseer die werklike houer, ondersoek plekke met baie potensiële inligting (metadata, aangehegte data, ingebedde lêers), en pas eers daarna tegnieke toe om inhoud te onttrek.

### Werkvloei en aanvanklike ondersoek

’n Gestruktureerde werkvloei wat prioriteit gee aan die identifisering van houers, die ondersoek van metadata en stringe, carving en formaatspesifieke vertakkings.

{{#ref}}
workflow/README.md
{{#endref}}

### Beelde

Waar die meeste CTF-stego voorkom: LSB/bit-vlakke (PNG/BMP), ongewone brokkies/lêerformate, JPEG-nutsgoed en truuks met GIF-lêers met veelvuldige rame.

{{#ref}}
images/README.md
{{#endref}}

### Oudio

Boodskappe in spektrogramme, LSB-inbedding in monsters en toonkodes van telefoonsleutelborde (DTMF) is algemene patrone.

{{#ref}}
audio/README.md
{{#endref}}

### Teks

As teks normaal vertoon word maar onverwags optree, oorweeg Unicode-homogliewe, nulwydtekarakters of enkodering wat op witspasie gebaseer is.

{{#ref}}
text/README.md
{{#endref}}

### Dokumente

PDF- en Office-lêers is eerstens houers; aanvalle draai gewoonlik om ingebedde lêers/strome, objek-/verhoudingsgrafieke en ZIP-onttrekking.

{{#ref}}
documents/README.md
{{#endref}}

### Malware en steganografie vir aflewering

Loodsvragaflewering kan lêers gebruik wat geldig lyk, soos GIF- of PNG-beelde, wat merkerafgebakende teksloodsvragte bevat eerder as data wat in pixels versteek is.

{{#ref}}
malware-and-network/README.md
{{#endref}}

## References

- [1] [NIST CSRC-woordelys - Steganografie](https://csrc.nist.gov/glossary/term/steganography)
{{#include ../banners/hacktricks-training.md}}
