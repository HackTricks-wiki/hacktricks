# Stego

{{#include ../banners/hacktricks-training.md}}

Hierdie afdeling fokus op **die vind en onttrekking van versteekte data** uit beelde, oudio, video, dokumente, argiewe en teks. Steganografie verberg die bestaan van ’n kommunikasie deur data binne ander data in te bed.<sup>[[1]](#references)</sup>

As jy hier is vir kriptografiese attacks, gaan na die **Crypto**-afdeling.

## Beginpunt

Benader steganografie as ’n forensiese probleem: identifiseer die werklike houer, enumereer liggings met ’n hoë sein (metadata, aangehegte data, ingebedde lêers), en pas eers daarna inhoudsvlak-onttrekkingstegnieke toe.

### Workflow & triage

’n Gestruktureerde workflow wat prioriteit gee aan houer-identifikasie, metadata/string-inspeksie, carving en formaatspesifieke vertakking.

{{#ref}}
workflow/README.md
{{#endref}}

### Beelde

Waar die meeste CTF stego voorkom: LSB/bit-planes (PNG/BMP), eienaardighede in chunks/lêerformate, JPEG-tooling en multi-frame GIF-truuks.

{{#ref}}
images/README.md
{{#endref}}

### Oudio

Spektrogramboodskappe, sample-LSB-inbedding en telefoonsleutelbordtone (DTMF) is herhalende patrone.

{{#ref}}
audio/README.md
{{#endref}}

### Teks

As teks normaal weergegee word maar onverwags optree, oorweeg Unicode-homogliewe, zero-width-karakters of whitespace-gebaseerde encoding.

{{#ref}}
text/README.md
{{#endref}}

### Dokumente

PDF’s en Office-lêers is eerstens houers; attacks draai gewoonlik om ingebedde lêers/streams, objek-/verhoudingsgrafieke en ZIP-onttrekking.

{{#ref}}
documents/README.md
{{#endref}}

### Malware- en delivery-styl-steganografie

Payload delivery kan lêers gebruik wat geldig lyk, soos GIF- of PNG-beelde, wat marker-afgebakende teks-payloads bevat eerder as om data in pixels te versteek.

{{#ref}}
malware-and-network/README.md
{{#endref}}

## References

- [1] [NIST CSRC Glossary - Steganografie](https://csrc.nist.gov/glossary/term/steganography)
{{#include ../banners/hacktricks-training.md}}
