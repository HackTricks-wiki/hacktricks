# Stego

{{#include ../banners/hacktricks-training.md}}

Hierdie afdeling fokus op **die vind en onttrekking van versteekte data** uit lêers (beelde/klank/video/dokumente/argiewe) en uit teksgebaseerde steganografie.

As jy hier is vir kriptografiese aanvalle, gaan na die **Crypto**-afdeling.

## Beginpunt

Benader steganografie as 'n forensiese probleem: identifiseer die werklike container, lys hoë-sein-liggings (metadata, aangehegte data, ingebedde lêers), en pas eers daarna inhoudsvlak-onttrekkingstegnieke toe.

### Werkvloei en triage

'n Gestruktureerde werkvloei wat prioriteit gee aan container-identifikasie, metadata/string-inspeksie, carving en formaatspesifieke vertakking.

{{#ref}}
workflow/README.md
{{#endref}}

### Beelde

Waar die meeste CTF-stego voorkom: LSB/bit-planes (PNG/BMP), eienaardighede in chunks/lêerformate, JPEG-tools en multi-frame GIF-truuks.

{{#ref}}
images/README.md
{{#endref}}

### Klank

Spektrogramboodskappe, sample-LSB-inbedding en telefoonsleutelbordtone (DTMF) is algemene patrone.

{{#ref}}
audio/README.md
{{#endref}}

### Teks

As teks normaal vertoon, maar onverwags optree, oorweeg Unicode-homogliewe, zero-width-karakters of whitespace-gebaseerde enkodering.

{{#ref}}
text/README.md
{{#endref}}

### Dokumente

PDF's en Office-lêers is eerstens containers; aanvalle wentel gewoonlik om ingebedde lêers/streams, objek-/verhoudingsgrafieke en ZIP-onttrekking.

{{#ref}}
documents/README.md
{{#endref}}

### Malware- en afleweringstyl-steganografie

Payload-aflewering gebruik dikwels lêers wat geldig lyk (bv. GIF/PNG) en teks-payloads bevat wat deur merkers afgebaken word, eerder as om data op pixelvlak te versteek.

{{#ref}}
malware-and-network/README.md
{{#endref}}

{{#include ../banners/hacktricks-training.md}}
