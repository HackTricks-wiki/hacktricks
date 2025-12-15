# Stego

{{#include ../banners/hacktricks-training.md}}

Sehemu hii inaangazia **kutafuta na kutoa data iliyofichwa** kutoka kwa files (images/audio/video/documents/archives) na kutoka kwa text-based steganography.

Ikiwa umekuja kwa ajili ya mashambulizi ya kriptografia, nenda kwenye sehemu ya **Crypto**.

## Sehemu ya Kuingia

Karibia steganography kama tatizo la forensics: tambua container halisi, orodhesha maeneo yenye ishara kubwa (metadata, appended data, embedded files), na kisha tumia mbinu za content-level extraction.

### Mfumo wa kazi & triage

Mfumo uliopangwa unaoweka kipaumbele kwenye utambuzi wa container, ukaguzi wa metadata/string, carving, na matawi maalum kwa format.
{{#ref}}
workflow/README.md
{{#endref}}

### Picha

Ambapo sehemu kubwa ya CTF stego inapatikana: LSB/bit-planes (PNG/BMP), chunk/file-format weirdness, JPEG tooling, na multi-frame GIF tricks.
{{#ref}}
images/README.md
{{#endref}}

### Sauti

Ujumbe katika spectrogram, sample LSB embedding, na telephone keypad tones (DTMF) ni mifumo inayorudiwa.
{{#ref}}
audio/README.md
{{#endref}}

### Maandishi

Ikiwa text inaonekana kawaida lakini inatenda kwa njia isiyotegemewa, tazama Unicode homoglyphs, zero-width characters, au whitespace-based encoding.
{{#ref}}
text/README.md
{{#endref}}

### Documents

PDFs na Office files ni containers kwanza; mashambulizi kwa kawaida yanazunguka embedded files/streams, object/relationship graphs, na ZIP extraction.
{{#ref}}
documents/README.md
{{#endref}}

### Malware and delivery-style steganography

Delivery ya payload mara nyingi inatumia files zinazoonekana halali (e.g., GIF/PNG) ambazo zinabeba marker-delimited text payloads, badala ya kuficha kwa ngazi ya pikseli.
{{#ref}}
malware-and-network/README.md
{{#endref}}

{{#include ../banners/hacktricks-training.md}}
