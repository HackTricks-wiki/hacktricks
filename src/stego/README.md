# Stego

{{#include ../banners/hacktricks-training.md}}

Sehemu hii inalenga **kutafuta na kutoa data iliyofichwa** kutoka kwenye picha, sauti, video, nyaraka, archives, na maandishi. Steganography huficha uwepo wa mawasiliano kwa kupachika data ndani ya data nyingine.<sup>[[1]](#references)</sup>

Ikiwa uko hapa kwa ajili ya cryptographic attacks, nenda kwenye sehemu ya **Crypto**.

## Entry Point

Shughulikia steganography kama tatizo la forensics: tambua container halisi, kagua maeneo yenye ishara nyingi (metadata, data iliyoongezwa mwishoni, embedded files), kisha tumia mbinu za content-level extraction.

### Workflow & triage

Workflow iliyopangwa inayotanguliza utambuzi wa container, ukaguzi wa metadata/strings, carving, na branching kulingana na format.

{{#ref}}
workflow/README.md
{{#endref}}

### Images

Hapa ndipo stego nyingi za CTF hupatikana: LSB/bit-planes (PNG/BMP), hitilafu za chunk/file-format, zana za JPEG, na mbinu za GIF zenye frames nyingi.

{{#ref}}
images/README.md
{{#endref}}

### Audio

Ujumbe kwenye spectrogram, LSB embedding kwenye samples, na tones za telephone keypad (DTMF) ni mifumo inayojirudia.

{{#ref}}
audio/README.md
{{#endref}}

### Text

Ikiwa maandishi yanaonekana kawaida lakini yanafanya mambo yasiyotarajiwa, zingatia Unicode homoglyphs, zero-width characters, au encoding inayotumia whitespace.

{{#ref}}
text/README.md
{{#endref}}

### Documents

PDFs na Office files ni containers kwanza; attacks kwa kawaida huzunguka embedded files/streams, object/relationship graphs, na ZIP extraction.

{{#ref}}
documents/README.md
{{#endref}}

### Malware and delivery-style steganography

Payload delivery inaweza kutumia files zinazoonekana halali, kama GIF au PNG images, ambazo hubeba marker-delimited text payloads badala ya kuficha data kwenye pixels.

{{#ref}}
malware-and-network/README.md
{{#endref}}

## References

- [1] [NIST CSRC Glossary - Steganography](https://csrc.nist.gov/glossary/term/steganography)
{{#include ../banners/hacktricks-training.md}}
