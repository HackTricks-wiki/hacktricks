# Stego

{{#include ../banners/hacktricks-training.md}}

Sehemu hii inalenga **kutafuta na kutoa data iliyofichwa** kutoka kwenye files (images/audio/video/documents/archives) na kutoka kwenye steganography ya msingi wa maandishi.

Ikiwa uko hapa kwa ajili ya mashambulizi ya cryptographic, nenda kwenye sehemu ya **Crypto**.

## Sehemu ya kuanzia

Shughulikia steganography kama tatizo la forensics: tambua container halisi, kagua maeneo yenye uwezekano mkubwa wa kutoa taarifa (metadata, data iliyoongezwa mwishoni, files zilizopachikwa), kisha tumia mbinu za extraction za kiwango cha maudhui.

### Workflow na triage

Workflow iliyopangwa inayoweka kipaumbele kwenye utambuzi wa container, ukaguzi wa metadata/strings, carving, na branching mahususi kwa format.

{{#ref}}
workflow/README.md
{{#endref}}

### Images

Hapa ndipo stego nyingi za CTF hupatikana: LSB/bit-planes (PNG/BMP), mambo yasiyo ya kawaida kwenye chunks/file-format, zana za JPEG, na mbinu za GIF zenye frames nyingi.

{{#ref}}
images/README.md
{{#endref}}

### Audio

Ujumbe wa spectrogram, embedding ya sample LSB, na sauti za vitufe vya simu (DTMF) ni mifumo inayojirudia.

{{#ref}}
audio/README.md
{{#endref}}

### Text

Ikiwa text inaonekana kawaida lakini inatenda kwa njia isiyotarajiwa, zingatia Unicode homoglyphs, zero-width characters, au encoding inayotumia whitespace.

{{#ref}}
text/README.md
{{#endref}}

### Documents

PDFs na Office files ni containers kwanza; mashambulizi kwa kawaida huhusu files/streams zilizopachikwa, object/relationship graphs, na ZIP extraction.

{{#ref}}
documents/README.md
{{#endref}}

### Steganography ya malware na delivery

Uwasilishaji wa payload mara nyingi hutumia files zinazoonekana kuwa halali (kwa mfano, GIF/PNG) zinazobeba payloads za text zilizotenganishwa kwa markers, badala ya kuficha data katika kiwango cha pixels.

{{#ref}}
malware-and-network/README.md
{{#endref}}

{{#include ../banners/hacktricks-training.md}}
