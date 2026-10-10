# Stego

{{#include ../banners/hacktricks-training.md}}

Sehemu hii inalenga **kutafuta na kutoa data iliyofichwa** kutoka kwenye picha, sauti, video, nyaraka, faili za archive, na maandishi. Steganografia huficha kuwepo kwa mawasiliano kwa kupachika data ndani ya data nyingine.<sup>[[1]](#references)</sup>

Ikiwa unatafuta mashambulizi ya cryptographic, nenda kwenye sehemu ya **Crypto**.

## Mahali pa Kuanza

Chukulia steganografia kama tatizo la uchunguzi wa kidijitali: tambua container halisi, kagua maeneo yenye uwezekano mkubwa wa kuwa na data (metadata, data iliyoongezwa mwishoni, faili zilizopachikwa), kisha tumia mbinu za kutoa data kulingana na maudhui.

### Mtiririko wa kazi na uchujaji wa awali

Mtiririko wa kazi uliopangwa unaotanguliza utambuzi wa container, ukaguzi wa metadata na string, carving, na kuchagua hatua kulingana na format.

{{#ref}}
workflow/README.md
{{#endref}}

### Picha

Hapa ndipo stego nyingi za CTF hupatikana: LSB/bit-planes (PNG/BMP), hitilafu za chunks/format za faili, zana za JPEG, na mbinu za GIF zenye fremu nyingi.

{{#ref}}
images/README.md
{{#endref}}

### Sauti

Ujumbe kwenye spectrogram, upachikaji wa LSB kwenye sampuli, na milio ya vitufe vya simu (DTMF) ni mifumo inayojirudia.

{{#ref}}
audio/README.md
{{#endref}}

### Maandishi

Ikiwa maandishi yanaonekana ya kawaida lakini yanatenda kwa njia isiyotarajiwa, zingatia homoglyphs za Unicode, herufi zisizo na upana (zero-width), au usimbaji unaotumia nafasi tupu.

{{#ref}}
text/README.md
{{#endref}}

### Nyaraka

PDF na faili za Office kwanza ni containers; mashambulizi kwa kawaida huhusu faili/mitiririko iliyopachikwa, grafu za object/relationship, na utoaji wa ZIP.

{{#ref}}
documents/README.md
{{#endref}}

### Malware na steganografia ya mtindo wa usambazaji

Usambazaji wa payload unaweza kutumia faili zinazoonekana halali, kama picha za GIF au PNG, zenye payload za maandishi zilizowekwa alama za mwanzo na mwisho badala ya kuficha data kwenye pikseli.

{{#ref}}
malware-and-network/README.md
{{#endref}}

## References

- [1] [Kamusi ya NIST CSRC - Steganografia](https://csrc.nist.gov/glossary/term/steganography)
{{#include ../banners/hacktricks-training.md}}
