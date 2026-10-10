# Stego

{{#include ../banners/hacktricks-training.md}}

Ovaj odeljak se bavi **pronalaženjem i izdvajanjem skrivenih podataka** iz slika, zvuka, video-snimaka, dokumenata, arhiva i teksta. Steganografija prikriva postojanje komunikacije tako što ugrađuje podatke u druge podatke.<sup>[[1]](#references)</sup>

Ako ste ovde zbog kriptografskih napada, pređite na odeljak **Crypto**.

## Ulazna tačka

Pristupite steganografiji kao forenzičkom problemu: utvrdite koji je stvarni kontejner, proverite lokacije sa najviše potencijalnih tragova (metapodatke, dodate podatke, ugrađene datoteke), a tek zatim primenite tehnike izdvajanja na nivou sadržaja.

### Tok rada i trijaža

Strukturisani tok rada koji daje prioritet utvrđivanju kontejnera, pregledu metapodataka i nizova, izdvajanju podataka i grananju prema konkretnom formatu.

{{#ref}}
workflow/README.md
{{#endref}}

### Slike

Ovde se nalazi većina CTF steganografije: LSB/bit-planes (PNG/BMP), neobičnosti u chunk/file-format strukturama, alati za JPEG i trikovi sa GIF-ovima sa više frejmova.

{{#ref}}
images/README.md
{{#endref}}

### Zvuk

Poruke u spektrogramu, ugrađivanje u LSB uzoraka i tonovi telefonske tastature (DTMF) česti su obrasci.

{{#ref}}
audio/README.md
{{#endref}}

### Tekst

Ako se tekst prikazuje uobičajeno, ali se ponaša neočekivano, razmotrite Unicode homoglife, znakove nulte širine ili kodiranje zasnovano na razmacima.

{{#ref}}
text/README.md
{{#endref}}

### Dokumenti

PDF i Office datoteke su pre svega kontejneri; napadi se obično zasnivaju na ugrađenim datotekama i tokovima, grafovima objekata i relacija i izdvajanju ZIP sadržaja.

{{#ref}}
documents/README.md
{{#endref}}

### Malware i steganografija za isporuku payload-a

Za isporuku payload-a mogu da se koriste datoteke koje izgledaju ispravno, kao što su GIF ili PNG slike, a koje sadrže tekstualne payload-e omeđene markerima umesto podataka skrivenih u pikselima.

{{#ref}}
malware-and-network/README.md
{{#endref}}

## References

- [1] [NIST CSRC Rečnik pojmova - Steganografija](https://csrc.nist.gov/glossary/term/steganography)
{{#include ../banners/hacktricks-training.md}}
