# Stego

{{#include ../banners/hacktricks-training.md}}

Ovaj odeljak se fokusira na **pronalaženje i izdvajanje skrivenih podataka** iz slika, audio i video zapisa, dokumenata, arhiva i teksta. Steganografija prikriva postojanje komunikacije ugrađivanjem podataka u druge podatke.<sup>[[1]](#references)</sup>

Ako ste ovde zbog kriptografskih napada, pređite na odeljak **Crypto**.

## Entry Point

Pristupite steganografiji kao forenzičkom problemu: identifikujte pravi kontejner, popišite lokacije sa visokim signalom (metapodaci, dodati podaci, ugrađene datoteke), a tek zatim primenite tehnike ekstrakcije na nivou sadržaja.

### Workflow & triage

Strukturisan tok rada koji daje prioritet identifikaciji kontejnera, pregledu metapodataka/stringova, carving-u i grananju specifičnom za format.

{{#ref}}
workflow/README.md
{{#endref}}

### Images

Ovde se nalazi najveći deo CTF stega sadržaja: LSB/bit-plane (PNG/BMP), neobičnosti chunk/file formata, alati za JPEG i trikovi sa GIF datotekama sa više frejmova.

{{#ref}}
images/README.md
{{#endref}}

### Audio

Poruke u spektrogramu, LSB ugrađivanje u uzorke i tonovi telefonske tastature (DTMF) obrasci su koji se često ponavljaju.

{{#ref}}
audio/README.md
{{#endref}}

### Text

Ako se tekst normalno prikazuje, ali se ponaša neočekivano, razmotrite Unicode homoglife, zero-width karaktere ili kodiranje zasnovano na razmacima.

{{#ref}}
text/README.md
{{#endref}}

### Documents

PDF i Office datoteke su prvenstveno kontejneri; napadi se obično vrte oko ugrađenih datoteka/stream-ova, grafova objekata/relacija i ZIP ekstrakcije.

{{#ref}}
documents/README.md
{{#endref}}

### Malware and delivery-style steganography

Isporuka payload-a može koristiti datoteke koje izgledaju validno, kao što su GIF ili PNG slike, a koje nose tekstualne payload-e razgraničene markerima umesto skrivanja podataka u pikselima.

{{#ref}}
malware-and-network/README.md
{{#endref}}

## References

- [1] [NIST CSRC Glossary - Steganografija](https://csrc.nist.gov/glossary/term/steganography)
{{#include ../banners/hacktricks-training.md}}
