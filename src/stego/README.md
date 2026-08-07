# Stego

{{#include ../banners/hacktricks-training.md}}

Ovaj odeljak se fokusira na **pronalaženje i izdvajanje skrivenih podataka** iz datoteka (slika/audio/video dokumenata/arhiva) i na steganografiju zasnovanu na tekstu.

Ako ste ovde zbog kriptografskih napada, pređite na odeljak **Crypto**.

## Entry Point

Pristupite steganografiji kao forenzičkom problemu: identifikujte pravi kontejner, popišite lokacije sa visokim signalom (metapodaci, dodati podaci, ugrađene datoteke), a tek zatim primenite tehnike izdvajanja na nivou sadržaja.

### Workflow & triage

Strukturisani workflow koji daje prioritet identifikaciji kontejnera, pregledu metapodataka/stringova, carving-u i grananju specifičnom za format.

{{#ref}}
workflow/README.md
{{#endref}}

### Images

Ovde se nalazi najveći deo CTF stega: LSB/bit-planes (PNG/BMP), neobičnosti chunk/file-format strukture, alati za JPEG i trikovi sa GIF datotekama sa više frejmova.

{{#ref}}
images/README.md
{{#endref}}

### Audio

Poruke u spectrogram-u, LSB embedding u uzorcima i tonovi telefonske tastature (DTMF) predstavljaju česte obrasce.

{{#ref}}
audio/README.md
{{#endref}}

### Text

Ako se tekst normalno prikazuje, ali se ponaša neočekivano, razmotrite Unicode homoglyphs, zero-width characters ili encoding zasnovan na razmacima.

{{#ref}}
text/README.md
{{#endref}}

### Documents

PDF i Office datoteke su prvenstveno kontejneri; napadi se obično vrte oko ugrađenih datoteka/stream-ova, object/relationship grafova i ZIP ekstrakcije.

{{#ref}}
documents/README.md
{{#endref}}

### Malware and delivery-style steganography

Isporuka payload-a često koristi datoteke koje izgledaju validno (npr. GIF/PNG), a koje sadrže tekstualne payload-e razgraničene markerima, umesto skrivanja na nivou piksela.

{{#ref}}
malware-and-network/README.md
{{#endref}}

{{#include ../banners/hacktricks-training.md}}
