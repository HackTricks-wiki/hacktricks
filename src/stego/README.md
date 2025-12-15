# Stego

{{#include ../banners/hacktricks-training.md}}

Ovaj odeljak se fokusira na **pronalaženje i izvlačenje skrivenih podataka** iz fajlova (images/audio/video/documents/archives) i iz text-based steganography.

Ako ste ovde zbog cryptographic attacks, idite u sekciju **Crypto**.

## Ulazna tačka

Pristupite steganography kao forensics problemu: identifikujte pravi container, nabrojte lokacije sa visokim signalom (metadata, appended data, embedded files), i tek onda primenite tehnike ekstrakcije na nivou sadržaja.

### Tok rada i trijaža

Strukturisan tok rada koji prioritizuje identifikaciju container-a, metadata/string inspekciju, carving, i grananje specifično za format.
{{#ref}}
workflow/README.md
{{#endref}}

### Slike

Gde većina CTF stego zadataka nastaje: LSB/bit-planes (PNG/BMP), chunk/file-format weirdness, JPEG tooling, i multi-frame GIF trikovi.
{{#ref}}
images/README.md
{{#endref}}

### Audio

Poruke u spektrogramu, sample LSB embedding, i tonovi telefonske tastature (DTMF) su česti obrasci.
{{#ref}}
audio/README.md
{{#endref}}

### Tekst

Ako se tekst normalno prikazuje ali se ponaša neočekivano, razmotrite Unicode homoglyphs, zero-width characters, ili kodiranje zasnovano na whitespace-u.
{{#ref}}
text/README.md
{{#endref}}

### Dokumenti

PDFs i Office fajlovi su pre svega kontejneri; napadi se obično zasnivaju na embedded files/streams, object/relationship graphs i ZIP ekstrakciji.
{{#ref}}
documents/README.md
{{#endref}}

### Malware i delivery-style steganography

Payload delivery često koristi fajlove koji izgledaju validno (npr. GIF/PNG) koji sadrže marker-delimited text payloads, umesto skrivanja na nivou piksela.
{{#ref}}
malware-and-network/README.md
{{#endref}}

{{#include ../banners/hacktricks-training.md}}
