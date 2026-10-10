# Kriptografija

{{#include ../banners/hacktricks-training.md}}

Ovaj odeljak bavi se praktičnom kriptografijom za bezbednosno testiranje i CTF-ove: prepoznavanjem uobičajenih obrazaca, izborom odgovarajućih alata i primenom poznatih napada.

Za tehnike skrivanja podataka unutar datoteka pogledajte odeljak **Stego**.

## Kako koristiti ovaj odeljak

Počnite tako što ćete identifikovati primitiv i njegove parametre. Zatim utvrdite šta napadač kontroliše ili može da posmatra, na primer oracle, vrednost dobijenu kroz leak ili ponovnu upotrebu nonce-a, pa tek onda izaberite napad.

### CTF radni tok

{{#ref}}
ctf-workflow/README.md
{{#endref}}

### Simetrična kriptografija

{{#ref}}
symmetric/README.md
{{#endref}}

### Hash funkcije, MAC-ovi i KDF-ovi

{{#ref}}
hashes/README.md
{{#endref}}

### Kriptografija sa javnim ključem

{{#ref}}
public-key/README.md
{{#endref}}

### TLS i sertifikati

{{#ref}}
tls-and-certificates/README.md
{{#endref}}

### Kriptografija u malveru

{{#ref}}
crypto-in-malware/README.md
{{#endref}}

### Razno

{{#ref}}
ctf-misc/README.md
{{#endref}}

## Brzo podešavanje

Napravite izolovano Python okruženje i instalirajte često korišćene pakete. Dokumentacija za PyCryptodome preporučuje instalaciju paketa `pycryptodome` pomoću `pip`-a; SageMath pruža zasebna uputstva za instalaciju za svaku podržanu platformu.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install pycryptodome gmpy2 sympy pwntools
```

SageMath je često koristan za algebarske proračune, proračune s rešetkama, RSA i proračune eliptičkih krivih.<sup>[[2]](#references)</sup>

## References

- [1] [PyCryptodome dokumentacija - Instalacija](https://www.pycryptodome.org/src/installation)
- [2] [SageMath dokumentacija - Vodič za instalaciju](https://doc.sagemath.org/html/en/installation/)
{{#include ../banners/hacktricks-training.md}}
