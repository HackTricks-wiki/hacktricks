# Kriptografija

{{#include ../banners/hacktricks-training.md}}

Ovaj odeljak se fokusira na praktičnu kriptografiju za security testing i CTF-ove: prepoznavanje uobičajenih obrazaca, izbor odgovarajućih alata i primenu poznatih napada.

Za tehnike koje skrivaju podatke unutar datoteka pogledajte odeljak **Stego**.

## Kako koristiti ovaj odeljak

Počnite identifikovanjem primitive i njenih parametara. Zatim utvrdite čime napadač upravlja ili šta može da posmatra, kao što su oracle, leaked vrednost ili ponovna upotreba nonce-a, pre nego što izaberete napad.

### CTF workflow

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

### Kriptografija u malware-u

{{#ref}}
crypto-in-malware/README.md
{{#endref}}

### Razno

{{#ref}}
ctf-misc/README.md
{{#endref}}

## Brzo podešavanje

Kreirajte izolovano Python okruženje i instalirajte često korišćene pakete. Dokumentacija za PyCryptodome preporučuje instaliranje paketa `pycryptodome` pomoću `pip`-a; SageMath pruža posebna uputstva za instalaciju za svaku podržanu platformu.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install pycryptodome gmpy2 sympy pwntools
```
SageMath je često koristan za algebraičke, lattice, RSA i proračune na eliptičkim krivama.<sup>[[2]](#references)</sup>

## References

- [1] [Dokumentacija za PyCryptodome - Instalacija](https://www.pycryptodome.org/src/installation)
- [2] [Dokumentacija za SageMath - Vodič za instalaciju](https://doc.sagemath.org/html/en/installation/)
{{#include ../banners/hacktricks-training.md}}
