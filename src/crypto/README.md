# Kriptografie

{{#include ../banners/hacktricks-training.md}}

Hierdie afdeling fokus op praktiese kriptografie vir sekuriteitstoetsing en CTFs: die herkenning van algemene patrone, die keuse van geskikte nutsmiddels, en die toepassing van bekende aanvalle.

Vir tegnieke wat data binne lêers versteek, sien die **Stego**-afdeling.

## Hoe om hierdie afdeling te gebruik

Begin deur die primitief en sy parameters te identifiseer. Bepaal dan wat die aanvaller beheer of waarneem, soos 'n oracle, 'n gelekte waarde, of nonce-hergebruik, voordat jy 'n aanval kies.

### CTF-werkvloei

{{#ref}}
ctf-workflow/README.md
{{#endref}}

### Simmetriese kriptografie

{{#ref}}
symmetric/README.md
{{#endref}}

### Hashes, MACs en KDFs

{{#ref}}
hashes/README.md
{{#endref}}

### Publieksleutel-kriptografie

{{#ref}}
public-key/README.md
{{#endref}}

### TLS en sertifikate

{{#ref}}
tls-and-certificates/README.md
{{#endref}}

### Kriptografie in malware

{{#ref}}
crypto-in-malware/README.md
{{#endref}}

### Diverse

{{#ref}}
ctf-misc/README.md
{{#endref}}

## Vinnige opstelling

Skep 'n geïsoleerde Python-omgewing en installeer algemeen gebruikte pakkette. PyCryptodome se dokumentasie beveel aan dat `pycryptodome` met `pip` geïnstalleer word; SageMath verskaf afsonderlike installasie-instruksies vir elke ondersteunde platform.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install pycryptodome gmpy2 sympy pwntools
```
SageMath is dikwels nuttig vir algebraïese, rooster-, RSA- en elliptiese-kurweberekeninge.<sup>[[2]](#references)</sup>

## References

- [1] [PyCryptodome-dokumentasie - Installasie](https://www.pycryptodome.org/src/installation)
- [2] [SageMath-dokumentasie - Installasiegids](https://doc.sagemath.org/html/en/installation/)
{{#include ../banners/hacktricks-training.md}}
