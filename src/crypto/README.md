# Kriptografie

{{#include ../banners/hacktricks-training.md}}

Hierdie afdeling fokus op praktiese kriptografie vir sekuriteitstoetsing en CTFs: om algemene patrone te herken, geskikte nutsgoed te kies en bekende aanvalle toe te pas.

Vir tegnieke wat data in lêers versteek, sien die **Stego**-afdeling.

## Hoe om hierdie afdeling te gebruik

Begin deur die primitief en sy parameters te identifiseer. Bepaal dan wat die aanvaller beheer of waarneem, soos ’n oracle, ’n leak-waarde of nonce-hergebruik, voordat jy ’n aanval kies.

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

### Publieke-sleutel-kriptografie

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

Skep ’n geïsoleerde Python-omgewing en installeer pakkette wat algemeen gebruik word. PyCryptodome se dokumentasie beveel aan dat jy `pycryptodome` met `pip` installeer; SageMath bied afsonderlike installasie-instruksies vir elke ondersteunde platform.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install pycryptodome gmpy2 sympy pwntools
```

SageMath is dikwels nuttig vir algebraïese, rooster-, RSA- en elliptiesekromme-berekeninge.<sup>[[2]](#references)</sup>

## References

- [1] [PyCryptodome-dokumentasie - Installasie](https://www.pycryptodome.org/src/installation)
- [2] [SageMath-dokumentasie - Installasiegids](https://doc.sagemath.org/html/en/installation/)
{{#include ../banners/hacktricks-training.md}}
