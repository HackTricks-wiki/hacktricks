# Crypto

{{#include ../banners/hacktricks-training.md}}

Sehemu hii inalenga cryptography ya vitendo kwa security testing na CTFs: kutambua mifumo ya kawaida, kuchagua tools zinazofaa, na kutumia attacks zinazojulikana.

Kwa techniques zinazoficha data ndani ya files, angalia sehemu ya **Stego**.

## Jinsi ya kutumia sehemu hii

Anza kwa kutambua primitive na parameters zake. Kisha tambua kile attacker anachodhibiti au kuona, kama vile oracle, thamani iliyoleak, au nonce reuse, kabla ya kuchagua attack.

### Mtiririko wa CTF

{{#ref}}
ctf-workflow/README.md
{{#endref}}

### Symmetric cryptography

{{#ref}}
symmetric/README.md
{{#endref}}

### Hashes, MACs, na KDFs

{{#ref}}
hashes/README.md
{{#endref}}

### Public-key cryptography

{{#ref}}
public-key/README.md
{{#endref}}

### TLS na certificates

{{#ref}}
tls-and-certificates/README.md
{{#endref}}

### Cryptography katika malware

{{#ref}}
crypto-in-malware/README.md
{{#endref}}

### Mengineyo

{{#ref}}
ctf-misc/README.md
{{#endref}}

## Usanidi wa haraka

Tengeneza Python environment iliyotengwa na usakinishe packages zinazotumika mara kwa mara. Documentation ya PyCryptodome inapendekeza kusakinisha `pycryptodome` kwa kutumia `pip`; SageMath hutoa maelekezo tofauti ya usakinishaji kwa kila platform inayotumika.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install pycryptodome gmpy2 sympy pwntools
```
SageMath mara nyingi huwa muhimu kwa hesabu za algebra, lattice, RSA, na elliptic-curve.<sup>[[2]](#references)</sup>

## References

- [1] [Nyaraka za PyCryptodome - Usakinishaji](https://www.pycryptodome.org/src/installation)
- [2] [Nyaraka za SageMath - Mwongozo wa usakinishaji](https://doc.sagemath.org/html/en/installation/)
{{#include ../banners/hacktricks-training.md}}
