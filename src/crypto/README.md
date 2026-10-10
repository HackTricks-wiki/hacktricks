# Kriptografia

{{#include ../banners/hacktricks-training.md}}

Sehemu hii inajikita kwenye kriptografia ya vitendo kwa ajili ya majaribio ya usalama na CTFs: kutambua mifumo ya kawaida, kuchagua zana zinazofaa, na kutumia mashambulizi yanayojulikana.

Kwa mbinu zinazoficha data ndani ya faili, angalia sehemu ya **Stego**.

## Jinsi ya kutumia sehemu hii

Anza kwa kutambua primitive na vigezo vyake. Kisha bainisha kile ambacho mshambuliaji anaweza kudhibiti au kuona, kama vile oracle, thamani iliyoleak, au matumizi tena ya nonce, kabla ya kuchagua shambulizi.

### Mtiririko wa kazi wa CTF

{{#ref}}
ctf-workflow/README.md
{{#endref}}

### Kriptografia ya ulinganifu

{{#ref}}
symmetric/README.md
{{#endref}}

### Hashes, MACs, na KDFs

{{#ref}}
hashes/README.md
{{#endref}}

### Kriptografia ya funguo za umma

{{#ref}}
public-key/README.md
{{#endref}}

### TLS na vyeti

{{#ref}}
tls-and-certificates/README.md
{{#endref}}

### Kriptografia kwenye malware

{{#ref}}
crypto-in-malware/README.md
{{#endref}}

### Mengineyo

{{#ref}}
ctf-misc/README.md
{{#endref}}

## Usanidi wa haraka

Unda mazingira ya Python yaliyotengwa na usakinishe vifurushi vinavyotumika mara nyingi. Nyaraka za PyCryptodome zinapendekeza kusakinisha `pycryptodome` kwa kutumia `pip`; SageMath hutoa mwongozo tofauti wa usakinishaji kwa kila jukwaa linaloungwa mkono.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install pycryptodome gmpy2 sympy pwntools
```

SageMath mara nyingi ni muhimu kwa hesabu za algebra, lattice, RSA na elliptic-curve.<sup>[[2]](#references)</sup>

## References

- [1] [PyCryptodome documentation - Usakinishaji](https://www.pycryptodome.org/src/installation)
- [2] [SageMath documentation - Mwongozo wa usakinishaji](https://doc.sagemath.org/html/en/installation/)
{{#include ../banners/hacktricks-training.md}}
