# Crypto

{{#include ../banners/hacktricks-training.md}}

Bu bölüm **hacking/CTF'ler için pratik kriptografi** üzerine odaklanır: yaygın kalıpları hızlıca nasıl tanıyacağınız, doğru araçları nasıl seçeceğiniz ve bilinen saldırıları nasıl uygulayacağınız.

If you're here for hiding data inside files, go to the **Stego** section.

## Bu bölümü nasıl kullanmalı

Crypto challenge'leri hıza ödül verir: primitive'i sınıflandırın, kontrol ettiğiniz şeyi belirleyin (oracle/leak/nonce reuse), sonra bilinen bir saldırı şablonunu uygulayın.

### CTF workflow
{{#ref}}
ctf-workflow/README.md
{{#endref}}

### Symmetric crypto
{{#ref}}
symmetric/README.md
{{#endref}}

### Hashes, MACs, and KDFs
{{#ref}}
hashes/README.md
{{#endref}}

### Public-key crypto
{{#ref}}
public-key/README.md
{{#endref}}

### TLS and certificates
{{#ref}}
tls-and-certificates/README.md
{{#endref}}

### Crypto in malware
{{#ref}}
crypto-in-malware/README.md
{{#endref}}

### Misc
{{#ref}}
ctf-misc/README.md
{{#endref}}

## Hızlı kurulum

- Python: `python3 -m venv .venv && source .venv/bin/activate`
- Kütüphaneler: `pip install pycryptodome gmpy2 sympy pwntools`
- SageMath (genellikle lattice/RSA/ECC için gerekli): https://www.sagemath.org/

{{#include ../banners/hacktricks-training.md}}
