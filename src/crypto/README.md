# Kriptografi

{{#include ../banners/hacktricks-training.md}}

Bu bölüm **hacking/CTF'ler için pratik kriptografiye** odaklanır: yaygın pattern'leri hızlıca tanımak, doğru tools'ları seçmek ve bilinen attack'leri uygulamak.

Verileri dosyaların içine gizlemek için buradaysanız **Stego** bölümüne gidin.

## Bu bölüm nasıl kullanılır

Crypto challenge'ları hızı ödüllendirir: primitive'i sınıflandırın, neyi kontrol ettiğinizi (oracle/leak/nonce reuse) belirleyin, ardından bilinen bir attack template'i uygulayın.

### CTF workflow
{{#ref}}
ctf-workflow/README.md
{{#endref}}

### Symmetric crypto
{{#ref}}
symmetric/README.md
{{#endref}}

### Hash'ler, MAC'ler ve KDF'ler
{{#ref}}
hashes/README.md
{{#endref}}

### Public-key crypto
{{#ref}}
public-key/README.md
{{#endref}}

### TLS ve sertifikalar
{{#ref}}
tls-and-certificates/README.md
{{#endref}}

### Malware'da crypto
{{#ref}}
crypto-in-malware/README.md
{{#endref}}

### Misc
{{#ref}}
ctf-misc/README.md
{{#endref}}

## Hızlı kurulum

- Python: `python3 -m venv .venv && source .venv/bin/activate`
- Libraries: `pip install pycryptodome gmpy2 sympy pwntools`
- SageMath (lattice/RSA/ECC için çoğu zaman gerekli): <https://www.sagemath.org/>

{{#include ../banners/hacktricks-training.md}}
