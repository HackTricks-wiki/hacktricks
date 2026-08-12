# Kriptografi

{{#include ../banners/hacktricks-training.md}}

Bu bölüm, security testing ve CTF'ler için pratik kriptografiye odaklanır: yaygın kalıpları tanıma, uygun araçları seçme ve bilinen attack'leri uygulama.

Verileri dosyaların içine gizleyen teknikler için **Stego** bölümüne bakın.

## Bu bölüm nasıl kullanılır

Primitive'i ve parametrelerini belirleyerek başlayın. Ardından bir oracle, leak edilmiş bir değer veya nonce reuse gibi saldırganın kontrol ettiği ya da gözlemlediği unsurları belirleyin ve sonra bir attack seçin.

### CTF workflow

{{#ref}}
ctf-workflow/README.md
{{#endref}}

### Symmetric cryptography

{{#ref}}
symmetric/README.md
{{#endref}}

### Hashes, MACs, and KDFs

{{#ref}}
hashes/README.md
{{#endref}}

### Public-key cryptography

{{#ref}}
public-key/README.md
{{#endref}}

### TLS and certificates

{{#ref}}
tls-and-certificates/README.md
{{#endref}}

### Cryptography in malware

{{#ref}}
crypto-in-malware/README.md
{{#endref}}

### Miscellaneous

{{#ref}}
ctf-misc/README.md
{{#endref}}

## Hızlı kurulum

İzole bir Python ortamı oluşturun ve yaygın olarak kullanılan paketleri yükleyin. PyCryptodome belgeleri `pycryptodome` paketinin `pip` ile yüklenmesini önerir; SageMath ise desteklenen her platform için ayrı kurulum yönergeleri sunar.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install pycryptodome gmpy2 sympy pwntools
```
SageMath, algebra, lattice, RSA ve elliptic-curve hesaplamaları için genellikle kullanışlıdır.<sup>[[2]](#references)</sup>

## References

- [1] [PyCryptodome documentation - Kurulum](https://www.pycryptodome.org/src/installation)
- [2] [SageMath documentation - Kurulum rehberi](https://doc.sagemath.org/html/en/installation/)
{{#include ../banners/hacktricks-training.md}}
