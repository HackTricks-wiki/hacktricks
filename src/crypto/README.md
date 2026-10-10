# Crypto

{{#include ../banners/hacktricks-training.md}}

Bu bölüm, güvenlik testleri ve CTF'ler için pratik kriptografiye odaklanır: yaygın örüntüleri tanıma, uygun araçları seçme ve bilinen saldırıları uygulama.

Verileri dosyaların içine gizleyen teknikler için **Stego** bölümüne bakın.

## Bu bölüm nasıl kullanılır?

Önce kullanılan primitive'i ve parametrelerini belirleyin. Ardından saldırı seçmeden önce saldırganın neleri kontrol ettiğini veya gözlemlediğini (ör. bir oracle, leak olmuş bir değer ya da nonce'un yeniden kullanılması) belirleyin.

### CTF iş akışı

{{#ref}}
ctf-workflow/README.md
{{#endref}}

### Simetrik kriptografi

{{#ref}}
symmetric/README.md
{{#endref}}

### Hash'ler, MAC'ler ve KDF'ler

{{#ref}}
hashes/README.md
{{#endref}}

### Açık anahtarlı kriptografi

{{#ref}}
public-key/README.md
{{#endref}}

### TLS ve sertifikalar

{{#ref}}
tls-and-certificates/README.md
{{#endref}}

### Malware'de kriptografi

{{#ref}}
crypto-in-malware/README.md
{{#endref}}

### Çeşitli

{{#ref}}
ctf-misc/README.md
{{#endref}}

## Hızlı kurulum

Yaygın olarak kullanılan paketleri yüklemek için izole bir Python ortamı oluşturun. PyCryptodome belgeleri, `pycryptodome` paketinin `pip` ile yüklenmesini önerir; SageMath ise desteklenen her platform için ayrı kurulum yönergeleri sunar.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install pycryptodome gmpy2 sympy pwntools
```

SageMath cebirsel, lattice, RSA ve elliptic-curve hesaplamalarında sıklıkla kullanışlıdır.<sup>[[2]](#references)</sup>

## References

- [1] [PyCryptodome belgeleri - Kurulum](https://www.pycryptodome.org/src/installation)
- [2] [SageMath belgeleri - Kurulum kılavuzu](https://doc.sagemath.org/html/en/installation/)
{{#include ../banners/hacktricks-training.md}}
