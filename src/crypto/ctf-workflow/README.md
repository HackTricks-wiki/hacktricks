# Crypto CTF İş Akışı

{{#include ../../banners/hacktricks-training.md}}

## Triage kontrol listesi

1. Elinizdekini belirleyin: encoding mi, encryption mı, hash mi, signature mı, MAC mi?
2. Nelerin kontrol edildiğini belirleyin: plaintext/ciphertext, IV/nonce, key, oracle (padding/error/timing), kısmi leak.
3. Sınıflandırın: symmetric (AES/CTR/GCM), public-key (RSA/ECC), hash/MAC (SHA/MD5/HMAC), klasik (Vigenere/XOR).
4. Önce en yüksek olasılıklı kontrolleri uygulayın: katmanları decode etme, bilinen-plaintext XOR, nonce yeniden kullanımı, mode hatalı kullanımı, oracle davranışı.
5. Yalnızca gerektiğinde gelişmiş yöntemlere geçin: lattices (LLL/Coppersmith), SMT/Z3, side-channels.

## Online kaynaklar ve araçlar

Bunlar, görevin identification ve katmanları ayırma olduğu ya da bir hipotezi hızlıca doğrulamanız gerektiği durumlarda kullanışlıdır.

### Hash aramaları

- Synthetic/public olduğu bilinen bir challenge hash'i arayın.
- CrackStation.<sup>[[1]](#references)</sup>
- MD5Decrypt.<sup>[[2]](#references)</sup>
- hashes.org search.<sup>[[3]](#references)</sup>
- OnlineHashCrack.<sup>[[4]](#references)</sup>
- GPUHash.me.<sup>[[5]](#references)</sup>
- Hash Toolkit.<sup>[[6]](#references)</sup>

Gerçek password hash'lerini veya gizli challenge materyallerini üçüncü taraf lookup servislerine göndermeyin. Bilgilerin açığa çıkması, hizmet şartları veya yarışma kuralları sorun oluşturuyorsa offline wordlist/rule attack yöntemini tercih edin.

### Identification yardımcıları

- CyberChef (Magic, decoding ve conversion).<sup>[[7]](#references)</sup>
- dCode (cipher/encoding playground).<sup>[[8]](#references)</sup>
- Boxentriq (substitution solvers).<sup>[[9]](#references)</sup>

### Practice platformları / referanslar

- CryptoHack (uygulamalı cryptography challenges).<sup>[[10]](#references)</sup>
- Cryptopals (modern cryptography'deki klasik tuzaklar).<sup>[[11]](#references)</sup>

### Automated decoding

- Ciphey.<sup>[[12]](#references)</sup>
- python-codext (birçok base/encoding dener).<sup>[[13]](#references)</sup>

## Encoding'ler ve klasik cipher'lar

### Technique

Birçok CTF crypto görevi katmanlı dönüşümler içerir: base encoding + basit substitution + compression. Amaç, katmanları belirlemek ve güvenli şekilde ayırmaktır.

### Encoding'ler: birçok base deneyin

Katmanlı encoding'den şüpheleniyorsanız (base64 → base32 → …), şunları deneyin:

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

Yaygın göstergeler:

- Base64: `A-Za-z0-9+/=` (padding olarak `=` yaygındır)
- Base32: `A-Z2-7=` (çoğunlukla çok miktarda `=` padding içerir)
- Ascii85/Base85: yoğun punctuation; bazen `<~ ~>` içine alınır

### Substitution / monoalphabetic

- Boxentriq cryptogram solver.<sup>[[9]](#references)</sup>
- quipqiup.<sup>[[14]](#references)</sup>

### Caesar / ROT / Atbash

- Nayuki automatic Caesar-cipher breaker.<sup>[[15]](#references)</sup>
- Rumkin Atbash tool.<sup>[[16]](#references)</sup>

### Vigenère

- dCode Vigenère tool.<sup>[[8]](#references)</sup>
- Guballa Vigenère solver.<sup>[[17]](#references)</sup>

### Bacon cipher

Genellikle 5 bit veya 5 harflik gruplar olarak görünür:
```
00111 01101 01010 00000 ...
AABBB ABBAB ABABA AAAAA ...
```
### Morse
```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```
### Runes

Runeler sıklıkla substitution alphabets olarak kullanılır; "futhark cipher" için arama yapın ve mapping tablolarını deneyin.

## Zorluklarda Sıkıştırma

### Teknik

Compression, ekstra bir katman olarak sürekli karşınıza çıkar (zlib/deflate/gzip/xz/zstd); bazen iç içe olabilir. Çıktı neredeyse parse ediliyor ancak anlamsız görünüyorsa compression olduğundan şüphelenin.

### Hızlı tanımlama

- `file <blob>`
- Magic byte'ları arayın:
- gzip: `1f 8b`
- zlib: genellikle `78 01`, `78 5e`, `78 9c` veya `78 da` (ikinci byte compression flags'e bağlıdır)
- zip: `50 4b 03 04`
- bzip2: `42 5a 68` (`BZh`)
- xz: `fd 37 7a 58 5a 00`
- zstd: `28 b5 2f fd`

### Raw DEFLATE

CyberChef'te **Raw Deflate/Raw Inflate** bulunur; blob compressed görünüyor ancak `zlib` başarısız oluyorsa genellikle en hızlı yoldur.

### Faydalı CLI
```bash
python3 - blob.bin <<'PY'
import sys, zlib
data = open(sys.argv[1], 'rb').read()
for wbits in [zlib.MAX_WBITS, -zlib.MAX_WBITS]:
try:
print(zlib.decompress(data, wbits=wbits)[:200])
except Exception:
pass
PY
```
## Yaygın CTF crypto yapıları

### Technique

Bunlar gerçekçi geliştirici hataları veya yanlış kullanılan yaygın kütüphaneler oldukları için sıkça karşınıza çıkar. Amaç genellikle tanımak ve bilinen bir extraction veya reconstruction workflow uygulamaktır.

### Fernet

Tipik ipucu: iki Base64 string'i (token + key).

- Decoder/notes: Asecuritysite Fernet decoder.<sup>[[18]](#references)</sup>
- Python'da: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

Birden fazla share görüyorsanız ve bir threshold `t` belirtilmişse, büyük olasılıkla Shamir'dir.

- Online reconstructor (yalnızca hassas olmayan CTF share'leri için).<sup>[[19]](#references)</sup>

### OpenSSL salted formats

CTF'lerde bazen `openssl enc` çıktıları verilir (header genellikle `Salted__` ile başlar).

Bruteforce yardımcıları:

- `bruteforce-salted-openssl`.<sup>[[20]](#references)</sup>
- `easy_BFopensslCTF`.<sup>[[21]](#references)</sup>

### General toolset

- RsaCtfTool.<sup>[[22]](#references)</sup>
- featherduster.<sup>[[23]](#references)</sup>
- cryptovenom.<sup>[[24]](#references)</sup>

## Önerilen local setup

Pratik CTF stack'i:

- Symmetric primitive'ler ve hızlı prototyping için `pycryptodome` ile Python.<sup>[[25]](#references)</sup>
- Modular arithmetic, CRT, lattices ve RSA/ECC çalışmaları için SageMath.<sup>[[26]](#references)</sup>
- Constraint-based challenge'lar için Z3 (crypto constraint'lere indirgendiğinde).<sup>[[27]](#references)</sup>

Önerilen Python paketleri:
```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```
## References

- [1] [CrackStation](https://crackstation.net/)
- [2] [MD5Decrypt](https://md5decrypt.net/)
- [3] [hashes.org araması](https://hashes.org/search.php)
- [4] [OnlineHashCrack](https://www.onlinehashcrack.com/)
- [5] [GPUHash.me](https://gpuhash.me/)
- [6] [Hash Toolkit](https://hashtoolkit.com/reverse-hash)
- [7] [GCHQ CyberChef](https://gchq.github.io/CyberChef/)
- [8] [dCode araçları](https://www.dcode.fr/tools-list)
- [9] [Boxentriq code-breaking araçları](https://www.boxentriq.com/code-breaking)
- [10] [CryptoHack](https://cryptohack.org/)
- [11] [Cryptopals](https://cryptopals.com/)
- [12] [Ciphey](https://github.com/Ciphey/Ciphey)
- [13] [python-codext](https://github.com/dhondta/python-codext)
- [14] [quipqiup](https://quipqiup.com/)
- [15] [Nayuki - Automatic Caesar cipher breaker](https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript)
- [16] [Rumkin - Atbash cipher](https://rumkin.com/tools/cipher/atbash/)
- [17] [Guballa Vigenère solver](https://www.guballa.de/vigenere-solver)
- [18] [Asecuritysite - Fernet decoder](https://asecuritysite.com/encryption/ferdecode)
- [19] [Shamir secret-sharing reconstructor](https://christian.gen.co/secrets/)
- [20] [bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
- [21] [easy_BFopensslCTF](https://github.com/carlospolop/easy_BFopensslCTF)
- [22] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [23] [featherduster](https://github.com/nccgroup/featherduster)
- [24] [cryptovenom](https://github.com/lockedbyte/cryptovenom)
- [25] [PyCryptodome documentation](https://pycryptodome.readthedocs.io/en/latest/)
- [26] [SageMath](https://www.sagemath.org/)
- [27] [Z3](https://github.com/Z3Prover/z3)
{{#include ../../banners/hacktricks-training.md}}
