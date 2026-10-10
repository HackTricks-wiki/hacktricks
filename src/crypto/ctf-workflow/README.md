# Crypto CTF İş Akışı

{{#include ../../banners/hacktricks-training.md}}

## Ön değerlendirme kontrol listesi

1. Elinizdekini belirleyin: encoding mi, encryption mı, hash mi, signature mı, MAC mi?
2. Nelerin kontrol edilebildiğini belirleyin: plaintext/ciphertext, IV/nonce, key, oracle (padding/error/timing), kısmi sızıntı.
3. Sınıflandırın: symmetric (AES/CTR/GCM), public-key (RSA/ECC), hash/MAC (SHA/MD5/HMAC), classical (Vigenere/XOR).
4. Önce olasılığı en yüksek kontrolleri uygulayın: katmanları decode edin, bilinen plaintext ile XOR deneyin, nonce tekrar kullanımını ve mode hatalı kullanımını kontrol edin, oracle davranışını inceleyin.
5. Yalnızca gerektiğinde ileri yöntemlere geçin: lattices (LLL/Coppersmith), SMT/Z3, side-channel’lar.

## Online kaynaklar ve araçlar

Bunlar, görevin bir şeyi tanımlamak ve katmanları çözmek olduğu durumlarda veya bir hipotezi hızlıca doğrulamanız gerektiğinde kullanışlıdır.

### Hash aramaları

- Bilinen hash sentetik/kamuya açık olduğunda challenge hash’ini arayın.
- CrackStation.<sup>[[1]](#references)</sup>
- MD5Decrypt.<sup>[[2]](#references)</sup>
- hashes.org araması.<sup>[[3]](#references)</sup>
- OnlineHashCrack.<sup>[[4]](#references)</sup>
- GPUHash.me.<sup>[[5]](#references)</sup>
- Hash Toolkit.<sup>[[6]](#references)</sup>

Gerçek parola hash’lerini veya gizli challenge materyallerini üçüncü taraf arama servislerine göndermeyin. Bilginin ifşa edilmesi, hizmet şartları veya yarışma kuralları sorun yaratabilecekse çevrimdışı wordlist/rule saldırısını tercih edin.

### Tanımlama yardımcıları

- CyberChef (Magic, decoding ve conversion).<sup>[[7]](#references)</sup>
- dCode (cipher/encoding deneme ortamı).<sup>[[8]](#references)</sup>
- Boxentriq (substitution solver’ları).<sup>[[9]](#references)</sup>

### Pratik platformları / kaynaklar

- CryptoHack (uygulamalı cryptography challenge’ları).<sup>[[10]](#references)</sup>
- Cryptopals (modern cryptography’deki klasik tuzaklar).<sup>[[11]](#references)</sup>

### Otomatik decoding

- Ciphey.<sup>[[12]](#references)</sup>
- python-codext (birçok base/encoding’i dener).<sup>[[13]](#references)</sup>

## Encoding’ler ve klasik cipher’lar

### Teknik

Birçok CTF crypto görevi, katmanlı dönüşümlerden oluşur: base encoding + basit substitution + compression. Amaç, katmanları belirleyip güvenli bir şekilde çözmektir.

### Encoding’ler: farklı base’leri deneyin

Katmanlı encoding’den şüpheleniyorsanız (base64 → base32 → …), şunları deneyin:

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

Yaygın ipuçları:

- Base64: `A-Za-z0-9+/=` (sondaki `=` yaygındır)
- Base32: `A-Z2-7=` (çoğunlukla çok sayıda `=` padding içerir)
- Ascii85/Base85: yoğun noktalama işaretleri; bazen `<~ ~>` ile çevrelenir

### Substitution / monoalphabetic

- Boxentriq cryptogram solver.<sup>[[9]](#references)</sup>
- quipqiup.<sup>[[14]](#references)</sup>

### Caesar / ROT / Atbash

- Nayuki otomatik Caesar-cipher breaker.<sup>[[15]](#references)</sup>
- Rumkin Atbash aracı.<sup>[[16]](#references)</sup>

### Vigenère

- dCode Vigenère aracı.<sup>[[8]](#references)</sup>
- Guballa Vigenère solver.<sup>[[17]](#references)</sup>

### Bacon cipher

Genellikle 5 bitlik veya 5 harflik gruplar hâlinde görülür:

```
00111 01101 01010 00000 ...
AABBB ABBAB ABABA AAAAA ...
```

### Morse

```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```

### Runes

Runes çoğunlukla substitution alphabet'tir; "futhark cipher" için arama yapın ve eşleme tablolarını deneyin.

## Yarışmalarda sıkıştırma

### Teknik

Sıkıştırma, bazen iç içe geçmiş katmanlar hâlinde, sürekli karşınıza çıkar (zlib/deflate/gzip/xz/zstd). Çıktı neredeyse çözümlenebilir gibi görünüyorsa ama anlamsızsa sıkıştırmadan şüphelenin.

### Hızlı tanımlama

- `file <blob>`
- Magic byte'ları kontrol edin:
  - gzip: `1f 8b`
  - zlib: yaygın olarak `78 01`, `78 5e`, `78 9c` veya `78 da` (ikinci byte sıkıştırma bayraklarına bağlıdır)
  - zip: `50 4b 03 04`
  - bzip2: `42 5a 68` (`BZh`)
  - xz: `fd 37 7a 58 5a 00`
  - zstd: `28 b5 2f fd`

### Raw DEFLATE

CyberChef'te **Raw Deflate/Raw Inflate** seçenekleri bulunur. Blob sıkıştırılmış gibi görünüyor ama `zlib` başarısız oluyorsa genellikle en hızlı çözüm budur.

### Kullanışlı CLI-ler

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

## Yaygın CTF kripto yapıları

### Teknik

Bunlar gerçekçi geliştirici hataları veya yanlış kullanılan yaygın kütüphaneler oldukları için sıkça karşımıza çıkar. Amaç genellikle yapıyı tanımak ve bilinen bir çıkarma ya da yeniden oluşturma iş akışını uygulamaktır.

### Fernet

Tipik ipucu: iki Base64 dizisi (token + key).

- Decoder/notlar: Asecuritysite Fernet decoder.<sup>[[18]](#references)</sup>
- Python'da: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

Birden fazla share görüyorsanız ve bir eşik `t` belirtilmişse, büyük olasılıkla Shamir'dir.

- Online yeniden oluşturucu (yalnızca hassas olmayan CTF share'ları için).<sup>[[19]](#references)</sup>

### OpenSSL salt'lı biçimler

CTF'lerde bazen `openssl enc` çıktıları verilir (başlık genellikle `Salted__` ile başlar).

Bruteforce yardımcıları:

- `bruteforce-salted-openssl`.<sup>[[20]](#references)</sup>
- `easy_BFopensslCTF`.<sup>[[21]](#references)</sup>

### Genel araç seti

- RsaCtfTool.<sup>[[22]](#references)</sup>
- featherduster.<sup>[[23]](#references)</sup>
- cryptovenom.<sup>[[24]](#references)</sup>

## Önerilen yerel kurulum

Pratik CTF araç seti:

- Simetrik primitive'ler ve hızlı prototipleme için Python ve `pycryptodome`.<sup>[[25]](#references)</sup>
- Modüler aritmetik, CRT, lattice'ler ve RSA/ECC çalışmaları için SageMath.<sup>[[26]](#references)</sup>
- Kısıt tabanlı challenge'lar için Z3 (kripto kısıtlara indirgenebildiğinde).<sup>[[27]](#references)</sup>

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
- [9] [Boxentriq şifre çözme araçları](https://www.boxentriq.com/code-breaking)
- [10] [CryptoHack](https://cryptohack.org/)
- [11] [Cryptopals](https://cryptopals.com/)
- [12] [Ciphey](https://github.com/Ciphey/Ciphey)
- [13] [python-codext](https://github.com/dhondta/python-codext)
- [14] [quipqiup](https://quipqiup.com/)
- [15] [Nayuki - Otomatik Caesar şifresi çözücü](https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript)
- [16] [Rumkin - Atbash şifresi](https://rumkin.com/tools/cipher/atbash/)
- [17] [Guballa Vigenère çözücü](https://www.guballa.de/vigenere-solver)
- [18] [Asecuritysite - Fernet kod çözücü](https://asecuritysite.com/encryption/ferdecode)
- [19] [Shamir gizli paylaşım yeniden oluşturucusu](https://christian.gen.co/secrets/)
- [20] [bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
- [21] [easy_BFopensslCTF](https://github.com/carlospolop/easy_BFopensslCTF)
- [22] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [23] [featherduster](https://github.com/nccgroup/featherduster)
- [24] [cryptovenom](https://github.com/lockedbyte/cryptovenom)
- [25] [PyCryptodome belgeleri](https://pycryptodome.readthedocs.io/en/latest/)
- [26] [SageMath](https://www.sagemath.org/)
- [27] [Z3](https://github.com/Z3Prover/z3)
{{#include ../../banners/hacktricks-training.md}}
