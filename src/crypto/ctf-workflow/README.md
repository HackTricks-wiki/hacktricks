# Crypto CTF İş Akışı

{{#include ../../banners/hacktricks-training.md}}

## İlk değerlendirme kontrol listesi

1. Elinizde ne olduğunu belirleyin: encoding mi, encryption mı, hash mi, signature mı, MAC mi?
2. Nelerin kontrol edilebildiğini belirleyin: plaintext/ciphertext, IV/nonce, key, oracle (padding/error/timing), kısmi sızıntı.
3. Sınıflandırın: symmetric (AES/CTR/GCM), public-key (RSA/ECC), hash/MAC (SHA/MD5/HMAC), klasik (Vigenere/XOR).
4. Önce olasılığı en yüksek kontrolleri uygulayın: encoding katmanlarını çözme, known-plaintext XOR, nonce reuse, mode misuse, oracle davranışı.
5. Yalnızca gerektiğinde gelişmiş yöntemlere geçin: lattices (LLL/Coppersmith), SMT/Z3, side-channel saldırıları.

## Çevrimiçi kaynaklar ve yardımcı araçlar

Bunlar, görevde bir şeyi tanımlamanız ve katmanları ayıklamanız gerektiğinde ya da bir varsayımı hızlıca doğrulamak istediğinizde işe yarar.

### Hash aramaları

- Bilinen, sentetik/kamuya açık bir challenge hash için arama yapın.
- CrackStation.<sup>[[1]](#references)</sup>
- MD5Decrypt.<sup>[[2]](#references)</sup>
- hashes.org araması.<sup>[[3]](#references)</sup>
- OnlineHashCrack.<sup>[[4]](#references)</sup>
- GPUHash.me.<sup>[[5]](#references)</sup>
- Hash Toolkit.<sup>[[6]](#references)</sup>

Gerçek password hash'lerini veya gizli challenge materyallerini üçüncü taraf arama hizmetlerine göndermeyin. Bilgilerin ifşa olmasının, hizmet koşullarının veya yarışma kurallarının sorun yaratabileceği durumlarda çevrimdışı wordlist/rule saldırısı kullanmayı tercih edin.

### Tanımlama yardımcıları

- CyberChef (Magic, decoding ve conversion).<sup>[[7]](#references)</sup>
- dCode (cipher/encoding deneme alanı).<sup>[[8]](#references)</sup>
- Boxentriq (substitution çözücüleri).<sup>[[9]](#references)</sup>

### Pratik platformları / kaynaklar

- CryptoHack (uygulamalı cryptography challenge'ları).<sup>[[10]](#references)</sup>
- Cryptopals (modern cryptography'deki klasik tuzaklar).<sup>[[11]](#references)</sup>

### Otomatik decoding

- Ciphey.<sup>[[12]](#references)</sup>
- python-codext (çok sayıda base/encoding'i dener).<sup>[[13]](#references)</sup>

## Encoding'ler ve klasik şifreler

### Teknik

Birçok CTF crypto görevi katmanlı dönüşümlerden oluşur: base encoding + basit substitution + compression. Amaç, katmanları belirleyip güvenli şekilde ayıklamaktır.

### Encoding'ler: birçok base deneyin

Katmanlı encoding'den şüpheleniyorsanız (base64 → base32 → …), şunları deneyin:

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

Yaygın ipuçları:

- Base64: `A-Za-z0-9+/=` (sondaki `=` yaygındır)
- Base32: `A-Z2-7=` (genellikle çok sayıda `=` padding bulunur)
- Ascii85/Base85: yoğun noktalama işaretleri; bazen `<~ ~>` ile çevrelenir

### Substitution / monoalphabetic

- Boxentriq cryptogram çözücüsü.<sup>[[9]](#references)</sup>
- quipqiup.<sup>[[14]](#references)</sup>

#### Substituted Base32 dosya adlarını known-plaintext ile kurtarma

Obfuscation uygulanmış bir dosya adı yalnızca `a-z2-7` karakterlerini kullanıyorsa, sabit bir suffix çıkarıldıktan sonra `ceil(8 * byte_length / 5)` karaktere yakın bir uzunluğa ulaşıyorsa ve aynı plaintext farklı dosyalarda aynı çıktıyı üretiyorsa, **padding'siz Base32'nin ardından sabit bir symbol substitution uygulanmış olmasını** test edin. Bu ipuçları tek başlarına kanıt değildir. Tahmin edilebilir dosya adlarını ve bunların ciphertext'lerini toplayın, büyük/küçük harfleri koruyun, her plaintext'i Base32 ile encode edin ve sembolleri konumlarına göre hizalayın. Tekrarlanan her plaintext sembolü aynı ciphertext sembolüne eşlenmeli, ters eşleme de tekil olmalıdır. Bir ransomware vakasında `ntuser.ini` ve `NTUSER.DAT` bu tür eşleşmeler sağladı; bu yöntem dosya adlarını kurtardı, **dosya içeriklerini veya encryption key'lerini değil**.<sup>[[28]](#references)</sup>

```python
import base64
pairs = [("ntuser.ini", "zsub5mdlekr37dx4"), ("NTUSER.DAT", "4s5l5tul5kr6kv5t")]
forward, inverse = {}, {}
for name, ciphertext in pairs:
    b32 = base64.b32encode(name.encode("ascii")).decode().lower().rstrip("=")
    assert len(b32) == len(ciphertext)
    for p, c in zip(b32, ciphertext):
        assert forward.get(p, c) == c and inverse.get(c, p) == p
        forward[p], inverse[c] = c, p
target = "4s5l5tul5kr6kv5t"  # Remove the fixed suffix first
b32 = "".join(inverse[c] for c in target)
clear = base64.b32decode(b32.upper() + "=" * (-len(b32) % 8))
assert "".join(forward[c] for c in b32) == target
print(clear.decode("ascii"))
```

Hedef, eşlenmemiş semboller içeriyorsa daha fazla bilinen eşleşme elde edin veya yalnızca kullanılmamış Base32 sembol eşlemelerinin permütasyonlarını deneyin. Dolguyu sekiz karakterlik sınıra tamamlayın, geçersiz Base32'yi ve yazdırılamayan çözümlenmiş adları reddedin; ardından kalan adayları yeniden kodlayıp özgün ciphertext'in **tamamıyla** karşılaştırın. Tekrarlanan ciphertext blokları ek tahminler sağlayabilir: yukarıdaki örnekte `3gpng2wv`, Base32 `gaydambq` olarak eşlendi ve bu da beş ASCII sıfırına çözümlendi. Yalnızca yazdırılabilir bir aday, eşsiz bir kanıt değildir.<sup>[[28]](#references)</sup>

### Caesar / ROT / Atbash

- Nayuki otomatik Caesar-cipher kırıcı.<sup>[[15]](#references)</sup>
- Rumkin Atbash aracı.<sup>[[16]](#references)</sup>

### Vigenère

- dCode Vigenère aracı.<sup>[[8]](#references)</sup>
- Guballa Vigenère çözücüsü.<sup>[[17]](#references)</sup>

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

### Rünler

Rünler genellikle yerine koyma alfabeleridir; "futhark cipher" için arama yapın ve eşleme tablolarını deneyin.

## Challenge'larda sıkıştırma

### Teknik

Sıkıştırma, ek bir katman olarak (zlib/deflate/gzip/xz/zstd) sürekli karşınıza çıkar; bazen iç içe kullanılır. Çıktı neredeyse ayrıştırılabiliyor ama anlamsız görünüyorsa sıkıştırmadan şüphelenin.

### Hızlı tanımlama

- `file <blob>`
- Magic byte'ları arayın:
  - gzip: `1f 8b`
  - zlib: genellikle `78 01`, `78 5e`, `78 9c` veya `78 da` (ikinci byte, sıkıştırma bayraklarına bağlıdır)
  - zip: `50 4b 03 04`
  - bzip2: `42 5a 68` (`BZh`)
  - xz: `fd 37 7a 58 5a 00`
  - zstd: `28 b5 2f fd`

### Raw DEFLATE

CyberChef'te **Raw Deflate/Raw Inflate** bulunur. Blob sıkıştırılmış gibi görünüyor ama `zlib` başarısız oluyorsa genellikle en hızlı yöntem budur.

### Kullanışlı CLI

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

Bunlar, gerçekçi geliştirici hataları veya yanlış kullanılan yaygın kütüphaneler oldukları için sık görülür. Amaç genellikle bunları tanımak ve bilinen bir çıkarma veya yeniden oluşturma iş akışını uygulamaktır.

### Fernet

Tipik ipucu: iki Base64 dizgesi (token + key).

- Decoder/notlar: Asecuritysite Fernet decoder.<sup>[[18]](#references)</sup>
- Python'da: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

Birden fazla share görürseniz ve `t` eşiğinden bahsediliyorsa, bu büyük olasılıkla Shamir'dir.

- Çevrimiçi yeniden oluşturucu (yalnızca hassas olmayan CTF share'leri için).<sup>[[19]](#references)</sup>

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
- Kısıt tabanlı challenge'lar için Z3 (kriptografi kısıtlara indirgenebildiğinde).<sup>[[27]](#references)</sup>

Önerilen Python paketleri:

```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```

{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [CrackStation](https://crackstation.net/)
- [2] [MD5Decrypt](https://md5decrypt.net/)
- [3] [hashes.org arama](https://hashes.org/search.php)
- [4] [OnlineHashCrack](https://www.onlinehashcrack.com/)
- [5] [GPUHash.me](https://gpuhash.me/)
- [6] [Hash Araç Seti](https://hashtoolkit.com/reverse-hash)
- [7] [GCHQ CyberChef](https://gchq.github.io/CyberChef/)
- [8] [dCode araçları](https://www.dcode.fr/tools-list)
- [9] [Boxentriq şifre çözme araçları](https://www.boxentriq.com/code-breaking)
- [10] [CryptoHack](https://cryptohack.org/)
- [11] [Cryptopals](https://cryptopals.com/)
- [12] [Ciphey](https://github.com/Ciphey/Ciphey)
- [13] [python-codext](https://github.com/dhondta/python-codext)
- [14] [quipqiup](https://quipqiup.com/)
- [15] [Nayuki - Otomatik Caesar şifresi kırıcı](https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript)
- [16] [Rumkin - Atbash şifresi](https://rumkin.com/tools/cipher/atbash/)
- [17] [Guballa Vigenère çözücüsü](https://www.guballa.de/vigenere-solver)
- [18] [Asecuritysite - Fernet çözücüsü](https://asecuritysite.com/encryption/ferdecode)
- [19] [Shamir secret-sharing yeniden oluşturucusu](https://christian.gen.co/secrets/)
- [20] [bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
- [21] [easy_BFopensslCTF](https://github.com/carlospolop/easy_BFopensslCTF)
- [22] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [23] [featherduster](https://github.com/nccgroup/featherduster)
- [24] [cryptovenom](https://github.com/lockedbyte/cryptovenom)
- [25] [PyCryptodome belgeleri](https://pycryptodome.readthedocs.io/en/latest/)
- [26] [SageMath](https://www.sagemath.org/)
- [27] [Z3](https://github.com/Z3Prover/z3)
- [28] [Eye Research – Şifreleme şemalarını kolay yoldan kırma](https://labs.eye.security/breaking-encryption-schemes-the-lazy-way/)
