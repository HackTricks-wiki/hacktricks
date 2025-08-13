# Synology PAT/SPK Şifreli Arşiv Şifre Çözme

{{#include ../../banners/hacktricks-training.md}}

## Genel Bakış

Birçok Synology cihazı (DSM/BSM NAS, BeeStation, …) yazılım ve uygulama paketlerini **şifreli PAT / SPK arşivleri** içinde dağıtır. Bu arşivler, resmi çıkarım kütüphanelerine gömülü olan sabit anahtarlar sayesinde yalnızca kamuya açık indirme dosyaları ile *çevrimdışı* olarak şifresi çözülebilir.

Bu sayfa, şifreli formatın nasıl çalıştığını ve her paketin içinde bulunan açık metin **TAR** dosyasının nasıl tamamen geri kazanılacağını adım adım belgeler. Prosedür, Pwn2Own İrlanda 2024 sırasında gerçekleştirilen Synacktiv araştırmasına dayanmaktadır ve açık kaynaklı araç [`synodecrypt`](https://github.com/synacktiv/synodecrypt) içinde uygulanmıştır.

> ⚠️  Format, `*.pat` (sistem güncellemesi) ve `*.spk` (uygulama) arşivleri için tam olarak aynıdır – yalnızca seçilen sabit anahtar çiftlerinde farklılık gösterir.

---

## 1. Arşivi Al

Yazılım/uygulama güncellemesi genellikle Synology’nin kamu portalından indirilebilir:
```bash
$ wget https://archive.synology.com/download/Os/BSM/BSM_BST150-4T_65374.pat
```
## 2. PAT yapısını dökme (isteğe bağlı)

`*.pat` görüntüleri, birkaç dosyayı (önyükleme yükleyici, çekirdek, rootfs, paketler…) içeren bir **cpio paketi**dir. Bu sarmayı incelemek için ücretsiz araç [`patology`](https://github.com/sud0woodo/patology) kullanışlıdır:
```bash
$ python3 patology.py --dump -i BSM_BST150-4T_65374.pat
[…]
$ ls
DiskCompatibilityDB.tar  hda1.tgz  rd.bin  packages/  …
```
For `*.spk` doğrudan 3. adıma geçebilirsiniz.

## 3. Synology çıkarım kütüphanelerini çıkarın

Gerçek şifre çözme mantığı şunlarda bulunur:

* `/usr/syno/sbin/synoarchive`               → ana CLI sarmalayıcı
* `/usr/lib/libsynopkg.so.1`                 → DSM UI'den sarmalayıcıyı çağırır
* `libsynocodesign.so`                       → **kriptografik uygulamayı içerir**

Her iki ikili dosya da sistem rootfs (`hda1.tgz`) **ve** sıkıştırılmış init-rd (`rd.bin`) içinde mevcuttur. Eğer sadece PAT'iniz varsa, bunları bu şekilde alabilirsiniz:
```bash
# rd.bin is LZMA-compressed CPIO
$ lzcat rd.bin | cpio -id 2>/dev/null
$ file usr/lib/libsynocodesign.so
usr/lib/libsynocodesign.so: ELF 64-bit LSB shared object, ARM aarch64, …
```
## 4. Hard-coded anahtarları geri al (`get_keys`)

`libsynocodesign.so` içinde `get_keys(int keytype)` fonksiyonu, istenen arşiv ailesi için iki 128-bit global değişkeni basitçe döndürür:
```c
case 0:            // PAT (system)
case 10:
case 11:
signature_key = qword_23A40;
master_key    = qword_23A68;
break;

case 3:            // SPK (applications)
signature_key = qword_23AE0;
master_key    = qword_23B08;
break;
```
* **signature_key** → Arşiv başlığını doğrulamak için kullanılan Ed25519 genel anahtarı.
* **master_key**    → Her arşiv için şifreleme anahtarını türetmek için kullanılan kök anahtar.

Her DSM ana sürümü için bu iki sabiti yalnızca bir kez dökmeniz gerekir.

## 5. Başlık yapısı & imza doğrulama

`synoarchive_open()` → `support_format_synoarchive()` → `archive_read_support_format_synoarchive()` aşağıdakileri gerçekleştirir:

1. Magic (3 bayt) `0xBFBAAD` **veya** `0xADBEEF` okuyun.
2. Küçük sonlu 32-bit `header_len` okuyun.
3. `header_len` baytını + sonraki **0x40-bayt Ed25519 imzasını** okuyun.
4. `crypto_sign_verify_detached()` başarılı olana kadar tüm gömülü genel anahtarlar üzerinde yineleyin.
5. **MessagePack** ile başlığı çözün, sonuç:
```python
[
data: bytes,
entries: [ [size: int, sha256: bytes], … ],
archive_description: bytes,
serial_number: [bytes],
not_valid_before: int
]
```
`entries`, daha sonra libarchive'ın her dosyayı şifresi çözülürken bütünlüğünü kontrol etmesine olanak tanır.

## 6. Arşiv başına alt anahtarı türetin

MessagePack başlığında bulunan `data` blob'undan:

* `subkey_id`  = little-endian `uint64` 0x10 ofsetinde
* `ctx`        = 0x18 ofsetinde 7 bayt

32 baytlık **stream key**, libsodium ile elde edilir:
```c
crypto_kdf_derive_from_key(kdf_subkey, 32, subkey_id, ctx, master_key);
```
## 7. Synology’nin özel **libarchive** arka ucu

Synology, sihirli değer `0xADBEEF` olduğunda sahte bir "tar" formatı kaydeden yamanmış bir libarchive paketler:
```c
register_format(
"tar", spk_bid, spk_options,
spk_read_header, spk_read_data, spk_read_data_skip,
NULL, spk_cleanup, NULL, NULL);
```
### spk_read_header()
```
- Read 0x200 bytes
- nonce  = buf[0:0x18]
- cipher = buf[0x18:0x18+0x193]
- crypto_secretstream_xchacha20poly1305_init_pull(state, nonce, kdf_subkey)
- crypto_secretstream_xchacha20poly1305_pull(state, tar_hdr, …, cipher, 0x193)
```
Şifrelenmemiş `tar_hdr`, **klasik POSIX TAR başlığıdır**.

### spk_read_data()
```
while (remaining > 0):
chunk_len = min(0x400000, remaining) + 0x11   # +tag
buf   = archive_read_ahead(chunk_len)
crypto_secretstream_xchacha20poly1305_pull(state, out, …, buf, chunk_len)
remaining -= chunk_len - 0x11
```
Her **0x18-byte nonce** şifreli parçanın önüne eklenir.

Tüm girişler işlendiğinde, libarchive herhangi bir standart araçla açılabilen tamamen geçerli bir **`.tar`** dosyası üretir.

## 8. Her şeyi synodecrypt ile şifre çözün
```bash
$ python3 synodecrypt.py SynologyPhotos-rtd1619b-1.7.0-0794.spk
[+] found matching keys (SPK)
[+] header signature verified
[+] 104 entries
[+] archive successfully decrypted → SynologyPhotos-rtd1619b-1.7.0-0794.tar

$ tar xf SynologyPhotos-rtd1619b-1.7.0-0794.tar
```
`synodecrypt` otomatik olarak PAT/SPK'yı tespit eder, doğru anahtarları yükler ve yukarıda açıklanan tam zinciri uygular.

## 9. Yaygın tuzaklar

* `signature_key` ve `master_key`'i **değiştirmeyin** – farklı amaçlara hizmet ederler.
* **nonce**, her blok (başlık ve veri) için şifreli metinden *önce* gelir.
* Maksimum şifreli parça boyutu **0x400000 + 0x11**'dir (libsodium etiketi).
* Bir DSM nesli için oluşturulan arşivler, bir sonraki sürümde farklı sabit anahtarlara geçebilir.

## 10. Ek araçlar

* [`patology`](https://github.com/sud0woodo/patology) – PAT arşivlerini ayrıştırma/dökme.
* [`synodecrypt`](https://github.com/synacktiv/synodecrypt) – PAT/SPK/diğerlerini şifre çözme.
* [`libsodium`](https://github.com/jedisct1/libsodium) – XChaCha20-Poly1305 secretstream için referans uygulaması.
* [`msgpack`](https://msgpack.org/) – başlık serileştirmesi.

## Referanslar

- [Synology şifreli arşivlerinin çıkarılması – Synacktiv (Pwn2Own IE 2024)](https://www.synacktiv.com/publications/extraction-des-archives-chiffrees-synology-pwn2own-irlande-2024.html)
- [synodecrypt GitHub'da](https://github.com/synacktiv/synodecrypt)
- [patology GitHub'da](https://github.com/sud0woodo/patology)

{{#include ../../banners/hacktricks-training.md}}
