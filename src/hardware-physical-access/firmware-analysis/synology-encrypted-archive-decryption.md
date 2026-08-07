# Synology PAT/SPK Encrypted Archive Decryption

{{#include ../../banners/hacktricks-training.md}}

## Genel Bakış

Several Synology devices (DSM/BSM NAS, BeeStation, …) distribute their firmware and application packages in **encrypted PAT / SPK archives**.  Bu arşivler, resmi extraction libraries içinde gömülü hard-coded keys sayesinde yalnızca public download files kullanılarak *offline* decrypt edilebilir.

This page documents, step-by-step, how the encrypted format works and how to fully recover the clear-text **TAR** that sits inside each package.  Prosedür, Pwn2Own Ireland 2024 sırasında gerçekleştirilen Synacktiv araştırmasına dayanır ve open-source tool [`synodecrypt`](https://github.com/synacktiv/synodecrypt) içinde uygulanmıştır.<sup>[[1]](#references)[[2]](#references)</sup>

> ⚠️  Format, hem `*.pat` (system update) hem de `*.spk` (application) archives için tamamen aynıdır – yalnızca seçilen hard-coded keys çifti farklıdır.

---

## 1. Grab the archive

Firmware/application update normalde Synology’s public portal üzerinden indirilebilir:
```bash
$ wget https://archive.synology.com/download/Os/BSM/BSM_BST150-4T_65374.pat
```
## 2. PAT yapısını dump et (isteğe bağlı)

`*.pat` image'ları, çeşitli dosyaları (boot loader, kernel, rootfs, package'lar…) içeren bir **cpio bundle**'dır. Ücretsiz [`patology`](https://github.com/sud0woodo/patology) utility'si bu wrapper'ı incelemek için kullanışlıdır:<sup>[[3]](#references)</sup>
```bash
$ python3 patology.py --dump -i BSM_BST150-4T_65374.pat
[…]
$ ls
DiskCompatibilityDB.tar  hda1.tgz  rd.bin  packages/  …
```
`*.spk` için doğrudan 3. adıma geçebilirsiniz.

## 3. Synology extraction kütüphanelerini çıkarma

Asıl decryption mantığı şurada bulunur:

* `/usr/syno/sbin/synoarchive`               → ana CLI wrapper
* `/usr/lib/libsynopkg.so.1`                 → DSM UI üzerinden wrapper'ı çağırır
* `libsynocodesign.so`                       → **cryptographic implementation'ı içerir**

Her iki binary de system rootfs (`hda1.tgz`) **ve** compressed init-rd (`rd.bin`) içinde bulunur. Yalnızca PAT dosyanız varsa bunları şu şekilde alabilirsiniz:
```bash
# rd.bin is LZMA-compressed CPIO
$ lzcat rd.bin | cpio -id 2>/dev/null
$ file usr/lib/libsynocodesign.so
usr/lib/libsynocodesign.so: ELF 64-bit LSB shared object, ARM aarch64, …
```
## 4. Hard-coded anahtarları kurtarma (`get_keys`)

`libsynocodesign.so` içindeki `get_keys(int keytype)` işlevi, istenen arşiv ailesi için iki adet 128-bit global değişken döndürür:<sup>[[1]](#references)</sup>
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
* **signature_key** → Archive header'ı doğrulamak için kullanılan Ed25519 public key.
* **master_key**    → Archive başına özel encryption key'i türetmek için kullanılan root key.

Bu iki constant'ı her DSM major version için yalnızca bir kez dump etmeniz gerekir.

## 5. Header yapısı ve signature verification

`synoarchive_open()` → `support_format_synoarchive()` → `archive_read_support_format_synoarchive()` aşağıdaki işlemleri gerçekleştirir:<sup>[[1]](#references)</sup>

1. Magic'i (3 bytes) `0xBFBAAD` **veya** `0xADBEEF` olarak oku.
2. Little-endian 32-bit `header_len` değerini oku.
3. `header_len` byte + sonraki **0x40-byte Ed25519 signature** değerini oku.
4. `crypto_sign_verify_detached()` başarılı olana kadar gömülü tüm public key'ler üzerinde iterate et.
5. Header'ı **MessagePack** ile decode ederek şunları elde et:
```python
[
data: bytes,
entries: [ [size: int, sha256: bytes], … ],
archive_description: bytes,
serial_number: [bytes],
not_valid_before: int
]
```
`entries`, daha sonra her dosyanın şifresi çözülürken libarchive'ın bütünlük denetimi yapmasına olanak tanır.

## 6. Arşiv başına alt anahtarı türetme

MessagePack header içinde bulunan `data` blob'undan:

* `subkey_id`  = offset 0x10'da little-endian `uint64`
* `ctx`        = offset 0x18'deki 7 bayt

32 baytlık **stream key**, libsodium kullanılarak elde edilir:
```c
crypto_kdf_derive_from_key(kdf_subkey, 32, subkey_id, ctx, master_key);
```
## 7. Synology’nin özel **libarchive** backend’i

Synology, magic değeri `0xADBEEF` olduğunda sahte bir "tar" formatı kaydeden yamalanmış bir libarchive ile birlikte gelir:<sup>[[1]](#references)</sup>
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
Şifresi çözülmüş `tar_hdr`, **klasik bir POSIX TAR başlığıdır**.

### spk_read_data()
```
while (remaining > 0):
chunk_len = min(0x400000, remaining) + 0x11   # +tag
buf   = archive_read_ahead(chunk_len)
crypto_secretstream_xchacha20poly1305_pull(state, out, …, buf, chunk_len)
remaining -= chunk_len - 0x11
```
Her **0x18-byte nonce**, şifrelenmiş chunk'ın başına eklenir.

Tüm entries işlendiğinde libarchive, herhangi bir standard tool ile açılabilen tamamen geçerli bir **`.tar`** üretir.

## 8. Her şeyi synodecrypt ile decrypt edin
```bash
$ python3 synodecrypt.py SynologyPhotos-rtd1619b-1.7.0-0794.spk
[+] found matching keys (SPK)
[+] header signature verified
[+] 104 entries
[+] archive successfully decrypted → SynologyPhotos-rtd1619b-1.7.0-0794.tar

$ tar xf SynologyPhotos-rtd1619b-1.7.0-0794.tar
```
`synodecrypt`, PAT/SPK'yi otomatik olarak algılar, doğru anahtarları yükler ve yukarıda açıklanan tam zinciri uygular.<sup>[[2]](#references)</sup>

## 9. Yaygın tuzaklar

* **`signature_key` ile `master_key`'i değiştirmeyin** – farklı amaçlara hizmet ederler.
* **Nonce**, her blok için (header ve data) ciphertext'ten *önce* gelir.
* Maksimum encrypted chunk boyutu **0x400000 + 0x11**'dir (libsodium tag).
* Bir DSM nesli için oluşturulan arşivler, sonraki sürümde farklı hard-coded key'lere geçebilir.

## 10. Ek araçlar

* [`patology`](https://github.com/sud0woodo/patology) – PAT arşivlerini parse/dump eder.<sup>[[3]](#references)</sup>
* [`synodecrypt`](https://github.com/synacktiv/synodecrypt) – PAT/SPK/diğerlerini decrypt eder.<sup>[[2]](#references)</sup>
* [`libsodium`](https://github.com/jedisct1/libsodium) – XChaCha20-Poly1305 secretstream için referans implementasyonu.
* [`msgpack`](https://msgpack.org/) – header serialisation.

## References

- [1] [Extraction of Synology encrypted archives – Synacktiv (Pwn2Own IE 2024)](https://www.synacktiv.com/publications/extraction-des-archives-chiffrees-synology-pwn2own-irlande-2024.html)
- [2] [synodecrypt on GitHub](https://github.com/synacktiv/synodecrypt)
- [3] [patology on GitHub](https://github.com/sud0woodo/patology)

{{#include ../../banners/hacktricks-training.md}}
