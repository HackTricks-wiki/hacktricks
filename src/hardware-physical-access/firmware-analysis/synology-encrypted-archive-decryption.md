# Synology PAT/SPK Encrypted Archive Decryption

{{#include ../../banners/hacktricks-training.md}}

## अवलोकन

कई Synology devices (DSM/BSM NAS, BeeStation, …) अपने firmware और application packages को **encrypted PAT / SPK archives** में वितरित करते हैं। इन archives को केवल public download files की सहायता से *offline* decrypt किया जा सकता है, क्योंकि official extraction libraries के अंदर hard-coded keys embedded होती हैं।

यह पेज step-by-step दस्तावेज़ करता है कि encrypted format कैसे काम करता है और प्रत्येक package के अंदर मौजूद clear-text **TAR** को पूरी तरह कैसे recover किया जाए। यह procedure Pwn2Own Ireland 2024 के दौरान किए गए Synacktiv research पर आधारित है और open-source tool [`synodecrypt`](https://github.com/synacktiv/synodecrypt) में implemented है।<sup>[[1]](#references)[[2]](#references)</sup>

> ⚠️  Format दोनों `*.pat` (system update) और `*.spk` (application) archives के लिए बिल्कुल समान है – इनमें केवल selected hard-coded keys की pair अलग होती है।

---

## 1. Archive प्राप्त करें

Firmware/application update सामान्यतः Synology के public portal से download किया जा सकता है:
```bash
$ wget https://archive.synology.com/download/Os/BSM/BSM_BST150-4T_65374.pat
```
## 2. PAT structure Dump करें (वैकल्पिक)

`*.pat` images स्वयं एक **cpio bundle** हैं, जिसमें कई files (boot loader, kernel, rootfs, packages…) embedded होती हैं। इस wrapper को inspect करने के लिए free utility [`patology`](https://github.com/sud0woodo/patology) सुविधाजनक है:<sup>[[3]](#references)</sup>
```bash
$ python3 patology.py --dump -i BSM_BST150-4T_65374.pat
[…]
$ ls
DiskCompatibilityDB.tar  hda1.tgz  rd.bin  packages/  …
```
`*.spk` के लिए आप सीधे चरण 3 पर जा सकते हैं।

## 3. Synology extraction libraries निकालें

वास्तविक decryption logic यहां मौजूद है:

* `/usr/syno/sbin/synoarchive`               → मुख्य CLI wrapper
* `/usr/lib/libsynopkg.so.1`                 → DSM UI से wrapper को call करता है
* `libsynocodesign.so`                       → **cryptographic implementation शामिल है**

दोनों binaries system rootfs (`hda1.tgz`) **और** compressed init-rd (`rd.bin`) में मौजूद हैं। यदि आपके पास केवल PAT है, तो आप इन्हें इस तरह प्राप्त कर सकते हैं:
```bash
# rd.bin is LZMA-compressed CPIO
$ lzcat rd.bin | cpio -id 2>/dev/null
$ file usr/lib/libsynocodesign.so
usr/lib/libsynocodesign.so: ELF 64-bit LSB shared object, ARM aarch64, …
```
## 4. hard-coded keys recover करना (`get_keys`)

`libsynocodesign.so` के अंदर `get_keys(int keytype)` function अनुरोधित archive family के लिए दो 128-bit global variables को सीधे return करता है:<sup>[[1]](#references)</sup>
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
* **signature_key** → archive header को verify करने के लिए उपयोग की जाने वाली Ed25519 public key।
* **master_key**    → प्रति-archive encryption key derive करने के लिए उपयोग की जाने वाली root key।

आपको प्रत्येक DSM major version के लिए इन दोनों constants को केवल एक बार dump करना होगा।

## 5. Header structure और signature verification

`synoarchive_open()` → `support_format_synoarchive()` → `archive_read_support_format_synoarchive()` निम्नलिखित कार्य करता है:<sup>[[1]](#references)</sup>

1. magic (3 bytes) `0xBFBAAD` **या** `0xADBEEF` पढ़ता है।
2. little-endian 32-bit `header_len` पढ़ता है।
3. `header_len` bytes + अगले **0x40-byte Ed25519 signature** को पढ़ता है।
4. सभी embedded public keys पर iterate करता है, जब तक कि `crypto_sign_verify_detached()` सफल न हो जाए।
5. Header को **MessagePack** के साथ decode करता है, जिससे प्राप्त होता है:
```python
[
data: bytes,
entries: [ [size: int, sha256: bytes], … ],
archive_description: bytes,
serial_number: [bytes],
not_valid_before: int
]
```
`entries` बाद में libarchive को decrypted होने पर प्रत्येक file की integrity-check करने की अनुमति देता है।

## 6. प्रत्येक archive की sub-key derive करें

MessagePack header में मौजूद `data` blob से:

* `subkey_id`  = offset 0x10 पर little-endian `uint64`
* `ctx`        = offset 0x18 पर 7 bytes

32-byte **stream key** libsodium से प्राप्त की जाती है:
```c
crypto_kdf_derive_from_key(kdf_subkey, 32, subkey_id, ctx, master_key);
```
## 7. Synology का custom **libarchive** backend

Synology एक patched libarchive को bundle करता है, जो magic के `0xADBEEF` होने पर एक fake "tar" format register करता है:<sup>[[1]](#references)</sup>
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
डिक्रिप्ट किया गया `tar_hdr` एक **classical POSIX TAR header** है।

### spk_read_data()
```
while (remaining > 0):
chunk_len = min(0x400000, remaining) + 0x11   # +tag
buf   = archive_read_ahead(chunk_len)
crypto_secretstream_xchacha20poly1305_pull(state, out, …, buf, chunk_len)
remaining -= chunk_len - 0x11
```
प्रत्येक **0x18-byte nonce** को encrypted chunk के आगे जोड़ा जाता है।

सभी entries को process करने के बाद libarchive एक पूरी तरह मान्य **`.tar`** बनाता है, जिसे किसी भी standard tool से unpack किया जा सकता है।

## 8. synodecrypt से सब कुछ decrypt करें
```bash
$ python3 synodecrypt.py SynologyPhotos-rtd1619b-1.7.0-0794.spk
[+] found matching keys (SPK)
[+] header signature verified
[+] 104 entries
[+] archive successfully decrypted → SynologyPhotos-rtd1619b-1.7.0-0794.tar

$ tar xf SynologyPhotos-rtd1619b-1.7.0-0794.tar
```
`synodecrypt` स्वचालित रूप से PAT/SPK का पता लगाता है, सही keys लोड करता है और ऊपर वर्णित पूरी chain लागू करता है।<sup>[[2]](#references)</sup>

## 9. सामान्य समस्याएँ

* `signature_key` और `master_key` को **आपस में न बदलें** – इनके उद्देश्य अलग-अलग हैं।
* प्रत्येक block (header और data) के लिए **nonce**, ciphertext से *पहले* आता है।
* maximum encrypted chunk size **0x400000 + 0x11** (libsodium tag) है।
* एक DSM generation के लिए बनाए गए archives अगले release में अलग hard-coded keys पर switch कर सकते हैं।

## 10. अतिरिक्त tooling

* [`patology`](https://github.com/sud0woodo/patology) – PAT archives को parse/dump करता है।<sup>[[3]](#references)</sup>
* [`synodecrypt`](https://github.com/synacktiv/synodecrypt) – PAT/SPK/others को decrypt करता है।<sup>[[2]](#references)</sup>
* [`libsodium`](https://github.com/jedisct1/libsodium) – XChaCha20-Poly1305 secretstream का reference implementation।
* [`msgpack`](https://msgpack.org/) – header serialisation।

## References

- [1] [Synology encrypted archives का Extraction – Synacktiv (Pwn2Own IE 2024)](https://www.synacktiv.com/publications/extraction-des-archives-chiffrees-synology-pwn2own-irlande-2024.html)
- [2] [GitHub पर synodecrypt](https://github.com/synacktiv/synodecrypt)
- [3] [GitHub पर patology](https://github.com/sud0woodo/patology)

{{#include ../../banners/hacktricks-training.md}}
