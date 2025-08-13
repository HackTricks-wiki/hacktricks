# Synology PAT/SPK Encrypted Archive Decryption

{{#include ../../banners/hacktricks-training.md}}

## Overview

कई Synology उपकरण (DSM/BSM NAS, BeeStation, …) अपने फर्मवेयर और एप्लिकेशन पैकेज को **encrypted PAT / SPK archives** में वितरित करते हैं। ये आर्काइव *ऑफलाइन* केवल सार्वजनिक डाउनलोड फ़ाइलों के साथ डिक्रिप्ट किए जा सकते हैं, धन्यवाद हार्ड-कोडेड कुंजी जो आधिकारिक निष्कर्षण पुस्तकालयों के अंदर एम्बेडेड हैं।

यह पृष्ठ चरण-दर-चरण दस्तावेज करता है कि एन्क्रिप्टेड प्रारूप कैसे काम करता है और प्रत्येक पैकेज के अंदर स्थित स्पष्ट-टेक्स्ट **TAR** को पूरी तरह से कैसे पुनर्प्राप्त किया जाए। यह प्रक्रिया Synacktiv द्वारा Pwn2Own Ireland 2024 के दौरान किए गए शोध पर आधारित है और ओपन-सोर्स टूल [`synodecrypt`](https://github.com/synacktiv/synodecrypt) में लागू की गई है।

> ⚠️  प्रारूप `*.pat` (सिस्टम अपडेट) और `*.spk` (एप्लिकेशन) आर्काइव के लिए बिल्कुल समान है - वे केवल चयनित हार्ड-कोडेड कुंजियों के जोड़े में भिन्न होते हैं।

---

## 1. Grab the archive

फर्मवेयर/एप्लिकेशन अपडेट सामान्यतः Synology के सार्वजनिक पोर्टल से डाउनलोड किया जा सकता है:
```bash
$ wget https://archive.synology.com/download/Os/BSM/BSM_BST150-4T_65374.pat
```
## 2. PAT संरचना को डंप करें (वैकल्पिक)

`*.pat` इमेज स्वयं एक **cpio बंडल** हैं जो कई फ़ाइलों (बूट लोडर, कर्नेल, rootfs, पैकेज…) को एम्बेड करती हैं। मुफ्त उपयोगिता [`patology`](https://github.com/sud0woodo/patology) उस लपेटने की जांच करने के लिए सुविधाजनक है:
```bash
$ python3 patology.py --dump -i BSM_BST150-4T_65374.pat
[…]
$ ls
DiskCompatibilityDB.tar  hda1.tgz  rd.bin  packages/  …
```
For `*.spk` आप सीधे चरण 3 पर जा सकते हैं।

## 3. Synology निष्कर्षण पुस्तकालयों को निकालें

वास्तविक डिक्रिप्शन लॉजिक यहाँ है:

* `/usr/syno/sbin/synoarchive`               → मुख्य CLI रैपर
* `/usr/lib/libsynopkg.so.1`                 → DSM UI से रैपर को कॉल करता है
* `libsynocodesign.so`                       → **क्रिप्टोग्राफिक कार्यान्वयन शामिल है**

दोनों बाइनरी सिस्टम रूटफाइल सिस्टम (`hda1.tgz`) **और** संकुचित init-rd (`rd.bin`) में मौजूद हैं। यदि आपके पास केवल PAT है, तो आप उन्हें इस तरह प्राप्त कर सकते हैं:
```bash
# rd.bin is LZMA-compressed CPIO
$ lzcat rd.bin | cpio -id 2>/dev/null
$ file usr/lib/libsynocodesign.so
usr/lib/libsynocodesign.so: ELF 64-bit LSB shared object, ARM aarch64, …
```
## 4. हार्ड-कोडेड कुंजियों को पुनर्प्राप्त करें (`get_keys`)

`libsynocodesign.so` के अंदर `get_keys(int keytype)` फ़ंक्शन बस अनुरोधित आर्काइव परिवार के लिए दो 128-बिट वैश्विक चर लौटाता है:
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
* **signature_key** → Ed25519 सार्वजनिक कुंजी जो संग्रह हेडर को सत्यापित करने के लिए उपयोग की जाती है।
* **master_key**    → रूट कुंजी जो प्रति-संग्रह एन्क्रिप्शन कुंजी निकालने के लिए उपयोग की जाती है।

आपको प्रत्येक DSM प्रमुख संस्करण के लिए केवल एक बार इन दो स्थिरांक को डंप करना है।

## 5. हेडर संरचना और हस्ताक्षर सत्यापन

`synoarchive_open()` → `support_format_synoarchive()` → `archive_read_support_format_synoarchive()` निम्नलिखित कार्य करता है:

1. मैजिक पढ़ें (3 बाइट) `0xBFBAAD` **या** `0xADBEEF`।
2. लिटिल-एंडियन 32-बिट `header_len` पढ़ें।
3. `header_len` बाइट्स + अगली **0x40-बाइट Ed25519 हस्ताक्षर** पढ़ें।
4. सभी एम्बेडेड सार्वजनिक कुंजियों पर दोहराएं जब तक `crypto_sign_verify_detached()` सफल न हो जाए।
5. **MessagePack** के साथ हेडर को डिकोड करें, yielding:
```python
[
data: bytes,
entries: [ [size: int, sha256: bytes], … ],
archive_description: bytes,
serial_number: [bytes],
not_valid_before: int
]
```
`entries` बाद में libarchive को प्रत्येक फ़ाइल की सत्यता की जांच करने की अनुमति देता है जब इसे डिक्रिप्ट किया जाता है।

## 6. प्रति-आर्काइव उप-कुंजी निकालें

MessagePack हेडर में निहित `data` ब्लॉब से:

* `subkey_id`  = little-endian `uint64` ऑफ़सेट 0x10 पर
* `ctx`        = ऑफ़सेट 0x18 पर 7 बाइट्स

32-बाइट **स्ट्रीम कुंजी** libsodium के साथ प्राप्त की जाती है:
```c
crypto_kdf_derive_from_key(kdf_subkey, 32, subkey_id, ctx, master_key);
```
## 7. Synology का कस्टम **libarchive** बैकएंड

Synology एक पैच किया हुआ libarchive बंडल करता है जो एक नकली "tar" फॉर्मेट को रजिस्टर करता है जब भी मैजिक `0xADBEEF` होता है:
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
डिक्रिप्ट किया गया `tar_hdr` एक **क्लासिकल POSIX TAR हेडर** है।

### spk_read_data()
```
while (remaining > 0):
chunk_len = min(0x400000, remaining) + 0x11   # +tag
buf   = archive_read_ahead(chunk_len)
crypto_secretstream_xchacha20poly1305_pull(state, out, …, buf, chunk_len)
remaining -= chunk_len - 0x11
```
प्रत्येक **0x18-byte nonce** को एन्क्रिप्टेड भाग के पहले जोड़ा जाता है।

एक बार जब सभी प्रविष्टियाँ संसाधित हो जाती हैं, तो libarchive एक पूरी तरह से मान्य **`.tar`** उत्पन्न करता है जिसे किसी भी मानक उपकरण के साथ अनपैक किया जा सकता है।

## 8. सब कुछ synodecrypt के साथ डिक्रिप्ट करें
```bash
$ python3 synodecrypt.py SynologyPhotos-rtd1619b-1.7.0-0794.spk
[+] found matching keys (SPK)
[+] header signature verified
[+] 104 entries
[+] archive successfully decrypted → SynologyPhotos-rtd1619b-1.7.0-0794.tar

$ tar xf SynologyPhotos-rtd1619b-1.7.0-0794.tar
```
`synodecrypt` स्वचालित रूप से PAT/SPK का पता लगाता है, सही कुंजियाँ लोड करता है और ऊपर वर्णित पूर्ण श्रृंखला लागू करता है।

## 9. सामान्य pitfalls

* `signature_key` और `master_key` को **स्वैप** न करें - वे विभिन्न उद्देश्यों के लिए काम करते हैं।
* **nonce** हर ब्लॉक (हेडर और डेटा) के लिए ciphertext से *पहले* आता है।
* अधिकतम एन्क्रिप्टेड चंक आकार **0x400000 + 0x11** है (libsodium टैग)।
* एक DSM पीढ़ी के लिए बनाए गए आर्काइव अगले रिलीज़ में विभिन्न हार्ड-कोडेड कुंजियों पर स्विच कर सकते हैं।

## 10. अतिरिक्त उपकरण

* [`patology`](https://github.com/sud0woodo/patology) – PAT आर्काइव को पार्स/डंप करें।
* [`synodecrypt`](https://github.com/synacktiv/synodecrypt) – PAT/SPK/अन्य को डिक्रिप्ट करें।
* [`libsodium`](https://github.com/jedisct1/libsodium) – XChaCha20-Poly1305 सीक्रेटस्ट्रीम का संदर्भ कार्यान्वयन।
* [`msgpack`](https://msgpack.org/) – हेडर सीरियलाइजेशन।

## संदर्भ

- [Extraction of Synology encrypted archives – Synacktiv (Pwn2Own IE 2024)](https://www.synacktiv.com/publications/extraction-des-archives-chiffrees-synology-pwn2own-irlande-2024.html)
- [synodecrypt on GitHub](https://github.com/synacktiv/synodecrypt)
- [patology on GitHub](https://github.com/sud0woodo/patology)

{{#include ../../banners/hacktricks-training.md}}
