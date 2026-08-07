# Synology PAT/SPK 암호화 아카이브 복호화

{{#include ../../banners/hacktricks-training.md}}

## 개요

여러 Synology 장치(DSM/BSM NAS, BeeStation, …)는 **암호화된 PAT / SPK 아카이브** 형태로 firmware와 application package를 배포합니다. 공식 extraction library 내부에 hard-coded key가 포함되어 있으므로, 공개 다운로드 파일만으로도 해당 아카이브를 *offline*에서 복호화할 수 있습니다.

이 페이지에서는 암호화된 형식의 작동 방식과 각 package 내부에 포함된 평문 **TAR**를 완전히 복구하는 방법을 단계별로 설명합니다. 이 절차는 Pwn2Own Ireland 2024 기간에 수행된 Synacktiv의 research를 기반으로 하며, open-source tool [`synodecrypt`](https://github.com/synacktiv/synodecrypt)에 구현되어 있습니다.<sup>[[1]](#references)[[2]](#references)</sup>

> ⚠️  `*.pat` (system update)와 `*.spk` (application) 아카이브의 형식은 정확히 동일하며, 선택되는 hard-coded key 쌍만 다릅니다.

---

## 1. 아카이브 가져오기

firmware/application update는 일반적으로 Synology의 public portal에서 다운로드할 수 있습니다:
```bash
$ wget https://archive.synology.com/download/Os/BSM/BSM_BST150-4T_65374.pat
```
## 2. PAT 구조 덤프 (선택 사항)

`*.pat` 이미지는 그 자체로 여러 파일(boot loader, kernel, rootfs, packages 등)을 포함하는 **cpio bundle**입니다. 무료 유틸리티인 [`patology`](https://github.com/sud0woodo/patology)를 사용하면 해당 wrapper를 편리하게 검사할 수 있습니다:<sup>[[3]](#references)</sup>
```bash
$ python3 patology.py --dump -i BSM_BST150-4T_65374.pat
[…]
$ ls
DiskCompatibilityDB.tar  hda1.tgz  rd.bin  packages/  …
```
`*.spk`의 경우 3단계로 바로 진행할 수 있습니다.

## 3. Synology extraction libraries 추출

실제 decryption logic은 다음 위치에 있습니다.

* `/usr/syno/sbin/synoarchive`               → main CLI wrapper
* `/usr/lib/libsynopkg.so.1`                 → DSM UI에서 wrapper 호출
* `libsynocodesign.so`                       → **cryptographic implementation 포함**

두 binary 모두 system rootfs(`hda1.tgz`)와 compressed init-rd(`rd.bin`)에 있습니다. PAT만 있는 경우 다음과 같이 가져올 수 있습니다:
```bash
# rd.bin is LZMA-compressed CPIO
$ lzcat rd.bin | cpio -id 2>/dev/null
$ file usr/lib/libsynocodesign.so
usr/lib/libsynocodesign.so: ELF 64-bit LSB shared object, ARM aarch64, …
```
## 4. 하드코딩된 키 복구 (`get_keys`)

`libsynocodesign.so` 내부의 `get_keys(int keytype)` 함수는 요청된 아카이브 family에 해당하는 두 개의 128비트 전역 변수를 단순히 반환합니다:<sup>[[1]](#references)</sup>
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
* **signature_key** → archive header를 검증하는 데 사용되는 Ed25519 public key.
* **master_key**    → archive별 encryption key를 파생하는 데 사용되는 root key.

각 DSM major version마다 이 두 constant만 한 번 dump하면 됩니다.

## 5. Header structure 및 signature verification

`synoarchive_open()` → `support_format_synoarchive()` → `archive_read_support_format_synoarchive()`는 다음을 수행합니다:<sup>[[1]](#references)</sup>

1. magic (3 bytes) `0xBFBAAD` **또는** `0xADBEEF`를 읽습니다.
2. little-endian 32-bit `header_len`을 읽습니다.
3. `header_len` bytes와 그 다음 **0x40-byte Ed25519 signature**를 읽습니다.
4. `crypto_sign_verify_detached()`가 성공할 때까지 포함된 모든 public key를 순회합니다.
5. **MessagePack**으로 header를 decode하여 다음을 얻습니다:
```python
[
data: bytes,
entries: [ [size: int, sha256: bytes], … ],
archive_description: bytes,
serial_number: [bytes],
not_valid_before: int
]
```
`entries`를 사용하면 이후 libarchive가 각 파일이 복호화되는 동안 무결성을 검사할 수 있습니다.

## 6. 아카이브별 sub-key 도출

MessagePack 헤더에 포함된 `data` blob에서 다음을 확인합니다:

* `subkey_id`  = 오프셋 0x10의 little-endian `uint64`
* `ctx`        = 오프셋 0x18의 7바이트

32바이트 **stream key**는 libsodium을 사용하여 얻습니다:
```c
crypto_kdf_derive_from_key(kdf_subkey, 32, subkey_id, ctx, master_key);
```
## 7. Synology의 custom **libarchive** 백엔드

Synology는 magic이 `0xADBEEF`일 때마다 가짜 "tar" format을 등록하는 patched libarchive를 번들로 제공합니다:<sup>[[1]](#references)</sup>
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
복호화된 `tar_hdr`는 **고전적인 POSIX TAR 헤더**입니다.

### spk_read_data()
```
while (remaining > 0):
chunk_len = min(0x400000, remaining) + 0x11   # +tag
buf   = archive_read_ahead(chunk_len)
crypto_secretstream_xchacha20poly1305_pull(state, out, …, buf, chunk_len)
remaining -= chunk_len - 0x11
```
각 **0x18-byte nonce**는 암호화된 chunk 앞에 추가됩니다.

모든 entries가 처리되면 libarchive는 모든 표준 도구로 압축을 풀 수 있는 완전히 유효한 **`.tar`**를 생성합니다.

## 8. synodecrypt로 모두 Decrypt하기
```bash
$ python3 synodecrypt.py SynologyPhotos-rtd1619b-1.7.0-0794.spk
[+] found matching keys (SPK)
[+] header signature verified
[+] 104 entries
[+] archive successfully decrypted → SynologyPhotos-rtd1619b-1.7.0-0794.tar

$ tar xf SynologyPhotos-rtd1619b-1.7.0-0794.tar
```
`synodecrypt`는 PAT/SPK를 자동으로 감지하고, 올바른 키를 로드한 후 위에서 설명한 전체 chain을 적용합니다.<sup>[[2]](#references)</sup>

## 9. 일반적인 pitfalls

* `signature_key`와 `master_key`를 **절대** 바꾸지 마세요. 두 키는 서로 다른 용도로 사용됩니다.
* 모든 block(header 및 data)에서 **nonce**는 ciphertext 앞에 옵니다.
* 최대 encrypted chunk size는 **0x400000 + 0x11**입니다(libsodium tag).
* 한 DSM generation용으로 생성된 archive는 다음 release에서 다른 hard-coded key로 변경될 수 있습니다.

## 10. 추가 tooling

* [`patology`](https://github.com/sud0woodo/patology) – PAT archive를 parse/dump합니다.<sup>[[3]](#references)</sup>
* [`synodecrypt`](https://github.com/synacktiv/synodecrypt) – PAT/SPK/기타 archive를 decrypt합니다.<sup>[[2]](#references)</sup>
* [`libsodium`](https://github.com/jedisct1/libsodium) – XChaCha20-Poly1305 secretstream의 reference implementation입니다.
* [`msgpack`](https://msgpack.org/) – header serialisation에 사용됩니다.

## References

- [1] [Synology encrypted archive extraction – Synacktiv (Pwn2Own IE 2024)](https://www.synacktiv.com/publications/extraction-des-archives-chiffrees-synology-pwn2own-irlande-2024.html)
- [2] [GitHub의 synodecrypt](https://github.com/synacktiv/synodecrypt)
- [3] [GitHub의 patology](https://github.com/sud0woodo/patology)

{{#include ../../banners/hacktricks-training.md}}
