# Synology PAT/SPK 암호화 아카이브 복호화

{{#include ../../banners/hacktricks-training.md}}

## 개요

여러 Synology 장치 (DSM/BSM NAS, BeeStation 등)는 **암호화된 PAT / SPK 아카이브**로 펌웨어 및 애플리케이션 패키지를 배포합니다. 이러한 아카이브는 공식 추출 라이브러리에 내장된 하드코딩된 키 덕분에 공개 다운로드 파일만으로 *오프라인*에서 복호화할 수 있습니다.

이 페이지는 암호화된 형식이 작동하는 방식과 각 패키지 내부에 있는 평문 **TAR**를 완전히 복구하는 방법을 단계별로 문서화합니다. 이 절차는 Pwn2Own Ireland 2024 동안 수행된 Synacktiv 연구를 기반으로 하며 오픈 소스 도구 [`synodecrypt`](https://github.com/synacktiv/synodecrypt)에서 구현되었습니다.

> ⚠️  형식은 `*.pat` (시스템 업데이트)와 `*.spk` (애플리케이션) 아카이브 모두에 대해 정확히 동일합니다 – 선택되는 하드코딩된 키 쌍만 다릅니다.

---

## 1. 아카이브 가져오기

펌웨어/애플리케이션 업데이트는 일반적으로 Synology의 공개 포털에서 다운로드할 수 있습니다:
```bash
$ wget https://archive.synology.com/download/Os/BSM/BSM_BST150-4T_65374.pat
```
## 2. PAT 구조 덤프하기 (선택 사항)

`*.pat` 이미지는 여러 파일(부트 로더, 커널, rootfs, 패키지 등)을 포함하는 **cpio 번들**입니다. 무료 유틸리티 [`patology`](https://github.com/sud0woodo/patology)는 해당 래퍼를 검사하는 데 유용합니다:
```bash
$ python3 patology.py --dump -i BSM_BST150-4T_65374.pat
[…]
$ ls
DiskCompatibilityDB.tar  hda1.tgz  rd.bin  packages/  …
```
`*.spk` 파일의 경우 3단계로 바로 이동할 수 있습니다.

## 3. Synology 추출 라이브러리 추출

실제 복호화 로직은 다음에 있습니다:

* `/usr/syno/sbin/synoarchive`               → 메인 CLI 래퍼
* `/usr/lib/libsynopkg.so.1`                 → DSM UI에서 래퍼 호출
* `libsynocodesign.so`                       → **암호화 구현 포함**

두 바이너리는 시스템 rootfs (`hda1.tgz`) **및** 압축된 init-rd (`rd.bin`)에 존재합니다. PAT만 있는 경우 다음과 같은 방법으로 가져올 수 있습니다:
```bash
# rd.bin is LZMA-compressed CPIO
$ lzcat rd.bin | cpio -id 2>/dev/null
$ file usr/lib/libsynocodesign.so
usr/lib/libsynocodesign.so: ELF 64-bit LSB shared object, ARM aarch64, …
```
## 4. 하드코딩된 키 복구하기 (`get_keys`)

`libsynocodesign.so` 내부의 `get_keys(int keytype)` 함수는 요청된 아카이브 패밀리에 대해 두 개의 128비트 전역 변수를 단순히 반환합니다:
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
* **signature_key** → 아카이브 헤더를 검증하는 데 사용되는 Ed25519 공개 키.
* **master_key**    → 아카이브별 암호화 키를 파생하는 데 사용되는 루트 키.

각 DSM 주요 버전마다 이 두 상수를 한 번만 덤프하면 됩니다.

## 5. 헤더 구조 및 서명 검증

`synoarchive_open()` → `support_format_synoarchive()` → `archive_read_support_format_synoarchive()`는 다음을 수행합니다:

1. 매직 읽기 (3 바이트) `0xBFBAAD` **또는** `0xADBEEF`.
2. 리틀 엔디안 32비트 `header_len` 읽기.
3. `header_len` 바이트 + 다음 **0x40 바이트 Ed25519 서명** 읽기.
4. `crypto_sign_verify_detached()`가 성공할 때까지 모든 내장 공개 키를 반복합니다.
5. **MessagePack**으로 헤더를 디코딩하여 결과를 생성합니다:
```python
[
data: bytes,
entries: [ [size: int, sha256: bytes], … ],
archive_description: bytes,
serial_number: [bytes],
not_valid_before: int
]
```
`entries`는 libarchive가 각 파일을 복호화할 때 무결성 검사를 수행할 수 있도록 합니다.

## 6. 아카이브별 서브 키 유도

MessagePack 헤더에 포함된 `data` 블롭에서:

* `subkey_id`  = 오프셋 0x10의 리틀 엔디안 `uint64`
* `ctx`        = 오프셋 0x18의 7 바이트

32바이트 **스트림 키**는 libsodium을 사용하여 얻습니다:
```c
crypto_kdf_derive_from_key(kdf_subkey, 32, subkey_id, ctx, master_key);
```
## 7. Synology의 커스텀 **libarchive** 백엔드

Synology는 매직이 `0xADBEEF`일 때 가짜 "tar" 형식을 등록하는 패치된 libarchive를 번들로 제공합니다:
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
각 **0x18-byte nonce**는 암호화된 청크 앞에 추가됩니다.

모든 항목이 처리되면 libarchive는 표준 도구로 압축 해제할 수 있는 완벽하게 유효한 **`.tar`** 파일을 생성합니다.

## 8. synodecrypt로 모든 것을 복호화합니다.
```bash
$ python3 synodecrypt.py SynologyPhotos-rtd1619b-1.7.0-0794.spk
[+] found matching keys (SPK)
[+] header signature verified
[+] 104 entries
[+] archive successfully decrypted → SynologyPhotos-rtd1619b-1.7.0-0794.tar

$ tar xf SynologyPhotos-rtd1619b-1.7.0-0794.tar
```
`synodecrypt`는 PAT/SPK를 자동으로 감지하고, 올바른 키를 로드하며, 위에 설명된 전체 체인을 적용합니다.

## 9. 일반적인 함정

* `signature_key`와 `master_key`를 **교환하지 마십시오** – 이들은 서로 다른 목적을 가지고 있습니다.
* **nonce**는 모든 블록(헤더 및 데이터)의 암호문 *앞*에 위치합니다.
* 최대 암호화 청크 크기는 **0x400000 + 0x11**(libsodium 태그)입니다.
* 한 DSM 세대에 대해 생성된 아카이브는 다음 릴리스에서 다른 하드코딩된 키로 전환될 수 있습니다.

## 10. 추가 도구

* [`patology`](https://github.com/sud0woodo/patology) – PAT 아카이브를 파싱/덤프합니다.
* [`synodecrypt`](https://github.com/synacktiv/synodecrypt) – PAT/SPK/기타를 복호화합니다.
* [`libsodium`](https://github.com/jedisct1/libsodium) – XChaCha20-Poly1305 secretstream의 참조 구현입니다.
* [`msgpack`](https://msgpack.org/) – 헤더 직렬화.

## 참고 문헌

- [Extraction of Synology encrypted archives – Synacktiv (Pwn2Own IE 2024)](https://www.synacktiv.com/publications/extraction-des-archives-chiffrees-synology-pwn2own-irlande-2024.html)
- [synodecrypt on GitHub](https://github.com/synacktiv/synodecrypt)
- [patology on GitHub](https://github.com/sud0woodo/patology)

{{#include ../../banners/hacktricks-training.md}}
