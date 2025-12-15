# Crypto CTF Workflow

{{#include ../../banners/hacktricks-training.md}}

## 트리아지 체크리스트

1. 무엇이 있는지 식별: encoding vs encryption vs hash vs signature vs MAC.
2. 어떤 것을 제어할 수 있는지 판단: plaintext/ciphertext, IV/nonce, key, oracle (padding/error/timing), partial leakage.
3. 분류: symmetric (AES/CTR/GCM), public-key (RSA/ECC), hash/MAC (SHA/MD5/HMAC), classical (Vigenere/XOR).
4. 가능성 높은 검사부터 먼저 적용: decode layers, known-plaintext XOR, nonce reuse, mode misuse, oracle behavior.
5. 필요한 경우에만 고급 기법으로 확장: lattices (LLL/Coppersmith), SMT/Z3, side-channels.

## 온라인 리소스 & 유틸리티

이 리소스들은 작업이 식별 및 레이어 분해가 필요하거나 가설을 빠르게 확인해야 할 때 유용합니다.

### Hash lookups

- 해시를 Google에 검색하세요 (의외로 효과적입니다).
- https://crackstation.net/
- https://md5decrypt.net/
- https://hashes.org/search.php
- https://www.onlinehashcrack.com/
- https://gpuhash.me/
- http://hashtoolkit.com/reverse-hash

### Identification helpers

- CyberChef (magic, decode, convert): https://gchq.github.io/CyberChef/
- dCode (ciphers/encodings playground): https://www.dcode.fr/tools-list
- Boxentriq (substitution solvers): https://www.boxentriq.com/code-breaking

### Practice platforms / references

- CryptoHack (hands-on crypto challenges): https://cryptohack.org/
- Cryptopals (classic modern crypto pitfalls): https://cryptopals.com/

### Automated decoding

- Ciphey: https://github.com/Ciphey/Ciphey
- python-codext (tries many bases/encodings): https://github.com/dhondta/python-codext

## Encodings & classical ciphers

### Technique

많은 CTF crypto 문제는 여러 겹의 변환(layered transforms)으로 구성됩니다: base encoding + simple substitution + compression. 목표는 레이어를 식별하고 안전하게 벗겨내는 것입니다.

### Encodings: try many bases

레이어드 인코딩(base64 → base32 → …)이 의심되면 다음을 시도하세요:

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

일반적인 징후:

- Base64: `A-Za-z0-9+/=` (`=` 패딩이 흔함)
- Base32: `A-Z2-7=` (종종 많은 `=` 패딩)
- Ascii85/Base85: 구두점이 빽빽함; 때때로 `<~ ~>`로 둘러싸임

### Substitution / monoalphabetic

- Boxentriq cryptogram solver: https://www.boxentriq.com/code-breaking/cryptogram
- quipqiup: https://quipqiup.com/

### Caesar / ROT / Atbash

- Nayuki auto breaker: https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript
- Atbash: http://rumkin.com/tools/cipher/atbash.php

### Vigenère

- https://www.dcode.fr/vigenere-cipher
- https://www.guballa.de/vigenere-solver

### Bacon cipher

종종 5비트 또는 5글자 그룹으로 나타납니다:
```
00111 01101 01010 00000 ...
AABBB ABBAB ABABA AAAAA ...
```
### Morse
```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```
### 룬

룬은 종종 치환 알파벳입니다; "futhark cipher"를 검색하고 매핑 테이블을 시도해 보세요.

## 챌린지에서의 압축

### 기법

압축은 추가 레이어로 빈번히 등장합니다 (zlib/deflate/gzip/xz/zstd), 때로는 중첩되기도 합니다. 출력이 거의 파싱되지만 쓰레기처럼 보이면 압축을 의심하세요.

### 빠른 식별

- `file <blob>`
- 매직 바이트를 확인:
- gzip: `1f 8b`
- zlib: often `78 01/9c/da`
- zip: `50 4b 03 04`
- bzip2: `42 5a 68` (`BZh`)
- xz: `fd 37 7a 58 5a 00`
- zstd: `28 b5 2f fd`

### Raw DEFLATE

CyberChef에는 **Raw Deflate/Raw Inflate**가 있습니다, 블롭이 압축된 것처럼 보이는데 `zlib`이 실패할 때 종종 가장 빠른 방법입니다.

### 유용한 CLI
```bash
python3 - <<'PY'
import sys, zlib
data = sys.stdin.buffer.read()
for wbits in [zlib.MAX_WBITS, -zlib.MAX_WBITS]:
try:
print(zlib.decompress(data, wbits=wbits)[:200])
except Exception:
pass
PY
```
## 일반적인 CTF crypto 구성

### 기법

이것들은 현실적인 개발자 실수이거나 잘못 사용된 일반적인 라이브러리 때문에 자주 등장합니다. 목표는 보통 이를 인식하고 알려진 추출 또는 복원 워크플로를 적용하는 것입니다.

### Fernet

일반적인 힌트: 두 개의 Base64 문자열 (token + key).

- Decoder/notes: https://asecuritysite.com/encryption/ferdecode
- In Python: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

여러 shares가 있고 임계값 `t`가 언급되면, 대개 Shamir입니다.

- Online reconstructor (handy for CTFs): http://christian.gen.co/secrets/

### OpenSSL salted formats

CTF에서는 때때로 `openssl enc` 출력(헤더가 종종 `Salted__`로 시작)을 제공합니다.

Bruteforce helpers:

- https://github.com/glv2/bruteforce-salted-openssl
- https://github.com/carlospolop/easy_BFopensslCTF

### 일반 도구 모음

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- featherduster: https://github.com/nccgroup/featherduster
- cryptovenom: https://github.com/lockedbyte/cryptovenom

## 권장 로컬 설정

실전 CTF 스택:

- Python + `pycryptodome` (대칭 primitives 및 빠른 프로토타이핑용)
- SageMath: 모듈러 산술, CRT, 격자, 그리고 RSA/ECC 작업용
- Z3: 제약 기반 챌린지용(crypto가 제약으로 축소될 때)

권장 Python 패키지:
```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```
{{#include ../../banners/hacktricks-training.md}}
