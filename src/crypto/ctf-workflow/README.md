# Crypto CTF 워크플로

{{#include ../../banners/hacktricks-training.md}}

## Triage 체크리스트

1. 가지고 있는 것이 무엇인지 식별합니다: encoding, encryption, hash, signature 또는 MAC.
2. 무엇을 제어할 수 있는지 확인합니다: plaintext/ciphertext, IV/nonce, key, oracle (padding/error/timing), partial leakage.
3. 분류합니다: symmetric (AES/CTR/GCM), public-key (RSA/ECC), hash/MAC (SHA/MD5/HMAC), classical (Vigenere/XOR).
4. 가능성이 가장 높은 검사부터 적용합니다: decode layers, known-plaintext XOR, nonce reuse, mode misuse, oracle behavior.
5. 필요한 경우에만 advanced methods로 진행합니다: lattices (LLL/Coppersmith), SMT/Z3, side-channels.

## Online resources & utilities

이 항목들은 task가 identification 및 layer peeling인 경우나, 가설을 빠르게 확인해야 할 때 유용합니다.

### Hash lookups

- Google에서 hash를 검색합니다 (놀라울 정도로 효과적입니다).
- [https://crackstation.net/](https://crackstation.net/)
- [https://md5decrypt.net/](https://md5decrypt.net/)
- [https://hashes.org/search.php](https://hashes.org/search.php)
- [https://www.onlinehashcrack.com/](https://www.onlinehashcrack.com/)
- [https://gpuhash.me/](https://gpuhash.me/)
- [http://hashtoolkit.com/reverse-hash](http://hashtoolkit.com/reverse-hash)

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

많은 CTF crypto task는 layered transforms입니다: base encoding + simple substitution + compression. 목표는 layer를 식별하고 안전하게 하나씩 제거하는 것입니다.

### Encodings: try many bases

layered encoding (base64 → base32 → …)이라고 의심되면 다음을 시도합니다:

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

Common tells:

- Base64: `A-Za-z0-9+/=` (padding `=`이 흔함)
- Base32: `A-Z2-7=` (대개 `=` padding이 많음)
- Ascii85/Base85: punctuation이 조밀하게 나타남. 때로는 `<~ ~>`로 감싸짐

### Substitution / monoalphabetic

- Boxentriq cryptogram solver: https://www.boxentriq.com/code-breaking/cryptogram
- quipqiup: https://quipqiup.com/

### Caesar / ROT / Atbash

- Nayuki auto breaker: https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript
- Atbash: http://rumkin.com/tools/cipher/atbash.php

### Vigenère

- [https://www.dcode.fr/vigenere-cipher](https://www.dcode.fr/vigenere-cipher)
- [https://www.guballa.de/vigenere-solver](https://www.guballa.de/vigenere-solver)

### Bacon cipher

대개 5 bits 또는 5 letters 단위의 그룹으로 나타납니다:
```
00111 01101 01010 00000 ...
AABBB ABBAB ABABA AAAAA ...
```
### Morse
```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```
### Runes

Runes는 자주 치환 알파벳으로 사용됩니다. `"futhark cipher"`를 검색하고 매핑 테이블을 시도해 보세요.

## challenges에서의 압축

### 기법

압축은 추가 계층으로 매우 자주 등장합니다(zlib/deflate/gzip/xz/zstd). 때로는 중첩되어 있기도 합니다. 출력이 거의 파싱될 것처럼 보이지만 깨진 데이터처럼 보인다면 압축을 의심하세요.

### 빠른 식별

- `file <blob>`
- 매직 바이트를 확인합니다:
- gzip: `1f 8b`
- zlib: 보통 `78 01/9c/da`
- zip: `50 4b 03 04`
- bzip2: `42 5a 68` (`BZh`)
- xz: `fd 37 7a 58 5a 00`
- zstd: `28 b5 2f fd`

### Raw DEFLATE

CyberChef에는 **Raw Deflate/Raw Inflate**가 있으며, blob이 압축된 것처럼 보이지만 `zlib`가 실패할 때 가장 빠른 방법인 경우가 많습니다.

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

### Technique

이러한 구성은 현실적인 개발자 실수나 흔히 잘못 사용되는 library 때문에 자주 등장합니다. 보통 목표는 이를 식별하고 알려진 추출 또는 재구성 workflow를 적용하는 것입니다.

### Fernet

일반적인 hint: 두 개의 Base64 문자열(token + key).

- Decoder/notes: https://asecuritysite.com/encryption/ferdecode
- Python에서: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

여러 개의 share가 보이고 threshold `t`가 언급된다면, Shamir일 가능성이 높습니다.

- Online reconstructor (CTF에 유용): http://christian.gen.co/secrets/

### OpenSSL salted formats

CTF에서는 `openssl enc` output이 주어지는 경우가 있습니다(header는 대개 `Salted__`로 시작).

Bruteforce helpers:

- [https://github.com/glv2/bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
- [https://github.com/carlospolop/easy_BFopensslCTF](https://github.com/carlospolop/easy_BFopensslCTF)

### 일반적인 toolset

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- featherduster: https://github.com/nccgroup/featherduster
- cryptovenom: https://github.com/lockedbyte/cryptovenom

## 권장 local setup

실용적인 CTF stack:

- 대칭 primitive와 빠른 prototyping을 위한 Python + `pycryptodome`
- modular arithmetic, CRT, lattice 및 RSA/ECC 작업을 위한 SageMath
- constraint 기반 challenge를 위한 Z3 (crypto가 constraint로 축소되는 경우)

권장 Python packages:
```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```
{{#include ../../banners/hacktricks-training.md}}
