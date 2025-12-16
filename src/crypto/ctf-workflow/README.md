# Crypto CTF Workflow

{{#include ../../banners/hacktricks-training.md}}

## Triage checklist

1. 어떤 것이 있는지 파악: 인코딩 vs 암호화 vs 해시 vs 서명 vs MAC.
2. 어떤 항목이 제어되는지 판단: plaintext/ciphertext, IV/nonce, key, oracle (padding/error/timing), partial leakage.
3. 분류: symmetric (AES/CTR/GCM), public-key (RSA/ECC), hash/MAC (SHA/MD5/HMAC), classical (Vigenere/XOR).
4. 가능성이 높은 검사부터 먼저 적용: decode layers, known-plaintext XOR, nonce reuse, mode misuse, oracle behavior.
5. 필요한 경우에만 고급 기법으로 확대: lattices (LLL/Coppersmith), SMT/Z3, side-channels.

## Online resources & utilities

이 리소스들은 식별 및 레이어 벗기기(layer peeling)를 하거나 가설을 빠르게 검증할 때 유용하다.

### Hash lookups

- 해시를 Google에 검색해 보라 (의외로 효과적임).
- [https://crackstation.net/](https://crackstation.net/)
- [https://md5decrypt.net/](https://md5decrypt.net/)
- [https://hashes.org/search.php](https://hashes.org/search.php)
- [https://www.onlinehashcrack.com/](https://www.onlinehashcrack.com/)
- [https://gpuhash.me/](https://gpuhash.me/)
- [http://hashtoolkit.com/reverse-hash](http://hashtoolkit.com/reverse-hash)

### Identification helpers

- CyberChef (Magic, decode, convert): https://gchq.github.io/CyberChef/
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

많은 CTF crypto 문제는 base encoding + simple substitution + compression 같은 레이어형 변환이다. 목표는 레이어를 식별하고 안전하게 벗기는 것이다.

### Encodings: try many bases

레이어 인코딩이 의심되면 (base64 → base32 → …) 다음을 시도하라:

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

Common tells:

- Base64: `A-Za-z0-9+/=` (패딩 `=`가 흔함)
- Base32: `A-Z2-7=` (종종 많은 `=` 패딩)
- Ascii85/Base85: 구두점이 빽빽함; 때때로 `<~ ~>`로 감싸짐

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

종종 5비트 또는 5글자 그룹으로 나타난다:
```
00111 01101 01010 00000 ...
AABBB ABBAB ABABA AAAAA ...
```
### Morse
```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```
### Runes

Runes는 자주 치환 알파벳입니다; "futhark cipher"를 검색하고 매핑 테이블을 시도해보세요.

## 챌린지에서의 압축

### Technique

압축은 추가 레이어로 자주 등장합니다 (zlib/deflate/gzip/xz/zstd), 때로는 중첩되기도 합니다. 출력이 거의 파싱되지만 엉망으로 보인다면 압축을 의심하세요.

### Quick identification

- `file <blob>`
- 매직 바이트를 찾아보세요:
- gzip: `1f 8b`
- zlib: often `78 01/9c/da`
- zip: `50 4b 03 04`
- bzip2: `42 5a 68` (`BZh`)
- xz: `fd 37 7a 58 5a 00`
- zstd: `28 b5 2f fd`

### Raw DEFLATE

CyberChef has **Raw Deflate/Raw Inflate**, which is often the fastest path when the blob looks compressed but `zlib` fails.

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

이것들은 현실적인 개발자 실수이거나 잘못 사용된 일반적인 라이브러리이기 때문에 자주 등장합니다. 목표는 보통 이를 식별하고 알려진 추출 또는 재구성 워크플로우를 적용하는 것입니다.

### Fernet

일반적인 힌트: 두 개의 Base64 문자열 (token + key).

- Decoder/notes: https://asecuritysite.com/encryption/ferdecode
- In Python: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

여러 shares가 보이고 임계값 `t`가 언급되어 있다면, 이는 Shamir일 가능성이 높습니다.

- Online reconstructor (handy for CTFs): http://christian.gen.co/secrets/

### OpenSSL salted formats

CTF에서는 때때로 `openssl enc` 출력(헤더가 종종 `Salted__`로 시작)을 제공합니다.

Bruteforce helpers:

- [https://github.com/glv2/bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
- [https://github.com/carlospolop/easy_BFopensslCTF](https://github.com/carlospolop/easy_BFopensslCTF)

### 일반 도구 모음

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- featherduster: https://github.com/nccgroup/featherduster
- cryptovenom: https://github.com/lockedbyte/cryptovenom

## 권장 로컬 설정

실용적인 CTF 스택:

- Python + `pycryptodome` for symmetric primitives and fast prototyping
- SageMath for modular arithmetic, CRT, lattices, and RSA/ECC work
- Z3 for constraint-based challenges (when the crypto reduces to constraints)

권장 Python 패키지:
```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```
{{#include ../../banners/hacktricks-training.md}}
