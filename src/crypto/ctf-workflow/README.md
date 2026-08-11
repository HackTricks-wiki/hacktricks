# Crypto CTF 워크플로

{{#include ../../banners/hacktricks-training.md}}

## Triage 체크리스트

1. 가진 것이 무엇인지 식별합니다: encoding인지 encryption인지 hash인지 signature인지 MAC인지 확인합니다.
2. 무엇을 제어할 수 있는지 파악합니다: plaintext/ciphertext, IV/nonce, key, oracle (padding/error/timing), partial leakage.
3. 분류합니다: symmetric (AES/CTR/GCM), public-key (RSA/ECC), hash/MAC (SHA/MD5/HMAC), classical (Vigenere/XOR).
4. 성공 확률이 가장 높은 확인부터 적용합니다: decode layers, known-plaintext XOR, nonce reuse, mode misuse, oracle behavior.
5. 필요한 경우에만 advanced methods로 진행합니다: lattices (LLL/Coppersmith), SMT/Z3, side-channels.

## Online resources & utilities

task가 식별 및 layer peeling인 경우나 가설을 빠르게 확인해야 할 때 유용합니다.

### Hash lookups

- synthetic/public으로 알려진 challenge hash를 검색합니다.
- CrackStation.<sup>[[1]](#references)</sup>
- MD5Decrypt.<sup>[[2]](#references)</sup>
- hashes.org search.<sup>[[3]](#references)</sup>
- OnlineHashCrack.<sup>[[4]](#references)</sup>
- GPUHash.me.<sup>[[5]](#references)</sup>
- Hash Toolkit.<sup>[[6]](#references)</sup>

실제 password hash나 기밀 challenge 자료를 third-party lookup service에 제출하지 마세요. 공개, terms of service 또는 competition rules가 문제가 될 수 있다면 offline wordlist/rule attack을 우선 사용하세요.

### Identification helpers

- CyberChef (Magic, decoding, conversion).<sup>[[7]](#references)</sup>
- dCode (cipher/encoding playground).<sup>[[8]](#references)</sup>
- Boxentriq (substitution solvers).<sup>[[9]](#references)</sup>

### Practice platforms / references

- CryptoHack (hands-on cryptography challenges).<sup>[[10]](#references)</sup>
- Cryptopals (classic modern-cryptography pitfalls).<sup>[[11]](#references)</sup>

### Automated decoding

- Ciphey.<sup>[[12]](#references)</sup>
- python-codext (tries many bases/encodings).<sup>[[13]](#references)</sup>

## Encodings & classical ciphers

### Technique

많은 CTF crypto task는 layered transform입니다: base encoding + simple substitution + compression. 목표는 layer를 식별하고 안전하게 하나씩 제거하는 것입니다.

### Encodings: 여러 base 시도

layered encoding (base64 → base32 → …)이라고 의심되면 다음을 시도합니다:

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

일반적인 특징:

- Base64: `A-Za-z0-9+/=` (padding `=`이 일반적)
- Base32: `A-Z2-7=` (대개 `=` padding이 많음)
- Ascii85/Base85: punctuation이 조밀하며, 때로는 `<~ ~>`로 감싸져 있음

### Substitution / monoalphabetic

- Boxentriq cryptogram solver.<sup>[[9]](#references)</sup>
- quipqiup.<sup>[[14]](#references)</sup>

### Caesar / ROT / Atbash

- Nayuki automatic Caesar-cipher breaker.<sup>[[15]](#references)</sup>
- Rumkin Atbash tool.<sup>[[16]](#references)</sup>

### Vigenère

- dCode Vigenère tool.<sup>[[8]](#references)</sup>
- Guballa Vigenère solver.<sup>[[17]](#references)</sup>

### Bacon cipher

대개 5 bits 또는 5 letters 단위로 나타납니다:
```
00111 01101 01010 00000 ...
AABBB ABBAB ABABA AAAAA ...
```
### Morse
```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```
### 룬

룬은 자주 치환 알파벳으로 사용됩니다. "futhark cipher"를 검색하고 매핑 테이블을 시도해 보세요.

## challenges에서의 압축

### 기법

압축은 추가 레이어로 지속적으로 등장합니다(zlib/deflate/gzip/xz/zstd). 때로는 중첩되어 있기도 합니다. 출력이 거의 파싱되지만 깨진 것처럼 보인다면 압축을 의심하세요.

### 빠른 식별

- `file <blob>`
- magic bytes를 찾습니다:
- gzip: `1f 8b`
- zlib: 일반적으로 `78 01`, `78 5e`, `78 9c`, 또는 `78 da` (두 번째 바이트는 압축 플래그에 따라 달라집니다)
- zip: `50 4b 03 04`
- bzip2: `42 5a 68` (`BZh`)
- xz: `fd 37 7a 58 5a 00`
- zstd: `28 b5 2f fd`

### Raw DEFLATE

CyberChef에는 **Raw Deflate/Raw Inflate**가 있으며, blob이 압축된 것처럼 보이지만 `zlib`가 실패할 때 가장 빠른 방법인 경우가 많습니다.

### 유용한 CLI
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
## 일반적인 CTF crypto 구성 요소

### Technique

이는 현실적인 developer 실수이거나 일반적인 library를 잘못 사용하는 경우이기 때문에 자주 등장합니다. 일반적으로 목표는 이를 인식하고 알려진 extraction 또는 reconstruction workflow를 적용하는 것입니다.

### Fernet

일반적인 hint: 두 개의 Base64 문자열(token + key).

- Decoder/notes: Asecuritysite Fernet decoder.<sup>[[18]](#references)</sup>
- Python에서: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

여러 share가 보이고 threshold `t`가 언급된다면 Shamir일 가능성이 높습니다.

- Online reconstructor (민감하지 않은 CTF share 전용).<sup>[[19]](#references)</sup>

### OpenSSL salted formats

CTF에서는 때때로 `openssl enc` 출력이 제공됩니다(header는 흔히 `Salted__`로 시작합니다).

Bruteforce helpers:

- `bruteforce-salted-openssl`.<sup>[[20]](#references)</sup>
- `easy_BFopensslCTF`.<sup>[[21]](#references)</sup>

### General toolset

- RsaCtfTool.<sup>[[22]](#references)</sup>
- featherduster.<sup>[[23]](#references)</sup>
- cryptovenom.<sup>[[24]](#references)</sup>

## 권장 local setup

실용적인 CTF stack:

- 대칭 primitive와 빠른 prototyping을 위한 Python 및 `pycryptodome`.<sup>[[25]](#references)</sup>
- modular arithmetic, CRT, lattice, RSA/ECC 작업을 위한 SageMath.<sup>[[26]](#references)</sup>
- constraint 기반 challenge를 위한 Z3 (crypto가 constraint로 환원되는 경우).<sup>[[27]](#references)</sup>

권장 Python package:
```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```
## References

- [1] [CrackStation](https://crackstation.net/)
- [2] [MD5Decrypt](https://md5decrypt.net/)
- [3] [hashes.org 검색](https://hashes.org/search.php)
- [4] [OnlineHashCrack](https://www.onlinehashcrack.com/)
- [5] [GPUHash.me](https://gpuhash.me/)
- [6] [Hash Toolkit](https://hashtoolkit.com/reverse-hash)
- [7] [GCHQ CyberChef](https://gchq.github.io/CyberChef/)
- [8] [dCode 도구](https://www.dcode.fr/tools-list)
- [9] [Boxentriq 코드 해독 도구](https://www.boxentriq.com/code-breaking)
- [10] [CryptoHack](https://cryptohack.org/)
- [11] [Cryptopals](https://cryptopals.com/)
- [12] [Ciphey](https://github.com/Ciphey/Ciphey)
- [13] [python-codext](https://github.com/dhondta/python-codext)
- [14] [quipqiup](https://quipqiup.com/)
- [15] [Nayuki - Automatic Caesar cipher breaker](https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript)
- [16] [Rumkin - Atbash cipher](https://rumkin.com/tools/cipher/atbash/)
- [17] [Guballa Vigenère solver](https://www.guballa.de/vigenere-solver)
- [18] [Asecuritysite - Fernet decoder](https://asecuritysite.com/encryption/ferdecode)
- [19] [Shamir secret-sharing reconstructor](https://christian.gen.co/secrets/)
- [20] [bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
- [21] [easy_BFopensslCTF](https://github.com/carlospolop/easy_BFopensslCTF)
- [22] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [23] [featherduster](https://github.com/nccgroup/featherduster)
- [24] [cryptovenom](https://github.com/lockedbyte/cryptovenom)
- [25] [PyCryptodome documentation](https://pycryptodome.readthedocs.io/en/latest/)
- [26] [SageMath](https://www.sagemath.org/)
- [27] [Z3](https://github.com/Z3Prover/z3)
{{#include ../../banners/hacktricks-training.md}}
