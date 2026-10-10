# 암호 CTF 워크플로

{{#include ../../banners/hacktricks-training.md}}

## 초기 분류 체크리스트

1. 가진 것이 무엇인지 파악합니다: 인코딩인지, 암호화인지, hash인지, 서명인지, MAC인지 확인합니다.
2. 제어할 수 있는 항목을 확인합니다: plaintext/ciphertext, IV/nonce, key, oracle (padding/error/timing), 부분적인 leak.
3. 유형을 분류합니다: 대칭키 (AES/CTR/GCM), 공개키 (RSA/ECC), hash/MAC (SHA/MD5/HMAC), 고전 암호 (Vigenere/XOR).
4. 성공 가능성이 높은 점검부터 적용합니다: 인코딩 계층 디코딩, known-plaintext XOR, nonce 재사용, 모드 오용, oracle 동작.
5. 필요한 경우에만 고급 기법을 사용합니다: lattice (LLL/Coppersmith), SMT/Z3, side-channel.

## 온라인 리소스 및 도구

과제가 식별과 계층 분리에 관한 것이거나, 가설을 빠르게 확인해야 할 때 유용합니다.

### Hash 조회

- 인위적으로 생성되었거나 공개된 challenge hash라면 검색합니다.
- CrackStation.<sup>[[1]](#references)</sup>
- MD5Decrypt.<sup>[[2]](#references)</sup>
- hashes.org 검색.<sup>[[3]](#references)</sup>
- OnlineHashCrack.<sup>[[4]](#references)</sup>
- GPUHash.me.<sup>[[5]](#references)</sup>
- Hash Toolkit.<sup>[[6]](#references)</sup>

실제 password hash나 기밀 challenge 자료를 타사 조회 서비스에 제출하지 마세요. 정보 공개, 서비스 이용 약관 또는 대회 규정이 우려된다면 오프라인 wordlist/rule 공격을 우선 사용하세요.

### 식별 도구

- CyberChef (Magic, 디코딩, 변환).<sup>[[7]](#references)</sup>
- dCode (암호/인코딩 플레이그라운드).<sup>[[8]](#references)</sup>
- Boxentriq (치환 암호 해독기).<sup>[[9]](#references)</sup>

### 연습 플랫폼 및 참고 자료

- CryptoHack (실습형 암호학 challenge).<sup>[[10]](#references)</sup>
- Cryptopals (현대 암호학의 고전적인 취약점).<sup>[[11]](#references)</sup>

### 자동 디코딩

- Ciphey.<sup>[[12]](#references)</sup>
- python-codext (다양한 base/인코딩을 시도합니다).<sup>[[13]](#references)</sup>

## 인코딩 및 고전 암호

### 기법

많은 CTF 암호 과제는 여러 변환을 겹쳐 적용합니다. 예를 들면 base 인코딩 + 단순 치환 + 압축입니다. 목표는 계층을 식별하고 안전하게 하나씩 벗겨내는 것입니다.

### 인코딩: 다양한 base 시도

여러 인코딩이 겹쳐 있다고 생각되면 (base64 → base32 → …), 다음을 시도합니다.

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

흔한 특징:

- Base64: `A-Za-z0-9+/=` (패딩 문자 `=`가 흔함)
- Base32: `A-Z2-7=` (패딩 문자 `=`가 많이 붙는 경우가 많음)
- Ascii85/Base85: 문장 부호가 빽빽하게 나타나며, `<~ ~>`로 감싸기도 함

### 치환 / 단일 알파벳 암호

- Boxentriq cryptogram solver.<sup>[[9]](#references)</sup>
- quipqiup.<sup>[[14]](#references)</sup>

### Caesar / ROT / Atbash

- Nayuki 자동 Caesar cipher 해독기.<sup>[[15]](#references)</sup>
- Rumkin Atbash 도구.<sup>[[16]](#references)</sup>

### Vigenère

- dCode Vigenère 도구.<sup>[[8]](#references)</sup>
- Guballa Vigenère 해독기.<sup>[[17]](#references)</sup>

### Bacon cipher

보통 5비트 또는 5글자 단위로 나타납니다:

```
00111 01101 01010 00000 ...
AABBB ABBAB ABABA AAAAA ...
```

### Morse

```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```

### 룬 문자

룬 문자는 대개 치환 알파벳입니다. "futhark cipher"를 검색하고 매핑 테이블을 찾아보세요.

## 챌린지에서의 압축

### 기법

압축은 추가 레이어(zlib/deflate/gzip/xz/zstd)로 자주 등장하며, 때로는 여러 번 중첩되기도 합니다. 출력이 거의 파싱될 것처럼 보이지만 깨진 데이터처럼 보인다면 압축을 의심하세요.

### 빠른 식별

- `file <blob>`
- 매직 바이트 확인:
  - gzip: `1f 8b`
  - zlib: 흔히 `78 01`, `78 5e`, `78 9c` 또는 `78 da` (두 번째 바이트는 압축 플래그에 따라 다름)
  - zip: `50 4b 03 04`
  - bzip2: `42 5a 68` (`BZh`)
  - xz: `fd 37 7a 58 5a 00`
  - zstd: `28 b5 2f fd`

### Raw DEFLATE

CyberChef에는 **Raw Deflate/Raw Inflate**가 있으며, 데이터가 압축된 것처럼 보이지만 `zlib`가 실패할 때 가장 빠른 방법인 경우가 많습니다.

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

## 일반적인 CTF 암호화 구성 요소

### Technique

실제 개발자의 실수이거나 잘못 사용된 일반적인 라이브러리인 경우가 많아 자주 등장합니다. 보통은 이를 알아보고 알려진 추출 또는 재구성 워크플로를 적용하는 것이 목표입니다.

### Fernet

일반적인 힌트: Base64 문자열 두 개(token + key).

- Decoder/notes: Asecuritysite Fernet decoder.<sup>[[18]](#references)</sup>
- Python에서는: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

여러 개의 share가 보이고 임계값 `t`가 언급되면 Shamir일 가능성이 높습니다.

- Online reconstructor (민감하지 않은 CTF shares에만 사용).<sup>[[19]](#references)</sup>

### OpenSSL salted 형식

CTF에서 `openssl enc` 출력을 제공하는 경우가 있습니다(헤더는 대개 `Salted__`로 시작).

Bruteforce 도구:

- `bruteforce-salted-openssl`.<sup>[[20]](#references)</sup>
- `easy_BFopensslCTF`.<sup>[[21]](#references)</sup>

### 일반 도구 모음

- RsaCtfTool.<sup>[[22]](#references)</sup>
- featherduster.<sup>[[23]](#references)</sup>
- cryptovenom.<sup>[[24]](#references)</sup>

## 권장 로컬 환경

실용적인 CTF 도구 구성:

- Python과 `pycryptodome`: 대칭 암호 프리미티브와 빠른 프로토타이핑에 사용합니다.<sup>[[25]](#references)</sup>
- SageMath: 모듈러 산술, CRT, 격자, RSA/ECC 작업에 사용합니다.<sup>[[26]](#references)</sup>
- Z3: 제약 조건 기반 챌린지에 사용합니다(암호 문제가 제약 조건으로 환원되는 경우).<sup>[[27]](#references)</sup>

권장 Python 패키지:

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
- [9] [Boxentriq 암호 해독 도구](https://www.boxentriq.com/code-breaking)
- [10] [CryptoHack](https://cryptohack.org/)
- [11] [Cryptopals](https://cryptopals.com/)
- [12] [Ciphey](https://github.com/Ciphey/Ciphey)
- [13] [python-codext](https://github.com/dhondta/python-codext)
- [14] [quipqiup](https://quipqiup.com/)
- [15] [Nayuki - 자동 Caesar 암호 해독기](https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript)
- [16] [Rumkin - Atbash 암호](https://rumkin.com/tools/cipher/atbash/)
- [17] [Guballa Vigenère 풀이 도구](https://www.guballa.de/vigenere-solver)
- [18] [Asecuritysite - Fernet 디코더](https://asecuritysite.com/encryption/ferdecode)
- [19] [Shamir 비밀 공유 재구성 도구](https://christian.gen.co/secrets/)
- [20] [bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
- [21] [easy_BFopensslCTF](https://github.com/carlospolop/easy_BFopensslCTF)
- [22] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [23] [featherduster](https://github.com/nccgroup/featherduster)
- [24] [cryptovenom](https://github.com/lockedbyte/cryptovenom)
- [25] [PyCryptodome 문서](https://pycryptodome.readthedocs.io/en/latest/)
- [26] [SageMath](https://www.sagemath.org/)
- [27] [Z3](https://github.com/Z3Prover/z3)
{{#include ../../banners/hacktricks-training.md}}
