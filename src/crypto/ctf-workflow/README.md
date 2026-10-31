# Crypto CTF 워크플로

{{#include ../../banners/hacktricks-training.md}}

## 초기 분석 체크리스트

1. 가진 데이터가 무엇인지 식별합니다: 인코딩, 암호화, 해시, 서명, MAC 중 무엇인지 확인합니다.
2. 제어 가능한 요소를 파악합니다: 평문/암호문, IV/nonce, 키, 오라클(패딩/오류/타이밍), 부분적인 leak.
3. 분류합니다: 대칭키(AES/CTR/GCM), 공개키(RSA/ECC), 해시/MAC(SHA/MD5/HMAC), 고전 암호(Vigenere/XOR).
4. 가능성이 가장 높은 검사부터 수행합니다: 인코딩 계층 디코딩, known-plaintext XOR, nonce 재사용, 모드 오용, 오라클 동작.
5. 필요한 경우에만 고급 기법으로 넘어갑니다: 격자(LLL/Coppersmith), SMT/Z3, side-channel.

## 온라인 리소스 및 유틸리티

과제가 식별 및 계층 분해에 관한 것이거나, 가설을 빠르게 확인해야 할 때 유용합니다.

### 해시 조회

- 합성 데이터이거나 공개된 것으로 알려진 챌린지 해시를 검색합니다.
- CrackStation.<sup>[[1]](#references)</sup>
- MD5Decrypt.<sup>[[2]](#references)</sup>
- hashes.org 검색.<sup>[[3]](#references)</sup>
- OnlineHashCrack.<sup>[[4]](#references)</sup>
- GPUHash.me.<sup>[[5]](#references)</sup>
- Hash Toolkit.<sup>[[6]](#references)</sup>

실제 비밀번호 해시나 기밀 챌린지 자료를 타사 조회 서비스에 제출하지 마세요. 공개 여부, 서비스 이용 약관 또는 대회 규정이 우려된다면 오프라인 wordlist/rule 공격을 우선 사용하세요.

### 식별 도구

- CyberChef (Magic, 디코딩 및 변환).<sup>[[7]](#references)</sup>
- dCode (암호/인코딩 실험 도구).<sup>[[8]](#references)</sup>
- Boxentriq (치환 암호 풀이 도구).<sup>[[9]](#references)</sup>

### 연습 플랫폼 및 참고 자료

- CryptoHack (실습 중심 암호학 챌린지).<sup>[[10]](#references)</sup>
- Cryptopals (현대 암호학의 고전적인 함정).<sup>[[11]](#references)</sup>

### 자동 디코딩

- Ciphey.<sup>[[12]](#references)</sup>
- python-codext (다양한 base/인코딩 시도).<sup>[[13]](#references)</sup>

## 인코딩 및 고전 암호

### 기법

많은 CTF 암호 과제는 여러 변환을 겹쳐 적용합니다: base 인코딩 + 단순 치환 + 압축. 목표는 각 계층을 식별하고 안전하게 벗겨내는 것입니다.

### 인코딩: 다양한 base 시도

계층형 인코딩(base64 → base32 → …)이 의심되면 다음을 시도합니다.

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

흔한 특징:

- Base64: `A-Za-z0-9+/=` (패딩 `=`이 흔함)
- Base32: `A-Z2-7=` (패딩 `=`이 많은 경우가 흔함)
- Ascii85/Base85: 구두점이 촘촘히 들어가며, 때로는 `<~ ~>`로 둘러싸임

### 치환 암호 / 단일 알파벳 치환

- Boxentriq 암호문 풀이 도구.<sup>[[9]](#references)</sup>
- quipqiup.<sup>[[14]](#references)</sup>

#### 치환된 Base32 파일명의 known-plaintext 복구

난독화된 파일명이 `a-z2-7`만 사용하고, 고정된 접미사를 제거한 뒤 대략 `ceil(8 * byte_length / 5)`개의 문자로 확장되며, 같은 평문이 파일마다 같은 출력을 만든다면 **패딩 없는 Base32 인코딩 뒤에 고정된 기호 치환을 적용했는지** 확인해 보세요. 이러한 단서만으로는 확정할 수 없습니다. 예측 가능한 파일명과 그 암호문을 모으고, 대소문자를 보존한 채 각 평문을 Base32로 인코딩한 다음 문자를 위치별로 정렬합니다. 반복되는 평문 기호는 모두 같은 암호문 기호에 대응해야 하며, 역방향 매핑도 유일해야 합니다. 한 랜섬웨어 사례에서는 `ntuser.ini`와 `NTUSER.DAT`가 이러한 쌍을 제공했습니다. 이를 통해 복구한 것은 파일명이지, **파일 내용이나 암호화 키가 아닙니다**.<sup>[[28]](#references)</sup>

```python
import base64
pairs = [("ntuser.ini", "zsub5mdlekr37dx4"), ("NTUSER.DAT", "4s5l5tul5kr6kv5t")]
forward, inverse = {}, {}
for name, ciphertext in pairs:
    b32 = base64.b32encode(name.encode("ascii")).decode().lower().rstrip("=")
    assert len(b32) == len(ciphertext)
    for p, c in zip(b32, ciphertext):
        assert forward.get(p, c) == c and inverse.get(c, p) == p
        forward[p], inverse[c] = c, p
target = "4s5l5tul5kr6kv5t"  # Remove the fixed suffix first
b32 = "".join(inverse[c] for c in target)
clear = base64.b32decode(b32.upper() + "=" * (-len(b32) % 8))
assert "".join(forward[c] for c in b32) == target
print(clear.decode("ascii"))
```

대상에 매핑되지 않은 기호가 있으면 알려진 쌍을 더 확보하거나 사용되지 않은 Base32 기호 매핑만 순열하세요. 패딩을 8자 경계에 맞게 복원하고, 잘못된 Base32와 출력 불가능한 디코딩 이름은 거부한 다음, 남은 후보를 다시 인코딩해 원본 암호문 전체와 비교하세요. 반복되는 암호문 블록에서 추가 추측을 얻을 수 있습니다. 위 사례에서는 `3gpng2wv`를 Base32 `gaydambq`로 역매핑했으며, 이는 ASCII 숫자 0 다섯 개로 디코딩됩니다. 출력 가능한 후보만으로는 유일한 해답임을 증명할 수 없습니다.<sup>[[28]](#references)</sup>

### Caesar / ROT / Atbash

- Nayuki 자동 Caesar 암호 해독기.<sup>[[15]](#references)</sup>
- Rumkin Atbash 도구.<sup>[[16]](#references)</sup>

### Vigenère

- dCode Vigenère 도구.<sup>[[8]](#references)</sup>
- Guballa Vigenère 솔버.<sup>[[17]](#references)</sup>

### Bacon cipher

5비트 또는 5개 문자의 그룹으로 자주 나타납니다:

```
00111 01101 01010 00000 ...
AABBB ABBAB ABABA AAAAA ...
```

### 모스 부호

```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```

### Runes

Runes는 자주 치환 알파벳으로 사용됩니다. "futhark cipher"를 검색하고 매핑 테이블을 시도해 보세요.

## Challenges에서의 압축

### Technique

압축은 추가 계층(zlib/deflate/gzip/xz/zstd)으로 계속 등장하며, 때로는 중첩되어 있습니다. 출력이 거의 파싱될 것 같지만 깨진 데이터처럼 보인다면 압축을 의심하세요.

### 빠른 식별

- `file <blob>`
- 매직 바이트 확인:
  - gzip: `1f 8b`
  - zlib: 일반적으로 `78 01`, `78 5e`, `78 9c`, 또는 `78 da` (두 번째 바이트는 압축 플래그에 따라 다름)
  - zip: `50 4b 03 04`
  - bzip2: `42 5a 68` (`BZh`)
  - xz: `fd 37 7a 58 5a 00`
  - zstd: `28 b5 2f fd`

### Raw DEFLATE

CyberChef에는 **Raw Deflate/Raw Inflate**가 있으며, blob이 압축된 것처럼 보이지만 `zlib`이 실패할 때 가장 빠른 방법인 경우가 많습니다.

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

현실적인 개발자 실수나 잘못 사용된 일반 라이브러리와 관련이 있어 자주 등장합니다. 보통은 이를 알아보고, 이미 알려진 추출 또는 재구성 절차를 적용하는 것이 목표입니다.

### Fernet

일반적인 힌트: Base64 문자열 2개(token + key).

- Decoder/notes: Asecuritysite Fernet decoder.<sup>[[18]](#references)</sup>
- Python에서: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

여러 개의 share가 있고 threshold `t`가 언급된다면 Shamir일 가능성이 높습니다.

- Online reconstructor (민감하지 않은 CTF share에만 사용).<sup>[[19]](#references)</sup>

### OpenSSL salted 형식

CTF에서 `openssl enc` 출력이 주어지는 경우가 있습니다(헤더는 보통 `Salted__`로 시작합니다).

Bruteforce 도구:

- `bruteforce-salted-openssl`.<sup>[[20]](#references)</sup>
- `easy_BFopensslCTF`.<sup>[[21]](#references)</sup>

### 일반 도구 모음

- RsaCtfTool.<sup>[[22]](#references)</sup>
- featherduster.<sup>[[23]](#references)</sup>
- cryptovenom.<sup>[[24]](#references)</sup>

## 권장 로컬 환경

실용적인 CTF 도구 구성:

- 대칭 암호 기본 연산과 빠른 프로토타이핑을 위한 Python 및 `pycryptodome`.<sup>[[25]](#references)</sup>
- 모듈러 연산, CRT, 격자, RSA/ECC 작업을 위한 SageMath.<sup>[[26]](#references)</sup>
- 제약 조건 기반 문제용 Z3(암호 문제가 제약 조건으로 표현되는 경우).<sup>[[27]](#references)</sup>

권장 Python 패키지:

```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```

{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [CrackStation](https://crackstation.net/)
- [2] [MD5Decrypt](https://md5decrypt.net/)
- [3] [hashes.org 검색](https://hashes.org/search.php)
- [4] [OnlineHashCrack](https://www.onlinehashcrack.com/)
- [5] [GPUHash.me](https://gpuhash.me/)
- [6] [해시 툴킷](https://hashtoolkit.com/reverse-hash)
- [7] [GCHQ CyberChef](https://gchq.github.io/CyberChef/)
- [8] [dCode 도구](https://www.dcode.fr/tools-list)
- [9] [Boxentriq 코드 해독 도구](https://www.boxentriq.com/code-breaking)
- [10] [CryptoHack](https://cryptohack.org/)
- [11] [Cryptopals](https://cryptopals.com/)
- [12] [Ciphey](https://github.com/Ciphey/Ciphey)
- [13] [python-codext](https://github.com/dhondta/python-codext)
- [14] [quipqiup](https://quipqiup.com/)
- [15] [Nayuki - 자동 Caesar cipher 해독기](https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript)
- [16] [Rumkin - Atbash cipher](https://rumkin.com/tools/cipher/atbash/)
- [17] [Guballa Vigenère solver](https://www.guballa.de/vigenere-solver)
- [18] [Asecuritysite - Fernet 디코더](https://asecuritysite.com/encryption/ferdecode)
- [19] [Shamir 비밀 공유 복원기](https://christian.gen.co/secrets/)
- [20] [bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
- [21] [easy_BFopensslCTF](https://github.com/carlospolop/easy_BFopensslCTF)
- [22] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [23] [featherduster](https://github.com/nccgroup/featherduster)
- [24] [cryptovenom](https://github.com/lockedbyte/cryptovenom)
- [25] [PyCryptodome 문서](https://pycryptodome.readthedocs.io/en/latest/)
- [26] [SageMath](https://www.sagemath.org/)
- [27] [Z3](https://github.com/Z3Prover/z3)
- [28] [Eye Research – 암호화 방식을 손쉽게 깨는 방법](https://labs.eye.security/breaking-encryption-schemes-the-lazy-way/)
