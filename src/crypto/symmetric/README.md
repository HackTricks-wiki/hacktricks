# 대칭 암호

{{#include ../../banners/hacktricks-training.md}}

## CTF에서 확인할 사항

- **모드 오용**: ECB 패턴, CBC malleability, CTR/GCM nonce 재사용.
- **Padding oracle**: 잘못된 padding에 대해 서로 다른 오류나 처리 시간이 나타나는지 확인합니다.
- **MAC 혼동**: 가변 길이 메시지에 CBC-MAC을 사용하거나 MAC-then-encrypt를 잘못 사용하는 경우입니다.
- **어디서나 XOR**: stream cipher와 사용자 지정 구성은 keystream과의 XOR 연산으로 환원되는 경우가 많습니다.

## AES 모드 및 오용

NIST는 SP 800-38A에서 ECB, CBC, CTR 기밀성 모드를, SP 800-38D에서 GCM 인증 암호화를 지정합니다.<sup>[[2]](#references)[[3]](#references)</sup>

### ECB: Electronic Codebook

ECB는 패턴을 leak합니다. 평문 블록이 같으면 암호문 블록도 같습니다. 이를 이용하면 다음이 가능합니다.

- 잘라 붙이기 / 블록 재정렬
- 블록 삭제 (형식이 계속 유효한 경우)

평문을 제어하고 암호문(또는 쿠키)을 관찰할 수 있다면, 반복 블록을 만들고(예: `A`를 여러 번 입력) 반복되는 부분이 있는지 확인합니다.

### CBC: Cipher Block Chaining

- CBC는 **malleable**합니다. `C[i-1]`의 비트를 뒤집으면 `P[i]`의 예측 가능한 비트가 뒤집히지만, 동시에 `P[i-1]`도 손상됩니다. IV를 수정하면 앞선 평문 블록을 손상하지 않고 첫 번째 평문 블록을 조작할 수 있습니다.
- 시스템에서 유효한 padding과 잘못된 padding을 구분해 노출한다면 **padding oracle**이 있을 수 있습니다.

### CTR

CTR은 AES를 stream cipher로 바꿉니다: `C = P XOR keystream`.

같은 key로 nonce/IV를 재사용하면 다음이 성립합니다.

- `C1 XOR C2 = P1 XOR P2` (전형적인 keystream 재사용)
- 알려진 평문으로 keystream을 복구해 다른 암호문을 복호화할 수 있습니다.

**Nonce/IV 재사용 악용 패턴**

- 평문을 알고 있거나 추측할 수 있는 부분의 keystream 복구:

  ```text
  keystream[i..] = ciphertext[i..] XOR known_plaintext[i..]
  ```

  복구한 keystream 바이트를 적용해, 같은 key+IV와 동일한 오프셋으로 생성된 다른 ciphertext를 복호화합니다.
- 구조가 매우 정형화된 데이터(예: ASN.1/X.509 인증서, 파일 헤더, JSON/CBOR)에는 알려진 평문 영역이 넓게 존재합니다. 인증서의 ciphertext를 예측 가능한 인증서 본문과 XOR해 keystream을 구한 다음, 재사용된 IV로 암호화된 다른 비밀 정보를 복호화할 수 있는 경우가 많습니다. 일반적인 인증서 레이아웃은 [TLS & Certificates](../tls-and-certificates/README.md)도 참고하세요.<sup>[[1]](#references)</sup>
- **직렬화 형식과 크기가 동일한** 여러 비밀 정보가 같은 key+IV로 암호화되면, 완전한 평문을 몰라도 필드 정렬 정보가 노출됩니다. 예를 들어, 같은 modulus 크기의 PKCS#8 RSA 키는 소인수가 거의 같은 오프셋에 놓입니다(2048-bit의 경우 정렬률 약 99.6%). 재사용된 keystream으로 두 ciphertext를 XOR하면 `p ⊕ p'` / `q ⊕ q'`가 분리되며, 이를 몇 초 만에 brute-force로 복구할 수 있습니다.<sup>[[1]](#references)</sup>
- 라이브러리의 기본 IV(예: 상수 `000...01`)는 치명적인 함정입니다. 암호화할 때마다 같은 keystream이 재사용되어 CTR이 재사용된 one-time pad로 바뀝니다.<sup>[[1]](#references)</sup>

**CTR 변조 가능성**

- CTR은 기밀성만 제공합니다. ciphertext의 비트를 뒤집으면 평문의 같은 비트가 결정적으로 뒤집힙니다. 인증 태그가 없으면 공격자는 데이터(예: 키, 플래그, 메시지)를 변조해도 탐지되지 않을 수 있습니다.
- 비트 플립을 탐지할 수 있도록 AEAD(GCM, GCM-SIV, ChaCha20-Poly1305 등)를 사용하고 태그 검증을 적용하세요.

### GCM

GCM도 nonce를 재사용하면 심각하게 취약해집니다. 같은 key+nonce를 두 번 이상 사용하면 일반적으로 다음 문제가 발생합니다.

- 암호화에 keystream이 재사용됩니다(CTR과 동일). 평문을 알고 있는 경우 평문 복구가 가능합니다.
- 무결성 보장이 무너집니다. 동일한 nonce로 생성된 여러 메시지/태그 쌍 등 노출된 정보에 따라 공격자는 태그를 위조할 수 있습니다.

운영 지침:

- AEAD에서의 "nonce 재사용"은 치명적인 취약점으로 취급하세요.
- AES-GCM-SIV와 같은 오용 방지 AEAD는 nonce 재사용으로 인한 피해를 줄입니다. 호출자는 구성 방식의 인터페이스에서 요구하는 고유 nonce를 여전히 제공해야 합니다. 다만 실수로 nonce를 재사용해도 일반 GCM보다 피해가 제한됩니다.<sup>[[3]](#references)[[4]](#references)</sup>
- 같은 nonce로 생성된 ciphertext가 여러 개 있다면, 먼저 `C1 XOR C2 = P1 XOR P2`와 같은 관계가 성립하는지 확인하세요.

### 도구

- 빠른 실험에는 [CyberChef](https://gchq.github.io/CyberChef/)를 사용합니다.<sup>[[8]](#references)</sup>
- 스크립트 작성에는 Python의 [PyCryptodome](https://www.pycryptodome.org/) 패키지를 사용합니다.<sup>[[9]](#references)</sup>

## ECB 악용 패턴

ECB (Electronic Code Book)는 각 블록을 독립적으로 암호화합니다.

- 동일한 평문 블록 → 동일한 ciphertext 블록
- 이로 인해 구조가 노출되고 cut-and-paste 방식의 공격이 가능해집니다.

![ECB mode decryption block diagram](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### 탐지 아이디어: token/cookie 패턴

여러 번 로그인해도 **항상 같은 cookie를 받는다면**, ciphertext가 결정론적일 수 있습니다(ECB 또는 고정 IV).

평문 레이아웃이 대부분 동일한 사용자 두 명(예: 긴 반복 문자)을 만들고, 같은 오프셋에서 반복되는 ciphertext 블록이 보인다면 ECB를 우선 의심하세요.

### 악용 패턴

#### 블록 전체 제거

token 형식이 `<username>|<password>`와 같고 블록 경계가 맞는 경우, `admin` 블록이 정렬되도록 사용자를 만든 다음 앞쪽 블록을 제거해 `admin`의 유효한 token을 얻을 수 있습니다.

#### 블록 이동

백엔드가 패딩/추가 공백(`admin`과 `admin    `)을 허용한다면 다음을 할 수 있습니다.

- `admin   `을 포함하는 블록을 정렬합니다.
- 해당 ciphertext 블록을 다른 token으로 옮기거나 재사용합니다.

## Padding Oracle

### 개요

CBC 모드에서 서버가 복호화된 평문에 **유효한 PKCS#7 패딩이 있는지** 직접 또는 간접적으로 알려주면, 다음과 같은 작업을 수행할 수 있는 경우가 많습니다.<sup>[[7]](#references)</sup>

- 키 없이 ciphertext를 복호화합니다.
- 조작한 이전 블록이나 IV를 제출할 수 있고 애플리케이션이 유효한 패딩이 있는 메시지를 받아들이는 경우, 선택한 평문으로 복호화되는 ciphertext를 만듭니다.

Oracle은 다음과 같은 형태일 수 있습니다.

- 특정 오류 메시지
- 다른 HTTP 상태 코드 또는 응답 크기
- 타이밍 차이

### 실제 공격

PadBuster는 대표적인 도구입니다.

{{#ref}}
https://github.com/AonCyberLabs/PadBuster
{{#endref}}

예시:

```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 16 \
  -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```

참고:

- 블록 크기는 AES에서 흔히 `16`입니다.
- `-encoding 0`은 Base64를 의미합니다.
- oracle이 특정 문자열을 반환한다면 `-error`를 사용하세요.

### 작동 원리

CBC 복호화는 `P[i] = D(C[i]) XOR C[i-1]`을 계산합니다. `C[i-1]`의 바이트를 수정하고 padding이 유효한지 확인하면 `P[i]`를 바이트 단위로 복구할 수 있습니다.

## CBC의 Bit-flipping

padding oracle이 없어도 CBC는 변조 가능합니다. 암호문 블록을 수정할 수 있고 애플리케이션이 복호화된 평문을 구조화된 데이터(예: `role=user`)로 사용한다면, 다음 블록에서 선택한 위치의 특정 평문 바이트가 바뀌도록 비트를 뒤집을 수 있습니다.

일반적인 CTF 패턴:

- Token = `IV || C1 || C2 || ...`
- `C[i]`의 바이트를 제어할 수 있음
- `P[i+1] = D(C[i+1]) XOR C[i]`이므로 `P[i+1]`의 평문 바이트를 목표로 함

이것만으로 기밀성이 깨지는 것은 아니지만, 무결성이 보장되지 않을 때 권한 상승에 흔히 사용되는 primitive입니다.

## CBC-MAC

CBC-MAC은 특정 조건(특히 **고정 길이 메시지**와 올바른 도메인 분리)을 만족할 때만 안전합니다. AES-CMAC은 가변 길이 입력을 안전하게 처리하는 표준화된 구성입니다.<sup>[[5]](#references)</sup>

### 고전적인 가변 길이 위조 패턴

CBC-MAC은 보통 다음과 같이 계산합니다.

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

선택한 메시지의 tag를 얻을 수 있다면, CBC의 블록 체이닝 방식을 악용해 키를 몰라도 연결된 메시지(또는 관련된 구성)의 tag를 만드는 경우가 많습니다.

이 방식은 CBC-MAC으로 사용자 이름이나 역할에 MAC을 적용하는 CTF 쿠키/token에서 자주 등장합니다.

### 더 안전한 대안

- HMAC (SHA-256/512) 사용
- CMAC (AES-CMAC)을 올바르게 사용
- 메시지 길이 / 도메인 분리 포함

## 스트림 암호: XOR 및 RC4

### 기본 개념

대부분의 스트림 암호 상황은 다음과 같이 나타낼 수 있습니다.

`ciphertext = plaintext XOR keystream`

따라서:

- 평문을 알고 있으면 keystream을 복구할 수 있습니다.
- keystream이 재사용되면(같은 key+nonce) `C1 XOR C2 = P1 XOR P2`입니다.

### XOR 기반 암호화

위치 `i`의 평문 일부를 알고 있으면 keystream 바이트를 복구하고 같은 위치에 있는 다른 암호문을 복호화할 수 있습니다.

자동 풀이 도구:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4는 구식 스트림 암호이며, 암호화와 복호화는 동일한 XOR 연산입니다. 알려진 편향 때문에 새로운 시스템에는 적합하지 않으며, TLS는 RC4 cipher suite를 명시적으로 금지합니다.<sup>[[6]](#references)</sup>

같은 key로 알려진 평문을 RC4 암호화한 결과를 얻을 수 있다면, keystream을 복구해 길이와 오프셋이 같은 다른 메시지를 복호화할 수 있습니다.

참고 writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

## References

- [1] [Trail of Bits – 암호학에서의 부주의와 장인정신](https://blog.trailofbits.com/2026/02/18/carelessness-versus-craftsmanship-in-cryptography/)
- [2] [NIST SP 800-38A - 블록 암호 운용 모드 권고](https://csrc.nist.gov/pubs/sp/800/38/a/final)
- [3] [NIST SP 800-38D - Galois/Counter Mode (GCM) 및 GMAC 권고](https://csrc.nist.gov/pubs/sp/800/38/d/final)
- [4] [RFC 8452 - AES-GCM-SIV: nonce 오용에 강한 인증 암호화](https://www.rfc-editor.org/rfc/rfc8452)
- [5] [RFC 4493 - AES-CMAC 알고리즘](https://www.rfc-editor.org/rfc/rfc4493)
- [6] [RFC 7465 - RC4 Cipher Suite 금지](https://www.rfc-editor.org/rfc/rfc7465)
- [7] [OWASP 웹 보안 테스트 가이드 - Padding Oracle 테스트](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/02-Testing_for_Padding_Oracle)
- [8] [GCHQ CyberChef](https://gchq.github.io/CyberChef/)
- [9] [PyCryptodome 문서](https://www.pycryptodome.org/)
{{#include ../../banners/hacktricks-training.md}}
