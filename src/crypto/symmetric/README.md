# 대칭 암호

{{#include ../../banners/hacktricks-training.md}}

## CTFs에서 찾아볼 것

- **모드 오용**: ECB 패턴, CBC 가변성(malleability), CTR/GCM nonce 재사용.
- **Padding oracles**: 잘못된 패딩에 대해 서로 다른 오류/타이밍을 보이는 경우.
- **MAC confusion**: variable-length 메시지에 대한 CBC-MAC 사용이나 MAC-then-encrypt 실수.
- **XOR everywhere**: 스트림 암호와 커스텀 구성은 종종 keystream과의 XOR으로 환원된다.

## AES 모드와 오용

### ECB: Electronic Codebook

ECB leaks patterns: 같은 평문 블록 → 같은 암호문 블록. 이는 다음을 가능하게 한다:

- Cut-and-paste / block reordering
- 블록 삭제(포맷이 유효한 경우)

평문을 제어하고 암호문(또는 쿠키)을 관찰할 수 있다면 반복 블록(예: 많은 `A`)을 만들어 반복을 찾아보라.

### CBC: Cipher Block Chaining

- CBC는 **malleable**하다: `C[i-1]`의 비트를 뒤집으면 `P[i]`의 예측 가능한 비트가 뒤집힌다.
- 시스템이 유효한 패딩과 무효 패딩을 구분해 노출하면, **padding oracle**이 존재할 수 있다.

### CTR

CTR은 AES를 스트림 암호로 바꾼다: `C = P XOR keystream`.

동일한 키로 nonce/IV가 재사용되면:

- `C1 XOR C2 = P1 XOR P2` (고전적인 keystream 재사용)
- 알려진 평문으로 keystream을 복구해 다른 암호문을 복호화할 수 있다.

**Nonce/IV 재사용 악용 패턴**

- 알려져 있거나 추측 가능한 평문이 있는 위치에서 keystream을 복구하라:

```text
keystream[i..] = ciphertext[i..] XOR known_plaintext[i..]
```

복구한 keystream 바이트를 동일한 key+IV로 생성된 다른 암호문의 동일한 오프셋에 적용해 복호화한다.
- ASN.1/X.509 인증서, 파일 헤더, JSON/CBOR처럼 구조가 잘 정의된 데이터는 큰 known-plaintext 영역을 제공한다. 인증서의 예측 가능한 본문과 인증서 암호문을 XOR해 keystream을 도출한 뒤, 재사용된 IV로 암호화된 다른 비밀을 복호화하는 식이다. See also [TLS & Certificates](../tls-and-certificates/README.md) for typical certificate layouts.
- 동일한 직렬화 포맷/크기의 여러 비밀이 동일한 key+IV로 암호화되면, 전체 평문을 알지 못해도 필드 정렬로 정보가 유출된다. 예: 동일한 모듈러스 크기를 가진 PKCS#8 RSA 키는 소수들이 거의 같은 오프셋에 놓인다(~2048-bit에서 약 99.6% 정렬). 재사용된 keystream으로 두 암호문을 XOR하면 `p ⊕ p'` / `q ⊕ q'`가 분리되어 몇 초 내에 브루트포스로 복구할 수 있다.
- 라이브러리의 기본 IV(예: 상수 `000...01`)는 치명적인 함정이다: 모든 암호화가 같은 keystream을 반복해 CTR을 재사용된 one-time pad로 만든다.

**CTR 가변성(malleability)**

- CTR은 기밀성만 제공: 암호문의 비트를 뒤집으면 평문의 같은 비트가 결정론적으로 뒤집힌다. 인증 태그가 없으면 공격자가 데이터(예: 키, 플래그, 메시지)를 눈치채지 못한 채 변조할 수 있다.
- 비트플립을 탐지하려면 AEAD(GCM, GCM-SIV, ChaCha20-Poly1305 등)를 사용하고 태그 검증을 강제하라.

### GCM

GCM도 nonce 재사용에서 심각하게 깨진다. 동일한 key+nonce가 여러 번 사용되면 일반적으로:

- 암호화에 대해 keystream 재사용 발생(CTR과 동일), 어떤 평문이라도 알려져 있으면 복호화 가능.
- 무결성 보장 상실. 노출되는 것이 무엇인지(동일 nonce 아래의 여러 message/tag 쌍 등)에 따라 공격자가 태그를 위조할 수 있다.

운영 지침:

- AEAD에서 "nonce 재사용"은 치명적 취약점으로 취급하라.
- misuse-resistant AEAD(e.g., GCM-SIV)는 nonce 오용의 피해를 줄이지만 여전히 고유한 nonce/IV가 필요하다.
- 동일 nonce 아래의 여러 암호문이 있다면 `C1 XOR C2 = P1 XOR P2` 형태의 관계를 먼저 확인하라.

### 도구

- CyberChef for quick experiments: https://gchq.github.io/CyberChef/
- Python: `pycryptodome` for scripting

## ECB 악용 패턴

ECB(Electronic Code Book)는 각 블록을 독립적으로 암호화한다:

- 같은 평문 블록 → 같은 암호문 블록
- 이는 구조를 노출하고 cut-and-paste 스타일 공격을 가능하게 한다

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### 탐지 아이디어: token/cookie 패턴

여러 번 로그인했을 때 **항상 같은 cookie를 받는다면**, 암호문이 결정론적일 수 있다(ECB 또는 고정 IV).

대부분 동일한 평문 레이아웃(예: 긴 반복 문자)을 가진 두 사용자를 만들어 동일한 오프셋에서 반복되는 암호문 블록이 보이면 ECB가 유력하다.

### 악용 패턴

#### Removing entire blocks

토큰 포맷이 `<username>|<password>` 같고 블록 경계가 정렬되면, `admin` 블록이 정렬되도록 사용자를 만들고 앞의 블록들을 제거해 유효한 `admin` 토큰을 얻을 수 있다.

#### Moving blocks

백엔드가 패딩/여분 공백(`admin` vs `admin    `)을 허용하면:

- `admin   `을 포함한 블록을 정렬한다
- 그 암호문 블록을 다른 토큰에 교체/재사용한다

## Padding Oracle

### What it is

CBC 모드에서 서버가 복호화된 평문에 대해 **PKCS#7 padding**이 유효한지 여부를 (직접적이거나 간접적으로) 노출하면, 종종 다음을 할 수 있다:

- 키 없이도 암호문을 복호화
- 선택 평문 암호화(암호문 위조)

오라클은 다음과 같을 수 있다:

- 특정 오류 메시지
- 다른 HTTP 상태 / 응답 크기
- 타이밍 차이

### 실전 악용

PadBuster is the classic tool:

{{#ref}}
https://github.com/AonCyberLabs/PadBuster
{{#endref}}

Example:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 16 \
-encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
Notes:

- 블록 크기는 종종 `16` (AES)이다.
- `-encoding 0`는 Base64를 의미한다.
- oracle이 특정 문자열일 경우 `-error`를 사용하라.

### 동작 원리

CBC 복호화는 `P[i] = D(C[i]) XOR C[i-1]`를 계산한다. `C[i-1]`의 바이트를 수정하고 padding이 유효한지 관찰함으로써 `P[i]`를 바이트 단위로 복구할 수 있다.

## Bit-flipping in CBC

Even without a padding oracle, CBC is malleable. If you can modify ciphertext blocks and the application uses the decrypted plaintext as structured data (e.g., `role=user`), you can flip specific bits to change selected plaintext bytes at a chosen position in the next block.

Typical CTF pattern:

- Token = `IV || C1 || C2 || ...`
- You control bytes in `C[i]`
- You target plaintext bytes in `P[i+1]` because `P[i+1] = D(C[i+1]) XOR C[i]`

This is not a break of confidentiality by itself, but it is a common privilege-escalation primitive when integrity is missing.

## CBC-MAC

CBC-MAC은 특정 조건(특히 **고정 길이 메시지** 및 올바른 도메인 분리)이 있을 때만 안전하다.

### Classic variable-length forgery pattern

CBC-MAC은 보통 다음과 같이 계산된다:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

선택한 메시지에 대한 태그를 얻을 수 있다면, CBC가 블록을 체인하는 방식을 악용하여 키를 알지 못해도 종종 이어붙인 메시지(또는 관련 구성)에 대한 태그를 만들 수 있다.

이는 종종 username이나 role을 CBC-MAC으로 MAC하는 CTF의 쿠키/토큰에서 자주 나타난다.

### Safer alternatives

- HMAC (SHA-256/512)를 사용하라
- CMAC (AES-CMAC)를 올바르게 사용하라
- 메시지 길이 및 도메인 분리 포함

## Stream ciphers: XOR and RC4

### The mental model

대부분의 스트림 암호 상황은 다음으로 환원된다:

`ciphertext = plaintext XOR keystream`

즉:

- 평문을 알면 keystream을 복구할 수 있다.
- keystream이 재사용되면 (same key+nonce), `C1 XOR C2 = P1 XOR P2`.

### XOR-based encryption

위치 `i`에서 평문의 일부를 알고 있다면, 해당 위치의 keystream 바이트를 복구하여 다른 암호문을 복호화할 수 있다.

Autosolvers:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4는 스트림 암호이며, 암호화와 복호화가 동일한 연산이다.

같은 키로 알려진 평문에 대한 RC4 암호문을 얻을 수 있다면, keystream을 복구하여 동일한 길이/오프셋의 다른 메시지를 복호화할 수 있다.

Reference writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

## References

- [Trail of Bits – Carelessness versus craftsmanship in cryptography](https://blog.trailofbits.com/2026/02/18/carelessness-versus-craftsmanship-in-cryptography/)

{{#include ../../banners/hacktricks-training.md}}
