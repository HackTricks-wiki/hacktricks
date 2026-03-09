# 대칭 암호

{{#include ../../banners/hacktricks-training.md}}

## CTFs에서 확인할 것

- **Mode misuse**: ECB patterns, CBC malleability, CTR/GCM nonce reuse.
- **Padding oracles**: 잘못된 padding에 대해 서로 다른 에러/타이밍이 발생하는지 확인.
- **MAC confusion**: CBC-MAC를 가변 길이 메시지와 함께 사용하거나 MAC-then-encrypt 실수.
- **XOR everywhere**: 스트림 암호와 커스텀 구성은 종종 keystream과의 XOR로 환원된다.

## AES 모드와 오용

### ECB: Electronic Codebook

ECB leaks patterns: equal plaintext blocks → equal ciphertext blocks. That enables:

- Cut-and-paste / block reordering
- Block deletion (if the format remains valid)

만약 plaintext를 제어하고 ciphertext(또는 cookies)를 관찰할 수 있다면, 반복 블록(예: 많은 `A`s)을 만들어 반복을 찾아보라.

### CBC: Cipher Block Chaining

- CBC는 **malleable**: `C[i-1]`의 비트를 뒤집으면 `P[i]`의 예측 가능한 비트가 뒤집힌다.
- 시스템이 유효한 padding과 유효하지 않은 padding을 구분해서 노출하면, **padding oracle**이 존재할 수 있다.

### CTR

CTR는 AES를 스트림 암호로 바꾼다: `C = P XOR keystream`.

동일한 키로 nonce/IV가 재사용되면:

- `C1 XOR C2 = P1 XOR P2` (classic keystream reuse)
- known plaintext가 있으면 keystream을 복구해 다른 것들을 복호화할 수 있다.

**Nonce/IV reuse exploitation patterns**

- plaintext가 알려져 있거나 추측 가능한 곳에서 keystream을 복구:

```text
keystream[i..] = ciphertext[i..] XOR known_plaintext[i..]
```

복구한 keystream 바이트를 동일한 key+IV로 같은 오프셋에서 생성된 다른 ciphertext를 복호화하는 데 적용한다.
- Highly structured data(예: ASN.1/X.509 certificates, file headers, JSON/CBOR)는 큰 known-plaintext 영역을 제공한다. 종종 certificate의 예측 가능한 본문과 certificate의 ciphertext를 XOR하여 keystream을 도출하고, 동일한 IV로 암호화된 다른 비밀들을 복호화할 수 있다. 전형적인 certificate 레이아웃은 [TLS & Certificates](../tls-and-certificates/README.md)를 참조하라.
- 동일한 직렬화 형식/크기의 여러 비밀이 동일한 key+IV로 암호화되면, 필드 정렬(field alignment)이 전체 known plaintext 없이도 leak된다. 예: 동일한 modulus 크기를 가진 PKCS#8 RSA 키는 소수 인자가 대략 동일한 오프셋에 놓인다(~2048-bit의 경우 약 99.6% 정렬). 재사용된 keystream 하에서 두 ciphertext를 XOR하면 `p ⊕ p'` / `q ⊕ q'`가 분리되어 몇 초 안에 브루트포스로 복구할 수 있다.
- 라이브러리의 기본 IV(예: 상수 `000...01`)는 치명적 실수다: 모든 암호화에서 동일한 keystream이 반복되어 CTR을 재사용된 one-time pad로 만든다.

**CTR malleability**

- CTR은 기밀성만 제공한다: ciphertext의 비트를 뒤집으면 plaintext의 동일한 비트가 결정론적으로 뒤집힌다. 인증 태그가 없으면 공격자는 데이터(예: 키, 플래그, 메시지)를 탐지되지 않은 상태로 변조할 수 있다.
- AEAD(GCM, GCM-SIV, ChaCha20-Poly1305 등)를 사용하고 태그 검증을 강제하라.

### GCM

GCM도 nonce 재사용 시 심각하게 손상된다. 동일한 key+nonce가 여러 번 사용되면 일반적으로 다음이 발생한다:

- 암호화에서의 keystream 재사용(CTR과 유사), 알려진 plaintext가 있으면 plaintext 복구 가능.
- 무결성 보장 상실. 노출되는 정보(동일 nonce 하의 여러 message/tag 쌍)에 따라 공격자가 태그를 위조할 수 있다.

운영 지침:

- AEAD에서 "nonce reuse"는 치명적 취약점으로 다뤄라.
- GCM-SIV와 같은 misuse-resistant AEAD는 nonce 오용의 파급을 줄이지만 여전히 고유한 nonce/IV가 필요하다.
- 동일한 nonce로 여러 ciphertext가 있으면 `C1 XOR C2 = P1 XOR P2` 형태의 관계를 먼저 확인하라.

### Tools

- CyberChef for quick experiments: https://gchq.github.io/CyberChef/
- Python: `pycryptodome` for scripting

## ECB 악용 패턴

ECB (Electronic Code Book)는 각 블록을 독립적으로 암호화한다:

- equal plaintext blocks → equal ciphertext blocks
- this leaks structure and enables cut-and-paste style attacks

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Detection idea: token/cookie pattern

여러 번 로그인했는데 **항상 동일한 cookie**를 받는다면, ciphertext가 결정론적일 수 있다(ECB 또는 고정 IV).

대부분 레이아웃이 동일한 두 사용자를 만들고(예: 길게 반복되는 문자) 동일한 오프셋에서 반복되는 ciphertext 블록을 보면 ECB가 유력한 후보다.

### Exploitation patterns

#### Removing entire blocks

토큰 형식이 `<username>|<password>` 같고 블록 경계가 맞으면, `admin` 블록이 정렬되도록 사용자 입력을 만들고 앞의 블록을 제거해 `admin`에 대한 유효한 토큰을 얻을 수 있다.

#### Moving blocks

백엔드가 padding/여분의 공백(`admin` vs `admin    `)을 허용하면:

- `admin   `을 포함한 블록을 정렬
- 해당 ciphertext 블록을 다른 토큰에 교체/재사용

## Padding Oracle

### 무엇인지

CBC 모드에서 서버가 복호화된 평문에 대해 **유효한 PKCS#7 padding**인지 여부를(직간접적으로) 노출하면, 종종:

- 키 없이 ciphertext를 복호화 가능
- 선택한 평문을 암호화(위조 ciphertext 생성) 가능

오라클은 다음과 같을 수 있다:

- 특정 에러 메시지
- 다른 HTTP 상태 / response size
- 타이밍 차이

### 실전 악용

PadBuster는 고전적인 도구다:

{{#ref}}
https://github.com/AonCyberLabs/PadBuster
{{#endref}}

예시:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 16 \
-encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
참고:

- Block size is often `16` for AES.
- `-encoding 0` means Base64.
- Use `-error` if the oracle is a specific string.

### 작동 원리

CBC 복호화는 `P[i] = D(C[i]) XOR C[i-1]`를 계산합니다. `C[i-1]`의 바이트를 수정하고 패딩이 유효한지 관찰함으로써, 바이트 단위로 `P[i]`를 복구할 수 있습니다.

## Bit-flipping in CBC

패딩 오라클 없이도, CBC는 변형 가능(malleable)합니다. 만약 암호문 블록을 수정할 수 있고 애플리케이션이 복호화된 평문을 구조화된 데이터(예: `role=user`)로 사용할 경우, 다음 블록의 선택된 위치에 있는 평문 바이트를 변경하도록 특정 비트를 뒤집을 수 있습니다.

Typical CTF pattern:

- Token = `IV || C1 || C2 || ...`
- You control bytes in `C[i]`
- You target plaintext bytes in `P[i+1]` because `P[i+1] = D(C[i+1]) XOR C[i]`

이는 그 자체로 기밀성(confidentiality)을 깨는 것은 아니지만, 무결성(integrity)이 없을 때 일반적인 privilege-escalation primitive로 사용됩니다.

## CBC-MAC

CBC-MAC는 특정 조건(특히 **fixed-length messages**와 올바른 도메인 분리)에서만 안전합니다.

### Classic variable-length forgery pattern

CBC-MAC는 보통 다음과 같이 계산됩니다:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

선택한 메시지들에 대한 태그를 얻을 수 있다면, CBC 체이닝 동작을 이용해 키를 모른 채도 연결된(또는 관련된) 메시지의 태그를 만들어낼 수 있습니다.

이 패턴은 username이나 role을 CBC-MAC로 MAC 처리하는 CTF 쿠키/토큰에서 자주 등장합니다.

### Safer alternatives

- Use HMAC (SHA-256/512)
- Use CMAC (AES-CMAC) correctly
- Include message length / domain separation

## Stream ciphers: XOR and RC4

### The mental model

대부분의 스트림 암호 상황은 다음 식으로 환원됩니다:

`ciphertext = plaintext XOR keystream`

따라서:

- If you know plaintext, you recover keystream.
- If keystream is reused (same key+nonce), `C1 XOR C2 = P1 XOR P2`.

### XOR-based encryption

만약 위치 `i`에서 어떤 평문의 구간을 알고 있다면, 해당 위치의 keystream 바이트를 복원하여 다른 암호문들을 복호화할 수 있습니다.

Autosolvers:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4는 스트림 암호로, 암호화와 복호화가 동일한 연산입니다.

동일한 키로 알려진 평문에 대한 RC4 암호문을 얻을 수 있다면, keystream을 복원하여 동일한 길이/오프셋의 다른 메시지들을 복호화할 수 있습니다.

Reference writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

## References

- [Trail of Bits – Carelessness versus craftsmanship in cryptography](https://blog.trailofbits.com/2026/02/18/carelessness-versus-craftsmanship-in-cryptography/)

{{#include ../../banners/hacktricks-training.md}}
