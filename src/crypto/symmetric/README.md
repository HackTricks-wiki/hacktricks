# 대칭 암호

{{#include ../../banners/hacktricks-training.md}}

## CTF에서 찾아볼 것

- **모드 오용**: ECB 패턴, CBC 변조 가능성(malleability), CTR/GCM nonce reuse.
- **Padding oracles**: 잘못된 padding에 대해 다른 오류/타이밍이 나타남.
- **MAC confusion**: CBC-MAC을 가변 길이 메시지에 사용하거나, MAC-then-encrypt 실수.
- **XOR everywhere**: stream ciphers와 커스텀 구성은 종종 keystream과의 XOR으로 환원됨.

## AES 모드와 오용

### ECB: Electronic Codebook

ECB leaks patterns: equal plaintext blocks → equal ciphertext blocks. 이는 다음을 가능하게 한다:

- Cut-and-paste / block reordering
- Block deletion (if the format remains valid)

만약 plaintext를 제어하고 ciphertext(또는 쿠키)를 관찰할 수 있다면, 반복되는 블록(예: 많은 `A`s)을 만들어 반복을 찾아보세요.

### CBC: Cipher Block Chaining

- CBC is **malleable**: `C[i-1]`에서 비트를 뒤집으면 `P[i]`의 예측 가능한 비트가 뒤집힌다.
- 시스템이 유효한 padding과 유효하지 않은 padding을 구분해 노출한다면, **padding oracle**이 있을 수 있다.

### CTR

CTR는 AES를 stream cipher로 바꾼다: `C = P XOR keystream`.

만약 nonce/IV가 같은 키로 재사용되면:

- `C1 XOR C2 = P1 XOR P2` (classic keystream reuse)
- 알려진 plaintext가 있으면 keystream을 복원하고 다른 것들을 복호화할 수 있다.

### GCM

GCM도 nonce reuse 시 심하게 깨진다. 같은 key+nonce가 여러 번 사용되면 보통 다음이 발생한다:

- 암호화에 대한 keystream 재사용(CTR과 유사), 어떤 plaintext가 알려져 있으면 평문 복구가 가능.
- 무결성 보장이 손실된다. 노출된 내용(같은 nonce 아래의 여러 메시지/태그 쌍)에 따라 공격자가 태그를 위조할 수 있다.

운영 지침:

- AEAD에서 "nonce reuse"를 치명적인 취약점으로 취급하라.
- 같은 nonce 아래 여러 ciphertext가 있다면, 먼저 `C1 XOR C2 = P1 XOR P2` 형태의 관계를 확인하라.

### 도구

- CyberChef for quick experiments: https://gchq.github.io/CyberChef/
- Python: `pycryptodome` for scripting

## ECB exploitation patterns

ECB (Electronic Code Book)는 각 블록을 독립적으로 암호화한다:

- 동일한 plaintext 블록 → 동일한 ciphertext 블록
- 이는 구조를 leaks하며 cut-and-paste 스타일 공격을 가능하게 한다

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### 탐지 아이디어: 토큰/쿠키 패턴

여러 번 로그인했는데 **항상 같은 cookie를 받는다면**, ciphertext가 결정론적일 수 있다 (ECB 또는 고정 IV).

예를 들어 대부분 동일한 plaintext 레이아웃(예: 길게 반복된 문자)을 가진 두 사용자를 만들고 같은 오프셋에서 반복된 ciphertext 블록이 보이면, ECB가 유력한 의심 대상이다.

### 악용 패턴

#### 전체 블록 제거

토큰 형식이 `<username>|<password>` 같은 경우 블록 경계가 맞으면, `admin` 블록이 정렬되도록 사용자를 만들고 앞의 블록을 제거하여 `admin`에 대한 유효한 토큰을 얻을 수 있다.

#### 블록 이동

백엔드가 padding/여분의 공백(`admin` vs `admin    `)을 허용하면, 다음을 할 수 있다:

- `admin   `를 포함하는 블록을 정렬한다
- 그 ciphertext 블록을 다른 토큰에 교체/재사용한다

## Padding Oracle

### 개요

CBC 모드에서 서버가 복호화된 평문의 **valid PKCS#7 padding** 여부를 (직접 또는 간접적으로) 노출하면, 종종 다음을 할 수 있다:

- 키 없이 ciphertext를 복호화
- 선택한 plaintext를 암호화(위조된 ciphertext 생성)

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

- 블록 크기는 AES의 경우 흔히 `16`입니다.
- `-encoding 0`는 Base64를 의미합니다.
- 오라클이 특정 문자열인 경우 `-error`를 사용하세요.

### Why it works

CBC 복호화는 `P[i] = D(C[i]) XOR C[i-1]`를 계산합니다. `C[i-1]`의 바이트를 수정하고 padding이 유효한지 관찰함으로써, `P[i]`를 바이트 단위로 복원할 수 있습니다.

## Bit-flipping in CBC

padding oracle 없이도 CBC는 malleable합니다. 암호문 블록을 수정할 수 있고 애플리케이션이 복호화된 평문을 구조화된 데이터(예: `role=user`)로 사용할 경우, 특정 비트를 뒤집어 다음 블록의 선택한 위치에 있는 평문 바이트를 변경할 수 있습니다.

Typical CTF pattern:

- Token = `IV || C1 || C2 || ...`
- You control bytes in `C[i]`
- You target plaintext bytes in `P[i+1]` because `P[i+1] = D(C[i+1]) XOR C[i]`

이것 자체로 기밀성(confidentiality)을 깨는 것은 아니지만, 무결성(integrity)이 없을 때 일반적인 privilege-escalation 프리미티브입니다.

## CBC-MAC

CBC-MAC는 특정 조건(특히 고정 길이 메시지와 올바른 도메인 분리)이 있어야만 안전합니다.

### Classic variable-length forgery pattern

CBC-MAC는 보통 다음과 같이 계산됩니다:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

선택한 메시지에 대한 태그를 얻을 수 있다면, CBC가 블록을 연결하는 방식을 악용하여 키를 모른 채로 메시지의 연결(concatenation) 등과 관련된 태그를 자주 만들어낼 수 있습니다.

이는 CTF에서 username이나 role을 CBC-MAC으로 MAC 처리하는 쿠키/토큰에서 자주 나타납니다.

### Safer alternatives

- HMAC (SHA-256/512)를 사용하세요.
- CMAC (AES-CMAC)를 올바르게 사용하세요.
- 메시지 길이 및 도메인 분리를 포함하세요.

## Stream ciphers: XOR and RC4

### The mental model

대부분의 스트림 암호 상황은 다음으로 환원됩니다:

`ciphertext = plaintext XOR keystream`

따라서:

- plaintext를 알면 keystream을 복원할 수 있습니다.
- keystream이 재사용되는 경우(같은 key+nonce), `C1 XOR C2 = P1 XOR P2`.

### XOR-based encryption

만약 위치 `i`에서의 어떤 plaintext 세그먼트를 알고 있다면, keystream 바이트를 복원하여 해당 위치의 다른 암호문들을 복호화할 수 있습니다.

Autosolvers:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4는 스트림 암호로, 암호화와 복호화가 동일한 연산입니다.

같은 키로 알려진 plaintext의 RC4 암호문을 얻을 수 있다면, keystream을 복원하여 동일한 길이/오프셋의 다른 메시지들을 복호화할 수 있습니다.

Reference writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
