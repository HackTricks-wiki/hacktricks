# Symmetric Crypto

{{#include ../../banners/hacktricks-training.md}}

## What to look for in CTFs

- **모드 오용**: ECB patterns, CBC malleability, CTR/GCM nonce reuse.
- **Padding oracles**: 잘못된 패딩에 대해 서로 다른 오류/타이밍이 발생하는지 확인.
- **MAC confusion**: CBC-MAC을 가변 길이 메시지에 사용하거나 MAC-then-encrypt 실수.
- **XOR everywhere**: 스트림 암호와 커스텀 구성은 종종 keystream과의 XOR로 환원된다.

## AES modes and misuse

### ECB: Electronic Codebook

ECB leaks patterns: equal plaintext blocks → equal ciphertext blocks. That enables:

- Cut-and-paste / block reordering
- Block deletion (if the format remains valid)

If you can control plaintext and observe ciphertext (or cookies), try making repeated blocks (e.g., many `A`s) and look for repeats.

### CBC: Cipher Block Chaining

- CBC is **malleable**: flipping bits in `C[i-1]` flips predictable bits in `P[i]`.
- If the system exposes valid padding vs invalid padding, you may have a **padding oracle**.

### CTR

CTR turns AES into a stream cipher: `C = P XOR keystream`.

If a nonce/IV is reused with the same key:

- `C1 XOR C2 = P1 XOR P2` (classic keystream reuse)
- With known plaintext, you can recover the keystream and decrypt others.

### GCM

GCM also breaks badly under nonce reuse. If the same key+nonce is used more than once, you typically get:

- Keystream reuse for encryption (like CTR), enabling plaintext recovery when any plaintext is known.
- Loss of integrity guarantees. Depending on what is exposed (multiple message/tag pairs under the same nonce), attackers may be able to forge tags.

Operational guidance:

- Treat "nonce reuse" in AEAD as a critical vulnerability.
- If you have multiple ciphertexts under the same nonce, start by checking `C1 XOR C2 = P1 XOR P2` style relations.

### Tools

- CyberChef for quick experiments: https://gchq.github.io/CyberChef/
- Python: `pycryptodome` for scripting

## ECB exploitation patterns

ECB (Electronic Code Book) encrypts each block independently:

- equal plaintext blocks → equal ciphertext blocks
- this leaks structure and enables cut-and-paste style attacks

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Detection idea: token/cookie pattern

If you login several times and **always get the same cookie**, the ciphertext may be deterministic (ECB or fixed IV).

If you create two users with mostly identical plaintext layouts (e.g., long repeated characters) and see repeated ciphertext blocks at the same offsets, ECB is a prime suspect.

### Exploitation patterns

#### Removing entire blocks

If the token format is something like `<username>|<password>` and the block boundary aligns, you can sometimes craft a user so the `admin` block appears aligned, then remove preceding blocks to obtain a valid token for `admin`.

#### Moving blocks

If the backend tolerates padding/extra spaces (`admin` vs `admin    `), you can:

- Align a block that contains `admin   `
- Swap/reuse that ciphertext block into another token

## Padding Oracle

### 무엇인지

In CBC mode, if the server reveals (directly or indirectly) whether decrypted plaintext has **valid PKCS#7 padding**, you can often:

- Decrypt ciphertext without the key
- Encrypt chosen plaintext (forge ciphertext)

The oracle can be:

- A specific error message
- A different HTTP status / response size
- A timing difference

### Practical exploitation

PadBuster is the classic tool:

{{#ref}}
https://github.com/AonCyberLabs/PadBuster
{{#endref}}

Example:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 16 \
-encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
참고:

- 블록 크기는 보통 `16` (AES).
- `-encoding 0`는 Base64를 의미합니다.
- oracle이 특정 문자열인 경우 `-error`를 사용하세요.

### 동작 원리

CBC 복호화는 `P[i] = D(C[i]) XOR C[i-1]`를 계산합니다. `C[i-1]`의 바이트를 수정하고 padding이 유효한지 관찰함으로써, 바이트 단위로 `P[i]`를 복원할 수 있습니다.

## CBC에서의 Bit-flipping

padding oracle 없이도, CBC는 변조 가능(malleable)합니다. 만약 ciphertext 블록을 수정할 수 있고 애플리케이션이 복호화된 plaintext를 구조화된 데이터(예: `role=user`)로 사용한다면, 특정 비트를 뒤집어 다음 블록의 선택한 위치에 있는 plaintext 바이트를 변경할 수 있습니다.

일반적인 CTF 패턴:

- Token = `IV || C1 || C2 || ...`
- 당신은 `C[i]`의 바이트를 제어합니다
- 당신은 `P[i+1]`의 plaintext 바이트를 목표로 삼습니다. 이유: `P[i+1] = D(C[i+1]) XOR C[i]`

이는 그 자체로 기밀성(confidentiality)의 파괴는 아니지만, integrity가 없을 때 흔한 권한 상승 프리미티브입니다.

## CBC-MAC

CBC-MAC는 특정 조건(특히 **fixed-length messages** 및 올바른 domain separation)에서만 안전합니다.

### 고전적 가변-길이 forgery 패턴

CBC-MAC은 보통 다음과 같이 계산됩니다:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

선택한 메시지에 대한 태그를 얻을 수 있다면, CBC가 블록을 체인하는 방식을 이용해 키를 모르는 상태에서도 종종 연결(concatenation)이나 관련 구성에 대한 태그를 만들어낼 수 있습니다.

이는 CBC-MAC로 username 또는 role에 MAC을 적용한 CTF의 cookies/tokens에서 자주 나타납니다.

### 더 안전한 대안

- HMAC (SHA-256/512) 사용
- CMAC (AES-CMAC)를 올바르게 사용
- 메시지 길이 포함 / domain separation 적용

## 스트림 암호: XOR 및 RC4

### 사고 모델

대부분의 스트림 암호 상황은 다음으로 환원됩니다:

`ciphertext = plaintext XOR keystream`

따라서:

- plaintext를 알고 있으면 keystream을 복원합니다.
- keystream이 재사용되면 (same key+nonce), `C1 XOR C2 = P1 XOR P2`.

### XOR 기반 암호화

위치 `i`에서 어떤 plaintext 세그먼트라도 알면, keystream 바이트를 복원하여 해당 위치의 다른 ciphertext들을 복호화할 수 있습니다.

자동 해결 도구:

- https://wiremask.eu/tools/xor-cracker/

### RC4

RC4는 스트림 암호이며, encrypt/decrypt는 동일한 연산입니다.

동일한 키로 알려진 plaintext의 RC4 암호문을 얻을 수 있다면, keystream을 복원하여 동일한 길이/오프셋의 다른 메시지들을 복호화할 수 있습니다.

Reference writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
