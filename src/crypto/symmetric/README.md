# Symmetric Crypto

{{#include ../../banners/hacktricks-training.md}}

## CTF에서 확인할 사항

- **Mode misuse**: ECB patterns, CBC malleability, CTR/GCM nonce reuse.
- **Padding oracles**: 잘못된 padding에 대한 서로 다른 오류/타이밍.
- **MAC confusion**: variable-length 메시지에 CBC-MAC을 사용하거나 MAC-then-encrypt 실수를 하는 경우.
- **XOR everywhere**: stream cipher와 custom construction은 흔히 keystream과의 XOR로 환원됩니다.

## AES modes and misuse

### ECB: Electronic Codebook

ECB는 패턴을 leak합니다: 동일한 plaintext block → 동일한 ciphertext block. 이를 통해 다음이 가능합니다:

- Cut-and-paste / block reordering
- Block deletion (format이 유효하게 유지되는 경우)

plaintext를 제어하고 ciphertext(또는 cookies)를 확인할 수 있다면, 반복되는 block(예: 많은 `A`)을 만들고 반복 패턴을 확인해 보세요.

### CBC: Cipher Block Chaining

- CBC는 **malleable**합니다: `C[i-1]`의 bit를 뒤집으면 `P[i]`의 예측 가능한 bit가 뒤집힙니다.
- 시스템이 valid padding과 invalid padding을 구분해 노출한다면 **padding oracle**이 있을 수 있습니다.

### CTR

CTR은 AES를 stream cipher로 변환합니다: `C = P XOR keystream`.

동일한 key로 nonce/IV를 재사용하면:

- `C1 XOR C2 = P1 XOR P2` (classic keystream reuse)
- known plaintext가 있으면 keystream을 복구하여 다른 데이터도 decrypt할 수 있습니다.

**Nonce/IV reuse exploitation patterns**

- plaintext가 알려져 있거나 추측 가능한 부분에서 keystream을 복구합니다:

```text
keystream[i..] = ciphertext[i..] XOR known_plaintext[i..]
```

복구한 keystream bytes를 동일한 key+IV로 생성된 다른 ciphertext의 동일한 offsets에 적용하여 decrypt합니다.
- 고도로 구조화된 데이터(예: ASN.1/X.509 certificates, file headers, JSON/CBOR)는 큰 known-plaintext 영역을 제공합니다. certificate의 ciphertext를 예측 가능한 certificate body와 XOR하여 keystream을 도출한 다음, 재사용된 IV로 encrypt된 다른 secrets를 decrypt할 수 있는 경우가 많습니다. 일반적인 certificate layout은 [TLS & Certificates](../tls-and-certificates/README.md)도 참고하세요.<sup>[[1]](#references)</sup>
- **동일한 serialized format/size**의 여러 secrets가 동일한 key+IV로 encrypt되면, full known plaintext가 없어도 field alignment가 leak됩니다. 예를 들어 동일한 modulus size의 PKCS#8 RSA keys는 prime factors를 일치하는 offsets에 배치합니다(2048-bit에서 약 99.6% alignment). 재사용된 keystream으로 encrypt된 두 ciphertext를 XOR하면 `p ⊕ p'` / `q ⊕ q'`가 분리되며, 이를 seconds 단위로 brute-recover할 수 있습니다.<sup>[[1]](#references)</sup>
- libraries의 default IV(예: constant `000...01`)는 critical footgun입니다. 모든 encryption이 동일한 keystream을 반복하게 되어 CTR이 reused one-time pad로 변합니다.<sup>[[1]](#references)</sup>

**CTR malleability**

- CTR은 confidentiality만 제공합니다. ciphertext의 bit를 뒤집으면 plaintext의 동일한 bit가 deterministic하게 뒤집힙니다. authentication tag가 없으면 attackers가 데이터를 tamper할 수 있으며(예: keys, flags 또는 messages 변경), 이를 감지하지 못합니다.
- AEAD(GCM, GCM-SIV, ChaCha20-Poly1305 등)를 사용하고 tag verification을 강제하여 bit-flips를 감지하세요.

### GCM

GCM도 nonce reuse 시 심각하게 손상됩니다. 동일한 key+nonce가 두 번 이상 사용되면 일반적으로 다음이 발생합니다:

- Encryption에서 keystream reuse(CTR과 동일)가 발생하여, plaintext 중 일부가 알려진 경우 plaintext recovery가 가능합니다.
- Integrity guarantees가 상실됩니다. 동일한 nonce 아래의 여러 message/tag pairs가 노출되는 방식에 따라 attackers가 tags를 forge할 수 있습니다.

Operational guidance:

- AEAD에서의 "nonce reuse"를 critical vulnerability로 취급하세요.
- Misuse-resistant AEAD(예: GCM-SIV)는 nonce-misuse의 피해를 줄이지만 여전히 unique nonces/IVs가 필요합니다.
- 동일한 nonce 아래에 여러 ciphertexts가 있다면 먼저 `C1 XOR C2 = P1 XOR P2` 형태의 관계를 확인하세요.

### Tools

- 빠른 실험에는 CyberChef: https://gchq.github.io/CyberChef/
- Python: scripting에는 `pycryptodome`

## ECB exploitation patterns

ECB (Electronic Code Book)는 각 block을 독립적으로 encrypt합니다:

- 동일한 plaintext blocks → 동일한 ciphertext blocks
- 이로 인해 structure가 leak되고 cut-and-paste style attacks가 가능합니다.

![ECB mode decryption block diagram](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Detection idea: token/cookie pattern

여러 번 login했는데 **항상 동일한 cookie를 받는다면**, ciphertext가 deterministic할 수 있습니다(ECB 또는 fixed IV).

대부분 동일한 plaintext layout(예: 긴 반복 characters)을 가진 두 users를 생성했을 때 동일한 offsets에서 반복되는 ciphertext blocks가 보이면 ECB가 유력한 suspect입니다.

### Exploitation patterns

#### Removing entire blocks

token format이 `<username>|<password>`와 같고 block boundary가 일치한다면, `admin` block이 정렬되어 나타나도록 user를 craft한 다음 preceding blocks를 제거하여 `admin`에 대한 valid token을 얻을 수 있는 경우가 있습니다.

#### Moving blocks

backend가 padding/extra spaces(`admin` vs `admin    `)를 허용한다면 다음을 수행할 수 있습니다:

- `admin   `을 포함하는 block을 align
- 해당 ciphertext block을 다른 token으로 swap/reuse

## Padding Oracle

### What it is

CBC mode에서 server가 decrypt된 plaintext에 **valid PKCS#7 padding**이 있는지 직접 또는 간접적으로 reveal하면 다음이 가능한 경우가 많습니다:

- key 없이 ciphertext decrypt
- chosen plaintext encrypt (ciphertext forge)

oracle은 다음과 같을 수 있습니다:

- 특정 error message
- 다른 HTTP status / response size
- timing difference

### Practical exploitation

PadBuster는 classic tool입니다:

{{#ref}}
https://github.com/AonCyberLabs/PadBuster
{{#endref}}

Example:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 16 \
-encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
Notes:

- Block size는 AES에서 흔히 `16`입니다.
- `-encoding 0`은 Base64를 의미합니다.
- oracle이 특정 문자열인 경우 `-error`를 사용합니다.

### 작동 원리

CBC 복호화는 `P[i] = D(C[i]) XOR C[i-1]`을 계산합니다. `C[i-1]`의 바이트를 수정하고 padding이 유효한지 관찰하면 `P[i]`를 바이트 단위로 복구할 수 있습니다.

## CBC에서의 Bit-flipping

padding oracle이 없어도 CBC는 malleable합니다. ciphertext block을 수정할 수 있고 애플리케이션이 복호화된 plaintext를 구조화된 데이터(예: `role=user`)로 사용하는 경우, 다음 block의 선택한 위치에서 특정 plaintext 바이트를 변경하도록 특정 bit를 flip할 수 있습니다.

일반적인 CTF 패턴:

- Token = `IV || C1 || C2 || ...`
- `C[i]`의 바이트를 제어할 수 있음
- `P[i+1]`의 plaintext 바이트를 대상으로 함. `P[i+1] = D(C[i+1]) XOR C[i]`이기 때문

이는 그 자체로 confidentiality를 break하는 것은 아니지만, integrity가 없을 때 흔히 사용되는 privilege-escalation primitive입니다.

## CBC-MAC

CBC-MAC은 특정 조건, 특히 **fixed-length messages** 및 올바른 domain separation이 적용된 경우에만 secure합니다.

### Classic variable-length forgery pattern

CBC-MAC은 일반적으로 다음과 같이 계산됩니다.

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

선택한 message에 대한 tag를 얻을 수 있다면, CBC가 block을 chain하는 방식을 악용하여 key를 모른 채 concatenation(또는 관련 construction)에 대한 tag를 제작할 수 있는 경우가 많습니다.

이는 username 또는 role을 CBC-MAC으로 MAC하는 CTF cookies/tokens에서 자주 나타납니다.

### 더 안전한 대안

- HMAC (SHA-256/512) 사용
- CMAC (AES-CMAC)을 올바르게 사용
- message length / domain separation 포함

## Stream ciphers: XOR 및 RC4

### Mental model

대부분의 stream cipher 상황은 다음으로 정리됩니다.

`ciphertext = plaintext XOR keystream`

따라서:

- plaintext를 알고 있으면 keystream을 복구할 수 있습니다.
- keystream이 재사용되면(동일한 key+nonce), `C1 XOR C2 = P1 XOR P2`입니다.

### XOR-based encryption

위치 `i`에서 plaintext segment를 알고 있으면 keystream 바이트를 복구하고, 동일한 위치의 다른 ciphertext를 복호화할 수 있습니다.

Autosolvers:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4는 stream cipher이며, encrypt/decrypt는 동일한 operation입니다.

동일한 key로 known plaintext의 RC4 encryption을 얻을 수 있다면 keystream을 복구하고, 동일한 length/offset을 가진 다른 message를 복호화할 수 있습니다.

Reference writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

## References

- [1] [Trail of Bits – Carelessness versus craftsmanship in cryptography](https://blog.trailofbits.com/2026/02/18/carelessness-versus-craftsmanship-in-cryptography/)

{{#include ../../banners/hacktricks-training.md}}
