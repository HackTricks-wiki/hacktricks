# Symmetric Crypto

{{#include ../../banners/hacktricks-training.md}}

## CTF에서 확인할 사항

- **Mode misuse**: ECB patterns, CBC malleability, CTR/GCM nonce reuse.
- **Padding oracles**: 잘못된 padding에 대한 서로 다른 오류/타이밍.
- **MAC confusion**: variable-length messages에 CBC-MAC을 사용하거나 MAC-then-encrypt 실수를 하는 경우.
- **XOR everywhere**: stream ciphers와 custom constructions는 흔히 keystream과의 XOR로 귀결됩니다.

## AES modes and misuse

NIST는 SP 800-38A에서 ECB, CBC 및 CTR confidentiality modes를, SP 800-38D에서 GCM authenticated encryption을 지정합니다.<sup>[[2]](#references)[[3]](#references)</sup>

### ECB: Electronic Codebook

ECB는 patterns를 leak합니다: 동일한 plaintext blocks → 동일한 ciphertext blocks. 이를 통해 다음이 가능합니다.

- Cut-and-paste / block reordering
- Block deletion (format이 유효하게 유지되는 경우)

plaintext를 제어하고 ciphertext(또는 cookies)를 관찰할 수 있다면, repeated blocks(예: 많은 `A`s)를 만들고 반복을 확인해 보세요.

### CBC: Cipher Block Chaining

- CBC는 **malleable**합니다. `C[i-1]`의 bits를 뒤집으면 `P[i]`에서 예측 가능한 bits가 뒤집히며, 동시에 `P[i-1]`이 손상됩니다. IV를 수정하면 이전 plaintext block을 손상시키지 않고 첫 번째 plaintext block을 대상으로 삼을 수 있습니다.
- 시스템이 valid padding과 invalid padding을 구분해 노출한다면 **padding oracle**이 있을 수 있습니다.

### CTR

CTR은 AES를 stream cipher로 변환합니다: `C = P XOR keystream`.

동일한 key로 nonce/IV가 재사용되면:

- `C1 XOR C2 = P1 XOR P2` (classic keystream reuse)
- known plaintext가 있으면 keystream을 복구하여 다른 것들을 decrypt할 수 있습니다.

**Nonce/IV reuse exploitation patterns**

- plaintext가 알려졌거나 추측 가능한 곳에서 keystream을 복구합니다.

```text
keystream[i..] = ciphertext[i..] XOR known_plaintext[i..]
```

복구한 keystream bytes를 동일한 key+IV를 사용해 동일한 offsets에서 생성된 다른 ciphertext에 적용하여 decrypt합니다.
- 고도로 구조화된 data(예: ASN.1/X.509 certificates, file headers, JSON/CBOR)는 넓은 known-plaintext 영역을 제공합니다. certificate의 ciphertext를 예측 가능한 certificate body와 XOR하여 keystream을 도출한 다음, 재사용된 IV로 encrypt된 다른 secrets를 decrypt할 수 있는 경우가 많습니다. 일반적인 certificate layouts는 [TLS & Certificates](../tls-and-certificates/README.md)도 참고하세요.<sup>[[1]](#references)</sup>
- 여러 secrets가 **동일한 serialized format/size**로 동일한 key+IV를 사용해 encrypt되면, 완전한 known plaintext가 없어도 field alignment가 leak됩니다. 예를 들어 동일한 modulus size의 PKCS#8 RSA keys는 prime factors를 일치하는 offsets에 배치합니다(2048-bit에서 약 99.6% alignment). 재사용된 keystream으로 두 ciphertext를 XOR하면 `p ⊕ p'` / `q ⊕ q'`가 분리되며, 이를 수 초 내에 brute-force로 복구할 수 있습니다.<sup>[[1]](#references)</sup>
- libraries의 default IV(예: constant `000...01`)는 치명적인 footgun입니다. 모든 encryption이 동일한 keystream을 반복하여 CTR을 재사용된 one-time pad로 바꿉니다.<sup>[[1]](#references)</sup>

**CTR malleability**

- CTR은 confidentiality만 제공합니다. ciphertext의 bits를 뒤집으면 plaintext에서도 동일한 bits가 결정적으로 뒤집힙니다. authentication tag가 없으면 attackers가 data(예: keys, flags 또는 messages)를 tamper해도 감지되지 않습니다.
- AEAD(GCM, GCM-SIV, ChaCha20-Poly1305 등)를 사용하고 tag verification을 강제하여 bit-flips를 탐지하세요.

### GCM

GCM도 nonce reuse 시 심각하게 손상됩니다. 동일한 key+nonce가 두 번 이상 사용되면 일반적으로 다음이 발생합니다.

- Encryption에서 keystream reuse(CTR과 동일)로, plaintext 중 일부라도 알려져 있으면 plaintext recovery가 가능합니다.
- Integrity guarantees가 손실됩니다. 무엇이 노출되는지(동일한 nonce를 사용한 여러 message/tag pairs)에 따라 attackers가 tags를 forge할 수 있습니다.

Operational guidance:

- AEAD에서 "nonce reuse"를 critical vulnerability로 취급하세요.
- AES-GCM-SIV와 같은 misuse-resistant AEADs는 nonce-reuse fallout을 줄입니다. 호출자는 construction의 interface에서 요구하는 대로 여전히 unique nonces를 제공해야 합니다. 다만 accidental reuse의 consequences는 일반적인 GCM에 비해 제한적입니다.<sup>[[3]](#references)[[4]](#references)</sup>
- 동일한 nonce를 사용하는 여러 ciphertexts가 있다면, 먼저 `C1 XOR C2 = P1 XOR P2` 형식의 relations를 확인하세요.

### Tools

- 빠른 실험을 위한 [CyberChef](https://gchq.github.io/CyberChef/).<sup>[[8]](#references)</sup>
- scripting을 위한 Python의 [PyCryptodome](https://www.pycryptodome.org/) package.<sup>[[9]](#references)</sup>

## ECB exploitation patterns

ECB (Electronic Code Book)는 각 block을 독립적으로 encrypt합니다.

- 동일한 plaintext blocks → 동일한 ciphertext blocks
- 이는 structure를 leak하며 cut-and-paste style attacks를 가능하게 합니다.

![ECB mode decryption block diagram](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Detection idea: token/cookie pattern

여러 번 login했을 때 **항상 동일한 cookie를 받는다면**, ciphertext가 deterministic할 수 있습니다(ECB 또는 fixed IV).

대부분 동일한 plaintext layouts(예: 긴 repeated characters)을 가진 두 users를 생성하고 동일한 offsets에서 repeated ciphertext blocks가 보인다면 ECB를 우선 의심해야 합니다.

### Exploitation patterns

#### Removing entire blocks

token format이 `<username>|<password>`와 같고 block boundary가 정렬된다면, `admin` block이 정렬되어 나타나는 user를 만든 다음 앞의 blocks를 제거하여 `admin`에 대한 valid token을 얻을 수 있는 경우가 있습니다.

#### Moving blocks

backend가 padding/extra spaces(`admin` 대 `admin    `)를 허용한다면 다음을 수행할 수 있습니다.

- `admin   `을 포함하는 block을 정렬
- 해당 ciphertext block을 다른 token으로 교체/재사용

## Padding Oracle

### What it is

CBC mode에서 server가 decrypt된 plaintext에 **valid PKCS#7 padding**이 있는지를 직접 또는 간접적으로 알려주면, 다음을 수행할 수 있는 경우가 많습니다.<sup>[[7]](#references)</sup>

- key 없이 ciphertext를 decrypt
- crafted preceding blocks 또는 IV를 제출할 수 있고 application이 그 결과로 생성된 validly padded message를 허용할 때, chosen plaintext로 decrypt되는 ciphertext 구성

oracle은 다음과 같을 수 있습니다.

- 특정 error message
- 다른 HTTP status / response size
- timing difference

### Practical exploitation

PadBuster는 classic tool입니다.

{{#ref}}
https://github.com/AonCyberLabs/PadBuster
{{#endref}}

Example:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 16 \
-encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
Notes:

- Block size is AES에서 `16`인 경우가 많습니다.
- `-encoding 0`은 Base64를 의미합니다.
- oracle이 특정 문자열인 경우 `-error`를 사용합니다.

### 작동 원리

CBC decryption은 `P[i] = D(C[i]) XOR C[i-1]`를 계산합니다. `C[i-1]`의 바이트를 수정하고 padding이 유효한지 확인하면 `P[i]`를 byte-by-byte로 복구할 수 있습니다.

## Bit-flipping in CBC

padding oracle이 없어도 CBC는 malleable합니다. ciphertext blocks를 수정할 수 있고 application이 decrypted plaintext를 structured data(예: `role=user`)로 사용하는 경우, 다음 block의 선택한 위치에 있는 특정 plaintext bytes를 변경하도록 특정 bits를 flip할 수 있습니다.

Typical CTF pattern:

- Token = `IV || C1 || C2 || ...`
- `C[i]`의 bytes를 제어합니다.
- `P[i+1]`의 plaintext bytes를 target으로 삼습니다. `P[i+1] = D(C[i+1]) XOR C[i]`이기 때문입니다.

이는 그 자체로 confidentiality를 break하지는 않지만, integrity가 없을 때 흔히 사용되는 privilege-escalation primitive입니다.

## CBC-MAC

CBC-MAC은 특정 조건(특히 **fixed-length messages** 및 올바른 domain separation)에서만 안전합니다. AES-CMAC은 variable-length inputs를 안전하게 처리하는 standardized construction입니다.<sup>[[5]](#references)</sup>

### Classic variable-length forgery pattern

CBC-MAC은 일반적으로 다음과 같이 계산됩니다.

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

chosen messages에 대한 tags를 얻을 수 있다면, CBC가 blocks를 chain하는 방식을 exploit하여 key를 몰라도 concatenation(또는 관련 construction)에 대한 tag를 제작할 수 있는 경우가 많습니다.

이는 username 또는 role에 CBC-MAC을 사용하는 CTF cookies/tokens에서 자주 나타납니다.

### Safer alternatives

- HMAC (SHA-256/512) 사용
- CMAC (AES-CMAC)을 올바르게 사용
- message length / domain separation 포함

## Stream ciphers: XOR and RC4

### The mental model

대부분의 stream cipher 상황은 다음과 같이 정리됩니다.

`ciphertext = plaintext XOR keystream`

따라서:

- plaintext를 알고 있다면 keystream을 복구할 수 있습니다.
- keystream이 재사용되면(동일한 key+nonce), `C1 XOR C2 = P1 XOR P2`입니다.

### XOR-based encryption

position `i`에서 plaintext segment를 알고 있다면 keystream bytes를 복구하고 해당 position의 다른 ciphertexts를 decrypt할 수 있습니다.

Autosolvers:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4는 legacy stream cipher이며, encrypt/decrypt는 동일한 XOR operation입니다. 알려진 biases 때문에 새로운 systems에 사용하기에 부적합하고, TLS는 해당 cipher suites를 명시적으로 금지합니다.<sup>[[6]](#references)</sup>

동일한 key로 known plaintext의 RC4 encryption을 얻을 수 있다면, keystream을 복구하고 동일한 length/offset을 가진 다른 messages를 decrypt할 수 있습니다.

Reference writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

## References

- [1] [Trail of Bits – cryptography에서의 부주의와 장인정신](https://blog.trailofbits.com/2026/02/18/carelessness-versus-craftsmanship-in-cryptography/)
- [2] [NIST SP 800-38A - Block Cipher Modes of Operation에 대한 권고](https://csrc.nist.gov/pubs/sp/800/38/a/final)
- [3] [NIST SP 800-38D - Galois/Counter Mode (GCM) 및 GMAC에 대한 권고](https://csrc.nist.gov/pubs/sp/800/38/d/final)
- [4] [RFC 8452 - AES-GCM-SIV: Nonce Misuse-Resistant Authenticated Encryption](https://www.rfc-editor.org/rfc/rfc8452)
- [5] [RFC 4493 - The AES-CMAC Algorithm](https://www.rfc-editor.org/rfc/rfc4493)
- [6] [RFC 7465 - Prohibiting RC4 Cipher Suites](https://www.rfc-editor.org/rfc/rfc7465)
- [7] [OWASP Web Security Testing Guide - Padding Oracle 테스트](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/02-Testing_for_Padding_Oracle)
- [8] [GCHQ CyberChef](https://gchq.github.io/CyberChef/)
- [9] [PyCryptodome documentation](https://www.pycryptodome.org/)
{{#include ../../banners/hacktricks-training.md}}
