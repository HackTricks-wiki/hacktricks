# Symmetric Crypto

{{#include ../../banners/hacktricks-training.md}}

## CTFs में क्या देखें

- **Mode misuse**: ECB patterns, CBC malleability, CTR/GCM nonce reuse।
- **Padding oracles**: bad padding के लिए अलग errors/timings।
- **MAC confusion**: variable-length messages के साथ CBC-MAC का उपयोग, या MAC-then-encrypt mistakes।
- **XOR everywhere**: stream ciphers और custom constructions अक्सर keystream के साथ XOR में बदल जाते हैं।

## AES modes और misuse

### ECB: Electronic Codebook

ECB patterns को leak करता है: समान plaintext blocks → समान ciphertext blocks। इससे संभव होते हैं:

- Cut-and-paste / block reordering
- Block deletion (यदि format valid बना रहे)

यदि आप plaintext को control कर सकते हैं और ciphertext (या cookies) observe कर सकते हैं, तो repeated blocks बनाने का प्रयास करें (जैसे, कई `A`s) और repeats खोजें।

### CBC: Cipher Block Chaining

- CBC **malleable** है: `C[i-1]` में bits flip करने पर `P[i]` में predictable bits flip होते हैं।
- यदि system valid padding और invalid padding को अलग-अलग expose करता है, तो आपके पास **padding oracle** हो सकता है।

### CTR

CTR AES को stream cipher में बदल देता है: `C = P XOR keystream`।

यदि समान key के साथ nonce/IV reuse किया जाता है:

- `C1 XOR C2 = P1 XOR P2` (classic keystream reuse)
- Known plaintext के साथ आप keystream recover कर सकते हैं और अन्य data को decrypt कर सकते हैं।

**Nonce/IV reuse exploitation patterns**

- जहाँ plaintext known/guessable हो, वहाँ keystream recover करें:

```text
keystream[i..] = ciphertext[i..] XOR known_plaintext[i..]
```

Recovered keystream bytes को समान key+IV के साथ समान offsets पर produced किसी भी अन्य ciphertext को decrypt करने के लिए apply करें।
- Highly structured data (जैसे ASN.1/X.509 certificates, file headers, JSON/CBOR) बड़े known-plaintext regions प्रदान करता है। आप अक्सर certificate के ciphertext को predictable certificate body के साथ XOR करके keystream derive कर सकते हैं, फिर reused IV के अंतर्गत encrypted अन्य secrets को decrypt कर सकते हैं। Typical certificate layouts के लिए [TLS & Certificates](../tls-and-certificates/README.md) भी देखें।<sup>[[1]](#references)</sup>
- जब **same serialized format/size** के कई secrets को समान key+IV के अंतर्गत encrypt किया जाता है, तो full known plaintext के बिना भी field alignment leak होता है। उदाहरण: समान modulus size वाली PKCS#8 RSA keys में prime factors matching offsets पर रखे जाते हैं (2048-bit के लिए ~99.6% alignment)। Reused keystream के अंतर्गत दो ciphertexts को XOR करने से `p ⊕ p'` / `q ⊕ q'` isolate होता है, जिसे seconds में brute-recover किया जा सकता है।<sup>[[1]](#references)</sup>
- Libraries में default IVs (जैसे constant `000...01`) एक critical footgun हैं: हर encryption समान keystream दोहराता है, जिससे CTR reused one-time pad में बदल जाता है।<sup>[[1]](#references)</sup>

**CTR malleability**

- CTR केवल confidentiality प्रदान करता है: ciphertext में bits flip करने पर plaintext में वही bits deterministically flip होते हैं। Authentication tag के बिना attackers data में tamper कर सकते हैं (जैसे keys, flags या messages को tweak करना), और इसका पता नहीं चलता।
- AEAD (GCM, GCM-SIV, ChaCha20-Poly1305, आदि) का उपयोग करें और bit-flips पकड़ने के लिए tag verification enforce करें।

### GCM

Nonce reuse होने पर GCM भी बुरी तरह fail होता है। यदि same key+nonce को एक से अधिक बार use किया जाता है, तो आम तौर पर आपको मिलता है:

- Encryption के लिए keystream reuse (CTR की तरह), जिससे कोई plaintext known होने पर plaintext recovery संभव होती है।
- Integrity guarantees का loss। जो expose हुआ है उसके आधार पर (same nonce के अंतर्गत multiple message/tag pairs), attackers tags forge कर सकते हैं।

Operational guidance:

- AEAD में "nonce reuse" को critical vulnerability मानें।
- Misuse-resistant AEADs (जैसे GCM-SIV) nonce-misuse के प्रभाव को कम करते हैं, लेकिन फिर भी unique nonces/IVs आवश्यक हैं।
- यदि आपके पास same nonce के अंतर्गत multiple ciphertexts हैं, तो `C1 XOR C2 = P1 XOR P2` style relations check करने से शुरू करें।

### Tools

- Quick experiments के लिए CyberChef: https://gchq.github.io/CyberChef/
- Python: scripting के लिए `pycryptodome`

## ECB exploitation patterns

ECB (Electronic Code Book) प्रत्येक block को independently encrypt करता है:

- समान plaintext blocks → समान ciphertext blocks
- यह structure को leak करता है और cut-and-paste style attacks को enable करता है

![ECB mode decryption block diagram](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Detection idea: token/cookie pattern

यदि आप कई बार login करते हैं और **हमेशा same cookie प्राप्त करते हैं**, तो ciphertext deterministic हो सकता है (ECB या fixed IV)।

यदि आप mostly identical plaintext layouts वाले दो users बनाते हैं (जैसे long repeated characters) और समान offsets पर repeated ciphertext blocks देखते हैं, तो ECB prime suspect है।

### Exploitation patterns

#### Removing entire blocks

यदि token format कुछ ऐसा है `<username>|<password>` और block boundary align होती है, तो आप कभी-कभी ऐसा user craft कर सकते हैं जिससे `admin` block aligned दिखाई दे, फिर preceding blocks remove करके `admin` के लिए valid token प्राप्त कर सकते हैं।

#### Moving blocks

यदि backend padding/extra spaces (`admin` बनाम `admin    `) tolerate करता है, तो आप:

- ऐसा block align करें जिसमें `admin   ` हो
- उस ciphertext block को किसी अन्य token में swap/reuse करें

## Padding Oracle

### What it is

CBC mode में, यदि server प्रत्यक्ष या अप्रत्यक्ष रूप से यह reveal करता है कि decrypted plaintext में **valid PKCS#7 padding** है या नहीं, तो आप अक्सर:

- Key के बिना ciphertext decrypt कर सकते हैं
- Chosen plaintext encrypt कर सकते हैं (ciphertext forge)

Oracle हो सकता है:

- Specific error message
- अलग HTTP status / response size
- Timing difference

### Practical exploitation

PadBuster classic tool है:

{{#ref}}
https://github.com/AonCyberLabs/PadBuster
{{#endref}}

Example:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 16 \
-encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
Notes:

- Block size अक्सर AES के लिए `16` होता है।
- `-encoding 0` का अर्थ Base64 है।
- यदि oracle एक specific string है, तो `-error` का उपयोग करें।

### यह क्यों काम करता है

CBC decryption `P[i] = D(C[i]) XOR C[i-1]` compute करता है। `C[i-1]` में bytes modify करके और यह देखकर कि padding valid है या नहीं, आप `P[i]` को byte-by-byte recover कर सकते हैं।

## CBC में Bit-flipping

Padding oracle के बिना भी CBC malleable होता है। यदि आप ciphertext blocks को modify कर सकते हैं और application decrypted plaintext को structured data (जैसे `role=user`) के रूप में उपयोग करती है, तो आप अगले block में चुने गए position पर specific plaintext bytes को बदलने के लिए specific bits flip कर सकते हैं।

Typical CTF pattern:

- Token = `IV || C1 || C2 || ...`
- आप `C[i]` में bytes control करते हैं
- आप `P[i+1]` में plaintext bytes को target करते हैं क्योंकि `P[i+1] = D(C[i+1]) XOR C[i]`

यह अपने-आप में confidentiality का break नहीं है, लेकिन integrity न होने पर यह एक common privilege-escalation primitive है।

## CBC-MAC

CBC-MAC केवल specific conditions में secure होता है (विशेष रूप से **fixed-length messages** और सही domain separation के साथ)।

### Classic variable-length forgery pattern

CBC-MAC आमतौर पर इस तरह compute किया जाता है:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

यदि आप chosen messages के लिए tags प्राप्त कर सकते हैं, तो आप key जाने बिना अक्सर concatenation (या related construction) के लिए tag craft कर सकते हैं, क्योंकि आप CBC के blocks को chain करने के तरीके का लाभ उठाते हैं।

यह अक्सर उन CTF cookies/tokens में दिखाई देता है जो username या role पर CBC-MAC लगाते हैं।

### Safer alternatives

- HMAC (SHA-256/512) का उपयोग करें
- CMAC (AES-CMAC) का सही तरीके से उपयोग करें
- Message length / domain separation शामिल करें

## Stream ciphers: XOR और RC4

### Mental model

अधिकांश stream cipher situations इस प्रकार reduce होती हैं:

`ciphertext = plaintext XOR keystream`

इसलिए:

- यदि आपको plaintext पता है, तो आप keystream recover कर सकते हैं।
- यदि keystream reuse किया जाता है (same key+nonce), तो `C1 XOR C2 = P1 XOR P2`।

### XOR-based encryption

यदि आपको position `i` पर कोई plaintext segment पता है, तो आप keystream bytes recover कर सकते हैं और उन्हीं positions पर अन्य ciphertexts को decrypt कर सकते हैं।

Autosolvers:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 एक stream cipher है; encrypt/decrypt एक ही operation हैं।

यदि आप same key के अंतर्गत known plaintext का RC4 encryption प्राप्त कर सकते हैं, तो आप keystream recover कर सकते हैं और same length/offset के अन्य messages को decrypt कर सकते हैं।

Reference writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

## References

- [1] [Trail of Bits – Carelessness versus craftsmanship in cryptography](https://blog.trailofbits.com/2026/02/18/carelessness-versus-craftsmanship-in-cryptography/)

{{#include ../../banners/hacktricks-training.md}}
