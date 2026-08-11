# Symmetric Crypto

{{#include ../../banners/hacktricks-training.md}}

## CTFs में क्या देखें

- **Mode misuse**: ECB patterns, CBC malleability, CTR/GCM nonce reuse।
- **Padding oracles**: खराब padding के लिए अलग errors/timings।
- **MAC confusion**: variable-length messages के साथ CBC-MAC का उपयोग, या MAC-then-encrypt की गलतियाँ।
- **XOR everywhere**: stream ciphers और custom constructions अक्सर keystream के साथ XOR तक सीमित हो जाते हैं।

## AES modes और misuse

NIST ने SP 800-38A में ECB, CBC और CTR confidentiality modes तथा SP 800-38D में GCM authenticated encryption निर्दिष्ट किए हैं।<sup>[[2]](#references)[[3]](#references)</sup>

### ECB: Electronic Codebook

ECB patterns को leak करता है: समान plaintext blocks → समान ciphertext blocks। इससे सक्षम होता है:

- Cut-and-paste / block reordering
- Block deletion (यदि format valid बना रहे)

यदि आप plaintext को नियंत्रित कर सकते हैं और ciphertext (या cookies) देख सकते हैं, तो repeated blocks बनाने का प्रयास करें (जैसे, कई `A`s) और repetitions खोजें।

### CBC: Cipher Block Chaining

- CBC **malleable** है: `C[i-1]` में bits flip करने पर `P[i]` में अनुमानित bits flip होते हैं, जबकि `P[i-1]` भी garble हो जाता है। IV को modify करने पर पहले plaintext block को target किया जा सकता है, बिना किसी पहले plaintext block को garble किए।
- यदि system valid padding और invalid padding को अलग-अलग expose करता है, तो आपके पास **padding oracle** हो सकता है।

### CTR

CTR, AES को stream cipher में बदल देता है: `C = P XOR keystream`।

यदि समान key के साथ nonce/IV reuse किया जाता है:

- `C1 XOR C2 = P1 XOR P2` (classic keystream reuse)
- Known plaintext के साथ आप keystream recover करके अन्य को decrypt कर सकते हैं।

**Nonce/IV reuse exploitation patterns**

- जहाँ plaintext known/guessable हो, वहाँ keystream recover करें:

```text
keystream[i..] = ciphertext[i..] XOR known_plaintext[i..]
```

Recovered keystream bytes को समान key+IV से समान offsets पर बनाए गए किसी भी अन्य ciphertext को decrypt करने के लिए apply करें।
- Highly structured data (जैसे ASN.1/X.509 certificates, file headers, JSON/CBOR) बड़े known-plaintext regions प्रदान करता है। आप अक्सर certificate के ciphertext को predictable certificate body के साथ XOR करके keystream derive कर सकते हैं, फिर reused IV के अंतर्गत encrypted अन्य secrets को decrypt कर सकते हैं। Typical certificate layouts के लिए [TLS & Certificates](../tls-and-certificates/README.md) भी देखें।<sup>[[1]](#references)</sup>
- जब **same serialized format/size** के कई secrets समान key+IV के अंतर्गत encrypted हों, तो full known plaintext के बिना भी field alignment leak होता है। उदाहरण: समान modulus size वाली PKCS#8 RSA keys में prime factors matching offsets पर होते हैं (2048-bit के लिए ~99.6% alignment)। Reused keystream के अंतर्गत दो ciphertexts को XOR करने से `p ⊕ p'` / `q ⊕ q'` isolate हो जाता है, जिसे seconds में brute-recover किया जा सकता है।<sup>[[1]](#references)</sup>
- Libraries में default IVs (जैसे constant `000...01`) एक critical footgun हैं: हर encryption समान keystream को दोहराता है, जिससे CTR एक reused one-time pad में बदल जाता है।<sup>[[1]](#references)</sup>

**CTR malleability**

- CTR केवल confidentiality प्रदान करता है: ciphertext में bits flip करने पर plaintext में वही bits deterministically flip होते हैं। Authentication tag के बिना attackers data से tamper कर सकते हैं (जैसे keys, flags या messages में बदलाव) और इसका पता नहीं चलता।
- AEAD (GCM, GCM-SIV, ChaCha20-Poly1305, आदि) का उपयोग करें और bit-flips पकड़ने के लिए tag verification enforce करें।

### GCM

Nonce reuse के अंतर्गत GCM भी गंभीर रूप से fail होता है। यदि समान key+nonce को एक से अधिक बार उपयोग किया जाता है, तो सामान्यतः आपको मिलता है:

- Encryption के लिए keystream reuse (CTR की तरह), जिससे कोई भी plaintext known होने पर plaintext recovery संभव होती है।
- Integrity guarantees का loss। Exposed data (एक ही nonce के अंतर्गत multiple message/tag pairs) के आधार पर attackers tags forge कर सकते हैं।

Operational guidance:

- AEAD में "nonce reuse" को critical vulnerability मानें।
- AES-GCM-SIV जैसे misuse-resistant AEADs nonce-reuse fallout को कम करते हैं। Callers को construction के interface के अनुसार unique nonces फिर भी provide करने चाहिए; ordinary GCM की तुलना में accidental reuse के consequences bounded होते हैं।<sup>[[3]](#references)[[4]](#references)</sup>
- यदि आपके पास समान nonce के अंतर्गत multiple ciphertexts हैं, तो `C1 XOR C2 = P1 XOR P2` style relations जाँचने से शुरुआत करें।

### Tools

- त्वरित experiments के लिए [CyberChef](https://gchq.github.io/CyberChef/)।<sup>[[8]](#references)</sup>
- Scripting के लिए Python का [PyCryptodome](https://www.pycryptodome.org/) package।<sup>[[9]](#references)</sup>

## ECB exploitation patterns

ECB (Electronic Code Book) प्रत्येक block को independently encrypt करता है:

- समान plaintext blocks → समान ciphertext blocks
- इससे structure leak होता है और cut-and-paste style attacks संभव होते हैं

![ECB mode decryption block diagram](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Detection idea: token/cookie pattern

यदि आप कई बार login करते हैं और **हर बार वही cookie मिलती है**, तो ciphertext deterministic हो सकता है (ECB या fixed IV)।

यदि आप mostly identical plaintext layouts वाले दो users बनाते हैं (जैसे, लंबे repeated characters) और समान offsets पर repeated ciphertext blocks देखते हैं, तो ECB एक prime suspect है।

### Exploitation patterns

#### Removing entire blocks

यदि token format कुछ ऐसा है `<username>|<password>` और block boundary align होती है, तो आप कभी-कभी ऐसा user craft कर सकते हैं जिसमें `admin` block aligned हो, फिर preceding blocks remove करके `admin` के लिए valid token प्राप्त कर सकते हैं।

#### Moving blocks

यदि backend padding/extra spaces (`admin` बनाम `admin    `) tolerate करता है, तो आप:

- ऐसा block align करें जिसमें `admin   ` हो
- उस ciphertext block को किसी अन्य token में swap/reuse करें

## Padding Oracle

### What it is

CBC mode में, यदि server (प्रत्यक्ष या अप्रत्यक्ष रूप से) यह reveal करता है कि decrypted plaintext में **valid PKCS#7 padding** है या नहीं, तो आप अक्सर:<sup>[[7]](#references)</sup>

- बिना key के ciphertext decrypt कर सकते हैं
- ऐसा ciphertext construct कर सकते हैं जो chosen plaintext में decrypt हो, जब आप crafted preceding blocks या IVs submit कर सकें और application resulting validly padded message accept करे

Oracle हो सकता है:

- Specific error message
- अलग HTTP status / response size
- Timing difference

### Practical exploitation

PadBuster classic tool है:

{{#ref}}
https://github.com/AonCyberLabs/PadBuster
{{#endref}}

उदाहरण:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 16 \
-encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
Notes:

- AES के लिए block size अक्सर `16` होता है।
- `-encoding 0` का अर्थ Base64 है।
- यदि oracle एक specific string है, तो `-error` का उपयोग करें।

### यह क्यों काम करता है

CBC decryption `P[i] = D(C[i]) XOR C[i-1]` की गणना करता है। `C[i-1]` में bytes को modify करके और यह देखकर कि padding valid है या नहीं, आप `P[i]` को byte-by-byte recover कर सकते हैं।

## CBC में Bit-flipping

Padding oracle के बिना भी CBC malleable होता है। यदि आप ciphertext blocks को modify कर सकते हैं और application decrypted plaintext को structured data (जैसे `role=user`) के रूप में उपयोग करती है, तो आप अगले block में चुने गए स्थान पर specific plaintext bytes को बदलने के लिए specific bits flip कर सकते हैं।

Typical CTF pattern:

- Token = `IV || C1 || C2 || ...`
- आप `C[i]` में bytes को control करते हैं
- आप `P[i+1]` में plaintext bytes को target करते हैं क्योंकि `P[i+1] = D(C[i+1]) XOR C[i]`

यह अपने-आप में confidentiality को break नहीं करता, लेकिन integrity न होने पर यह privilege-escalation primitive का common रूप है।

## CBC-MAC

CBC-MAC केवल specific conditions में secure होता है (विशेष रूप से **fixed-length messages** और सही domain separation के साथ)। AES-CMAC एक standardized construction है, जो variable-length inputs को सुरक्षित रूप से handle करता है।<sup>[[5]](#references)</sup>

### Classic variable-length forgery pattern

CBC-MAC की सामान्यतः गणना इस प्रकार की जाती है:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

यदि आप चुने गए messages के लिए tags प्राप्त कर सकते हैं, तो CBC के blocks को chain करने के तरीके का exploitation करके, key जाने बिना concatenation (या संबंधित construction) के लिए tag बना सकते हैं।

यह अक्सर उन CTF cookies/tokens में दिखाई देता है जो username या role के लिए CBC-MAC का उपयोग करते हैं।

### अधिक सुरक्षित alternatives

- HMAC (SHA-256/512) का उपयोग करें
- CMAC (AES-CMAC) का सही तरीके से उपयोग करें
- Message length / domain separation शामिल करें

## Stream ciphers: XOR और RC4

### Mental model

अधिकांश stream cipher situations इस पर आकर सिमट जाती हैं:

`ciphertext = plaintext XOR keystream`

इसलिए:

- यदि आपको plaintext पता है, तो आप keystream recover कर सकते हैं।
- यदि keystream reuse किया जाता है (same key+nonce), तो `C1 XOR C2 = P1 XOR P2`।

### XOR-based encryption

यदि आपको position `i` पर कोई plaintext segment पता है, तो आप keystream bytes recover करके उन्हीं positions पर अन्य ciphertexts को decrypt कर सकते हैं।

Autosolvers:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 एक legacy stream cipher है; encrypt/decrypt एक ही XOR operation हैं। इसके ज्ञात biases इसे नए systems के लिए अनुपयुक्त बनाते हैं, और TLS इसके cipher suites को explicitly prohibit करता है।<sup>[[6]](#references)</sup>

यदि आपको same key के अंतर्गत known plaintext का RC4 encryption मिल सकता है, तो आप keystream recover करके समान length/offset वाले अन्य messages को decrypt कर सकते हैं।

Reference writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

## References

- [1] [Trail of Bits – cryptography में लापरवाही बनाम कुशल craftsmanship](https://blog.trailofbits.com/2026/02/18/carelessness-versus-craftsmanship-in-cryptography/)
- [2] [NIST SP 800-38A - Block Cipher Modes of Operation के लिए Recommendation](https://csrc.nist.gov/pubs/sp/800/38/a/final)
- [3] [NIST SP 800-38D - Galois/Counter Mode (GCM) और GMAC के लिए Recommendation](https://csrc.nist.gov/pubs/sp/800/38/d/final)
- [4] [RFC 8452 - AES-GCM-SIV: Nonce Misuse-Resistant Authenticated Encryption](https://www.rfc-editor.org/rfc/rfc8452)
- [5] [RFC 4493 - AES-CMAC Algorithm](https://www.rfc-editor.org/rfc/rfc4493)
- [6] [RFC 7465 - RC4 Cipher Suites को Prohibit करना](https://www.rfc-editor.org/rfc/rfc7465)
- [7] [OWASP Web Security Testing Guide - Padding Oracle के लिए Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/02-Testing_for_Padding_Oracle)
- [8] [GCHQ CyberChef](https://gchq.github.io/CyberChef/)
- [9] [PyCryptodome documentation](https://www.pycryptodome.org/)
{{#include ../../banners/hacktricks-training.md}}
