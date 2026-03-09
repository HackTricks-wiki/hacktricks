# Symmetric Crypto

{{#include ../../banners/hacktricks-training.md}}

## CTFs में क्या देखें

- **मोड का गलत उपयोग**: ECB patterns, CBC malleability, CTR/GCM nonce reuse.
- **Padding oracles**: गलत padding के लिए अलग त्रुटियाँ/समय अंतर।
- **MAC confusion**: CBC-MAC का उपयोग variable-length messages के साथ, या MAC-then-encrypt गलतियाँ।
- **XOR everywhere**: stream ciphers और custom constructions अक्सर keystream के साथ XOR में घट जाते हैं।

## AES मोड और गलत उपयोग

### ECB: Electronic Codebook

ECB leaks patterns: equal plaintext blocks → equal ciphertext blocks. इससे ये संभव होता है:

- Cut-and-paste / block reordering
- Block deletion (यदि format मान्य रहता है)

यदि आप plaintext नियंत्रित कर सकते हैं और ciphertext (या cookies) देख सकते हैं, तो repeated blocks (उदा., कई `A`s) बनाकर repeats की तलाश करें।

### CBC: Cipher Block Chaining

- CBC **malleable** है: `C[i-1]` में बिट्स flip करने से `P[i]` में predictable बिट्स flip होते हैं।
- यदि सिस्टम valid padding बनाम invalid padding का पता लगाता है, तो आपके पास **padding oracle** हो सकता है।

### CTR

CTR AES को एक stream cipher में बदल देता है: `C = P XOR keystream`.

यदि nonce/IV एक ही key के साथ पुन: उपयोग किया जाता है:

- `C1 XOR C2 = P1 XOR P2` (classic keystream reuse)
- ज्ञात plaintext के साथ, आप keystream recover करके अन्य ciphertexts decrypt कर सकते हैं।

**Nonce/IV reuse exploitation patterns**

- जहाँ भी plaintext ज्ञात/अनुमान्य है, वहाँ से keystream recover करें:

```text
keystream[i..] = ciphertext[i..] XOR known_plaintext[i..]
```

Recover किए गए keystream बाइट्स को उसी offsets पर उसी key+IV के साथ बनाए गए किसी भी अन्य ciphertext को decrypt करने के लिए लागू करें।
- Highly structured data (उदा., ASN.1/X.509 certificates, file headers, JSON/CBOR) बड़े known-plaintext क्षेत्रों देती है। अक्सर आप certificate के predictable body के साथ ciphertext XOR करके keystream निकाल सकते हैं, फिर उसी reused IV के तहत encrypted अन्य secrets decrypt कर सकते हैं। सामान्य certificate layouts के लिए देखें [TLS & Certificates](../tls-and-certificates/README.md)।
- जब एक ही serialized format/size के कई secrets उसी key+IV के साथ encrypted हों, तो field alignment बिना पूर्ण known plaintext के भी leak कर देती है। उदाहरण: PKCS#8 RSA keys एक ही modulus size के लिए prime factors को matching offsets पर रखते हैं (~2048-bit के लिए ~99.6% alignment)। reused keystream के तहत दो ciphertexts को XOR करने से `p ⊕ p'` / `q ⊕ q'` अलग हो जाते हैं, जिन्हें सेकंडों में brute-recover किया जा सकता है।
- Libraries में default IVs (उदा., constant `000...01`) एक गंभीर footgun होते हैं: हर encryption एक ही keystream repeat करती है, जिससे CTR एक reused one-time pad में बदल जाता है।

**CTR malleability**

- CTR केवल confidentiality प्रदान करती है: ciphertext में बिट बदलने से plaintext में deterministic रूप से वही बिट बदलते हैं। बिना authentication tag के, attackers डेटा (उदा., keys, flags, या messages) को undetected तरीके से tamper कर सकते हैं।
- Bit-flips पकड़ने के लिए AEAD (GCM, GCM-SIV, ChaCha20-Poly1305, आदि) का उपयोग करें और tag verification लागू करें।

### GCM

GCM भी nonce reuse के तहत बुरी तरह टूट जाता है। यदि वही key+nonce एक से अधिक बार उपयोग हो, तो आमतौर पर आपको मिलता है:

- Encryption के लिए keystream reuse (CTR जैसा), जिससे किसी भी ज्ञात plaintext के साथ plaintext recovery संभव होता है।
- Integrity guarantees का नुकसान। जो कुछ expose होता है (एक ही nonce के तहत multiple message/tag pairs), उसके आधार पर attackers tags forge कर सकते हैं।

ऑपरेशनल मार्गदर्शन:

- AEAD में "nonce reuse" को critical vulnerability मानें।
- Misuse-resistant AEADs (उदा., GCM-SIV) nonce-misuse fallout को कम करते हैं पर फिर भी unique nonces/IVs आवश्यक हैं।
- यदि आपके पास एक ही nonce के तहत multiple ciphertexts हैं, तो `C1 XOR C2 = P1 XOR P2` जैसी relations से शुरुआत करें।

### Tools

- CyberChef for quick experiments: https://gchq.github.io/CyberChef/
- Python: `pycryptodome` for scripting

## ECB exploitation patterns

ECB (Electronic Code Book) प्रत्येक block को independently encrypt करता है:

- equal plaintext blocks → equal ciphertext blocks
- यह structure को leak करता है और cut-and-paste style attacks सक्षम बनाता है

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Detection idea: token/cookie pattern

यदि आप कई बार login करते हैं और **हमेशा वही cookie मिलता है**, तो ciphertext deterministic हो सकता है (ECB या fixed IV)।

यदि आप दो users बनाते हैं जिनका plaintext layout ज्यादातर समान है (उदा., लंबे repeated characters) और एक ही offsets पर repeated ciphertext blocks देखते हैं, तो ECB मुख्य संदेह है।

### Exploitation patterns

#### Removing entire blocks

यदि token format कुछ इस तरह है `<username>|<password>` और block boundary align हो, तो कभी-कभी आप ऐसा user craft कर सकते हैं कि `admin` block aligned आए, फिर preceding blocks हटा कर `admin` के लिए valid token प्राप्त कर लें।

#### Moving blocks

यदि backend padding/extra spaces (`admin` vs `admin    `) सहन करता है, तो आप:

- एक ऐसा block align करें जिसमें `admin   ` हो
- उस ciphertext block को दूसरे token में swap/reuse करें

## Padding Oracle

### यह क्या है

CBC mode में, यदि server decrypted plaintext के PKCS#7 padding के valid होने या न होने को (directly या indirectly) प्रकट करता है, तो आप अक्सर:

- ciphertext को बिना key के decrypt कर सकते हैं
- चुना हुआ plaintext encrypt कर सकते हैं (ciphertext forge कर सकते हैं)

Oracle हो सकता है:

- एक विशिष्ट error message
- अलग HTTP status / response size
- timing difference

### व्यावहारिक एक्सप्लॉइटेशन

PadBuster एक क्लासिक टूल है:

{{#ref}}
https://github.com/AonCyberLabs/PadBuster
{{#endref}}

Example:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 16 \
-encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
नोट:

- ब्लॉक साइज अक्सर `16` होता है (AES के लिए)।
- `-encoding 0` का मतलब Base64 है।
- अगर oracle कोई specific string है तो `-error` का उपयोग करें।

### यह क्यों काम करता है

CBC decryption computes `P[i] = D(C[i]) XOR C[i-1]`. यदि आप `C[i-1]` में बाइट्स बदलें और देखकर कि padding वैध है या नहीं, तो आप `P[i]` को बाइट-दर-बाइट पुनर्प्राप्त कर सकते हैं।

## Bit-flipping in CBC

padding oracle के बिना भी, CBC परिवर्तनीय है। अगर आप ciphertext ब्लॉक्स संशोधित कर सकते हैं और application decrypted plaintext को structured data के रूप में इस्तेमाल करती है (उदा., `role=user`), तो आप specific bits फ्लिप करके अगले ब्लॉक में चुने हुए plaintext बाइट्स को बदल सकते हैं।

सामान्य CTF पैटर्न:

- Token = `IV || C1 || C2 || ...`
- आप `C[i]` में बाइट्स नियंत्रित करते हैं
- आप `P[i+1]` में plaintext बाइट्स को लक्ष्य करते हैं क्योंकि `P[i+1] = D(C[i+1]) XOR C[i]`

यह स्वयं में confidentiality का ब्रेक नहीं है, पर जब integrity मौजूद नहीं होती तो यह एक सामान्य privilege-escalation primitive है।

## CBC-MAC

CBC-MAC केवल विशिष्ट शर्तों में ही सुरक्षित होता है (विशेषकर **fixed-length messages** और correct domain separation)।

### Classic variable-length forgery pattern

CBC-MAC आम तौर पर इस तरह से गणना किया जाता है:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

अगर आप चुने हुए messages के tags प्राप्त कर सकते हैं, तो आप अक्सर एक concatenation (या संबंधित संरचना) के लिए tag बना सकते हैं बिना key जाने, CBC के ब्लॉक चेनिंग के तरीके का फ़ायदा उठाकर।

यह अक्सर CTF cookies/tokens में दिखाई देता है जो username या role को CBC-MAC से MAC करते हैं।

### सुरक्षित विकल्प

- HMAC (SHA-256/512) का उपयोग करें
- CMAC (AES-CMAC) का सही तरीके से उपयोग करें
- message length / domain separation शामिल करें

## Stream ciphers: XOR and RC4

### मानसिक मॉडल

ज़्यादातर stream cipher मामलों में समीकरण यह होता है:

`ciphertext = plaintext XOR keystream`

तो:

- अगर आप plaintext जानते हैं, तो आप keystream प्राप्त कर लेते हैं।
- अगर keystream reuse होता है (same key+nonce), तो `C1 XOR C2 = P1 XOR P2`।

### XOR-based encryption

यदि आप किसी भी plaintext segment को position `i` पर जानते हैं, तो आप keystream बाइट्स पुनर्प्राप्त करके उन positions पर अन्य ciphertexts को decrypt कर सकते हैं।

Autosolvers:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 एक stream cipher है; encrypt और decrypt एक ही ऑपरेशन हैं।

यदि आप एक ही key के तहत ज्ञात plaintext का RC4 encryption प्राप्त कर सकते हैं, तो आप keystream पुनर्प्राप्त करके समान length/offset के अन्य संदेशों को decrypt कर सकते हैं।

Reference writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

## संदर्भ

- [Trail of Bits – Carelessness versus craftsmanship in cryptography](https://blog.trailofbits.com/2026/02/18/carelessness-versus-craftsmanship-in-cryptography/)

{{#include ../../banners/hacktricks-training.md}}
