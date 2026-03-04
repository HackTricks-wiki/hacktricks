# Symmetric Crypto

{{#include ../../banners/hacktricks-training.md}}

## CTFs में क्या देखना है

- **मोड का गलत उपयोग**: ECB patterns, CBC malleability, CTR/GCM nonce reuse.
- **Padding oracles**: खराब padding के लिए अलग errors/timings।
- **MAC confusion**: CBC-MAC का variable-length messages के साथ उपयोग, या MAC-then-encrypt की गलतियाँ।
- **XOR everywhere**: stream ciphers और custom constructions अक्सर keystream के साथ XOR तक घटकर बचते हैं।

## AES modes and misuse

### ECB: Electronic Codebook

ECB leaks patterns: equal plaintext blocks → equal ciphertext blocks. इससे यह संभव होता है:

- Cut-and-paste / block reordering
- Block deletion (यदि format वैध बना रहता है)

यदि आप plaintext नियंत्रित कर सकते हैं और ciphertext (या cookies) देख सकते हैं, तो repeated blocks (उदा., कई `A`s) बनाकर repeats की तलाश करें।

### CBC: Cipher Block Chaining

- CBC is **malleable**: `C[i-1]` में bits flip करने से `P[i]` में predictable bits flip होते हैं।
- यदि सिस्टम valid padding और invalid padding को अलग तरह से प्रकट करता है, तो आपके पास एक **padding oracle** हो सकता है।

### CTR

CTR AES को एक stream cipher में बदल देता है: `C = P XOR keystream`.

यदि nonce/IV एक ही key के साथ reuse हो रहा है:

- `C1 XOR C2 = P1 XOR P2` (classic keystream reuse)
- Known plaintext होने पर आप keystream recover करके अन्य ciphertexts को decrypt कर सकते हैं।

**Nonce/IV reuse exploitation patterns**

- जहाँ भी plaintext known/guessable हो, वहाँ keystream recover करें:

```text
keystream[i..] = ciphertext[i..] XOR known_plaintext[i..]
```

Recover किए गए keystream bytes को apply कर के किसी भी अन्य ciphertext को decrypt करें जो उसी key+IV और offsets के साथ बनाया गया है।
- Highly structured data (उदा., ASN.1/X.509 certificates, file headers, JSON/CBOR) बड़े known-plaintext क्षेत्रों को देती है। अक्सर आप certificate के predictable body के साथ ciphertext XOR करके keystream निकाल सकते हैं, फिर उसी reused IV के तहत encrypt किए गए अन्य secrets को decrypt कर सकते हैं। सामान्य certificate layouts के लिए देखें [TLS & Certificates](../tls-and-certificates/README.md)।
- जब कई secrets एक ही serialized format/size में उसी key+IV के तहत encrypt होते हैं, तो field alignment leaks बिना पूरा known plaintext होने भी जानकारी देता है। उदाहरण: एक ही modulus size के PKCS#8 RSA keys prime factors को matching offsets पर रखते हैं (~2048-bit के लिए ~99.6% alignment)। reused keystream के तहत दो ciphertexts को XOR करने से `p ⊕ p'` / `q ⊕ q'` अलग हो जाते हैं, जिन्हें थोड़े समय में brute-recover किया जा सकता है।
- Libraries में default IVs (उदा., constant `000...01`) एक गंभीर footgun हैं: हर encryption वही keystream दोहराता है, CTR को एक reused one-time pad में बदल देता है।

**CTR malleability**

- CTR केवल confidentiality प्रदान करता है: ciphertext के bits flip करने से plaintext के वही bits deterministic तरीके से flip होते हैं। बिना authentication tag के, attackers डेटा में छेड़छाड़ कर सकते हैं (उदा., keys, flags, या messages tweak करना) बिना पता चले।
- Bit-flips पकड़ने के लिए AEAD (GCM, GCM-SIV, ChaCha20-Poly1305, आदि) और tag verification का उपयोग करें।

### GCM

GCM भी nonce reuse पर बुरी तरह टूट सकता है। यदि same key+nonce एक से अधिक बार उपयोग होता है, तो आमतौर पर आपको मिलता है:

- Encryption के लिए keystream reuse (CTR जैसा), जिससे किसी भी known plaintext के साथ plaintext recovery संभव होता है।
- Integrity guarantees का नुकसान। यह निर्भर करता है कि क्या expose किया जाता है (एक ही nonce के तहत कई message/tag pairs), attackers tags forge कर सकते हैं।

Operational guidance:

- AEAD में "nonce reuse" को critical vulnerability मानें।
- Misuse-resistant AEADs (उदा., GCM-SIV) nonce-misuse fallout को कम करते हैं पर फिर भी unique nonces/IVs की आवश्यकता होती है।
- यदि आपके पास एक ही nonce के तहत कई ciphertexts हैं, तो पहले `C1 XOR C2 = P1 XOR P2` जैसी relations जांचें।

### Tools

- CyberChef for quick experiments: https://gchq.github.io/CyberChef/
- Python: `pycryptodome` for scripting

## ECB exploitation patterns

ECB (Electronic Code Book) प्रत्येक block को independently encrypt करता है:

- equal plaintext blocks → equal ciphertext blocks
- यह structure को leaks करता है और cut-and-paste style attacks को सक्षम बनाता है

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Detection idea: token/cookie pattern

यदि आप कई बार login करते हैं और **हमेशा वही cookie मिलता है**, तो ciphertext deterministic हो सकता है (ECB या fixed IV)।

यदि आप दो users बनाते हैं जिनका plaintext layouts लगभग identical हैं (उदा., लंबे repeated characters) और आपने same offsets पर repeated ciphertext blocks देखे, तो ECB एक प्रमुख संदिग्ध है।

### Exploitation patterns

#### Removing entire blocks

यदि token format `<username>|<password>` जैसा है और block boundary align हो रहा है, तो आप कभी-कभार ऐसा user craft कर सकते हैं कि `admin` block aligned दिखाई दे, फिर preceding blocks हटा कर `admin` के लिए एक वैध token प्राप्त कर लें।

#### Moving blocks

यदि backend padding/extra spaces (उदा., `admin` बनाम `admin    `) सहन कर लेता है, आप कर सकते हैं:

- एक block align करें जिसमें `admin   ` हो
- उस ciphertext block को दूसरे token में swap/reuse करें

## Padding Oracle

### What it is

CBC mode में, यदि server यह बताता है (directly या indirectly) कि decrypted plaintext में **valid PKCS#7 padding** है या नहीं, तो आप अक्सर:

- बिना key के ciphertext decrypt कर सकते हैं
- chosen plaintext encrypt कर सकते हैं (ciphertext forge)

Oracle हो सकता है:

- कोई specific error message
- अलग HTTP status / response size
- timing difference

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

- Block size is often `16` for AES.
- `-encoding 0` means Base64.
- Use `-error` if the oracle is a specific string.

### यह क्यों काम करता है

CBC decryption computes `P[i] = D(C[i]) XOR C[i-1]`. `C[i-1]` में बाइट्स बदलकर और यह देख कर कि padding वैध है या नहीं, आप बाइट-दर-बाइट `P[i]` पुनर्प्राप्त कर सकते हैं।

## Bit-flipping in CBC

Even without a padding oracle, CBC is बदलने योग्य। अगर आप ciphertext ब्लॉक्स बदल सकें और एप्लिकेशन decrypted plaintext को structured data के रूप में उपयोग करता हो (उदाहरण के लिए, `role=user`), तो आप specific बिट्स flip करके अगले ब्लॉक में चुने गए position पर plaintext के कुछ बाइट बदल सकते हैं।

सामान्य CTF पैटर्न:

- Token = `IV || C1 || C2 || ...`
- You control bytes in `C[i]`
- You target plaintext bytes in `P[i+1]` because `P[i+1] = D(C[i+1]) XOR C[i]`

यह अपने आप में confidentiality का उल्लंघन नहीं है, लेकिन जब integrity मौजूद नहीं होती तो यह एक सामान्य privilege-escalation primitive होता है।

## CBC-MAC

CBC-MAC केवल कुछ विशिष्ट शर्तों के अंतर्गत ही सुरक्षित है (विशेष रूप से **fixed-length messages** और सही domain separation)।

### Classic variable-length forgery pattern

CBC-MAC सामान्यतः ऐसे निकाला जाता है:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

यदि आप चुने हुए संदेशों के लिए tags प्राप्त कर सकते हैं, तो आप अक्सर बिना key जाने भी concatenation (या संबंधित निर्माण) के लिए tag रचना कर सकते हैं, क्योंकि CBC ब्लॉकों को कैसे chain करता है उससे आप फायदा उठा सकते हैं।

यह अक्सर CTF cookies/tokens में दिखाई देता है जो username या role को CBC-MAC से MAC करते हैं।

### सुरक्षित विकल्प

- Use HMAC (SHA-256/512)
- Use CMAC (AES-CMAC) correctly
- संदेश की लंबाई / domain separation शामिल करें

## Stream ciphers: XOR and RC4

### मानसिक मॉडल

Most stream cipher situations reduce to:

`ciphertext = plaintext XOR keystream`

तो:

- अगर आप plaintext जानते हैं, तो आप keystream पुनर्प्राप्त कर लेते हैं।
- अगर keystream reuse होता है (same key+nonce), तो `C1 XOR C2 = P1 XOR P2` होता है।

### XOR-based encryption

यदि आप position `i` पर कोई भी plaintext segment जानते हैं, तो आप keystream बाइट्स recover कर सकते हैं और उन positions पर अन्य ciphertexts को decrypt कर सकते हैं।

Autosolvers:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 एक stream cipher है; encrypt/decrypt वही ऑपरेशन हैं।

यदि आप एक ही key के तहत known plaintext का RC4 encryption प्राप्त कर सकते हैं, तो आप keystream recover करके समान length/offset के अन्य संदेशों को decrypt कर सकते हैं।

Reference writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

## References

- [Trail of Bits – Carelessness versus craftsmanship in cryptography](https://blog.trailofbits.com/2026/02/18/carelessness-versus-craftsmanship-in-cryptography/)

{{#include ../../banners/hacktricks-training.md}}
