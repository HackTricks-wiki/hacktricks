# सममित क्रिप्टो

{{#include ../../banners/hacktricks-training.md}}

## CTFs में क्या देखें

- **Mode misuse**: ECB patterns, CBC malleability, CTR/GCM nonce reuse.
- **Padding oracles**: खराब padding के लिए अलग-अलग errors/timings।
- **MAC confusion**: variable-length messages के साथ CBC-MAC का उपयोग, या MAC-then-encrypt की गलतियाँ।
- **हर जगह XOR**: stream ciphers और custom constructions अक्सर keystream के साथ XOR तक सीमित हो जाते हैं।

## AES modes और उनका गलत उपयोग

NIST, SP 800-38A में ECB, CBC और CTR confidentiality modes तथा SP 800-38D में GCM authenticated encryption निर्दिष्ट करता है।<sup>[[2]](#references)[[3]](#references)</sup>

### ECB: Electronic Codebook

ECB patterns leak करता है: समान plaintext blocks → समान ciphertext blocks। इससे ये संभव होते हैं:

- Cut-and-paste / block reordering
- Block deletion (अगर format वैध बना रहे)

अगर आप plaintext नियंत्रित कर सकते हैं और ciphertext (या cookies) देख सकते हैं, तो दोहराए गए blocks बनाने की कोशिश करें (जैसे, बहुत सारे `A`) और देखें कि कोई blocks दोहराए गए हैं या नहीं।

### CBC: Cipher Block Chaining

- CBC **malleable** है: `C[i-1]` में bits flip करने से `P[i]` में अनुमानित bits flip होते हैं, साथ ही `P[i-1]` भी बिगड़ जाता है। IV में बदलाव करके पहले plaintext block को बदला जा सकता है, बिना उससे पहले के किसी plaintext block को बिगाड़े।
- अगर system valid padding और invalid padding के लिए अलग-अलग परिणाम दिखाता है, तो आपके पास **padding oracle** हो सकता है।

### CTR

CTR, AES को stream cipher में बदल देता है: `C = P XOR keystream`।

अगर एक ही key के साथ nonce/IV दोबारा इस्तेमाल किया जाता है:

- `C1 XOR C2 = P1 XOR P2` (classic keystream reuse)
- ज्ञात plaintext से आप keystream प्राप्त करके दूसरे ciphertexts को decrypt कर सकते हैं।

**Nonce/IV reuse के exploitation patterns**

- जहाँ plaintext ज्ञात हो या उसका अनुमान लगाया जा सके, वहाँ keystream प्राप्त करें:

  ```text
  keystream[i..] = ciphertext[i..] XOR known_plaintext[i..]
  ```

  बरामद keystream bytes को उन्हीं offsets पर समान key+IV से बने किसी अन्य ciphertext को decrypt करने के लिए लागू करें।
- अत्यधिक संरचित डेटा (जैसे ASN.1/X.509 certificates, file headers, JSON/CBOR) में known-plaintext के बड़े क्षेत्र होते हैं। अक्सर certificate के ciphertext को अनुमानित certificate body के साथ XOR करके keystream निकाला जा सकता है, फिर उसी IV के दोबारा उपयोग के तहत encrypted अन्य secrets को decrypt किया जा सकता है। सामान्य certificate layouts के लिए [TLS & Certificates](../tls-and-certificates/README.md) भी देखें।<sup>[[1]](#references)</sup>
- जब समान **serialized format/size** के कई secrets को एक ही key+IV से encrypt किया जाता है, तो पूरे known plaintext के बिना भी field alignment leak होता है। उदाहरण: समान modulus size वाली PKCS#8 RSA keys में prime factors एक जैसे offsets पर होते हैं (2048-bit के लिए ~99.6% alignment)। दो ciphertexts को दोबारा इस्तेमाल किए गए keystream के तहत XOR करने से `p ⊕ p'` / `q ⊕ q'` अलग हो जाते हैं, जिन्हें कुछ ही सेकंड में brute-force करके रिकवर किया जा सकता है।<sup>[[1]](#references)</sup>
- Libraries में default IVs (जैसे constant `000...01`) एक गंभीर footgun हैं: हर encryption में वही keystream दोहराई जाती है, जिससे CTR दोबारा इस्तेमाल किए गए one-time pad में बदल जाता है।<sup>[[1]](#references)</sup>

**CTR malleability**

- CTR केवल confidentiality देता है: ciphertext में bits flip करने से plaintext में भी वही bits deterministic तरीके से flip होते हैं। Authentication tag के बिना, attackers बिना पता चले data में छेड़छाड़ कर सकते हैं (जैसे keys, flags या messages बदलना)।
- Bit-flips पकड़ने के लिए AEAD (GCM, GCM-SIV, ChaCha20-Poly1305 आदि) का उपयोग करें और tag verification अनिवार्य करें।

### GCM

Nonce के दोबारा इस्तेमाल पर GCM भी गंभीर रूप से असुरक्षित हो जाता है। यदि समान key+nonce का एक से अधिक बार उपयोग किया जाता है, तो आम तौर पर ये परिणाम मिलते हैं:

- Encryption के लिए keystream का दोबारा इस्तेमाल (CTR की तरह), जिससे कोई plaintext ज्ञात होने पर plaintext रिकवर किया जा सकता है।
- Integrity guarantees का खत्म होना। क्या जानकारी उजागर है इस पर निर्भर करते हुए (उसी nonce के तहत कई message/tag pairs), attackers tags forge कर सकते हैं।

Operational guidance:

- AEAD में "nonce reuse" को एक गंभीर vulnerability मानें।
- AES-GCM-SIV जैसे misuse-resistant AEADs nonce reuse के नुकसान को कम करते हैं। Callers को फिर भी construction के interface के अनुसार unique nonces देने चाहिए; सामान्य GCM की तुलना में आकस्मिक reuse के परिणाम सीमित होते हैं।<sup>[[3]](#references)[[4]](#references)</sup>
- यदि आपके पास समान nonce के तहत कई ciphertexts हैं, तो `C1 XOR C2 = P1 XOR P2` जैसे संबंधों की जाँच से शुरुआत करें।

### Tools

- त्वरित प्रयोगों के लिए [CyberChef](https://gchq.github.io/CyberChef/).<sup>[[8]](#references)</sup>
- Scripting के लिए Python का [PyCryptodome](https://www.pycryptodome.org/) package.<sup>[[9]](#references)</sup>

## ECB exploitation patterns

ECB (Electronic Code Book) हर block को स्वतंत्र रूप से encrypt करता है:

- समान plaintext blocks → समान ciphertext blocks
- इससे structure leak होता है और cut-and-paste style attacks संभव होते हैं

![ECB mode decryption block diagram](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Detection idea: token/cookie pattern

यदि आप कई बार login करते हैं और **हर बार वही cookie मिलती है**, तो ciphertext deterministic हो सकता है (ECB या fixed IV)।

यदि आप लगभग समान plaintext layouts वाले दो users बनाते हैं (जैसे, लंबे दोहराए गए characters) और समान offsets पर दोहराए गए ciphertext blocks देखते हैं, तो ECB एक प्रमुख संदिग्ध है।

### Exploitation patterns

#### पूरे blocks हटाना

यदि token format कुछ ऐसा है `<username>|<password>` और block boundary सही जगह पर align होती है, तो कभी-कभी ऐसा user बनाया जा सकता है जिससे `admin` block align हो जाए, फिर उससे पहले के blocks हटाकर `admin` के लिए valid token प्राप्त किया जा सकता है।

#### Blocks स्थानांतरित करना

यदि backend padding/अतिरिक्त spaces (`admin` बनाम `admin    `) स्वीकार करता है, तो आप:

- `admin   ` वाला block align कर सकते हैं
- उस ciphertext block को किसी दूसरे token में swap/reuse कर सकते हैं

## Padding Oracle

### यह क्या है

CBC mode में, यदि server यह बताता है (सीधे या परोक्ष रूप से) कि decrypted plaintext में **valid PKCS#7 padding** है या नहीं, तो अक्सर आप:<sup>[[7]](#references)</sup>

- key के बिना ciphertext decrypt कर सकते हैं
- ऐसा ciphertext बना सकते हैं जो chosen plaintext में decrypt हो, जब आप crafted preceding blocks या IVs submit कर सकें और application resulting validly padded message को स्वीकार करे

Oracle इनमें से कुछ हो सकता है:

- कोई विशिष्ट error message
- HTTP status / response size में अंतर
- Timing में अंतर

### Practical exploitation

PadBuster एक क्लासिक tool है:

{{#ref}}
https://github.com/AonCyberLabs/PadBuster
{{#endref}}

उदाहरण:

```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 16 \
  -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```

नोट्स:

- AES के लिए block size अक्सर `16` होता है।
- `-encoding 0` का अर्थ Base64 है।
- यदि oracle कोई विशिष्ट string है, तो `-error` का उपयोग करें।

### यह कैसे काम करता है

CBC decryption `P[i] = D(C[i]) XOR C[i-1]` की गणना करता है। `C[i-1]` में bytes को बदलकर और यह देखकर कि padding valid है या नहीं, आप `P[i]` को byte-by-byte recover कर सकते हैं।

## CBC में bit-flipping

Padding oracle के बिना भी CBC malleable होता है। यदि आप ciphertext blocks को बदल सकते हैं और application decrypted plaintext को structured data (जैसे, `role=user`) के रूप में इस्तेमाल करती है, तो आप अगले block में चुनी हुई position पर विशिष्ट plaintext bytes बदलने के लिए कुछ bits को flip कर सकते हैं।

आम CTF pattern:

- Token = `IV || C1 || C2 || ...`
- `C[i]` में bytes पर आपका नियंत्रण है
- आप `P[i+1]` में plaintext bytes को target करते हैं, क्योंकि `P[i+1] = D(C[i+1]) XOR C[i]`

यह अपने-आप में confidentiality को नहीं तोड़ता, लेकिन integrity मौजूद न होने पर privilege-escalation का एक आम primitive है।

## CBC-MAC

CBC-MAC केवल विशिष्ट शर्तों के तहत secure होता है (विशेष रूप से **fixed-length messages** और सही domain separation)। AES-CMAC एक standardized construction है, जो variable-length inputs को सुरक्षित रूप से संभालता है।<sup>[[5]](#references)</sup>

### Variable-length forgery का पारंपरिक pattern

CBC-MAC की गणना आमतौर पर इस तरह की जाती है:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

यदि आप चुने हुए messages के tags प्राप्त कर सकते हैं, तो अक्सर key जाने बिना CBC के blocks को chain करने के तरीके का फ़ायदा उठाकर concatenation (या उससे संबंधित construction) के लिए tag तैयार कर सकते हैं।

यह अक्सर उन CTF cookies/tokens में दिखता है जो username या role पर CBC-MAC का उपयोग करते हैं।

### अधिक सुरक्षित विकल्प

- HMAC (SHA-256/512) का उपयोग करें
- CMAC (AES-CMAC) का सही तरीके से उपयोग करें
- Message length / domain separation शामिल करें

## Stream ciphers: XOR और RC4

### मानसिक मॉडल

अधिकांश stream cipher स्थितियों को इस तरह समझा जा सकता है:

`ciphertext = plaintext XOR keystream`

इसलिए:

- यदि आपको plaintext पता है, तो आप keystream recover कर सकते हैं।
- यदि keystream का दोबारा उपयोग किया जाता है (वही key+nonce), तो `C1 XOR C2 = P1 XOR P2`।

### XOR-आधारित encryption

यदि आपको position `i` पर plaintext का कोई भी segment पता है, तो आप keystream bytes recover करके उन्हीं positions पर दूसरे ciphertexts को decrypt कर सकते हैं।

Autosolvers:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 एक legacy stream cipher है; encrypt/decrypt एक ही XOR operation हैं। इसके ज्ञात biases के कारण यह नए systems के लिए अनुपयुक्त है, और TLS इसके cipher suites पर स्पष्ट रूप से रोक लगाता है।<sup>[[6]](#references)</sup>

यदि आपको उसी key के तहत ज्ञात plaintext का RC4 encryption मिल सकता है, तो आप keystream recover करके समान length/offset वाले दूसरे messages को decrypt कर सकते हैं।

Reference writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

## References

- [1] [Trail of Bits – Cryptography में लापरवाही बनाम शिल्प-कौशल](https://blog.trailofbits.com/2026/02/18/carelessness-versus-craftsmanship-in-cryptography/)
- [2] [NIST SP 800-38A - Block Cipher Modes of Operation के लिए अनुशंसा](https://csrc.nist.gov/pubs/sp/800/38/a/final)
- [3] [NIST SP 800-38D - Galois/Counter Mode (GCM) और GMAC के लिए अनुशंसा](https://csrc.nist.gov/pubs/sp/800/38/d/final)
- [4] [RFC 8452 - AES-GCM-SIV: Nonce के गलत उपयोग के प्रति प्रतिरोधी Authenticated Encryption](https://www.rfc-editor.org/rfc/rfc8452)
- [5] [RFC 4493 - AES-CMAC Algorithm](https://www.rfc-editor.org/rfc/rfc4493)
- [6] [RFC 7465 - RC4 Cipher Suites पर रोक](https://www.rfc-editor.org/rfc/rfc7465)
- [7] [OWASP Web Security Testing Guide - Padding Oracle की जाँच](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/02-Testing_for_Padding_Oracle)
- [8] [GCHQ CyberChef](https://gchq.github.io/CyberChef/)
- [9] [PyCryptodome दस्तावेज़](https://www.pycryptodome.org/)
{{#include ../../banners/hacktricks-training.md}}
