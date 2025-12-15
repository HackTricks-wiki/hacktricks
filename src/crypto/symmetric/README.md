# Symmetric Crypto

{{#include ../../banners/hacktricks-training.md}}

## CTFs में क्या देखना चाहिए

- **Mode misuse**: ECB patterns, CBC malleability, CTR/GCM nonce reuse.
- **Padding oracles**: खराब padding के लिए अलग त्रुटियाँ/टाइमिंग।
- **MAC confusion**: CBC-MAC का प्रयोग variable-length messages के साथ, या MAC-then-encrypt गलतियाँ।
- **XOR everywhere**: stream ciphers और custom constructions अक्सर keystream के साथ XOR तक घटकर रह जाते हैं।

## AES modes and misuse

### ECB: Electronic Codebook

ECB leaks patterns: equal plaintext blocks → equal ciphertext blocks. यह अनुमति देता है:

- Cut-and-paste / block reordering
- Block deletion (यदि format वैध रहता है)

यदि आप plaintext नियंत्रित कर सकते हैं और ciphertext (या cookies) देख सकते हैं, तो repeated blocks (उदा., बहुत सारे `A`s) बनाकर repeats देखें।

### CBC: Cipher Block Chaining

- CBC is **malleable**: `C[i-1]` में bits flip करने से `P[i]` में predictable bits flip होते हैं।
- यदि सिस्टम valid padding बनाम invalid padding अलग प्रकट करता है, तो आपके पास एक **padding oracle** हो सकता है।

### CTR

CTR AES को एक stream cipher में बदल देता है: `C = P XOR keystream`.

यदि nonce/IV को same key के साथ reuse किया गया है:

- `C1 XOR C2 = P1 XOR P2` (classic keystream reuse)
- Known plaintext के साथ, आप keystream recover करके दूसरों को decrypt कर सकते हैं।

### GCM

GCM भी nonce reuse पर बुरी तरह टूट सकता है। यदि same key+nonce एक से अधिक बार उपयोग किया गया है, तो सामान्यतः आपको मिलता है:

- Encryption के लिए keystream reuse (CTR जैसी), जिससे किसी भी known plaintext से plaintext recovery संभव हो सकती है।
- Integrity guarantees का नुकसान। यह निर्भर करता है कि क्या expose होता है (same nonce के तहत multiple message/tag pairs), attackers tags forge कर सकते हैं।

ऑपरेशनल मार्गदर्शन:

- AEAD में "nonce reuse" को एक critical vulnerability मानें।
- यदि आपके पास same nonce के तहत कई ciphertexts हैं, तो `C1 XOR C2 = P1 XOR P2` जैसी रिलेशनशिप्स की जाँच से शुरू करें।

### Tools

- CyberChef for quick experiments: https://gchq.github.io/CyberChef/
- Python: `pycryptodome` for scripting

## ECB exploitation patterns

ECB (Electronic Code Book) प्रत्येक block को स्वतंत्र रूप से encrypt करता है:

- equal plaintext blocks → equal ciphertext blocks
- यह structure को leaks करता है और cut-and-paste style attacks को सक्षम बनाता है

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Detection idea: token/cookie pattern

यदि आप कई बार login करते हैं और **हमेशा वही cookie मिलता है**, तो ciphertext deterministic हो सकता है (ECB या fixed IV)।

यदि आप दो users बनाते हैं जिनके plaintext layouts अधिकतर समान हों (उदा., लंबे repeated characters) और same offsets पर repeated ciphertext blocks देखें, तो ECB मुख्य संदेह है।

### Exploitation patterns

#### Removing entire blocks

यदि token का प्रारूप `<username>|<password>` जैसा है और block boundary align करता है, तो आप कभी-कभी ऐसा user craft कर सकते हैं ताकि `admin` block aligned दिखे, फिर preceding blocks को हटाकर `admin` के लिए एक valid token प्राप्त कर सकते हैं।

#### Moving blocks

यदि backend padding/extra spaces (`admin` vs `admin    `) सहन करता है, तो आप:

- उस block को align करें जिसमें `admin   ` होता है
- उस ciphertext block को दूसरे token में swap/reuse करें

## Padding Oracle

### What it is

CBC mode में, यदि server (सीधे या परोक्ष रूप से) यह बताता है कि decrypted plaintext में **valid PKCS#7 padding** है या नहीं, तो आप अक्सर:

- बिना key के ciphertext को decrypt कर सकते हैं
- चुनी हुई plaintext encrypt कर सकते हैं (ciphertext forge करना)

Oracle हो सकता है:

- एक विशिष्ट त्रुटि संदेश
- अलग HTTP status / response size
- समय अंतर

### Practical exploitation

PadBuster is the classic tool:

{{#ref}}
https://github.com/AonCyberLabs/PadBuster
{{#endref}}

उदाहरण:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 16 \
-encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
नोट्स:

- ब्लॉक साइज अक्सर `16` होता है AES के लिए।
- `-encoding 0` का मतलब Base64 होता है।
- अगर oracle एक विशिष्ट स्ट्रिंग है तो `-error` का उपयोग करें।

### Why it works

CBC डिक्रिप्शन `P[i] = D(C[i]) XOR C[i-1]` गणना करता है। `C[i-1]` में बाइट्स बदलकर और यह देखकर कि padding वैध है या नहीं, आप बाइट-दर-बाइट `P[i]` रिकवर कर सकते हैं।

## Bit-flipping in CBC

padding oracle के बिना भी, CBC परिवर्तनीय (malleable) होता है। अगर आप ciphertext ब्लॉक्स में बदलाव कर सकते हैं और application डिक्रिप्टेड plaintext को structured data के रूप में उपयोग करता है (उदा., `role=user`), तो आप अगले ब्लॉक में चुने हुए स्थान पर specific plaintext बाइट्स बदलने के लिए बिट्स flip कर सकते हैं।

Typical CTF pattern:

- Token = `IV || C1 || C2 || ...`
- आप `C[i]` में बाइट्स नियंत्रित करते हैं
- आप `P[i+1]` में plaintext बाइट्स को टारगेट करते हैं क्योंकि `P[i+1] = D(C[i+1]) XOR C[i]`

यह अपने आप में confidentiality का ब्रेक नहीं है, लेकिन जब integrity मौजूद नहीं होती तो यह एक आम privilege-escalation primitive होता है।

## CBC-MAC

CBC-MAC केवल विशेष शर्तों के अंतर्गत सुरक्षित होता है (खासकर **fixed-length messages** और सही domain separation)।

### Classic variable-length forgery pattern

CBC-MAC आमतौर पर इस तरह से गणना किया जाता है:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

अगर आप चुने हुए messages के लिए tags प्राप्त कर सकते हैं, तो आप अक्सर बिना key जाने concatenation (या संबंधित निर्माण) के लिए एक tag तैयार कर सकते हैं, क्योंकि CBC ब्लॉक्स कैसे chain करता है इसे एक्सप्लॉइट करके।

यह अक्सर CTF cookies/tokens में दिखाई देता है जो username या role को CBC-MAC से MAC करते हैं।

### Safer alternatives

- Use HMAC (SHA-256/512)
- Use CMAC (AES-CMAC) correctly
- Include message length / domain separation

## Stream ciphers: XOR and RC4

### The mental model

अधिकांश stream cipher स्थितियाँ इस रूप में घटित होती हैं:

`ciphertext = plaintext XOR keystream`

तो:

- अगर आप plaintext जानते हैं, तो आप keystream रिकवर कर लेते हैं।
- अगर keystream reuse होता है (same key+nonce), तो `C1 XOR C2 = P1 XOR P2`।

### XOR-based encryption

अगर आप किसी भी plaintext segment को position `i` पर जानते हैं, तो आप keystream बाइट्स रिकवर कर सकते हैं और उन positions पर अन्य ciphertexts को डिक्रिप्ट कर सकते हैं।

Autosolvers:

- https://wiremask.eu/tools/xor-cracker/

### RC4

RC4 एक stream cipher है; encrypt/decrypt वही ऑपरेशन हैं।

अगर आप वही key के तहत known plaintext का RC4 encryption प्राप्त कर सकते हैं, तो आप keystream रिकवर कर सकते हैं और वही length/offset के अन्य मैसेजेस को डिक्रिप्ट कर सकते हैं।

Reference writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
