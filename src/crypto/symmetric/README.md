# Symmetric Crypto

{{#include ../../banners/hacktricks-training.md}}

## CTFs में क्या देखें

- **Mode misuse**: ECB patterns, CBC malleability, CTR/GCM nonce reuse.
- **Padding oracles**: गलत padding के लिए अलग त्रुटि संदेश/समयांतर।
- **MAC confusion**: CBC-MAC का उपयोग variable-length messages के साथ, या MAC-then-encrypt की गलतियाँ।
- **XOR everywhere**: stream ciphers और custom constructions अक्सर keystream के साथ XOR तक सिमट जाती हैं।

## AES modes and misuse

### ECB: Electronic Codebook

ECB leaks patterns: equal plaintext blocks → equal ciphertext blocks. That enables:

- Cut-and-paste / block reordering
- Block deletion (यदि format वैध रहता है)

यदि आप plaintext को नियंत्रित कर सकते हैं और ciphertext (या cookies) को देख सकते हैं, तो repeated blocks (उदा., कई `A`s) बनाकर repeats की तलाश करें।

### CBC: Cipher Block Chaining

- CBC is **malleable**: `C[i-1]` में बिट्स बदलने से `P[i]` में अनुमानित बिट्स बदल जाते हैं।
- यदि सिस्टम valid padding बनाम invalid padding को उजागर करता है, तो आपके पास एक **padding oracle** हो सकता है।

### CTR

CTR AES को एक stream cipher में बदल देता है: `C = P XOR keystream`.

यदि nonce/IV को उसी key के साथ पुन: उपयोग किया जाता है:

- `C1 XOR C2 = P1 XOR P2` (classic keystream reuse)
- ज्ञात plaintext के साथ, आप keystream recover कर सकते हैं और अन्य को decrypt कर सकते हैं।

### GCM

GCM भी nonce reuse पर बुरी तरह टूट सकता है। यदि वही key+nonce एक से अधिक बार उपयोग हुआ है, तो सामान्यतः आपको मिलता है:

- Encryption के लिए keystream reuse (CTR की तरह), जिससे किसी भी ज्ञात plaintext के साथ plaintext recovery संभव हो जाता है।
- Integrity guarantees का नुकसान। जो कुछ एक्सपोज़ होता है उसके आधार पर (एक ही nonce के तहत multiple message/tag pairs), attackers tags को forge कर सकते हैं।

ऑपरेशनल मार्गदर्शन:

- AEAD में "nonce reuse" को एक critical vulnerability मानें।
- यदि आपके पास एक ही nonce के तहत multiple ciphertexts हैं, तो `C1 XOR C2 = P1 XOR P2` जैसी relations की जाँच करके शुरु करें।

### Tools

- Quick experiments के लिए CyberChef: https://gchq.github.io/CyberChef/
- Python: scripting के लिए `pycryptodome`

## ECB exploitation patterns

ECB (Electronic Code Book) प्रत्येक block को स्वतंत्र रूप से encrypt करता है:

- equal plaintext blocks → equal ciphertext blocks
- यह structure को leak करता है और cut-and-paste style attacks को सक्षम बनाता है

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Detection idea: token/cookie pattern

यदि आप कई बार login करते हैं और **हमेशा वही cookie मिलता है**, तो ciphertext deterministic हो सकता है (ECB या fixed IV)।

यदि आप दो users बनाते हैं जिनके plaintext layouts ज्यादातर समान हों (उदा., लंबे repeated characters) और समान offsets पर repeated ciphertext blocks दिखें, तो ECB मुख्य संदिग्ध है।

### Exploitation patterns

#### Removing entire blocks

यदि token का format कुछ `<username>|<password>` जैसा है और block boundary align होता है, तो आप कभी-कभी ऐसा user craft कर सकते हैं ताकि `admin` block aligned दिखे, फिर पिछले blocks को हटाकर `admin` के लिए वैध token प्राप्त कर सकते हैं।

#### Moving blocks

यदि backend padding/extra spaces (`admin` vs `admin    `) सहन कर देता है, तो आप:

- एक block align करें जिसमें `admin   ` मौजूद हो
- उस ciphertext block को दूसरे token में swap/reuse करें

## Padding Oracle

### What it is

In CBC mode, यदि server यह (सीधे या indirectly) बताता है कि decrypted plaintext में **valid PKCS#7 padding** है या नहीं, तो आप अक्सर:

- बिना key के ciphertext को decrypt कर सकते हैं
- चुने हुए plaintext को encrypt कर सकते हैं (ciphertext forge)

Oracle हो सकता है:

- एक specific error message
- अलग HTTP status / response size
- timing का अंतर

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
नोट्स:

- ब्लॉक साइज अक्सर `16` होता है (AES के लिए)।
- `-encoding 0` का मतलब Base64 है।
- यदि oracle एक विशिष्ट string है तो `-error` का उपयोग करें।

### Why it works

CBC decryption computes `P[i] = D(C[i]) XOR C[i-1]`. `C[i-1]` में बाइट्स बदलकर और यह देखकर कि padding वैध है या नहीं, आप बाइट-दर-बाइट `P[i]` को रिकवर कर सकते हैं।

## Bit-flipping in CBC

padding oracle के बिना भी, CBC परिवर्तनीय (malleable) है। यदि आप ciphertext blocks संशोधित कर सकते हैं और application decrypted plaintext को structured data के रूप में उपयोग करती है (उदाहरण के लिए, `role=user`), तो आप specific bits flip करके अगले ब्लॉक में चुने हुए स्थान पर plaintext bytes बदल सकते हैं।

Typical CTF pattern:

- Token = `IV || C1 || C2 || ...`
- आप `C[i]` में बाइट्स नियंत्रित करते हैं
- आप `P[i+1]` में plaintext bytes को टार्गेट करते हैं क्योंकि `P[i+1] = D(C[i+1]) XOR C[i]`

यह अपने आप confidentiality का उल्लंघन नहीं है, लेकिन जब integrity मौजूद नहीं होती तो यह सामान्य privilege-escalation primitive बन जाता है।

## CBC-MAC

CBC-MAC केवल विशिष्ट शर्तों के तहत ही सुरक्षित है (विशेषकर **fixed-length messages** और सही domain separation)।

### Classic variable-length forgery pattern

CBC-MAC आमतौर पर इस तरह से निकाला जाता है:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

यदि आप चुने हुए messages के लिए tags प्राप्त कर सकते हैं, तो आप अक्सर बिना key जाने भी CBC के ब्लॉक्स कैसे chain होते हैं इसका फायदा उठाकर concatenation (या संबंधित निर्माण) के लिए एक tag तैयार कर सकते हैं।

यह अक्सर CTF cookies/tokens में दिखाई देता है जो username या role को CBC-MAC से MAC करते हैं।

### Safer alternatives

- HMAC (SHA-256/512) का उपयोग करें
- CMAC (AES-CMAC) को सही तरीके से उपयोग करें
- message length / domain separation शामिल करें

## Stream ciphers: XOR and RC4

### The mental model

अधिकांश stream cipher स्थितियाँ इस रूप में घटकर आती हैं:

`ciphertext = plaintext XOR keystream`

तो:

- यदि आप plaintext जानते हैं, तो आप keystream रिकवर कर लेते हैं।
- यदि keystream reuse होता है (same key+nonce), तो `C1 XOR C2 = P1 XOR P2`।

### XOR-based encryption

यदि आप किसी भी plaintext segment को position `i` पर जानते हैं, तो आप keystream बाइट्स रिकवर करके उन positions पर अन्य ciphertexts को decrypt कर सकते हैं।

Autosolvers:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 एक stream cipher है; encrypt/decrypt समान ऑपरेशन हैं।

यदि आप उसी key के तहत ज्ञात plaintext का RC4 encryption प्राप्त कर सकते हैं, तो आप keystream रिकवर करके समान length/offset के अन्य messages को decrypt कर सकते हैं।

Reference writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
