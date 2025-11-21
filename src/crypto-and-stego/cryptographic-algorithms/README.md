# क्रिप्टोग्राफिक/कम्प्रेशन एल्गोरिद्म

{{#include ../../banners/hacktricks-training.md}}

## एल्गोरिदम की पहचान

यदि किसी कोड में **right/left shifts, xors और कई अंकगणितीय ऑपरेशन्स** दिख रहे हों तो इसकी संभावना है कि यह किसी **क्रिप्टोग्राफिक एल्गोरिदम** का implementation है। यहाँ कुछ तरीके बताए गए हैं जिनसे बिना हर स्टेप को reverse किए आप प्रयोग किए गए एल्गोरिदम की पहचान कर सकते हैं।

### API फ़ंक्शन्स

**CryptDeriveKey**

यदि यह फ़ंक्शन उपयोग हो रहा है तो आप दूसरे पैरामीटर के मान को चेक करके पता लगा सकते हैं कि कौन सा **algorithm** उपयोग हो रहा है:

![](<../../images/image (156).png>)

यहाँ संभव एल्गोरिद्म और उनके असाइन किए गए मानों की तालिका देखें: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

**RtlCompressBuffer/RtlDecompressBuffer**

दिए गए डेटा बफ़र को compress और decompress करता है।

**CryptAcquireContext**

From [the docs](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta): The **CryptAcquireContext** function is used to acquire a handle to a particular key container within a particular cryptographic service provider (CSP). **This returned handle is used in calls to CryptoAPI** functions that use the selected CSP.

**CryptCreateHash**

Initiates the hashing of a stream of data. If this function is used, you can find which **algorithm is being used** checking the value of the second parameter:

![](<../../images/image (549).png>)

\
यहाँ संभव एल्गोरिद्म और उनके असाइन किए गए मानों की तालिका देखें: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

### कोड कॉन्स्टैंट्स

कभी-कभी किसी एल्गोरिद्म की पहचान करना बहुत आसान होता है क्योंकि वह किसी विशेष और अनूठे मान का उपयोग करता है।

![](<../../images/image (833).png>)

यदि आप पहले कॉन्स्टैंट को Google में खोजें तो यह मिलता है:

![](<../../images/image (529).png>)

इसलिए आप मान सकते हैं कि decompiled फ़ंक्शन एक **sha256 calculator** है।\
आप किसी भी अन्य कॉन्स्टैंट को खोजेंगे तो संभवतः वही परिणाम मिलेगा।

### डेटा जानकारी

यदि कोड में कोई महत्वपूर्ण कॉन्स्टैंट नहीं है तो यह संभव है कि यह **.data सेक्शन** से जानकारी लोड कर रहा हो।\
आप उस डेटा को एक्सेस कर के पहले dword को ग्रुप कर के पहले की तरह Google में खोज सकते हैं:

![](<../../images/image (531).png>)

इस मामले में, यदि आप **0xA56363C6** खोजते हैं तो यह पता चलता है कि यह **AES algorithm** की तालिकाओं से संबंधित है।

## RC4 **(Symmetric Crypt)**

### लक्षण

यह मुख्यतः 3 हिस्सों में होता है:

- **Initialization stage/**: 0x00 से 0xFF तक के मानों की एक तालिका बनाता है (कुल 256 bytes, 0x100)। इस तालिका को आमतौर पर **Substitution Box** (या SBox) कहा जाता है।
- **Scrambling stage**: पहले बनाए गए तालिका के माध्यम से लूप करेगा (0x100 इटरेशन्स) और हर मान को सेमी-रैंडम बाइट्स से बदल देगा। इन सेमी-रैंडम बाइट्स को बनाने के लिए RC4 **key** का उपयोग किया जाता है। RC4 keys की लंबाई 1 से 256 bytes तक हो सकती है, हालांकि आमतौर पर 5 से अधिक बाइट्स सुझाए जाते हैं। सामान्यतः RC4 keys 16 bytes की होती हैं।
- **XOR stage**: अंत में, plaintext या ciphertext को पहले बनाए गए मानों के साथ **XOR** किया जाता है। encrypt और decrypt के लिए वही फ़ंक्शन उपयोग होता है। इसके लिए बनाई गई 256 bytes के माध्यम से आवश्यकतानुसार कई बार लूप किया जाता है। यह आमतौर पर decompiled कोड में **%256 (mod 256)** के साथ पहचाना जाता है।

> [!TIP]
> **RC4 को disassembly/decompiled कोड में पहचानने के लिए आप 0x100 आकार के 2 लूप (key के उपयोग के साथ) और फिर इन 256 मानों के साथ इनपुट डेटा का XOR (संभवतः %256 के साथ) खोजें।**

### **Initialization stage/Substitution Box:** (ध्यान दें कि काउंटर में 256 का उपयोग हो रहा है और हर जगह 0 लिखा जा रहा है)

![](<../../images/image (584).png>)

### **Scrambling Stage:**

![](<../../images/image (835).png>)

### **XOR Stage:**

![](<../../images/image (904).png>)

## **AES (Symmetric Crypt)**

### **लक्षण**

- उपयोग होता है **substitution boxes और lookup tables** का
- AES को विशिष्ट lookup table मानों (constants) के उपयोग से पहचाना जा सकता है। _ध्यान दें कि ये **constants** बाइनरी में **स्टोर** हो सकते हैं या **डायनामिकली बनाए** जा सकते हैं।_
- **encryption key** को आमतौर पर 16 से विभाज्य होना चाहिए (अक्सर 32B) और आमतौर पर 16B का **IV** उपयोग होता है।

### SBox constants

![](<../../images/image (208).png>)

## Serpent **(Symmetric Crypt)**

### लक्षण

- इसे इस्तेमाल करते हुए मैलवेयर मिलना दुर्लभ है पर उदाहरण मौजूद हैं (Ursnif)
- यह इसकी लंबाई के आधार पर आसानी से पहचाना जा सकता है (बहुत लंबा फ़ंक्शन)

### पहचान

निम्न चित्र में ध्यान दें कि constant **0x9E3779B9** उपयोग हो रहा है (ध्यान दें कि यह constant अन्य क्रिप्टो एल्गोरिद्म जैसे **TEA** में भी उपयोग होता है)।\
साथ ही लूप का **आकार (132)** और डिसअसेंबली में XOR ऑपरेशन्स की संख्या पर ध्यान दें:

![](<../../images/image (547).png>)

जैसा पहले उल्लेख किया गया, यह कोड किसी भी decompiler में एक **बहुत लंबा फ़ंक्शन** के रूप में दिखाई देता है क्योंकि इसमें अंदर jumps नहीं होते। Decompiled कोड कुछ इस तरह दिख सकता है:

![](<../../images/image (513).png>)

इसलिए, आप इस एल्गोरिद्म को magic number और आरंभिक XORs देखकर, बहुत लंबे फ़ंक्शन को देखकर और कुछ निर्देशों की तुलना किसी implementation (जैसे shift left by 7 और rotate left by 22) से करके पहचान सकते हैं।

## RSA **(Asymmetric Crypt)**

### लक्षण

- symmetric algorithms से अधिक जटिल
- अक्सर कोई constants नहीं होते! (कस्टम implementations पहचानना मुश्किल)
- KANAL (a crypto analyzer) constants पर निर्भर करता है इसलिए RSA में संकेत नहीं देता।

### तुलना द्वारा पहचान

![](<../../images/image (1113).png>)

- लाइन 11 (बाएँ) में `+7) >> 3` है जो लाइन 35 (दाएं) में `+7) / 8` के समान है
- लाइन 12 (बाएँ) यह चेक कर रही है कि `modulus_len < 0x040` और लाइन 36 (दाएँ) में यह चेक है कि `inputLen+11 > modulusLen`

## MD5 & SHA (hash)

### लक्षण

- 3 फ़ंक्शन्स: Init, Update, Final
- initialize फ़ंक्शन्स समान

### पहचान

**Init**

आप constants की जाँच करके दोनों की पहचान कर सकते हैं। ध्यान दें कि sha_init में एक अतिरिक्त constant होता है जो MD5 में नहीं है:

![](<../../images/image (406).png>)

**MD5 Transform**

ध्यान दें कि अधिक constants का उपयोग होता है

![](<../../images/image (253) (1) (1).png>)

## CRC (hash)

- यह छोटा और अधिक प्रभावी है क्योंकि इसका फ़ंक्शन डेटा में आकस्मिक परिवर्तनों का पता लगाना है
- lookup tables का उपयोग करता है (इसलिए आप constants से पहचान कर सकते हैं)

### पहचान

Lookup table constants चेक करें:

![](<../../images/image (508).png>)

एक CRC hash algorithm इस प्रकार दिखता है:

![](<../../images/image (391).png>)

## APLib (Compression)

### लक्षण

- पहचाने जाने योग्य constants नहीं होते
- आप एल्गोरिद्म को Python में लिखने की कोशिश कर सकते हैं और ऑनलाइन मिलते-जुलते उदाहरण खोज सकते हैं

### पहचान

ग्राफ काफी बड़ा होता है:

![](<../../images/image (207) (2) (1).png>)

पहचानने के लिए 3 तुलनियाँ देखें:

![](<../../images/image (430).png>)

## Elliptic-Curve Signature Implementation Bugs

### EdDSA scalar range enforcement (HashEdDSA malleability)

- FIPS 186-5 §7.8.2 के अनुसार HashEdDSA verifiers को signature `sig = R || s` को विभाजित करना चाहिए और किसी भी scalar को अस्वीकार करना चाहिए जिसका `s \geq n` हो, जहाँ `n` group order है। `elliptic` JS library ने उस bound check को छोड़ दिया, इसलिए कोई भी attacker जो वैध जोड़ी `(msg, R || s)` जानता है वह alternate signatures बना सकता है `s' = s + k·n` और फिर से `sig' = R || s'` के रूप में encode कर सकता है।
- verification routines केवल `s mod n` को उपयोग करती हैं, इसलिए सभी `s'` जो `s` के समकक्ष हैं स्वीकार किए जाते हैं भले ही वे अलग byte strings हों। सिस्टम जो signatures को canonical tokens के रूप में मानते हैं (blockchain consensus, replay caches, DB keys, आदि) desynchronize हो सकते हैं क्योंकि सख्त implementations `s'` को reject करेंगी।
- अन्य HashEdDSA कोड का ऑडिट करते समय सुनिश्चित करें कि parser both point `R` और scalar length को validate करता है; किसी ज्ञात-सही `s` में `n` के गुणा जोड़कर देखें ताकि यह सुनिश्चित हो कि verifier बंद (fails closed) कर रहा है।

### ECDSA truncation vs. leading-zero hashes

- ECDSA verifiers को message hash `H` के केवल बाएँ सबसे अधिक `log2(n)` बिट्स का उपयोग करना चाहिए। `elliptic` में, truncation helper ने `delta = (BN(msg).byteLength()*8) - bitlen(n)` की गणना की; `BN` constructor leading zero octets को हटाता है, इसलिए किसी भी hash जो ≥4 zero bytes से शुरू होता है (secp192r1 जैसे curves पर, 192-bit order) वह 256 के बजाय केवल 224 बिट्स दिखाई देता था।
- verifier ने 64 की जगह 32 बिट्स right-shift किए, जिससे एक `E` बना जो signer द्वारा उपयोग किए गए मान से मेल नहीं खाता। उन hashes पर वैध signatures इसलिए SHA-256 input के लिए ≈`2^-32` संभावना से असफल होते हैं।
- लक्ष्य implementation पर “all good” वेरिएंट और leading-zero वेरिएंट (उदा., Wycheproof `ecdsa_secp192r1_sha256_test.json` case `tc296`) दोनों फीड करें; यदि verifier signer से असहमत है तो आपने एक exploitable truncation bug पाया है।

### Wycheproof vectors को लाइब्रेरीज़ पर चलाना
- Wycheproof JSON टेस्ट सेट भेजता है जो malformed points, malleable scalars, असामान्य hashes और अन्य corner cases को encode करते हैं। `elliptic` (या किसी भी crypto library) के चारों ओर एक harness बनाना सरल है: JSON लोड करें, प्रत्येक test case को deserialize करें, और assert करें कि implementation अपेक्षित `result` flag से मेल खाती है।
```javascript
for (const tc of ecdsaVectors.testGroups) {
const curve = new EC(tc.curve);
const pub = curve.keyFromPublic(tc.key, 'hex');
const ok = curve.verify(tc.msg, tc.sig, pub, 'hex', tc.msgSize);
assert.strictEqual(ok, tc.result === 'valid');
}
```
- विफलताओं को triage किया जाना चाहिए ताकि spec उल्लंघनों और false positives में अंतर किया जा सके। ऊपर के दोनों बग्स के लिए, असफल Wycheproof केसों ने तुरंत missing scalar range checks (EdDSA) और incorrect hash truncation (ECDSA) की ओर संकेत किया।
- हर्नेस को CI में एकीकृत करें ताकि scalar parsing, hash handling, या coordinate validity में होने वाले regressions जैसे ही आ जाएं, वे टेस्ट तुरंत ट्रिगर हों। यह खासकर high-level languages (JS, Python, Go) के लिए उपयोगी है जहाँ सूक्ष्म bignum conversions आसानी से गलत हो सकते हैं।

## संदर्भ

- [Trail of Bits - We found cryptography bugs in the elliptic library using Wycheproof](https://blog.trailofbits.com/2025/11/18/we-found-cryptography-bugs-in-the-elliptic-library-using-wycheproof/)
- [Wycheproof Test Suite](https://github.com/C2SP/wycheproof)

{{#include ../../banners/hacktricks-training.md}}
