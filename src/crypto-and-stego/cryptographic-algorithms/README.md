# क्रिप्टोग्राफिक/कम्प्रेशन एल्गोरिदम

{{#include ../../banners/hacktricks-training.md}}

## एल्गोरिदम की पहचान

अगर किसी कोड में आप कोड़े (shift rights and lefts, xors and several arithmetic operations) देखते हैं तो संभावना अधिक है कि वह किसी क्रिप्टोग्राफिक एल्गोरिथ्म का इम्प्लीमेंटेशन है। यहाँ कुछ तरीके बताए जा रहे हैं जिनसे आप किसी एल्गोरिथ्म की पहचान कर सकते हैं बिना हर स्टेप को रिवर्स किये।

### API फ़ंक्शन

**CryptDeriveKey**

यदि यह फ़ंक्शन उपयोग में है, तो आप दूसरे पैरामीटर के मान की जाँच करके पता लगा सकते हैं कि कौन सा **algorithm** उपयोग हो रहा है:

![](<../../images/image (156).png>)

संभावित एल्गोरिदम और उनके असाइन किए गए मानों की तालिका यहाँ देखें: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

**RtlCompressBuffer/RtlDecompressBuffer**

दिये गए डेटा बफर को compress और decompress करता है।

**CryptAcquireContext**

Docs के अनुसार: The **CryptAcquireContext** function is used to acquire a handle to a particular key container within a particular cryptographic service provider (CSP). **This returned handle is used in calls to CryptoAPI** functions that use the selected CSP.

**CryptCreateHash**

डेटा स्ट्रीम की hashing शुरू करता है। अगर यह फ़ंक्शन उपयोग में है, तो आप दूसरे पैरामीटर के मान को देखकर पता लगा सकते हैं कि कौन सा **algorithm** उपयोग हो रहा है:

![](<../../images/image (549).png>)

\
संभावित एल्गोरिदम और उनके असाइन किए गए मानों की तालिका यहाँ देखें: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

### Code constants

कभी-कभी किसी एल्गोरिथ्म की पहचान करना आसान होता है क्योंकि वह किसी विशेष और यूनिक मान का उपयोग करता है।

![](<../../images/image (833).png>)

यदि आप Google पर पहले constant की खोज करते हैं तो आपको ऐसा परिणाम मिलता है:

![](<../../images/image (529).png>)

इसलिए आप मान सकते हैं कि decompiled फ़ंक्शन एक **sha256 calculator** है।\
आप अन्य constants में से किसी की भी खोज कर के (संभावित रूप से) वही परिणाम पा सकेंगे।

### डेटा जानकारी

यदि कोड में कोई महत्वपूर्ण constant नहीं है तो संभव है कि वह .data सेक्शन से जानकारी लोड कर रहा हो।\
आप उस डेटा तक पहुँच कर पहले dword को समूहित कर सकते हैं और जैसा पहले किया गया था उसे Google पर खोज सकते हैं:

![](<../../images/image (531).png>)

इस उदाहरण में, यदि आप **0xA56363C6** खोजते हैं तो आप पाएंगे कि यह **AES algorithm** की तालिकाओं से जुड़ा है।

## RC4 **(Symmetric Crypt)**

### विशेषताएँ

यह 3 मुख्य भागों से बना है:

- **Initialization stage/**: 0x00 से 0xFF तक (कुल 256 bytes, 0x100) मानों की एक तालिका बनाता है। इस तालिका को आमतौर पर **Substitution Box (SBox)** कहा जाता है।
- **Scrambling stage**: पहले बनायी गयी तालिका के माध्यम से लूप चलेगा (0x100 इटरेशन्स का लूप) और प्रत्येक मान को कुछ **semi-random** बाइट्स से बदल देगा। ये semi-random बाइट्स बनाने के लिए RC4 **key** का उपयोग होता है। RC4 **keys** की लंबाई 1 से 256 bytes तक हो सकती है, लेकिन आमतौर पर 5 bytes से ऊपर होना सलाह दी जाती है। सामान्यत: RC4 keys 16 bytes लंबे होते हैं।
- **XOR stage**: अंत में, plain-text या cyphertext को पहले बनाए गए मानों के साथ **XOR** किया जाता है। encrypt और decrypt के लिए एक ही फ़ंक्शन उपयोग होता है। इसके लिए बनाई गयी 256 bytes के माध्यम से जितनी बार ज़रूरी हो उतनी बार लूप किया जाएगा। यह अक्सर decompiled कोड में एक **%256 (mod 256)** के साथ पहचाना जाता है।

> [!TIP]
> **RC4 को disassembly/decompiled code में पहचानने के लिए आप 0x100 साइज के 2 लूप (key के उपयोग के साथ) और उसके बाद इन 256 मानों के साथ इनपुट डेटा का XOR (शायद %256 उपयोग करते हुए) खोजें।**

### **Initialization stage/Substitution Box:** (नोट करें कि counter के रूप में 256 का उपयोग हो रहा है और प्रत्येक स्थान पर 0 लिखा जा रहा है)

![](<../../images/image (584).png>)

### **Scrambling Stage:**

![](<../../images/image (835).png>)

### **XOR Stage:**

![](<../../images/image (904).png>)

## **AES (Symmetric Crypt)**

### **विशेषताएँ**

- substitution boxes और lookup tables का उपयोग
- विशिष्ट lookup table मानों (constants) के उपयोग से AES की पहचान संभव है। _ध्यान दें कि ये **constant** बाइनरी में **store** किए जा सकते हैं या **dynamically** बनाए जा सकते हैं।_
- **encryption key** को 16 से विभाज्य होना चाहिए (आमतौर पर 32B) और सामान्यत: 16B का **IV** उपयोग किया जाता है।

### SBox constants

![](<../../images/image (208).png>)

## Serpent **(Symmetric Crypt)**

### विशेषताएँ

- इसका उपयोग करने वाला malware कम मिलता है लेकिन उदाहरण मौजूद हैं (Ursnif)
- इसकी पहचान उसके आकार के आधार पर सरल है (बहुत लंबा फ़ंक्शन)

### पहचान

निम्न चित्र में ध्यान दें कि constant **0x9E3779B9** का उपयोग हो रहा है (ध्यान दें कि यह constant अन्य crypto algorithms जैसे **TEA** में भी उपयोग होता है).\
साथ ही लूप का **size** (**132**) और disassembly निर्देशों व कोड उदाहरण में XOR ऑपरेशनों की संख्या पर ध्यान दें:

![](<../../images/image (547).png>)

जैसा कि पहले बताया गया था, यह कोड किसी भी decompiler में **बहुत लंबे फ़ंक्शन** के रूप में दिखेगा क्योंकि इसमें अंदर jumps कम होते हैं। decompiled कोड कुछ इस तरह दिखाई दे सकता है:

![](<../../images/image (513).png>)

इसलिए, आप magic number और आरंभिक XORs की जाँच करके, बहुत लंबे फ़ंक्शन को देखकर और कुछ निर्देशों (जैसे shift left by 7 और rotate left by 22) की तुलना किसी known implementation से करके इस एल्गोरिद्म की पहचान कर सकते हैं।

## RSA **(Asymmetric Crypt)**

### विशेषताएँ

- symmetric एल्गोरिथ्म्स की तुलना में जटिल
- कोई constants नहीं! (custom implementations की पहचान कठिन)
- KANAL (a crypto analyzer) RSA पर संकेत देने में विफल रहता है क्योंकि वह constants पर निर्भर करता है।

### तुलना द्वारा पहचान

![](<../../images/image (1113).png>)

- लाइन 11 (बाएँ) में `+7) >> 3` है जो लाइन 35 (दाएँ) में `+7) / 8` जैसा ही है
- लाइन 12 (बाएँ) यह जाँच रही है कि `modulus_len < 0x040` और लाइन 36 (दाएँ) में यह जाँच है कि `inputLen+11 > modulusLen`

## MD5 & SHA (hash)

### विशेषताएँ

- 3 फ़ंक्शन्स: Init, Update, Final
- initialize फ़ंक्शन्स समान

### पहचान

**Init**

आप constants देखकर दोनों की पहचान कर सकते हैं। ध्यान दें कि sha_init में MD5 में न होने वाला 1 constant होता है:

![](<../../images/image (406).png>)

**MD5 Transform**

ध्यान दें अधिक constants का उपयोग

![](<../../images/image (253) (1) (1).png>)

## CRC (hash)

- यह छोटे और अधिक प्रभावी है क्योंकि इसका उद्देश्य डेटा में आकस्मिक परिवर्तनों का पता लगाना है
- lookup tables का उपयोग करता है (इसलिए आप constants से पहचान सकते हैं)

### पहचान

lookup table constants जाँचें:

![](<../../images/image (508).png>)

एक CRC hash algorithm इस तरह दिखता है:

![](<../../images/image (391).png>)

## APLib (Compression)

### विशेषताएँ

- पहचान योग्य constants नहीं होते
- आप एल्गोरिथ्म को python में लिखकर और ऑनलाइन समान चीजें खोजकर पहचानने की कोशिश कर सकते हैं

### पहचान

ग्राफ काफी बड़ा है:

![](<../../images/image (207) (2) (1).png>)

पहचानने के लिए **3 comparisons** देखें:

![](<../../images/image (430).png>)

## Elliptic-Curve Signature Implementation Bugs

### EdDSA scalar range enforcement (HashEdDSA malleability)

- FIPS 186-5 §7.8.2 के अनुसार HashEdDSA verifiers को एक signature `sig = R || s` को split करके किसी भी scalar को reject करना चाहिए जिसका `s \geq n` है, जहाँ `n` समूह का order है। `elliptic` JS library ने उस bound चेक को छोड़ दिया, इसलिए कोई भी attacker जो वैध जोड़ी `(msg, R || s)` जानता है वह alternate signatures `s' = s + k·n` forge कर सकता है और `sig' = R || s'` को बार-बार पुन: encode कर सकता है।
- verification routines केवल `s mod n` का उपयोग करते हैं, इसलिए सभी `s'` जो `s` के congruent हैं स्वीकार हो जाते हैं भले ही वे अलग byte strings हों। सिस्टम जो signatures को canonical tokens के रूप में मानते हैं (जैसे blockchain consensus, replay caches, DB keys, आदि) असमंजस में पड़ सकते हैं क्योंकि strict implementations `s'` को reject कर देंगे।
- जब आप अन्य HashEdDSA कोड का audit कर रहे हों, सुनिश्चित करें कि parser दोनों, point `R` और scalar की length को validate करे; किसी known-good `s` में `n` के multiples जोड़ कर चेक करें कि verifier closed तरीके से fail करता है।

### ECDSA truncation vs. leading-zero hashes

- ECDSA verifiers को message hash `H` के केवल leftmost `log2(n)` bits का उपयोग करना चाहिए। `elliptic` में truncation helper ने `delta = (BN(msg).byteLength()*8) - bitlen(n)` की गणना की; `BN` constructor leading zero octets को drop कर देता है, इसलिए कोई भी hash जो ≥4 zero bytes से शुरू होता है जैसे curves पर secp192r1 (192-bit order) पर वह 224 bits के रूप में दिखाई दे सकता था बजाय 256 के।
- verifier ने 64 की बजाय 32 बिट्स right-shift किया, जिससे एक ऐसा `E` बना जो signer द्वारा उपयोग किए गए मान से मेल नहीं खाता। उन hashes पर वैध signatures इसलिए लगभग `2^-32` की संभावना से fail करते हैं जब इनपुट SHA-256 होते हैं।
- लक्ष्य implementation पर दोनों “सामान्य” वेक्टर और leading-zero variants (उदाहरण के लिए Wycheproof `ecdsa_secp192r1_sha256_test.json` केस `tc296`) feed करें; यदि verifier signer से असहमत है, तो आपने एक exploitable truncation bug पाया है।

### Wycheproof vectors का libraries के खिलाफ उपयोग करना
- Wycheproof JSON test sets भेजता है जो malformed points, malleable scalars, unusual hashes और अन्य corner cases encode करते हैं। `elliptic` (या किसी भी crypto library) के चारों ओर एक harness बनाना सरल है: JSON लोड करें, प्रत्येक test case को deserialize करें, और assert करें कि implementation अपेक्षित `result` flag से मेल खाती है।
```javascript
for (const tc of ecdsaVectors.testGroups) {
const curve = new EC(tc.curve);
const pub = curve.keyFromPublic(tc.key, 'hex');
const ok = curve.verify(tc.msg, tc.sig, pub, 'hex', tc.msgSize);
assert.strictEqual(ok, tc.result === 'valid');
}
```
- त्रुटियों को श्रेणीबद्ध किया जाना चाहिए ताकि spec उल्लंघनों को false positives से अलग किया जा सके। ऊपर दिए गए दो बग्स के लिए, असफल Wycheproof मामलों ने तुरंत scalar range checks (EdDSA) की कमी और गलत hash truncation (ECDSA) की ओर इशारा किया।
- हर्नेस को CI में एकीकृत करें ताकि scalar parsing, hash handling, या coordinate validity में regressions जैसे ही प्रवेश करें परीक्षण स्वतः ट्रिगर हो जाएँ। यह उच्च-स्तरीय भाषाओं (JS, Python, Go) के लिए विशेष रूप से उपयोगी है, जहाँ सूक्ष्म bignum conversions आसानी से गलत हो सकते हैं।

## संदर्भ

- [Trail of Bits - We found cryptography bugs in the elliptic library using Wycheproof](https://blog.trailofbits.com/2025/11/18/we-found-cryptography-bugs-in-the-elliptic-library-using-wycheproof/)
- [Wycheproof Test Suite](https://github.com/C2SP/wycheproof)

{{#include ../../banners/hacktricks-training.md}}
