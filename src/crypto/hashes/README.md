# Hashes, MACs & KDFs

{{#include ../../banners/hacktricks-training.md}}

## सामान्य CTF पैटर्न

- "Signature" वास्तव में `hash(secret || message)` है → length extension।
- Unsalted password hashes → trivial cracking / lookup।
- Hash को MAC समझना (hash != authentication)।

## Hash length extension attack

### Technique

यदि कोई server इस तरह की "signature" compute करता है, तो आप अक्सर इसका exploit कर सकते हैं:

`sig = HASH(secret || message)`

और Merkle–Damgård hash का उपयोग करता है (classic examples: MD5, SHA-1, SHA-256)।

यदि आपको पता हो:

- `message`
- `sig`
- hash function
- (या आप brute-force कर सकते हों) `len(secret)`

तो आप बिना secret जाने, इसके लिए valid signature compute कर सकते हैं:

`message || padding || appended_data`

<sup>[[1]](#references)</sup>

### Important limitation: HMAC is not affected

Length extension attacks, Merkle–Damgård hashes के लिए `HASH(secret || message)` जैसी constructions पर लागू होते हैं। ये **HMAC** (जैसे HMAC-SHA256) पर लागू नहीं होते, जिसे विशेष रूप से इस प्रकार की समस्या से बचने के लिए design किया गया है।<sup>[[1]](#references)</sup>

### Tools

- hash_extender:
{{#ref}}
https://github.com/iagox86/hash_extender
{{#endref}}
- hashpump:
{{#ref}}
https://github.com/bwall/HashPump
{{#endref}}

### Good explanation

{{#ref}}
https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks
{{#endref}}

## Password hashing and cracking

### First questions

- क्या यह **salted** है? (`salt$hash` formats देखें)
- क्या यह **fast hash** (MD5/SHA1/SHA256) है या **slow KDF** (bcrypt/scrypt/argon2/PBKDF2)?
- क्या आपके पास **format hint** (hashcat mode / John format) है?

### Practical workflow

1. Hash की पहचान करें:
- `hashid <hash>`
- `hashcat --example-hashes | rg -n "<pattern>"`
2. यदि unsalted और common है: crypto workflow section से online DBs और identification tooling आज़माएँ।
3. अन्यथा crack करें:
- `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
- `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### Common mistakes you can exploit

- Users के बीच same password reuse → एक को crack करें, फिर pivot करें।
- Truncated hashes / custom transforms → normalize करके फिर प्रयास करें।
- Weak KDF parameters (जैसे, low PBKDF2 iterations) → अभी भी crackable।

## References

- [1] [Everything you need to know about hash length extension attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)

{{#include ../../banners/hacktricks-training.md}}
