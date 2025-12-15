# Hashes, MACs & KDFs

{{#include ../../banners/hacktricks-training.md}}

## सामान्य CTF पैटर्न

- "Signature" वास्तव में `hash(secret || message)` है → length extension.
- Unsalted password hashes → trivial cracking / lookup.
- hash और MAC को भ्रमित करना (hash != authentication).

## Hash length extension attack

### Technique

आप अक्सर इसका फायदा उठा सकते हैं अगर कोई सर्वर इस तरह का "signature" गणना करता है:

`sig = HASH(secret || message)`

और Merkle–Damgård hash का उपयोग करता है (क्लासिक उदाहरण: MD5, SHA-1, SHA-256).

यदि आपको पता हो:

- `message`
- `sig`
- hash function
- (या brute-force कर सकते हैं) `len(secret)`

तो आप एक वैध signature गणना कर सकते हैं:

`message || padding || appended_data`

बिना secret जाने।

### Important limitation: HMAC is not affected

Length extension attacks उन निर्माणों पर लागू होते हैं जैसे `HASH(secret || message)` जो Merkle–Damgård hashes के लिए हैं। वे **HMAC** (उदा., HMAC-SHA256) पर लागू नहीं होते, जो विशेष रूप से इस प्रकार की समस्या से बचने के लिए डिज़ाइन किया गया है।

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

### शुरुआती प्रश्न

- क्या यह **salted** है? (देखें `salt$hash` formats)
- क्या यह एक **fast hash** (MD5/SHA1/SHA256) है या एक **slow KDF** (bcrypt/scrypt/argon2/PBKDF2)?
- क्या आपके पास कोई **format hint** है (hashcat mode / John format)?

### व्यावहारिक वर्कफ़्लो

1. हैश की पहचान करें:
- `hashid <hash>`
- `hashcat --example-hashes | rg -n "<pattern>"`
2. यदि unsalted और सामान्य: ऑनलाइन DBs और identification tooling (crypto workflow सेक्शन) आज़माएँ।
3. अन्यथा crack करें:
- `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
- `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### सामान्य गलतियाँ जिनका आप फायदा उठा सकते हैं

- Same password reused across users → crack one, pivot.
- Truncated hashes / custom transforms → normalize and retry.
- Weak KDF parameters (e.g., low PBKDF2 iterations) → still crackable.

{{#include ../../banners/hacktricks-training.md}}
