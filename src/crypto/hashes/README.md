# Hashes, MACs और KDFs

{{#include ../../banners/hacktricks-training.md}}

## सामान्य CTF पैटर्न

- "Signature" वास्तव में `hash(secret || message)` है → length extension।
- बिना salt वाले password hashes → तेज़ repeated cracking और precomputed lookup attacks।
- hash को MAC समझ लेना (hash != authentication)।

## Hash length extension attack

### Technique

Length-extension attack संभव हो सकता है जब कोई server इस तरह का "signature" compute करता है:

`sig = HASH(secret || message)`

और MD5, SHA-1 या SHA-256 जैसे Merkle-Damgård hash का उपयोग करता है।

यदि आपको पता है:

- `message`
- `sig`
- hash function
- (या आप brute-force कर सकते हैं) `len(secret)`

तो आप इसके लिए valid signature compute कर सकते हैं:

`message || padding || appended_data`

secret जाने बिना।<sup>[[1]](#references)</sup>

### महत्वपूर्ण सीमा: HMAC प्रभावित नहीं होता

Length-extension attacks, `HASH(secret || message)` जैसे vulnerable prefix constructions पर लागू होते हैं। वे HMAC construction (उदाहरण के लिए, HMAC-SHA256) को expose नहीं करते, जो अलग-अलग inner और outer hash applications के साथ key को combine करता है।<sup>[[1]](#references)[[2]](#references)</sup>

### Tools

- [`hash_extender`](https://github.com/iagox86/hash_extender)<sup>[[3]](#references)</sup>
- [`hashpumpy`](https://pypi.org/project/hashpumpy/), HashPump length-extension tool के लिए Python bindings<sup>[[7]](#references)</sup>

### अच्छा explanation

[Hash length extension attacks के बारे में जानने योग्य सब कुछ](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)<sup>[[1]](#references)</sup>

## Password hashing और cracking

### पहले प्रश्न<sup>[[4]](#references)</sup>

- क्या यह **salted** है? (`salt$hash` formats देखें)
- क्या यह **fast hash** (MD5/SHA1/SHA256) है या **slow KDF** (bcrypt/scrypt/argon2/PBKDF2)?
- क्या आपके पास **format hint** (hashcat mode / John format) है?

### Practical workflow<sup>[[5]](#references)[[6]](#references)</sup>

1. Hash की पहचान करें:
- `hashid <hash>`
- `hashcat --example-hashes | rg -n "<pattern>"`
2. यदि unsalted और common है: crypto workflow section से online DBs और identification tooling आज़माएँ।
3. अन्यथा crack करें:
- `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
- `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### सामान्य गलतियाँ जिनका आप exploit कर सकते हैं

- Users के बीच same password reuse → एक को crack करें, pivot करें।
- Truncated hashes / custom transforms → normalize करके फिर प्रयास करें।
- Weak KDF parameters (जैसे, low PBKDF2 iterations) → फिर भी crackable।

## References

- [1] [SkullSecurity - Hash length-extension attacks के बारे में जानने योग्य सब कुछ](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
- [2] [NIST FIPS 198-1 - Keyed-Hash Message Authentication Code](https://csrc.nist.gov/pubs/fips/198-1/final)
- [3] [hash_extender](https://github.com/iagox86/hash_extender)
- [4] [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [5] [Hashcat example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [6] [John the Ripper command-line options](https://www.openwall.com/john/doc/OPTIONS.shtml)
- [7] [PyPI: `hashpumpy` Python bindings for HashPump](https://pypi.org/project/hashpumpy/)
{{#include ../../banners/hacktricks-training.md}}
