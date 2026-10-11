# Hashes, MACs & KDFs

{{#include ../../banners/hacktricks-training.md}}

## आम CTF पैटर्न

- "Signature" वास्तव में `hash(secret || message)` है → length extension.
- बिना salt वाले password hashes → तेज़ी से बार-बार cracking और precomputed lookup attacks.
- hash को MAC समझना (hash != authentication).

## Hash length extension attack

### तकनीक

Length-extension attack संभव हो सकता है जब कोई server इस तरह का "signature" compute करता है:

`sig = HASH(secret || message)`

और MD5, SHA-1 या SHA-256 जैसे Merkle-Damgård hash का उपयोग करता है।

अगर आपको पता है:

- `message`
- `sig`
- hash function
- (या आप brute-force कर सकते हैं) `len(secret)`

तो आप यह जाने बिना कि secret क्या है, इसके लिए valid signature compute कर सकते हैं:

`message || padding || appended_data`

<sup>[[1]](#references)</sup>

### अहम सीमा: HMAC प्रभावित नहीं होता

Length-extension attacks, `HASH(secret || message)` जैसी असुरक्षित prefix constructions पर लागू होते हैं। वे HMAC construction (उदाहरण के लिए, HMAC-SHA256) को उजागर नहीं करते, जिसमें key को अलग-अलग inner और outer hash applications के साथ जोड़ा जाता है।<sup>[[1]](#references)[[2]](#references)</sup>

### Tools

- [`hash_extender`](https://github.com/iagox86/hash_extender)<sup>[[3]](#references)</sup>
- [`hashpumpy`](https://pypi.org/project/hashpumpy/), HashPump length-extension tool के लिए Python bindings<sup>[[7]](#references)</sup>

### अच्छी व्याख्या

[Hash length extension attacks के बारे में वह सब कुछ जो आपको जानना चाहिए](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)<sup>[[1]](#references)</sup>

## Password hashing और cracking

### पहले पूछे जाने वाले सवाल<sup>[[4]](#references)</sup>

- क्या इसमें **salted** है? (`salt$hash` formats देखें)
- क्या यह **fast hash** (MD5/SHA1/SHA256) है या **slow KDF** (bcrypt/scrypt/argon2/PBKDF2)?
- क्या आपके पास **format hint** है (hashcat mode / John format)?

### व्यावहारिक workflow<sup>[[5]](#references)[[6]](#references)</sup>

1. Hash की पहचान करें:
   - `hashid <hash>`
   - `hashcat --example-hashes | rg -n "<pattern>"`
2. अगर hash बिना salt का और आम है: online DBs और crypto workflow section के identification tooling को आज़माएँ।
3. वरना crack करें:
   - `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
   - `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### आम गलतियाँ जिनका फ़ायदा उठाया जा सकता है

- अलग-अलग users द्वारा एक ही password का दोबारा उपयोग → एक को crack करें, फिर pivot करें।
- Truncated hashes / custom transforms → normalize करके फिर कोशिश करें।
- कमज़ोर KDF parameters (जैसे, PBKDF2 में कम iterations) → फिर भी crack किए जा सकते हैं।

### Appended secret के साथ chosen-input bcrypt oracle

ऐसा callable helper, जो `bcrypt(user_input || secret)` लौटाता है, appended secret के बारे में जानकारी उजागर कर सकता है, अगर उसका bcrypt implementation 72 **bytes** के बाद input को चुपचाप truncate करता हो। UTF-8 encoding से पहले character-count limit लगाने से उस byte limit का पालन सुनिश्चित नहीं होता: multibyte characters bcrypt input को भर सकते हैं और secret के केवल छोटे-से prefix के लिए जगह छोड़ सकते हैं। इसके बाद चुने गए inputs और लौटाए गए hashes से candidate suffix bytes को offline जाँचना संभव हो सकता है। इसके लिए helper के input पर नियंत्रण, उसके exact transform और encoding की जानकारी, और ऐसा implementation ज़रूरी है जो वास्तव में truncate करता हो; केवल callable helper या bcrypt hash से यह पूरी शृंखला साबित नहीं होती। [pyca/bcrypt का documentation](https://github.com/pyca/bcrypt#maximum-password-length) बताता है कि मौजूदा `hashpw` 72 bytes से बड़े inputs पर error देता है, जबकि पहले के behavior में उन्हें चुपचाप truncate किया जाता था। दूसरे wrappers लंबे inputs को prehash या reject कर सकते हैं, इसलिए truncation मान लेने के बजाय installed implementation को verify करें।

किसी दूसरे account के विरुद्ध मिले हुए secret का उपयोग करने के लिए यह सबूत भी चाहिए कि वहाँ उजागर hash उसी **secret** और transform से बनाया गया था, साथ ही एक अलग credential या login path भी चाहिए। Root के रूप में चलने वाले hashing helper को oracle तभी मानकर जाँचना चाहिए जब कम privilege वाला user उसे लागू policy के तहत invoke कर सके; passive host enumeration में उसे call करना या चुने हुए passwords भेजना आवश्यक नहीं है।

## References

- [1] [SkullSecurity - Hash length-extension attacks के बारे में वह सब कुछ जो आपको जानना चाहिए](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
- [2] [NIST FIPS 198-1 - Keyed-Hash Message Authentication Code](https://csrc.nist.gov/pubs/fips/198-1/final)
- [3] [hash_extender](https://github.com/iagox86/hash_extender)
- [4] [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [5] [Hashcat के example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [6] [John the Ripper के command-line options](https://www.openwall.com/john/doc/OPTIONS.shtml)
- [7] [PyPI: HashPump के लिए `hashpumpy` Python bindings](https://pypi.org/project/hashpumpy/)
{{#include ../../banners/hacktricks-training.md}}
