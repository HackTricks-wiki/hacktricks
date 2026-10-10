# Hashes, MACs और KDFs

{{#include ../../banners/hacktricks-training.md}}

## सामान्य CTF पैटर्न

- "Signature" वास्तव में `hash(secret || message)` है → length extension.
- बिना salt वाले password hashes → तेज़ी से बार-बार cracking और पहले से तैयार lookup attacks.
- hash को MAC समझना (hash != authentication).

## Hash length extension attack

### तकनीक

Length-extension attack संभव हो सकता है, जब कोई server इस तरह का "signature" बनाता है:

`sig = HASH(secret || message)`

और Merkle-Damgård hash, जैसे MD5, SHA-1 या SHA-256, इस्तेमाल करता है।

अगर आपको पता है:

- `message`
- `sig`
- hash function
- (`len(secret)` को brute-force कर सकते हैं)

तो आप यह जाने बिना कि secret क्या है, इसके लिए valid signature निकाल सकते हैं:

`message || padding || appended_data`

<sup>[[1]](#references)</sup>

### महत्वपूर्ण सीमा: HMAC प्रभावित नहीं होता

Length-extension attacks, `HASH(secret || message)` जैसी vulnerable prefix constructions पर लागू होते हैं। ये HMAC construction (उदाहरण के लिए, HMAC-SHA256) को उजागर नहीं करते, क्योंकि इसमें key को अलग-अलग inner और outer hash applications के साथ जोड़ा जाता है।<sup>[[1]](#references)[[2]](#references)</sup>

### Tools

- [`hash_extender`](https://github.com/iagox86/hash_extender)<sup>[[3]](#references)</sup>
- [`hashpumpy`](https://pypi.org/project/hashpumpy/), HashPump length-extension tool के लिए Python bindings<sup>[[7]](#references)</sup>

### अच्छी व्याख्या

[Hash length extension attacks के बारे में जानने योग्य सब कुछ](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)<sup>[[1]](#references)</sup>

## Password hashing और cracking

### शुरुआती सवाल<sup>[[4]](#references)</sup>

- क्या इसमें **salt** है? (`salt$hash` formats देखें)
- क्या यह **fast hash** (MD5/SHA1/SHA256) है या **slow KDF** (bcrypt/scrypt/argon2/PBKDF2)?
- क्या आपके पास **format hint** (hashcat mode / John format) है?

### व्यावहारिक workflow<sup>[[5]](#references)[[6]](#references)</sup>

1. Hash पहचानें:
   - `hashid <hash>`
   - `hashcat --example-hashes | rg -n "<pattern>"`
2. अगर salt नहीं है और hash आम है: online DBs और crypto workflow section के identification tools आज़माएँ।
3. अन्यथा crack करें:
   - `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
   - `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### आम गलतियाँ जिनका आप फ़ायदा उठा सकते हैं

- अलग-अलग users द्वारा एक ही password का दोबारा इस्तेमाल → एक को crack करें, फिर pivot करें।
- Truncated hashes / custom transforms → normalize करके फिर कोशिश करें।
- कमजोर KDF parameters (जैसे, कम PBKDF2 iterations) → फिर भी crack किए जा सकते हैं।

### जोड़े गए secret के साथ Chosen-input bcrypt oracle

ऐसा callable helper जो `bcrypt(user_input || secret)` लौटाता है, जोड़े गए secret के बारे में जानकारी उजागर कर सकता है, अगर उसका bcrypt implementation चुपचाप input को 72 **bytes** के बाद truncate करता हो। UTF-8 encoding से पहले character-count limit लगाने से यह byte limit लागू नहीं होती: multibyte characters bcrypt input को भर सकते हैं और secret के केवल छोटे-से prefix के लिए जगह छोड़ सकते हैं। इसके बाद चुने गए inputs और उनसे लौटाए गए hashes की मदद से candidate suffix bytes को offline जाँचा जा सकता है। इसके लिए helper के input पर नियंत्रण, उसके exact transform और encoding की जानकारी, और वास्तव में truncate करने वाला implementation ज़रूरी है; केवल callable helper या bcrypt hash से यह पूरी प्रक्रिया साबित नहीं होती। [pyca/bcrypt दस्तावेज़](https://github.com/pyca/bcrypt#maximum-password-length) के अनुसार, वर्तमान `hashpw` 72 bytes से बड़े inputs पर error देता है, जबकि पुराने behavior में उन्हें चुपचाप truncate किया जाता था। दूसरे wrappers लंबे inputs को prehash या reject कर सकते हैं, इसलिए truncation मान लेने के बजाय installed implementation की जाँच करें।

Recovered secret को किसी दूसरे account के विरुद्ध इस्तेमाल करने के लिए यह प्रमाण भी चाहिए कि उसका उजागर hash **उसी** secret और transform से बनाया गया था, और इसके अलावा अलग credential या login path भी चाहिए। Root-run hashing helper को oracle तभी मानकर जाँचना चाहिए, जब कम privileged user उसे लागू policy के तहत invoke कर सकता हो; host की passive enumeration के लिए उसे call करना या चुने हुए passwords देना ज़रूरी नहीं है।

## References

- [1] [SkullSecurity - Hash length-extension attacks के बारे में जानने योग्य सब कुछ](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
- [2] [NIST FIPS 198-1 - Keyed-Hash Message Authentication Code](https://csrc.nist.gov/pubs/fips/198-1/final)
- [3] [hash_extender](https://github.com/iagox86/hash_extender)
- [4] [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [5] [Hashcat के उदाहरण hashes](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [6] [John the Ripper के command-line options](https://www.openwall.com/john/doc/OPTIONS.shtml)
- [7] [PyPI: `hashpumpy` - HashPump के लिए Python bindings](https://pypi.org/project/hashpumpy/)
{{#include ../../banners/hacktricks-training.md}}
