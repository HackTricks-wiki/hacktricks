# Hashes, MACs & KDFs

{{#include ../../banners/hacktricks-training.md}}

## आम CTF पैटर्न

- "Signature" वास्तव में `hash(secret || message)` है → length extension.
- बिना salt वाले password hashes → तेज़ी से बार-बार cracking और पहले से तैयार lookup attacks.
- hash को MAC समझने की गलती (hash != authentication).

## चुने गए input के लिए MD5 hash खोज

ये Python उदाहरण दो अलग-अलग output patterns खोजते हैं: चुना गया MD5 suffix और ऐसा MD5 value जो `0e` से शुरू हो और जिसके बाद केवल अंक हों। दूसरा pattern तब प्रासंगिक होता है जब कोई application numeric strings की ढीली तुलना करती है; PHP-विशिष्ट व्यवहार और version संबंधी सावधानियों के लिए [PHP loose comparisons](../../network-services-pentesting/pentesting-web/php-tricks-esp/README.md#loose-comparisons-and-type-juggling) देखें।

### MD5 hash suffix brute force

```python
import hashlib

target = '2f2e2e' #/..
candidate = 0
while True:
    plaintext = str(candidate)
    hash = hashlib.md5(plaintext.encode('ascii')).hexdigest()
    if hash[-1*(len(target)):] == target: #End in target
        print('plaintext:"' + plaintext + '", md5:' + hash)
        break
    candidate = candidate + 1
```

### ढीली तुलना के लिए MD5 0e hash जनरेशन

```python
#From isHaacK
import hashlib
from multiprocessing import Process, Queue, cpu_count


def loose_comparison(queue, num):
	target = '0e'
	plaintext = f"a_prefix{str(num)}a_suffix"
	hash = hashlib.md5(plaintext.encode('ascii')).hexdigest()

	if hash[:len(target)] == target and not any(x in "abcdef" for x in hash[2:]):
		print('plaintext: ' + plaintext + ', md5: ' + hash)
		queue.put("done") # triggers program exit

def worker(queue, thread_i, threads):
	for num in range(thread_i, 100**50, threads):
		loose_comparison(queue, num)

def main():
	procs = []
	queue = Queue()
	threads = cpu_count() # 2

	for thread_i in range(threads):
		proc = Process(target=worker, args=(queue, thread_i, threads ))
		proc.daemon = True # kill all subprocess when main process exits.
		procs.append(proc)
		proc.start()

	while queue.empty(): # exits when a subprocess is done
		pass
	return 0

main()
```

## Hash length extension attack

### तकनीक

जब कोई सर्वर इस तरह का "signature" बनाता है, तो length-extension attack संभव हो सकता है:

`sig = HASH(secret || message)`

और MD5, SHA-1 या SHA-256 जैसे Merkle-Damgård hash का उपयोग करता है।

अगर आपको पता है:

- `message`
- `sig`
- hash function
- (या आप brute-force कर सकते हैं) `len(secret)`

तो आप secret जाने बिना इसके लिए valid signature बना सकते हैं:

`message || padding || appended_data`

<sup>[[1]](#references)</sup>

### महत्वपूर्ण सीमा: HMAC प्रभावित नहीं होता

Length-extension attacks, `HASH(secret || message)` जैसी असुरक्षित prefix constructions पर लागू होते हैं। वे HMAC construction (उदाहरण के लिए, HMAC-SHA256) को उजागर नहीं करते, जो key को अलग-अलग inner और outer hash applications के साथ जोड़ता है।<sup>[[1]](#references)[[2]](#references)</sup>

### Tools

- [`hash_extender`](https://github.com/iagox86/hash_extender)<sup>[[3]](#references)</sup>
- [`hashpumpy`](https://pypi.org/project/hashpumpy/), HashPump length-extension tool के लिए Python bindings<sup>[[7]](#references)</sup>

### अच्छी व्याख्या

[Everything you need to know about hash length extension attacks](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)<sup>[[1]](#references)</sup>

## अस्पष्ट tuple hashing और MACs

### Boundary-confusion attack

Incremental hash APIs, call boundaries को authenticate नहीं करते। `update(A); update(B)` उसी byte string का hash करता है जिसका `update(A + B)` करता है। इसलिए raw concatenation को hash या MAC करने से tuple authenticate नहीं होता। अगर साथ-साथ के fields की लंबाई variable हो, तो attacker underlying hash में collision ढूँढे बिना bytes को अलग tuple में पुनर्विभाजित कर सकता है:<sup>[[8]](#references)[[9]](#references)</sup>

```python
import hashlib

def raw_hash(parts):
    h = hashlib.sha256()
    for part in parts:
        h.update(part)
    return h.digest()

assert raw_hash([b"alice", b"admin"]) == raw_hash([b"aliceadmin", b""])
```

यह तब exploitable हो जाता है जब verifier मानता है कि digest, fields के अर्थों को बाँधता है, लेकिन attacker-controlled input किसी दूसरे parser या protocol चरण तक पहुँच सकता है, जो अलग boundaries तय करता है। Commitments के alternate openings हो सकते हैं और Fiat-Shamir transcripts को अलग statements के रूप में समझा जा सकता है। HMAC [hash length extension](#hash-length-extension-attack) को रोकता है, लेकिन `HMAC(K, A || B)` में फिर भी यही tuple-encoding ambiguity रहती है, क्योंकि दोनों tuples से वही message bytes बनते हैं।<sup>[[8]](#references)[[9]](#references)</sup>

यह जाँचने के लिए इस audit workflow का उपयोग करें कि ambiguous tuple encoding किसी security boundary को पार करती है या नहीं।<sup>[[8]](#references)[[9]](#references)</sup>

1. `HASH(A || B)`, `HMAC(K, A || B)`, और दो या उससे अधिक fields पर लगातार होने वाले `update()`/`Write()` calls खोजें।
2. हर attacker-controlled या variable-length field को चिह्नित करें। पूरी concatenation को समान रखते हुए, हर boundary पर bytes को एक field से दूसरे में ले जाने की कोशिश करें। खाली fields भी शामिल करें।
3. Delimiter schemes में जाँचें कि inputs में delimiter bytes हो सकते हैं या नहीं, escaping में असहमति है या नहीं, और क्या कुछ fields की ही length encode की जाती है।
4. पता लगाएँ कि हर consumer authenticated bytes को कैसे parse करता है। कोई alternate partition तभी महत्वपूर्ण है जब उससे security decision, proof statement, record, transaction या commitment opening बदलती हो। Fixed-width fields या canonical, injective serialization इस विशेष attack को रोकते हैं।
5. जाँचें कि क्या वही encoded digest किसी दूसरे protocol version, message type, round या application में स्वीकार किया जाता है। Callers पर इन्हें अलग रखने के लिए निर्भर रहने के बजाय, इन contexts को स्पष्ट रूप से bind करें।

### SequenceHash और SequenceMAC

SequenceHash, byte strings के sequences के लिए hash-agnostic construction है। हर `add()` operation atomic होता है: यह value और fixed 16-byte, little-endian length suffix को inner hash में जोड़ता है। खाली values भी अलग-अलग objects बनी रहती हैं। एक outer hash, length-extendable inner state को उजागर होने से रोकता है, जबकि वैकल्पिक customization string domain separation देती है। `add()` को underlying hash API के सामान्य writes से न बदलें।<sup>[[8]](#references)[[9]](#references)</sup>

```python
import sequencehash

h = sequencehash.SequenceHash.new("sha256")
h.add(b"alice")
h.add(b"admin")
digest = h.result_with_customizer(b"example:v1:user-record")
```

प्रोटोकॉल की परिभाषा में customizer चुनें, और उसमें application, protocol version, message type और round को अलग-अलग पहचानने के लिए पर्याप्त जानकारी शामिल करें। SequenceHash के लिए अब भी सभी पक्षों को field order, byte encoding और canonical serialization पर सहमत होना आवश्यक है, और यह किसी छूटे हुए field की सुरक्षा नहीं कर सकता। Ports को C2SP के intermediate और final test vectors के विरुद्ध जाँचना चाहिए।<sup>[[8]](#references)[[11]](#references)</sup>

Authentication के लिए, SequenceMAC वही atomic encoding और customization interface प्रदान करता है। इसके लिए कम-से-कम 32 bytes की key आवश्यक है। HMAC key preprocessing के विपरीत, इसके headers ठीक-ठीक key length से बंधे होते हैं: लंबी raw key अपनी prehash के बराबर नहीं होती, और zero bytes जोड़ने से key बदल जाती है। यह अंतर तब मायने रखता है जब components key के अलग-अलग representations या length metadata स्वीकार करते हैं।<sup>[[8]](#references)[[9]](#references)</sup>

```python
key = b"\x00" * 32
mac = sequencehash.SequenceMAC.new(key, digestmod="sha256")
mac.add(header_bytes)
mac.add(body_bytes)
tag = mac.result_with_customizer(b"example:v1:request-mac")
```

Python API और इसके समकक्ष Go और Rust implementations संदर्भ के रूप में उपलब्ध हैं, लेकिन protocol implementations को इस सारांश से encoding दोबारा बनाने के बजाय live C2SP specification का पालन करना चाहिए।<sup>[[8]](#references)[[10]](#references)</sup>

## Password hashing और cracking

### शुरुआती सवाल<sup>[[4]](#references)</sup>

- क्या यह **salted** है? (`salt$hash` formats देखें)
- क्या यह **fast hash** (MD5/SHA1/SHA256) है या **slow KDF** (bcrypt/scrypt/argon2/PBKDF2)?
- क्या आपके पास **format hint** है (hashcat mode / John format)?

### व्यावहारिक workflow<sup>[[5]](#references)[[6]](#references)</sup>

1. Hash की पहचान करें:
   - `hashid <hash>`
   - `hashcat --example-hashes | rg -n "<pattern>"`
2. अगर यह unsalted और आम है: crypto workflow section के online DBs और identification tooling आज़माएँ।
3. अन्यथा crack करें:
   - `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
   - `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### आम गलतियाँ जिनका आप फ़ायदा उठा सकते हैं

- अलग-अलग users द्वारा एक ही password का दोबारा इस्तेमाल → एक को crack करें, फिर pivot करें।
- Truncated hashes / custom transforms → normalize करके फिर कोशिश करें।
- कमजोर KDF parameters (जैसे, कम PBKDF2 iterations) → फिर भी crack किए जा सकते हैं।

### जोड़े गए secret के साथ chosen-input bcrypt oracle

ऐसा callable helper जो `bcrypt(user_input || secret)` लौटाता है, जोड़े गए secret के बारे में जानकारी उजागर कर सकता है, अगर उसका bcrypt implementation चुपचाप 72 **bytes** के बाद input को truncate करता हो। UTF-8 encoding से पहले लगाई गई character-count सीमा इस byte सीमा को लागू नहीं करती: multibyte characters bcrypt input को भर सकते हैं और secret के केवल छोटे prefix के लिए जगह छोड़ सकते हैं। तब चुने गए inputs और उनसे लौटाए गए hashes के ज़रिए candidate suffix bytes की offline जाँच संभव हो सकती है। इसके लिए helper के input पर नियंत्रण, उसके सटीक transform और encoding की जानकारी, और वास्तव में truncation करने वाला implementation आवश्यक है; केवल callable helper या bcrypt hash से यह पूरी शृंखला साबित नहीं होती। [pyca/bcrypt दस्तावेज़](https://github.com/pyca/bcrypt#maximum-password-length) के अनुसार, मौजूदा `hashpw` 72 bytes से बड़े inputs पर error देता है, जबकि पहले के versions उन्हें चुपचाप truncate करते थे। अन्य wrappers लंबे inputs को prehash कर सकते हैं या अस्वीकार कर सकते हैं, इसलिए truncation मान लेने के बजाय installed implementation को verify करें।

किसी recovered secret का किसी दूसरे account के विरुद्ध इस्तेमाल करने के लिए यह प्रमाण भी चाहिए कि उजागर hash उसी **secret** और transform से बनाया गया था, साथ ही एक अलग credential या login path भी होना चाहिए। Root के रूप में चलने वाले hashing helper को oracle तभी मानकर जाँचना चाहिए, जब कम privilege वाला user उसे लागू policy के तहत चला सके; passive host enumeration में उसे call करना या चुने हुए passwords देना ज़रूरी नहीं है।

## References

- [1] [SkullSecurity - Hash length-extension attacks के बारे में वह सब कुछ जो आपको जानना चाहिए](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
- [2] [NIST FIPS 198-1 - Keyed-Hash Message Authentication Code](https://csrc.nist.gov/pubs/fips/198-1/final)
- [3] [hash_extender](https://github.com/iagox86/hash_extender)
- [4] [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [5] [Hashcat के उदाहरण hashes](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [6] [John the Ripper के command-line options](https://www.openwall.com/john/doc/OPTIONS.shtml)
- [7] [PyPI: HashPump के लिए `hashpumpy` Python bindings](https://pypi.org/project/hashpumpy/)
- [8] [C2SP - SequenceHash और SequenceMAC specification](https://c2sp.org/sequencehash)
- [9] [Trail of Bits - SequenceHash: हम सभी के लिए multihashing](https://blog.trailofbits.com/2026/10/02/sequencehash-multihashing-for-the-rest-of-us/)
- [10] [Trail of Bits - SequenceHash Python implementation](https://github.com/trailofbits/sequencehash-py)
- [11] [C2SP CCTV - SequenceHash test vectors](https://github.com/C2SP/CCTV/tree/main/sequencehash)
