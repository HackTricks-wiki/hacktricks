# Crypto CTF वर्कफ़्लो

{{#include ../../banners/hacktricks-training.md}}

## प्रारंभिक जांच सूची

1. पहचानें कि आपके पास क्या है: encoding, encryption, hash, signature या MAC।
2. पता लगाएँ कि किस चीज़ पर आपका नियंत्रण है: plaintext/ciphertext, IV/nonce, key, oracle (padding/error/timing), आंशिक leak।
3. वर्गीकृत करें: symmetric (AES/CTR/GCM), public-key (RSA/ECC), hash/MAC (SHA/MD5/HMAC), classical (Vigenere/XOR)।
4. सबसे अधिक सफल होने की संभावना वाली जाँच पहले करें: decode की परतें, known-plaintext XOR, nonce reuse, mode का गलत इस्तेमाल, oracle का व्यवहार।
5. केवल ज़रूरत पड़ने पर उन्नत तरीकों पर जाएँ: lattices (LLL/Coppersmith), SMT/Z3, side-channels।

## ऑनलाइन संसाधन और यूटिलिटी

जब काम किसी चीज़ की पहचान करने और परतें हटाने का हो, या किसी परिकल्पना की तुरंत पुष्टि करनी हो, तो ये उपयोगी हैं।

### Hash lookup

- जब challenge hash को synthetic/public माना जाता हो, तो उसे खोजें।
- CrackStation.<sup>[[1]](#references)</sup>
- MD5Decrypt.<sup>[[2]](#references)</sup>
- hashes.org पर खोजें।<sup>[[3]](#references)</sup>
- OnlineHashCrack.<sup>[[4]](#references)</sup>
- GPUHash.me.<sup>[[5]](#references)</sup>
- Hash Toolkit.<sup>[[6]](#references)</sup>

वास्तविक password hashes या गोपनीय challenge सामग्री को third-party lookup सेवाओं पर सबमिट न करें। यदि जानकारी उजागर होने, सेवा की शर्तों या प्रतियोगिता के नियमों को लेकर चिंता हो, तो offline wordlist/rule attack को प्राथमिकता दें।

### पहचान में मददगार टूल

- CyberChef (Magic, decoding और conversion)।<sup>[[7]](#references)</sup>
- dCode (cipher/encoding playground)।<sup>[[8]](#references)</sup>
- Boxentriq (substitution solvers)।<sup>[[9]](#references)</sup>

### अभ्यास प्लेटफ़ॉर्म / संदर्भ

- CryptoHack (cryptography की व्यावहारिक चुनौतियाँ)।<sup>[[10]](#references)</sup>
- Cryptopals (आधुनिक cryptography की पारंपरिक कमियाँ)।<sup>[[11]](#references)</sup>

### स्वचालित decoding

- Ciphey.<sup>[[12]](#references)</sup>
- python-codext (कई bases/encodings आज़माता है)।<sup>[[13]](#references)</sup>

Esoteric-language source और custom interpreter state के लिए, [Crypto CTF Misc](../ctf-misc/) देखें।

## Encodings और classical ciphers

### तकनीक

कई CTF crypto tasks में कई transforms की परतें होती हैं: base encoding + simple substitution + compression। लक्ष्य परतों की पहचान करके उन्हें सुरक्षित रूप से हटाना है।

### Encodings: कई bases आज़माएँ

अगर आपको layered encoding (base64 → base32 → …) का संदेह है, तो आज़माएँ:

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

आम संकेत:

- Base64: `A-Za-z0-9+/=` (padding `=` आम है)
- Base32: `A-Z2-7=` (अक्सर बहुत-सा `=` padding होता है)
- Ascii85/Base85: सघन punctuation; कभी-कभी `<~ ~>` के बीच होता है

### Substitution / monoalphabetic

- Boxentriq cryptogram solver.<sup>[[9]](#references)</sup>
- quipqiup.<sup>[[14]](#references)</sup>

#### Substituted Base32 filenames को known-plaintext से पुनर्प्राप्त करना

जब किसी obfuscated filename में केवल `a-z2-7` हों, किसी fixed suffix को हटाने के बाद उसकी लंबाई लगभग `ceil(8 * byte_length / 5)` characters हो, और अलग-अलग files में एक ही plaintext से वही output बने, तो **unpadded Base32 के बाद fixed symbol substitution** को जाँचें। ये संकेत अपने-आप में प्रमाण नहीं हैं। अनुमान लगाने योग्य filenames और उनके ciphertexts इकट्ठा करें, case को जस का तस रखें, हर plaintext को Base32-encode करें और symbols को स्थान-दर-स्थान मिलाएँ। हर दोहराए गए plaintext symbol का ciphertext symbol हमेशा एक ही होना चाहिए, और inverse mapping भी unique होनी चाहिए। Ransomware के एक मामले में, `ntuser.ini` और `NTUSER.DAT` से ऐसे pairs मिले; इससे filenames पुनर्प्राप्त हुए, **file contents या encryption keys नहीं**।<sup>[[28]](#references)</sup>

```python
import base64
pairs = [("ntuser.ini", "zsub5mdlekr37dx4"), ("NTUSER.DAT", "4s5l5tul5kr6kv5t")]
forward, inverse = {}, {}
for name, ciphertext in pairs:
    b32 = base64.b32encode(name.encode("ascii")).decode().lower().rstrip("=")
    assert len(b32) == len(ciphertext)
    for p, c in zip(b32, ciphertext):
        assert forward.get(p, c) == c and inverse.get(c, p) == p
        forward[p], inverse[c] = c, p
target = "4s5l5tul5kr6kv5t"  # Remove the fixed suffix first
b32 = "".join(inverse[c] for c in target)
clear = base64.b32decode(b32.upper() + "=" * (-len(b32) % 8))
assert "".join(forward[c] for c in b32) == target
print(clear.decode("ascii"))
```

यदि किसी target में unmapped symbols हों, तो अधिक ज्ञात pairs प्राप्त करें या केवल अप्रयुक्त Base32-symbol mappings को permute करें। Padding को आठ-अक्षरों की सीमा तक बहाल करें, अमान्य Base32 और non-printable decoded names को अस्वीकार करें, फिर बचे हुए candidates को दोबारा encode करके पूरे मूल ciphertext से तुलना करें। दोहराए गए ciphertext blocks से अतिरिक्त अनुमान मिल सकते हैं: ऊपर दिए गए मामले में, `3gpng2wv` को वापस Base32 `gaydambq` में map किया गया, जो पाँच ASCII zeroes में decode होता है। केवल printable candidate होना विशिष्ट प्रमाण नहीं है।<sup>[[28]](#references)</sup>

### Caesar / ROT / Atbash

- Nayuki का automatic Caesar-cipher breaker।<sup>[[15]](#references)</sup>
- Rumkin का Atbash tool।<sup>[[16]](#references)</sup>

### Vigenère

- dCode का Vigenère tool।<sup>[[8]](#references)</sup>
- Guballa का Vigenère solver।<sup>[[17]](#references)</sup>

### Bacon cipher

अक्सर 5 bits या 5 letters के समूहों के रूप में दिखाई देता है:

```
00111 01101 01010 00000 ...
AABBB ABBAB ABABA AAAAA ...
```

### Morse

```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```

### Runes

Runes अक्सर substitution alphabets होते हैं; "futhark cipher" खोजें और mapping tables आज़माएँ।

## Challenges में Compression

### Technique

Compression अक्सर एक अतिरिक्त layer के रूप में दिखाई देता है (zlib/deflate/gzip/xz/zstd), कभी-कभी nested रूप में। अगर output लगभग parse हो जाता है, लेकिन garbage जैसा दिखता है, तो compression का संदेह करें।

### तुरंत पहचान

- `file <blob>`
- Magic bytes देखें:
  - gzip: `1f 8b`
  - zlib: आम तौर पर `78 01`, `78 5e`, `78 9c`, या `78 da` (दूसरा byte compression flags पर निर्भर करता है)
  - zip: `50 4b 03 04`
  - bzip2: `42 5a 68` (`BZh`)
  - xz: `fd 37 7a 58 5a 00`
  - zstd: `28 b5 2f fd`

### Raw DEFLATE

CyberChef में **Raw Deflate/Raw Inflate** उपलब्ध है; जब blob compressed दिखता है, लेकिन `zlib` काम नहीं करता, तो अक्सर यह सबसे तेज़ तरीका होता है।

### उपयोगी CLI

```bash
python3 - blob.bin <<'PY'
import sys, zlib
data = open(sys.argv[1], 'rb').read()
for wbits in [zlib.MAX_WBITS, -zlib.MAX_WBITS]:
  try:
    print(zlib.decompress(data, wbits=wbits)[:200])
  except Exception:
    pass
PY
```

## सामान्य CTF क्रिप्टो संरचनाएँ

### तकनीक

ये अक्सर दिखाई देते हैं, क्योंकि ये डेवलपर की वास्तविक गलतियाँ या गलत तरीके से इस्तेमाल की गई आम लाइब्रेरी होती हैं। आम तौर पर लक्ष्य इन्हें पहचानना और पहले से ज्ञात extraction या reconstruction workflow लागू करना होता है।

### Fernet

आम संकेत: दो Base64 strings (token + key)।

- Decoder/notes: Asecuritysite Fernet decoder.<sup>[[18]](#references)</sup>
- Python में: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

अगर कई shares दिखें और threshold `t` का ज़िक्र हो, तो संभवतः यह Shamir है।

- Online reconstructor (केवल गैर-संवेदनशील CTF shares के लिए)।<sup>[[19]](#references)</sup>

### OpenSSL salted formats

CTF में कभी-कभी `openssl enc` outputs दिए जाते हैं (header अक्सर `Salted__` से शुरू होता है)।

Bruteforce helpers:

- `bruteforce-salted-openssl`.<sup>[[20]](#references)</sup>
- `easy_BFopensslCTF`.<sup>[[21]](#references)</sup>

### सामान्य toolset

- RsaCtfTool.<sup>[[22]](#references)</sup>
- featherduster.<sup>[[23]](#references)</sup>
- cryptovenom.<sup>[[24]](#references)</sup>

## सुझाया गया स्थानीय setup

व्यावहारिक CTF stack:

- Symmetric primitives और fast prototyping के लिए Python और `pycryptodome`।<sup>[[25]](#references)</sup>
- Modular arithmetic, CRT, lattices और RSA/ECC कार्य के लिए SageMath।<sup>[[26]](#references)</sup>
- Constraint-based challenges के लिए Z3 (जब crypto को constraints में बदला जा सके)।<sup>[[27]](#references)</sup>

सुझाए गए Python packages:

```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```



## References

- [1] [CrackStation](https://crackstation.net/)
- [2] [MD5Decrypt](https://md5decrypt.net/)
- [3] [hashes.org खोज](https://hashes.org/search.php)
- [4] [OnlineHashCrack](https://www.onlinehashcrack.com/)
- [5] [GPUHash.me](https://gpuhash.me/)
- [6] [Hash Toolkit](https://hashtoolkit.com/reverse-hash)
- [7] [GCHQ CyberChef](https://gchq.github.io/CyberChef/)
- [8] [dCode टूल](https://www.dcode.fr/tools-list)
- [9] [Boxentriq के कोड-ब्रेकिंग टूल](https://www.boxentriq.com/code-breaking)
- [10] [CryptoHack](https://cryptohack.org/)
- [11] [Cryptopals](https://cryptopals.com/)
- [12] [Ciphey](https://github.com/Ciphey/Ciphey)
- [13] [python-codext](https://github.com/dhondta/python-codext)
- [14] [quipqiup](https://quipqiup.com/)
- [15] [Nayuki - स्वचालित Caesar cipher ब्रेकर](https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript)
- [16] [Rumkin - Atbash cipher](https://rumkin.com/tools/cipher/atbash/)
- [17] [Guballa Vigenère solver](https://www.guballa.de/vigenere-solver)
- [18] [Asecuritysite - Fernet decoder](https://asecuritysite.com/encryption/ferdecode)
- [19] [Shamir secret-sharing reconstructor](https://christian.gen.co/secrets/)
- [20] [bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
- [21] [easy_BFopensslCTF](https://github.com/carlospolop/easy_BFopensslCTF)
- [22] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [23] [featherduster](https://github.com/nccgroup/featherduster)
- [24] [cryptovenom](https://github.com/lockedbyte/cryptovenom)
- [25] [PyCryptodome दस्तावेज़](https://pycryptodome.readthedocs.io/en/latest/)
- [26] [SageMath](https://www.sagemath.org/)
- [27] [Z3](https://github.com/Z3Prover/z3)
- [28] [Eye Research – आसान तरीके से encryption schemes तोड़ना](https://labs.eye.security/breaking-encryption-schemes-the-lazy-way/)
{{#include ../../banners/hacktricks-training.md}}
