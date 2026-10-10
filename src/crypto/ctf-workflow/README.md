# Crypto CTF कार्यप्रवाह

{{#include ../../banners/hacktricks-training.md}}

## शुरुआती जाँच की सूची

1. पहचानें कि आपके पास क्या है: encoding, encryption, hash, signature या MAC।
2. तय करें कि किस चीज़ पर नियंत्रण है: plaintext/ciphertext, IV/nonce, key, oracle (padding/error/timing), या आंशिक जानकारी का leak।
3. वर्गीकृत करें: symmetric (AES/CTR/GCM), public-key (RSA/ECC), hash/MAC (SHA/MD5/HMAC), classical (Vigenere/XOR)।
4. सबसे अधिक संभावना वाली जाँचें पहले करें: decoding की परतें, known-plaintext XOR, nonce का दोबारा इस्तेमाल, mode का गलत इस्तेमाल, oracle का व्यवहार।
5. उन्नत तरीकों पर तभी जाएँ जब ज़रूरी हो: lattices (LLL/Coppersmith), SMT/Z3, side-channels।

## ऑनलाइन संसाधन और उपयोगिताएँ

जब काम में पहचान और परतें हटाना शामिल हो, या किसी परिकल्पना की तुरंत पुष्टि करनी हो, तब ये उपयोगी हैं।

### Hash खोज

- अगर challenge hash synthetic/public है, तो उसे खोजें।
- CrackStation.<sup>[[1]](#references)</sup>
- MD5Decrypt.<sup>[[2]](#references)</sup>
- hashes.org खोज.<sup>[[3]](#references)</sup>
- OnlineHashCrack.<sup>[[4]](#references)</sup>
- GPUHash.me.<sup>[[5]](#references)</sup>
- Hash Toolkit.<sup>[[6]](#references)</sup>

असली password hashes या गोपनीय challenge सामग्री को third-party lookup सेवाओं पर न भेजें। अगर जानकारी उजागर होने, सेवा की शर्तों या प्रतियोगिता के नियमों को लेकर चिंता हो, तो offline wordlist/rule attack को प्राथमिकता दें।

### पहचान में मदद करने वाले टूल

- CyberChef (Magic, decoding और conversion)।<sup>[[7]](#references)</sup>
- dCode (cipher/encoding playground)।<sup>[[8]](#references)</sup>
- Boxentriq (substitution solvers)।<sup>[[9]](#references)</sup>

### अभ्यास प्लेटफ़ॉर्म / संदर्भ

- CryptoHack (cryptography की hands-on चुनौतियाँ)।<sup>[[10]](#references)</sup>
- Cryptopals (आधुनिक cryptography की आम खामियाँ)।<sup>[[11]](#references)</sup>

### स्वचालित decoding

- Ciphey.<sup>[[12]](#references)</sup>
- python-codext (कई bases/encodings आज़माता है)।<sup>[[13]](#references)</sup>

## Encodings और classical ciphers

### तकनीक

कई CTF crypto कार्यों में कई transforms एक के ऊपर एक होते हैं: base encoding + simple substitution + compression। लक्ष्य है परतों की पहचान करना और उन्हें सुरक्षित रूप से हटाना।

### Encodings: कई bases आज़माएँ

अगर आपको layered encoding (base64 → base32 → …) का शक है, तो आज़माएँ:

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

आम संकेत:

- Base64: `A-Za-z0-9+/=` (padding `=` आम है)
- Base32: `A-Z2-7=` (अक्सर बहुत सारा `=` padding होता है)
- Ascii85/Base85: घने punctuation वाले अक्षर; कभी-कभी `<~ ~>` में लिपटे होते हैं

### Substitution / monoalphabetic

- Boxentriq cryptogram solver.<sup>[[9]](#references)</sup>
- quipqiup.<sup>[[14]](#references)</sup>

### Caesar / ROT / Atbash

- Nayuki automatic Caesar-cipher breaker.<sup>[[15]](#references)</sup>
- Rumkin Atbash tool.<sup>[[16]](#references)</sup>

### Vigenère

- dCode Vigenère tool.<sup>[[8]](#references)</sup>
- Guballa Vigenère solver.<sup>[[17]](#references)</sup>

### Bacon cipher

अक्सर 5 bits या 5 letters के समूहों में दिखता है:

```
00111 01101 01010 00000 ...
AABBB ABBAB ABABA AAAAA ...
```

### Morse

```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```

### रून्स

रून्स अक्सर substitution alphabets होते हैं; "futhark cipher" खोजें और mapping tables आज़माएँ।

## Challenges में Compression

### Technique

Compression अक्सर एक अतिरिक्त layer के रूप में दिखाई देता है (zlib/deflate/gzip/xz/zstd), कभी-कभी nested रूप में। अगर output लगभग parse हो जाता है, लेकिन कचरे जैसा दिखता है, तो compression का संदेह करें।

### तुरंत पहचान

- `file <blob>`
- Magic bytes देखें:
  - gzip: `1f 8b`
  - zlib: आमतौर पर `78 01`, `78 5e`, `78 9c`, या `78 da` (दूसरा byte compression flags पर निर्भर करता है)
  - zip: `50 4b 03 04`
  - bzip2: `42 5a 68` (`BZh`)
  - xz: `fd 37 7a 58 5a 00`
  - zstd: `28 b5 2f fd`

### Raw DEFLATE

CyberChef में **Raw Deflate/Raw Inflate** उपलब्ध है; जब blob compressed दिखता हो, लेकिन `zlib` विफल हो जाए, तो यह अक्सर सबसे तेज़ तरीका होता है।

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

## आम CTF crypto संरचनाएँ

### Technique

ये अक्सर दिखाई देते हैं, क्योंकि ये डेवलपर की वास्तविक गलतियाँ होती हैं या आम libraries का गलत इस्तेमाल होता है। आमतौर पर लक्ष्य इन्हें पहचानना और पहले से ज्ञात extraction या reconstruction workflow लागू करना होता है।

### Fernet

आम संकेत: दो Base64 strings (token + key)।

- Decoder/notes: Asecuritysite Fernet decoder.<sup>[[18]](#references)</sup>
- Python में: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

अगर आपको कई shares दिखें और threshold `t` का उल्लेख हो, तो संभवतः यह Shamir है।

- Online reconstructor (केवल गैर-संवेदनशील CTF shares के लिए)।<sup>[[19]](#references)</sup>

### OpenSSL salted formats

CTF में कभी-कभी `openssl enc` के outputs दिए जाते हैं (header अक्सर `Salted__` से शुरू होता है)।

Bruteforce के सहायक tools:

- `bruteforce-salted-openssl`.<sup>[[20]](#references)</sup>
- `easy_BFopensslCTF`.<sup>[[21]](#references)</sup>

### सामान्य toolset

- RsaCtfTool.<sup>[[22]](#references)</sup>
- featherduster.<sup>[[23]](#references)</sup>
- cryptovenom.<sup>[[24]](#references)</sup>

## सुझाया गया local setup

व्यावहारिक CTF stack:

- Symmetric primitives और तेज़ prototyping के लिए Python के साथ `pycryptodome`।<sup>[[25]](#references)</sup>
- Modular arithmetic, CRT, lattices और RSA/ECC कार्यों के लिए SageMath।<sup>[[26]](#references)</sup>
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
- [9] [Boxentriq कोड-भंजक टूल](https://www.boxentriq.com/code-breaking)
- [10] [CryptoHack](https://cryptohack.org/)
- [11] [Cryptopals](https://cryptopals.com/)
- [12] [Ciphey](https://github.com/Ciphey/Ciphey)
- [13] [python-codext](https://github.com/dhondta/python-codext)
- [14] [quipqiup](https://quipqiup.com/)
- [15] [Nayuki - स्वचालित Caesar cipher ब्रेकर](https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript)
- [16] [Rumkin - Atbash cipher](https://rumkin.com/tools/cipher/atbash/)
- [17] [Guballa Vigenère सॉल्वर](https://www.guballa.de/vigenere-solver)
- [18] [Asecuritysite - Fernet डिकोडर](https://asecuritysite.com/encryption/ferdecode)
- [19] [Shamir secret-sharing पुनर्निर्माता](https://christian.gen.co/secrets/)
- [20] [bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
- [21] [easy_BFopensslCTF](https://github.com/carlospolop/easy_BFopensslCTF)
- [22] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [23] [featherduster](https://github.com/nccgroup/featherduster)
- [24] [cryptovenom](https://github.com/lockedbyte/cryptovenom)
- [25] [PyCryptodome प्रलेखन](https://pycryptodome.readthedocs.io/en/latest/)
- [26] [SageMath](https://www.sagemath.org/)
- [27] [Z3](https://github.com/Z3Prover/z3)
{{#include ../../banners/hacktricks-training.md}}
