# Crypto CTF Workflow

{{#include ../../banners/hacktricks-training.md}}

## Triage checklist

1. Identify what you have: encoding vs encryption vs hash vs signature vs MAC.
2. Determine what is controlled: plaintext/ciphertext, IV/nonce, key, oracle (padding/error/timing), partial leakage.
3. Classify: symmetric (AES/CTR/GCM), public-key (RSA/ECC), hash/MAC (SHA/MD5/HMAC), classical (Vigenere/XOR).
4. Apply the highest-probability checks first: decode layers, known-plaintext XOR, nonce reuse, mode misuse, oracle behavior.
5. Escalate to advanced methods only when required: lattices (LLL/Coppersmith), SMT/Z3, side-channels.

## Online resources & utilities

These are useful when the task is identification and layer peeling, or when you need quick confirmation of a hypothesis.

### Hash lookups

- Search for a challenge hash when it is known to be synthetic/public.
- CrackStation.<sup>[[1]](#references)</sup>
- MD5Decrypt.<sup>[[2]](#references)</sup>
- hashes.org search.<sup>[[3]](#references)</sup>
- OnlineHashCrack.<sup>[[4]](#references)</sup>
- GPUHash.me.<sup>[[5]](#references)</sup>
- Hash Toolkit.<sup>[[6]](#references)</sup>

Do not submit real password hashes or confidential challenge material to third-party lookup services. Prefer an offline wordlist/rule attack when disclosure, terms of service, or competition rules are a concern.

### Identification helpers

- CyberChef (Magic, decoding, and conversion).<sup>[[7]](#references)</sup>
- dCode (cipher/encoding playground).<sup>[[8]](#references)</sup>
- Boxentriq (substitution solvers).<sup>[[9]](#references)</sup>

### Practice platforms / references

- CryptoHack (hands-on cryptography challenges).<sup>[[10]](#references)</sup>
- Cryptopals (classic modern-cryptography pitfalls).<sup>[[11]](#references)</sup>

### Automated decoding

- Ciphey.<sup>[[12]](#references)</sup>
- python-codext (tries many bases/encodings).<sup>[[13]](#references)</sup>

## Encodings & classical ciphers

### Technique

Many CTF crypto tasks are layered transforms: base encoding + simple substitution + compression. The goal is to identify layers and peel them safely.

### Encodings: try many bases

If you suspect layered encoding (base64 → base32 → …), try:

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

Common tells:

- Base64: `A-Za-z0-9+/=` (padding `=` is common)
- Base32: `A-Z2-7=` (often lots of `=` padding)
- Ascii85/Base85: dense punctuation; sometimes wrapped in `<~ ~>`

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

Often appears as groups of 5 bits or 5 letters:

```
00111 01101 01010 00000 ...
AABBB ABBAB ABABA AAAAA ...
```

### Morse

```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```

### Runes

Runes are frequently substitution alphabets; search for "futhark cipher" and try mapping tables.

## Compression in challenges

### Technique

Compression shows up constantly as an extra layer (zlib/deflate/gzip/xz/zstd), sometimes nested. If output almost parses but looks like garbage, suspect compression.

### Quick identification

- `file <blob>`
- Look for magic bytes:
  - gzip: `1f 8b`
  - zlib: commonly `78 01`, `78 5e`, `78 9c`, or `78 da` (the second byte depends on compression flags)
  - zip: `50 4b 03 04`
  - bzip2: `42 5a 68` (`BZh`)
  - xz: `fd 37 7a 58 5a 00`
  - zstd: `28 b5 2f fd`

### Raw DEFLATE

CyberChef has **Raw Deflate/Raw Inflate**, which is often the fastest path when the blob looks compressed but `zlib` fails.

### Useful CLI

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

## Common CTF crypto constructs

### Technique

These appear frequently because they are realistic developer mistakes or common libraries used incorrectly. The goal is usually recognition and applying a known extraction or reconstruction workflow.

### Fernet

Typical hint: two Base64 strings (token + key).

- Decoder/notes: Asecuritysite Fernet decoder.<sup>[[18]](#references)</sup>
- In Python: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

If you see multiple shares and a threshold `t` is mentioned, it is likely Shamir.

- Online reconstructor (for non-sensitive CTF shares only).<sup>[[19]](#references)</sup>

### OpenSSL salted formats

CTFs sometimes give `openssl enc` outputs (header often begins with `Salted__`).

Bruteforce helpers:

- `bruteforce-salted-openssl`.<sup>[[20]](#references)</sup>
- `easy_BFopensslCTF`.<sup>[[21]](#references)</sup>

### General toolset

- RsaCtfTool.<sup>[[22]](#references)</sup>
- featherduster.<sup>[[23]](#references)</sup>
- cryptovenom.<sup>[[24]](#references)</sup>

## Recommended local setup

Practical CTF stack:

- Python plus `pycryptodome` for symmetric primitives and fast prototyping.<sup>[[25]](#references)</sup>
- SageMath for modular arithmetic, CRT, lattices, and RSA/ECC work.<sup>[[26]](#references)</sup>
- Z3 for constraint-based challenges (when the crypto reduces to constraints).<sup>[[27]](#references)</sup>

Suggested Python packages:

```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```

## References

- [1] [CrackStation](https://crackstation.net/)
- [2] [MD5Decrypt](https://md5decrypt.net/)
- [3] [hashes.org search](https://hashes.org/search.php)
- [4] [OnlineHashCrack](https://www.onlinehashcrack.com/)
- [5] [GPUHash.me](https://gpuhash.me/)
- [6] [Hash Toolkit](https://hashtoolkit.com/reverse-hash)
- [7] [GCHQ CyberChef](https://gchq.github.io/CyberChef/)
- [8] [dCode tools](https://www.dcode.fr/tools-list)
- [9] [Boxentriq code-breaking tools](https://www.boxentriq.com/code-breaking)
- [10] [CryptoHack](https://cryptohack.org/)
- [11] [Cryptopals](https://cryptopals.com/)
- [12] [Ciphey](https://github.com/Ciphey/Ciphey)
- [13] [python-codext](https://github.com/dhondta/python-codext)
- [14] [quipqiup](https://quipqiup.com/)
- [15] [Nayuki - Automatic Caesar cipher breaker](https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript)
- [16] [Rumkin - Atbash cipher](https://rumkin.com/tools/cipher/atbash/)
- [17] [Guballa Vigenère solver](https://www.guballa.de/vigenere-solver)
- [18] [Asecuritysite - Fernet decoder](https://asecuritysite.com/encryption/ferdecode)
- [19] [Shamir secret-sharing reconstructor](https://christian.gen.co/secrets/)
- [20] [bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
- [21] [easy_BFopensslCTF](https://github.com/carlospolop/easy_BFopensslCTF)
- [22] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [23] [featherduster](https://github.com/nccgroup/featherduster)
- [24] [cryptovenom](https://github.com/lockedbyte/cryptovenom)
- [25] [PyCryptodome documentation](https://pycryptodome.readthedocs.io/en/latest/)
- [26] [SageMath](https://www.sagemath.org/)
- [27] [Z3](https://github.com/Z3Prover/z3)

{{#include ../../banners/hacktricks-training.md}}
