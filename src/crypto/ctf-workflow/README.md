# Mtiririko wa Kazi wa Crypto CTF

{{#include ../../banners/hacktricks-training.md}}

## Orodha ya ukaguzi wa awali

1. Tambua ulicho nacho: encoding dhidi ya encryption dhidi ya hash dhidi ya signature dhidi ya MAC.
2. Bainisha kinachodhibitiwa: plaintext/ciphertext, IV/nonce, key, oracle (padding/error/timing), partial leakage.
3. Ainisha: symmetric (AES/CTR/GCM), public-key (RSA/ECC), hash/MAC (SHA/MD5/HMAC), classical (Vigenere/XOR).
4. Fanya kwanza ukaguzi wenye uwezekano mkubwa zaidi: decode tabaka, known-plaintext XOR, nonce reuse, matumizi yasiyo sahihi ya mode, tabia ya oracle.
5. Tumia mbinu za kina zaidi inapohitajika tu: lattices (LLL/Coppersmith), SMT/Z3, side-channels.

## Rasilimali na zana za mtandaoni

Hizi ni muhimu wakati kazi ni kutambua na kuondoa tabaka, au unapohitaji kuthibitisha haraka dhana.

### Utafutaji wa hash

- Tafuta hash ya challenge ikiwa inajulikana kuwa synthetic/public.
- CrackStation.<sup>[[1]](#references)</sup>
- MD5Decrypt.<sup>[[2]](#references)</sup>
- Utafutaji wa hashes.org.<sup>[[3]](#references)</sup>
- OnlineHashCrack.<sup>[[4]](#references)</sup>
- GPUHash.me.<sup>[[5]](#references)</sup>
- Hash Toolkit.<sup>[[6]](#references)</sup>

Usiwasilishe hash halisi za password au nyenzo za challenge za siri kwenye huduma za utafutaji za watu wengine. Pendelea shambulio la wordlist/rule la offline pale ambapo ufichuaji, masharti ya huduma, au kanuni za mashindano ni jambo la kuzingatia.

### Zana za kusaidia utambuzi

- CyberChef (Magic, decoding, na conversion).<sup>[[7]](#references)</sup>
- dCode (mazingira ya majaribio ya cipher/encoding).<sup>[[8]](#references)</sup>
- Boxentriq (vitatua substitution).<sup>[[9]](#references)</sup>

### Majukwaa ya mazoezi / marejeo

- CryptoHack (changamoto za vitendo za cryptography).<sup>[[10]](#references)</sup>
- Cryptopals (mitego ya kawaida ya cryptography ya kisasa).<sup>[[11]](#references)</sup>

### Decoding ya kiotomatiki

- Ciphey.<sup>[[12]](#references)</sup>
- python-codext (hujaribu base/encoding nyingi).<sup>[[13]](#references)</sup>

## Encodings na classical ciphers

### Mbinu

Kazi nyingi za crypto za CTF hutumia mabadiliko yaliyowekwa kwa tabaka: base encoding + simple substitution + compression. Lengo ni kutambua tabaka na kuziondoa kwa usalama.

### Encodings: jaribu base nyingi

Ikiwa unashuku encoding iliyowekwa kwa tabaka (base64 → base32 → …), jaribu:

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

Viashiria vya kawaida:

- Base64: `A-Za-z0-9+/=` (padding `=` ni ya kawaida)
- Base32: `A-Z2-7=` (mara nyingi huwa na padding nyingi ya `=`)
- Ascii85/Base85: alama nyingi za uandishi; wakati mwingine hufungwa ndani ya `<~ ~>`

### Substitution / monoalphabetic

- Kitatua cryptogram cha Boxentriq.<sup>[[9]](#references)</sup>
- quipqiup.<sup>[[14]](#references)</sup>

### Caesar / ROT / Atbash

- Kivunja Caesar cipher kiotomatiki cha Nayuki.<sup>[[15]](#references)</sup>
- Zana ya Atbash ya Rumkin.<sup>[[16]](#references)</sup>

### Vigenère

- Zana ya Vigenère ya dCode.<sup>[[8]](#references)</sup>
- Kitatua Vigenère cha Guballa.<sup>[[17]](#references)</sup>

### Bacon cipher

Mara nyingi huonekana kama makundi ya bits 5 au herufi 5:

```
00111 01101 01010 00000 ...
AABBB ABBAB ABABA AAAAA ...
```

### Morse

```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```

### Runes

Runes mara nyingi ni alfabeti za kubadilisha herufi; tafuta "futhark cipher" na ujaribu kutumia majedwali ya ulinganishaji.

## Compression kwenye challenges

### Mbinu

Compression hujitokeza mara kwa mara kama safu ya ziada (zlib/deflate/gzip/xz/zstd), na wakati mwingine huwekwa katika safu nyingi. Ikiwa matokeo yanakaribia kuchanganulika lakini yanaonekana kama takataka, shuku compression.

### Utambuzi wa haraka

- `file <blob>`
- Tafuta magic bytes:
  - gzip: `1f 8b`
  - zlib: mara nyingi `78 01`, `78 5e`, `78 9c`, au `78 da` (byte ya pili hutegemea flags za compression)
  - zip: `50 4b 03 04`
  - bzip2: `42 5a 68` (`BZh`)
  - xz: `fd 37 7a 58 5a 00`
  - zstd: `28 b5 2f fd`

### Raw DEFLATE

CyberChef ina **Raw Deflate/Raw Inflate**, ambayo mara nyingi ndiyo njia ya haraka zaidi ikiwa blob inaonekana imebanwa lakini `zlib` inashindwa.

### CLI muhimu

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

## Miundo ya kawaida ya crypto katika CTF

### Mbinu

Hivi hujitokeza mara nyingi kwa sababu ni makosa halisi ya developers au matumizi yasiyo sahihi ya libraries za kawaida. Lengo kwa kawaida ni kutambua muundo na kutumia workflow inayojulikana ya kutoa au kujenga upya data.

### Fernet

Kidokezo cha kawaida: strings mbili za Base64 (token + key).

- Decoder/maelezo: Asecuritysite Fernet decoder.<sup>[[18]](#references)</sup>
- Katika Python: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

Ukiona shares nyingi na threshold `t` imetajwa, huenda ni Shamir.

- Kifaa cha kujenga upya mtandaoni (kwa shares za CTF zisizo na taarifa nyeti pekee).<sup>[[19]](#references)</sup>

### Miundo ya OpenSSL yenye chumvi

Wakati mwingine CTF hutoa matokeo ya `openssl enc` (kichwa mara nyingi huanza na `Salted__`).

Vifaa vya bruteforce:

- `bruteforce-salted-openssl`.<sup>[[20]](#references)</sup>
- `easy_BFopensslCTF`.<sup>[[21]](#references)</sup>

### Seti ya jumla ya vifaa

- RsaCtfTool.<sup>[[22]](#references)</sup>
- featherduster.<sup>[[23]](#references)</sup>
- cryptovenom.<sup>[[24]](#references)</sup>

## Mpangilio wa ndani unaopendekezwa

Seti ya vitendo ya CTF:

- Python pamoja na `pycryptodome` kwa primitives za symmetric na uundaji wa prototypes kwa haraka.<sup>[[25]](#references)</sup>
- SageMath kwa hesabu za modular, CRT, lattices, na kazi za RSA/ECC.<sup>[[26]](#references)</sup>
- Z3 kwa changamoto zinazotegemea constraints (crypto inapoweza kuwakilishwa kama constraints).<sup>[[27]](#references)</sup>

Packages za Python zinazopendekezwa:

```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```

## References

- [1] [CrackStation](https://crackstation.net/)
- [2] [MD5Decrypt](https://md5decrypt.net/)
- [3] [Utafutaji wa hashes.org](https://hashes.org/search.php)
- [4] [OnlineHashCrack](https://www.onlinehashcrack.com/)
- [5] [GPUHash.me](https://gpuhash.me/)
- [6] [Zana ya Hash](https://hashtoolkit.com/reverse-hash)
- [7] [GCHQ CyberChef](https://gchq.github.io/CyberChef/)
- [8] [Zana za dCode](https://www.dcode.fr/tools-list)
- [9] [Zana za kuvunja misimbo za Boxentriq](https://www.boxentriq.com/code-breaking)
- [10] [CryptoHack](https://cryptohack.org/)
- [11] [Cryptopals](https://cryptopals.com/)
- [12] [Ciphey](https://github.com/Ciphey/Ciphey)
- [13] [python-codext](https://github.com/dhondta/python-codext)
- [14] [quipqiup](https://quipqiup.com/)
- [15] [Nayuki - Kivunja cipher ya Caesar kiotomatiki](https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript)
- [16] [Rumkin - Cipher ya Atbash](https://rumkin.com/tools/cipher/atbash/)
- [17] [Kitatuzi cha Vigenère cha Guballa](https://www.guballa.de/vigenere-solver)
- [18] [Asecuritysite - Dekoda ya Fernet](https://asecuritysite.com/encryption/ferdecode)
- [19] [Kijenga upya cha ugawaji-siri wa Shamir](https://christian.gen.co/secrets/)
- [20] [bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
- [21] [easy_BFopensslCTF](https://github.com/carlospolop/easy_BFopensslCTF)
- [22] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [23] [featherduster](https://github.com/nccgroup/featherduster)
- [24] [cryptovenom](https://github.com/lockedbyte/cryptovenom)
- [25] [Nyaraka za PyCryptodome](https://pycryptodome.readthedocs.io/en/latest/)
- [26] [SageMath](https://www.sagemath.org/)
- [27] [Z3](https://github.com/Z3Prover/z3)
{{#include ../../banners/hacktricks-training.md}}
