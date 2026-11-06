# Mtiririko wa Kazi wa Crypto CTF

{{#include ../../banners/hacktricks-training.md}}

## Orodha ya ukaguzi wa awali

1. Tambua ulicho nacho: encoding dhidi ya encryption dhidi ya hash dhidi ya signature dhidi ya MAC.
2. Bainisha vitu vinavyodhibitiwa: plaintext/ciphertext, IV/nonce, key, oracle (padding/error/timing), au partial leakage.
3. Ainisha: symmetric (AES/CTR/GCM), public-key (RSA/ECC), hash/MAC (SHA/MD5/HMAC), classical (Vigenere/XOR).
4. Anza na ukaguzi wenye uwezekano mkubwa zaidi wa kufanikiwa: fungua tabaka za encoding, known-plaintext XOR, nonce reuse, matumizi mabaya ya mode, na tabia ya oracle.
5. Tumia mbinu za hali ya juu tu zinapohitajika: lattices (LLL/Coppersmith), SMT/Z3, side-channels.

## Rasilimali na zana za mtandaoni

Hizi zinafaa wakati kazi ni kutambua na kuondoa tabaka, au unapohitaji kuthibitisha haraka dhana fulani.

### Utafutaji wa hash

- Tafuta hash ya challenge ikiwa inajulikana kuwa ya majaribio/ya umma.
- CrackStation.<sup>[[1]](#references)</sup>
- MD5Decrypt.<sup>[[2]](#references)</sup>
- Utafutaji wa hashes.org.<sup>[[3]](#references)</sup>
- OnlineHashCrack.<sup>[[4]](#references)</sup>
- GPUHash.me.<sup>[[5]](#references)</sup>
- Hash Toolkit.<sup>[[6]](#references)</sup>

Usiwasilishe password hashes halisi au nyenzo za siri za challenge kwenye huduma za utafutaji za wahusika wengine. Ikiwa una wasiwasi kuhusu kufichua taarifa, sheria na masharti, au kanuni za mashindano, pendelea kutumia wordlist/rule attack nje ya mtandao.

### Zana saidizi za utambuzi

- CyberChef (Magic, decoding, na conversion).<sup>[[7]](#references)</sup>
- dCode (cipher/encoding playground).<sup>[[8]](#references)</sup>
- Boxentriq (substitution solvers).<sup>[[9]](#references)</sup>

### Majukwaa ya mazoezi / marejeo

- CryptoHack (changamoto za cryptography za vitendo).<sup>[[10]](#references)</sup>
- Cryptopals (changamoto za kawaida za modern cryptography).<sup>[[11]](#references)</sup>

### Decoding ya kiotomatiki

- Ciphey.<sup>[[12]](#references)</sup>
- python-codext (hujaribu bases/encodings nyingi).<sup>[[13]](#references)</sup>

Kwa msimbo wa lugha zisizo za kawaida na hali maalum ya interpreter, angalia [Crypto CTF Misc](../ctf-misc/).

## Encodings na classical ciphers

### Mbinu

Kazi nyingi za crypto za CTF hutumia transforms zilizopangwa kwa tabaka: base encoding + simple substitution + compression. Lengo ni kutambua tabaka na kuziondoa kwa usalama.

### Encodings: jaribu bases nyingi

Ikiwa unashuku encoding yenye tabaka (base64 → base32 → …), jaribu:

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

Dalili za kawaida:

- Base64: `A-Za-z0-9+/=` (padding `=` hutumika mara nyingi)
- Base32: `A-Z2-7=` (mara nyingi huwa na padding nyingi za `=`)
- Ascii85/Base85: alama nyingi za uandishi; wakati mwingine huwekwa ndani ya `<~ ~>`

### Substitution / monoalphabetic

- Boxentriq cryptogram solver.<sup>[[9]](#references)</sup>
- quipqiup.<sup>[[14]](#references)</sup>

#### Urejeshaji wa known-plaintext wa majina ya faili ya Base32 yaliyobadilishwa

Ikiwa jina la faili lililofichwa linatumia `a-z2-7` pekee, linakuwa na takriban `ceil(8 * byte_length / 5)` herufi baada ya kuondoa suffix isiyobadilika, na plaintext ileile hutoa matokeo yaleyale kwenye faili tofauti, jaribu **unpadded Base32 ikifuatiwa na fixed symbol substitution**. Dalili hizi hazitoshi kuthibitisha hilo zenyewe. Kusanya majina ya faili yanayotabirika na ciphertext zake, hifadhi herufi kubwa na ndogo kama zilivyo, encode kila plaintext kwa Base32, kisha linganisha alama moja baada ya nyingine. Kila alama ya plaintext inayojirudia lazima ihusishwe na alama ileile ya ciphertext, na mapping ya kinyume lazima pia iwe ya kipekee. Katika tukio moja la ransomware, `ntuser.ini` na `NTUSER.DAT` zilitoa jozi kama hizo; jambo hili liliwezesha kurejesha majina ya faili, **si maudhui ya faili au funguo za encryption**.<sup>[[28]](#references)</sup>

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

Ikiwa target ina alama ambazo hazijapangiwa, pata jozi zaidi zinazojulikana au badilisha tu upangaji wa alama za Base32 ambazo hazijatumika. Rejesha padding ili kufikia urefu unaogawanyika kwa nane, kataa Base32 isiyo halali na majina yaliyodekodiwa yasiyoweza kuchapishwa, kisha encode upya wagombea waliosalia na ulinganishe **ciphertext nzima** ya awali. Vitalu vya ciphertext vinavyojirudia vinaweza kutoa makisio ya ziada: katika mfano ulio hapo juu, `3gpng2wv` ilipangwa kurudi kwenye Base32 `gaydambq`, ambayo hufasiriwa kuwa sufuri tano za ASCII. Mgombea unaoweza kuchapishwa pekee si uthibitisho wa kipekee.<sup>[[28]](#references)</sup>

### Caesar / ROT / Atbash

- Kivunja-cipher cha Caesar cha kiotomatiki cha Nayuki.<sup>[[15]](#references)</sup>
- Zana ya Atbash ya Rumkin.<sup>[[16]](#references)</sup>

### Vigenère

- Zana ya Vigenère ya dCode.<sup>[[8]](#references)</sup>
- Kitatuzi cha Vigenère cha Guballa.<sup>[[17]](#references)</sup>

### Bacon cipher

Mara nyingi huonekana katika makundi ya biti 5 au herufi 5:

```
00111 01101 01010 00000 ...
AABBB ABBAB ABABA AAAAA ...
```

### Morse

```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```

### Runes

Runes mara nyingi huwa alfabeti za ubadilishaji; tafuta "futhark cipher" na ujaribu jedwali za ulinganishaji.

## Ukandamizaji katika changamoto

### Mbinu

Ukandamizaji huonekana mara kwa mara kama safu ya ziada (zlib/deflate/gzip/xz/zstd), wakati mwingine ikiwa imepachikwa ndani ya ukandamizaji mwingine. Ikiwa matokeo yanakaribia kuchanganulika lakini yanaonekana kama data isiyoeleweka, shuku ukandamizaji.

### Utambuzi wa haraka

- `file <blob>`
- Tafuta byte za utambulisho:
  - gzip: `1f 8b`
  - zlib: mara nyingi `78 01`, `78 5e`, `78 9c`, au `78 da` (byte ya pili hutegemea bendera za ukandamizaji)
  - zip: `50 4b 03 04`
  - bzip2: `42 5a 68` (`BZh`)
  - xz: `fd 37 7a 58 5a 00`
  - zstd: `28 b5 2f fd`

### DEFLATE ghafi

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

## Miundo ya crypto ya kawaida katika CTF

### Mbinu

Hii hutokea mara nyingi kwa sababu ni makosa halisi ya watengenezaji au matumizi yasiyo sahihi ya maktaba za kawaida. Lengo kwa kawaida ni kuitambua na kutumia utaratibu unaojulikana wa kutoa au kujenga upya data.

### Fernet

Kidokezo cha kawaida: mifuatano miwili ya Base64 (token + key).

- Decoder/maelezo: Asecuritysite Fernet decoder.<sup>[[18]](#references)</sup>
- Katika Python: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

Ukiona shares nyingi na kizingiti `t` kimetajwa, kuna uwezekano ni Shamir.

- Zana ya kujenga upya mtandaoni (kwa shares za CTF zisizo nyeti pekee).<sup>[[19]](#references)</sup>

### Miundo ya OpenSSL yenye chumvi

Wakati mwingine CTF hutoa matokeo ya `openssl enc` (header mara nyingi huanza na `Salted__`).

Zana saidizi za bruteforce:

- `bruteforce-salted-openssl`.<sup>[[20]](#references)</sup>
- `easy_BFopensslCTF`.<sup>[[21]](#references)</sup>

### Seti ya jumla ya zana

- RsaCtfTool.<sup>[[22]](#references)</sup>
- featherduster.<sup>[[23]](#references)</sup>
- cryptovenom.<sup>[[24]](#references)</sup>

## Mpangilio wa ndani unaopendekezwa

Seti ya vitendo ya CTF:

- Python pamoja na `pycryptodome` kwa primitives za symmetric na uundaji wa prototypes kwa haraka.<sup>[[25]](#references)</sup>
- SageMath kwa hesabu za modular, CRT, lattices, na kazi za RSA/ECC.<sup>[[26]](#references)</sup>
- Z3 kwa changamoto zinazotegemea constraints (wakati crypto inapoweza kuwakilishwa kama constraints).<sup>[[27]](#references)</sup>

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
- [17] [Kitatua cha Vigenère cha Guballa](https://www.guballa.de/vigenere-solver)
- [18] [Asecuritysite - Dekoda ya Fernet](https://asecuritysite.com/encryption/ferdecode)
- [19] [Kijenzi upya cha ugawaji-siri wa Shamir](https://christian.gen.co/secrets/)
- [20] [bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
- [21] [easy_BFopensslCTF](https://github.com/carlospolop/easy_BFopensslCTF)
- [22] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [23] [featherduster](https://github.com/nccgroup/featherduster)
- [24] [cryptovenom](https://github.com/lockedbyte/cryptovenom)
- [25] [Hati za PyCryptodome](https://pycryptodome.readthedocs.io/en/latest/)
- [26] [SageMath](https://www.sagemath.org/)
- [27] [Z3](https://github.com/Z3Prover/z3)
- [28] [Eye Research – Kuvunja mifumo ya usimbaji fiche kwa njia rahisi](https://labs.eye.security/breaking-encryption-schemes-the-lazy-way/)
{{#include ../../banners/hacktricks-training.md}}
