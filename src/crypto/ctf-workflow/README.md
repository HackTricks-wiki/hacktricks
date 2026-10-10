# Crypto CTF-werkvloei

{{#include ../../banners/hacktricks-training.md}}

## Triage-kontrolelys

1. Identifiseer wat jy het: encoding teenoor encryption teenoor hash teenoor signature teenoor MAC.
2. Bepaal wat beheer word: plaintext/ciphertext, IV/nonce, key, oracle (padding/error/timing), gedeeltelike leakage.
3. Klassifiseer: simmetries (AES/CTR/GCM), public-key (RSA/ECC), hash/MAC (SHA/MD5/HMAC), klassiek (Vigenere/XOR).
4. Pas eers die kontroles met die hoogste waarskynlikheid toe: decode lae, known-plaintext XOR, nonce-hergebruik, misbruik van modes, oracle-gedrag.
5. Skuif slegs na gevorderde metodes wanneer nodig: lattices (LLL/Coppersmith), SMT/Z3, side-channels.

## Aanlyn hulpbronne en nutsprogramme

Dit is nuttig wanneer die taak identifikasie en die afskil van lae behels, of wanneer jy vinnig ’n hipotese wil bevestig.

### Hash-opsoeke

- Soek na ’n challenge-hash wanneer dit bekend is dat dit sinteties/openbaar is.
- CrackStation.<sup>[[1]](#references)</sup>
- MD5Decrypt.<sup>[[2]](#references)</sup>
- hashes.org-soektog.<sup>[[3]](#references)</sup>
- OnlineHashCrack.<sup>[[4]](#references)</sup>
- GPUHash.me.<sup>[[5]](#references)</sup>
- Hash Toolkit.<sup>[[6]](#references)</sup>

Moenie regte password hashes of vertroulike challenge-materiaal by derdeparty-opsoekdienste indien nie. Verkies ’n offline woordlys-/reël-aanval wanneer openbaarmaking, diensbepalings of kompetisiereëls ’n bekommernis is.

### Identifikasiehulpmiddels

- CyberChef (Magic, decoding en omskakeling).<sup>[[7]](#references)</sup>
- dCode (cipher-/encoding-speelplek).<sup>[[8]](#references)</sup>
- Boxentriq (substitution-oplossers).<sup>[[9]](#references)</sup>

### Oefenplatforms / verwysings

- CryptoHack (praktiese kriptografie-uitdagings).<sup>[[10]](#references)</sup>
- Cryptopals (klassieke slaggate in moderne kriptografie).<sup>[[11]](#references)</sup>

### Outomatiese decoding

- Ciphey.<sup>[[12]](#references)</sup>
- python-codext (probeer baie bases/encodings).<sup>[[13]](#references)</sup>

## Encodings en klassieke ciphers

### Tegniek

Baie CTF-crypto-take is gelaagde transformasies: base encoding + eenvoudige substitution + compression. Die doel is om die lae te identifiseer en dit veilig af te skil.

### Encodings: probeer baie bases

As jy gelaagde encoding vermoed (base64 → base32 → …), probeer:

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

Algemene aanduidings:

- Base64: `A-Za-z0-9+/=` (padding `=` is algemeen)
- Base32: `A-Z2-7=` (dikwels baie `=`-padding)
- Ascii85/Base85: digte leestekens; soms omring deur `<~ ~>`

### Substitution / monoalphabeties

- Boxentriq-kriptogramoplosser.<sup>[[9]](#references)</sup>
- quipqiup.<sup>[[14]](#references)</sup>

### Caesar / ROT / Atbash

- Nayuki se outomatiese Caesar-cipher-kraker.<sup>[[15]](#references)</sup>
- Rumkin Atbash-nutsprogram.<sup>[[16]](#references)</sup>

### Vigenère

- dCode Vigenère-nutsprogram.<sup>[[8]](#references)</sup>
- Guballa Vigenère-oplosser.<sup>[[17]](#references)</sup>

### Bacon-cipher

Kom dikwels voor as groepe van 5 bits of 5 letters:

```
00111 01101 01010 00000 ...
AABBB ABBAB ABABA AAAAA ...
```

### Morse

```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```

### Runes

Runes is dikwels substitusie-alfabette; soek vir "futhark cipher" en probeer karteringstabelle.

## Kompressie in uitdagings

### Tegniek

Kompressie kom voortdurend voor as ’n ekstra laag (zlib/deflate/gzip/xz/zstd), soms genestel. As die uitvoer amper ontleed kan word, maar soos gemors lyk, vermoed kompressie.

### Vinnige identifikasie

- `file <blob>`
- Soek na magic bytes:
  - gzip: `1f 8b`
  - zlib: gewoonlik `78 01`, `78 5e`, `78 9c` of `78 da` (die tweede byte hang van die kompressievlae af)
  - zip: `50 4b 03 04`
  - bzip2: `42 5a 68` (`BZh`)
  - xz: `fd 37 7a 58 5a 00`
  - zstd: `28 b5 2f fd`

### Raw DEFLATE

CyberChef het **Raw Deflate/Raw Inflate**, wat dikwels die vinnigste oplossing is wanneer die blob saamgepers lyk, maar `zlib` misluk.

### Nuttige CLI

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

## Algemene CTF-crypto-konstruksies

### Tegniek

Dit kom gereeld voor omdat dit realistiese ontwikkelaarsfoute is of algemene libraries is wat verkeerd gebruik word. Die doel is gewoonlik om dit te herken en ’n bekende onttrekkings- of rekonstruksiewerkvloei toe te pas.

### Fernet

Tipiese wenk: twee Base64-stringe (token + key).

- Decoder/notas: Asecuritysite Fernet decoder.<sup>[[18]](#references)</sup>
- In Python: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

As jy verskeie shares sien en ’n drempel `t` genoem word, is dit waarskynlik Shamir.

- Aanlyn rekonstruktor (slegs vir nie-sensitiewe CTF-shares).<sup>[[19]](#references)</sup>

### OpenSSL-gesoute formate

CTF’s gee soms `openssl enc`-uitsette (die koptekst begin dikwels met `Salted__`).

Bruteforce-hulpmiddels:

- `bruteforce-salted-openssl`.<sup>[[20]](#references)</sup>
- `easy_BFopensslCTF`.<sup>[[21]](#references)</sup>

### Algemene gereedskapstel

- RsaCtfTool.<sup>[[22]](#references)</sup>
- featherduster.<sup>[[23]](#references)</sup>
- cryptovenom.<sup>[[24]](#references)</sup>

## Aanbevole plaaslike opstelling

Praktiese CTF-stapel:

- Python plus `pycryptodome` vir simmetriese primitiewe en vinnige prototipering.<sup>[[25]](#references)</sup>
- SageMath vir modulêre rekenkunde, CRT, roosters en RSA/ECC-werk.<sup>[[26]](#references)</sup>
- Z3 vir beperkingsgebaseerde uitdagings (wanneer die crypto tot beperkings gereduseer kan word).<sup>[[27]](#references)</sup>

Voorgestelde Python-pakkette:

```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```

## References

- [1] [CrackStation](https://crackstation.net/)
- [2] [MD5Decrypt](https://md5decrypt.net/)
- [3] [hashes.org-soektog](https://hashes.org/search.php)
- [4] [OnlineHashCrack](https://www.onlinehashcrack.com/)
- [5] [GPUHash.me](https://gpuhash.me/)
- [6] [Hash Toolkit](https://hashtoolkit.com/reverse-hash)
- [7] [GCHQ CyberChef](https://gchq.github.io/CyberChef/)
- [8] [dCode-gereedskap](https://www.dcode.fr/tools-list)
- [9] [Boxentriq se kodebreekgereedskap](https://www.boxentriq.com/code-breaking)
- [10] [CryptoHack](https://cryptohack.org/)
- [11] [Cryptopals](https://cryptopals.com/)
- [12] [Ciphey](https://github.com/Ciphey/Ciphey)
- [13] [python-codext](https://github.com/dhondta/python-codext)
- [14] [quipqiup](https://quipqiup.com/)
- [15] [Nayuki - Outomatiese Caesar-syferkraker](https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript)
- [16] [Rumkin - Atbash-syfer](https://rumkin.com/tools/cipher/atbash/)
- [17] [Guballa Vigenère-oplosser](https://www.guballa.de/vigenere-solver)
- [18] [Asecuritysite - Fernet-dekodeerder](https://asecuritysite.com/encryption/ferdecode)
- [19] [Shamir-geheimedelingsherbouer](https://christian.gen.co/secrets/)
- [20] [bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
- [21] [easy_BFopensslCTF](https://github.com/carlospolop/easy_BFopensslCTF)
- [22] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [23] [featherduster](https://github.com/nccgroup/featherduster)
- [24] [cryptovenom](https://github.com/lockedbyte/cryptovenom)
- [25] [PyCryptodome-dokumentasie](https://pycryptodome.readthedocs.io/en/latest/)
- [26] [SageMath](https://www.sagemath.org/)
- [27] [Z3](https://github.com/Z3Prover/z3)
{{#include ../../banners/hacktricks-training.md}}
