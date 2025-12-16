# Crypto CTF-werksvloei

{{#include ../../banners/hacktricks-training.md}}

## Triage-kontrolelys

1. Identifiseer wat jy het: encoding vs encryption vs hash vs signature vs MAC.
2. Bepaal wat beheer word: plaintext/ciphertext, IV/nonce, key, oracle (padding/error/timing), partial leakage.
3. Klassifiseer: symmetric (AES/CTR/GCM), public-key (RSA/ECC), hash/MAC (SHA/MD5/HMAC), classical (Vigenere/XOR).
4. Voer eers die kansrykste kontroles uit: dekodeer lae, known-plaintext XOR, nonce reuse, mode misuse, oracle behavior.
5. Skakel slegs na gevorderde metodes as dit nodig is: lattices (LLL/Coppersmith), SMT/Z3, side-channels.

## Aanlyn hulpbronne & nutsprogramme

Hierdie is nuttig wanneer die taak identifikasie en laagverwydering is, of wanneer jy vinnige bevestiging van 'n hipotese nodig het.

### Hash-opsoeke

- Google die hash (verbasend effektief).
- [https://crackstation.net/](https://crackstation.net/)
- [https://md5decrypt.net/](https://md5decrypt.net/)
- [https://hashes.org/search.php](https://hashes.org/search.php)
- [https://www.onlinehashcrack.com/](https://www.onlinehashcrack.com/)
- [https://gpuhash.me/](https://gpuhash.me/)
- [http://hashtoolkit.com/reverse-hash](http://hashtoolkit.com/reverse-hash)

### Identifikasie-hulpmiddels

- CyberChef (magie, dekodeer, omskakel): https://gchq.github.io/CyberChef/
- dCode (ciphers/encodings playground): https://www.dcode.fr/tools-list
- Boxentriq (substitusie-oplossers): https://www.boxentriq.com/code-breaking

### Oefenplatforms / verwysings

- CryptoHack (hands-on crypto challenges): https://cryptohack.org/
- Cryptopals (classic modern crypto pitfalls): https://cryptopals.com/

### Outomatiese dekodering

- Ciphey: https://github.com/Ciphey/Ciphey
- python-codext (tries many bases/encodings): https://github.com/dhondta/python-codext

## Enkoderinge & klassieke sifferings

### Tegniek

Baie CTF-crypto-take is gelaagde transformasies: base encoding + simple substitution + compression. Die doel is om lae te identifiseer en dit veilig af te pel.

### Enkoderinge: probeer verskeie basisse

As jy vermoed daar is gelaagde enkodering (base64 → base32 → …), probeer:

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

Algemene tekens:

- Base64: `A-Za-z0-9+/=` (padding `=` is algemeen)
- Base32: `A-Z2-7=` (dikwels baie `=` padding)
- Ascii85/Base85: digte leestekens; soms omhul met `<~ ~>`

### Substitusie / monoalfabeties

- Boxentriq cryptogram solver: https://www.boxentriq.com/code-breaking/cryptogram
- quipqiup: https://quipqiup.com/

### Caesar / ROT / Atbash

- Nayuki auto breaker: https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript
- Atbash: http://rumkin.com/tools/cipher/atbash.php

### Vigenère

- [https://www.dcode.fr/vigenere-cipher](https://www.dcode.fr/vigenere-cipher)
- [https://www.guballa.de/vigenere-solver](https://www.guballa.de/vigenere-solver)

### Bacon cipher

Kom dikwels voor as groepe van 5 bits of 5 letters:
```
00111 01101 01010 00000 ...
AABBB ABBAB ABABA AAAAA ...
```
### Morse
```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```
### Runetekens

Runetekens is dikwels substitusie-alfabette; soek na "futhark cipher" en probeer toewysingstabellen.

## Kompressie in uitdagings

### Tegniek

Kompressie verskyn gereeld as 'n ekstra laag (zlib/deflate/gzip/xz/zstd), soms geneste. As die uitvoer amper parsbaar is maar na rommel lyk, vermoed kompressie.

### Vinnige identifikasie

- `file <blob>`
- Soek na magic bytes:
- gzip: `1f 8b`
- zlib: often `78 01/9c/da`
- zip: `50 4b 03 04`
- bzip2: `42 5a 68` (`BZh`)
- xz: `fd 37 7a 58 5a 00`
- zstd: `28 b5 2f fd`

### Raw DEFLATE

CyberChef het **Raw Deflate/Raw Inflate**, wat dikwels die vinnigste pad is wanneer die blob na gekomprimeer lyk maar `zlib` faal.

### Nuttige CLI
```bash
python3 - <<'PY'
import sys, zlib
data = sys.stdin.buffer.read()
for wbits in [zlib.MAX_WBITS, -zlib.MAX_WBITS]:
try:
print(zlib.decompress(data, wbits=wbits)[:200])
except Exception:
pass
PY
```
## Algemene CTF-kripto-konstruksies

### Tegniek

Hierdie kom gereeld voor omdat dit realistiese ontwikkelaarfoute of algemene biblioteke is wat verkeerd gebruik word. Die doel is gewoonlik om dit te herken en 'n bekende ekstraheer- of herbou-werkstroom toe te pas.

### Fernet

Tipies: twee Base64-strings (token + sleutel).

- Dekoder/notas: https://asecuritysite.com/encryption/ferdecode
- In Python: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

As jy meerdere shares sien en 'n drempel `t` genoem word, is dit waarskynlik Shamir.

- Aanlyn-rekonstrukteur (handig vir CTFs): http://christian.gen.co/secrets/

### OpenSSL salted formats

CTFs gee soms `openssl enc`-uitsette (header begin dikwels met `Salted__`).

Bruteforce helpers:

- [https://github.com/glv2/bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
- [https://github.com/carlospolop/easy_BFopensslCTF](https://github.com/carlospolop/easy_BFopensslCTF)

### Algemene gereedskapstel

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- featherduster: https://github.com/nccgroup/featherduster
- cryptovenom: https://github.com/lockedbyte/cryptovenom

## Aanbevole plaaslike opstelling

Praktiese CTF-stapel:

- Python + `pycryptodome` vir symmetriese primitives en vinnige prototipering
- SageMath vir modulêre rekenkunde, CRT, roosters, en RSA/ECC-werk
- Z3 vir beperkingsgebaseerde uitdagings (wanneer die crypto tot beperkings herlei word)

Voorgestelde Python-pakkette:
```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```
{{#include ../../banners/hacktricks-training.md}}
