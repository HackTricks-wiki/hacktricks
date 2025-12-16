# Crypto CTF Workflow

{{#include ../../banners/hacktricks-training.md}}

## Liste de contrôle de triage

1. Identifiez ce que vous avez : encoding vs encryption vs hash vs signature vs MAC.
2. Déterminez ce qui est contrôlé : plaintext/ciphertext, IV/nonce, key, oracle (padding/error/timing), partial leakage.
3. Classez : symmetric (AES/CTR/GCM), public-key (RSA/ECC), hash/MAC (SHA/MD5/HMAC), classical (Vigenere/XOR).
4. Appliquez d’abord les vérifications à plus haute probabilité : décoder les couches, known-plaintext XOR, réutilisation de nonce, mauvaise utilisation du mode, comportement de l’oracle.
5. Montez en complexité uniquement si nécessaire : lattices (LLL/Coppersmith), SMT/Z3, side-channels.

## Ressources en ligne & utilitaires

Ceux-ci sont utiles quand la tâche est l’identification et le pelage des couches, ou quand vous avez besoin d’une confirmation rapide d’une hypothèse.

### Hash lookups

- Google the hash (surprisingly effective).
- [https://crackstation.net/](https://crackstation.net/)
- [https://md5decrypt.net/](https://md5decrypt.net/)
- [https://hashes.org/search.php](https://hashes.org/search.php)
- [https://www.onlinehashcrack.com/](https://www.onlinehashcrack.com/)
- [https://gpuhash.me/](https://gpuhash.me/)
- [http://hashtoolkit.com/reverse-hash](http://hashtoolkit.com/reverse-hash)

### Aides à l'identification

- CyberChef (magic, decode, convert): https://gchq.github.io/CyberChef/
- dCode (ciphers/encodings playground): https://www.dcode.fr/tools-list
- Boxentriq (substitution solvers): https://www.boxentriq.com/code-breaking

### Plateformes de pratique / références

- CryptoHack (hands-on crypto challenges): https://cryptohack.org/
- Cryptopals (classic modern crypto pitfalls): https://cryptopals.com/

### Décodage automatisé

- Ciphey: https://github.com/Ciphey/Ciphey
- python-codext (tries many bases/encodings): https://github.com/dhondta/python-codext

## Encodages & chiffrements classiques

### Technique

Beaucoup de challenges crypto en CTF sont des transformations en couches : base encoding + simple substitution + compression. L’objectif est d’identifier les couches et de les enlever en toute sécurité.

### Encodages : tester de nombreuses bases

Si vous suspectez un encodage en couches (base64 → base32 → …), essayez :

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

Indicateurs courants :

- Base64: `A-Za-z0-9+/=` (padding `=` is common)
- Base32: `A-Z2-7=` (often lots of `=` padding)
- Ascii85/Base85: ponctuation dense ; parfois encadré par `<~ ~>`

### Substitution / monoalphabetic

- Boxentriq cryptogram solver: https://www.boxentriq.com/code-breaking/cryptogram
- quipqiup: https://quipqiup.com/

### Caesar / ROT / Atbash

- Nayuki auto breaker: https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript
- Atbash: http://rumkin.com/tools/cipher/atbash.php

### Vigenère

- [https://www.dcode.fr/vigenere-cipher](https://www.dcode.fr/vigenere-cipher)
- [https://www.guballa.de/vigenere-solver](https://www.guballa.de/vigenere-solver)

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

Les runes sont fréquemment des alphabets de substitution ; cherchez "futhark cipher" et essayez des tables de correspondance.

## Compression dans les défis

### Technique

La compression apparaît constamment comme une couche supplémentaire (zlib/deflate/gzip/xz/zstd), parfois emboîtée. Si la sortie se parse presque mais ressemble à des données illisibles, suspectez la compression.

### Identification rapide

- `file <blob>`
- Cherchez les octets magiques :
- gzip: `1f 8b`
- zlib: often `78 01/9c/da`
- zip: `50 4b 03 04`
- bzip2: `42 5a 68` (`BZh`)
- xz: `fd 37 7a 58 5a 00`
- zstd: `28 b5 2f fd`

### Raw DEFLATE

CyberChef propose **Raw Deflate/Raw Inflate**, souvent le chemin le plus rapide lorsque le blob semble compressé mais que `zlib` échoue.

### CLI utiles
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
## Constructions cryptographiques courantes pour CTF

### Technique

Celles-ci apparaissent fréquemment parce qu'il s'agit d'erreurs réalistes de développeurs ou de bibliothèques courantes mal utilisées. L'objectif est généralement la reconnaissance et l'application d'un flux de travail connu d'extraction ou de reconstruction.

### Fernet

Indice typique : deux chaînes Base64 (token + key).

- Décodeur/notes: https://asecuritysite.com/encryption/ferdecode
- En Python: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

Si vous voyez plusieurs shares et qu'un seuil `t` est mentionné, il s'agit probablement de Shamir.

- Reconstructeur en ligne (pratique pour les CTFs): http://christian.gen.co/secrets/

### OpenSSL salted formats

Les CTFs fournissent parfois des sorties `openssl enc` (l'en-tête commence souvent par `Salted__`).

Bruteforce helpers:

- [https://github.com/glv2/bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
- [https://github.com/carlospolop/easy_BFopensslCTF](https://github.com/carlospolop/easy_BFopensslCTF)

### General toolset

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- featherduster: https://github.com/nccgroup/featherduster
- cryptovenom: https://github.com/lockedbyte/cryptovenom

## Configuration locale recommandée

Stack pratique pour CTF:

- Python + `pycryptodome` pour les primitives symétriques et le prototypage rapide
- SageMath pour l'arithmétique modulaire, CRT, les lattices, et le travail RSA/ECC
- Z3 pour les challenges basés sur des contraintes (lorsque la crypto se réduit à des contraintes)

Packages Python suggérés:
```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```
{{#include ../../banners/hacktricks-training.md}}
