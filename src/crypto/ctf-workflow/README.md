# Flux de travail Crypto CTF

{{#include ../../banners/hacktricks-training.md}}

## Liste de vérification de triage

1. Identifiez ce que vous avez : encoding vs encryption vs hash vs signature vs MAC.
2. Déterminez ce qui est contrôlé : plaintext/ciphertext, IV/nonce, key, oracle (padding/error/timing), partial leakage.
3. Classifiez : symmetric (AES/CTR/GCM), public-key (RSA/ECC), hash/MAC (SHA/MD5/HMAC), classical (Vigenere/XOR).
4. Appliquez d'abord les vérifications les plus probables : décodage des couches, known-plaintext XOR, nonce reuse, mode misuse, oracle behavior.
5. N'utilisez des méthodes avancées que si nécessaire : lattices (LLL/Coppersmith), SMT/Z3, side-channels.

## Ressources en ligne & utilitaires

Utile pour l'identification et le décorticage des couches, ou lorsque vous avez besoin d'une confirmation rapide d'une hypothèse.

### Hash lookups

- Cherchez le hash sur Google (surprenamment efficace).
- https://crackstation.net/
- https://md5decrypt.net/
- https://hashes.org/search.php
- https://www.onlinehashcrack.com/
- https://gpuhash.me/
- http://hashtoolkit.com/reverse-hash

### Aides à l'identification

- CyberChef (magique, décoder, convertir): https://gchq.github.io/CyberChef/
- dCode (playground pour ciphers/encodings): https://www.dcode.fr/tools-list
- Boxentriq (solveurs de substitution): https://www.boxentriq.com/code-breaking

### Plateformes d'entraînement / références

- CryptoHack (challenges crypto pratiques): https://cryptohack.org/
- Cryptopals (pièges classiques de la crypto moderne): https://cryptopals.com/

### Décodage automatisé

- Ciphey: https://github.com/Ciphey/Ciphey
- python-codext (essaie de nombreuses bases/encodings): https://github.com/dhondta/python-codext

## Encodings & classical ciphers

### Technique

De nombreuses tâches crypto CTF sont des transformations en couches : base encoding + simple substitution + compression. L'objectif est d'identifier les couches et de les décortiquer en toute sécurité.

### Encodings: try many bases

Si vous suspectez un encodage en couches (base64 → base32 → …), essayez :

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

Signes courants :

- Base64: `A-Za-z0-9+/=` (padding `=` est courant)
- Base32: `A-Z2-7=` (souvent beaucoup de padding `=`)
- Ascii85/Base85: ponctuation dense ; parfois encadré par `<~ ~>`

### Substitution / monoalphabetic

- Boxentriq cryptogram solver: https://www.boxentriq.com/code-breaking/cryptogram
- quipqiup: https://quipqiup.com/

### Caesar / ROT / Atbash

- Nayuki auto breaker: https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript
- Atbash: http://rumkin.com/tools/cipher/atbash.php

### Vigenère

- https://www.dcode.fr/vigenere-cipher
- https://www.guballa.de/vigenere-solver

### Bacon cipher

Apparaît souvent sous forme de groupes de 5 bits ou 5 lettres :
```
00111 01101 01010 00000 ...
AABBB ABBAB ABABA AAAAA ...
```
### Morse
```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```
### Runes

Les runes sont fréquemment des alphabets de substitution ; recherchez "futhark cipher" et essayez des tables de correspondance.

## Compression in challenges

### Technique

La compression apparaît constamment comme une couche supplémentaire (zlib/deflate/gzip/xz/zstd), parfois imbriquée. Si la sortie se parse presque mais ressemble à des données illisibles, suspectez une compression.

### Quick identification

- `file <blob>`
- Cherchez les octets magiques :
- gzip: `1f 8b`
- zlib: souvent `78 01/9c/da`
- zip: `50 4b 03 04`
- bzip2: `42 5a 68` (`BZh`)
- xz: `fd 37 7a 58 5a 00`
- zstd: `28 b5 2f fd`

### Raw DEFLATE

CyberChef propose **Raw Deflate/Raw Inflate**, souvent la voie la plus rapide lorsque le blob semble compressé mais que `zlib` échoue.

### Commandes utiles
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
## Common CTF crypto constructs

### Technique

Ils apparaissent fréquemment parce qu'il s'agit d'erreurs réalistes de développeurs ou de bibliothèques courantes mal utilisées. L'objectif est généralement la reconnaissance et l'application d'un workflow connu d'extraction ou de reconstruction.

### Fernet

Indice typique : deux chaînes Base64 (token + key).

- Decodeur/notes: https://asecuritysite.com/encryption/ferdecode
- En Python : `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

Si vous voyez plusieurs shares et qu'un seuil `t` est mentionné, il s'agit probablement de Shamir.

- Online reconstructor (handy for CTFs): http://christian.gen.co/secrets/

### OpenSSL salted formats

Les CTF fournissent parfois des sorties `openssl enc` (l'en-tête commence souvent par `Salted__`).

Aides au bruteforce :

- https://github.com/glv2/bruteforce-salted-openssl
- https://github.com/carlospolop/easy_BFopensslCTF

### Outils généraux

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- featherduster: https://github.com/nccgroup/featherduster
- cryptovenom: https://github.com/lockedbyte/cryptovenom

## Configuration locale recommandée

Stack CTF pratique :

- Python + `pycryptodome` pour les primitives symétriques et le prototypage rapide
- SageMath pour l'arithmétique modulaire, CRT, les réseaux (lattices) et le travail sur RSA/ECC
- Z3 pour les challenges basés sur des contraintes (quand le crypto se réduit à des contraintes)

Paquets Python suggérés:
```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```
{{#include ../../banners/hacktricks-training.md}}
