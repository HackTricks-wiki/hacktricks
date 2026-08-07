# Workflow Crypto CTF

{{#include ../../banners/hacktricks-training.md}}

## Checklist de triage

1. Identifiez ce que vous avez : encoding vs encryption vs hash vs signature vs MAC.
2. Déterminez ce qui est contrôlé : plaintext/ciphertext, IV/nonce, key, oracle (padding/error/timing), partial leak.
3. Classez : symmetric (AES/CTR/GCM), public-key (RSA/ECC), hash/MAC (SHA/MD5/HMAC), classical (Vigenere/XOR).
4. Appliquez d’abord les vérifications les plus probables : décoder les couches, known-plaintext XOR, réutilisation du nonce, mauvaise utilisation du mode, comportement de l’oracle.
5. Passez aux méthodes avancées uniquement si nécessaire : lattices (LLL/Coppersmith), SMT/Z3, side-channels.

## Ressources en ligne et utilitaires

Ces ressources sont utiles lorsque la tâche consiste à identifier et retirer des couches, ou lorsque vous avez besoin de confirmer rapidement une hypothèse.

### Recherche de hash

- Recherchez le hash sur Google (étonnamment efficace).
- [https://crackstation.net/](https://crackstation.net/)
- [https://md5decrypt.net/](https://md5decrypt.net/)
- [https://hashes.org/search.php](https://hashes.org/search.php)
- [https://www.onlinehashcrack.com/](https://www.onlinehashcrack.com/)
- [https://gpuhash.me/](https://gpuhash.me/)
- [http://hashtoolkit.com/reverse-hash](http://hashtoolkit.com/reverse-hash)

### Outils d’aide à l’identification

- CyberChef (magic, decode, convert) : https://gchq.github.io/CyberChef/
- dCode (playground de ciphers/encodings) : https://www.dcode.fr/tools-list
- Boxentriq (substitution solvers) : https://www.boxentriq.com/code-breaking

### Plateformes d’entraînement / références

- CryptoHack (hands-on crypto challenges) : https://cryptohack.org/
- Cryptopals (pièges classiques de la modern crypto) : https://cryptopals.com/

### Décodage automatisé

- Ciphey : https://github.com/Ciphey/Ciphey
- python-codext (essaie de nombreuses bases/encodings) : https://github.com/dhondta/python-codext

## Encodings et classical ciphers

### Technique

De nombreuses tâches de crypto CTF sont constituées de transformations en couches : base encoding + simple substitution + compression. L’objectif est d’identifier les couches et de les retirer prudemment.

### Encodings : essayer de nombreuses bases

Si vous soupçonnez un encoding en couches (base64 → base32 → …), essayez :

- CyberChef « Magic »
- `codext` (python-codext) : `codext <string>`

Signes courants :

- Base64 : `A-Za-z0-9+/=` (le padding `=` est fréquent)
- Base32 : `A-Z2-7=` (souvent beaucoup de padding `=`)
- Ascii85/Base85 : ponctuation dense ; parfois encadré par `<~ ~>`

### Substitution / monoalphabetic

- Boxentriq cryptogram solver : https://www.boxentriq.com/code-breaking/cryptogram
- quipqiup : https://quipqiup.com/

### Caesar / ROT / Atbash

- Nayuki auto breaker : https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript
- Atbash : http://rumkin.com/tools/cipher/atbash.php

### Vigenère

- [https://www.dcode.fr/vigenere-cipher](https://www.dcode.fr/vigenere-cipher)
- [https://www.guballa.de/vigenere-solver](https://www.guballa.de/vigenere-solver)

### Bacon cipher

Apparaît souvent sous forme de groupes de 5 bits ou de 5 lettres :
```
00111 01101 01010 00000 ...
AABBB ABBAB ABABA AAAAA ...
```
### Morse
```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```
### Runes

Les runes sont fréquemment des alphabets de substitution ; recherchez « futhark cipher » et essayez les tables de correspondance.

## Compression dans les challenges

### Technique

La compression apparaît constamment comme couche supplémentaire (zlib/deflate/gzip/xz/zstd), parfois imbriquée. Si la sortie est presque parsable, mais ressemble à du charabia, suspectez une compression.

### Identification rapide

- `file <blob>`
- Recherchez les magic bytes :
- gzip : `1f 8b`
- zlib : souvent `78 01/9c/da`
- zip : `50 4b 03 04`
- bzip2 : `42 5a 68` (`BZh`)
- xz : `fd 37 7a 58 5a 00`
- zstd : `28 b5 2f fd`

### Raw DEFLATE

CyberChef possède **Raw Deflate/Raw Inflate**, ce qui constitue souvent la méthode la plus rapide lorsque le blob semble compressé, mais que `zlib` échoue.

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
## Constructions cryptographiques courantes des CTF

### Technique

Elles apparaissent fréquemment, car elles correspondent à des erreurs réalistes de développeurs ou à des bibliothèques courantes mal utilisées. L’objectif consiste généralement à les reconnaître et à appliquer un workflow connu d’extraction ou de reconstruction.

### Fernet

Indice typique : deux chaînes Base64 (token + key).

- Decoder/notes: https://asecuritysite.com/encryption/ferdecode
- En Python : `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

Si vous voyez plusieurs shares et qu’un seuil `t` est mentionné, il s’agit probablement de Shamir.

- Online reconstructor (pratique pour les CTFs) : http://christian.gen.co/secrets/

### Formats OpenSSL salted

Les CTFs fournissent parfois des sorties de `openssl enc` (l’en-tête commence souvent par `Salted__`).

Bruteforce helpers :

- [https://github.com/glv2/bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
- [https://github.com/carlospolop/easy_BFopensslCTF](https://github.com/carlospolop/easy_BFopensslCTF)

### General toolset

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- featherduster: https://github.com/nccgroup/featherduster
- cryptovenom: https://github.com/lockedbyte/cryptovenom

## Configuration locale recommandée

Stack CTF pratique :

- Python + `pycryptodome` pour les primitives symétriques et le prototypage rapide
- SageMath pour l’arithmétique modulaire, le CRT, les réseaux et le travail sur RSA/ECC
- Z3 pour les challenges fondés sur des contraintes (lorsque la cryptographie se réduit à des contraintes)

Packages Python suggérés :
```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```
{{#include ../../banners/hacktricks-training.md}}
