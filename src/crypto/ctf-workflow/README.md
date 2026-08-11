# Workflow Crypto CTF

{{#include ../../banners/hacktricks-training.md}}

## Checklist de triage

1. Identifiez ce que vous avez : encoding vs encryption vs hash vs signature vs MAC.
2. Déterminez ce qui est contrôlé : plaintext/ciphertext, IV/nonce, key, oracle (padding/error/timing), partial leakage.
3. Classez : symmetric (AES/CTR/GCM), public-key (RSA/ECC), hash/MAC (SHA/MD5/HMAC), classical (Vigenere/XOR).
4. Appliquez d’abord les vérifications les plus probables : décoder les layers, known-plaintext XOR, nonce reuse, mode misuse, comportement de l’oracle.
5. Passez aux méthodes avancées uniquement si nécessaire : lattices (LLL/Coppersmith), SMT/Z3, side-channels.

## Ressources en ligne et utilities

Elles sont utiles lorsque la tâche consiste à identifier et retirer des layers, ou lorsque vous avez besoin de confirmer rapidement une hypothèse.

### Recherches de hash

- Recherchez un hash de challenge lorsqu’il est connu pour être synthetic/public.
- CrackStation.<sup>[[1]](#references)</sup>
- MD5Decrypt.<sup>[[2]](#references)</sup>
- Recherche sur hashes.org.<sup>[[3]](#references)</sup>
- OnlineHashCrack.<sup>[[4]](#references)</sup>
- GPUHash.me.<sup>[[5]](#references)</sup>
- Hash Toolkit.<sup>[[6]](#references)</sup>

Ne soumettez pas de vrais password hashes ni de contenu confidentiel de challenge à des services de lookup tiers. Préférez une attaque offline avec wordlist/rule lorsque la divulgation, les conditions d’utilisation ou les règles de la compétition posent problème.

### Helpers d’identification

- CyberChef (Magic, decoding et conversion).<sup>[[7]](#references)</sup>
- dCode (cipher/encoding playground).<sup>[[8]](#references)</sup>
- Boxentriq (substitution solvers).<sup>[[9]](#references)</sup>

### Plateformes de pratique / références

- CryptoHack (hands-on cryptography challenges).<sup>[[10]](#references)</sup>
- Cryptopals (pièges classiques de la modern cryptography).<sup>[[11]](#references)</sup>

### Décodage automatisé

- Ciphey.<sup>[[12]](#references)</sup>
- python-codext (essaie de nombreuses bases/encodings).<sup>[[13]](#references)</sup>

## Encodings et classical ciphers

### Technique

De nombreuses tâches de crypto CTF sont des transformations en layers : base encoding + simple substitution + compression. L’objectif est d’identifier les layers et de les retirer de manière sûre.

### Encodings : essayer plusieurs bases

Si vous soupçonnez un layered encoding (base64 → base32 → …), essayez :

- CyberChef "Magic"
- `codext` (python-codext) : `codext <string>`

Indices courants :

- Base64 : `A-Za-z0-9+/=` (le padding `=` est courant)
- Base32 : `A-Z2-7=` (beaucoup de padding `=` sont souvent présents)
- Ascii85/Base85 : ponctuation dense ; parfois entouré par `<~ ~>`

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

Apparaît souvent sous la forme de groupes de 5 bits ou de 5 lettres :
```
00111 01101 01010 00000 ...
AABBB ABBAB ABABA AAAAA ...
```
### Morse
```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```
### Runes

Les runes sont fréquemment des alphabets de substitution ; recherchez « futhark cipher » et essayez des tables de correspondance.

## Compression dans les challenges

### Technique

La compression apparaît constamment comme une couche supplémentaire (zlib/deflate/gzip/xz/zstd), parfois imbriquée. Si la sortie est presque analysable, mais ressemble à du charabia, suspectez une compression.

### Identification rapide

- `file <blob>`
- Recherchez les octets magiques :
- gzip : `1f 8b`
- zlib : généralement `78 01`, `78 5e`, `78 9c` ou `78 da` (le deuxième octet dépend des indicateurs de compression)
- zip : `50 4b 03 04`
- bzip2 : `42 5a 68` (`BZh`)
- xz : `fd 37 7a 58 5a 00`
- zstd : `28 b5 2f fd`

### Raw DEFLATE

CyberChef dispose de **Raw Deflate/Raw Inflate**, ce qui est souvent la méthode la plus rapide lorsque le blob semble compressé, mais que `zlib` échoue.

### CLI utiles
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
## Constructions cryptographiques courantes des CTF

### Technique

Elles apparaissent fréquemment, car elles correspondent à des erreurs réalistes de développeurs ou à des bibliothèques courantes mal utilisées. L'objectif est généralement de les reconnaître et d'appliquer un workflow connu d'extraction ou de reconstruction.

### Fernet

Indice typique : deux chaînes encodées en Base64 (token + key).

- Décodeur/notes : décodeur Fernet d'Asecuritysite.<sup>[[18]](#references)</sup>
- En Python : `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

Si vous voyez plusieurs shares et qu'un seuil `t` est mentionné, il s'agit probablement de Shamir.

- Reconstructeur en ligne (uniquement pour des shares de CTF non sensibles).<sup>[[19]](#references)</sup>

### Formats OpenSSL avec salt

Les CTF fournissent parfois des sorties de `openssl enc` (l'en-tête commence souvent par `Salted__`).

Helpers de bruteforce :

- `bruteforce-salted-openssl`.<sup>[[20]](#references)</sup>
- `easy_BFopensslCTF`.<sup>[[21]](#references)</sup>

### Boîte à outils générale

- RsaCtfTool.<sup>[[22]](#references)</sup>
- featherduster.<sup>[[23]](#references)</sup>
- cryptovenom.<sup>[[24]](#references)</sup>

## Configuration locale recommandée

Stack pratique pour les CTF :

- Python avec `pycryptodome` pour les primitives symétriques et le prototypage rapide.<sup>[[25]](#references)</sup>
- SageMath pour l'arithmétique modulaire, le CRT, les réseaux et le travail sur RSA/ECC.<sup>[[26]](#references)</sup>
- Z3 pour les challenges fondés sur des contraintes (lorsque la crypto se réduit à des contraintes).<sup>[[27]](#references)</sup>

Packages Python suggérés :
```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```
## References

- [1] [CrackStation](https://crackstation.net/)
- [2] [MD5Decrypt](https://md5decrypt.net/)
- [3] [recherche de hashes.org](https://hashes.org/search.php)
- [4] [OnlineHashCrack](https://www.onlinehashcrack.com/)
- [5] [GPUHash.me](https://gpuhash.me/)
- [6] [Boîte à outils de hash](https://hashtoolkit.com/reverse-hash)
- [7] [GCHQ CyberChef](https://gchq.github.io/CyberChef/)
- [8] [outils dCode](https://www.dcode.fr/tools-list)
- [9] [outils de résolution de codes de Boxentriq](https://www.boxentriq.com/code-breaking)
- [10] [CryptoHack](https://cryptohack.org/)
- [11] [Cryptopals](https://cryptopals.com/)
- [12] [Ciphey](https://github.com/Ciphey/Ciphey)
- [13] [python-codext](https://github.com/dhondta/python-codext)
- [14] [quipqiup](https://quipqiup.com/)
- [15] [Nayuki - Outil automatique de résolution du chiffrement de Caesar](https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript)
- [16] [Rumkin - Chiffrement Atbash](https://rumkin.com/tools/cipher/atbash/)
- [17] [Solveur Vigenère de Guballa](https://www.guballa.de/vigenere-solver)
- [18] [Asecuritysite - Décodeur Fernet](https://asecuritysite.com/encryption/ferdecode)
- [19] [Reconstructeur de partage de secret de Shamir](https://christian.gen.co/secrets/)
- [20] [bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
- [21] [easy_BFopensslCTF](https://github.com/carlospolop/easy_BFopensslCTF)
- [22] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [23] [featherduster](https://github.com/nccgroup/featherduster)
- [24] [cryptovenom](https://github.com/lockedbyte/cryptovenom)
- [25] [Documentation de PyCryptodome](https://pycryptodome.readthedocs.io/en/latest/)
- [26] [SageMath](https://www.sagemath.org/)
- [27] [Z3](https://github.com/Z3Prover/z3)
{{#include ../../banners/hacktricks-training.md}}
