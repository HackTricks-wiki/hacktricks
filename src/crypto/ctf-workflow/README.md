# Workflow Crypto CTF

{{#include ../../banners/hacktricks-training.md}}

## Liste de vérification de triage

1. Identifiez ce que vous avez : encodage, chiffrement, hash, signature ou MAC.
2. Déterminez ce qui est contrôlé : texte en clair/chiffré, IV/nonce, clé, oracle (padding/erreur/temps), fuite partielle.
3. Classez : symétrique (AES/CTR/GCM), à clé publique (RSA/ECC), hash/MAC (SHA/MD5/HMAC), classique (Vigenère/XOR).
4. Commencez par les vérifications les plus probables : décodage des couches, known-plaintext XOR, réutilisation de nonce, mauvaise utilisation du mode, comportement de l’oracle.
5. Ne passez aux méthodes avancées que si nécessaire : réseaux (LLL/Coppersmith), SMT/Z3, canaux auxiliaires.

## Ressources et utilitaires en ligne

Ces outils sont utiles pour identifier et retirer des couches, ou pour confirmer rapidement une hypothèse.

### Recherche de hash

- Recherchez le hash d’un challenge lorsqu’il est connu pour être synthétique/public.
- CrackStation.<sup>[[1]](#references)</sup>
- MD5Decrypt.<sup>[[2]](#references)</sup>
- Recherche sur hashes.org.<sup>[[3]](#references)</sup>
- OnlineHashCrack.<sup>[[4]](#references)</sup>
- GPUHash.me.<sup>[[5]](#references)</sup>
- Hash Toolkit.<sup>[[6]](#references)</sup>

Ne soumettez pas de vrais hashes de mots de passe ni de données confidentielles de challenge à des services de recherche tiers. Privilégiez une attaque hors ligne par wordlist/règles si la divulgation, les conditions d’utilisation ou le règlement de la compétition posent problème.

### Outils d’identification

- CyberChef (Magic, décodage et conversion).<sup>[[7]](#references)</sup>
- dCode (environnement de test pour chiffrements/encodages).<sup>[[8]](#references)</sup>
- Boxentriq (solveurs de substitution).<sup>[[9]](#references)</sup>

### Plateformes d’entraînement / références

- CryptoHack (challenges pratiques de cryptographie).<sup>[[10]](#references)</sup>
- Cryptopals (pièges classiques de la cryptographie moderne).<sup>[[11]](#references)</sup>

### Décodage automatisé

- Ciphey.<sup>[[12]](#references)</sup>
- python-codext (essaie de nombreuses bases/encodages).<sup>[[13]](#references)</sup>

## Encodages et chiffrements classiques

### Technique

De nombreuses tâches crypto de CTF sont des transformations en couches : encodage base + substitution simple + compression. L’objectif est d’identifier les couches et de les retirer sans risque.

### Encodages : essayez plusieurs bases

Si vous soupçonnez un encodage en couches (base64 → base32 → …), essayez :

- CyberChef « Magic »
- `codext` (python-codext) : `codext <string>`

Indices courants :

- Base64 : `A-Za-z0-9+/=` (le padding `=` est fréquent)
- Base32 : `A-Z2-7=` (souvent beaucoup de padding `=`)
- Ascii85/Base85 : ponctuation dense ; parfois encadré par `<~ ~>`

### Substitution / monoalphabétique

- Solveur de cryptogrammes Boxentriq.<sup>[[9]](#references)</sup>
- quipqiup.<sup>[[14]](#references)</sup>

### César / ROT / Atbash

- Outil automatique de décryptage du chiffre de César de Nayuki.<sup>[[15]](#references)</sup>
- Outil Atbash de Rumkin.<sup>[[16]](#references)</sup>

### Vigenère

- Outil Vigenère de dCode.<sup>[[8]](#references)</sup>
- Solveur Vigenère de Guballa.<sup>[[17]](#references)</sup>

### Chiffre de Bacon

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

Les runes sont souvent des alphabets de substitution ; recherchez « futhark cipher » et essayez des tables de correspondance.

## Compression dans les challenges

### Technique

La compression apparaît constamment comme couche supplémentaire (zlib/deflate/gzip/xz/zstd), parfois imbriquée. Si la sortie semble presque analysable, mais ressemble à du charabia, suspectez une compression.

### Identification rapide

- `file <blob>`
- Repérez les octets magiques :
  - gzip : `1f 8b`
  - zlib : souvent `78 01`, `78 5e`, `78 9c` ou `78 da` (le deuxième octet dépend des indicateurs de compression)
  - zip : `50 4b 03 04`
  - bzip2 : `42 5a 68` (`BZh`)
  - xz : `fd 37 7a 58 5a 00`
  - zstd : `28 b5 2f fd`

### DEFLATE brut

CyberChef propose **Raw Deflate/Raw Inflate**, souvent la méthode la plus rapide lorsque le blob semble compressé, mais que `zlib` échoue.

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

## Constructions cryptographiques courantes en CTF

### Technique

Elles apparaissent fréquemment, car elles résultent d’erreurs réalistes de développeurs ou d’une mauvaise utilisation de bibliothèques courantes. Le but est généralement de les reconnaître et d’appliquer une méthode connue d’extraction ou de reconstruction.

### Fernet

Indice typique : deux chaînes Base64 (token + clé).

- Décodeur/notes : décodeur Fernet d’Asecuritysite.<sup>[[18]](#references)</sup>
- En Python : `from cryptography.fernet import Fernet`

### Partage de secret de Shamir

Si vous voyez plusieurs parts et qu’un seuil `t` est mentionné, il s’agit probablement de Shamir.

- Outil de reconstruction en ligne (uniquement pour des parts de CTF non sensibles).<sup>[[19]](#references)</sup>

### Formats salés d’OpenSSL

Les CTF fournissent parfois des sorties `openssl enc` (l’en-tête commence souvent par `Salted__`).

Outils de bruteforce :

- `bruteforce-salted-openssl`.<sup>[[20]](#references)</sup>
- `easy_BFopensslCTF`.<sup>[[21]](#references)</sup>

### Boîte à outils générale

- RsaCtfTool.<sup>[[22]](#references)</sup>
- featherduster.<sup>[[23]](#references)</sup>
- cryptovenom.<sup>[[24]](#references)</sup>

## Configuration locale recommandée

Stack CTF pratique :

- Python avec `pycryptodome` pour les primitives symétriques et le prototypage rapide.<sup>[[25]](#references)</sup>
- SageMath pour l’arithmétique modulaire, le CRT, les réseaux et les opérations RSA/ECC.<sup>[[26]](#references)</sup>
- Z3 pour les défis fondés sur des contraintes (lorsque le problème cryptographique se réduit à des contraintes).<sup>[[27]](#references)</sup>

Packages Python suggérés :

```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```

## References

- [1] [CrackStation](https://crackstation.net/)
- [2] [MD5Decrypt](https://md5decrypt.net/)
- [3] [recherche hashes.org](https://hashes.org/search.php)
- [4] [OnlineHashCrack](https://www.onlinehashcrack.com/)
- [5] [GPUHash.me](https://gpuhash.me/)
- [6] [Hash Toolkit](https://hashtoolkit.com/reverse-hash)
- [7] [GCHQ CyberChef](https://gchq.github.io/CyberChef/)
- [8] [outils dCode](https://www.dcode.fr/tools-list)
- [9] [outils de décryptage de codes Boxentriq](https://www.boxentriq.com/code-breaking)
- [10] [CryptoHack](https://cryptohack.org/)
- [11] [Cryptopals](https://cryptopals.com/)
- [12] [Ciphey](https://github.com/Ciphey/Ciphey)
- [13] [python-codext](https://github.com/dhondta/python-codext)
- [14] [quipqiup](https://quipqiup.com/)
- [15] [Nayuki - déchiffreur automatique du chiffre de César](https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript)
- [16] [Rumkin - chiffre Atbash](https://rumkin.com/tools/cipher/atbash/)
- [17] [solveur Vigenère de Guballa](https://www.guballa.de/vigenere-solver)
- [18] [Asecuritysite - décodeur Fernet](https://asecuritysite.com/encryption/ferdecode)
- [19] [reconstructeur de partage de secret de Shamir](https://christian.gen.co/secrets/)
- [20] [bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
- [21] [easy_BFopensslCTF](https://github.com/carlospolop/easy_BFopensslCTF)
- [22] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [23] [featherduster](https://github.com/nccgroup/featherduster)
- [24] [cryptovenom](https://github.com/lockedbyte/cryptovenom)
- [25] [documentation PyCryptodome](https://pycryptodome.readthedocs.io/en/latest/)
- [26] [SageMath](https://www.sagemath.org/)
- [27] [Z3](https://github.com/Z3Prover/z3)
{{#include ../../banners/hacktricks-training.md}}
