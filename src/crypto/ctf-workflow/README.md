# Workflow Crypto CTF

{{#include ../../banners/hacktricks-training.md}}

## Liste de vérification du triage

1. Identifiez ce que vous avez : encodage, chiffrement, hash, signature ou MAC.
2. Déterminez les éléments contrôlés : texte en clair/chiffré, IV/nonce, clé, oracle (padding/erreur/temps), fuite partielle.
3. Classez : symétrique (AES/CTR/GCM), clé publique (RSA/ECC), hash/MAC (SHA/MD5/HMAC), classique (Vigenere/XOR).
4. Commencez par les vérifications les plus susceptibles de réussir : décoder les couches, XOR avec texte connu, réutilisation de nonce, mauvaise utilisation du mode, comportement de l’oracle.
5. Passez aux méthodes avancées uniquement si nécessaire : réseaux (LLL/Coppersmith), SMT/Z3, canaux auxiliaires.

## Ressources en ligne et utilitaires

Ces ressources sont utiles pour identifier et retirer les couches, ou pour confirmer rapidement une hypothèse.

### Recherche de hash

- Recherchez un hash de challenge s’il est connu pour être synthétique/public.
- CrackStation.<sup>[[1]](#references)</sup>
- MD5Decrypt.<sup>[[2]](#references)</sup>
- Recherche sur hashes.org.<sup>[[3]](#references)</sup>
- OnlineHashCrack.<sup>[[4]](#references)</sup>
- GPUHash.me.<sup>[[5]](#references)</sup>
- Hash Toolkit.<sup>[[6]](#references)</sup>

Ne soumettez pas de vrais hashes de mots de passe ni de données confidentielles de challenge à des services de recherche tiers. Privilégiez une attaque hors ligne par wordlist/règles en cas de risque lié à la divulgation, aux conditions d’utilisation ou au règlement de la compétition.

### Outils d’identification

- CyberChef (Magic, décodage et conversion).<sup>[[7]](#references)</sup>
- dCode (environnement de test pour chiffrements/encodages).<sup>[[8]](#references)</sup>
- Boxentriq (solveurs de substitution).<sup>[[9]](#references)</sup>

### Plateformes d’entraînement / références

- CryptoHack (challenges de cryptographie pratiques).<sup>[[10]](#references)</sup>
- Cryptopals (pièges classiques de la cryptographie moderne).<sup>[[11]](#references)</sup>

### Décodage automatisé

- Ciphey.<sup>[[12]](#references)</sup>
- python-codext (essaie de nombreuses bases/encodages).<sup>[[13]](#references)</sup>

Pour le code source en langage ésotérique et l’état personnalisé d’un interpréteur, voir [Crypto CTF Misc](../ctf-misc/).

## Encodages et chiffrements classiques

### Technique

De nombreuses tâches de crypto CTF sont des transformations en couches : encodage base + substitution simple + compression. L’objectif est d’identifier les couches et de les retirer sans risque.

### Encodages : essayez plusieurs bases

Si vous soupçonnez un encodage en couches (base64 → base32 → …), essayez :

- CyberChef « Magic »
- `codext` (python-codext) : `codext <string>`

Indices courants :

- Base64 : `A-Za-z0-9+/=` (le padding `=` est courant)
- Base32 : `A-Z2-7=` (souvent beaucoup de padding `=`)
- Ascii85/Base85 : ponctuation dense ; parfois encadré par `<~ ~>`

### Substitution / monoalphabétique

- Solveur de cryptogrammes Boxentriq.<sup>[[9]](#references)</sup>
- quipqiup.<sup>[[14]](#references)</sup>

#### Récupération par texte connu de noms de fichiers Base32 substitués

Lorsqu’un nom de fichier obfusqué n’utilise que `a-z2-7`, contient environ `ceil(8 * byte_length / 5)` caractères après suppression d’un suffixe fixe, et que le même texte clair produit le même résultat pour différents fichiers, testez **Base32 sans padding suivi d’une substitution fixe de symboles**. Ces indices ne constituent pas à eux seuls une preuve. Collectez des noms de fichiers prévisibles et leurs textes chiffrés, conservez la casse, encodez chaque texte clair en Base32 et alignez les symboles position par position. Chaque symbole répété du texte clair doit correspondre au même symbole chiffré, et la correspondance inverse doit également être unique. Dans un cas de ransomware, `ntuser.ini` et `NTUSER.DAT` ont fourni de telles paires ; cela a permis de récupérer les noms de fichiers, **pas le contenu des fichiers ni les clés de chiffrement**.<sup>[[28]](#references)</sup>

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

Si une cible contient des symboles non mappés, obtenez davantage de paires connues ou permutez uniquement les mappings Base32 inutilisés. Rétablissez le padding pour atteindre une longueur de huit caractères, rejetez les chaînes Base32 invalides et les noms décodés non imprimables, puis réencodez les candidats restants et comparez l’intégralité du texte chiffré d’origine. Des blocs de texte chiffré répétés peuvent fournir des hypothèses supplémentaires : dans le cas ci-dessus, `3gpng2wv` correspondait à Base32 `gaydambq`, qui se décode en cinq zéros ASCII. Un candidat imprimable ne constitue pas, à lui seul, une preuve unique.<sup>[[28]](#references)</sup>

### Caesar / ROT / Atbash

- Nayuki automatic Caesar-cipher breaker.<sup>[[15]](#references)</sup>
- Rumkin Atbash tool.<sup>[[16]](#references)</sup>

### Vigenère

- dCode Vigenère tool.<sup>[[8]](#references)</sup>
- Guballa Vigenère solver.<sup>[[17]](#references)</sup>

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

Les runes sont souvent des alphabets de substitution ; recherchez « futhark cipher » et essayez des tables de correspondance.

## Compression dans les challenges

### Technique

La compression apparaît constamment comme une couche supplémentaire (zlib/deflate/gzip/xz/zstd), parfois imbriquée. Si la sortie semble presque analysable, mais ressemble à du charabia, suspectez une compression.

### Identification rapide

- `file <blob>`
- Repérez les octets magiques :
  - gzip : `1f 8b`
  - zlib : généralement `78 01`, `78 5e`, `78 9c` ou `78 da` (le deuxième octet dépend des options de compression)
  - zip : `50 4b 03 04`
  - bzip2 : `42 5a 68` (`BZh`)
  - xz : `fd 37 7a 58 5a 00`
  - zstd : `28 b5 2f fd`

### DEFLATE brut

CyberChef propose **Raw Deflate/Raw Inflate**, souvent la solution la plus rapide lorsque le blob semble compressé, mais que `zlib` échoue.

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

Elles apparaissent fréquemment, car elles sont dues à des erreurs réalistes de développeurs ou à une mauvaise utilisation de bibliothèques courantes. Il s’agit généralement de les reconnaître et d’appliquer un workflow d’extraction ou de reconstruction connu.

### Fernet

Indice typique : deux chaînes Base64 (token + clé).

- Décodeur/notes : décodeur Fernet d’Asecuritysite.<sup>[[18]](#references)</sup>
- En Python : `from cryptography.fernet import Fernet`

### Partage de secret de Shamir

Si vous voyez plusieurs parts et qu’un seuil `t` est mentionné, il s’agit probablement de Shamir.

- Outil de reconstruction en ligne (uniquement pour les parts de CTF non sensibles).<sup>[[19]](#references)</sup>

### Formats OpenSSL avec salt

Les CTF fournissent parfois des sorties de `openssl enc` (l’en-tête commence souvent par `Salted__`).

Outils de brute force :

- `bruteforce-salted-openssl`.<sup>[[20]](#references)</sup>
- `easy_BFopensslCTF`.<sup>[[21]](#references)</sup>

### Ensemble d’outils général

- RsaCtfTool.<sup>[[22]](#references)</sup>
- featherduster.<sup>[[23]](#references)</sup>
- cryptovenom.<sup>[[24]](#references)</sup>

## Configuration locale recommandée

Environnement pratique pour les CTF :

- Python et `pycryptodome` pour les primitives symétriques et le prototypage rapide.<sup>[[25]](#references)</sup>
- SageMath pour l’arithmétique modulaire, le CRT, les réseaux et le travail sur RSA/ECC.<sup>[[26]](#references)</sup>
- Z3 pour les défis fondés sur des contraintes (lorsque le problème cryptographique se ramène à des contraintes).<sup>[[27]](#references)</sup>

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
- [9] [outils de décryptage Boxentriq](https://www.boxentriq.com/code-breaking)
- [10] [CryptoHack](https://cryptohack.org/)
- [11] [Cryptopals](https://cryptopals.com/)
- [12] [Ciphey](https://github.com/Ciphey/Ciphey)
- [13] [python-codext](https://github.com/dhondta/python-codext)
- [14] [quipqiup](https://quipqiup.com/)
- [15] [Nayuki - outil automatique de cassage du chiffre de César](https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript)
- [16] [Rumkin - chiffre Atbash](https://rumkin.com/tools/cipher/atbash/)
- [17] [résolveur Vigenère Guballa](https://www.guballa.de/vigenere-solver)
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
- [28] [Eye Research – Casser des schémas de chiffrement à la manière paresseuse](https://labs.eye.security/breaking-encryption-schemes-the-lazy-way/)
{{#include ../../banners/hacktricks-training.md}}
