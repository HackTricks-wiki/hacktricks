# Crypto symétrique

{{#include ../../banners/hacktricks-training.md}}

## Que rechercher dans les CTFs

- **Mauvais usage des modes** : ECB patterns, CBC malleability, CTR/GCM nonce reuse.
- **Padding oracles** : erreurs/temporisations différentes pour bad padding.
- **MAC confusion** : utilisation de CBC-MAC avec des messages de longueur variable, ou erreurs de type MAC-then-encrypt.
- **XOR everywhere** : les stream ciphers et constructions custom se réduisent souvent à XOR avec un keystream.

## AES modes and misuse

### ECB: Electronic Codebook

ECB leaks patterns: equal plaintext blocks → equal ciphertext blocks. Cela permet :

- Cut-and-paste / block reordering
- Block deletion (si le format reste valide)

Si vous pouvez contrôler plaintext et observer ciphertext (ou cookies), essayez de créer des blocs répétés (par ex., beaucoup de `A`s) et recherchez des répétitions.

### CBC: Cipher Block Chaining

- CBC is **malleable** : flipping bits in `C[i-1]` flips predictable bits in `P[i]`.
- Si le système révèle valid padding vs invalid padding, vous pouvez avoir un **padding oracle**.

### CTR

CTR turns AES into a stream cipher: `C = P XOR keystream`.

Si un nonce/IV est réutilisé avec la même clé :

- `C1 XOR C2 = P1 XOR P2` (classique keystream reuse)
- Avec du plaintext connu, vous pouvez récupérer le keystream et décrypter les autres.

**Nonce/IV reuse exploitation patterns**

- Recover keystream wherever plaintext is known/guessable:

```text
keystream[i..] = ciphertext[i..] XOR known_plaintext[i..]
```

Appliquez les octets de keystream récupérés pour décrypter n'importe quel autre ciphertext produit avec la même key+IV aux mêmes offsets.
- Des données fortement structurées (par ex. ASN.1/X.509 certificates, file headers, JSON/CBOR) fournissent de larges régions de known-plaintext. Vous pouvez souvent XOR le ciphertext du certificate avec le predictable certificate body pour dériver le keystream, puis décrypter d'autres secrets chiffrés sous le même IV réutilisé. See also [TLS & Certificates](../tls-and-certificates/README.md) pour les layouts typiques de certificates.
- Quand plusieurs secrets du **même format/size sérialisé** sont chiffrés sous la même key+IV, l'alignement des champs leaks même sans full known plaintext. Exemple : les PKCS#8 RSA keys du même modulus size placent les facteurs premiers aux offsets correspondants (~99.6% alignment pour 2048-bit). XORer deux ciphertexts sous le keystream réutilisé isole `p ⊕ p'` / `q ⊕ q'`, qui peut être brute-recovered en quelques secondes.
- Les IVs par défaut dans certaines libraries (par ex., constant `000...01`) sont un piège critique : chaque chiffrement répète le même keystream, transformant CTR en un reused one-time pad.

**CTR malleability**

- CTR provides confidentiality only : flipping bits in ciphertext flips deterministically les mêmes bits dans plaintext. Sans tag d'authentification, un attaquant peut tamper les données (par ex., tweak keys, flags, ou messages) sans être détecté.
- Utilisez AEAD (GCM, GCM-SIV, ChaCha20-Poly1305, etc.) et imposez la vérification du tag pour détecter les bit-flips.

### GCM

GCM also breaks badly under nonce reuse. Si la même key+nonce est utilisée plus d'une fois, on obtient typiquement :

- Keystream reuse pour le chiffrement (comme CTR), permettant la récupération de plaintext quand n'importe quel plaintext est known.
- Perte des garanties d'intégrité. Selon ce qui est exposé (plusieurs message/tag pairs sous le même nonce), des attaquants peuvent être capables de forger des tags.

Guidance opérationnelle :

- Traitez la "nonce reuse" en AEAD comme une vulnérabilité critique.
- Les AEAD misuse-resistant (par ex., GCM-SIV) réduisent l'impact d'un nonce-misuse mais exigent toujours des nonces/IVs uniques.
- Si vous avez plusieurs ciphertexts sous le même nonce, commencez par vérifier des relations de type `C1 XOR C2 = P1 XOR P2`.

### Outils

- CyberChef pour des expérimentations rapides : https://gchq.github.io/CyberChef/
- Python : `pycryptodome` pour du scripting

## ECB exploitation patterns

ECB (Electronic Code Book) chiffre chaque bloc indépendamment :

- equal plaintext blocks → equal ciphertext blocks
- ça fuit la structure et permet des attaques de type cut-and-paste

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Idée de détection : pattern token/cookie

Si vous vous connectez plusieurs fois et **obtenez toujours le même cookie**, le ciphertext peut être déterministe (ECB ou IV fixe).

Si vous créez deux users avec des layouts de plaintext majoritairement identiques (par ex., longues répétitions de caractères) et voyez des blocks de ciphertext répétés aux mêmes offsets, ECB est un suspect majeur.

### Schémas d'exploitation

#### Removing entire blocks

Si le format du token est quelque chose comme `<username>|<password>` et la frontière de bloc est alignée, vous pouvez parfois créer un user de sorte que le bloc `admin` apparaisse aligné, puis supprimer les blocs précédents pour obtenir un token valide pour `admin`.

#### Moving blocks

Si le backend tolère padding/espaces en trop (`admin` vs `admin    `), vous pouvez :

- Aligner un bloc qui contient `admin   `
- Swap/reuse ce bloc de ciphertext dans un autre token

## Padding Oracle

### Qu'est-ce que c'est

En mode CBC, si le serveur révèle (directement ou indirectement) si le plaintext déchiffré a un **valid PKCS#7 padding**, vous pouvez souvent :

- Décrypter un ciphertext sans la clé
- Encrypt chosen plaintext (forger un ciphertext)

L'oracle peut être :

- Un message d'erreur spécifique
- Un HTTP status / taille de réponse différente
- Une différence de timing

### Exploitation pratique

PadBuster est l'outil classique :

{{#ref}}
https://github.com/AonCyberLabs/PadBuster
{{#endref}}

Exemple:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 16 \
-encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
Remarques:

- La taille de bloc est souvent `16` pour AES.
- `-encoding 0` signifie Base64.
- Utilisez `-error` si l'oracle est une chaîne spécifique.

### Pourquoi cela fonctionne

La décryption CBC calcule `P[i] = D(C[i]) XOR C[i-1]`. En modifiant des octets dans `C[i-1]` et en observant si le padding est valide, on peut récupérer `P[i]` octet par octet.

## Bit-flipping in CBC

Même sans padding oracle, CBC est malléable. Si vous pouvez modifier des blocs de ciphertext et que l'application utilise le plaintext déchiffré comme données structurées (p.ex., `role=user`), vous pouvez inverser des bits spécifiques pour modifier des octets choisis du plaintext à une position ciblée dans le bloc suivant.

Typical CTF pattern:

- Token = `IV || C1 || C2 || ...`
- Vous contrôlez des octets dans `C[i]`
- Vous ciblez des octets de plaintext dans `P[i+1]` car `P[i+1] = D(C[i+1]) XOR C[i]`

Ce n'est pas une violation de confidentialité en soi, mais c'est un primitive d'escalade de privilèges courant lorsque l'intégrité fait défaut.

## CBC-MAC

CBC-MAC n'est sécurisé que sous conditions spécifiques (notamment **messages de longueur fixe** et séparation correcte des domaines).

### Classic variable-length forgery pattern

CBC-MAC est généralement calculé comme :

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

Si vous pouvez obtenir des tags pour des messages choisis, vous pouvez souvent fabriquer un tag pour une concaténation (ou construction liée) sans connaître la clé, en exploitant la façon dont CBC enchaîne les blocs.

Cela apparaît fréquemment dans des cookies/tokens de CTF qui calculent un MAC du username ou du role avec CBC-MAC.

### Alternatives plus sûres

- Use HMAC (SHA-256/512)
- Use CMAC (AES-CMAC) correctly
- Include message length / domain separation

## Stream ciphers: XOR and RC4

### Le modèle mental

La plupart des situations de stream cipher se réduisent à :

`ciphertext = plaintext XOR keystream`

Donc :

- Si vous connaissez le plaintext, vous récupérez le keystream.
- If keystream is reused (same key+nonce), `C1 XOR C2 = P1 XOR P2`.

### XOR-based encryption

Si vous connaissez un segment de plaintext à la position `i`, vous pouvez récupérer les octets du keystream et déchiffrer d'autres ciphertexts à ces positions.

Solveurs automatiques:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 est un stream cipher ; chiffrer/déchiffrer sont la même opération.

Si vous pouvez obtenir un chiffrement RC4 d'un plaintext connu sous la même clé, vous pouvez récupérer le keystream et déchiffrer d'autres messages de la même longueur/décalage.

Reference writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

## References

- [Trail of Bits – Carelessness versus craftsmanship in cryptography](https://blog.trailofbits.com/2026/02/18/carelessness-versus-craftsmanship-in-cryptography/)

{{#include ../../banners/hacktricks-training.md}}
