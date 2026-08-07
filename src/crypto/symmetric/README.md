# Crypto symétrique

{{#include ../../banners/hacktricks-training.md}}

## Ce qu'il faut rechercher dans les CTFs

- **Mauvaise utilisation des modes** : motifs ECB, malléabilité de CBC, réutilisation du nonce en CTR/GCM.
- **Padding oracles** : erreurs/temps de réponse différents pour un padding incorrect.
- **Confusion au niveau du MAC** : utilisation de CBC-MAC avec des messages de longueur variable, ou erreurs de type MAC-then-encrypt.
- **XOR partout** : les stream ciphers et constructions personnalisées se réduisent souvent à un XOR avec un keystream.

## Modes AES et mauvaise utilisation

### ECB: Electronic Codebook

ECB leak les motifs : des blocs de plaintext identiques donnent des blocs de ciphertext identiques. Cela permet :

- Cut-and-paste / réorganisation de blocs
- Suppression de blocs (si le format reste valide)

Si vous pouvez contrôler le plaintext et observer le ciphertext (ou des cookies), essayez de créer des blocs répétés (par exemple, beaucoup de `A`) et recherchez les répétitions.

### CBC: Cipher Block Chaining

- CBC est **malléable** : inverser des bits dans `C[i-1]` inverse des bits prévisibles dans `P[i]`.
- Si le système indique si le padding est valide ou non, vous disposez peut-être d'un **padding oracle**.

### CTR

CTR transforme AES en stream cipher : `C = P XOR keystream`.

Si un nonce/IV est réutilisé avec la même clé :

- `C1 XOR C2 = P1 XOR P2` (réutilisation classique du keystream)
- Avec un plaintext connu, vous pouvez retrouver le keystream et déchiffrer les autres.

**Nonce/IV reuse exploitation patterns**

- Retrouver le keystream partout où le plaintext est connu/devinable :

```text
keystream[i..] = ciphertext[i..] XOR known_plaintext[i..]
```

Appliquez les octets de keystream récupérés pour déchiffrer tout autre ciphertext produit avec la même clé+IV aux mêmes offsets.
- Les données très structurées (par exemple, les certificats ASN.1/X.509, les en-têtes de fichiers, JSON/CBOR) fournissent de grandes régions de plaintext connu. Vous pouvez souvent effectuer un XOR entre le ciphertext du certificat et le corps prévisible du certificat pour dériver le keystream, puis déchiffrer d'autres secrets chiffrés avec l'IV réutilisé. Voir également [TLS & Certificates](../tls-and-certificates/README.md) pour des structures de certificats courantes.<sup>[[1]](#references)</sup>
- Lorsque plusieurs secrets du **même format/taille sérialisé** sont chiffrés avec la même clé+IV, l'alignement des champs leak même sans plaintext entièrement connu. Exemple : les clés RSA PKCS#8 de même taille de modulus placent les facteurs premiers aux mêmes offsets (environ 99,6 % d'alignement pour 2048 bits). Effectuer un XOR entre deux ciphertexts utilisant le keystream réutilisé isole `p ⊕ p'` / `q ⊕ q'`, ce qui peut être retrouvé par brute force en quelques secondes.<sup>[[1]](#references)</sup>
- Les IV par défaut des libraries (par exemple, une valeur constante `000...01`) constituent un piège critique : chaque chiffrement répète le même keystream, transformant CTR en one-time pad réutilisé.<sup>[[1]](#references)</sup>

**CTR malleability**

- CTR fournit uniquement la confidentialité : inverser des bits dans le ciphertext inverse de manière déterministe les mêmes bits dans le plaintext. Sans authentication tag, les attackers peuvent modifier les données (par exemple, changer les clés, flags ou messages) sans être détectés.
- Utilisez AEAD (GCM, GCM-SIV, ChaCha20-Poly1305, etc.) et imposez la vérification du tag afin de détecter les bit-flips.

### GCM

GCM échoue également de manière grave en cas de réutilisation du nonce. Si la même clé+nonce est utilisée plusieurs fois, vous obtenez généralement :

- Réutilisation du keystream pour le chiffrement (comme avec CTR), permettant de retrouver le plaintext lorsqu'un plaintext est connu.
- Perte des garanties d'intégrité. Selon ce qui est exposé (plusieurs paires message/tag avec le même nonce), les attackers peuvent être capables de forger des tags.

Conseils opérationnels :

- Considérez la "nonce reuse" dans AEAD comme une vulnérabilité critique.
- Les AEADs résistants aux mauvaises utilisations (par exemple, GCM-SIV) réduisent les conséquences d'une mauvaise utilisation du nonce, mais nécessitent toujours des nonces/IV uniques.
- Si vous avez plusieurs ciphertexts avec le même nonce, commencez par vérifier les relations du type `C1 XOR C2 = P1 XOR P2`.

### Tools

- CyberChef pour des expérimentations rapides : https://gchq.github.io/CyberChef/
- Python : `pycryptodome` pour le scripting

## ECB exploitation patterns

ECB (Electronic Code Book) chiffre chaque bloc indépendamment :

- des blocs de plaintext identiques donnent des blocs de ciphertext identiques
- cela leak la structure et permet des attaques de type cut-and-paste

![Diagramme de déchiffrement par blocs du mode ECB](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Idée de détection : motif de token/cookie

Si vous vous connectez plusieurs fois et obtenez **toujours le même cookie**, le ciphertext peut être déterministe (ECB ou IV fixe).

Si vous créez deux utilisateurs dont les layouts de plaintext sont presque identiques (par exemple, de longues séquences de caractères répétés) et observez des blocs de ciphertext répétés aux mêmes offsets, ECB est le principal suspect.

### Exploitation patterns

#### Suppression de blocs entiers

Si le format du token est quelque chose comme `<username>|<password>` et que la limite de bloc est correctement alignée, vous pouvez parfois créer un utilisateur de sorte que le bloc `admin` soit aligné, puis supprimer les blocs précédents afin d'obtenir un token valide pour `admin`.

#### Déplacement de blocs

Si le backend tolère le padding/des espaces supplémentaires (`admin` vs `admin    `), vous pouvez :

- Aligner un bloc qui contient `admin   `
- Échanger/réutiliser ce bloc de ciphertext dans un autre token

## Padding Oracle

### De quoi s'agit-il ?

En mode CBC, si le serveur révèle (directement ou indirectement) si le plaintext déchiffré possède un **padding PKCS#7 valide**, vous pouvez souvent :

- Déchiffrer le ciphertext sans la clé
- Chiffrer un plaintext choisi (forger un ciphertext)

L'oracle peut être :

- Un message d'erreur spécifique
- Un status HTTP / une taille de réponse différente
- Une différence de timing

### Exploitation pratique

PadBuster est le tool classique :

{{#ref}}
https://github.com/AonCyberLabs/PadBuster
{{#endref}}

Exemple :
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 16 \
-encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
Notes :

- La taille de bloc est souvent `16` pour AES.
- `-encoding 0` signifie Base64.
- Utilisez `-error` si l’oracle renvoie une chaîne spécifique.

### Pourquoi cela fonctionne

Le déchiffrement CBC calcule `P[i] = D(C[i]) XOR C[i-1]`. En modifiant les octets dans `C[i-1]` et en observant si le padding est valide, vous pouvez récupérer `P[i]` octet par octet.

## Bit-flipping in CBC

Même sans padding oracle, CBC est malléable. Si vous pouvez modifier des blocs de ciphertext et que l’application utilise le plaintext déchiffré comme des données structurées (par exemple, `role=user`), vous pouvez inverser des bits spécifiques afin de modifier certains octets du plaintext à une position choisie dans le bloc suivant.

Pattern CTF typique :

- Token = `IV || C1 || C2 || ...`
- Vous contrôlez les octets dans `C[i]`
- Vous ciblez les octets du plaintext dans `P[i+1]` car `P[i+1] = D(C[i+1]) XOR C[i]`

Il ne s’agit pas en soi d’une rupture de la confidentialité, mais c’est une primitive courante d’élévation de privilèges lorsque l’intégrité n’est pas assurée.

## CBC-MAC

CBC-MAC est sécurisé uniquement dans des conditions spécifiques (notamment pour les **messages de longueur fixe** et avec une séparation correcte des domaines).

### Schéma classique de forgery pour les longueurs variables

CBC-MAC est généralement calculé ainsi :

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

Si vous pouvez obtenir les tags de messages choisis, vous pouvez souvent créer un tag pour une concaténation (ou une construction associée) sans connaître la clé, en exploitant la manière dont CBC enchaîne les blocs.

Cela apparaît fréquemment dans les cookies/tokens de CTF qui authentifient le nom d’utilisateur ou le rôle avec CBC-MAC.

### Alternatives plus sûres

- Utiliser HMAC (SHA-256/512)
- Utiliser CMAC (AES-CMAC) correctement
- Inclure la longueur du message / une séparation des domaines

## Stream ciphers: XOR and RC4

### Le modèle mental

La plupart des situations impliquant un stream cipher se réduisent à :

`ciphertext = plaintext XOR keystream`

Donc :

- Si vous connaissez le plaintext, vous récupérez le keystream.
- Si le keystream est réutilisé (même clé+nonce), `C1 XOR C2 = P1 XOR P2`.

### Chiffrement basé sur XOR

Si vous connaissez un segment de plaintext à la position `i`, vous pouvez récupérer les octets du keystream et déchiffrer d’autres ciphertexts à ces positions.

Outils de résolution automatique :

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 est un stream cipher ; le chiffrement et le déchiffrement sont la même opération.

Si vous pouvez obtenir le chiffrement RC4 d’un plaintext connu avec la même clé, vous pouvez récupérer le keystream et déchiffrer d’autres messages de même longueur/offset.

Article de référence (HTB Kryptos) :

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

## Références

- [1] [Trail of Bits – Carelessness versus craftsmanship in cryptography](https://blog.trailofbits.com/2026/02/18/carelessness-versus-craftsmanship-in-cryptography/)

{{#include ../../banners/hacktricks-training.md}}
