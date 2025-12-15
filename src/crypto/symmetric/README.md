# Cryptographie symétrique

{{#include ../../banners/hacktricks-training.md}}

## Ce qu'il faut rechercher dans les CTFs

- **Mauvaise utilisation des modes** : ECB patterns, CBC malleability, CTR/GCM nonce reuse.
- **Padding oracles** : erreurs/temps de réponse différents pour un padding invalide.
- **MAC confusion** : utiliser CBC-MAC avec des messages de longueur variable, ou erreurs de type MAC-then-encrypt.
- **XOR partout** : les stream ciphers et constructions custom se réduisent souvent à XOR avec un keystream.

## Modes AES et mauvaise utilisation

### ECB: Electronic Codebook

ECB leaks patterns : equal plaintext blocks → equal ciphertext blocks. Cela permet :

- Cut-and-paste / block reordering
- Block deletion (si le format reste valide)

Si vous pouvez contrôler le plaintext et observer le ciphertext (ou les cookies), essayez de produire des blocs répétés (par ex. beaucoup de `A`) et recherchez des répétitions.

### CBC: Cipher Block Chaining

- CBC est **malleable** : basculer des bits dans `C[i-1]` bascule des bits prédictibles dans `P[i]`.
- Si le système révèle padding valide vs padding invalide, vous pouvez avoir un **padding oracle**.

### CTR

CTR transforme AES en un stream cipher : `C = P XOR keystream`.

Si un nonce/IV est réutilisé avec la même clé :

- `C1 XOR C2 = P1 XOR P2` (réutilisation classique du keystream)
- Avec du plaintext connu, vous pouvez récupérer le keystream et décrypter d'autres messages.

### GCM

GCM casse aussi sévèrement en cas de réutilisation du nonce. Si la même key+nonce est utilisée plusieurs fois, vous obtenez généralement :

- Réutilisation du keystream pour le chiffrement (comme CTR), permettant la récupération de plaintext lorsque n'importe quel plaintext est connu.
- Perte des garanties d'intégrité. Selon ce qui est exposé (plusieurs paires message/tag sous le même nonce), un attaquant peut être capable de forger des tags.

Conseils opérationnels :

- Considérez la "nonce reuse" en AEAD comme une vulnérabilité critique.
- Si vous avez plusieurs ciphertexts sous le même nonce, commencez par vérifier des relations du type `C1 XOR C2 = P1 XOR P2`.

### Outils

- CyberChef pour des expériences rapides : https://gchq.github.io/CyberChef/
- Python : `pycryptodome` pour du scripting

## ECB exploitation patterns

ECB (Electronic Code Book) chiffre chaque bloc indépendamment :

- equal plaintext blocks → equal ciphertext blocks
- this leaks structure and enables cut-and-paste style attacks

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Idée de détection : pattern token/cookie

Si vous vous connectez plusieurs fois et que vous **recevez toujours le même cookie**, le ciphertext peut être déterministe (ECB ou IV fixe).

Si vous créez deux utilisateurs avec des mises en page de plaintext majoritairement identiques (par ex. longues séquences répétées) et voyez des blocs de ciphertext répétés aux mêmes offsets, ECB est un suspect majeur.

### Schémas d'exploitation

#### Suppression de blocs entiers

Si le format du token ressemble à `<username>|<password>` et que la frontière des blocs s'aligne, vous pouvez parfois façonner un utilisateur de sorte que le bloc `admin` apparaisse aligné, puis supprimer les blocs précédents pour obtenir un token valide pour `admin`.

#### Déplacement de blocs

Si le backend tolère le padding/espaces supplémentaires (`admin` vs `admin    `), vous pouvez :

- Aligner un bloc contenant `admin   `
- Échanger/réutiliser ce bloc de ciphertext dans un autre token

## Padding Oracle

### What it is

En mode CBC, si le serveur révèle (directement ou indirectement) si le plaintext déchiffré a un **valid PKCS#7 padding**, vous pouvez souvent :

- Décrypter le ciphertext sans la clé
- Chiffrer un plaintext choisi (forger le ciphertext)

L'oracle peut être :

- Un message d'erreur spécifique
- Un statut HTTP différent / taille de réponse différente
- Une différence de timing

### Exploitation pratique

PadBuster est l'outil classique :

{{#ref}}
https://github.com/AonCyberLabs/PadBuster
{{#endref}}

Example:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 16 \
-encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
Remarques :

- Block size is often `16` for AES.
- `-encoding 0` means Base64.
- Use `-error` if the oracle is a specific string.

### Pourquoi cela fonctionne

CBC decryption computes `P[i] = D(C[i]) XOR C[i-1]`. En modifiant des octets dans `C[i-1]` et en observant si le padding est valide, vous pouvez récupérer `P[i]` octet par octet.

## Bit-flipping in CBC

Even without a padding oracle, CBC is malleable. Si vous pouvez modifier des blocs de ciphertext et que l'application utilise le plaintext déchiffré comme données structurées (par ex., `role=user`), vous pouvez inverser des bits spécifiques pour changer des octets choisis du plaintext à une position donnée dans le bloc suivant.

Typical CTF pattern:

- Token = `IV || C1 || C2 || ...`
- You control bytes in `C[i]`
- You target plaintext bytes in `P[i+1]` because `P[i+1] = D(C[i+1]) XOR C[i]`

This is not a break of confidentiality by itself, but it is a common privilege-escalation primitive when integrity is missing.

## CBC-MAC

CBC-MAC is secure only under specific conditions (notably **fixed-length messages** and correct domain separation).

### Schéma classique de falsification pour messages de longueur variable

CBC-MAC is usually computed as:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

Si vous pouvez obtenir des tags pour des messages choisis, vous pouvez souvent fabriquer un tag pour une concaténation (ou une construction connexe) sans connaître la clé, en exploitant la façon dont CBC enchaîne les blocs.

Cela apparaît fréquemment dans des cookies/tokens CTF qui appliquent un MAC au username ou au role avec CBC-MAC.

### Alternatives plus sûres

- Use HMAC (SHA-256/512)
- Use CMAC (AES-CMAC) correctly
- Inclure la longueur du message / séparation de domaine

## Stream ciphers: XOR and RC4

### Modèle mental

Most stream cipher situations reduce to:

`ciphertext = plaintext XOR keystream`

So:

- If you know plaintext, you recover keystream.
- If keystream is reused (same key+nonce), `C1 XOR C2 = P1 XOR P2`.

### Chiffrement XOR

If you know any plaintext segment at position `i`, you can recover keystream bytes and decrypt other ciphertexts at those positions.

Autosolvers:

- https://wiremask.eu/tools/xor-cracker/

### RC4

RC4 est un stream cipher ; chiffrement et déchiffrement sont la même opération.

Si vous pouvez obtenir des chiffrements RC4 de plaintext connu sous la même clé, vous pouvez récupérer le keystream et déchiffrer d'autres messages de la même longueur/décalage.

Reference writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
