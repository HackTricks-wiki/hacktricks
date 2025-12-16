# Cryptographie symétrique

{{#include ../../banners/hacktricks-training.md}}

## Que rechercher dans les CTFs

- **Mauvais usage des modes** : ECB patterns, CBC malleability, CTR/GCM nonce reuse.
- **Padding oracles** : erreurs/timings différents pour un mauvais padding.
- **Confusion de MAC** : utiliser CBC-MAC avec des messages de longueur variable, ou des erreurs MAC-then-encrypt.
- **XOR partout** : les stream ciphers et constructions personnalisées se réduisent souvent à XOR avec un keystream.

## AES modes and misuse

### ECB: Electronic Codebook

ECB leaks patterns: equal plaintext blocks → equal ciphertext blocks. That enables:

- Cut-and-paste / block reordering
- Block deletion (si le format reste valide)

Si vous pouvez contrôler plaintext et observer ciphertext (ou les cookies), essayez de créer des blocs répétés (par ex., many `A`s) et cherchez des répétitions.

### CBC: Cipher Block Chaining

- CBC est **malléable** : flipping bits in `C[i-1]` flips predictable bits in `P[i]`.
- Si le système révèle padding valide vs padding invalide, vous pourriez avoir un **padding oracle**.

### CTR

CTR transforme AES en stream cipher : `C = P XOR keystream`.

Si un nonce/IV est réutilisé avec la même clé :

- `C1 XOR C2 = P1 XOR P2` (réutilisation classique du keystream)
- Avec le plaintext connu, vous pouvez récupérer le keystream et déchiffrer les autres.

### GCM

GCM se casse aussi en cas de réutilisation du nonce. Si la même clé+nonce est utilisée plus d'une fois, on obtient typiquement :

- Réutilisation du keystream pour le chiffrement (comme CTR), permettant la récupération du plaintext lorsqu'au moins un plaintext est connu.
- Perte des garanties d'intégrité. Selon ce qui est exposé (paires message/tag multiples sous le même nonce), un attaquant peut être capable de forger des tags.

Conseils opérationnels :

- Considérez la réutilisation de nonce en AEAD comme une vulnérabilité critique.
- Si vous avez plusieurs ciphertexts sous le même nonce, commencez par vérifier des relations du type `C1 XOR C2 = P1 XOR P2`.

### Tools

- CyberChef pour des expérimentations rapides : https://gchq.github.io/CyberChef/
- Python : `pycryptodome` pour le scripting

## ECB exploitation patterns

ECB (Electronic Code Book) chiffre chaque bloc de façon indépendante :

- equal plaintext blocks → equal ciphertext blocks
- cela leaks la structure et permet des attaques de type cut-and-paste

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Detection idea: token/cookie pattern

Si vous vous connectez plusieurs fois et **recevez toujours le même cookie**, le ciphertext peut être déterministe (ECB ou IV fixe).

Si vous créez deux utilisateurs avec des mises en page plaintext essentiellement identiques (par ex., longues répétitions de caractères) et voyez des blocs ciphertext répétés aux mêmes offsets, ECB est un suspect de premier plan.

### Exploitation patterns

#### Suppression de blocs entiers

Si le format du token est quelque chose comme `<username>|<password>` et que la frontière de bloc s'aligne, vous pouvez parfois créer un utilisateur de sorte que le bloc `admin` apparaisse aligné, puis supprimer les blocs précédents pour obtenir un token valide pour `admin`.

#### Déplacement de blocs

Si le backend tolère le padding/espaces supplémentaires (`admin` vs `admin    `), vous pouvez :

- Aligner un bloc qui contient `admin   `
- Échanger/réutiliser ce bloc ciphertext dans un autre token

## Padding Oracle

### Qu'est-ce que c'est

En mode CBC, si le serveur révèle (directement ou indirectement) si le plaintext déchiffré a un **padding PKCS#7 valide**, vous pouvez souvent :

- Déchiffrer le ciphertext sans la clé
- Chiffrer un plaintext choisi (forger du ciphertext)

L'oracle peut être :

- Un message d'erreur spécifique
- Un status HTTP / une taille de réponse différente
- Une différence de timing

### Exploitation pratique

PadBuster is the classic tool:

{{#ref}}
https://github.com/AonCyberLabs/PadBuster
{{#endref}}

Example:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 16 \
-encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
Remarques :

- La taille de bloc est souvent `16` pour AES.
- `-encoding 0` signifie Base64.
- Utilisez `-error` si l'oracle est une chaîne spécifique.

### Pourquoi ça fonctionne

CBC decryption computes `P[i] = D(C[i]) XOR C[i-1]`. En modifiant des octets dans `C[i-1]` et en observant si le padding est valide, vous pouvez récupérer `P[i]` octet par octet.

## Bit-flipping in CBC

Même sans un padding oracle, CBC est malléable. Si vous pouvez modifier des blocs de ciphertext et que l'application utilise le plaintext déchiffré comme données structurées (par ex., `role=user`), vous pouvez flipper des bits spécifiques pour changer des octets sélectionnés du plaintext à une position choisie dans le bloc suivant.

Schéma CTF typique :

- Token = `IV || C1 || C2 || ...`
- Vous contrôlez les octets dans `C[i]`
- Vous ciblez les octets du plaintext dans `P[i+1]` parce que `P[i+1] = D(C[i+1]) XOR C[i]`

Ce n'est pas une violation de la confidentialité en soi, mais c'est un vecteur d'escalade de privilèges courant lorsque l'intégrité fait défaut.

## CBC-MAC

CBC-MAC n'est sécurisé que sous des conditions spécifiques (notamment **messages de longueur fixe** et séparation correcte des domaines).

### Schéma classique de falsification pour messages de longueur variable

CBC-MAC est généralement calculé comme :

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

Si vous pouvez obtenir des tags pour des messages choisis, vous pouvez souvent fabriquer un tag pour une concaténation (ou construction connexe) sans connaître la clé, en exploitant la manière dont CBC chaîne les blocs.

Cela apparaît fréquemment dans des cookies/tokens CTF qui MAC le username ou le role avec CBC-MAC.

### Alternatives plus sûres

- Utilisez HMAC (SHA-256/512)
- Utilisez CMAC (AES-CMAC) correctement
- Inclure la longueur du message / séparation de domaine

## Stream ciphers: XOR and RC4

### Modèle mental

La plupart des situations de stream cipher se résument à :

`ciphertext = plaintext XOR keystream`

Donc :

- Si vous connaissez le plaintext, vous récupérez le keystream.
- Si le keystream est réutilisé (same key+nonce), `C1 XOR C2 = P1 XOR P2`.

### XOR-based encryption

Si vous connaissez un segment de plaintext à la position `i`, vous pouvez récupérer les octets du keystream et déchiffrer d'autres ciphertexts à ces positions.

Autosolvers:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 est un stream cipher ; encrypt/decrypt sont la même opération.

Si vous pouvez obtenir des encryptions RC4 de plaintext connu sous la même key, vous pouvez récupérer le keystream et déchiffrer d'autres messages de la même longueur/décalage.

Reference writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
