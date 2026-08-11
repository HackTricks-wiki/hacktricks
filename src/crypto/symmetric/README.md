# Crypto symétrique

{{#include ../../banners/hacktricks-training.md}}

## Éléments à rechercher dans les CTFs

- **Mauvaise utilisation des modes** : motifs ECB, malléabilité CBC, réutilisation du nonce en CTR/GCM.
- **Padding oracles** : erreurs/délais différents en cas de mauvais padding.
- **Confusion concernant le MAC** : utilisation de CBC-MAC avec des messages de longueur variable, ou erreurs de type MAC-then-encrypt.
- **XOR partout** : les chiffrements par flot et les constructions personnalisées se réduisent souvent à un XOR avec un keystream.

## Modes AES et mauvaise utilisation

NIST spécifie les modes de confidentialité ECB, CBC et CTR dans SP 800-38A, ainsi que le chiffrement authentifié GCM dans SP 800-38D.<sup>[[2]](#references)[[3]](#references)</sup>

### ECB : Electronic Codebook

ECB leak les motifs : des blocs de plaintext identiques produisent des blocs de ciphertext identiques. Cela permet :

- Le cut-and-paste / la réorganisation de blocs
- La suppression de blocs (si le format reste valide)

Si vous pouvez contrôler le plaintext et observer le ciphertext (ou des cookies), essayez de créer des blocs répétés (par exemple, beaucoup de `A`) et recherchez les répétitions.

### CBC : Cipher Block Chaining

- CBC est **malleable** : inverser des bits dans `C[i-1]` inverse des bits prévisibles dans `P[i]`, tout en rendant `P[i-1]` illisible. Modifier l'IV cible le premier bloc de plaintext sans rendre illisible un bloc de plaintext précédent.
- Si le système expose un padding valide par rapport à un padding invalide, vous disposez peut-être d'un **padding oracle**.

### CTR

CTR transforme AES en chiffrement par flot : `C = P XOR keystream`.

Si un nonce/IV est réutilisé avec la même clé :

- `C1 XOR C2 = P1 XOR P2` (réutilisation classique du keystream)
- Avec un plaintext connu, vous pouvez récupérer le keystream et déchiffrer les autres.

**Motifs d'exploitation de la réutilisation du nonce/IV**

- Récupérez le keystream partout où le plaintext est connu ou devinable :

```text
keystream[i..] = ciphertext[i..] XOR known_plaintext[i..]
```

Appliquez les octets de keystream récupérés pour déchiffrer tout autre ciphertext produit avec la même clé+IV aux mêmes offsets.
- Les données très structurées (par exemple, les certificats ASN.1/X.509, les headers de fichiers, JSON/CBOR) fournissent de grandes régions de plaintext connu. Vous pouvez souvent effectuer un XOR entre le ciphertext du certificat et le corps prévisible du certificat afin de dériver le keystream, puis déchiffrer d'autres secrets chiffrés avec l'IV réutilisé. Voir également [TLS & Certificates](../tls-and-certificates/README.md) pour les structures de certificats courantes.<sup>[[1]](#references)</sup>
- Lorsque plusieurs secrets au **format/taille sérialisé identique** sont chiffrés avec la même clé+IV, l'alignement des champs leak même sans plaintext connu complet. Exemple : les clés RSA PKCS#8 de même taille de modulus placent les facteurs premiers aux mêmes offsets (environ 99,6 % d'alignement pour 2048 bits). Effectuer un XOR entre deux ciphertexts utilisant le keystream réutilisé isole `p ⊕ p'` / `q ⊕ q'`, ce qui peut être brute-forcé en quelques secondes.<sup>[[1]](#references)</sup>
- Les IV par défaut des libraries (par exemple, une valeur constante `000...01`) constituent un piège critique : chaque chiffrement répète le même keystream, transformant CTR en one-time pad réutilisé.<sup>[[1]](#references)</sup>

**Malleability de CTR**

- CTR fournit uniquement la confidentialité : inverser des bits dans le ciphertext inverse de manière déterministe les mêmes bits dans le plaintext. Sans authentication tag, les attackers peuvent modifier les données (par exemple, altérer des clés, des flags ou des messages) sans être détectés.
- Utilisez AEAD (GCM, GCM-SIV, ChaCha20-Poly1305, etc.) et imposez la vérification du tag afin de détecter les bit-flips.

### GCM

GCM est également fortement compromis en cas de réutilisation du nonce. Si la même clé+nonce est utilisée plus d'une fois, vous obtenez généralement :

- La réutilisation du keystream pour le chiffrement (comme avec CTR), permettant de récupérer le plaintext lorsqu'un plaintext est connu.
- La perte des garanties d'intégrité. Selon ce qui est exposé (plusieurs paires message/tag utilisant le même nonce), les attackers peuvent être en mesure de forger des tags.

Conseils opérationnels :

- Traitez la « réutilisation du nonce » dans AEAD comme une vulnérabilité critique.
- Les AEAD résistants aux mauvaises utilisations, comme AES-GCM-SIV, réduisent les conséquences de la réutilisation du nonce. Les callers doivent tout de même fournir des nonces uniques comme l'exige l'interface de la construction ; une réutilisation accidentelle a des conséquences limitées par rapport à GCM ordinaire.<sup>[[3]](#references)[[4]](#references)</sup>
- Si vous avez plusieurs ciphertexts utilisant le même nonce, commencez par vérifier les relations de type `C1 XOR C2 = P1 XOR P2`.

### Outils

- [CyberChef](https://gchq.github.io/CyberChef/) pour des expériences rapides.<sup>[[8]](#references)</sup>
- Le package Python [PyCryptodome](https://www.pycryptodome.org/) pour le scripting.<sup>[[9]](#references)</sup>

## Motifs d'exploitation d'ECB

ECB (Electronic Code Book) chiffre chaque bloc indépendamment :

- des blocs de plaintext identiques produisent des blocs de ciphertext identiques
- cela leak la structure et permet des attacks de type cut-and-paste

![Diagramme de blocs du déchiffrement en mode ECB](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Idée de détection : motif de token/cookie

Si vous vous connectez plusieurs fois et que vous obtenez **toujours le même cookie**, le ciphertext peut être déterministe (ECB ou IV fixe).

Si vous créez deux users avec des layouts de plaintext presque identiques (par exemple, de longs caractères répétés) et observez des blocs de ciphertext répétés aux mêmes offsets, ECB est un suspect de premier plan.

### Motifs d'exploitation

#### Suppression de blocs entiers

Si le format du token ressemble à `<username>|<password>` et que la limite de bloc est alignée, vous pouvez parfois créer un user de manière à ce que le bloc `admin` soit aligné, puis supprimer les blocs précédents afin d'obtenir un token valide pour `admin`.

#### Déplacement de blocs

Si le backend tolère le padding ou les espaces supplémentaires (`admin` contre `admin    `), vous pouvez :

- Aligner un bloc contenant `admin   `
- Échanger/réutiliser ce bloc de ciphertext dans un autre token

## Padding Oracle

### De quoi s'agit-il ?

En mode CBC, si le serveur révèle (directement ou indirectement) si le plaintext déchiffré possède un **padding PKCS#7 valide**, vous pouvez souvent :<sup>[[7]](#references)</sup>

- Déchiffrer le ciphertext sans la clé
- Construire un ciphertext qui se déchiffre en plaintext choisi lorsque vous pouvez soumettre des blocs précédents ou des IV forgés et que l'application accepte le message résultant avec un padding valide

L'oracle peut être :

- Un message d'erreur spécifique
- Un status HTTP / une taille de réponse différente
- Une différence de timing

### Exploitation pratique

PadBuster est l'outil classique :

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
- Utilisez `-error` si l'oracle est une chaîne spécifique.

### Pourquoi cela fonctionne

Le déchiffrement CBC calcule `P[i] = D(C[i]) XOR C[i-1]`. En modifiant des octets dans `C[i-1]` et en observant si le padding est valide, vous pouvez récupérer `P[i]` octet par octet.

## Bit-flipping dans CBC

Même sans padding oracle, CBC est malléable. Si vous pouvez modifier des blocs de ciphertext et que l'application utilise le plaintext déchiffré comme données structurées (par exemple, `role=user`), vous pouvez inverser des bits spécifiques afin de modifier certains octets du plaintext à une position choisie dans le bloc suivant.

Pattern CTF typique :

- Token = `IV || C1 || C2 || ...`
- Vous contrôlez les octets dans `C[i]`
- Vous ciblez les octets du plaintext dans `P[i+1]` car `P[i+1] = D(C[i+1]) XOR C[i]`

Il ne s'agit pas en soi d'une compromission de la confidentialité, mais c'est une primitive courante d'élévation de privilèges lorsque l'intégrité est absente.

## CBC-MAC

CBC-MAC est sécurisé uniquement dans des conditions spécifiques (notamment les **messages de longueur fixe** et une séparation correcte des domaines). AES-CMAC est une construction standardisée qui gère correctement les entrées de longueur variable.<sup>[[5]](#references)</sup>

### Pattern classique de forgery avec longueur variable

CBC-MAC est généralement calculé ainsi :

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

Si vous pouvez obtenir les tags de messages choisis, vous pouvez souvent créer un tag pour une concaténation (ou une construction associée) sans connaître la clé, en exploitant la manière dont CBC enchaîne les blocs.

Cela apparaît fréquemment dans les cookies/tokens de CTF qui authentifient le username ou le rôle avec CBC-MAC.

### Alternatives plus sûres

- Utiliser HMAC (SHA-256/512)
- Utiliser CMAC (AES-CMAC) correctement
- Inclure la longueur du message / une séparation des domaines

## Stream ciphers : XOR et RC4

### Le modèle mental

La plupart des situations impliquant des stream ciphers se réduisent à :

`ciphertext = plaintext XOR keystream`

Donc :

- Si vous connaissez le plaintext, vous récupérez le keystream.
- Si le keystream est réutilisé (même clé+nonce), `C1 XOR C2 = P1 XOR P2`.

### Chiffrement basé sur XOR

Si vous connaissez un segment de plaintext à la position `i`, vous pouvez récupérer les octets du keystream et déchiffrer d'autres ciphertexts aux mêmes positions.

Autosolvers :

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 est un stream cipher legacy ; le chiffrement et le déchiffrement correspondent à la même opération XOR. Ses biais connus le rendent inadapté aux nouveaux systèmes, et TLS interdit explicitement ses suites de chiffrement.<sup>[[6]](#references)</sup>

Si vous pouvez obtenir le chiffrement RC4 d'un plaintext connu avec la même clé, vous pouvez récupérer le keystream et déchiffrer d'autres messages de même longueur/offset.

Writeup de référence (HTB Kryptos) :

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

## References

- [1] [Trail of Bits – Négligence contre savoir-faire en cryptographie](https://blog.trailofbits.com/2026/02/18/carelessness-versus-craftsmanship-in-cryptography/)
- [2] [NIST SP 800-38A - Recommandation pour les modes opératoires des chiffrements par blocs](https://csrc.nist.gov/pubs/sp/800/38/a/final)
- [3] [NIST SP 800-38D - Recommandation pour Galois/Counter Mode (GCM) et GMAC](https://csrc.nist.gov/pubs/sp/800/38/d/final)
- [4] [RFC 8452 - AES-GCM-SIV : chiffrement authentifié résistant à la réutilisation des nonces](https://www.rfc-editor.org/rfc/rfc8452)
- [5] [RFC 4493 - L'algorithme AES-CMAC](https://www.rfc-editor.org/rfc/rfc4493)
- [6] [RFC 7465 - Interdiction des suites de chiffrement RC4](https://www.rfc-editor.org/rfc/rfc7465)
- [7] [OWASP Web Security Testing Guide - Test du padding oracle](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/02-Testing_for_Padding_Oracle)
- [8] [GCHQ CyberChef](https://gchq.github.io/CyberChef/)
- [9] [Documentation PyCryptodome](https://www.pycryptodome.org/)
{{#include ../../banners/hacktricks-training.md}}
