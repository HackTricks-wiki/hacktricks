# Crypto symétrique

{{#include ../../banners/hacktricks-training.md}}

## Ce qu’il faut rechercher dans les CTFs

- **Mauvaise utilisation des modes** : motifs ECB, malléabilité de CBC, réutilisation de nonce dans CTR/GCM.
- **Padding oracles** : erreurs ou délais différents en cas de padding incorrect.
- **Confusion sur le MAC** : utilisation de CBC-MAC avec des messages de longueur variable, ou erreurs de type MAC-then-encrypt.
- **XOR partout** : les chiffrements par flot et les constructions personnalisées se réduisent souvent à un XOR avec un keystream.

## Modes AES et mauvaise utilisation

NIST spécifie les modes de confidentialité ECB, CBC et CTR dans la norme SP 800-38A, ainsi que le chiffrement authentifié GCM dans la norme SP 800-38D.<sup>[[2]](#references)[[3]](#references)</sup>

### ECB : Electronic Codebook

ECB révèle des motifs : des blocs de texte en clair identiques donnent des blocs chiffrés identiques. Cela permet :

- Le Cut-and-paste / la réorganisation de blocs
- La suppression de blocs (si le format reste valide)

Si vous pouvez contrôler le texte en clair et observer le texte chiffré (ou des cookies), essayez de créer des blocs répétés (par exemple, de nombreux `A`) et recherchez les répétitions.

### CBC : Cipher Block Chaining

- CBC est **malléable** : inverser des bits dans `C[i-1]` inverse des bits prévisibles dans `P[i]`, tout en corrompant également `P[i-1]`. Modifier l’IV cible le premier bloc de texte en clair sans corrompre de bloc précédent.
- Si le système distingue un padding valide d’un padding invalide, vous avez peut-être affaire à un **padding oracle**.

### CTR

CTR transforme AES en chiffrement par flot : `C = P XOR keystream`.

Si un nonce/IV est réutilisé avec la même clé :

- `C1 XOR C2 = P1 XOR P2` (réutilisation classique du keystream)
- Avec du texte en clair connu, vous pouvez retrouver le keystream et déchiffrer d’autres messages.

**Schémas d’exploitation de la réutilisation du nonce/IV**

- Récupérer le keystream partout où le texte en clair est connu ou devinable :

  ```text
  keystream[i..] = ciphertext[i..] XOR known_plaintext[i..]
  ```

  Appliquez les octets de keystream récupérés pour déchiffrer tout autre texte chiffré produit avec la même clé+IV aux mêmes offsets.
- Les données très structurées (p. ex., certificats ASN.1/X.509, en-têtes de fichiers, JSON/CBOR) fournissent de grandes zones de texte en clair connu. Vous pouvez souvent effectuer un XOR entre le texte chiffré du certificat et le corps prévisible du certificat pour dériver le keystream, puis déchiffrer d’autres secrets chiffrés avec le même IV réutilisé. Voir aussi [TLS & Certificates](../tls-and-certificates/README.md) pour les structures habituelles des certificats.<sup>[[1]](#references)</sup>
- Lorsque plusieurs secrets au **même format sérialisé et de même taille** sont chiffrés avec la même clé+IV, l’alignement des champs peut fuiter des informations même sans texte en clair connu complet. Exemple : les clés RSA PKCS#8 de même taille de module placent les facteurs premiers aux mêmes offsets (alignement d’environ 99,6 % pour 2048 bits). Effectuer un XOR entre deux textes chiffrés avec le keystream réutilisé isole `p ⊕ p'` / `q ⊕ q'`, qui peuvent être retrouvés par brute force en quelques secondes.<sup>[[1]](#references)</sup>
- Les IV par défaut des bibliothèques (p. ex., la constante `000...01`) constituent un piège critique : chaque chiffrement répète le même keystream, transformant CTR en masque jetable réutilisé.<sup>[[1]](#references)</sup>

**Malléabilité de CTR**

- CTR ne garantit que la confidentialité : inverser des bits dans le texte chiffré inverse de façon déterministe les mêmes bits dans le texte en clair. Sans tag d’authentification, les attaquants peuvent modifier les données (p. ex., changer des clés, des indicateurs ou des messages) sans être détectés.
- Utilisez AEAD (GCM, GCM-SIV, ChaCha20-Poly1305, etc.) et imposez la vérification du tag pour détecter les inversions de bits.

### GCM

GCM est également gravement vulnérable en cas de réutilisation du nonce. Si la même clé+nonce est utilisée plusieurs fois, vous obtenez généralement :

- La réutilisation du keystream pour le chiffrement (comme avec CTR), permettant de retrouver le texte en clair lorsqu’une partie de celui-ci est connue.
- La perte des garanties d’intégrité. Selon les éléments exposés (plusieurs paires message/tag utilisant le même nonce), les attaquants peuvent être en mesure de forger des tags.

Recommandations opérationnelles :

- Considérez la « réutilisation du nonce » dans AEAD comme une vulnérabilité critique.
- Les AEAD résistants aux erreurs d’utilisation, tels que AES-GCM-SIV, limitent les conséquences de la réutilisation du nonce. Les appelants doivent tout de même fournir des nonces uniques, comme l’exige l’interface de la construction ; une réutilisation accidentelle a des conséquences limitées par rapport à GCM classique.<sup>[[3]](#references)[[4]](#references)</sup>
- Si vous avez plusieurs textes chiffrés avec le même nonce, commencez par vérifier les relations du type `C1 XOR C2 = P1 XOR P2`.

### Outils

- [CyberChef](https://gchq.github.io/CyberChef/) pour des essais rapides.<sup>[[8]](#references)</sup>
- Le package [PyCryptodome](https://www.pycryptodome.org/) de Python pour l’automatisation.<sup>[[9]](#references)</sup>

## Schémas d’exploitation d’ECB

ECB (Electronic Code Book) chiffre chaque bloc indépendamment :

- des blocs de texte en clair identiques → des blocs de texte chiffré identiques
- cela révèle la structure et permet des attaques de type cut-and-paste

![Schéma de déchiffrement du mode ECB](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Idée de détection : motif de token/cookie

Si vous vous connectez plusieurs fois et obtenez **toujours le même cookie**, le texte chiffré peut être déterministe (ECB ou IV fixe).

Si vous créez deux utilisateurs dont les mises en page en texte clair sont presque identiques (p. ex., avec de longues chaînes de caractères répétées) et que vous observez des blocs de texte chiffré répétés aux mêmes offsets, ECB est un suspect de premier ordre.

### Schémas d’exploitation

#### Supprimer des blocs entiers

Si le format du token ressemble à `<username>|<password>` et que la limite des blocs est bien alignée, vous pouvez parfois créer un utilisateur de façon à aligner le bloc `admin`, puis supprimer les blocs précédents pour obtenir un token valide pour `admin`.

#### Déplacer des blocs

Si le backend tolère le padding ou les espaces supplémentaires (`admin` vs `admin    `), vous pouvez :

- Aligner un bloc contenant `admin   `
- Échanger/réutiliser ce bloc de texte chiffré dans un autre token

## Padding Oracle

### De quoi s’agit-il

En mode CBC, si le serveur révèle (directement ou indirectement) si le texte en clair déchiffré a un **padding PKCS#7 valide**, vous pouvez souvent :<sup>[[7]](#references)</sup>

- Déchiffrer le texte chiffré sans la clé
- Construire un texte chiffré qui se déchiffre en texte en clair choisi, lorsque vous pouvez soumettre des blocs précédents ou des IV forgés et que l’application accepte le message résultant avec un padding valide

L’oracle peut être :

- Un message d’erreur spécifique
- Un code d’état HTTP / une taille de réponse différents
- Une différence de timing

### Exploitation pratique

PadBuster est l’outil classique :

{{#ref}}
https://github.com/AonCyberLabs/PadBuster
{{#endref}}

Exemple :

```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 16 \
  -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```

Notes :

- La taille de bloc est souvent de `16` pour AES.
- `-encoding 0` signifie Base64.
- Utilisez `-error` si l’oracle renvoie une chaîne spécifique.

### Pourquoi ça fonctionne

Le déchiffrement CBC calcule `P[i] = D(C[i]) XOR C[i-1]`. En modifiant des octets dans `C[i-1]` et en observant si le padding est valide, vous pouvez récupérer `P[i]` octet par octet.

## Bit-flipping in CBC

Même sans padding oracle, CBC est malléable. Si vous pouvez modifier des blocs de ciphertext et que l’application utilise le plaintext déchiffré comme données structurées (par exemple, `role=user`), vous pouvez inverser certains bits pour modifier des octets précis du plaintext à une position donnée dans le bloc suivant.

Schéma typique en CTF :

- Token = `IV || C1 || C2 || ...`
- Vous contrôlez des octets dans `C[i]`
- Vous ciblez des octets du plaintext dans `P[i+1]`, car `P[i+1] = D(C[i+1]) XOR C[i]`

Cela ne compromet pas à lui seul la confidentialité, mais constitue un primitive courante de privilege-escalation lorsque l’intégrité n’est pas assurée.

## CBC-MAC

CBC-MAC n’est sécurisé que sous certaines conditions (notamment des **messages de longueur fixe** et une séparation de domaine correcte). AES-CMAC est une construction standardisée qui prend en charge les entrées de longueur variable de manière sûre.<sup>[[5]](#references)</sup>

### Schéma classique de forgery avec longueur variable

CBC-MAC est généralement calculé ainsi :

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

Si vous pouvez obtenir les tags de messages choisis, vous pouvez souvent créer un tag pour une concaténation (ou une construction apparentée) sans connaître la clé, en exploitant la façon dont CBC enchaîne les blocs.

Cela apparaît souvent dans les cookies/tokens de CTF qui authentifient le nom d’utilisateur ou le rôle avec CBC-MAC.

### Alternatives plus sûres

- Utilisez HMAC (SHA-256/512)
- Utilisez correctement CMAC (AES-CMAC)
- Incluez la longueur du message / une séparation de domaine

## Chiffrements par flot : XOR et RC4

### Le modèle mental

La plupart des situations impliquant des chiffrements par flot se ramènent à :

`ciphertext = plaintext XOR keystream`

Donc :

- Si vous connaissez le plaintext, vous retrouvez le keystream.
- Si le keystream est réutilisé (même clé+nonce), `C1 XOR C2 = P1 XOR P2`.

### Chiffrement basé sur XOR

Si vous connaissez un segment de plaintext à la position `i`, vous pouvez retrouver les octets du keystream et déchiffrer d’autres ciphertexts à ces positions.

Outils d’automatisation :

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 est un chiffrement par flot obsolète ; le chiffrement et le déchiffrement sont la même opération XOR. Ses biais connus le rendent inadapté aux nouveaux systèmes, et TLS interdit explicitement ses suites de chiffrement.<sup>[[6]](#references)</sup>

Si vous pouvez obtenir le chiffrement RC4 d’un plaintext connu avec la même clé, vous pouvez retrouver le keystream et déchiffrer d’autres messages de même longueur et au même décalage.

Writeup de référence (HTB Kryptos) :

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

## References

- [1] [Trail of Bits – Négligence et savoir-faire en cryptographie](https://blog.trailofbits.com/2026/02/18/carelessness-versus-craftsmanship-in-cryptography/)
- [2] [NIST SP 800-38A - Recommandation sur les modes de fonctionnement des chiffrements par blocs](https://csrc.nist.gov/pubs/sp/800/38/a/final)
- [3] [NIST SP 800-38D - Recommandation sur le mode Galois/Counter (GCM) et GMAC](https://csrc.nist.gov/pubs/sp/800/38/d/final)
- [4] [RFC 8452 - AES-GCM-SIV : chiffrement authentifié résistant à la réutilisation des nonces](https://www.rfc-editor.org/rfc/rfc8452)
- [5] [RFC 4493 - L’algorithme AES-CMAC](https://www.rfc-editor.org/rfc/rfc4493)
- [6] [RFC 7465 - Interdiction des suites de chiffrement RC4](https://www.rfc-editor.org/rfc/rfc7465)
- [7] [OWASP Web Security Testing Guide - Test des attaques par padding oracle](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/02-Testing_for_Padding_Oracle)
- [8] [GCHQ CyberChef](https://gchq.github.io/CyberChef/)
- [9] [Documentation PyCryptodome](https://www.pycryptodome.org/)
{{#include ../../banners/hacktricks-training.md}}
