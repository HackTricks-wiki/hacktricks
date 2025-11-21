# Algorithmes cryptographiques / de compression

{{#include ../../banners/hacktricks-training.md}}

## Identification des algorithmes

Si vous tombez sur un code **utilisant des décalages à droite et à gauche, des xors et plusieurs opérations arithmétiques** il est très probable qu'il s'agisse de l'implémentation d'un **algorithme cryptographique**. Ici seront montrées quelques méthodes pour **identifier l'algorithme utilisé sans avoir besoin de réverser chaque étape**.

### Fonctions API

**CryptDeriveKey**

Si cette fonction est utilisée, vous pouvez trouver quel **algorithme est utilisé** en vérifiant la valeur du second paramètre :

![](<../../images/image (156).png>)

Consultez ici la table des algorithmes possibles et leurs valeurs assignées : [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

**RtlCompressBuffer/RtlDecompressBuffer**

Compresse et décompresse un buffer de données donné.

**CryptAcquireContext**

D'après [la doc](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta) : la fonction **CryptAcquireContext** est utilisée pour obtenir un handle vers un conteneur de clés particulier au sein d'un fournisseur de services cryptographiques (CSP) particulier. **Ce handle retourné est utilisé dans les appels aux fonctions CryptoAPI** qui utilisent le CSP sélectionné.

**CryptCreateHash**

Initie le hachage d'un flux de données. Si cette fonction est utilisée, vous pouvez trouver quel **algorithme est utilisé** en vérifiant la valeur du second paramètre :

![](<../../images/image (549).png>)

\
Consultez ici la table des algorithmes possibles et leurs valeurs assignées : [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

### Constantes dans le code

Parfois il est vraiment facile d'identifier un algorithme grâce au fait qu'il utilise une valeur spéciale et unique.

![](<../../images/image (833).png>)

Si vous recherchez la première constante sur Google, voici ce que vous obtenez :

![](<../../images/image (529).png>)

Par conséquent, vous pouvez supposer que la fonction décompilée est un **calculateur sha256.**\
Vous pouvez rechercher n'importe laquelle des autres constantes et vous obtiendrez (probablement) le même résultat.

### info sur les données

Si le code n'a pas de constante significative, il peut **charger des informations depuis la section .data**.\
Vous pouvez accéder à ces données, **regrouper le premier dword** et le rechercher sur Google comme nous l'avons fait dans la section précédente :

![](<../../images/image (531).png>)

Dans ce cas, si vous cherchez **0xA56363C6** vous pouvez trouver que c'est lié aux **tables de l'algorithme AES**.

## RC4 (Symmetric Crypt)

### Caractéristiques

Il est composé de 3 parties principales :

- **Étape d'initialisation/** : Crée une **table de valeurs de 0x00 à 0xFF** (256 octets au total, 0x100). Cette table est communément appelée **Substitution Box** (ou SBox).
- **Étape de mélange** : Parcourt la **table créée précédemment** (boucle de 0x100 itérations, encore une fois) en modifiant chaque valeur avec des octets **semi-aléatoires**. Pour créer ces octets semi-aléatoires, la **clé RC4 est utilisée**. Les **clés RC4** peuvent avoir une **longueur entre 1 et 256 octets**, cependant il est généralement recommandé qu'elles fassent plus de 5 octets. Couramment, les clés RC4 ont une longueur de 16 octets.
- **Étape XOR** : Enfin, le texte en clair ou le cyphertext est **XORé avec les valeurs créées précédemment**. La fonction pour chiffrer et déchiffrer est la même. Pour cela, une **boucle sur les 256 octets créés** sera effectuée autant de fois que nécessaire. Ceci est généralement reconnu dans un code décompilé par un **%256 (mod 256)**.

> [!TIP]
> **Pour identifier un RC4 dans une disassembly/decompiled code, vous pouvez vérifier la présence de 2 boucles de taille 0x100 (utilisant une clé) puis un XOR des données d'entrée avec les 256 valeurs créées auparavant dans les 2 boucles, probablement en utilisant un %256 (mod 256)**

### Étape d'initialisation / Substitution Box : (Remarquez le nombre 256 utilisé comme compteur et comment un 0 est écrit à chaque emplacement des 256 caractères)

![](<../../images/image (584).png>)

### Étape de mélange :

![](<../../images/image (835).png>)

### Étape XOR :

![](<../../images/image (904).png>)

## AES (Symmetric Crypt)

### Caractéristiques

- Utilisation de **boîtes de substitution et de tables de lookup**
- Il est possible de **distinguer AES grâce à l'utilisation de valeurs spécifiques dans des tables de lookup** (constantes). _Notez que la **constante** peut être **stockée** dans le binaire **ou créée**_ _**dynamiquement**._
- La **clé de chiffrement** doit être **divisible** par **16** (généralement 32B) et généralement un **IV** de 16B est utilisé.

### Constantes SBox

![](<../../images/image (208).png>)

## Serpent (Symmetric Crypt)

### Caractéristiques

- Il est rare de trouver du malware l'utilisant mais il existe des exemples (Ursnif)
- Facile à déterminer si un algorithme est Serpent ou non basé sur sa longueur (fonction extrêmement longue)

### Identification

Dans l'image suivante, remarquez comment la constante **0x9E3779B9** est utilisée (notez que cette constante est aussi utilisée par d'autres algos crypto comme **TEA** - Tiny Encryption Algorithm).\
Notez aussi la **taille de la boucle** (**132**) et le **nombre d'opérations XOR** dans les instructions de **désassemblage** et dans l'exemple de **code** :

![](<../../images/image (547).png>)

Comme mentionné précédemment, ce code peut être visualisé dans n'importe quel decompiler comme une **fonction très longue** puisqu'il **n'y a pas de sauts** à l'intérieur. Le code décompilé peut ressembler à ce qui suit :

![](<../../images/image (513).png>)

Ainsi, il est possible d'identifier cet algorithme en vérifiant le **nombre magique** et les **XOR initiaux**, en voyant une **fonction très longue** et en **comparant** certaines **instructions** de la longue fonction **avec une implémentation** (comme le shift left de 7 et le rotate left de 22).

## RSA (Asymmetric Crypt)

### Caractéristiques

- Plus complexe que les algorithmes symétriques
- Il n'y a pas de constantes ! (les implémentations personnalisées sont difficiles à déterminer)
- KANAL (un analyseur crypto) ne parvient pas à donner des indices sur RSA car il repose sur des constantes.

### Identification par comparaison

![](<../../images/image (1113).png>)

- À la ligne 11 (gauche) il y a `+7) >> 3` ce qui est la même chose qu'à la ligne 35 (droite) : `+7) / 8`
- La ligne 12 (gauche) vérifie si `modulus_len < 0x040` et à la ligne 36 (droite) elle vérifie si `inputLen+11 > modulusLen`

## MD5 & SHA (hash)

### Caractéristiques

- 3 fonctions : Init, Update, Final
- Fonctions d'initialisation similaires

### Identification

**Init**

Vous pouvez identifier les deux en vérifiant les constantes. Notez que sha_init a 1 constante que MD5 n'a pas :

![](<../../images/image (406).png>)

**MD5 Transform**

Notez l'utilisation de davantage de constantes

![](<../../images/image (253) (1) (1).png>)

## CRC (hash)

- Plus petit et plus efficace car sa fonction est de détecter des modifications accidentelles dans les données
- Utilise des tables de lookup (vous pouvez donc identifier des constantes)

### Identification

Vérifiez les **constantes des tables de lookup** :

![](<../../images/image (508).png>)

Un algorithme de hash CRC ressemble à :

![](<../../images/image (391).png>)

## APLib (Compression)

### Caractéristiques

- Pas de constantes reconnaissables
- Vous pouvez essayer d'écrire l'algorithme en python et chercher des choses similaires en ligne

### Identification

Le graphe est assez large :

![](<../../images/image (207) (2) (1).png>)

Vérifiez **3 comparaisons pour le reconnaître** :

![](<../../images/image (430).png>)

## Bugs d'implémentation des signatures sur courbes elliptiques

### Enforcing de la plage scalaire EdDSA (malleability HashEdDSA)

- FIPS 186-5 §7.8.2 exige que les vérificateurs HashEdDSA scindent une signature `sig = R || s` et rejettent tout scalaire avec `s \geq n`, où `n` est l'ordre du groupe. La librairie JS `elliptic` a sauté cette vérification de borne, donc tout attaquant connaissant une paire valide `(msg, R || s)` peut forger des signatures alternatives `s' = s + k·n` et continuer à ré-encoder `sig' = R || s'`.
- Les routines de vérification ne consomment que `s mod n`, donc tous les `s'` congruents à `s` sont acceptés même s'ils sont des chaînes d'octets différentes. Les systèmes traitant les signatures comme des tokens canoniques (consensus blockchain, caches de replay, clés BD, etc.) peuvent être désynchronisés parce que des implémentations strictes rejetteront `s'`.
- Lors de l'audit d'autres codes HashEdDSA, assurez-vous que le parser valide à la fois le point `R` et la longueur du scalaire ; essayez d'ajouter des multiples de `n` à un `s` valide connu pour confirmer que le vérificateur échoue correctement.

### Tronquature ECDSA vs. hachages avec zéros en tête

- Les vérificateurs ECDSA doivent n'utiliser que les `log2(n)` bits les plus à gauche du hachage du message `H`. Dans `elliptic`, l'aide à la tronquature calculait `delta = (BN(msg).byteLength()*8) - bitlen(n)` ; le constructeur `BN` supprime les octets zéro en tête, donc tout hachage commençant par ≥4 octets zéro sur des courbes comme secp192r1 (ordre 192 bits) semblait n'avoir que 224 bits au lieu de 256.
- Le vérificateur a décalé à droite de 32 bits au lieu de 64, produisant un `E` qui ne correspond pas à la valeur utilisée par le signataire. Des signatures valides sur ces hachages échouent donc avec une probabilité ≈ `2^-32` pour des entrées SHA-256.
- Fournissez à une implémentation cible à la fois le vecteur « tout bon » et des variantes avec zéros en tête (par exemple, Wycheproof `ecdsa_secp192r1_sha256_test.json` cas `tc296`) ; si le vérificateur est en désaccord avec le signataire, vous avez trouvé un bug de tronquature exploitable.

### Exercer les vecteurs Wycheproof contre des librairies
- Wycheproof fournit des jeux de tests JSON qui encodent des points malformés, des scalaires malléables, des hachages inhabituels et d'autres cas limites. Construire un harness autour de `elliptic` (ou de toute librairie crypto) est simple : chargez le JSON, désérialisez chaque cas de test, et affirmez que l'implémentation correspond au drapeau `result` attendu.
```javascript
for (const tc of ecdsaVectors.testGroups) {
const curve = new EC(tc.curve);
const pub = curve.keyFromPublic(tc.key, 'hex');
const ok = curve.verify(tc.msg, tc.sig, pub, 'hex', tc.msgSize);
assert.strictEqual(ok, tc.result === 'valid');
}
```
- Les échecs doivent être triés pour distinguer les violations de spécification des faux positifs. Pour les deux bugs ci-dessus, les cas Wycheproof en échec ont immédiatement pointé les vérifications de plage des scalars manquantes (EdDSA) et une troncature incorrecte du hash (ECDSA).
- Intégrez le harness dans CI afin que les regressions dans scalar parsing, hash handling ou coordinate validity déclenchent des tests dès qu'elles sont introduites. Ceci est particulièrement utile pour les langages de haut niveau (JS, Python, Go) où des conversions bignum subtiles sont faciles à mal gérer.

## Références

- [Trail of Bits - We found cryptography bugs in the elliptic library using Wycheproof](https://blog.trailofbits.com/2025/11/18/we-found-cryptography-bugs-in-the-elliptic-library-using-wycheproof/)
- [Wycheproof Test Suite](https://github.com/C2SP/wycheproof)

{{#include ../../banners/hacktricks-training.md}}
