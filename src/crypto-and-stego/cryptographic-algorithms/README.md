# Algorithmes Cryptographiques/Compression

{{#include ../../banners/hacktricks-training.md}}

## Identification des Algorithmes

Si vous terminez par un code **utilisant des décalages à droite et à gauche, des xors et plusieurs opérations arithmétiques**, il est très probable qu'il s'agisse de l'implémentation d'un **algorithme cryptographique**. Voici quelques façons de **identifier l'algorithme utilisé sans avoir besoin de renverser chaque étape**.

### Fonctions API

**CryptDeriveKey**

Si cette fonction est utilisée, vous pouvez trouver quel **algorithme est utilisé** en vérifiant la valeur du deuxième paramètre :

![](<../../images/image (156).png>)

Consultez ici le tableau des algorithmes possibles et de leurs valeurs assignées : [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

**RtlCompressBuffer/RtlDecompressBuffer**

Compresse et décompresse un tampon de données donné.

**CryptAcquireContext**

D'après [la documentation](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta) : La fonction **CryptAcquireContext** est utilisée pour acquérir un handle à un conteneur de clés particulier au sein d'un fournisseur de services cryptographiques (CSP) particulier. **Ce handle retourné est utilisé dans les appels aux fonctions CryptoAPI** qui utilisent le CSP sélectionné.

**CryptCreateHash**

Initie le hachage d'un flux de données. Si cette fonction est utilisée, vous pouvez trouver quel **algorithme est utilisé** en vérifiant la valeur du deuxième paramètre :

![](<../../images/image (549).png>)

\
Consultez ici le tableau des algorithmes possibles et de leurs valeurs assignées : [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

### Constantes de code

Parfois, il est très facile d'identifier un algorithme grâce au fait qu'il doit utiliser une valeur spéciale et unique.

![](<../../images/image (833).png>)

Si vous recherchez la première constante sur Google, voici ce que vous obtenez :

![](<../../images/image (529).png>)

Par conséquent, vous pouvez supposer que la fonction décompilée est un **calculateur sha256.**\
Vous pouvez rechercher n'importe laquelle des autres constantes et vous obtiendrez (probablement) le même résultat.

### Informations sur les données

Si le code n'a pas de constante significative, il peut être **en train de charger des informations à partir de la section .data**.\
Vous pouvez accéder à ces données, **grouper le premier dword** et les rechercher sur Google comme nous l'avons fait dans la section précédente :

![](<../../images/image (531).png>)

Dans ce cas, si vous recherchez **0xA56363C6**, vous pouvez trouver qu'il est lié aux **tables de l'algorithme AES**.

## RC4 **(Cryptographie Symétrique)**

### Caractéristiques

Il est composé de 3 parties principales :

- **Étape d'initialisation/** : Crée une **table de valeurs de 0x00 à 0xFF** (256 octets au total, 0x100). Cette table est communément appelée **Boîte de Substitution** (ou SBox).
- **Étape de brouillage** : Va **parcourir la table** créée précédemment (boucle de 0x100 itérations, encore une fois) en modifiant chaque valeur avec des octets **semi-aléatoires**. Pour créer ces octets semi-aléatoires, la **clé RC4 est utilisée**. Les **clés RC4** peuvent avoir une **longueur comprise entre 1 et 256 octets**, cependant, il est généralement recommandé qu'elle soit supérieure à 5 octets. En général, les clés RC4 font 16 octets de long.
- **Étape XOR** : Enfin, le texte en clair ou le texte chiffré est **XORé avec les valeurs créées précédemment**. La fonction pour chiffrer et déchiffrer est la même. Pour cela, une **boucle à travers les 256 octets créés** sera effectuée autant de fois que nécessaire. Cela est généralement reconnu dans un code décompilé avec un **%256 (mod 256)**.

> [!TIP]
> **Pour identifier un RC4 dans un code désassemblé/décompilé, vous pouvez vérifier 2 boucles de taille 0x100 (avec l'utilisation d'une clé) et ensuite un XOR des données d'entrée avec les 256 valeurs créées précédemment dans les 2 boucles probablement en utilisant un %256 (mod 256)**

### **Étape d'initialisation/Boîte de Substitution :** (Notez le nombre 256 utilisé comme compteur et comment un 0 est écrit à chaque place des 256 caractères)

![](<../../images/image (584).png>)

### **Étape de Brouillage :**

![](<../../images/image (835).png>)

### **Étape XOR :**

![](<../../images/image (904).png>)

## **AES (Cryptographie Symétrique)**

### **Caractéristiques**

- Utilisation de **boîtes de substitution et de tables de recherche**
- Il est possible de **distinguer AES grâce à l'utilisation de valeurs de tables de recherche spécifiques** (constantes). _Notez que la **constante** peut être **stockée** dans le binaire **ou créée** _ _**dynamiquement**._
- La **clé de chiffrement** doit être **divisible** par **16** (généralement 32B) et un **IV** de 16B est généralement utilisé.

### Constantes SBox

![](<../../images/image (208).png>)

## Serpent **(Cryptographie Symétrique)**

### Caractéristiques

- Il est rare de trouver des malwares l'utilisant, mais il existe des exemples (Ursnif)
- Simple à déterminer si un algorithme est Serpent ou non en fonction de sa longueur (fonction extrêmement longue)

### Identification

Dans l'image suivante, remarquez comment la constante **0x9E3779B9** est utilisée (notez que cette constante est également utilisée par d'autres algorithmes cryptographiques comme **TEA** -Tiny Encryption Algorithm).\
Notez également la **taille de la boucle** (**132**) et le **nombre d'opérations XOR** dans les instructions de **désassemblage** et dans l'exemple de **code** :

![](<../../images/image (547).png>)

Comme mentionné précédemment, ce code peut être visualisé dans n'importe quel décompilateur comme une **très longue fonction** car il **n'y a pas de sauts** à l'intérieur. Le code décompilé peut ressembler à ce qui suit :

![](<../../images/image (513).png>)

Par conséquent, il est possible d'identifier cet algorithme en vérifiant le **nombre magique** et les **XOR initiaux**, en voyant une **très longue fonction** et en **comparant** certaines **instructions** de la longue fonction **avec une implémentation** (comme le décalage à gauche de 7 et la rotation à gauche de 22).

## RSA **(Cryptographie Asymétrique)**

### Caractéristiques

- Plus complexe que les algorithmes symétriques
- Il n'y a pas de constantes ! (les implémentations personnalisées sont difficiles à déterminer)
- KANAL (un analyseur crypto) ne parvient pas à montrer des indices sur RSA car il repose sur des constantes.

### Identification par comparaisons

![](<../../images/image (1113).png>)

- À la ligne 11 (gauche), il y a un `+7) >> 3` qui est le même qu'à la ligne 35 (droite) : `+7) / 8`
- La ligne 12 (gauche) vérifie si `modulus_len < 0x040` et à la ligne 36 (droite), elle vérifie si `inputLen+11 > modulusLen`

## MD5 & SHA (hachage)

### Caractéristiques

- 3 fonctions : Init, Update, Final
- Fonctions d'initialisation similaires

### Identifier

**Init**

Vous pouvez identifier les deux en vérifiant les constantes. Notez que le sha_init a 1 constante que MD5 n'a pas :

![](<../../images/image (406).png>)

**Transformation MD5**

Notez l'utilisation de plus de constantes

![](<../../images/image (253) (1) (1).png>)

## CRC (hachage)

- Plus petit et plus efficace car sa fonction est de trouver des changements accidentels dans les données
- Utilise des tables de recherche (vous pouvez donc identifier des constantes)

### Identifier

Vérifiez les **constantes de la table de recherche** :

![](<../../images/image (508).png>)

Un algorithme de hachage CRC ressemble à :

![](<../../images/image (391).png>)

## APLib (Compression)

### Caractéristiques

- Pas de constantes reconnaissables
- Vous pouvez essayer d'écrire l'algorithme en python et rechercher des choses similaires en ligne

### Identifier

Le graphique est assez grand :

![](<../../images/image (207) (2) (1).png>)

Vérifiez **3 comparaisons pour le reconnaître** :

![](<../../images/image (430).png>)

{{#include ../../banners/hacktricks-training.md}}
