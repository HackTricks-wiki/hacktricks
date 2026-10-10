# Hashes, MACs et KDFs

{{#include ../../banners/hacktricks-training.md}}

## Patterns courants en CTF

- Une « signature » est en réalité `hash(secret || message)` → length extension.
- Hashes de mots de passe sans salt → cracking répété plus rapide et attaques par recherche pré-calculée.
- Confusion entre hash et MAC (hash != authentification).

## Hash length extension attack

### Technique

Une attaque par length extension peut être possible lorsqu’un serveur calcule une « signature » comme :

`sig = HASH(secret || message)`

et utilise un hash Merkle-Damgård tel que MD5, SHA-1 ou SHA-256.

Si vous connaissez :

- `message`
- `sig`
- la fonction de hash
- (ou pouvez brute-forcer) `len(secret)`

Vous pouvez alors calculer une signature valide pour :

`message || padding || appended_data`

sans connaître le secret.<sup>[[1]](#references)</sup>

### Limitation importante : HMAC n’est pas affecté

Les attaques par length extension s’appliquent aux constructions préfixées vulnérables, telles que `HASH(secret || message)`. Elles ne compromettent pas la construction HMAC (par exemple, HMAC-SHA256), qui combine une clé avec des applications distinctes du hash interne et externe.<sup>[[1]](#references)[[2]](#references)</sup>

### Outils

- [`hash_extender`](https://github.com/iagox86/hash_extender)<sup>[[3]](#references)</sup>
- [`hashpumpy`](https://pypi.org/project/hashpumpy/), bindings Python pour l’outil de length extension HashPump<sup>[[7]](#references)</sup>

### Bonne explication

[Tout ce qu’il faut savoir sur les attaques par hash length extension](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)<sup>[[1]](#references)</sup>

## Hashing et cracking des mots de passe

### Premières questions<sup>[[4]](#references)</sup>

- Le hash est-il **salé** ? (cherchez des formats `salt$hash`)
- S’agit-il d’un **hash rapide** (MD5/SHA1/SHA256) ou d’un **KDF lent** (bcrypt/scrypt/argon2/PBKDF2) ?
- Avez-vous un **indice sur le format** (mode hashcat / format John) ?

### Workflow pratique<sup>[[5]](#references)[[6]](#references)</sup>

1. Identifiez le hash :
   - `hashid <hash>`
   - `hashcat --example-hashes | rg -n "<pattern>"`
2. S’il n’est pas salé et qu’il est courant : essayez les bases de données en ligne et les outils d’identification de la section sur le workflow crypto.
3. Sinon, procédez au cracking :
   - `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
   - `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### Erreurs courantes dont vous pouvez tirer parti

- Le même mot de passe est réutilisé par plusieurs utilisateurs → crackez-en un, puis pivotez.
- Hashes tronqués / transformations personnalisées → normalisez et réessayez.
- Paramètres KDF faibles (par ex., peu d’itérations PBKDF2) → le cracking reste possible.

### Oracle bcrypt à entrée choisie avec un secret ajouté

Un helper appelable qui renvoie `bcrypt(user_input || secret)` peut révéler des informations sur un secret ajouté si son implémentation bcrypt tronque silencieusement l’entrée après 72 **octets**. Une limite sur le nombre de caractères appliquée avant l’encodage UTF-8 ne fait pas respecter cette limite en octets : des caractères multioctets peuvent remplir l’entrée bcrypt tout en ne laissant de place que pour un petit préfixe du secret. Les entrées choisies et les hashes renvoyés peuvent alors permettre de vérifier hors ligne des octets suffixes candidats. Cela nécessite de contrôler l’entrée du helper, de connaître précisément sa transformation et son encodage, et d’utiliser une implémentation qui tronque réellement ; la présence d’un helper appelable ou d’un hash bcrypt ne suffit pas à établir toute la chaîne. [La documentation de pyca/bcrypt](https://github.com/pyca/bcrypt#maximum-password-length) indique que le `hashpw` actuel déclenche une erreur pour les entrées de plus de 72 octets, alors que les versions précédentes les tronquaient silencieusement. D’autres wrappers peuvent pré-hasher ou rejeter les entrées trop longues : vérifiez donc l’implémentation installée au lieu de supposer qu’elle tronque.

Utiliser un secret récupéré sur un autre compte nécessite également de prouver que son hash exposé a été généré avec le **même** secret et la même transformation, ainsi que de disposer d’un autre identifiant ou d’un chemin de connexion distinct. Un helper de hashing exécuté en tant que root ne doit être considéré comme un oracle que si l’utilisateur moins privilégié peut l’invoquer selon la politique effective ; l’énumération passive de l’hôte n’exige pas nécessairement de l’appeler ni de lui soumettre des mots de passe choisis.

## References

- [1] [SkullSecurity - Tout ce qu’il faut savoir sur les attaques par hash length extension](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
- [2] [NIST FIPS 198-1 - Code d’authentification de message par hash avec clé](https://csrc.nist.gov/pubs/fips/198-1/final)
- [3] [hash_extender](https://github.com/iagox86/hash_extender)
- [4] [OWASP - Fiche de bonnes pratiques sur le stockage des mots de passe](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [5] [Exemples de hashes Hashcat](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [6] [Options de ligne de commande de John the Ripper](https://www.openwall.com/john/doc/OPTIONS.shtml)
- [7] [PyPI : bindings Python de `hashpumpy` pour HashPump](https://pypi.org/project/hashpumpy/)
{{#include ../../banners/hacktricks-training.md}}
