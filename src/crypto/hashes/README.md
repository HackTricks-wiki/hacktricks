# Hashes, MACs et KDFs

{{#include ../../banners/hacktricks-training.md}}

## Motifs courants en CTF

- Une « signature » correspond en réalité à `hash(secret || message)` → length extension.
- Des hashes de mots de passe sans salt → cracking répété plus rapide et attaques par recherche précomputée.
- Confusion entre hash et MAC (hash != authentification).

## Attaque par length extension de hash

### Technique

Une attaque par length extension peut être possible lorsqu’un serveur calcule une « signature » comme :

`sig = HASH(secret || message)`

et utilise un hash Merkle-Damgård tel que MD5, SHA-1 ou SHA-256.

Si vous connaissez :

- `message`
- `sig`
- la fonction de hash
- (ou pouvez brute-forcer) `len(secret)`

Alors vous pouvez calculer une signature valide pour :

`message || padding || appended_data`

sans connaître le secret.<sup>[[1]](#references)</sup>

### Limitation importante : HMAC n’est pas affecté

Les attaques par length extension s’appliquent aux constructions préfixées vulnérables telles que `HASH(secret || message)`. Elles ne permettent pas de compromettre la construction HMAC (par exemple, HMAC-SHA256), qui combine une clé avec des applications distinctes du hash interne et externe.<sup>[[1]](#references)[[2]](#references)</sup>

### Outils

- [`hash_extender`](https://github.com/iagox86/hash_extender)<sup>[[3]](#references)</sup>
- [`hashpumpy`](https://pypi.org/project/hashpumpy/), bindings Python pour l’outil de length extension HashPump<sup>[[7]](#references)</sup>

### Bonne explication

[Tout ce qu’il faut savoir sur les attaques par length extension de hash](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)<sup>[[1]](#references)</sup>

## Hashing et cracking de mots de passe

### Premières questions<sup>[[4]](#references)</sup>

- Y a-t-il un **salt** ? (cherchez des formats `salt$hash`)
- S’agit-il d’un **hash rapide** (MD5/SHA1/SHA256) ou d’un **KDF lent** (bcrypt/scrypt/argon2/PBKDF2) ?
- Avez-vous un **indice sur le format** (mode hashcat / format John) ?

### Workflow pratique<sup>[[5]](#references)[[6]](#references)</sup>

1. Identifiez le hash :
   - `hashid <hash>`
   - `hashcat --example-hashes | rg -n "<pattern>"`
2. S’il n’a pas de salt et est courant : essayez les bases de données en ligne et les outils d’identification de la section sur le workflow crypto.
3. Sinon, lancez le cracking :
   - `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
   - `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### Erreurs courantes dont vous pouvez tirer parti

- Le même mot de passe est réutilisé sur plusieurs comptes → crackez-en un, puis pivotez.
- Hashes tronqués / transformations personnalisées → normalisez et réessayez.
- Paramètres KDF faibles (par ex., peu d’itérations PBKDF2) → le cracking reste possible.

### Oracle bcrypt à entrée choisie avec un secret ajouté

Un helper appelable qui renvoie `bcrypt(user_input || secret)` peut exposer des informations sur un secret ajouté si son implémentation bcrypt tronque silencieusement l’entrée après 72 **octets**. Une limite de caractères appliquée avant l’encodage UTF-8 ne garantit pas cette limite en octets : des caractères multioctets peuvent remplir l’entrée bcrypt tout en ne laissant de la place que pour un petit préfixe du secret. Les entrées choisies et les hashes renvoyés peuvent alors permettre de vérifier hors ligne des octets de suffixe candidats. Cela nécessite de contrôler l’entrée du helper, de connaître exactement sa transformation et son encodage, et d’utiliser une implémentation qui tronque réellement ; la seule présence d’un helper appelable ou d’un hash bcrypt ne suffit pas à établir cette chaîne. [La documentation de pyca/bcrypt](https://github.com/pyca/bcrypt#maximum-password-length) indique que la version actuelle de `hashpw` génère une erreur pour les entrées de plus de 72 octets, alors que les versions antérieures les tronquaient silencieusement. D’autres wrappers peuvent préhasher les entrées ou rejeter les entrées trop longues : vérifiez donc l’implémentation installée au lieu de supposer qu’elle tronque.

Pour utiliser un secret récupéré contre un autre compte, il faut aussi établir que son hash exposé a été généré avec le **même** secret et la même transformation, ainsi que disposer d’un moyen d’authentification distinct. Un helper de hashing exécuté avec les privilèges root ne doit être considéré comme un oracle que si l’utilisateur moins privilégié peut l’appeler selon la politique effective ; l’énumération passive de l’hôte n’implique pas nécessairement de l’appeler ni de lui soumettre des mots de passe choisis.

## References

- [1] [SkullSecurity - Tout ce qu’il faut savoir sur les attaques par length extension de hash](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
- [2] [NIST FIPS 198-1 - Code d’authentification de message par hash à clé](https://csrc.nist.gov/pubs/fips/198-1/final)
- [3] [hash_extender](https://github.com/iagox86/hash_extender)
- [4] [OWASP - Fiche pratique sur le stockage des mots de passe](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [5] [Exemples de hashes de Hashcat](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [6] [Options en ligne de commande de John the Ripper](https://www.openwall.com/john/doc/OPTIONS.shtml)
- [7] [PyPI : bindings Python `hashpumpy` pour HashPump](https://pypi.org/project/hashpumpy/)
{{#include ../../banners/hacktricks-training.md}}
