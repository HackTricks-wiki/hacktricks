# Hashes, MACs et KDFs

{{#include ../../banners/hacktricks-training.md}}

## Schémas CTF courants

- « Signature » correspond en réalité à `hash(secret || message)` → extension de longueur.
- Hashes de mots de passe sans salt → cracking répété plus rapide et attaques par recherche précomputée.
- Confusion entre hash et MAC (hash != authentification).

## Attaque par extension de longueur de hash

### Technique

Une attaque par extension de longueur peut être possible lorsqu'un serveur calcule une « signature » comme :

`sig = HASH(secret || message)`

et utilise un hash Merkle-Damgård tel que MD5, SHA-1 ou SHA-256.

Si vous connaissez :

- `message`
- `sig`
- la fonction de hash
- (ou pouvez brute-force) `len(secret)`

Alors vous pouvez calculer une signature valide pour :

`message || padding || appended_data`

sans connaître le secret.<sup>[[1]](#references)</sup>

### Limitation importante : HMAC n'est pas affecté

Les attaques par extension de longueur s'appliquent aux constructions préfixées vulnérables telles que `HASH(secret || message)`. Elles n'exposent pas la construction HMAC (par exemple, HMAC-SHA256), qui combine une clé avec des applications séparées du hash interne et externe.<sup>[[1]](#references)[[2]](#references)</sup>

### Outils

- [`hash_extender`](https://github.com/iagox86/hash_extender)<sup>[[3]](#references)</sup>
- [`hashpumpy`](https://pypi.org/project/hashpumpy/), bindings Python pour l'outil d'extension de longueur HashPump<sup>[[7]](#references)</sup>

### Bonne explication

[Tout ce que vous devez savoir sur les attaques par extension de longueur de hash](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)<sup>[[1]](#references)</sup>

## Hashing et cracking de mots de passe

### Premières questions<sup>[[4]](#references)</sup>

- Est-il **salé** ? (cherchez les formats `salt$hash`)
- S'agit-il d'un **hash rapide** (MD5/SHA1/SHA256) ou d'un **KDF lent** (bcrypt/scrypt/argon2/PBKDF2) ?
- Disposez-vous d'un **indice sur le format** (mode hashcat / format John) ?

### Workflow pratique<sup>[[5]](#references)[[6]](#references)</sup>

1. Identifiez le hash :
- `hashid <hash>`
- `hashcat --example-hashes | rg -n "<pattern>"`
2. S'il n'est pas salé et qu'il est courant : essayez les DB en ligne et les outils d'identification de la section sur le workflow crypto.
3. Sinon, crackez-le :
- `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
- `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### Erreurs courantes que vous pouvez exploiter

- Même mot de passe réutilisé entre plusieurs utilisateurs → crackez-en un, puis faites un pivot.
- Hashes tronqués / transformations personnalisées → normalisez et réessayez.
- Paramètres de KDF faibles (par exemple, peu d'itérations PBKDF2) → toujours crackables.

## References

- [1] [SkullSecurity - Tout ce que vous devez savoir sur les attaques par extension de longueur de hash](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
- [2] [NIST FIPS 198-1 - Le code d'authentification de message basé sur un hash avec clé](https://csrc.nist.gov/pubs/fips/198-1/final)
- [3] [hash_extender](https://github.com/iagox86/hash_extender)
- [4] [OWASP - Aide-mémoire sur le stockage des mots de passe](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [5] [Hashes d'exemple de Hashcat](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [6] [Options de ligne de commande de John the Ripper](https://www.openwall.com/john/doc/OPTIONS.shtml)
- [7] [PyPI : bindings Python `hashpumpy` pour HashPump](https://pypi.org/project/hashpumpy/)
{{#include ../../banners/hacktricks-training.md}}
