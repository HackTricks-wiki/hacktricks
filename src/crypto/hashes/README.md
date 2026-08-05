# Hashes, MACs & KDFs

{{#include ../../banners/hacktricks-training.md}}

## Patterns courants en CTF

- « Signature » signifie en réalité `hash(secret || message)` → length extension.
- Hashes de mots de passe non salés → cracking trivial / recherche dans des bases.
- Confusion entre hash et MAC (hash != authentification).

## Attaque de length extension sur les hashes

### Technique

Vous pouvez souvent exploiter cela si un serveur calcule une « signature » comme ceci :

`sig = HASH(secret || message)`

et utilise un hash Merkle–Damgård (exemples classiques : MD5, SHA-1, SHA-256).

Si vous connaissez :

- `message`
- `sig`
- la fonction de hash
- (ou pouvez brute-force) `len(secret)`

Alors vous pouvez calculer une signature valide pour :

`message || padding || appended_data`

sans connaître le secret.<sup>[[1]](#references)</sup>

### Limitation importante : HMAC n'est pas affecté

Les length extension attacks s'appliquent à des constructions comme `HASH(secret || message)` pour les hashes Merkle–Damgård. Elles ne s'appliquent pas à **HMAC** (par exemple, HMAC-SHA256), qui est spécifiquement conçu pour éviter cette classe de problèmes.<sup>[[1]](#references)</sup>

### Outils

- hash_extender:
{{#ref}}
https://github.com/iagox86/hash_extender
{{#endref}}
- hashpump:
{{#ref}}
https://github.com/bwall/HashPump
{{#endref}}

### Bonne explication

{{#ref}}
https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks
{{#endref}}

## Hashing et cracking de mots de passe

### Premières questions

- Est-il **salé** ? (cherchez des formats `salt$hash`)
- S'agit-il d'un **hash rapide** (MD5/SHA1/SHA256) ou d'un **KDF lent** (bcrypt/scrypt/argon2/PBKDF2) ?
- Disposez-vous d'un **indice sur le format** (mode hashcat / format John) ?

### Workflow pratique

1. Identifiez le hash :
- `hashid <hash>`
- `hashcat --example-hashes | rg -n "<pattern>"`
2. S'il n'est pas salé et qu'il est courant : essayez les DBs en ligne et les outils d'identification de la section crypto workflow.
3. Sinon, effectuez le cracking :
- `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
- `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### Erreurs courantes que vous pouvez exploiter

- Même mot de passe réutilisé par plusieurs utilisateurs → crackez-en un, puis pivotez.
- Hashes tronqués / transformations personnalisées → normalisez et réessayez.
- Paramètres de KDF faibles (par exemple, peu d'itérations PBKDF2) → toujours crackables.

## Références

- [1] [Everything you need to know about hash length extension attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)

{{#include ../../banners/hacktricks-training.md}}
