# Hashes, MACs & KDFs

{{#include ../../banners/hacktricks-training.md}}

## Padrões comuns de CTF

- "Signature" é na verdade `hash(secret || message)` → length extension.
- Unsalted password hashes → trivial cracking / lookup.
- Confundir hash com MAC (hash != autenticação).

## Hash length extension attack

### Técnica

Você pode frequentemente explorar isso se um servidor computar uma "signature" como:

`sig = HASH(secret || message)`

e usar um Merkle–Damgård hash (exemplos clássicos: MD5, SHA-1, SHA-256).

Se você souber:

- `message`
- `sig`
- hash function
- (ou puder brute-force) `len(secret)`

Então você pode computar uma assinatura válida para:

`message || padding || appended_data`

sem conhecer o segredo.

### Limitação importante: HMAC is not affected

Length extension attacks aplicam-se a construções como `HASH(secret || message)` para hashes Merkle–Damgård. Elas não se aplicam a **HMAC** (e.g., HMAC-SHA256), que é especificamente desenhada para evitar essa classe de problema.

### Ferramentas

- hash_extender:
{{#ref}}
https://github.com/iagox86/hash_extender
{{#endref}}
- hashpump:
{{#ref}}
https://github.com/bwall/HashPump
{{#endref}}

### Boa explicação

{{#ref}}
https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks
{{#endref}}

## Password hashing and cracking

### Primeiras perguntas

- Está **salted**? (procure por `salt$hash` formats)
- É um **fast hash** (MD5/SHA1/SHA256) ou um **slow KDF** (bcrypt/scrypt/argon2/PBKDF2)?
- Você tem uma **format hint** (hashcat mode / John format)?

### Fluxo de trabalho prático

1. Identificar o hash:
- `hashid <hash>`
- `hashcat --example-hashes | rg -n "<pattern>"`
2. Se unsalted e comum: tente DBs online e ferramentas de identificação da seção crypto workflow.
3. Caso contrário, crackeie:
- `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
- `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### Erros comuns que você pode explorar

- Mesma senha reutilizada entre usuários → crack one, pivot.
- Hashes truncados / transformações customizadas → normalizar e tentar novamente.
- Parâmetros fracos de KDF (e.g., low PBKDF2 iterations) → still crackable.

{{#include ../../banners/hacktricks-training.md}}
