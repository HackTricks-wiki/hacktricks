# Hashes, MACs e KDFs

{{#include ../../banners/hacktricks-training.md}}

## Padrões comuns de CTF

- "Assinatura" na verdade é `hash(secret || message)` → length extension.
- Hashes de senha sem salt → cracking trivial / consulta em bases de dados.
- Confundir hash com MAC (hash != autenticação).

## Ataque de length extension de hash

### Técnica

Você pode frequentemente explorar isso se um servidor calcula uma "assinatura" como:

`sig = HASH(secret || message)`

e usa um hash Merkle–Damgård (exemplos clássicos: MD5, SHA-1, SHA-256).

Se você conhece:

- `message`
- `sig`
- função de hash
- (ou consegue descobrir por brute-force) `len(secret)`

Então você pode calcular uma assinatura válida para:

`message || padding || appended_data`

sem conhecer o secret.<sup>[[1]](#references)</sup>

### Limitação importante: HMAC não é afetado

Ataques de length extension aplicam-se a construções como `HASH(secret || message)` para hashes Merkle–Damgård. Eles não se aplicam a **HMAC** (por exemplo, HMAC-SHA256), que foi especificamente projetado para evitar esse tipo de problema.<sup>[[1]](#references)</sup>

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

## Hashing e cracking de senhas

### Primeiras perguntas

- Possui **salt**? (procure formatos `salt$hash`)
- É um **hash rápido** (MD5/SHA1/SHA256) ou uma **KDF lenta** (bcrypt/scrypt/argon2/PBKDF2)?
- Você tem uma **dica do formato** (modo do hashcat / formato do John)?

### Workflow prático

1. Identifique o hash:
- `hashid <hash>`
- `hashcat --example-hashes | rg -n "<pattern>"`
2. Se não tiver salt e for comum: tente DBs online e ferramentas de identificação da seção de workflow de crypto.
3. Caso contrário, faça cracking:
- `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
- `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### Erros comuns que você pode explorar

- Mesma senha reutilizada entre usuários → faça cracking de uma e faça pivot.
- Hashes truncados / transformações customizadas → normalize e tente novamente.
- Parâmetros fracos de KDF (por exemplo, poucas iterações de PBKDF2) → ainda podem ser quebrados.

## Referências

- [1] [Everything you need to know about hash length extension attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)

{{#include ../../banners/hacktricks-training.md}}
