# Hashes, MACs & KDFs

{{#include ../../banners/hacktricks-training.md}}

## Padrões comuns de CTF

- "Signature" na verdade é `hash(secret || message)` → length extension.
- Hashes de senha sem salt → cracking repetido mais rápido e ataques de lookup pré-computados.
- Confundir hash com MAC (hash != autenticação).

## Ataque de length extension em hashes

### Técnica

Um ataque de length extension pode ser possível quando um servidor calcula uma "signature" como:

`sig = HASH(secret || message)`

e usa um hash Merkle-Damgård, como MD5, SHA-1 ou SHA-256.

Se você conhece:

- `message`
- `sig`
- função de hash
- (ou consegue fazer brute-force de) `len(secret)`

Então você pode calcular uma signature válida para:

`message || padding || appended_data`

sem conhecer o secret.<sup>[[1]](#references)</sup>

### Limitação importante: HMAC não é afetado

Ataques de length extension se aplicam a construções de prefixo vulneráveis, como `HASH(secret || message)`. Eles não expõem a construção HMAC (por exemplo, HMAC-SHA256), que combina uma key com aplicações separadas de hash interno e externo.<sup>[[1]](#references)[[2]](#references)</sup>

### Ferramentas

- [`hash_extender`](https://github.com/iagox86/hash_extender)<sup>[[3]](#references)</sup>
- [`hashpumpy`](https://pypi.org/project/hashpumpy/), bindings Python para a ferramenta de length extension HashPump<sup>[[7]](#references)</sup>

### Boa explicação

[Tudo o que você precisa saber sobre ataques de length extension em hashes](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)<sup>[[1]](#references)</sup>

## Hashing e cracking de senhas

### Primeiras perguntas<sup>[[4]](#references)</sup>

- Possui **salt**? (procure formatos `salt$hash`)
- É um **hash rápido** (MD5/SHA1/SHA256) ou uma **KDF lenta** (bcrypt/scrypt/argon2/PBKDF2)?
- Você possui uma **dica do formato** (modo do hashcat / formato do John)?

### Workflow prático<sup>[[5]](#references)[[6]](#references)</sup>

1. Identifique o hash:
- `hashid <hash>`
- `hashcat --example-hashes | rg -n "<pattern>"`
2. Se não possuir salt e for comum: tente DBs online e ferramentas de identificação da seção de crypto workflow.
3. Caso contrário, faça cracking:
- `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
- `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### Erros comuns que você pode explorar

- Mesma senha reutilizada entre usuários → faça crack de uma e faça pivot.
- Hashes truncados / transforms customizados → normalize e tente novamente.
- Parâmetros fracos de KDF (por exemplo, poucas iterações de PBKDF2) → ainda podem sofrer cracking.

## References

- [1] [SkullSecurity - Tudo o que você precisa saber sobre ataques de length extension em hashes](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
- [2] [NIST FIPS 198-1 - O Keyed-Hash Message Authentication Code](https://csrc.nist.gov/pubs/fips/198-1/final)
- [3] [hash_extender](https://github.com/iagox86/hash_extender)
- [4] [OWASP - Folha de referência sobre armazenamento de senhas](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [5] [Hashes de exemplo do Hashcat](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [6] [Opções de linha de comando do John the Ripper](https://www.openwall.com/john/doc/OPTIONS.shtml)
- [7] [PyPI: bindings Python de `hashpumpy` para HashPump](https://pypi.org/project/hashpumpy/)
{{#include ../../banners/hacktricks-training.md}}
