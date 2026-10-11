# Hashes, MACs e KDFs

{{#include ../../banners/hacktricks-training.md}}

## Padrões comuns em CTF

- "Assinatura" que na verdade é `hash(secret || message)` → length extension.
- Hashes de senha sem salt → cracking repetido mais rápido e ataques de busca pré-computada.
- Confundir hash com MAC (hash != autenticação).

## Hash length extension attack

### Técnica

Um length-extension attack pode ser possível quando um servidor calcula uma "assinatura" como:

`sig = HASH(secret || message)`

e usa um hash Merkle-Damgård, como MD5, SHA-1 ou SHA-256.

Se você souber:

- `message`
- `sig`
- a função hash
- (ou puder fazer brute-force de) `len(secret)`

Então você pode calcular uma assinatura válida para:

`message || padding || appended_data`

sem conhecer o segredo.<sup>[[1]](#references)</sup>

### Limitação importante: HMAC não é afetado

Length-extension attacks se aplicam a construções de prefixo vulneráveis, como `HASH(secret || message)`. Eles não expõem a construção HMAC (por exemplo, HMAC-SHA256), que combina uma chave com aplicações separadas de hash interno e externo.<sup>[[1]](#references)[[2]](#references)</sup>

### Ferramentas

- [`hash_extender`](https://github.com/iagox86/hash_extender)<sup>[[3]](#references)</sup>
- [`hashpumpy`](https://pypi.org/project/hashpumpy/), bindings Python para a ferramenta de length extension HashPump<sup>[[7]](#references)</sup>

### Boa explicação

[Tudo o que você precisa saber sobre hash length extension attacks](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)<sup>[[1]](#references)</sup>

## Hashing e cracking de senhas

### Perguntas iniciais<sup>[[4]](#references)</sup>

- Tem **salt**? (procure formatos `salt$hash`)
- É um **hash rápido** (MD5/SHA1/SHA256) ou uma **KDF lenta** (bcrypt/scrypt/argon2/PBKDF2)?
- Você tem uma **dica sobre o formato** (modo do hashcat / formato do John)?

### Fluxo de trabalho prático<sup>[[5]](#references)[[6]](#references)</sup>

1. Identifique o hash:
   - `hashid <hash>`
   - `hashcat --example-hashes | rg -n "<pattern>"`
2. Se não tiver salt e for comum: tente DBs online e ferramentas de identificação da seção de fluxo de trabalho de criptografia.
3. Caso contrário, faça cracking:
   - `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
   - `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### Erros comuns que você pode explorar

- A mesma senha é reutilizada por vários usuários → faça cracking de uma e use-a para pivotar.
- Hashes truncados / transformações personalizadas → normalize e tente novamente.
- Parâmetros fracos de KDF (por exemplo, poucas iterações de PBKDF2) → ainda é possível fazer cracking.

### Oracle bcrypt com entrada escolhida e um segredo anexado

Um helper chamável que retorna `bcrypt(user_input || secret)` pode revelar informações sobre um segredo anexado se a implementação de bcrypt truncar silenciosamente a entrada após 72 **bytes**. Um limite na quantidade de caracteres antes da codificação UTF-8 não impõe esse limite de bytes: caracteres multibyte podem preencher a entrada do bcrypt e deixar espaço apenas para um pequeno prefixo do segredo. As entradas escolhidas e os hashes retornados podem então permitir verificações offline de bytes candidatos para o sufixo. Isso requer controle sobre a entrada do helper, conhecimento da transformação e codificação exatas e uma implementação que realmente trunque; um helper chamável ou um hash bcrypt, por si só, não comprova essa cadeia. A [documentação do pyca/bcrypt](https://github.com/pyca/bcrypt#maximum-password-length) informa que o `hashpw` atual gera um erro para entradas com mais de 72 bytes, enquanto o comportamento anterior as truncava silenciosamente. Outros wrappers podem fazer prehash ou rejeitar entradas longas, portanto verifique a implementação instalada em vez de presumir que há truncamento.

Usar um segredo recuperado contra outra conta também exige evidências de que o hash exposto dessa conta foi gerado com o **mesmo** segredo e transformação, além de uma credencial ou caminho de login separado. Um helper de hashing executado como root deve ser analisado como um oracle somente se o usuário com menos privilégios puder invocá-lo segundo a política efetiva; a enumeração passiva do host não precisa chamá-lo nem enviar senhas escolhidas.

## References

- [1] [SkullSecurity - Tudo o que você precisa saber sobre hash length-extension attacks](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
- [2] [NIST FIPS 198-1 - Código de autenticação de mensagem com hash e chave](https://csrc.nist.gov/pubs/fips/198-1/final)
- [3] [hash_extender](https://github.com/iagox86/hash_extender)
- [4] [OWASP - Guia de armazenamento de senhas](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [5] [Hashes de exemplo do Hashcat](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [6] [Opções de linha de comando do John the Ripper](https://www.openwall.com/john/doc/OPTIONS.shtml)
- [7] [PyPI: bindings Python de `hashpumpy` para HashPump](https://pypi.org/project/hashpumpy/)
{{#include ../../banners/hacktricks-training.md}}
