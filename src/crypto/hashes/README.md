# Hashes, MACs e KDFs

{{#include ../../banners/hacktricks-training.md}}

## Padrões comuns de CTF

- "Assinatura" é, na verdade, `hash(secret || message)` → length extension.
- Hashes de senha sem salt → cracking repetido mais rápido e ataques de busca pré-computada.
- Confundir hash com MAC (hash != autenticação).

## Buscas de hash MD5 com entrada escolhida

Estes exemplos em Python procuram dois padrões de saída diferentes: um sufixo de MD5 escolhido e um valor MD5 que começa com `0e` seguido apenas por dígitos. O último padrão é relevante quando uma aplicação compara strings numéricas de forma frouxa; consulte o comportamento específico do PHP e as ressalvas relacionadas às versões em [PHP loose comparisons](../../network-services-pentesting/pentesting-web/php-tricks-esp/README.md#loose-comparisons-and-type-juggling).

### Brute force de sufixo de hash MD5

```python
import hashlib

target = '2f2e2e' #/..
candidate = 0
while True:
    plaintext = str(candidate)
    hash = hashlib.md5(plaintext.encode('ascii')).hexdigest()
    if hash[-1*(len(target)):] == target: #End in target
        print('plaintext:"' + plaintext + '", md5:' + hash)
        break
    candidate = candidate + 1
```

### Geração de hash MD5 0e para comparações não estritas

```python
#From isHaacK
import hashlib
from multiprocessing import Process, Queue, cpu_count


def loose_comparison(queue, num):
	target = '0e'
	plaintext = f"a_prefix{str(num)}a_suffix"
	hash = hashlib.md5(plaintext.encode('ascii')).hexdigest()

	if hash[:len(target)] == target and not any(x in "abcdef" for x in hash[2:]):
		print('plaintext: ' + plaintext + ', md5: ' + hash)
		queue.put("done") # triggers program exit

def worker(queue, thread_i, threads):
	for num in range(thread_i, 100**50, threads):
		loose_comparison(queue, num)

def main():
	procs = []
	queue = Queue()
	threads = cpu_count() # 2

	for thread_i in range(threads):
		proc = Process(target=worker, args=(queue, thread_i, threads ))
		proc.daemon = True # kill all subprocess when main process exits.
		procs.append(proc)
		proc.start()

	while queue.empty(): # exits when a subprocess is done
		pass
	return 0

main()
```

## Hash length extension attack

### Técnica

Um length-extension attack pode ser possível quando um servidor calcula uma "assinatura" como:

`sig = HASH(secret || message)`

e usa um hash Merkle-Damgård, como MD5, SHA-1 ou SHA-256.

Se você conhece:

- `message`
- `sig`
- a função de hash
- (ou consegue fazer brute-force de) `len(secret)`

Então você pode calcular uma assinatura válida para:

`message || padding || appended_data`

sem conhecer o secret.<sup>[[1]](#references)</sup>

### Limitação importante: HMAC não é afetado

Length-extension attacks se aplicam a construções vulneráveis com prefixo, como `HASH(secret || message)`. Eles não afetam a construção HMAC (por exemplo, HMAC-SHA256), que combina uma chave com aplicações separadas de hash interno e externo.<sup>[[1]](#references)[[2]](#references)</sup>

Para saber como encontrar e testar essas assinaturas em APIs web, consulte [Request and parameter signatures](../../pentesting-web/web-api-pentesting.md#request-and-parameter-signatures).

### Ferramentas

- [`hash_extender`](https://github.com/iagox86/hash_extender)<sup>[[3]](#references)</sup>
- [`hashpumpy`](https://pypi.org/project/hashpumpy/), bindings de Python para a ferramenta de length-extension HashPump<sup>[[7]](#references)</sup>

### Boa explicação

[Everything you need to know about hash length extension attacks](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)<sup>[[1]](#references)</sup>

## Hashing ambíguo de tuplas e MACs

### Ataque de confusão de limites

APIs de hash incremental não autenticam os limites entre chamadas. `update(A); update(B)` calcula o hash da mesma sequência de bytes que `update(A + B)`. Portanto, calcular o hash ou o MAC da concatenação bruta não autentica uma tupla. Se os campos adjacentes tiverem comprimentos variáveis, um atacante pode redistribuir os bytes em uma tupla diferente sem encontrar uma colisão no hash subjacente:<sup>[[8]](#references)[[9]](#references)</sup>

```python
import hashlib

def raw_hash(parts):
    h = hashlib.sha256()
    for part in parts:
        h.update(part)
    return h.digest()

assert raw_hash([b"alice", b"admin"]) == raw_hash([b"aliceadmin", b""])
```

Isso se torna explorável quando o verificador acredita que o digest vincula os significados dos campos, mas uma entrada controlada pelo atacante pode chegar a outro parser ou etapa do protocolo que atribui limites diferentes. Os compromissos podem passar a ter aberturas alternativas, e os transcripts Fiat-Shamir podem ser interpretados como enunciados diferentes. HMAC impede [hash length extension](#hash-length-extension-attack), mas `HMAC(K, A || B)` ainda tem essa ambiguidade de codificação de tuplas, pois ambas as tuplas produzem os mesmos bytes de mensagem.<sup>[[8]](#references)[[9]](#references)</sup>

Use este fluxo de auditoria para testar se uma codificação ambígua de tuplas atravessa um limite de segurança.<sup>[[8]](#references)[[9]](#references)</sup>

1. Procure `HASH(A || B)`, `HMAC(K, A || B)` e chamadas consecutivas de `update()`/`Write()` sobre dois ou mais campos.
2. Marque todos os campos controlados pelo atacante ou de comprimento variável. Tente mover bytes entre cada limite, mantendo inalterada a concatenação completa. Inclua campos vazios.
3. Verifique se os esquemas de delimitadores permitem que as entradas contenham os bytes delimitadores, se há divergências no escape e se o design codifica o comprimento de apenas alguns campos.
4. Rastreie como cada consumidor analisa os bytes autenticados. Uma alternativa só é relevante se uma partição diferente alterar uma decisão de segurança, um enunciado de prova, um registro, uma transação ou uma abertura de compromisso. Campos de largura fixa ou uma serialização canônica e injetiva impedem esse ataque específico.
5. Verifique se o mesmo digest codificado é aceito em outra versão do protocolo, tipo de mensagem, rodada ou aplicação. Vincule esses contextos explicitamente, em vez de depender dos chamadores para mantê-los separados.

### SequenceHash e SequenceMAC

SequenceHash é uma construção independente do hash usado, destinada a sequências de strings de bytes. Cada operação `add()` é atômica: acrescenta o valor e um sufixo fixo de comprimento de 16 bytes, em little-endian, ao hash interno. Valores vazios continuam sendo objetos distintos. Um hash externo impede a exposição de um estado interno que permite extensão de comprimento, enquanto uma string de personalização opcional fornece separação de domínio. Não substitua `add()` pelas chamadas comuns de escrita da API do hash subjacente.<sup>[[8]](#references)[[9]](#references)</sup>

```python
import sequencehash

h = sequencehash.SequenceHash.new("sha256")
h.add(b"alice")
h.add(b"admin")
digest = h.result_with_customizer(b"example:v1:user-record")
```

Escolha o personalizador como parte da definição do protocolo, incluindo informações suficientes para distinguir a aplicação, a versão do protocolo, o tipo de mensagem e a rodada. SequenceHash ainda exige que todas as partes concordem quanto à ordem dos campos, à codificação de bytes e à serialização canônica, e não pode proteger um campo omitido. As implementações devem ser verificadas com os vetores de teste intermediários e finais do C2SP.<sup>[[8]](#references)[[11]](#references)</sup>

Para autenticação, SequenceMAC oferece a mesma codificação atômica e interface de personalização. Ele exige uma chave de pelo menos 32 bytes. Ao contrário do pré-processamento de chaves do HMAC, seus cabeçalhos vinculam-se ao comprimento exato da chave: uma chave bruta longa não equivale ao seu hash prévio, e acrescentar bytes zero altera a chave. Essa distinção importa quando os componentes aceitam diferentes representações de chave ou metadados de comprimento.<sup>[[8]](#references)[[9]](#references)</sup>

```python
key = b"\x00" * 32
mac = sequencehash.SequenceMAC.new(key, digestmod="sha256")
mac.add(header_bytes)
mac.add(body_bytes)
tag = mac.result_with_customizer(b"example:v1:request-mac")
```

A API Python e as implementações equivalentes em Go e Rust estão disponíveis como referências, mas as implementações do protocolo devem seguir a especificação C2SP vigente, em vez de recriar a codificação com base neste resumo.<sup>[[8]](#references)[[10]](#references)</sup>

## Hashing de senhas e cracking

### Primeiras perguntas<sup>[[4]](#references)</sup>

- Tem **salt**? (procure formatos `salt$hash`)
- É um **hash rápido** (MD5/SHA1/SHA256) ou uma **KDF lenta** (bcrypt/scrypt/argon2/PBKDF2)?
- Você tem uma **dica sobre o formato** (modo do hashcat / formato do John)?

### Fluxo de trabalho prático<sup>[[5]](#references)[[6]](#references)</sup>

1. Identifique o hash:
   - `hashid <hash>`
   - `hashcat --example-hashes | rg -n "<pattern>"`
2. Se não tiver salt e for comum: tente DBs online e ferramentas de identificação da seção sobre fluxo de trabalho de criptografia.
3. Caso contrário, faça cracking:
   - `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
   - `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### Erros comuns que você pode explorar

- A mesma senha é reutilizada por vários usuários → faça cracking de uma e depois pivote.
- Hashes truncados / transformações personalizadas → normalize e tente novamente.
- Parâmetros fracos de KDF (por exemplo, poucas iterações de PBKDF2) → ainda podem ser quebrados.

### Oráculo bcrypt com entrada escolhida e segredo anexado

Um helper invocável que retorna `bcrypt(user_input || secret)` pode expor informações sobre um segredo anexado se a implementação de bcrypt truncar silenciosamente a entrada após 72 **bytes**. Um limite de caracteres aplicado antes da codificação UTF-8 não impõe esse limite em bytes: caracteres multibyte podem preencher a entrada do bcrypt e deixar espaço apenas para um pequeno prefixo do segredo. As entradas escolhidas e os hashes retornados podem então permitir verificações offline de bytes candidatos para o sufixo. Isso exige controle sobre a entrada do helper, conhecimento exato da transformação e da codificação usadas, e uma implementação que realmente trunque; a existência de um helper invocável ou de um hash bcrypt, por si só, não comprova essa cadeia. [A documentação de pyca/bcrypt](https://github.com/pyca/bcrypt#maximum-password-length) informa que a versão atual de `hashpw` gera um erro para entradas com mais de 72 bytes, enquanto versões anteriores as truncavam silenciosamente. Outros wrappers podem aplicar um pré-hash ou rejeitar entradas longas; portanto, verifique a implementação instalada em vez de presumir que há truncamento.

Usar um segredo recuperado contra outra conta também exige evidências de que o hash exposto dessa conta foi gerado com o **mesmo** segredo e transformação, além de uma credencial ou caminho de login independente. Um helper de hashing executado como root só deve ser avaliado como oráculo se o usuário com menos privilégios puder invocá-lo segundo a política efetiva; a enumeração passiva do host não precisa chamá-lo nem enviar senhas escolhidas.

## References

- [1] [SkullSecurity - Tudo o que você precisa saber sobre ataques de extensão de comprimento de hash](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
- [2] [NIST FIPS 198-1 - Código de autenticação de mensagens com hash e chave](https://csrc.nist.gov/pubs/fips/198-1/final)
- [3] [hash_extender](https://github.com/iagox86/hash_extender)
- [4] [OWASP - Guia prático de armazenamento de senhas](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [5] [Hashes de exemplo do Hashcat](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [6] [Opções de linha de comando do John the Ripper](https://www.openwall.com/john/doc/OPTIONS.shtml)
- [7] [PyPI: bindings Python para HashPump](https://pypi.org/project/hashpumpy/)
- [8] [C2SP - Especificação de SequenceHash e SequenceMAC](https://c2sp.org/sequencehash)
- [9] [Trail of Bits - SequenceHash: multihashing para todos](https://blog.trailofbits.com/2026/10/02/sequencehash-multihashing-for-the-rest-of-us/)
- [10] [Trail of Bits - Implementação Python de SequenceHash](https://github.com/trailofbits/sequencehash-py)
- [11] [C2SP CCTV - Vetores de teste de SequenceHash](https://github.com/C2SP/CCTV/tree/main/sequencehash)
