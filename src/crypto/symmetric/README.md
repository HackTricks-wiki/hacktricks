# Criptografia Simétrica

{{#include ../../banners/hacktricks-training.md}}

## O que procurar em CTFs

- **Mode misuse**: ECB patterns, CBC malleability, CTR/GCM nonce reuse.
- **Padding oracles**: diferentes erros/tempos para padding inválido.
- **MAC confusion**: usando CBC-MAC com mensagens de comprimento variável, ou erros de MAC-then-encrypt.
- **XOR everywhere**: stream ciphers e construções customizadas frequentemente reduzem-se a XOR com um keystream.

## AES modes and misuse

### ECB: Electronic Codebook

ECB leaks patterns: equal plaintext blocks → equal ciphertext blocks. Isso permite:

- Cut-and-paste / reordenação de blocos
- Deleção de blocos (se o formato permanecer válido)

Se você pode controlar plaintext e observar ciphertext (ou cookies), tente fazer blocos repetidos (por ex., muitos `A`s) e procure por repetições.

### CBC: Cipher Block Chaining

- CBC is **malleable**: flipping bits in `C[i-1]` flips predictable bits in `P[i]`.
- Se o sistema expõe padding válido vs padding inválido, você pode ter um **padding oracle**.

### CTR

CTR transforma AES em um stream cipher: `C = P XOR keystream`.

Se um nonce/IV for reutilizado com a mesma chave:

- `C1 XOR C2 = P1 XOR P2` (reutilização clássica do keystream)
- Com plaintext conhecido, você pode recuperar o keystream e descriptografar outros.

### GCM

GCM também falha gravemente sob nonce reuse. Se a mesma chave+nonce for usada mais de uma vez, normalmente você obtém:

- Reutilização do keystream para criptografia (como CTR), permitindo recuperação de plaintext quando algum plaintext é conhecido.
- Perda das garantias de integridade. Dependendo do que é exposto (múltiplos pares message/tag sob o mesmo nonce), atacantes podem conseguir forjar tags.

Orientações operacionais:

- Considere "nonce reuse" em AEAD como uma vulnerabilidade crítica.
- Se você tiver múltiplos ciphertexts sob o mesmo nonce, comece verificando relações do tipo `C1 XOR C2 = P1 XOR P2`.

### Ferramentas

- CyberChef para experimentos rápidos: https://gchq.github.io/CyberChef/
- Python: `pycryptodome` para scripting

## Padrões de exploração ECB

ECB (Electronic Code Book) encripta cada bloco independentemente:

- equal plaintext blocks → equal ciphertext blocks
- isso vaza estrutura e permite ataques estilo cut-and-paste

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Ideia de detecção: padrão de token/cookie

Se você fizer login várias vezes e **sempre receber o mesmo cookie**, o ciphertext pode ser determinístico (ECB ou IV fixo).

Se você criar dois usuários com layouts de plaintext majoritariamente idênticos (ex.: longos caracteres repetidos) e ver blocos de ciphertext repetidos nos mesmos offsets, ECB é um forte suspeito.

### Padrões de exploração

#### Remover blocos inteiros

Se o formato do token for algo como `<username>|<password>` e a fronteira de blocos alinhar, às vezes você consegue criar um usuário de modo que o bloco `admin` apareça alinhado, então remover os blocos precedentes para obter um token válido para `admin`.

#### Mover blocos

Se o backend tolerar padding/espaços extras (`admin` vs `admin    `), você pode:

- Alinhar um bloco que contenha `admin   `
- Trocar/reutilizar esse bloco de ciphertext em outro token

## Padding Oracle

### O que é

Em CBC mode, se o servidor revela (direta ou indiretamente) se o plaintext decodificado tem **PKCS#7 padding** válido, você frequentemente pode:

- Descriptografar ciphertext sem a chave
- Encriptar plaintext escolhido (forjar ciphertext)

O oracle pode ser:

- Uma mensagem de erro específica
- Um status HTTP / tamanho de resposta diferente
- Uma diferença de timing

### Exploração prática

PadBuster é a ferramenta clássica:

{{#ref}}
https://github.com/AonCyberLabs/PadBuster
{{#endref}}

Exemplo:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 16 \
-encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
Notes:

- Block size is often `16` for AES.
- `-encoding 0` means Base64.
- Use `-error` if the oracle is a specific string.

### Por que funciona

CBC decryption computes `P[i] = D(C[i]) XOR C[i-1]`. Ao modificar bytes em `C[i-1]` e observar se o padding é válido, você pode recuperar `P[i]` byte a byte.

## Bit-flipping in CBC

Mesmo sem um padding oracle, CBC é maleável. Se você pode modificar blocos de ciphertext e a aplicação usa o plaintext decriptado como dados estruturados (e.g., `role=user`), você pode inverter bits específicos para alterar bytes selecionados do plaintext em uma posição escolhida no próximo bloco.

Typical CTF pattern:

- Token = `IV || C1 || C2 || ...`
- You control bytes in `C[i]`
- You target plaintext bytes in `P[i+1]` because `P[i+1] = D(C[i+1]) XOR C[i]`

This is not a break of confidentiality by itself, but it is a common privilege-escalation primitive when integrity is missing.

## CBC-MAC

CBC-MAC is secure only under specific conditions (notably **fixed-length messages** and correct domain separation).

### Classic variable-length forgery pattern

CBC-MAC is usually computed as:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

If you can obtain tags for chosen messages, you can often craft a tag for a concatenation (or related construction) without knowing the key, by exploiting how CBC chains blocks.

This frequently appears in CTF cookies/tokens that MAC username or role with CBC-MAC.

### Safer alternatives

- Use HMAC (SHA-256/512)
- Use CMAC (AES-CMAC) correctly
- Include message length / domain separation

## Stream ciphers: XOR and RC4

### O modelo mental

Most stream cipher situations reduce to:

`ciphertext = plaintext XOR keystream`

So:

- If you know plaintext, you recover keystream.
- If keystream is reused (same key+nonce), `C1 XOR C2 = P1 XOR P2`.

### XOR-based encryption

If you know any plaintext segment at position `i`, you can recover keystream bytes and decrypt other ciphertexts at those positions.

Autosolvers:

- https://wiremask.eu/tools/xor-cracker/

### RC4

RC4 is a stream cipher; encrypt/decrypt are the same operation.

If you can get RC4 encryption of known plaintext under the same key, you can recover the keystream and decrypt other messages of the same length/offset.

Reference writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
