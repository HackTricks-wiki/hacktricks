# Criptografia Simétrica

{{#include ../../banners/hacktricks-training.md}}

## O que procurar em CTFs

- **Uso indevido de modos**: padrões ECB, maleabilidade CBC, nonce reuse em CTR/GCM.
- **Padding oracles**: erros/tempos diferentes para padding inválido.
- **Confusão de MAC**: usar CBC-MAC com mensagens de comprimento variável, ou erros de MAC-then-encrypt.
- **XOR everywhere**: stream ciphers e construções customizadas frequentemente reduzem-se a XOR com um keystream.

## Modos AES e uso indevido

### ECB: Electronic Codebook

ECB leaks patterns: equal plaintext blocks → equal ciphertext blocks. Isso possibilita:

- Cut-and-paste / reordenação de blocos
- Exclusão de blocos (se o formato permanecer válido)

Se você pode controlar o plaintext e observar o ciphertext (ou cookies), tente criar blocos repetidos (ex.: muitos `A`s) e procure por repetições.

### CBC: Cipher Block Chaining

- CBC é **maleável**: flipar bits em `C[i-1]` flipa bits previsíveis em `P[i]`.
- Se o sistema expõe padding válido vs padding inválido, você pode ter um **padding oracle**.

### CTR

CTR transforma AES em um stream cipher: `C = P XOR keystream`.

Se um nonce/IV for reutilizado com a mesma chave:

- `C1 XOR C2 = P1 XOR P2` (reutilização clássica de keystream)
- Com plaintext conhecido, você pode recuperar o keystream e descriptografar outros.

### GCM

GCM também falha gravemente sob nonce reuse. Se a mesma key+nonce for usada mais de uma vez, normalmente você obtém:

- Reutilização de keystream para encriptação (como CTR), permitindo recuperação de plaintext quando algum plaintext é conhecido.
- Perda das garantias de integridade. Dependendo do que é exposto (múltiplos pares message/tag sob o mesmo nonce), atacantes podem ser capazes de forjar tags.

Orientação operacional:

- Considere "nonce reuse" em AEAD como uma vulnerabilidade crítica.
- Se você tem múltiplos ciphertexts sob o mesmo nonce, comece verificando relações do tipo `C1 XOR C2 = P1 XOR P2`.

### Ferramentas

- CyberChef for quick experiments: https://gchq.github.io/CyberChef/
- Python: `pycryptodome` for scripting

## Padrões de exploração ECB

ECB (Electronic Code Book) encripta cada bloco independentemente:

- equal plaintext blocks → equal ciphertext blocks
- isso leaks structure e possibilita ataques do tipo cut-and-paste

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Ideia de detecção: padrão de token/cookie

Se você faz login várias vezes e **sempre recebe o mesmo cookie**, o ciphertext pode ser determinístico (ECB ou IV fixo).

Se você cria dois usuários com layouts de plaintext majoritariamente idênticos (ex.: muitos caracteres repetidos) e vê blocos de ciphertext repetidos nos mesmos offsets, ECB é um forte suspeito.

### Padrões de exploração

#### Removendo blocos inteiros

Se o formato do token for algo como `<username>|<password>` e a fronteira de bloco alinhar, às vezes você pode criar um usuário de forma que o bloco `admin` apareça alinhado, então remover blocos anteriores para obter um token válido para `admin`.

#### Movendo blocos

Se o backend tolera padding/espaços extras (`admin` vs `admin    `), você pode:

- Alinhar um bloco que contenha `admin   `
- Trocar/reutilizar esse bloco de ciphertext em outro token

## Padding Oracle

### O que é

Em CBC mode, se o servidor revela (direta ou indiretamente) se o plaintext decriptado tem **valid PKCS#7 padding**, você frequentemente pode:

- Descriptografar ciphertext sem a chave
- Encriptar plaintext escolhido (forjar ciphertext)

O oracle pode ser:

- Uma mensagem de erro específica
- Um status HTTP diferente / tamanho de resposta
- Uma diferença de timing

### Exploração prática

PadBuster is the classic tool:

{{#ref}}
https://github.com/AonCyberLabs/PadBuster
{{#endref}}

Exemplo:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 16 \
-encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
Notas:

- O tamanho do bloco costuma ser `16` para AES.
- `-encoding 0` significa Base64.
- Use `-error` se o oracle for uma string específica.

### Por que funciona

A descriptografia CBC calcula `P[i] = D(C[i]) XOR C[i-1]`. Ao modificar bytes em `C[i-1]` e observar se o padding é válido, você pode recuperar `P[i]` byte a byte.

## Bit-flipping em CBC

Mesmo sem um padding oracle, CBC é maleável. Se você pode modificar blocos de ciphertext e a aplicação usa o plaintext descriptografado como dados estruturados (por exemplo, `role=user`), você pode inverter bits específicos para alterar bytes de plaintext selecionados em uma posição escolhida no próximo bloco.

Padrão típico de CTF:

- Token = `IV || C1 || C2 || ...`
- Você controla bytes em `C[i]`
- Você direciona bytes de plaintext em `P[i+1]` porque `P[i+1] = D(C[i+1]) XOR C[i]`

Isso não é uma quebra de confidencialidade por si só, mas é um primitivo comum de escalonamento de privilégios quando a integridade está ausente.

## CBC-MAC

CBC-MAC é seguro apenas sob condições específicas (notadamente **mensagens de comprimento fixo** e separação de domínio correta).

### Padrão clássico de falsificação para mensagens de comprimento variável

CBC-MAC normalmente é computado como:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

Se você pode obter tags para mensagens escolhidas, você frequentemente pode forjar um tag para uma concatenação (ou construção relacionada) sem conhecer a chave, explorando como o CBC encadeia blocos.

Isso aparece frequentemente em cookies/tokens de CTF que aplicam CBC-MAC em username ou role.

### Alternativas mais seguras

- Use HMAC (SHA-256/512)
- Use CMAC (AES-CMAC) corretamente
- Inclua o comprimento da mensagem / separação de domínio

## Cifras de fluxo: XOR and RC4

### Modelo mental

A maioria das situações com cifras de fluxo reduz-se a:

`ciphertext = plaintext XOR keystream`

Então:

- Se você conhece o plaintext, você recupera o keystream.
- Se o keystream for reutilizado (mesma key+nonce), `C1 XOR C2 = P1 XOR P2`.

### XOR-based encryption

Se você conhece qualquer segmento de plaintext na posição `i`, você pode recuperar bytes do keystream e descriptografar outros ciphertexts nessas posições.

Autosolvers:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 é uma cifra de fluxo; criptografar/descriptografar são a mesma operação.

Se você conseguir obter criptografia RC4 de plaintext conhecido com a mesma chave, você pode recuperar o keystream e descriptografar outras mensagens com o mesmo comprimento/deslocamento.

Writeup de referência (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
