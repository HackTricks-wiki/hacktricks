# Criptografia Simétrica

{{#include ../../banners/hacktricks-training.md}}

## O que procurar em CTFs

- **Uso indevido de modos**: padrões ECB, maleabilidade do CBC, reutilização de nonce no CTR/GCM.
- **Padding oracles**: erros/tempos diferentes para padding inválido.
- **Confusão de MAC**: uso de CBC-MAC com mensagens de tamanho variável ou erros de MAC-then-encrypt.
- **XOR em todo lugar**: stream ciphers e construções customizadas geralmente se reduzem a XOR com um keystream.

## Modos do AES e uso indevido

### ECB: Electronic Codebook

ECB causa leak de padrões: blocos de plaintext iguais → blocos de ciphertext iguais. Isso permite:

- Cut-and-paste / reordenação de blocos
- Exclusão de blocos (se o formato continuar válido)

Se você puder controlar o plaintext e observar o ciphertext (ou cookies), tente criar blocos repetidos (por exemplo, muitos `A`s) e procure repetições.

### CBC: Cipher Block Chaining

- CBC é **maleável**: inverter bits em `C[i-1]` inverte bits previsíveis em `P[i]`.
- Se o sistema expõe padding válido versus padding inválido, você pode ter um **padding oracle**.

### CTR

CTR transforma o AES em um stream cipher: `C = P XOR keystream`.

Se um nonce/IV for reutilizado com a mesma chave:

- `C1 XOR C2 = P1 XOR P2` (reutilização clássica de keystream)
- Com plaintext conhecido, você pode recuperar o keystream e descriptografar outros.

**Padrões de exploração de reutilização de nonce/IV**

- Recupere o keystream onde quer que o plaintext seja conhecido/previsível:

```text
keystream[i..] = ciphertext[i..] XOR known_plaintext[i..]
```

Aplique os bytes recuperados do keystream para descriptografar qualquer outro ciphertext produzido com a mesma chave+IV nos mesmos offsets.
- Dados altamente estruturados (por exemplo, certificados ASN.1/X.509, headers de arquivos, JSON/CBOR) fornecem grandes regiões de plaintext conhecido. Geralmente, você pode aplicar XOR ao ciphertext do certificado com o corpo previsível do certificado para derivar o keystream e, então, descriptografar outros segredos criptografados sob o IV reutilizado. Consulte também [TLS & Certificates](../tls-and-certificates/README.md) para layouts típicos de certificados.<sup>[[1]](#references)</sup>
- Quando vários segredos no **mesmo formato/tamanho serializado** são criptografados sob a mesma chave+IV, o alinhamento dos campos causa leak mesmo sem plaintext conhecido completo. Exemplo: chaves RSA PKCS#8 com o mesmo tamanho de modulus colocam os fatores primos nos mesmos offsets (~99,6% de alinhamento para 2048 bits). Aplicar XOR a dois ciphertexts sob o keystream reutilizado isola `p ⊕ p'` / `q ⊕ q'`, o que pode ser recuperado por brute force em segundos.<sup>[[1]](#references)</sup>
- IVs padrão em libraries (por exemplo, a constante `000...01`) são um footgun crítico: cada criptografia repete o mesmo keystream, transformando o CTR em um one-time pad reutilizado.<sup>[[1]](#references)</sup>

**Maleabilidade do CTR**

- O CTR fornece apenas confidencialidade: inverter bits no ciphertext inverte deterministicamente os mesmos bits no plaintext. Sem uma authentication tag, attackers podem adulterar dados (por exemplo, alterar chaves, flags ou mensagens) sem serem detectados.
- Use AEAD (GCM, GCM-SIV, ChaCha20-Poly1305 etc.) e aplique a verificação da tag para detectar bit-flips.

### GCM

O GCM também falha gravemente sob reutilização de nonce. Se a mesma chave+nonce for usada mais de uma vez, normalmente ocorre:

- Reutilização de keystream na criptografia (como no CTR), permitindo a recuperação do plaintext quando algum plaintext é conhecido.
- Perda das garantias de integridade. Dependendo do que é exposto (vários pares de mensagem/tag sob o mesmo nonce), attackers podem conseguir forgear tags.

Orientações operacionais:

- Trate a "reutilização de nonce" em AEAD como uma vulnerabilidade crítica.
- AEADs resistentes a misuse (por exemplo, GCM-SIV) reduzem as consequências do uso indevido de nonce, mas ainda exigem nonces/IVs únicos.
- Se você tiver vários ciphertexts sob o mesmo nonce, comece verificando relações no estilo `C1 XOR C2 = P1 XOR P2`.

### Tools

- CyberChef para experimentos rápidos: https://gchq.github.io/CyberChef/
- Python: `pycryptodome` para scripting

## Padrões de exploração de ECB

ECB (Electronic Code Book) criptografa cada bloco independentemente:

- blocos de plaintext iguais → blocos de ciphertext iguais
- isso causa leak de estrutura e permite ataques no estilo cut-and-paste

![Diagrama de blocos da descriptografia no modo ECB](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Ideia de detecção: padrão de token/cookie

Se você fizer login várias vezes e **sempre receber o mesmo cookie**, o ciphertext pode ser determinístico (ECB ou IV fixo).

Se você criar dois usuários com layouts de plaintext quase idênticos (por exemplo, caracteres repetidos longos) e observar blocos de ciphertext repetidos nos mesmos offsets, ECB é o principal suspeito.

### Padrões de exploração

#### Removendo blocos inteiros

Se o formato do token for algo como `<username>|<password>` e o limite do bloco estiver alinhado, às vezes você pode criar um usuário de modo que o bloco `admin` fique alinhado e, então, remover os blocos anteriores para obter um token válido para `admin`.

#### Movendo blocos

Se o backend tolerar padding/espaços extras (`admin` versus `admin    `), você pode:

- Alinhar um bloco que contenha `admin   `
- Trocar/reutilizar esse bloco de ciphertext em outro token

## Padding Oracle

### O que é

No modo CBC, se o server revelar (direta ou indiretamente) se o plaintext descriptografado possui **padding PKCS#7 válido**, você geralmente pode:

- Descriptografar ciphertext sem a chave
- Criptografar plaintext escolhido (forjar ciphertext)

O oracle pode ser:

- Uma mensagem de erro específica
- Um status HTTP / tamanho da resposta diferente
- Uma diferença de tempo

### Exploração prática

PadBuster é a tool clássica:

{{#ref}}
https://github.com/AonCyberLabs/PadBuster
{{#endref}}

Exemplo:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 16 \
-encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
Notas:

- O tamanho do bloco geralmente é `16` para AES.
- `-encoding 0` significa Base64.
- Use `-error` se o oracle for uma string específica.

### Por que funciona

A descriptografia CBC calcula `P[i] = D(C[i]) XOR C[i-1]`. Ao modificar bytes em `C[i-1]` e observar se o padding é válido, você pode recuperar `P[i]` byte a byte.

## Bit-flipping em CBC

Mesmo sem um padding oracle, CBC é maleável. Se você puder modificar blocos de ciphertext e a aplicação usar o plaintext descriptografado como dados estruturados (por exemplo, `role=user`), poderá inverter bits específicos para alterar bytes selecionados do plaintext em uma posição escolhida no bloco seguinte.

Padrão típico de CTF:

- Token = `IV || C1 || C2 || ...`
- Você controla bytes em `C[i]`
- Você tem como alvo bytes do plaintext em `P[i+1]`, pois `P[i+1] = D(C[i+1]) XOR C[i]`

Isso, por si só, não é uma quebra de confidencialidade, mas é uma primitive comum de privilege escalation quando a integridade está ausente.

## CBC-MAC

CBC-MAC é seguro apenas sob condições específicas (principalmente **mensagens de tamanho fixo** e separação correta de domínio).

### Padrão clássico de forgery para tamanho variável

CBC-MAC geralmente é calculado como:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

Se você puder obter tags para mensagens escolhidas, muitas vezes poderá criar uma tag para uma concatenação (ou construção relacionada) sem conhecer a key, explorando como o CBC encadeia os blocos.

Isso aparece frequentemente em cookies/tokens de CTF que usam CBC-MAC no username ou role.

### Alternativas mais seguras

- Use HMAC (SHA-256/512)
- Use CMAC (AES-CMAC) corretamente
- Inclua o tamanho da mensagem / separação de domínio

## Stream ciphers: XOR e RC4

### O modelo mental

A maioria das situações com stream ciphers pode ser reduzida a:

`ciphertext = plaintext XOR keystream`

Portanto:

- Se você conhece o plaintext, recupera o keystream.
- Se o keystream for reutilizado (mesma key+nonce), `C1 XOR C2 = P1 XOR P2`.

### Criptografia baseada em XOR

Se você conhece qualquer segmento de plaintext na posição `i`, pode recuperar bytes do keystream e descriptografar outros ciphertexts nessas posições.

Ferramentas automáticas:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 é um stream cipher; criptografia e descriptografia são a mesma operação.

Se você conseguir obter a criptografia RC4 de um plaintext conhecido usando a mesma key, poderá recuperar o keystream e descriptografar outras mensagens do mesmo tamanho/offset.

Writeup de referência (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

## Referências

- [1] [Trail of Bits – Carelessness versus craftsmanship in cryptography](https://blog.trailofbits.com/2026/02/18/carelessness-versus-craftsmanship-in-cryptography/)

{{#include ../../banners/hacktricks-training.md}}
