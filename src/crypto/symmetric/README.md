# Criptografia Simétrica

{{#include ../../banners/hacktricks-training.md}}

## O que procurar em CTFs

- **Mode misuse**: ECB patterns, CBC malleability, CTR/GCM nonce reuse.
- **Padding oracles**: erros/tempos diferentes para padding inválido.
- **MAC confusion**: usando CBC-MAC com mensagens de comprimento variável, ou erros de MAC-then-encrypt.
- **XOR everywhere**: stream ciphers e construções customizadas frequentemente se reduzem a XOR com um keystream.

## AES modes and misuse

### ECB: Electronic Codebook

ECB leaks patterns: blocos de texto simples iguais → blocos de texto cifrado iguais. Isso permite:

- Cut-and-paste / block reordering
- Remoção de blocos (se o formato permanecer válido)

Se você pode controlar o texto simples e observar o texto cifrado (ou cookies), tente criar blocos repetidos (por ex., muitos `A`s) e procure por repetições.

### CBC: Cipher Block Chaining

- CBC é **malleável**: inverter bits em `C[i-1]` inverte bits previsíveis em `P[i]`.
- Se o sistema expõe padding válido vs padding inválido, você pode ter um **padding oracle**.

### CTR

CTR transforma AES em uma cifra de fluxo: `C = P XOR keystream`.

Se um nonce/IV for reutilizado com a mesma chave:

- `C1 XOR C2 = P1 XOR P2` (clássico reuso de keystream)
- Com texto simples conhecido, você pode recuperar o keystream e descriptografar outros.

**Nonce/IV reuse exploitation patterns**

- Recuperar o keystream onde o texto simples é conhecido/adivinhável:

```text
keystream[i..] = ciphertext[i..] XOR known_plaintext[i..]
```

Aplique os bytes do keystream recuperado para descriptografar qualquer outro texto cifrado produzido com a mesma chave+IV nos mesmos offsets.
- Dados altamente estruturados (por ex., ASN.1/X.509 certificates, file headers, JSON/CBOR) dão grandes regiões de texto simples conhecido. Frequentemente você pode XORar o ciphertext do certificado com o corpo previsível do certificado para derivar o keystream, então descriptografar outros segredos cifrados sob o IV reutilizado. Veja também [TLS & Certificates](../tls-and-certificates/README.md) para layouts típicos de certificados.
- Quando múltiplos segredos do mesmo formato/tamanho serializado são criptografados com a mesma chave+IV, o alinhamento de campos leaks mesmo sem plaintext conhecido completo. Exemplo: chaves PKCS#8 RSA do mesmo tamanho de módulo colocam fatores primos nos mesmos offsets (~99.6% de alinhamento para 2048-bit). XORing dois ciphertexts sob o keystream reutilizado isola `p ⊕ p'` / `q ⊕ q'`, que podem ser recuperados por força bruta em segundos.
- IVs padrão em bibliotecas (ex.: constante `000...01`) são uma armadilha crítica: cada criptografia repete o mesmo keystream, transformando CTR em um one-time pad reutilizado.

**CTR malleability**

- CTR fornece apenas confidencialidade: inverter bits no texto cifrado inverte deterministamente os mesmos bits no texto simples. Sem uma tag de autenticação, atacantes podem adulterar dados (ex.: ajustar chaves, flags ou mensagens) sem serem detectados.
- Use AEAD (GCM, GCM-SIV, ChaCha20-Poly1305, etc.) e exija verificação da tag para detectar bit-flips.

### GCM

GCM também falha severamente sob reuso de nonce. Se a mesma chave+nonce for usada mais de uma vez, tipicamente você obtém:

- Reuso de keystream para cifragem (como CTR), permitindo recuperação de plaintext quando qualquer plaintext é conhecido.
- Perda das garantias de integridade. Dependendo do que é exposto (múltiplos pares mensagem/tag sob o mesmo nonce), atacantes podem ser capazes de forjar tags.

Orientações operacionais:

- Trate "nonce reuse" em AEAD como uma vulnerabilidade crítica.
- AEADs resistentes a misuse (ex.: GCM-SIV) reduzem o impacto do reuso de nonce, mas ainda exigem nonces/IVs únicos.
- Se você tem múltiplos ciphertexts sob o mesmo nonce, comece checando relações do tipo `C1 XOR C2 = P1 XOR P2`.

### Tools

- CyberChef for quick experiments: https://gchq.github.io/CyberChef/
- Python: `pycryptodome` for scripting

## ECB exploitation patterns

ECB (Electronic Code Book) criptografa cada bloco independentemente:

- blocos de texto simples iguais → blocos de texto cifrado iguais
- isso vaza estrutura e possibilita ataques do tipo cut-and-paste

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Detection idea: token/cookie pattern

Se você faz login várias vezes e **sempre recebe o mesmo cookie**, o texto cifrado pode ser determinístico (ECB ou IV fixo).

Se você criar dois usuários com layouts de texto simples majoritariamente idênticos (ex.: longos caracteres repetidos) e ver blocos de texto cifrado repetidos nos mesmos offsets, o ECB é um forte suspeito.

### Exploitation patterns

#### Removing entire blocks

Se o formato do token for algo como `<username>|<password>` e a fronteira de bloco alinhar, às vezes você pode criar um usuário de modo que o bloco `admin` apareça alinhado, então remover blocos anteriores para obter um token válido para `admin`.

#### Moving blocks

Se o backend tolerar padding/espacos extras (`admin` vs `admin    `), você pode:

- Alinhar um bloco que contenha `admin   `
- Trocar/reusar esse bloco de texto cifrado em outro token

## Padding Oracle

### What it is

Em modo CBC, se o servidor revela (direta ou indiretamente) se o texto simples decifrado tem **valid PKCS#7 padding**, você frequentemente pode:

- Decifrar ciphertext sem a chave
- Criptografar plaintext escolhido (forjar ciphertext)

O oracle pode ser:

- Uma mensagem de erro específica
- Um status HTTP / tamanho de resposta diferente
- Uma diferença de timing

### Practical exploitation

PadBuster é a ferramenta clássica:

{{#ref}}
https://github.com/AonCyberLabs/PadBuster
{{#endref}}

Exemplo:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 16 \
-encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
Notas:

- O tamanho do bloco é frequentemente `16` para AES.
- `-encoding 0` significa Base64.
- Use `-error` se o oracle for uma string específica.

### Por que funciona

CBC decryption computes `P[i] = D(C[i]) XOR C[i-1]`. Ao modificar bytes em `C[i-1]` e observar se o padding é válido, você pode recuperar `P[i]` byte-a-byte.

## Bit-flipping in CBC

Mesmo sem um padding oracle, CBC é malleable. Se você puder modificar blocos de ciphertext e a aplicação usar o plaintext decriptado como dados estruturados (por exemplo, `role=user`), você pode inverter bits específicos para alterar bytes selecionados do plaintext em uma posição escolhida no próximo bloco.

Padrão típico em CTF:

- Token = `IV || C1 || C2 || ...`
- Você controla bytes em `C[i]`
- Você mira bytes do plaintext em `P[i+1]` porque `P[i+1] = D(C[i+1]) XOR C[i]`

Isso não é uma quebra de confidencialidade por si só, mas é um primitivo comum de elevação de privilégios quando falta integridade.

## CBC-MAC

CBC-MAC é seguro apenas sob condições específicas (notadamente **mensagens de comprimento fixo** e separação de domínio correta).

### Padrão clássico de falsificação para mensagens de comprimento variável

CBC-MAC geralmente é calculado como:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

Se você puder obter tags para mensagens escolhidas, frequentemente pode criar um tag para uma concatenação (ou construção relacionada) sem conhecer a chave, explorando como CBC encadeia blocos.

Isso aparece frequentemente em cookies/tokens de CTF que aplicam MAC ao username ou role com CBC-MAC.

### Alternativas mais seguras

- Use HMAC (SHA-256/512)
- Use CMAC (AES-CMAC) corretamente
- Inclua o comprimento da mensagem / separação de domínio

## Stream ciphers: XOR and RC4

### Modelo mental

A maioria das situações envolvendo stream ciphers se resume a:

`ciphertext = plaintext XOR keystream`

Então:

- Se você conhece o plaintext, você recupera o keystream.
- Se o keystream for reutilizado (mesma key+nonce), `C1 XOR C2 = P1 XOR P2`.

### XOR-based encryption

Se você conhece qualquer segmento de plaintext na posição `i`, você pode recuperar bytes do keystream e descriptografar outros ciphertexts nessas posições.

Autosolvers:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 é um stream cipher; encrypt/decrypt são a mesma operação.

Se você consegue obter a encriptação RC4 de um plaintext conhecido sob a mesma chave, você pode recuperar o keystream e descriptografar outras mensagens do mesmo comprimento/deslocamento.

Reference writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

## References

- [Trail of Bits – Carelessness versus craftsmanship in cryptography](https://blog.trailofbits.com/2026/02/18/carelessness-versus-craftsmanship-in-cryptography/)

{{#include ../../banners/hacktricks-training.md}}
