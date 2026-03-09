# Criptografia Simétrica

{{#include ../../banners/hacktricks-training.md}}

## O que procurar em CTFs

- **Uso incorreto de modos**: padrões ECB, maleabilidade CBC, reutilização de nonce em CTR/GCM.
- **Padding oracles**: erros/tempos diferentes para padding inválido.
- **Confusão de MAC**: usar CBC-MAC com mensagens de comprimento variável, ou erros de MAC-then-encrypt.
- **XOR por toda parte**: stream ciphers e construções customizadas frequentemente reduzem-se a XOR com um keystream.

## Modos AES e uso incorreto

### ECB: Electronic Codebook

ECB leaks patterns: equal plaintext blocks → equal ciphertext blocks. That enables:

- Cut-and-paste / block reordering
- Block deletion (if the format remains valid)

Se você pode controlar o plaintext e observar o ciphertext (ou cookies), tente criar blocos repetidos (ex.: muitos `A`s) e procure por repetições.

### CBC: Cipher Block Chaining

- CBC é **malleable**: inverter bits em `C[i-1]` inverte bits previsíveis em `P[i]`.
- Se o sistema expõe padding válido vs padding inválido, você pode ter um **padding oracle**.

### CTR

CTR transforma AES em um stream cipher: `C = P XOR keystream`.

Se um nonce/IV for reutilizado com a mesma chave:

- `C1 XOR C2 = P1 XOR P2` (reutilização clássica de keystream)
- Com plaintext conhecido, você pode recuperar o keystream e descriptografar outros.

**Nonce/IV reuse exploitation patterns**

- Recupere o keystream onde o plaintext for conhecido/possível de adivinhar:

```text
keystream[i..] = ciphertext[i..] XOR known_plaintext[i..]
```

Aplique os bytes de keystream recuperados para descriptografar qualquer outro ciphertext produzido com a mesma key+IV nos mesmos offsets.
- Dados altamente estruturados (ex.: ASN.1/X.509 certificates, file headers, JSON/CBOR) dão grandes regiões de plaintext previsível. Frequentemente você pode XORar o ciphertext do certificado com o corpo previsível para derivar o keystream e então descriptografar outros segredos encriptados com o mesmo IV. Veja também [TLS & Certificates](../tls-and-certificates/README.md) para layouts típicos de certificados.
- Quando múltiplos segredos do **mesmo formato/size serializado** são encriptados com a mesma key+IV, o alinhamento de campos vaza mesmo sem plaintext completo conhecido. Exemplo: chaves RSA PKCS#8 do mesmo tamanho de módulo colocam fatores primos em offsets correspondentes (~99.6% de alinhamento para 2048-bit). XORar dois ciphertexts sob o keystream reutilizado isola `p ⊕ p'` / `q ⊕ q'`, que pode ser recuperado por força bruta em segundos.
- IVs padrão em bibliotecas (ex.: constante `000...01`) são uma armadilha crítica: cada encriptação repete o mesmo keystream, transformando CTR em um one-time pad reutilizado.

**CTR malleability**

- CTR fornece apenas confidencialidade: inverter bits no ciphertext inverte determinísticamente os mesmos bits no plaintext. Sem uma tag de autenticação, atacantes podem adulterar os dados (ex.: tweak keys, flags, ou mensagens) sem serem detectados.
- Use AEAD (GCM, GCM-SIV, ChaCha20-Poly1305, etc.) e force verificação de tag para detectar bit-flips.

### GCM

GCM também falha gravemente sob reutilização de nonce. Se a mesma key+nonce for usada mais de uma vez, tipicamente você obtém:

- Reutilização de keystream para encriptação (como CTR), permitindo recuperação de plaintext quando qualquer plaintext for conhecido.
- Perda das garantias de integridade. Dependendo do que é exposto (múltiplos pares message/tag sob o mesmo nonce), atacantes podem ser capazes de forjar tags.

Orientação operacional:

- Trate "nonce reuse" em AEAD como uma vulnerabilidade crítica.
- AEADs resistentes a misuse (ex.: GCM-SIV) reduzem os efeitos da reutilização de nonce, mas ainda exigem nonces/IVs únicos.
- Se você tem múltiplos ciphertexts sob o mesmo nonce, comece checando relações do tipo `C1 XOR C2 = P1 XOR P2`.

### Ferramentas

- CyberChef para experimentos rápidos: https://gchq.github.io/CyberChef/
- Python: `pycryptodome` para scripting

## Padrões de exploração ECB

ECB (Electronic Code Book) encripta cada bloco independentemente:

- equal plaintext blocks → equal ciphertext blocks
- isso vaza estrutura e permite ataques do tipo cut-and-paste

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Ideia de detecção: padrão de token/cookie

Se você fizer login várias vezes e **sempre receber o mesmo cookie**, o ciphertext pode ser determinístico (ECB ou IV fixo).

Se você criar dois usuários com layouts de plaintext majoritariamente idênticos (ex.: caracteres repetidos longos) e ver blocos de ciphertext repetidos nos mesmos offsets, ECB é o principal suspeito.

### Padrões de exploração

#### Removendo blocos inteiros

Se o formato do token for algo como `<username>|<password>` e a fronteira de bloco alinhar, às vezes você pode criar um usuário de modo que o bloco `admin` apareça alinhado, então remover blocos precedentes para obter um token válido para `admin`.

#### Movendo blocos

Se o backend tolera padding/espaços extras (`admin` vs `admin    `), você pode:

- Alinhar um bloco que contenha `admin   `
- Trocar/reutilizar esse bloco de ciphertext em outro token

## Padding Oracle

### O que é

No modo CBC, se o servidor revela (direta ou indiretamente) se o plaintext decifrado tem **PKCS#7 padding válido**, você frequentemente pode:

- Decifrar ciphertext sem a chave
- Encriptar plaintext escolhido (forjar ciphertext)

O oracle pode ser:

- Uma mensagem de erro específica
- Um HTTP status diferente / tamanho de resposta distinto
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
Notas:

- Block size is often `16` for AES.
- `-encoding 0` means Base64.
- Use `-error` if the oracle is a specific string.

### Por que funciona

CBC decryption computes `P[i] = D(C[i]) XOR C[i-1]`. By modifying bytes in `C[i-1]` and watching whether the padding is valid, you can recover `P[i]` byte-by-byte.

## Bit-flipping in CBC

Mesmo sem um padding oracle, CBC é maleável. Se você pode modificar ciphertext blocks e a aplicação usa o decrypted plaintext como dados estruturados (por exemplo, `role=user`), você pode inverter bits específicos para alterar bytes selecionados do plaintext em uma posição escolhida no próximo bloco.

Padrão típico de CTF:

- Token = `IV || C1 || C2 || ...`
- You control bytes in `C[i]`
- You target plaintext bytes in `P[i+1]` because `P[i+1] = D(C[i+1]) XOR C[i]`

Isso não é uma quebra de confidencialidade por si só, mas é uma primitiva comum de escalonamento de privilégios quando falta integridade.

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

### Modelo mental

Most stream cipher situations reduce to:

`ciphertext = plaintext XOR keystream`

So:

- If you know plaintext, you recover keystream.
- If keystream is reused (same key+nonce), `C1 XOR C2 = P1 XOR P2`.

### XOR-based encryption

If you know any plaintext segment at position `i`, you can recover keystream bytes and decrypt other ciphertexts at those positions.

Autosolvers:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 is a stream cipher; encrypt/decrypt are the same operation.

If you can get RC4 encryption of known plaintext under the same key, you can recover the keystream and decrypt other messages of the same length/offset.

Reference writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

## References

- [Trail of Bits – Carelessness versus craftsmanship in cryptography](https://blog.trailofbits.com/2026/02/18/carelessness-versus-craftsmanship-in-cryptography/)

{{#include ../../banners/hacktricks-training.md}}
