# Criptografia Simétrica

{{#include ../../banners/hacktricks-training.md}}

## O que procurar em CTFs

- **Uso incorreto de modos**: padrões ECB, maleabilidade do CBC, reutilização de nonce no CTR/GCM.
- **Padding oracles**: erros/tempos diferentes para padding inválido.
- **Confusão de MAC**: uso de CBC-MAC com mensagens de tamanho variável ou erros de MAC-then-encrypt.
- **XOR em toda parte**: stream ciphers e construções personalizadas frequentemente se reduzem a XOR com um keystream.

## Modos AES e uso incorreto

A NIST especifica os modos de confidencialidade ECB, CBC e CTR no SP 800-38A e a authenticated encryption GCM no SP 800-38D.<sup>[[2]](#references)[[3]](#references)</sup>

### ECB: Electronic Codebook

ECB faz leak de padrões: blocos de plaintext iguais → blocos de ciphertext iguais. Isso permite:

- Cut-and-paste / reordenação de blocos
- Exclusão de blocos (se o formato continuar válido)

Se você puder controlar o plaintext e observar o ciphertext (ou cookies), tente criar blocos repetidos (por exemplo, muitos `A`s) e procure por repetições.

### CBC: Cipher Block Chaining

- CBC é **malleable**: inverter bits em `C[i-1]` inverte bits previsíveis em `P[i]`, enquanto também corrompe `P[i-1]`. Modificar o IV permite atingir o primeiro bloco de plaintext sem corromper um bloco de plaintext anterior.
- Se o sistema expuser padding válido versus padding inválido, você pode ter um **padding oracle**.

### CTR

CTR transforma o AES em um stream cipher: `C = P XOR keystream`.

Se um nonce/IV for reutilizado com a mesma chave:

- `C1 XOR C2 = P1 XOR P2` (reutilização clássica de keystream)
- Com plaintext conhecido, você pode recuperar o keystream e descriptografar outros dados.

**Padrões de exploração de reutilização de nonce/IV**

- Recupere o keystream onde o plaintext for conhecido/previsível:

```text
keystream[i..] = ciphertext[i..] XOR known_plaintext[i..]
```

Aplique os bytes de keystream recuperados para descriptografar qualquer outro ciphertext produzido com a mesma chave+IV nos mesmos offsets.
- Dados altamente estruturados (por exemplo, certificados ASN.1/X.509, cabeçalhos de arquivos, JSON/CBOR) fornecem grandes regiões de known-plaintext. Muitas vezes, você pode fazer XOR do ciphertext do certificado com o corpo previsível do certificado para derivar o keystream e, então, descriptografar outros segredos criptografados com o IV reutilizado. Consulte também [TLS & Certificates](../tls-and-certificates/README.md) para ver layouts típicos de certificados.<sup>[[1]](#references)</sup>
- Quando múltiplos segredos do **mesmo formato/tamanho serializado** são criptografados com a mesma chave+IV, o alinhamento dos campos faz leak mesmo sem plaintext completamente conhecido. Exemplo: chaves RSA PKCS#8 com módulos do mesmo tamanho posicionam os fatores primos nos mesmos offsets (aproximadamente 99,6% de alinhamento para 2048 bits). Fazer XOR de dois ciphertexts usando o keystream reutilizado isola `p ⊕ p'` / `q ⊕ q'`, que pode ser recuperado por brute force em segundos.<sup>[[1]](#references)</sup>
- IVs padrão em libraries (por exemplo, o valor constante `000...01`) são um footgun crítico: toda criptografia repete o mesmo keystream, transformando o CTR em um one-time pad reutilizado.<sup>[[1]](#references)</sup>

**Maleabilidade do CTR**

- CTR fornece apenas confidencialidade: inverter bits no ciphertext inverte deterministicamente os mesmos bits no plaintext. Sem uma authentication tag, attackers podem adulterar dados (por exemplo, modificar chaves, flags ou mensagens) sem serem detectados.
- Use AEAD (GCM, GCM-SIV, ChaCha20-Poly1305 etc.) e aplique a verificação da tag para detectar bit-flips.

### GCM

O GCM também falha gravemente com a reutilização de nonce. Se a mesma chave+nonce for usada mais de uma vez, normalmente você obtém:

- Reutilização de keystream para encryption (como no CTR), permitindo a recuperação do plaintext quando qualquer plaintext for conhecido.
- Perda das garantias de integridade. Dependendo do que for exposto (múltiplos pares mensagem/tag usando o mesmo nonce), attackers podem conseguir forjar tags.

Orientações operacionais:

- Trate a "reutilização de nonce" em AEAD como uma vulnerabilidade crítica.
- AEADs resistentes a misuse, como AES-GCM-SIV, reduzem os impactos da reutilização de nonce. Os callers ainda devem fornecer nonces únicos conforme exigido pela interface da construção; a reutilização acidental tem consequências limitadas em comparação com o GCM comum.<sup>[[3]](#references)[[4]](#references)</sup>
- Se você tiver múltiplos ciphertexts usando o mesmo nonce, comece verificando relações no estilo `C1 XOR C2 = P1 XOR P2`.

### Ferramentas

- [CyberChef](https://gchq.github.io/CyberChef/) para experimentos rápidos.<sup>[[8]](#references)</sup>
- O pacote [PyCryptodome](https://www.pycryptodome.org/) do Python para scripting.<sup>[[9]](#references)</sup>

## Padrões de exploração do ECB

ECB (Electronic Code Book) criptografa cada bloco independentemente:

- blocos de plaintext iguais → blocos de ciphertext iguais
- isso faz leak da estrutura e permite ataques no estilo cut-and-paste

![Diagrama de blocos da descriptografia no modo ECB](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Ideia de detecção: padrão de token/cookie

Se você fizer login várias vezes e **sempre receber o mesmo cookie**, o ciphertext pode ser determinístico (ECB ou IV fixo).

Se você criar dois usuários com layouts de plaintext em grande parte idênticos (por exemplo, caracteres repetidos longos) e observar blocos de ciphertext repetidos nos mesmos offsets, ECB é o principal suspeito.

### Padrões de exploração

#### Removendo blocos inteiros

Se o formato do token for algo como `<username>|<password>` e o limite do bloco estiver alinhado, às vezes você pode criar um usuário de modo que o bloco `admin` fique alinhado e, então, remover os blocos anteriores para obter um token válido para `admin`.

#### Movendo blocos

Se o backend tolerar padding/espaços extras (`admin` versus `admin    `), você pode:

- Alinhar um bloco que contenha `admin   `
- Trocar/reutilizar esse bloco de ciphertext em outro token

## Padding Oracle

### O que é

No modo CBC, se o servidor revelar (direta ou indiretamente) se o plaintext descriptografado possui **padding PKCS#7 válido**, muitas vezes você pode:<sup>[[7]](#references)</sup>

- Descriptografar ciphertext sem a chave
- Construir um ciphertext que seja descriptografado para um plaintext escolhido quando você puder enviar blocos anteriores ou IVs criados especialmente e a aplicação aceitar a mensagem resultante com padding válido

O oracle pode ser:

- Uma mensagem de erro específica
- Um status HTTP / tamanho de resposta diferente
- Uma diferença de tempo

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

- O tamanho do bloco geralmente é `16` para AES.
- `-encoding 0` significa Base64.
- Use `-error` se o oracle for uma string específica.

### Por que funciona

A descriptografia CBC calcula `P[i] = D(C[i]) XOR C[i-1]`. Ao modificar bytes em `C[i-1]` e observar se o padding é válido, você pode recuperar `P[i]` byte a byte.

## Bit-flipping in CBC

Mesmo sem um padding oracle, CBC é maleável. Se você puder modificar blocos de ciphertext e a aplicação usar o plaintext descriptografado como dados estruturados (por exemplo, `role=user`), poderá inverter bits específicos para alterar bytes selecionados do plaintext em uma posição escolhida no próximo bloco.

Padrão típico de CTF:

- Token = `IV || C1 || C2 || ...`
- Você controla bytes em `C[i]`
- Seu alvo são bytes do plaintext em `P[i+1]`, pois `P[i+1] = D(C[i+1]) XOR C[i]`

Isso, por si só, não é uma quebra de confidencialidade, mas é uma primitiva comum de privilege-escalation quando a integridade está ausente.

## CBC-MAC

CBC-MAC é seguro apenas sob condições específicas (principalmente **mensagens de tamanho fixo** e separação correta de domínio). AES-CMAC é uma construção padronizada que lida com segurança com entradas de tamanho variável.<sup>[[5]](#references)</sup>

### Padrão clássico de forgery com tamanho variável

CBC-MAC geralmente é calculado como:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

Se você puder obter tags para mensagens escolhidas, muitas vezes poderá criar uma tag para uma concatenação (ou construção relacionada) sem conhecer a chave, explorando a forma como o CBC encadeia os blocos.

Isso aparece frequentemente em cookies/tokens de CTF que usam CBC-MAC para autenticar username ou role.

### Alternativas mais seguras

- Use HMAC (SHA-256/512)
- Use CMAC (AES-CMAC) corretamente
- Inclua o tamanho da mensagem / separação de domínio

## Stream ciphers: XOR e RC4

### O modelo mental

A maioria das situações com stream ciphers se reduz a:

`ciphertext = plaintext XOR keystream`

Então:

- Se você conhece o plaintext, recupera o keystream.
- Se o keystream for reutilizado (mesma key+nonce), `C1 XOR C2 = P1 XOR P2`.

### Criptografia baseada em XOR

Se você conhece qualquer segmento de plaintext na posição `i`, pode recuperar bytes do keystream e descriptografar outros ciphertexts nessas posições.

Autosolvers:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 é um stream cipher legado; encrypt/decrypt são a mesma operação XOR. Seus biases conhecidos o tornam inadequado para sistemas novos, e o TLS proíbe explicitamente seus cipher suites.<sup>[[6]](#references)</sup>

Se você conseguir obter a encrypt de RC4 de um plaintext conhecido usando a mesma key, poderá recuperar o keystream e descriptografar outras mensagens com o mesmo tamanho/offset.

Writeup de referência (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

## References

- [1] [Trail of Bits – Descuido versus excelência em criptografia](https://blog.trailofbits.com/2026/02/18/carelessness-versus-craftsmanship-in-cryptography/)
- [2] [NIST SP 800-38A - Recomendação para modos de operação de block ciphers](https://csrc.nist.gov/pubs/sp/800/38/a/final)
- [3] [NIST SP 800-38D - Recomendação para Galois/Counter Mode (GCM) e GMAC](https://csrc.nist.gov/pubs/sp/800/38/d/final)
- [4] [RFC 8452 - AES-GCM-SIV: Authenticated Encryption resistente ao uso indevido de Nonce](https://www.rfc-editor.org/rfc/rfc8452)
- [5] [RFC 4493 - O algoritmo AES-CMAC](https://www.rfc-editor.org/rfc/rfc4493)
- [6] [RFC 7465 - Proibição de cipher suites RC4](https://www.rfc-editor.org/rfc/rfc7465)
- [7] [OWASP Web Security Testing Guide - Testando um Padding Oracle](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/02-Testing_for_Padding_Oracle)
- [8] [GCHQ CyberChef](https://gchq.github.io/CyberChef/)
- [9] [Documentação do PyCryptodome](https://www.pycryptodome.org/)
{{#include ../../banners/hacktricks-training.md}}
