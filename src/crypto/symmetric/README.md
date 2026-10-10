# Criptografia simétrica

{{#include ../../banners/hacktricks-training.md}}

## O que procurar em CTFs

- **Uso indevido de modos**: padrões ECB, maleabilidade do CBC, reutilização de nonce em CTR/GCM.
- **Padding oracles**: erros ou tempos de resposta diferentes para padding inválido.
- **Confusão de MAC**: uso de CBC-MAC com mensagens de tamanho variável ou erros de MAC-then-encrypt.
- **XOR em toda parte**: stream ciphers e construções personalizadas geralmente se reduzem a XOR com um keystream.

## Modos AES e uso indevido

O NIST especifica os modos de confidencialidade ECB, CBC e CTR no SP 800-38A e a criptografia autenticada GCM no SP 800-38D.<sup>[[2]](#references)[[3]](#references)</sup>

### ECB: Electronic Codebook

ECB vaza padrões: blocos de texto simples iguais → blocos de texto cifrado iguais. Isso permite:

- Cut-and-paste / reordenação de blocos
- Exclusão de blocos (se o formato continuar válido)

Se você puder controlar o texto simples e observar o texto cifrado (ou cookies), tente criar blocos repetidos (por exemplo, muitos `A`s) e procure por repetições.

### CBC: Cipher Block Chaining

- CBC é **maleável**: inverter bits em `C[i-1]` inverte bits previsíveis em `P[i]`, mas também corrompe `P[i-1]`. Modificar o IV afeta o primeiro bloco de texto simples sem corromper um bloco de texto simples anterior.
- Se o sistema expuser se o padding é válido ou inválido, você pode ter um **padding oracle**.

### CTR

CTR transforma AES em uma stream cipher: `C = P XOR keystream`.

Se um nonce/IV for reutilizado com a mesma chave:

- `C1 XOR C2 = P1 XOR P2` (reutilização clássica de keystream)
- Com texto simples conhecido, você pode recuperar o keystream e descriptografar outros textos.

**Padrões de exploração da reutilização de nonce/IV**

- Recupere o keystream onde o texto simples é conhecido ou pode ser deduzido:

  ```text
  keystream[i..] = ciphertext[i..] XOR known_plaintext[i..]
  ```

  Aplique os bytes de keystream recuperados para descriptografar qualquer outro ciphertext produzido com a mesma key+IV nos mesmos offsets.
- Dados altamente estruturados (por exemplo, certificados ASN.1/X.509, cabeçalhos de arquivos, JSON/CBOR) contêm grandes regiões de plaintext conhecido. Muitas vezes, você pode aplicar XOR ao ciphertext do certificado com o corpo previsível do certificado para derivar o keystream e, então, descriptografar outros segredos criptografados com o IV reutilizado. Consulte também [TLS & Certificates](../tls-and-certificates/README.md) para ver layouts típicos de certificados.<sup>[[1]](#references)</sup>
- Quando vários segredos do **mesmo formato/tamanho serializado** são criptografados com a mesma key+IV, o alinhamento dos campos vaza informações mesmo sem plaintext conhecido completo. Por exemplo, chaves RSA PKCS#8 com o mesmo tamanho de módulo colocam os fatores primos nos mesmos offsets (alinhamento de ~99,6% para 2048 bits). Aplicar XOR a dois ciphertexts usando o keystream reutilizado isola `p ⊕ p'` / `q ⊕ q'`, que podem ser recuperados por brute force em segundos.<sup>[[1]](#references)</sup>
- IVs padrão em bibliotecas (por exemplo, constante `000...01`) são uma armadilha crítica: cada criptografia repete o mesmo keystream, transformando CTR em um one-time pad reutilizado.<sup>[[1]](#references)</sup>

**Malleability de CTR**

- CTR fornece apenas confidencialidade: inverter bits no ciphertext inverte deterministicamente os mesmos bits no plaintext. Sem uma tag de autenticação, attackers podem adulterar dados (por exemplo, alterar chaves, flags ou mensagens) sem serem detectados.
- Use AEAD (GCM, GCM-SIV, ChaCha20-Poly1305 etc.) e exija a verificação da tag para detectar alterações de bits.

### GCM

GCM também falha gravemente quando há reutilização de nonce. Se a mesma key+nonce for usada mais de uma vez, normalmente ocorre:

- Reutilização do keystream na criptografia (como em CTR), permitindo recuperar plaintext quando qualquer plaintext é conhecido.
- Perda das garantias de integridade. Dependendo do que estiver exposto (vários pares de mensagem/tag com o mesmo nonce), attackers podem conseguir forjar tags.

Orientações operacionais:

- Trate a "reutilização de nonce" em AEAD como uma vulnerabilidade crítica.
- AEADs resistentes a uso incorreto, como AES-GCM-SIV, reduzem os danos causados pela reutilização de nonce. Ainda assim, os callers devem fornecer nonces únicos, conforme exigido pela interface da construção; a reutilização acidental tem consequências limitadas em comparação com o GCM comum.<sup>[[3]](#references)[[4]](#references)</sup>
- Se você tiver vários ciphertexts com o mesmo nonce, comece verificando relações do tipo `C1 XOR C2 = P1 XOR P2`.

### Ferramentas

- [CyberChef](https://gchq.github.io/CyberChef/) para experimentos rápidos.<sup>[[8]](#references)</sup>
- O pacote [PyCryptodome](https://www.pycryptodome.org/) do Python para scripting.<sup>[[9]](#references)</sup>

## Padrões de exploração de ECB

ECB (Electronic Code Book) criptografa cada bloco de forma independente:

- blocos de plaintext iguais → blocos de ciphertext iguais
- isso vaza a estrutura e possibilita ataques do tipo cut-and-paste

![Diagrama de blocos de descriptografia do modo ECB](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Ideia de detecção: padrão de token/cookie

Se você fizer login várias vezes e **sempre receber o mesmo cookie**, o ciphertext pode ser determinístico (ECB ou IV fixo).

Se você criar dois usuários com layouts de plaintext quase idênticos (por exemplo, longas sequências de caracteres repetidos) e observar blocos de ciphertext repetidos nos mesmos offsets, ECB é uma forte suspeita.

### Padrões de exploração

#### Remover blocos inteiros

Se o formato do token for algo como `<username>|<password>` e o limite do bloco estiver alinhado, às vezes é possível criar um usuário de modo que o bloco `admin` fique alinhado e, então, remover os blocos anteriores para obter um token válido para `admin`.

#### Mover blocos

Se o backend tolerar padding/espaços extras (`admin` vs `admin    `), você pode:

- Alinhar um bloco que contenha `admin   `
- Trocar/reutilizar esse bloco de ciphertext em outro token

## Padding Oracle

### O que é

No modo CBC, se o servidor revelar (direta ou indiretamente) se o plaintext descriptografado tem **padding PKCS#7 válido**, muitas vezes é possível:<sup>[[7]](#references)</sup>

- Descriptografar ciphertext sem a chave
- Construir um ciphertext que seja descriptografado para um plaintext escolhido, quando você pode enviar blocos anteriores ou IVs manipulados e a aplicação aceita a mensagem resultante com padding válido

O oracle pode ser:

- Uma mensagem de erro específica
- Um status HTTP / tamanho da resposta diferente
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

- O tamanho do bloco costuma ser `16` para AES.
- `-encoding 0` significa Base64.
- Use `-error` se o oracle retornar uma string específica.

### Por que funciona

A descriptografia CBC calcula `P[i] = D(C[i]) XOR C[i-1]`. Ao modificar bytes em `C[i-1]` e observar se o padding é válido, você pode recuperar `P[i]` byte por byte.

## Bit-flipping em CBC

Mesmo sem um padding oracle, CBC é maleável. Se você puder modificar blocos de ciphertext e a aplicação usar o plaintext descriptografado como dados estruturados (por exemplo, `role=user`), poderá inverter bits específicos para alterar bytes selecionados do plaintext em uma posição escolhida no bloco seguinte.

Padrão comum em CTFs:

- Token = `IV || C1 || C2 || ...`
- Você controla bytes em `C[i]`
- O alvo são bytes do plaintext em `P[i+1]`, pois `P[i+1] = D(C[i+1]) XOR C[i]`

Isso, por si só, não quebra a confidencialidade, mas é uma técnica comum de escalada de privilégios quando não há integridade.

## CBC-MAC

CBC-MAC só é seguro sob condições específicas (principalmente **mensagens de tamanho fixo** e separação de domínio correta). AES-CMAC é uma construção padronizada que lida com segurança com entradas de tamanho variável.<sup>[[5]](#references)</sup>

### Padrão clássico de falsificação com tamanho variável

CBC-MAC costuma ser calculado assim:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

Se você conseguir obter tags para mensagens escolhidas, muitas vezes poderá criar uma tag para uma concatenação (ou construção relacionada) sem conhecer a chave, explorando a forma como CBC encadeia os blocos.

Isso aparece com frequência em cookies/tokens de CTF que autenticam o nome de usuário ou a função com CBC-MAC.

### Alternativas mais seguras

- Use HMAC (SHA-256/512)
- Use CMAC (AES-CMAC) corretamente
- Inclua o tamanho da mensagem / separação de domínio

## Cifras de fluxo: XOR e RC4

### Modelo mental

A maioria das situações com cifras de fluxo se resume a:

`ciphertext = plaintext XOR keystream`

Assim:

- Se você conhece o plaintext, recupera o keystream.
- Se o keystream for reutilizado (mesma chave+nonce), `C1 XOR C2 = P1 XOR P2`.

### Criptografia baseada em XOR

Se você conhecer qualquer trecho do plaintext na posição `i`, poderá recuperar bytes do keystream e descriptografar outros ciphertexts nessas posições.

Ferramentas automatizadas:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 é uma cifra de fluxo legada; criptografar e descriptografar consistem na mesma operação XOR. Seus vieses conhecidos a tornam inadequada para novos sistemas, e o TLS proíbe explicitamente seus conjuntos de cifras.<sup>[[6]](#references)</sup>

Se você conseguir obter o resultado da criptografia RC4 de um plaintext conhecido usando a mesma chave, poderá recuperar o keystream e descriptografar outras mensagens com o mesmo tamanho/deslocamento.

Writeup de referência (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

## References

- [1] [Trail of Bits – Descuido versus rigor na criptografia](https://blog.trailofbits.com/2026/02/18/carelessness-versus-craftsmanship-in-cryptography/)
- [2] [NIST SP 800-38A - Recomendação para modos de operação de cifras de bloco](https://csrc.nist.gov/pubs/sp/800/38/a/final)
- [3] [NIST SP 800-38D - Recomendação para Galois/Counter Mode (GCM) e GMAC](https://csrc.nist.gov/pubs/sp/800/38/d/final)
- [4] [RFC 8452 - AES-GCM-SIV: Criptografia autenticada resistente ao uso indevido de nonce](https://www.rfc-editor.org/rfc/rfc8452)
- [5] [RFC 4493 - O algoritmo AES-CMAC](https://www.rfc-editor.org/rfc/rfc4493)
- [6] [RFC 7465 - Proibição de conjuntos de cifras RC4](https://www.rfc-editor.org/rfc/rfc7465)
- [7] [OWASP Web Security Testing Guide - Teste de padding oracle](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/02-Testing_for_Padding_Oracle)
- [8] [GCHQ CyberChef](https://gchq.github.io/CyberChef/)
- [9] [Documentação do PyCryptodome](https://www.pycryptodome.org/)
{{#include ../../banners/hacktricks-training.md}}
