# Algoritmos Criptográficos/Compressão

{{#include ../../banners/hacktricks-training.md}}

## Identificando Algoritmos

Se você se deparar com um código **using shift rights and lefts, xors and several arithmetic operations** é muito provável que seja a implementação de um **algoritmo criptográfico**. Aqui serão mostradas algumas maneiras de **identificar qual algoritmo está sendo usado sem precisar reverter cada etapa**.

### API functions

**CryptDeriveKey**

Se esta função for usada, você pode descobrir qual **algoritmo está sendo usado** verificando o valor do segundo parâmetro:

![](<../../images/image (156).png>)

Check here the table of possible algorithms and their assigned values: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

**RtlCompressBuffer/RtlDecompressBuffer**

Comprime e descomprime um buffer de dados.

**CryptAcquireContext**

From [the docs](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta): The **CryptAcquireContext** function is used to acquire a handle to a particular key container within a particular cryptographic service provider (CSP). **This returned handle is used in calls to CryptoAPI** functions that use the selected CSP.

**CryptCreateHash**

Inicia o hashing de um fluxo de dados. Se esta função for usada, você pode descobrir qual **algoritmo está sendo usado** verificando o valor do segundo parâmetro:

![](<../../images/image (549).png>)

\
Check here the table of possible algorithms and their assigned values: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

### Code constants

Às vezes é bem fácil identificar um algoritmo graças ao fato de que ele precisa usar um valor especial e único.

![](<../../images/image (833).png>)

Se você procurar pela primeira constante no Google, isto é o que obtém:

![](<../../images/image (529).png>)

Portanto, você pode assumir que a função decompilada é um **sha256 calculator.**\
Você pode buscar qualquer uma das outras constantes e provavelmente obterá o mesmo resultado.

### data info

Se o código não tiver nenhuma constante significativa, ele pode estar **carregando informações da seção .data**.\
Você pode acessar esses dados, **agrupar o primeiro dword** e procurar por ele no google como fizemos na seção anterior:

![](<../../images/image (531).png>)

Neste caso, se você procurar por **0xA56363C6** pode encontrar que está relacionado às **tabelas do algoritmo AES**.

## RC4 **(Criptografia Simétrica)**

### Characteristics

É composto por 3 partes principais:

- **Initialization stage/**: Cria uma **tabela de valores de 0x00 a 0xFF** (256 bytes no total, 0x100). Esta tabela é comumente chamada de **Substitution Box** (ou SBox).
- **Scrambling stage**: Percorre a tabela criada antes (loop de 0x100 iterações, novamente) modificando cada valor com bytes **semi-aleatórios**. Para gerar esses bytes semi-aleatórios, a **key do RC4 é usada**. As chaves do RC4 podem ter **entre 1 e 256 bytes de comprimento**, porém normalmente é recomendado que tenha mais de 5 bytes. Comumente, chaves RC4 têm 16 bytes.
- **XOR stage**: Finalmente, o plain-text ou ciphertext é **XORed com os valores gerados antes**. A função para encryptar e decryptar é a mesma. Para isso, um **loop através dos 256 bytes criados** será executado tantas vezes quanto necessário. Isso geralmente é reconhecido em código decompilado por um **%256 (mod 256)**.

> [!TIP]
> **Para identificar um RC4 em disassembly/decompiled code você pode procurar por 2 loops de tamanho 0x100 (com o uso de uma key) e depois um XOR dos dados de entrada com os 256 valores criados antes nos 2 loops, provavelmente usando um %256 (mod 256)**

### **Initialization stage/Substitution Box:** (Note the number 256 used as counter and how a 0 is written in each place of the 256 chars)

![](<../../images/image (584).png>)

### **Scrambling Stage:**

![](<../../images/image (835).png>)

### **XOR Stage:**

![](<../../images/image (904).png>)

## **AES (Criptografia Simétrica)**

### **Characteristics**

- Uso de **substitution boxes e lookup tables**
- É possível **distinguir AES pelo uso de valores específicos em tabelas de lookup** (constantes). _Note que a **constante** pode estar **armazenada** no binário ou **criada** **dinamicamente**._
- A **encryption key** deve ser **divisível** por **16** (normalmente 32B) e normalmente um **IV** de 16B é usado.

### SBox constants

![](<../../images/image (208).png>)

## Serpent **(Criptografia Simétrica)**

### Characteristics

- É raro encontrar malware usando Serpent, mas existem exemplos (Ursnif)
- Simples determinar se um algoritmo é Serpent ou não com base no seu comprimento (função extremamente longa)

### Identifying

Na imagem a seguir, note como a constante **0x9E3779B9** é usada (note que essa constante também é usada por outros algoritmos como **TEA** - Tiny Encryption Algorithm).\
Também observe o **tamanho do loop** (**132**) e o **número de operações XOR** nas instruções de **disassembly** e no **exemplo de código**:

![](<../../images/image (547).png>)

Como mencionado antes, este código pode ser visualizado em qualquer decompiler como uma **função muito longa** já que **não há jumps** dentro dela. O código decompilado pode parecer com o seguinte:

![](<../../images/image (513).png>)

Portanto, é possível identificar este algoritmo verificando o **magic number** e os **XORs iniciais**, vendo uma **função muito longa** e **comparando** algumas **instruções** da função longa **com uma implementação** (como o shift left por 7 e o rotate left por 22).

## RSA **(Criptografia Assimétrica)**

### Characteristics

- Mais complexo que algoritmos simétricos
- Não há constantes! (implementações custom são difíceis de identificar)
- KANAL (um crypto analyzer) falha em mostrar indícios sobre RSA pois depende de constantes.

### Identifying by comparisons

![](<../../images/image (1113).png>)

- Na linha 11 (esquerda) há um `+7) >> 3` que é o mesmo que na linha 35 (direita): `+7) / 8`
- A linha 12 (esquerda) verifica se `modulus_len < 0x040` e na linha 36 (direita) está verificando se `inputLen+11 > modulusLen`

## MD5 & SHA (hash)

### Characteristics

- 3 funções: Init, Update, Final
- Funções de inicialização similares

### Identify

**Init**

Você pode identificar ambos verificando as constantes. Note que o sha_init tem 1 constante que o MD5 não tem:

![](<../../images/image (406).png>)

**MD5 Transform**

Note o uso de mais constantes

![](<../../images/image (253) (1) (1).png>)

## CRC (hash)

- Menor e mais eficiente pois sua função é detectar mudanças acidentais nos dados
- Usa lookup tables (portanto você pode identificar pelas constantes)

### Identify

Verifique as **constantes das lookup tables**:

![](<../../images/image (508).png>)

Um algoritmo de hash CRC se parece com:

![](<../../images/image (391).png>)

## APLib (Compression)

### Characteristics

- Sem constantes reconhecíveis
- Você pode tentar escrever o algoritmo em python e procurar por coisas similares online

### Identify

O gráfico é bastante grande:

![](<../../images/image (207) (2) (1).png>)

Verifique **3 comparações para reconhecê-lo**:

![](<../../images/image (430).png>)

## Bugs em Implementações de Assinatura de Curva Elíptica

### EdDSA scalar range enforcement (HashEdDSA malleability)

- FIPS 186-5 §7.8.2 exige que verificadores HashEdDSA dividam uma assinatura `sig = R || s` e rejeitem qualquer escalar com `s \geq n`, onde `n` é a ordem do grupo. A biblioteca `elliptic` em JS ignorou essa verificação de bound, então qualquer atacante que conheça um par válido `(msg, R || s)` pode forjar assinaturas alternativas `s' = s + k·n` e continuar re-encodificando `sig' = R || s'`.
- As rotinas de verificação apenas consomem `s mod n`, portanto todos os `s'` congruentes a `s` são aceitos mesmo sendo strings de bytes diferentes. Sistemas que tratam assinaturas como tokens canônicos (consenso de blockchain, caches de replay, chaves de DB, etc.) podem ficar dessincronizados porque implementações estritas irão rejeitar `s'`.
- Ao auditar outro código HashEdDSA, assegure que o parser valida tanto o ponto `R` quanto o comprimento do escalar; tente adicionar múltiplos de `n` a um `s` conhecido-bom para confirmar que o verificador falha fechado.

### ECDSA truncation vs. leading-zero hashes

- Verificadores ECDSA devem usar apenas os bits mais à esquerda `log2(n)` do hash da mensagem `H`. Em `elliptic`, o helper de truncamento computou `delta = (BN(msg).byteLength()*8) - bitlen(n)`; o construtor `BN` descarta octetos zero à esquerda, então qualquer hash que comece com ≥4 bytes zero em curvas como secp192r1 (ordem de 192 bits) aparentava ter apenas 224 bits em vez de 256.
- O verificador fez um right-shift de 32 bits ao invés de 64, produzindo um `E` que não bate com o valor usado pelo signer. Assinaturas válidas nesses hashes falham com probabilidade ≈`2^-32` para inputs SHA-256.
- Alimente tanto o vetor “tudo certo” quanto variantes com leading-zero (por exemplo, Wycheproof `ecdsa_secp192r1_sha256_test.json` caso `tc296`) em uma implementação alvo; se o verificador discordar do signer, você encontrou um bug de truncamento explorável.

### Exercising Wycheproof vectors against libraries
- Wycheproof fornece conjuntos de testes JSON que codificam pontos malformados, escalares maleáveis, hashes incomuns e outros corner cases. Construir um harness ao redor de `elliptic` (ou qualquer crypto library) é direto: carregue o JSON, deserializa cada caso de teste, e verifique que a implementação corresponde à flag `result` esperada.
```javascript
for (const tc of ecdsaVectors.testGroups) {
const curve = new EC(tc.curve);
const pub = curve.keyFromPublic(tc.key, 'hex');
const ok = curve.verify(tc.msg, tc.sig, pub, 'hex', tc.msgSize);
assert.strictEqual(ok, tc.result === 'valid');
}
```
- As falhas devem ser triadas para distinguir violações da especificação de falsos positivos. Para os dois bugs acima, os casos do Wycheproof que falharam apontaram imediatamente para verificações de intervalo de escalar ausentes (EdDSA) e truncamento incorreto de hash (ECDSA).
- Integre o harness no CI para que regressões na análise de escalares, manuseio de hash ou validade de coordenadas acionem testes assim que forem introduzidas. Isso é especialmente útil para linguagens de alto nível (JS, Python, Go), onde conversões sutis de bignum são fáceis de errar.

## Referências

- [Trail of Bits - We found cryptography bugs in the elliptic library using Wycheproof](https://blog.trailofbits.com/2025/11/18/we-found-cryptography-bugs-in-the-elliptic-library-using-wycheproof/)
- [Wycheproof Test Suite](https://github.com/C2SP/wycheproof)

{{#include ../../banners/hacktricks-training.md}}
