# Cryptographic/Compression Algorithms

{{#include ../../banners/hacktricks-training.md}}

## Identifying Algorithms

Se o código termina em **usando shifts à direita e à esquerda, XORs e várias operações aritméticas** é bem provável que seja a implementação de um **algoritmo criptográfico**. Aqui serão mostradas algumas maneiras de **identificar qual algoritmo está sendo usado sem precisar reverter cada passo**.

### API functions

**CryptDeriveKey**

Se esta função for usada, você pode descobrir qual **algoritmo está sendo usado** verificando o valor do segundo parâmetro:

![](<../../images/image (156).png>)

Check here the table of possible algorithms and their assigned values: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

**RtlCompressBuffer/RtlDecompressBuffer**

Comprime e descomprime um buffer de dados fornecido.

**CryptAcquireContext**

From [the docs](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta): The **CryptAcquireContext** function is used to acquire a handle to a particular key container within a particular cryptographic service provider (CSP). **This returned handle is used in calls to CryptoAPI** functions that use the selected CSP.

**CryptCreateHash**

Inicia o hashing de um fluxo de dados. Se esta função for usada, você pode descobrir qual **algoritmo está sendo usado** verificando o valor do segundo parâmetro:

![](<../../images/image (549).png>)

\
Check here the table of possible algorithms and their assigned values: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

### Code constants

Às vezes é realmente fácil identificar um algoritmo graças ao fato de ele usar um valor especial e único.

![](<../../images/image (833).png>)

Se você pesquisar a primeira constante no Google isto é o que você obtém:

![](<../../images/image (529).png>)

Portanto, você pode assumir que a função decompilada é um **calculador de sha256.**\
Você pode procurar qualquer uma das outras constantes e provavelmente obterá o mesmo resultado.

### data info

Se o código não tem nenhuma constante significativa pode estar **carregando informação da seção .data**.\
Você pode acessar esses dados, **agrupar o primeiro dword** e pesquisá-lo no Google como fizemos na seção anterior:

![](<../../images/image (531).png>)

Neste caso, se você procurar **0xA56363C6** pode encontrar que está relacionado com as **tabelas do algoritmo AES**.

## RC4 **(Symmetric Crypt)**

### Characteristics

É composto por 3 partes principais:

- **Initialization stage/**: Cria uma **tabela de valores de 0x00 a 0xFF** (256 bytes no total, 0x100). Esta tabela é comumente chamada **Substitution Box** (ou SBox).
- **Scrambling stage**: Irá **percorrer a tabela** criada antes (loop de 0x100 iterações, novamente) modificando cada valor com bytes **semi-aleatórios**. Para criar esses bytes semi-aleatórios, a **key do RC4 é usada**. As chaves RC4 podem ter **entre 1 e 256 bytes de comprimento**, entretanto normalmente é recomendado que seja acima de 5 bytes. Comumente, as keys RC4 têm 16 bytes de comprimento.
- **XOR stage**: Finalmente, o plain-text ou ciphertext é **XORed com os valores criados antes**. A função para encriptar e decriptar é a mesma. Para isso, será feito um **loop pelos 256 bytes criados** tantas vezes quanto necessário. Isso normalmente é reconhecido em um código decompilado por um **%256 (mod 256)**.

> [!TIP]
> **Para identificar um RC4 em uma disassembly/decompiled code você pode checar por 2 loops de tamanho 0x100 (com o uso de uma key) e então um XOR dos dados de entrada com os 256 valores criados antes nos 2 loops provavelmente usando um %256 (mod 256)**

### **Initialization stage/Substitution Box:** (Note o número 256 usado como contador e como um 0 é escrito em cada posição dos 256 chars)

![](<../../images/image (584).png>)

### **Scrambling Stage:**

![](<../../images/image (835).png>)

### **XOR Stage:**

![](<../../images/image (904).png>)

## **AES (Symmetric Crypt)**

### **Characteristics**

- Uso de **substitution boxes e lookup tables**
- É possível **distinguir AES pelo uso de valores específicos de lookup tables** (constantes). _Note que a **constante** pode ser **armazenada** no binário **ou criada**_ _**dinamicamente**._
- A **encryption key** deve ser **divisível** por **16** (normalmente 32B) e geralmente um **IV** de 16B é usado.

### SBox constants

![](<../../images/image (208).png>)

## Serpent **(Symmetric Crypt)**

### Characteristics

- É raro encontrar malware usando-o, mas existem exemplos (Ursnif)
- Simples determinar se um algoritmo é Serpent ou não com base no seu tamanho (função extremamente longa)

### Identifying

Na imagem a seguir note como a constante **0x9E3779B9** é usada (note que essa constante também é usada por outros algoritmos como **TEA** - Tiny Encryption Algorithm).\
Também note o **tamanho do loop** (**132**) e o **número de operações XOR** nas instruções de **disassembly** e no exemplo de **código**:

![](<../../images/image (547).png>)

Como foi mencionado antes, este código pode ser visualizado em qualquer decompilador como uma **função muito longa** já que **não há jumps** dentro dela. O código decompilado pode parecer com o seguinte:

![](<../../images/image (513).png>)

Portanto, é possível identificar este algoritmo verificando o **magic number** e os **XORs iniciais**, vendo uma **função muito longa** e **comparando** algumas **instruções** da função longa **com uma implementação** (como o shift left por 7 e o rotate left por 22).

## RSA **(Asymmetric Crypt)**

### Characteristics

- Mais complexo que algoritmos simétricos
- Não há constantes! (implementações custom são difíceis de determinar)
- KANAL (a crypto analyzer) falha em dar pistas sobre RSA pois ele depende de constantes.

### Identifying by comparisons

![](<../../images/image (1113).png>)

- Na linha 11 (esquerda) há um `+7) >> 3` que é o mesmo que na linha 35 (direita): `+7) / 8`
- Linha 12 (esquerda) está verificando se `modulus_len < 0x040` e na linha 36 (direita) está verificando se `inputLen+11 > modulusLen`

## MD5 & SHA (hash)

### Characteristics

- 3 funções: Init, Update, Final
- Funções de inicialização semelhantes

### Identify

**Init**

Você pode identificar ambos verificando as constantes. Note que o sha_init tem 1 constante que MD5 não tem:

![](<../../images/image (406).png>)

**MD5 Transform**

Note o uso de mais constantes

![](<../../images/image (253) (1) (1).png>)

## CRC (hash)

- Menor e mais eficiente pois sua função é encontrar mudanças acidentais em dados
- Usa lookup tables (portanto você pode identificar por constantes)

### Identify

Cheque **lookup table constants**:

![](<../../images/image (508).png>)

Um algoritmo de hash CRC parece com:

![](<../../images/image (391).png>)

## APLib (Compression)

### Characteristics

- Sem constantes reconhecíveis
- Você pode tentar reescrever o algoritmo em python e procurar coisas semelhantes online

### Identify

O grafo é bastante grande:

![](<../../images/image (207) (2) (1).png>)

Cheque **3 comparações para reconhecê-lo**:

![](<../../images/image (430).png>)

## Elliptic-Curve Signature Implementation Bugs

### EdDSA scalar range enforcement (HashEdDSA malleability)

- FIPS 186-5 §7.8.2 exige que verificadores HashEdDSA dividam uma assinatura `sig = R || s` e rejeitem qualquer scalar com `s \geq n`, onde `n` é a ordem do grupo. A biblioteca `elliptic` em JS pulou essa checagem de limite, então qualquer atacante que conheça um par válido `(msg, R || s)` pode forjar assinaturas alternativas `s' = s + k·n` e continuar re-encodificando `sig' = R || s'`.
- As rotinas de verificação consomem apenas `s mod n`, portanto todos `s'` congruentes a `s` são aceitos mesmo sendo strings de bytes diferentes. Sistemas que tratam assinaturas como tokens canônicos (consenso de blockchain, caches de replay, chaves de BD, etc.) podem ser dessincronizados porque implementações estritas irão rejeitar `s'`.
- Ao auditar outro código HashEdDSA, assegure que o parser valide tanto o ponto `R` quanto o comprimento do scalar; tente acrescentar múltiplos de `n` a um `s` conhecido-bom para confirmar que o verificador falha de forma fechada.

### ECDSA truncation vs. leading-zero hashes

- Verificadores ECDSA devem usar apenas os bits mais à esquerda `log2(n)` do hash da mensagem `H`. Em `elliptic`, o helper de truncamento calculava `delta = (BN(msg).byteLength()*8) - bitlen(n)`; o construtor `BN` descarta octetos zero à esquerda, então qualquer hash que comece com ≥4 bytes zero em curvas como secp192r1 (ordem de 192 bits) aparentava ter apenas 224 bits em vez de 256.
- O verificador fez um right-shift por 32 bits em vez de 64, produzindo um `E` que não corresponde ao valor usado pelo signer. Assinaturas válidas nesses hashes portanto falham com probabilidade ≈`2^-32` para entradas SHA-256.
- Alimente tanto o vetor “all good” quanto variantes com leading-zero (por exemplo, Wycheproof `ecdsa_secp192r1_sha256_test.json` caso `tc296`) para uma implementação alvo; se o verificador discordar do signer, você encontrou um bug de truncamento explorável.

### Exercising Wycheproof vectors against libraries
- Wycheproof fornece conjuntos de testes em JSON que codificam pontos malformed, scalars maleáveis, hashes incomuns e outros corner cases. Construir um harness em torno de `elliptic` (ou qualquer crypto library) é direto: carregue o JSON, deserialize cada caso de teste, e assegure que a implementação corresponde ao `result` esperado.
```javascript
for (const tc of ecdsaVectors.testGroups) {
const curve = new EC(tc.curve);
const pub = curve.keyFromPublic(tc.key, 'hex');
const ok = curve.verify(tc.msg, tc.sig, pub, 'hex', tc.msgSize);
assert.strictEqual(ok, tc.result === 'valid');
}
```
- Falhas devem ser triadas para distinguir violações de especificação de falsos positivos. Para os dois bugs acima, os casos Wycheproof que falharam apontaram imediatamente para checagens de intervalo do escalar ausentes (EdDSA) e truncamento incorreto de hash (ECDSA).
- Integre o harness ao CI para que regressões no parsing de escalares, no tratamento de hash ou na validade de coordenadas acionem testes assim que forem introduzidas. Isso é especialmente útil para linguagens de alto nível (JS, Python, Go) onde conversões sutis de bignum são fáceis de errar.

## References

- [Trail of Bits - We found cryptography bugs in the elliptic library using Wycheproof](https://blog.trailofbits.com/2025/11/18/we-found-cryptography-bugs-in-the-elliptic-library-using-wycheproof/)
- [Wycheproof Test Suite](https://github.com/C2SP/wycheproof)

{{#include ../../banners/hacktricks-training.md}}
