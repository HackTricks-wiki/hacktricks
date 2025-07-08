# Algoritmos Criptográficos/Compressão

{{#include ../../banners/hacktricks-training.md}}

## Identificando Algoritmos

Se você se deparar com um código **usando deslocamentos à direita e à esquerda, xors e várias operações aritméticas**, é altamente provável que seja a implementação de um **algoritmo criptográfico**. Aqui serão mostradas algumas maneiras de **identificar o algoritmo que está sendo usado sem precisar reverter cada passo**.

### Funções da API

**CryptDeriveKey**

Se esta função for usada, você pode descobrir qual **algoritmo está sendo usado** verificando o valor do segundo parâmetro:

![](<../../images/image (375) (1) (1) (1) (1).png>)

Verifique aqui a tabela de possíveis algoritmos e seus valores atribuídos: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

**RtlCompressBuffer/RtlDecompressBuffer**

Comprime e descomprime um determinado buffer de dados.

**CryptAcquireContext**

Dos [docs](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta): A função **CryptAcquireContext** é usada para adquirir um identificador para um determinado contêiner de chaves dentro de um determinado provedor de serviços criptográficos (CSP). **Este identificador retornado é usado em chamadas para funções da CryptoAPI** que utilizam o CSP selecionado.

**CryptCreateHash**

Inicia a hash de um fluxo de dados. Se esta função for usada, você pode descobrir qual **algoritmo está sendo usado** verificando o valor do segundo parâmetro:

![](<../../images/image (376).png>)

\
Verifique aqui a tabela de possíveis algoritmos e seus valores atribuídos: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

### Constantes de Código

Às vezes, é realmente fácil identificar um algoritmo graças ao fato de que ele precisa usar um valor especial e único.

![](<../../images/image (370).png>)

Se você pesquisar a primeira constante no Google, isso é o que você obtém:

![](<../../images/image (371).png>)

Portanto, você pode assumir que a função decompilada é um **calculador de sha256.**\
Você pode pesquisar qualquer uma das outras constantes e provavelmente obterá o mesmo resultado.

### Informações de dados

Se o código não tiver nenhuma constante significativa, pode estar **carregando informações da seção .data**.\
Você pode acessar esses dados, **agrupar o primeiro dword** e pesquisar no Google como fizemos na seção anterior:

![](<../../images/image (372).png>)

Neste caso, se você procurar **0xA56363C6**, pode descobrir que está relacionado às **tabelas do algoritmo AES**.

## RC4 **(Criptografia Simétrica)**

### Características

É composto por 3 partes principais:

- **Estágio de Inicialização/**: Cria uma **tabela de valores de 0x00 a 0xFF** (256 bytes no total, 0x100). Esta tabela é comumente chamada de **Caixa de Substituição** (ou SBox).
- **Estágio de Embaralhamento**: Irá **percorrer a tabela** criada anteriormente (loop de 0x100 iterações, novamente) modificando cada valor com bytes **semi-aleatórios**. Para criar esses bytes semi-aleatórios, a **chave RC4 é usada**. As **chaves RC4** podem ter **entre 1 e 256 bytes de comprimento**, no entanto, geralmente é recomendado que sejam superiores a 5 bytes. Comumente, as chaves RC4 têm 16 bytes de comprimento.
- **Estágio XOR**: Finalmente, o texto simples ou o texto cifrado é **XORed com os valores criados anteriormente**. A função para criptografar e descriptografar é a mesma. Para isso, um **loop pelos 256 bytes criados** será realizado quantas vezes forem necessárias. Isso geralmente é reconhecido em um código decompilado com um **%256 (mod 256)**.

> [!TIP]
> **Para identificar um RC4 em um código desassemblado/decompilado, você pode verificar 2 loops de tamanho 0x100 (com o uso de uma chave) e, em seguida, um XOR dos dados de entrada com os 256 valores criados anteriormente nos 2 loops, provavelmente usando um %256 (mod 256)**

### **Estágio de Inicialização/Caixa de Substituição:** (Note o número 256 usado como contador e como um 0 é escrito em cada lugar dos 256 caracteres)

![](<../../images/image (377).png>)

### **Estágio de Embaralhamento:**

![](<../../images/image (378).png>)

### **Estágio XOR:**

![](<../../images/image (379).png>)

## **AES (Criptografia Simétrica)**

### **Características**

- Uso de **caixas de substituição e tabelas de consulta**
- É possível **distinguir o AES graças ao uso de valores específicos de tabela de consulta** (constantes). _Note que a **constante** pode ser **armazenada** no binário **ou criada** _**dinamicamente**._
- A **chave de criptografia** deve ser **divisível** por **16** (geralmente 32B) e geralmente é usado um **IV** de 16B.

### Constantes SBox

![](<../../images/image (380).png>)

## Serpent **(Criptografia Simétrica)**

### Características

- É raro encontrar algum malware usando, mas há exemplos (Ursnif)
- Simples de determinar se um algoritmo é Serpent ou não com base em seu comprimento (função extremamente longa)

### Identificação

Na imagem a seguir, note como a constante **0x9E3779B9** é usada (note que esta constante também é usada por outros algoritmos criptográficos como **TEA** -Tiny Encryption Algorithm).\
Também note o **tamanho do loop** (**132**) e o **número de operações XOR** nas instruções de **desmontagem** e no **exemplo de código**:

![](<../../images/image (381).png>)

Como mencionado anteriormente, este código pode ser visualizado dentro de qualquer decompilador como uma **função muito longa**, pois **não há saltos** dentro dele. O código decompilado pode parecer o seguinte:

![](<../../images/image (382).png>)

Portanto, é possível identificar este algoritmo verificando o **número mágico** e os **XORs iniciais**, vendo uma **função muito longa** e **comparando** algumas **instruções** da longa função **com uma implementação** (como o deslocamento à esquerda por 7 e a rotação à esquerda por 22).

## RSA **(Criptografia Assimétrica)**

### Características

- Mais complexo do que algoritmos simétricos
- Não há constantes! (implementações personalizadas são difíceis de determinar)
- KANAL (um analisador criptográfico) falha em mostrar dicas sobre RSA, pois depende de constantes.

### Identificação por comparações

![](<../../images/image (383).png>)

- Na linha 11 (esquerda) há um `+7) >> 3` que é o mesmo que na linha 35 (direita): `+7) / 8`
- A linha 12 (esquerda) está verificando se `modulus_len < 0x040` e na linha 36 (direita) está verificando se `inputLen+11 > modulusLen`

## MD5 & SHA (hash)

### Características

- 3 funções: Init, Update, Final
- Funções de inicialização semelhantes

### Identificar

**Init**

Você pode identificar ambos verificando as constantes. Note que o sha_init tem 1 constante que o MD5 não tem:

![](<../../images/image (385).png>)

**Transformação MD5**

Note o uso de mais constantes

![](<../../images/image (253) (1) (1) (1).png>)

## CRC (hash)

- Menor e mais eficiente, pois sua função é encontrar mudanças acidentais nos dados
- Usa tabelas de consulta (então você pode identificar constantes)

### Identificar

Verifique **constantes da tabela de consulta**:

![](<../../images/image (387).png>)

Um algoritmo de hash CRC se parece com:

![](<../../images/image (386).png>)

## APLib (Compressão)

### Características

- Constantes não reconhecíveis
- Você pode tentar escrever o algoritmo em python e procurar por coisas semelhantes online

### Identificar

O gráfico é bastante grande:

![](<../../images/image (207) (2) (1).png>)

Verifique **3 comparações para reconhecê-lo**:

![](<../../images/image (384).png>)

{{#include ../../banners/hacktricks-training.md}}
