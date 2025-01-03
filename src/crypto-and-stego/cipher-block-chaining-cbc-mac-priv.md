{{#include ../banners/hacktricks-training.md}}

# CBC

Se o **cookie** for **apenas** o **nome de usuário** (ou a primeira parte do cookie for o nome de usuário) e você quiser se passar pelo nome de usuário "**admin**". Então, você pode criar o nome de usuário **"bdmin"** e **bruteforçar** o **primeiro byte** do cookie.

# CBC-MAC

**Código de autenticação de mensagem em encadeamento de bloco** (**CBC-MAC**) é um método usado em criptografia. Funciona pegando uma mensagem e criptografando-a bloco por bloco, onde a criptografia de cada bloco está vinculada à anterior. Esse processo cria uma **cadeia de blocos**, garantindo que mudar até mesmo um único bit da mensagem original levará a uma mudança imprevisível no último bloco de dados criptografados. Para fazer ou reverter tal mudança, a chave de criptografia é necessária, garantindo segurança.

Para calcular o CBC-MAC da mensagem m, criptografa-se m em modo CBC com vetor de inicialização zero e mantém-se o último bloco. A figura a seguir esboça o cálculo do CBC-MAC de uma mensagem composta por blocos![https://wikimedia.org/api/rest_v1/media/math/render/svg/bbafe7330a5e40a04f01cc776c9d94fe914b17f5](https://wikimedia.org/api/rest_v1/media/math/render/svg/bbafe7330a5e40a04f01cc776c9d94fe914b17f5) usando uma chave secreta k e um cifrador de bloco E:

![https://upload.wikimedia.org/wikipedia/commons/thumb/b/bf/CBC-MAC_structure_(en).svg/570px-CBC-MAC_structure_(en).svg.png](<https://upload.wikimedia.org/wikipedia/commons/thumb/b/bf/CBC-MAC_structure_(en).svg/570px-CBC-MAC_structure_(en).svg.png>)

# Vulnerabilidade

Com o CBC-MAC, geralmente o **IV usado é 0**.\
Isso é um problema porque 2 mensagens conhecidas (`m1` e `m2`) independentemente gerarão 2 assinaturas (`s1` e `s2`). Então:

- `E(m1 XOR 0) = s1`
- `E(m2 XOR 0) = s2`

Então, uma mensagem composta por m1 e m2 concatenados (m3) gerará 2 assinaturas (s31 e s32):

- `E(m1 XOR 0) = s31 = s1`
- `E(m2 XOR s1) = s32`

**O que é possível calcular sem conhecer a chave da criptografia.**

Imagine que você está criptografando o nome **Administrator** em blocos de **8bytes**:

- `Administ`
- `rator\00\00\00`

Você pode criar um nome de usuário chamado **Administ** (m1) e recuperar a assinatura (s1).\
Então, você pode criar um nome de usuário chamado o resultado de `rator\00\00\00 XOR s1`. Isso gerará `E(m2 XOR s1 XOR 0)` que é s32.\
Agora, você pode usar s32 como a assinatura do nome completo **Administrator**.

### Resumo

1. Obtenha a assinatura do nome de usuário **Administ** (m1) que é s1
2. Obtenha a assinatura do nome de usuário **rator\x00\x00\x00 XOR s1 XOR 0** que é s32**.**
3. Defina o cookie para s32 e será um cookie válido para o usuário **Administrator**.

# Ataque Controlando IV

Se você puder controlar o IV usado, o ataque pode ser muito fácil.\
Se os cookies forem apenas o nome de usuário criptografado, para se passar pelo usuário "**administrator**" você pode criar o usuário "**Administrator**" e obter seu cookie.\
Agora, se você puder controlar o IV, pode mudar o primeiro byte do IV para que **IV\[0] XOR "A" == IV'\[0] XOR "a"** e regenerar o cookie para o usuário **Administrator.** Este cookie será válido para **se passar** pelo usuário **administrator** com o **IV** inicial.

## Referências

Mais informações em [https://en.wikipedia.org/wiki/CBC-MAC](https://en.wikipedia.org/wiki/CBC-MAC)

{{#include ../banners/hacktricks-training.md}}
