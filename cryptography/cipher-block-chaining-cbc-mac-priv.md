# CBC

Se o **cookie** for **apenas** o **nome de usuário** (ou a primeira parte do cookie for o nome de usuário) e você quiser se passar pelo nome de usuário "**admin**". Então, você pode criar o nome de usuário **"bdmin"** e **forçar** o **primeiro byte** do cookie.

# CBC-MAC

Na criptografia, um **código de autenticação de mensagem de cadeia de blocos cifrada** (**CBC-MAC**) é uma técnica para construir um código de autenticação de mensagem a partir de um cifrador de bloco. A mensagem é criptografada com algum algoritmo de cifra de bloco no modo CBC para criar uma **cadeia de blocos de forma que cada bloco dependa da criptografia adequada do bloco anterior**. Essa interdependência garante que uma **alteração** em **qualquer** dos **bits** do texto simples fará com que o **último bloco criptografado** mude de uma maneira que não pode ser prevista ou neutralizada sem conhecer a chave do cifrador de bloco.

Para calcular o CBC-MAC da mensagem m, criptografa-se m no modo CBC com vetor de inicialização zero e mantém-se o último bloco. A figura a seguir esboça o cálculo do CBC-MAC de uma mensagem composta por blocos![m\_{1}\\|m\_{2}\\|\cdots \\|m\_{x}](https://wikimedia.org/api/rest\_v1/media/math/render/svg/bbafe7330a5e40a04f01cc776c9d94fe914b17f5) usando uma chave secreta k e um cifrador de bloco E:

![CBC-MAC structure (en).svg](https://upload.wikimedia.org/wikipedia/commons/thumb/b/bf/CBC-MAC\_structure\_\(en\).svg/570px-CBC-MAC\_structure\_\(en\).svg.png)

# Vulnerabilidade

Com o CBC-MAC, geralmente o **IV usado é 0**.\
Isso é um problema porque 2 mensagens conhecidas (`m1` e `m2`) independentemente gerarão 2 assinaturas (`s1` e `s2`). Então:

* `E(m1 XOR 0) = s1`
* `E(m2 XOR 0) = s2`

Então, uma mensagem composta por m1 e m2 concatenados (m3) gerará 2 assinaturas (s31 e s32):

* `E(m1 XOR 0) = s31 = s1`
* `E(m2 XOR s1) = s32`

**O que é possível calcular sem conhecer a chave da criptografia.**

Imagine que você está criptografando o nome **Administrador** em blocos de **8 bytes**:

* `Administ`
* `rator\00\00\00`

Você pode criar um nome de usuário chamado **Administ** (m1) e recuperar a assinatura (s1).\
Então, você pode criar um nome de usuário chamado o resultado de `rator\00\00\00 XOR s1`. Isso gerará `E(m2 XOR s1 XOR 0)` que é s32.\
agora, você pode usar s32 como a assinatura do nome completo **Administrador**.

### Resumo

1. Obtenha a assinatura do nome de usuário **Administ** (m1), que é s1
2. Obtenha a assinatura do nome de usuário **rator\x00\x00\x00 XOR s1 XOR 0** é s32**.**
3. Defina o cookie como s32 e ele será um cookie válido para o usuário **Administrador**.

# Ataque controlando o IV

Se você pode controlar o IV usado, o ataque pode ser muito fácil.\
Se o cookie for apenas o nome de usuário criptografado, para se passar pelo usuário "**administrador**", você pode criar o usuário "**Administrator**" e obterá o cookie dele.\
Agora, se você pode controlar o IV, pode alterar o primeiro byte do IV para que **IV\[0] XOR "A" == IV'\[0] XOR "a"** e regenerar o cookie para o usuário **Administrator**. Este cookie será válido para **se passar** pelo usuário **administrador** com o IV inicial.

# Referências

Mais informações em [https://en.wikipedia.org/wiki/CBC-MAC](https://en.wikipedia.org/wiki/CBC-MAC)
