# ECB

(ECB) Livro de Códigos Eletrônico - esquema de criptografia simétrica que **substitui cada bloco do texto claro** pelo **bloco de texto cifrado**. É o esquema de criptografia **mais simples**. A ideia principal é **dividir** o texto claro em **blocos de N bits** (depende do tamanho do bloco de dados de entrada, algoritmo de criptografia) e, em seguida, criptografar (descriptografar) cada bloco de texto claro usando a única chave.

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

Usar ECB tem várias implicações de segurança:

* **Blocos da mensagem criptografada podem ser removidos**
* **Blocos da mensagem criptografada podem ser movidos**

# Detecção da vulnerabilidade

Imagine que você faz login em um aplicativo várias vezes e sempre recebe o mesmo cookie. Isso ocorre porque o cookie do aplicativo é **`<nome de usuário>|<senha>`**.\
Em seguida, você gera dois novos usuários, ambos com a **mesma senha longa** e **quase** o **mesmo nome de usuário**.\
Você descobre que os **blocos de 8B** onde a **informação de ambos os usuários** é a mesma são **iguais**. Então, você imagina que isso pode ser porque o **ECB está sendo usado**.

Como no exemplo a seguir. Observe como esses **2 cookies decodificados** têm várias vezes o bloco **`\x23U\xE45K\xCB\x21\xC8`**.
```
\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8\x04\xB6\xE1H\xD1\x1E \xB6\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8+=\xD4F\xF7\x99\xD9\xA9

\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8\x04\xB6\xE1H\xD1\x1E \xB6\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8+=\xD4F\xF7\x99\xD9\xA9
```
Isso ocorre porque o **nome de usuário e a senha desses cookies continham várias vezes a letra "a"** (por exemplo). Os **blocos** que são **diferentes** são blocos que continham **pelo menos 1 caractere diferente** (talvez o delimitador "|" ou alguma diferença necessária no nome de usuário).

Agora, o atacante só precisa descobrir se o formato é `<nome de usuário><delimitador><senha>` ou `<senha><delimitador><nome de usuário>`. Para fazer isso, ele pode simplesmente **gerar vários nomes de usuário** com **nomes de usuário e senhas semelhantes e longos** até encontrar o formato e o comprimento do delimitador:

| Comprimento do nome de usuário: | Comprimento da senha: | Comprimento do nome de usuário+senha: | Comprimento do cookie (após decodificação): |
| ------------------------------- | --------------------- | -------------------------------------- | ------------------------------------------ |
| 2                               | 2                     | 4                                      | 8                                          |
| 3                               | 3                     | 6                                      | 8                                          |
| 3                               | 4                     | 7                                      | 8                                          |
| 4                               | 4                     | 8                                      | 16                                         |
| 7                               | 7                     | 14                                     | 16                                         |

# Exploração da vulnerabilidade

## Removendo blocos inteiros

Sabendo o formato do cookie (`<nome de usuário>|<senha>`), para se passar pelo nome de usuário `admin`, crie um novo usuário chamado `aaaaaaaaadmin` e obtenha o cookie e decodifique-o:
```
\x23U\xE45K\xCB\x21\xC8\xE0Vd8oE\x123\aO\x43T\x32\xD5U\xD4
```
Podemos ver o padrão `\x23U\xE45K\xCB\x21\xC8` criado anteriormente com o nome de usuário que continha apenas `a`.\
Então, você pode remover o primeiro bloco de 8B e obterá um cookie válido para o nome de usuário `admin`:
```
\xE0Vd8oE\x123\aO\x43T\x32\xD5U\xD4
```
## Movendo blocos

Em muitos bancos de dados, é a mesma coisa procurar por `WHERE username='admin';` ou por `WHERE username='admin    ';` _(Note os espaços extras)_

Então, outra maneira de se passar pelo usuário `admin` seria:

* Gerar um nome de usuário que: `len(<username>) + len(<delimiter) % len(block)`. Com um tamanho de bloco de `8B`, você pode gerar um nome de usuário chamado: `username       `, com o delimitador `|` o pedaço `<username><delimiter>` gerará 2 blocos de 8Bs.
* Em seguida, gere uma senha que preencha um número exato de blocos contendo o nome de usuário que queremos passar e espaços, como: `admin   ` 

O cookie deste usuário será composto por 3 blocos: os primeiros 2 são os blocos do nome de usuário + delimitador e o terceiro é da senha (que está fingindo ser o nome de usuário): `username       |admin   `

** Então, basta substituir o primeiro bloco pelo último e estaremos passando pelo usuário `admin`: `admin          |username`**

# Referências

* [http://cryptowiki.net/index.php?title=Electronic_Code_Book\_(ECB)](http://cryptowiki.net/index.php?title=Electronic_Code_Book_\(ECB\))


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!

- Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)

- **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Compartilhe suas técnicas de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
