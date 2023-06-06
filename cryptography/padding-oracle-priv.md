# CBC - Cipher Block Chaining

No modo CBC, o **bloco criptografado anterior é usado como IV** para fazer XOR com o próximo bloco:

![CBC encryption](https://defuse.ca/images/cbc\_encryption.png)

Para descriptografar o CBC, as **operações opostas** são feitas:

![CBC decryption](https://defuse.ca/images/cbc\_decryption.png)

Observe que é necessário usar uma **chave de criptografia** e um **IV**.

# Preenchimento de Mensagem

Como a criptografia é realizada em **blocos de tamanho fixo**, geralmente é necessário um **preenchimento** no **último bloco** para completar seu comprimento.\
Geralmente, é usado o **PKCS7**, que gera um preenchimento **repetindo** o **número** de **bytes necessários** para **completar** o bloco. Por exemplo, se o último bloco estiver faltando 3 bytes, o preenchimento será `\x03\x03\x03`.

Vamos ver mais exemplos com **2 blocos de comprimento 8 bytes**:

| byte #0 | byte #1 | byte #2 | byte #3 | byte #4 | byte #5 | byte #6 | byte #7 | byte #0  | byte #1  | byte #2  | byte #3  | byte #4  | byte #5  | byte #6  | byte #7  |
| ------- | ------- | ------- | ------- | ------- | ------- | ------- | ------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | 6        | **0x02** | **0x02** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | **0x03** | **0x03** | **0x03** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | **0x05** | **0x05** | **0x05** | **0x05** | **0x05** |
| P       | A       | S       | S       | W       | O       | R       | D       | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** |

Observe como no último exemplo o **último bloco estava cheio, então outro foi gerado apenas com preenchimento**.

# Oracle de Preenchimento

Quando um aplicativo descriptografa dados criptografados, ele primeiro descriptografa os dados; em seguida, ele remove o preenchimento. Durante a limpeza do preenchimento, se um **preenchimento inválido desencadear um comportamento detectável**, você tem uma **vulnerabilidade de oracle de preenchimento**. O comportamento detectável pode ser um **erro**, uma **falta de resultados** ou uma **resposta mais lenta**.

Se você detectar esse comportamento, poderá **descriptografar os dados criptografados** e até mesmo **criptografar qualquer texto claro**.

## Como explorar

Você pode usar [https://github.com/AonCyberLabs/PadBuster](https://github.com/AonCyberLabs/PadBuster) para explorar esse tipo de vulnerabilidade ou apenas fazer
```
sudo apt-get install padbuster
```
Para testar se o cookie de um site é vulnerável, você pode tentar:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
**Codificação 0** significa que **base64** é usado (mas outros estão disponíveis, verifique o menu de ajuda).

Você também pode **abusar dessa vulnerabilidade para criptografar novos dados. Por exemplo, imagine que o conteúdo do cookie é "**_**user=MyUsername**_**", então você pode alterá-lo para "\_user=administrator\_" e escalar privilégios dentro da aplicação. Você também pode fazer isso usando `padbuster` especificando o parâmetro -plaintext**.
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA==" -plaintext "user=administrator"
```
Se o site for vulnerável, o `padbuster` tentará automaticamente encontrar quando ocorre o erro de preenchimento, mas você também pode indicar a mensagem de erro usando o parâmetro **-error**.
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "" 8 -encoding 0 -cookies "hcon=RVJDQrwUdTRWJUVUeBKkEA==" -error "Invalid padding"
```
## A teoria

Em resumo, você pode começar a descriptografar os dados criptografados adivinhando os valores corretos que podem ser usados para criar todos os **diferentes preenchimentos**. Em seguida, o ataque de oráculo de preenchimento começará a descriptografar bytes do final para o início, adivinhando qual será o valor correto que **cria um preenchimento de 1, 2, 3, etc**.

![](<../.gitbook/assets/image (629) (1) (1).png>)

Imagine que você tenha algum texto criptografado que ocupa **2 blocos** formados pelos bytes de **E0 a E15**.\
Para **descriptografar** o **último** **bloco** (**E8** a **E15**), todo o bloco passa pelo "descriptografador de cifra de bloco" gerando os **bytes intermediários I0 a I15**.\
Finalmente, cada byte intermediário é **XORed** com os bytes criptografados anteriores (E0 a E7). Então:

* `C15 = D(E15) ^ E7 = I15 ^ E7`
* `C14 = I14 ^ E6`
* `C13 = I13 ^ E5`
* `C12 = I12 ^ E4`
* ...

Agora, é possível **modificar `E7` até que `C15` seja `0x01`**, que também será um preenchimento correto. Então, neste caso: `\x01 = I15 ^ E'7`

Portanto, encontrando E'7, é possível calcular I15: `I15 = 0x01 ^ E'7`

O que nos permite **calcular C15**: `C15 = E7 ^ I15 = E7 ^ \x01 ^ E'7`

Conhecendo **C15**, agora é possível **calcular C14**, mas desta vez forçando o preenchimento `\x02\x02`.

Este BF é tão complexo quanto o anterior, pois é possível calcular o `E''15` cujo valor é 0x02: `E''7 = \x02 ^ I15`, então é necessário encontrar o **`E'14`** que gera um **`C14` igual a `0x02`**.\
Em seguida, faça os mesmos passos para descriptografar C14: **`C14 = E6 ^ I14 = E6 ^ \x02 ^ E''6`**

**Siga esta cadeia até descriptografar todo o texto criptografado.**

## Detecção da vulnerabilidade

Registre uma conta e faça login com esta conta.\
Se você **fizer login muitas vezes** e sempre receber o **mesmo cookie**, provavelmente há **algo errado** na aplicação. O **cookie enviado de volta deve ser único** cada vez que você fizer login. Se o cookie for **sempre** o **mesmo**, provavelmente sempre será válido e não haverá como invalidá-lo.

Agora, se você tentar **modificar** o **cookie**, poderá ver que recebe um **erro** da aplicação.\
Mas se você usar o padbuster para forçar o preenchimento, poderá obter outro cookie válido para um usuário diferente. Este cenário é altamente vulnerável ao padbuster.

# Referências

* [https://en.wikipedia.org/wiki/Block\_cipher\_mode\_of\_operation](https://en.wikipedia.org/wiki/Block\_cipher\_mode\_of\_operation)


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!

- Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)

- **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Compartilhe suas técnicas de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
