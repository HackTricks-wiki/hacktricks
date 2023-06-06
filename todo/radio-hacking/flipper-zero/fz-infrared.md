# FZ - Infravermelho

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) **grupo do Discord** ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live).
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Introdução <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Para mais informações sobre como funciona o infravermelho, consulte:

{% content-ref url="../infrared.md" %}
[infrared.md](../infrared.md)
{% endcontent-ref %}

## Receptor de Sinal IR no Flipper Zero <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

O Flipper usa um receptor de sinal IR digital TSOP, que **permite interceptar sinais de controles remotos IR**. Existem alguns **smartphones** como o Xiaomi, que também possuem uma porta IR, mas tenha em mente que **a maioria deles só pode transmitir** sinais e são **incapazes de recebê-los**.

O receptor infravermelho do Flipper é bastante sensível. Você pode até **capturar o sinal** enquanto estiver **em algum lugar entre** o controle remoto e a TV. Apontar o controle remoto diretamente para a porta IR do Flipper é desnecessário. Isso é útil quando alguém está mudando de canal enquanto está perto da TV, e tanto você quanto o Flipper estão a alguma distância.

Como a **decodificação do sinal infravermelho** acontece no **software**, o Flipper Zero potencialmente suporta a **receção e transmissão de quaisquer códigos de controle remoto IR**. No caso de **protocolos desconhecidos** que não puderam ser reconhecidos - ele **registra e reproduz** o sinal bruto exatamente como recebido.

## Ações

### Controles Remotos Universais

O Flipper Zero pode ser usado como um **controle remoto universal para controlar qualquer TV, ar condicionado ou centro de mídia**. Nesse modo, o Flipper **força bruta** todos os **códigos conhecidos** de todos os fabricantes suportados **de acordo com o dicionário do cartão SD**. Você não precisa escolher um controle remoto específico para desligar uma TV de um restaurante.

Basta pressionar o botão de energia no modo Controle Remoto Universal, e o Flipper enviará **sequencialmente comandos "Desligar"** de todas as TVs que conhece: Sony, Samsung, Panasonic... e assim por diante. Quando a TV recebe seu sinal, ela reage e desliga.

Essa força bruta leva tempo. Quanto maior o dicionário, mais tempo levará para terminar. É impossível descobrir qual sinal exatamente a TV reconheceu, já que não há feedback da TV.

### Aprender Novo Controle Remoto

É possível **capturar um sinal infravermelho** com o Flipper Zero. Se ele **encontrar o sinal no banco de dados**, o Flipper automaticamente **saberá qual dispositivo é** e permitirá que você interaja com ele.\
Se não encontrar, o Flipper pode **armazenar** o **sinal** e permitirá que você o **reproduza**.

## Referências

* [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) **grupo do Discord** ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live).
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
