# Sub-GHz RF

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Portas de Garagem

Os abridores de portas de garagem geralmente operam em frequências na faixa de 300-190 MHz, sendo as frequências mais comuns 300 MHz, 310 MHz, 315 MHz e 390 MHz. Essa faixa de frequência é comumente usada para abridores de portas de garagem porque é menos congestionada do que outras bandas de frequência e é menos propensa a sofrer interferência de outros dispositivos.

## Portas de Carros

A maioria dos controles remotos de chave de carro opera em **315 MHz ou 433 MHz**. Ambas são frequências de rádio e são usadas em uma variedade de aplicações diferentes. A principal diferença entre as duas frequências é que 433 MHz tem um alcance maior do que 315 MHz. Isso significa que 433 MHz é melhor para aplicações que requerem um alcance maior, como entrada remota sem chave.\
Na Europa, é comum o uso de 433,92 MHz e nos EUA e no Japão é o 315 MHz.

## Ataque de Força Bruta

<figure><img src="../../.gitbook/assets/image (4) (3).png" alt=""><figcaption></figcaption></figure>

Se, em vez de enviar cada código 5 vezes (enviado assim para garantir que o receptor o receba), você enviar apenas uma vez, o tempo é reduzido para 6 minutos:

<figure><img src="../../.gitbook/assets/image (1) (1) (2) (2).png" alt=""><figcaption></figcaption></figure>

e se você **remover o período de espera de 2 ms** entre os sinais, você pode **reduzir o tempo para 3 minutos**.

Além disso, usando a Sequência de De Bruijn (uma maneira de reduzir o número de bits necessários para enviar todos os números binários potenciais para força bruta), este **tempo é reduzido para apenas 8 segundos**:

<figure><img src="../../.gitbook/assets/image (5) (2) (3).png" alt=""><figcaption></figcaption></figure>

Um exemplo desse ataque foi implementado em [https://github.com/samyk/opensesame](https://github.com/samyk/opensesame)

Exigir **um preâmbulo evitará a otimização da Sequência de De Bruijn** e **códigos rolantes impedirão esse ataque** (supondo que o código seja longo o suficiente para não ser força bruta).

## Ataque Sub-GHz

Para atacar esses sinais com o Flipper Zero, verifique:

{% content-ref url="flipper-zero/fz-sub-ghz.md" %}
[fz-sub-ghz.md](flipper-zero/fz-sub-ghz.md)
{% endcontent-ref %}

## Proteção de Códigos Rolantes

Os abridores automáticos de portas de garagem geralmente
