# Sub-GHz RF

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Portas de Garagem

Os abridores de portas de garagem geralmente operam em frequências na faixa de 300-190 MHz, sendo as frequências mais comuns 300 MHz, 310 MHz, 315 MHz e 390 MHz. Essa faixa de frequência é comumente usada para abridores de portas de garagem porque é menos congestionada do que outras bandas de frequência e tem menos probabilidade de sofrer interferência de outros dispositivos.

## Portas de Carro

A maioria dos controles remotos de chave de carro opera em **315 MHz ou 433 MHz**. Essas são frequências de rádio e são usadas em uma variedade de aplicações diferentes. A principal diferença entre as duas frequências é que 433 MHz tem um alcance maior do que 315 MHz. Isso significa que 433 MHz é melhor para aplicações que requerem um alcance maior, como entrada remota sem chave.\
Na Europa, é comum usar 433,92 MHz e nos EUA e no Japão é 315 MHz.

## **Ataque de Força Bruta**

<figure><img src="../../.gitbook/assets/image (4) (3) (2).png" alt=""><figcaption></figcaption></figure>

Se, em vez de enviar cada código 5 vezes (enviado dessa forma para garantir que o receptor o receba), você enviar apenas uma vez, o tempo é reduzido para 6 minutos:

<figure><img src="../../.gitbook/assets/image (1) (1) (2) (2).png" alt=""><figcaption></figcaption></figure>

e se você **remover o período de espera de 2 ms** entre os sinais, você pode **reduzir o tempo para 3 minutos**.

Além disso, usando a Sequência de De Bruijn (uma maneira de reduzir o número de bits necessários para enviar todos os números binários potenciais para força bruta), esse **tempo é reduzido para apenas 8 segundos**:

<figure><img src="../../.gitbook/assets/image (5) (2) (3).png" alt=""><figcaption></figcaption></figure>

Um exemplo desse ataque foi implementado em [https://github.com/samyk/opensesame](https://github.com/samyk/opensesame)

Exigir **um preâmbulo evitará a otimização da Sequência de De Bruijn** e **códigos rolantes impedirão esse ataque** (supondo que o código seja longo o suficiente para não ser força bruta).

## Ataque Sub-GHz

Para atacar esses sinais com o Flipper Zero, verifique:

{% content-ref url="flipper-zero/fz-sub-ghz.md" %}
[fz-sub-ghz.md](flipper-zero/fz-sub-ghz.md)
{% endcontent-ref %}

## Proteção de Códigos Rolantes

Os abridores automáticos de portas de garagem geralmente usam um controle remoto sem fio para abrir e fechar a porta da garagem. O controle remoto **envia um sinal de frequência de rádio (RF)** para o abridor da porta da garagem, que ativa o motor para abrir ou fechar a porta.

É possível para alguém usar um dispositivo conhecido como um capturador de código para interceptar o sinal de RF e gravá-lo para uso posterior. Isso é conhecido como um **ataque de repetição**. Para evitar esse tipo de ataque, muitos abridores modernos de portas de garagem usam um método de criptografia mais seguro conhecido como um sistema de **código rolante**.

O **sinal de RF é transmitido usando um código rolante**, o que significa que o código muda a cada uso. Isso torna **difícil** para alguém **interceptar** o sinal e **usá-lo** para obter acesso **não autorizado** à garagem.

Em um sistema de código rolante, o controle remoto e o abridor da porta da garagem têm um **algoritmo compartilhado** que **gera um novo código** cada vez que o controle remoto é usado. O abridor da porta da garagem só responderá ao **código correto**, tornando muito mais difícil para alguém obter acesso não autorizado à garagem apenas capturando um código.

### **Ataque de Elo Perdido**

Basicamente, você ouve o botão e **captura o sinal enquanto o controle remoto está fora do alcance** do dispositivo (digamos o carro ou a garagem). Em seguida, você se move para o dispositivo e **usa o código capturado para abri-lo**.

### Ataque de Jamming de Link Completo

Um atacante pode **interferir no sinal perto do veículo ou receptor** para que o **receptor não consiga 'ouvir' o código**, e uma vez que isso esteja acontecendo, você pode simplesmente **capturar e reproduzir** o código quando parar de interferir.

A vítima em algum momento usará as **chaves para trancar o carro**, mas então o ataque terá **gravado códigos de "fechar a porta" suficientes** que, esperançosamente, poderiam ser reenviados para abrir a porta (uma **mudança de frequência pode ser necessária**, pois existem carros que usam os mesmos códigos para abrir e fechar, mas ouvem ambos os comandos em frequências diferentes).

{% hint style="warning" %}
**O Jamming funciona**, mas é perceptível, pois se a **pessoa que tranca o carro simplesmente testar as portas** para garantir que estejam trancadas, ela perceberá que o carro está destrancado. Além disso, se estiverem cientes de tais ataques, eles podem até ouvir o fato de que as portas não fizeram o **som** de travamento ou as **luzes** do carro não piscaram quando pressionaram o botão 'travar'.
{% endhint %}
### **Ataque de Captura de Código (também conhecido como 'RollJam')**

Este é uma técnica de **interferência mais furtiva**. O atacante irá interferir no sinal, de modo que quando a vítima tente trancar a porta, não funcione, mas o atacante irá **gravar esse código**. Em seguida, a vítima irá **tentar trancar o carro novamente** pressionando o botão e o carro irá **gravar esse segundo código**.\
Imediatamente após isso, o **atacante pode enviar o primeiro código** e o **carro irá trancar** (a vítima pensará que a segunda pressão o fechou). Em seguida, o atacante será capaz de **enviar o segundo código roubado para abrir** o carro (supondo que um **código de "fechar carro" também possa ser usado para abri-lo**). Uma mudança de frequência pode ser necessária (pois existem carros que usam os mesmos códigos para abrir e fechar, mas escutam ambos os comandos em frequências diferentes).

O atacante pode **interferir no receptor do carro e não no seu receptor** porque se o receptor do carro estiver escutando, por exemplo, em uma banda larga de 1MHz, o atacante não irá **interferir** na frequência exata usada pelo controle remoto, mas sim **em uma próxima nesse espectro**, enquanto o **receptor do atacante estará escutando em uma faixa menor** onde ele pode escutar o sinal do controle remoto **sem o sinal de interferência**.

{% hint style="warning" %}
Outras implementações vistas em especificações mostram que o **código rolante é uma parte** do código total enviado. Ou seja, o código enviado é uma **chave de 24 bits**, onde os primeiros **12 são o código rolante**, os **segundos 8 são o comando** (como trancar ou destrancar) e os últimos 4 são o **checksum**. Veículos que implementam esse tipo também são naturalmente suscetíveis, pois o atacante só precisa substituir o segmento do código rolante para poder **usar qualquer código rolante em ambas as frequências**.
{% endhint %}

{% hint style="danger" %}
Observe que se a vítima enviar um terceiro código enquanto o atacante estiver enviando o primeiro, o primeiro e o segundo código serão invalidados.
{% endhint %}

### Ataque de Interferência com Alarme Sonoro

Testando contra um sistema de código rolante de mercado instalado em um carro, **enviar o mesmo código duas vezes** imediatamente **ativou o alarme** e o imobilizador, proporcionando uma oportunidade única de **negação de serviço**. Ironicamente, a forma de **desativar o alarme** e o imobilizador era **pressionar** o **controle remoto**, fornecendo ao atacante a capacidade de **realizar continuamente um ataque de negação de serviço**. Ou misturar esse ataque com o **anterior para obter mais códigos**, já que a vítima gostaria de interromper o ataque o mais rápido possível.

## Referências

* [https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/](https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/)
* [https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
* [https://samy.pl/defcon2015/](https://samy.pl/defcon2015/)
* [https://hackaday.io/project/164566-how-to-hack-a-car/details](https://hackaday.io/project/164566-how-to-hack-a-car/details)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Gostaria de ver sua **empresa anunciada no HackTricks**? Ou gostaria de ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
