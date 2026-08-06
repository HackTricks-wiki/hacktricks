# Sub-GHz RF

{{#include ../../banners/hacktricks-training.md}}

## Portas de Garagem

Os abridores de portas de garagem normalmente operam na faixa de 300 a 190 MHz, sendo as frequências mais comuns 300 MHz, 310 MHz, 315 MHz e 390 MHz. Essa faixa de frequência é comumente usada por abridores de portas de garagem porque é menos congestionada do que outras bandas de frequência e tem menor probabilidade de sofrer interferência de outros dispositivos.

## Portas de Carros

A maioria dos key fobs de carros opera em **315 MHz ou 433 MHz**. Ambas são radiofrequências e são usadas em diversas aplicações. A principal diferença entre as duas frequências é que 433 MHz tem um alcance maior do que 315 MHz. Isso significa que 433 MHz é melhor para aplicações que exigem um alcance maior, como entrada remota sem chave.\
Na Europa, 433,92 MHz é comumente usado, enquanto nos EUA e no Japão usa-se 315 MHz.<sup>[[1]](#references)</sup>

## **Brute-force Attack**

<figure><img src="../../images/image (1084).png" alt=""><figcaption></figcaption></figure>

Se, em vez de enviar cada código 5 vezes (enviado dessa forma para garantir que o receptor o receba), ele for enviado apenas uma vez, o tempo será reduzido para 6 minutos:

<figure><img src="../../images/image (622).png" alt=""><figcaption></figcaption></figure>

e, se você **remover o período de espera de 2 ms** entre os sinais, poderá **reduzir o tempo para 3 minutos.**

Além disso, usando a De Bruijn Sequence (uma forma de reduzir o número de bits necessários para enviar todos os possíveis números binários a fim de realizar brute-force), esse **tempo é reduzido para apenas 8 segundos**:<sup>[[3]](#references)</sup>

<figure><img src="../../images/image (583).png" alt=""><figcaption></figcaption></figure>

Um exemplo desse ataque foi implementado em [https://github.com/samyk/opensesame](https://github.com/samyk/opensesame)

Exigir **um preâmbulo evitará a otimização da De Bruijn Sequence**, e **rolling codes impedirão esse ataque** (supondo que o código seja longo o suficiente para não ser possível realizar brute-force).

## Sub-GHz Attack

Para atacar esses sinais com o Flipper Zero, verifique:


{{#ref}}
flipper-zero/fz-sub-ghz.md
{{#endref}}

## Proteção por Rolling Codes

Os abridores automáticos de portas de garagem normalmente usam um controle remoto sem fio para abrir e fechar a porta da garagem. O controle remoto **envia um sinal de radiofrequência (RF)** ao abridor da porta da garagem, que ativa o motor para abrir ou fechar a porta.

É possível que alguém use um dispositivo conhecido como code grabber para interceptar o sinal RF e gravá-lo para uso posterior. Isso é conhecido como **replay attack**. Para evitar esse tipo de ataque, muitos abridores modernos de portas de garagem usam um método de criptografia mais seguro, conhecido como sistema de **rolling code**.

O **sinal RF normalmente é transmitido usando um rolling code**, o que significa que o código muda a cada uso. Isso torna **difícil** para alguém **interceptar** o sinal e **usá-lo** para obter acesso **não autorizado** à garagem.

Em um sistema de rolling code, o controle remoto e o abridor da porta da garagem possuem um **algoritmo compartilhado** que **gera um novo código** sempre que o controle remoto é usado. O abridor da porta da garagem responderá apenas ao **código correto**, tornando muito mais difícil que alguém obtenha acesso não autorizado à garagem simplesmente capturando um código.

### **Missing Link Attack**

Basicamente, você escuta o botão e **captura o sinal enquanto o controle remoto está fora do alcance** do dispositivo (por exemplo, do carro ou da garagem). Em seguida, você se aproxima do dispositivo e **usa o código capturado para abri-lo**.<sup>[[2]](#references)</sup>

### Full Link Jamming Attack

Um atacante poderia **bloquear o sinal próximo ao veículo ou ao recepto**r, de modo que o **receptor não consiga realmente “ouvir” o código** e, quando isso estiver acontecendo, basta **capturar e reproduzir** o código depois que você parar o jamming.<sup>[[2]](#references)</sup>

Em algum momento, a vítima usará as **chaves para trancar o carro**, mas o ataque terá **gravado códigos de “fechar a porta” suficientes** que, com sorte, poderão ser reenviados para abrir a porta (pode ser necessária uma **mudança de frequência**, pois há carros que usam os mesmos códigos para abrir e fechar, mas escutam ambos os comandos em frequências diferentes).

> [!WARNING]
> **Jamming funciona**, mas é perceptível, pois, se a **pessoa que está trancando o carro simplesmente testar as portas** para garantir que estão trancadas, perceberá que o carro está destrancado. Além disso, se tiver conhecimento desses ataques, ela poderá até perceber que as portas nunca emitiram o **som de travamento** ou que as **luzes do carro** nunca piscaram ao pressionar o botão de “travar”.

### **Code Grabbing Attack ( aka ‘RollJam’ )**

Essa é uma técnica de **Jamming mais furtiva**. O atacante bloqueará o sinal, de modo que, quando a vítima tentar trancar a porta, isso não funcionará, mas o atacante **gravará esse código**. Em seguida, a vítima **tentará trancar o carro novamente**, pressionando o botão, e o carro **gravará esse segundo código**.<sup>[[2]](#references)[[4]](#references)</sup>\
Imediatamente depois disso, o **atacante poderá enviar o primeiro código** e o **carro será trancado** (a vítima pensará que o segundo pressionamento o trancou). Então, o atacante poderá **enviar o segundo código roubado para abrir** o carro (supondo que um **código de “fechar o carro” também possa ser usado para abri-lo**). Pode ser necessária uma mudança de frequência (pois há carros que usam os mesmos códigos para abrir e fechar, mas escutam ambos os comandos em frequências diferentes).

O atacante pode **bloquear o receptor do carro, mas não o próprio receptor**, pois, se o receptor do carro estiver escutando, por exemplo, uma banda larga de 1 MHz, o atacante não **bloqueará** a frequência exata usada pelo controle remoto, mas **uma frequência próxima nesse espectro**, enquanto o receptor do **atacante ficará escutando em uma faixa menor**, na qual poderá escutar o sinal do controle remoto **sem o sinal de jamming**.

> [!WARNING]
> Outras implementações observadas em especificações mostram que o **rolling code é apenas uma parte** do código total enviado. Ou seja, o código enviado é uma **chave de 24 bits**, em que os primeiros **12 bits são o rolling code**, os **8 seguintes são o comando** (como travar ou destravar) e os 4 últimos são o **checksum**. Veículos que implementam esse tipo também são naturalmente suscetíveis, pois o atacante só precisa substituir o segmento do rolling code para conseguir **usar qualquer rolling code em ambas as frequências**.

> [!CAUTION]
> Observe que, se a vítima enviar um terceiro código enquanto o atacante estiver enviando o primeiro, o primeiro e o segundo códigos serão invalidados.

### Alarm Sounding Jamming Attack

Ao testar um sistema de rolling code instalado posteriormente em um carro, **enviar o mesmo código duas vezes** ativou imediatamente o alarme e o imobilizador, proporcionando uma oportunidade única de **denial of service**. Ironicamente, o meio de **desativar o alarme** e o imobilizador era **pressionar** o **controle remoto**, proporcionando ao atacante a capacidade de **realizar continuamente um ataque de DoS**. Ou combinar esse ataque com o **anterior para obter mais códigos**, pois a vítima tentaria interromper o ataque o mais rápido possível.<sup>[[2]](#references)</sup>

## Referências

- [1] [What Radio Frequency Does Car Key Fobs Run On?](https://www.americanradioarchives.com/what-radio-frequency-do-car-key-fobs-run-on/)
- [2] [Bypassing Rolling Code Systems - Andrew Mohawk](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
- [3] [Samy Kamkar - DEF CON 23: Drive It Like You Hacked It (OpenSesame)](https://samy.pl/defcon2015/)
- [4] [How To Hack A Car - RollJam recreation with YARD Stick One / RTL-SDR](https://hackaday.io/project/164566-how-to-hack-a-car/details)

{{#include ../../banners/hacktricks-training.md}}
