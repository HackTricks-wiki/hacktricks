# RF Sub-GHz

{{#include ../../banners/hacktricks-training.md}}

## Portões de garagem

Os controles remotos de portões de garagem usam alocações sub-GHz específicas de cada região e produto. É comum encontrar frequências como 300, 310, 315, 390 e 433,92 MHz, mas não existe uma faixa universal de “300–190 MHz” para portões de garagem. Identifique a etiqueta do alvo, a região regulatória e o sinal observado antes de transmitir.<sup>[[1]](#references)</sup>

## Portas de carros

Muitos controles remotos de chaves de carros usam **315 MHz ou 433,92 MHz**; as regras regionais e o projeto do veículo influenciam essa escolha. A frequência, por si só, não faz com que 433 MHz tenha um alcance maior do que 315 MHz: potência de transmissão, eficiência da antena, modulação, sensibilidade do receptor, propagação e regulamentações locais são fatores relevantes. Na Europa, é comum usar 433,92 MHz; na América do Norte e no Japão, 315 MHz é comum.<sup>[[1]](#references)</sup>

## **Brute-force Attack**

<figure><img src="../../images/image (1084).png" alt=""><figcaption></figcaption></figure>

No sistema de código fixo demonstrado, enviar cada código uma vez, em vez de cinco vezes, reduz o tempo estimado para seis minutos:

<figure><img src="../../images/image (622).png" alt=""><figcaption></figcaption></figure>

Remover a espera de 2 ms entre os sinais reduz essa demonstração para aproximadamente três minutos.

Usar uma sequência De Bruijn para sobrepor cadeias de bits candidatas reduz o ataque demonstrado para aproximadamente oito segundos, quando o receptor aceita a sequência contínua sem exigir um preâmbulo ou reinicialização de quadro.<sup>[[3]](#references)</sup>

<figure><img src="../../images/image (583).png" alt=""><figcaption></figcaption></figure>

OpenSesame implementa esse ataque contra sistemas de código fixo compatíveis.<sup>[[5]](#references)</sup>

Exigir **um preâmbulo evita** a otimização da **sequência De Bruijn** e **rolling codes impedem esse ataque** (presumindo que o código seja longo o suficiente para não ser suscetível a brute-force).

## Ataque Sub-GHz

Para atacar esses sinais com o Flipper Zero, consulte:


{{#ref}}
flipper-zero/fz-sub-ghz.md
{{#endref}}

## Proteção contra Rolling Codes

Os abridores automáticos de portões de garagem normalmente usam um controle remoto sem fio para abrir e fechar o portão. O controle remoto **envia um sinal de radiofrequência (RF)** ao abridor do portão, que ativa o motor para abrir ou fechar o portão.

É possível usar um dispositivo conhecido como code grabber para interceptar o sinal RF e gravá-lo para uso posterior. Isso é conhecido como **replay attack**. Para evitar esse tipo de ataque, muitos abridores modernos de portões de garagem usam um método de criptografia mais seguro, conhecido como sistema de **rolling code**.

O **sinal RF normalmente é transmitido usando um rolling code**, o que significa que o código muda a cada uso. Isso torna **difícil** para alguém **interceptar** o sinal e **usá-lo** para obter acesso **não autorizado** à garagem.

Em um sistema de rolling code, o controle remoto e o abridor do portão têm um **algoritmo compartilhado** que **gera um novo código** a cada uso do controle remoto. O abridor do portão só responderá ao **código correto**, tornando muito mais difícil obter acesso não autorizado à garagem apenas capturando um código.

### **Missing Link Attack**

Basicamente, você escuta o botão e **captura o sinal enquanto o controle remoto está fora do alcance** do dispositivo (por exemplo, do carro ou da garagem). Depois, você vai até o dispositivo e **usa o código capturado para abri-lo**.<sup>[[2]](#references)</sup>

### Full Link Jamming Attack

> [!CAUTION]
> A interferência RF intencional é ilegal em muitas jurisdições e pode afetar sistemas importantes para a segurança. Faça testes de jamming apenas em um laboratório blindado e autorizado, em conformidade com as regulamentações de rádio aplicáveis.<sup>[[6]](#references)</sup>

Um atacante poderia **bloquear o sinal perto do veículo ou do receptor** para que o receptor não consiga decodificar o código, capturar separadamente a transmissão bloqueada, parar o jamming e, em seguida, reproduzir o código capturado.<sup>[[2]](#references)</sup>

Em algum momento, a vítima usará as **chaves para trancar o carro**, mas então o ataque terá **gravado códigos de “fechar porta” suficientes** que talvez possam ser reenviados para abrir a porta (pode ser necessário **mudar a frequência**, pois há carros que usam os mesmos códigos para abrir e fechar, mas recebem os dois comandos em frequências diferentes).

> [!WARNING]
> **O jamming funciona**, mas é perceptível: se a **pessoa que está trancando o carro simplesmente testar as portas** para garantir que estejam trancadas, perceberá que o carro está destrancado. Além disso, se souber desse tipo de ataque, poderá até perceber que as portas não fizeram o **som** de trancamento ou que as **luzes** do carro não piscaram ao pressionar o botão de trancar.

### **Code Grabbing Attack ( aka ‘RollJam’ )**

Esta é uma técnica de **jamming mais furtiva**. O atacante bloqueia o sinal, de modo que, quando a vítima tenta trancar a porta, não funciona, mas o atacante **grava esse código**. Então, a vítima **tenta trancar o carro novamente**, pressionando o botão, e o carro **grava esse segundo código**.<sup>[[2]](#references)</sup><sup>[[4]](#references)</sup>\
Imediatamente depois, o **atacante pode enviar o primeiro código** e o **carro será trancado** (a vítima pensará que foi a segunda tentativa que o trancou). Então, o atacante poderá **enviar o segundo código roubado para abrir** o carro (presumindo que um código de **“trancar o carro” também possa ser usado para abri-lo**). Pode ser necessário mudar a frequência (pois há carros que usam os mesmos códigos para abrir e fechar, mas recebem os dois comandos em frequências diferentes).

Uma implementação de RollJam explora a largura de banda do receptor: o jammer transmite perto o suficiente da portadora do controle remoto para dessensibilizar o receptor mais amplo do veículo, enquanto o receptor mais estreito do atacante permanece sintonizado na frequência do controle remoto e ainda consegue gravar o sinal. O deslocamento e a largura de banda exatos dependem do hardware-alvo.<sup>[[2]](#references)</sup>

> [!WARNING]
> Outras implementações descritas em especificações mostram que o **rolling code é apenas uma parte** do código total enviado. Ou seja, o código enviado é uma **chave de 24 bits**, em que os primeiros **12 bits são o rolling code**, os **8 seguintes são o comando** (como trancar ou destrancar) e os últimos 4 são o **checksum**. Veículos que implementam esse tipo também são naturalmente vulneráveis, pois o atacante só precisa substituir o segmento do rolling code para poder **usar qualquer rolling code nas duas frequências**.

> [!CAUTION]
> Observe que, se a vítima enviar um terceiro código enquanto o atacante envia o primeiro, o primeiro e o segundo códigos serão invalidados.

### Ataque de jamming que aciona o alarme

Em testes contra um sistema de rolling code instalado posteriormente em um carro, **enviar o mesmo código duas vezes** ativou imediatamente o alarme e o imobilizador, criando uma oportunidade específica de **denial of service**. Ironicamente, para **desativar o alarme** e o imobilizador, era preciso **pressionar** o **controle remoto**, permitindo que um atacante **realizasse continuamente um ataque de DoS**. Ou combine esse ataque com o **anterior para obter mais códigos**, pois a vítima provavelmente tentará interromper o ataque o mais rápido possível.<sup>[[2]](#references)</sup>

## References

- [1] [Documentação do Flipper Zero - frequências Sub-GHz regionais](https://docs.flipper.net/zero/sub-ghz/frequencies)
- [2] [Como contornar sistemas de Rolling Code - Andrew Mohawk](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
- [3] [Samy Kamkar - DEF CON 23: Dirija como se tivesse hackeado (OpenSesame)](https://samy.pl/defcon2015/)
- [4] [Como hackear um carro - reprodução do RollJam com YARD Stick One / RTL-SDR](https://hackaday.io/project/164566-how-to-hack-a-car/details)
- [5] [Código-fonte do OpenSesame](https://github.com/samyk/opensesame)
- [6] [Aviso de fiscalização da FCC - fiscalização de jammers](https://www.fcc.gov/document/jammer-enforcement)
{{#include ../../banners/hacktricks-training.md}}
