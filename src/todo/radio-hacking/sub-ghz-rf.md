# Sub-GHz RF

{{#include ../../banners/hacktricks-training.md}}

## Portas de garagem

Os controles remotos de portas de garagem usam várias alocações sub-GHz específicas por região e produto. Frequências como 300, 310, 315, 390 e 433.92 MHz são encontradas, mas não existe uma banda universal de “300–190 MHz” para portas de garagem. Identifique a etiqueta do alvo, a região regulatória e o sinal observado antes de transmitir.<sup>[[1]](#references)</sup>

## Portas de carros

Muitos controles remotos de carros usam **315 MHz ou 433.92 MHz**, com regras regionais e o design do veículo influenciando a escolha. A frequência, por si só, não faz com que 433 MHz tenha um alcance maior que 315 MHz: potência de transmissão, eficiência da antena, modulação, sensibilidade do receptor, propagação e regulamentações locais são fatores relevantes. A Europa usa normalmente 433.92 MHz, enquanto 315 MHz é comum na América do Norte e no Japão.<sup>[[1]](#references)</sup>

## **Brute-force Attack**

<figure><img src="../../images/image (1084).png" alt=""><figcaption></figcaption></figure>

No sistema de código fixo demonstrado, enviar cada código uma vez em vez de cinco reduz o tempo estimado para seis minutos:

<figure><img src="../../images/image (622).png" alt=""><figcaption></figcaption></figure>

Remover a espera de 2 ms entre os sinais reduz essa demonstração para aproximadamente três minutos.

Usar uma sequência de De Bruijn para sobrepor strings de bits candidatas reduz o ataque demonstrado para aproximadamente oito segundos quando o receptor aceita a sequência contínua sem um preâmbulo obrigatório ou reinicialização de frame.<sup>[[3]](#references)</sup>

<figure><img src="../../images/image (583).png" alt=""><figcaption></figcaption></figure>

O OpenSesame implementa esse ataque contra sistemas de código fixo compatíveis.<sup>[[5]](#references)</sup>

Exigir **um preâmbulo evitará a otimização da De Bruijn Sequence** e **rolling codes impedirão esse ataque** (supondo que o código seja longo o suficiente para não ser vulnerável a brute force).

## Sub-GHz Attack

Para atacar esses sinais com o Flipper Zero, confira:


{{#ref}}
flipper-zero/fz-sub-ghz.md
{{#endref}}

## Rolling Codes Protection

Os abridores automáticos de portas de garagem normalmente usam um controle remoto sem fio para abrir e fechar a porta da garagem. O controle remoto **envia um sinal de radiofrequência (RF)** ao abridor da porta, que ativa o motor para abrir ou fechar a porta.

É possível que alguém use um dispositivo conhecido como code grabber para interceptar o sinal de RF e gravá-lo para uso posterior. Isso é conhecido como **replay attack**. Para impedir esse tipo de ataque, muitos abridores modernos de portas de garagem usam um método de criptografia mais seguro, conhecido como sistema de **rolling code**.

O **sinal de RF normalmente é transmitido usando um rolling code**, o que significa que o código muda a cada uso. Isso torna **difícil** para alguém **interceptar** o sinal e **usá-lo** para obter acesso **não autorizado** à garagem.

Em um sistema de rolling code, o controle remoto e o abridor da porta de garagem possuem um **algoritmo compartilhado** que **gera um novo código** sempre que o controle remoto é usado. O abridor da porta de garagem responderá apenas ao **código correto**, tornando muito mais difícil que alguém obtenha acesso não autorizado à garagem apenas capturando um código.

### **Missing Link Attack**

Basicamente, você escuta o botão e **captura o sinal enquanto o controle remoto está fora do alcance** do dispositivo (por exemplo, o carro ou a garagem). Em seguida, você se aproxima do dispositivo e **usa o código capturado para abri-lo**.<sup>[[2]](#references)</sup>

### Full Link Jamming Attack

> [!CAUTION]
> A interferência de RF intencional é ilegal em muitas jurisdições e pode interromper sistemas relevantes para a segurança. Execute testes de jamming somente em um laboratório autorizado e blindado, seguindo as regulamentações de rádio aplicáveis.<sup>[[6]](#references)</sup>

Um atacante poderia **bloquear o sinal próximo ao veículo ou receptor** para que o receptor não consiga decodificar o código, capturar separadamente a transmissão bloqueada, interromper o jamming e, em seguida, fazer replay do código capturado.<sup>[[2]](#references)</sup>

Em algum momento, a vítima usará as **chaves para trancar o carro**, mas o ataque terá **gravado códigos de “fechar a porta” suficientes** que talvez possam ser reenviados para abrir a porta (pode ser necessária uma **mudança de frequência**, pois há carros que usam os mesmos códigos para abrir e fechar, mas escutam os dois comandos em frequências diferentes).

> [!WARNING]
> **Jamming funciona**, mas é perceptível: se a **pessoa que trancou o carro simplesmente testar as portas** para garantir que estão trancadas, perceberá que o carro está destrancado. Além disso, se ela souber da existência desses ataques, poderá até perceber que as portas nunca emitiram o **som de travamento** ou que as **luzes do carro** nunca piscaram quando pressionou o botão de ‘travar’.

### **Code Grabbing Attack ( aka ‘RollJam’ )**

Esta é uma **técnica de Jamming mais furtiva**. O atacante bloqueará o sinal para que, quando a vítima tentar trancar a porta, isso não funcione, mas o atacante **gravará esse código**. Em seguida, a vítima **tentará trancar o carro novamente**, pressionando o botão, e o carro **gravará esse segundo código**.<sup>[[2]](#references)</sup><sup>[[4]](#references)</sup>\
Imediatamente depois disso, o **atacante poderá enviar o primeiro código** e o **carro será trancado** (a vítima pensará que o segundo pressionamento o trancou). Então, o atacante poderá **enviar o segundo código roubado para abrir** o carro (supondo que um código de **“fechar o carro” também possa ser usado para abri-lo**). Pode ser necessária uma mudança de frequência (pois há carros que usam os mesmos códigos para abrir e fechar, mas escutam os dois comandos em frequências diferentes).

Uma implementação de RollJam explora a largura de banda do receptor: o jammer transmite suficientemente próximo da portadora do controle remoto para dessensibilizar o receptor mais amplo do veículo, enquanto o receptor mais estreito do atacante permanece centrado no controle remoto e ainda consegue gravar o sinal. O deslocamento exato e a largura de banda dependem do hardware do alvo.<sup>[[2]](#references)</sup>

> [!WARNING]
> Outras implementações observadas em especificações mostram que o **rolling code é uma parte** do código total enviado. Ou seja, o código enviado é uma **chave de 24 bits**, em que os primeiros **12 bits são o rolling code**, os **8 seguintes são o comando** (como trancar ou destrancar) e os 4 últimos são o **checksum**. Veículos que implementam esse tipo também são naturalmente suscetíveis, pois o atacante precisa apenas substituir o segmento do rolling code para poder **usar qualquer rolling code nas duas frequências**.

> [!CAUTION]
> Observe que, se a vítima enviar um terceiro código enquanto o atacante estiver enviando o primeiro, o primeiro e o segundo códigos serão invalidados.

### Alarm Sounding Jamming Attack

Em um teste contra um sistema de rolling code instalado posteriormente em um carro, **enviar o mesmo código duas vezes** imediatamente **ativou o alarme** e o imobilizador, proporcionando uma oportunidade única de **denial of service**. Ironicamente, o meio de **desativar o alarme** e o imobilizador era **pressionar** o **controle remoto**, proporcionando ao atacante a capacidade de **realizar continuamente um ataque de DoS**. Ou combine esse ataque com o **anterior para obter mais códigos**, pois a vítima provavelmente desejará interromper o ataque o mais rápido possível.<sup>[[2]](#references)</sup>

## References

- [1] [Documentação do Flipper Zero - frequências Sub-GHz regionais](https://docs.flipper.net/zero/sub-ghz/frequencies)
- [2] [Contornando sistemas de Rolling Code - Andrew Mohawk](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
- [3] [Samy Kamkar - DEF CON 23: Drive It Like You Hacked It (OpenSesame)](https://samy.pl/defcon2015/)
- [4] [Como hackear um carro - recriação do RollJam com YARD Stick One / RTL-SDR](https://hackaday.io/project/164566-how-to-hack-a-car/details)
- [5] [Código-fonte do OpenSesame](https://github.com/samyk/opensesame)
- [6] [Aviso de fiscalização da FCC - fiscalização de Jammers](https://www.fcc.gov/document/jammer-enforcement)
{{#include ../../banners/hacktricks-training.md}}
