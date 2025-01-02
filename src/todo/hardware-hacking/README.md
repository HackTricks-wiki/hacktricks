# Hardware Hacking

{{#include ../../banners/hacktricks-training.md}}

## JTAG

JTAG permite realizar uma varredura de limite. A varredura de limite analisa certos circuitos, incluindo células de varredura de limite incorporadas e registradores para cada pino.

O padrão JTAG define **comandos específicos para conduzir varreduras de limite**, incluindo os seguintes:

- **BYPASS** permite testar um chip específico sem a sobrecarga de passar por outros chips.
- **SAMPLE/PRELOAD** coleta uma amostra dos dados que entram e saem do dispositivo quando está em seu modo de funcionamento normal.
- **EXTEST** define e lê os estados dos pinos.

Ele também pode suportar outros comandos, como:

- **IDCODE** para identificar um dispositivo
- **INTEST** para o teste interno do dispositivo

Você pode encontrar essas instruções ao usar uma ferramenta como o JTAGulator.

### The Test Access Port

As varreduras de limite incluem testes do **Test Access Port (TAP)** de quatro fios, uma porta de uso geral que fornece **acesso às funções de suporte de teste JTAG** incorporadas em um componente. O TAP usa os seguintes cinco sinais:

- Test clock input (**TCK**) O TCK é o **clock** que define com que frequência o controlador TAP realizará uma única ação (em outras palavras, pulará para o próximo estado na máquina de estados).
- Test mode select (**TMS**) input O TMS controla a **máquina de estados finita**. A cada pulso do clock, o controlador TAP JTAG do dispositivo verifica a voltagem no pino TMS. Se a voltagem estiver abaixo de um certo limite, o sinal é considerado baixo e interpretado como 0, enquanto se a voltagem estiver acima de um certo limite, o sinal é considerado alto e interpretado como 1.
- Test data input (**TDI**) O TDI é o pino que envia **dados para o chip através das células de varredura**. Cada fornecedor é responsável por definir o protocolo de comunicação através deste pino, pois o JTAG não define isso.
- Test data output (**TDO**) O TDO é o pino que envia **dados para fora do chip**.
- Test reset (**TRST**) input O TRST opcional redefine a máquina de estados finita **para um estado conhecido bom**. Alternativamente, se o TMS for mantido em 1 por cinco ciclos de clock consecutivos, ele invoca um reset, da mesma forma que o pino TRST faria, razão pela qual o TRST é opcional.

Às vezes, você poderá encontrar esses pinos marcados na PCB. Em outras ocasiões, pode ser necessário **encontrá-los**.

### Identifying JTAG pins

A maneira mais rápida, mas mais cara, de detectar portas JTAG é usando o **JTAGulator**, um dispositivo criado especificamente para esse propósito (embora também possa **detectar pinagens UART**).

Ele possui **24 canais** que você pode conectar aos pinos das placas. Em seguida, ele realiza um **ataque BF** de todas as combinações possíveis enviando comandos de varredura de limite **IDCODE** e **BYPASS**. Se receber uma resposta, ele exibe o canal correspondente a cada sinal JTAG.

Uma maneira mais barata, mas muito mais lenta, de identificar pinagens JTAG é usando o [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) carregado em um microcontrolador compatível com Arduino.

Usando o **JTAGenum**, você primeiro **define os pinos do dispositivo de sondagem** que usará para a enumeração. Você terá que consultar o diagrama de pinagem do dispositivo e, em seguida, conectar esses pinos aos pontos de teste no seu dispositivo alvo.

Uma **terceira maneira** de identificar pinos JTAG é **inspecionando a PCB** em busca de uma das pinagens. Em alguns casos, as PCBs podem convenientemente fornecer a **interface Tag-Connect**, que é uma indicação clara de que a placa também possui um conector JTAG. Você pode ver como essa interface se parece em [https://www.tag-connect.com/info/](https://www.tag-connect.com/info/). Além disso, inspecionar os **datasheets dos chipsets na PCB** pode revelar diagramas de pinagem que apontam para interfaces JTAG.

## SDW

SWD é um protocolo específico da ARM projetado para depuração.

A interface SWD requer **dois pinos**: um sinal bidirecional **SWDIO**, que é o equivalente aos pinos **TDI e TDO do JTAG** e um clock, e **SWCLK**, que é o equivalente ao **TCK** no JTAG. Muitos dispositivos suportam a **Serial Wire ou JTAG Debug Port (SWJ-DP)**, uma interface combinada JTAG e SWD que permite conectar um probe SWD ou JTAG ao alvo.

{{#include ../../banners/hacktricks-training.md}}
