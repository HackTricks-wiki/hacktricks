# Hardware Hacking

{{#include ../../banners/hacktricks-training.md}}

## JTAG

O JTAG permite realizar uma boundary scan. A boundary scan analisa determinados circuitos, incluindo células de boundary-scan incorporadas e registradores para cada pino.

O padrão JTAG define **comandos específicos para realizar boundary scans**, incluindo os seguintes:

- **BYPASS** permite testar um chip específico sem o overhead de passar por outros chips.
- **SAMPLE/PRELOAD** coleta uma amostra dos dados que entram e saem do dispositivo quando ele está em seu modo normal de funcionamento.
- **EXTEST** define e lê os estados dos pinos.

Ele também pode oferecer suporte a outros comandos, como:

- **IDCODE** para identificar um dispositivo
- **INTEST** para testar internamente o dispositivo

Você pode encontrar essas instruções ao usar uma ferramenta como o JTAGulator.

### The Test Access Port

As boundary scans incluem testes da **Test Access Port (TAP)** de quatro fios, uma porta de uso geral que fornece **acesso às funções de suporte a testes JTAG** incorporadas a um componente. A TAP usa os cinco sinais a seguir:

- Entrada de clock de teste (**TCK**) O TCK é o **clock** que define com que frequência o controlador TAP realizará uma ação individual (em outras palavras, avançará para o próximo estado na máquina de estados).
- Entrada de seleção do modo de teste (**TMS**) O TMS controla a **máquina de estados finitos**. A cada ciclo do clock, o controlador JTAG TAP do dispositivo verifica a tensão no pino TMS. Se a tensão estiver abaixo de determinado limite, o sinal será considerado baixo e interpretado como 0; se estiver acima de determinado limite, o sinal será considerado alto e interpretado como 1.
- Entrada de dados de teste (**TDI**) O TDI é o pino que envia **dados para dentro do chip através das scan cells**. Cada fornecedor é responsável por definir o protocolo de comunicação nesse pino, pois o JTAG não o define.
- Saída de dados de teste (**TDO**) O TDO é o pino que envia **dados para fora do chip**.
- Entrada de reset de teste (**TRST**) A TRST opcional redefine a máquina de estados finitos **para um estado válido conhecido**. Como alternativa, se o TMS permanecer em 1 por cinco ciclos de clock consecutivos, ele acionará um reset, da mesma forma que o pino TRST faria, motivo pelo qual a TRST é opcional.

Às vezes, você conseguirá encontrar esses pinos identificados na PCB. Em outras ocasiões, talvez precise **encontrá-los**.

### Identifying JTAG pins

A maneira mais rápida, porém mais cara, de detectar portas JTAG é usando o **JTAGulator**, um dispositivo criado especificamente para esse propósito (embora ele também possa **detectar pinouts de UART**).

Ele possui **24 canais** que podem ser conectados aos pinos da placa. Em seguida, realiza um **ataque BF** com todas as combinações possíveis, enviando comandos de boundary scan **IDCODE** e **BYPASS**. Se receber uma resposta, ele exibe o canal correspondente a cada sinal JTAG

Uma maneira mais barata, porém muito mais lenta, de identificar pinouts JTAG é usando o [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) carregado em um microcontrolador compatível com Arduino.

Usando o **JTAGenum**, primeiro você deve **definir os pinos do dispositivo de probing** que usará para a enumeração. Você terá que consultar o diagrama de pinout do dispositivo e, em seguida, conectar esses pinos aos pontos de teste do dispositivo-alvo.

Uma **terceira maneira** de identificar pinos JTAG é **inspecionar a PCB** em busca de um dos pinouts. Em alguns casos, as PCBs podem oferecer convenientemente a **Tag-Connect interface**, o que é uma indicação clara de que a placa também possui um conector JTAG. Você pode ver a aparência dessa interface em [https://www.tag-connect.com/info/](https://www.tag-connect.com/info/). Além disso, inspecionar os **datasheets dos chipsets na PCB** pode revelar diagramas de pinout que apontam para interfaces JTAG.

## SDW

SWD é um protocolo específico da ARM projetado para debugging.

A interface SWD requer **dois pinos**: um sinal **SWDIO** bidirecional, que é o equivalente aos **pinos TDI e TDO do JTAG e a um clock**, e o **SWCLK**, que é o equivalente ao **TCK** no JTAG. Muitos dispositivos oferecem suporte à **Serial Wire or JTAG Debug Port (SWJ-DP)**, uma interface combinada JTAG e SWD que permite conectar uma probe SWD ou JTAG ao alvo.

{{#include ../../banners/hacktricks-training.md}}
