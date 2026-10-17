# Hacking de hardware

{{#include ../../banners/hacktricks-training.md}}

Para um dispositivo ao qual você tem acesso físico, comece pela interface exposta pela placa ou pelos sinais: [consoles seriais UART](uart.md), [acesso de depuração JTAG/SWD](jtag.md), [rastreamento de instruções CoreSight](arm-coresight-instruction-tracing.md), barramentos [I²C](i2c.md) e [flash SPI](spi.md). [Análise de canal lateral](side_channel_analysis.md) e [injeção de falhas](fault_injection_attacks.md) atendem a tarefas diferentes de medição e glitching; [análise de sinais de rádio](radio.md) aborda um ponto de entrada sem fio. Para procedimentos específicos do alvo envolvendo RFID/NFC, sub-GHz, infravermelho, BLE, LoRaWAN e iButton, consulte [Radio Hacking and Proximity Interfaces](../radio-hacking/README.md). Verifique os níveis elétricos do alvo e as limitações descritas no capítulo relevante antes de conectar ferramentas.

## JTAG

JTAG (IEEE 1149.1) permite testes boundary-scan por meio de células posicionadas ao redor dos pinos de I/O de um dispositivo. Muitos processadores também expõem funções de depuração específicas do fabricante por meio da mesma Test Access Port (TAP); boundary scan e depuração de CPU são usos relacionados de JTAG, não sinônimos.<sup>[[1]](#references)</sup>

O padrão JTAG define **comandos específicos para realizar boundary scans**, incluindo os seguintes:

- **BYPASS** seleciona um registrador de bypass de um bit para que outros dispositivos em uma cadeia de scan possam ser acessados com o mínimo de sobrecarga.
- **SAMPLE/PRELOAD** captura os valores dos pinos durante a operação normal e pode carregar previamente o registrador boundary-scan antes de outra instrução.
- **EXTEST** define e lê os estados dos pinos.

Também pode oferecer suporte a outros comandos, como:

- **IDCODE** para identificar um dispositivo
- **INTEST** para testar o dispositivo internamente

Você pode encontrar essas instruções ao usar uma ferramenta como o JTAGulator.

### A Test Access Port

A **Test Access Port (TAP)** fornece acesso à lógica de teste JTAG de um componente. São necessários quatro sinais, e `TRST` é opcional:<sup>[[1]](#references)</sup>

- Entrada de clock de teste (**TCK**) O TCK é o **clock** que define a frequência com que o controlador TAP executa uma ação (em outras palavras, passa para o próximo estado da máquina de estados).
- Entrada de seleção do modo de teste (**TMS**) O TMS controla a **máquina de estados finitos**. A cada pulso do clock, o controlador TAP JTAG do dispositivo verifica a tensão no pino TMS. Se a tensão estiver abaixo de determinado limite, o sinal é considerado baixo e interpretado como 0; se estiver acima de determinado limite, é considerado alto e interpretado como 1.
- Entrada de dados de teste (**TDI**) Desloca instruções seriais ou dados de teste para o registrador TAP selecionado. A IEEE 1149.1 define o comportamento da transferência TAP, enquanto os fabricantes definem instruções opcionais e registradores de depuração.
- Saída de dados de teste (**TDO**) O TDO é o pino que envia **dados para fora do chip**.
- Entrada de reset de teste (**TRST**) O TRST opcional redefine a máquina de estados finitos **para um estado válido conhecido**. Como alternativa, manter o TMS em 1 por cinco ciclos consecutivos de clock aciona um reset, da mesma forma que o pino TRST, por isso o TRST é opcional.

Às vezes, você encontrará esses pinos identificados na PCB. Em outras situações, talvez precise **localizá-los**.

### Identificando pinos JTAG

Uma opção rápida e desenvolvida especificamente para detectar portas JTAG — mas comparativamente cara — é o **JTAGulator**, que também pode identificar pinagens UART.<sup>[[2]](#references)</sup>

Ele tem **24 canais** que podem ser conectados aos pontos de teste da placa. Ele enumera combinações candidatas de pinos usando scans **IDCODE** e **BYPASS** e informa quais canais correspondem aos sinais JTAG detectados.

Uma maneira mais barata, mas muito mais lenta, de identificar pinagens JTAG é usar o [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) carregado em um microcontrolador compatível com Arduino.

Com o **JTAGenum**, primeiro defina os pinos do microcontrolador de sondagem usados na enumeração. Consulte a pinagem e conecte esses pinos aos pontos de teste candidatos na placa-alvo.<sup>[[3]](#references)</sup>

Uma **terceira maneira** de identificar pinos JTAG é **inspecionar a PCB** em busca de um footprint conhecido. Algumas placas expõem um footprint **Tag-Connect**, embora Tag-Connect seja um sistema de conectores que pode transportar JTAG, SWD, UART ou outra interface — por si só, ele não comprova que os pinos sejam JTAG. Em seguida, datasheets dos componentes e medições de continuidade podem ajudar a identificar os sinais reais.<sup>[[5]](#references)</sup>

## SDW

SWD é uma interface de depuração da Arm, de dois pinos e baseada em pacotes.<sup>[[4]](#references)</sup>

A interface usa **SWDIO** bidirecional para dados e **SWCLK** para o clock. Muitos dispositivos implementam uma **Serial Wire/JTAG Debug Port (SWJ-DP)** que permite selecionar entre SWD e JTAG em pinos compartilhados.<sup>[[4]](#references)</sup>

## References

- [1] [Grupo de trabalho IEEE 1149.1 — JTAG e boundary scan](https://sagroups.ieee.org/1149/1/)
- [2] [Documentação do JTAGulator](https://github.com/grandideastudio/jtagulator/wiki)
- [3] [JTAGenum — Enumeração de pinos JTAG com Arduino](https://github.com/cyphunk/JTAGenum/)
- [4] [Arm — Interfaces de depuração com poucos pinos para sistemas com vários dispositivos](https://developer.arm.com/-/media/Arm%20Developer%20Community/PDF/Low_Pin-Count_Debug_Interfaces_for_Multi-device_Systems.pdf)
- [5] [Tag-Connect — Footprints para cabos de depuração e programação](https://www.tag-connect.com/info/)
{{#include ../../banners/hacktricks-training.md}}
