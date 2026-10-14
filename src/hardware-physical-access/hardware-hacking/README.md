# Hacking de Hardware

{{#include ../../banners/hacktricks-training.md}}

Para um dispositivo ao qual você tem acesso físico, comece pela interface exposta pela placa ou pelos sinais: [consoles seriais UART](uart.md), [acesso de depuração JTAG/SWD](jtag.md), barramentos [I²C](i2c.md) e [flash SPI](spi.md). A [análise de canal lateral](side_channel_analysis.md) e a [injeção de falhas](fault_injection_attacks.md) abordam tarefas distintas de medição e glitching; a [análise de sinais de rádio](radio.md) cobre um ponto de entrada sem fio. Verifique os níveis elétricos do alvo e as limitações descritas no capítulo relevante antes de conectar ferramentas.

## JTAG

JTAG (IEEE 1149.1) permite testes de boundary scan por meio de células posicionadas ao redor dos pinos de E/S de um dispositivo. Muitos processadores também expõem funções de depuração específicas do fornecedor pelo mesmo Test Access Port (TAP); boundary scan e depuração de CPU são usos relacionados do JTAG, não sinônimos.<sup>[[1]](#references)</sup>

O padrão JTAG define **comandos específicos para realizar boundary scans**, incluindo:

- **BYPASS** seleciona um registrador de bypass de um bit para que outros dispositivos em uma cadeia de varredura possam ser acessados com o mínimo de sobrecarga.
- **SAMPLE/PRELOAD** captura os valores dos pinos durante a operação normal e pode pré-carregar o registrador de boundary scan antes de outra instrução.
- **EXTEST** define e lê os estados dos pinos.

Também pode oferecer suporte a outros comandos, como:

- **IDCODE** para identificar um dispositivo
- **INTEST** para testes internos do dispositivo

Você pode encontrar essas instruções ao usar uma ferramenta como o JTAGulator.

### O Test Access Port

O **Test Access Port (TAP)** fornece acesso à lógica de teste JTAG de um componente. São necessários quatro sinais, e `TRST` é opcional:<sup>[[1]](#references)</sup>

- Entrada de clock de teste (**TCK**) O TCK é o **clock** que define com que frequência o controlador TAP executa uma ação (em outras palavras, avança para o próximo estado na máquina de estados).
- Entrada de seleção do modo de teste (**TMS**) O TMS controla a **máquina de estados finitos**. A cada pulso do clock, o controlador TAP JTAG do dispositivo verifica a tensão no pino TMS. Se a tensão estiver abaixo de um determinado limite, o sinal é considerado baixo e interpretado como 0; se estiver acima desse limite, é considerado alto e interpretado como 1.
- Entrada de dados de teste (**TDI**) O TDI desloca instruções seriais ou dados de teste para o registrador TAP selecionado. A norma IEEE 1149.1 define o comportamento das transferências pelo TAP, enquanto os fornecedores definem instruções opcionais e registradores de depuração.
- Saída de dados de teste (**TDO**) O TDO é o pino que envia **dados para fora do chip**.
- Entrada de reset de teste (**TRST**) O TRST opcional redefine a máquina de estados finitos **para um estado conhecido e válido**. Como alternativa, manter o TMS em 1 por cinco ciclos de clock consecutivos aciona um reset, da mesma forma que o pino TRST; por isso, o TRST é opcional.

Às vezes, você encontrará esses pinos identificados na PCB. Em outras ocasiões, talvez precise **localizá-los**.

### Identificar pinos JTAG

Uma opção rápida e criada especificamente para detectar portas JTAG — mas comparativamente cara — é o **JTAGulator**, que também pode identificar pinagens UART.<sup>[[2]](#references)</sup>

Ele tem **24 canais** que podem ser conectados aos pontos de teste da placa. Ele enumera combinações candidatas de pinos usando varreduras **IDCODE** e **BYPASS** e informa os canais correspondentes aos sinais JTAG detectados.

Uma alternativa mais barata, porém muito mais lenta, para identificar pinagens JTAG é usar o [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) carregado em um microcontrolador compatível com Arduino.

Com o **JTAGenum**, primeiro defina os pinos do microcontrolador de sondagem usados na enumeração. Consulte a pinagem e conecte esses pinos aos pontos de teste candidatos na placa-alvo.<sup>[[3]](#references)</sup>

Uma **terceira maneira** de identificar pinos JTAG é **inspecionar a PCB** em busca de um footprint conhecido. Algumas placas expõem um footprint **Tag-Connect**, embora Tag-Connect seja um sistema de conectores que pode transportar JTAG, SWD, UART ou outra interface — por si só, não prova que os pinos sejam JTAG. As folhas de dados dos componentes e as medições de continuidade podem então identificar os sinais reais.<sup>[[5]](#references)</sup>

## SDW

SWD é a interface de depuração de dois pinos e baseada em pacotes da Arm.<sup>[[4]](#references)</sup>

A interface usa **SWDIO** bidirecional para dados e **SWCLK** para o clock. Muitos dispositivos implementam uma **Serial Wire/JTAG Debug Port (SWJ-DP)** que permite selecionar entre SWD e JTAG em pinos compartilhados.<sup>[[4]](#references)</sup>

## References

- [1] [Grupo de trabalho IEEE 1149.1 — JTAG e boundary scan](https://sagroups.ieee.org/1149/1/)
- [2] [Documentação do JTAGulator](https://github.com/grandideastudio/jtagulator/wiki)
- [3] [JTAGenum — enumeração de pinos JTAG com Arduino](https://github.com/cyphunk/JTAGenum/)
- [4] [Arm — Interfaces de depuração com poucos pinos para sistemas com vários dispositivos](https://developer.arm.com/-/media/Arm%20Developer%20Community/PDF/Low_Pin-Count_Debug_Interfaces_for_Multi-device_Systems.pdf)
- [5] [Tag-Connect — footprints para cabos de depuração e programação](https://www.tag-connect.com/info/)
{{#include ../../banners/hacktricks-training.md}}
