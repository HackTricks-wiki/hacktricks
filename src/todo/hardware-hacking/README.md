# Hardware Hacking

{{#include ../../banners/hacktricks-training.md}}

## JTAG

JTAG (IEEE 1149.1) oferece testes de boundary scan por meio de células posicionadas ao redor dos pinos de I/O de um dispositivo. Muitos processadores também expõem funções de debug específicas do fabricante através da mesma Test Access Port (TAP); boundary scan e debug de CPU são usos relacionados do JTAG, mas não são sinônimos.<sup>[[1]](#references)</sup>

O padrão JTAG define **comandos específicos para realizar boundary scans**, incluindo os seguintes:

- **BYPASS** seleciona um registrador de bypass de um bit para que outros dispositivos em uma cadeia de scan possam ser acessados com o mínimo de overhead.
- **SAMPLE/PRELOAD** captura os valores dos pinos durante a operação normal e pode pré-carregar o registrador de boundary scan antes de outra instrução.
- **EXTEST** define e lê os estados dos pinos.

Ele também pode oferecer suporte a outros comandos, como:

- **IDCODE** para identificar um dispositivo
- **INTEST** para o teste interno do dispositivo

Você pode encontrar essas instruções ao usar uma ferramenta como o JTAGulator.

### The Test Access Port

A **Test Access Port (TAP)** fornece acesso à lógica de teste JTAG de um componente. Quatro sinais são necessários, e `TRST` é opcional:<sup>[[1]](#references)</sup>

- Entrada de clock de teste (**TCK**) O TCK é o **clock** que define com que frequência o controlador TAP executará uma única ação (em outras palavras, avançará para o próximo estado na máquina de estados).
- Entrada de seleção do modo de teste (**TMS**) O TMS controla a **máquina de estados finitos**. A cada ciclo do clock, o controlador JTAG TAP do dispositivo verifica a tensão no pino TMS. Se a tensão estiver abaixo de determinado limite, o sinal será considerado baixo e interpretado como 0; se estiver acima de determinado limite, o sinal será considerado alto e interpretado como 1.
- Entrada de dados de teste (**TDI**) desloca instruções seriais ou dados de teste para dentro do registrador TAP selecionado. A IEEE 1149.1 define o comportamento da transferência do TAP, enquanto os fabricantes definem instruções opcionais e registradores de debug.
- Saída de dados de teste (**TDO**) O TDO é o pino que envia **dados para fora do chip**.
- Entrada de reset de teste (**TRST**) O TRST opcional reseta a máquina de estados finitos **para um estado conhecido e seguro**. Como alternativa, se o TMS permanecer em 1 por cinco ciclos consecutivos do clock, ele aciona um reset da mesma forma que o pino TRST, motivo pelo qual o TRST é opcional.

Às vezes, você poderá encontrar esses pinos identificados na PCB. Em outras ocasiões, talvez precise **encontrá-los**.

### Identifying JTAG pins

Uma opção rápida e desenvolvida especificamente para detectar portas JTAG — mas comparativamente cara — é o **JTAGulator**, que também pode identificar pinouts de UART.<sup>[[2]](#references)</sup>

Ele possui **24 canais** que podem ser conectados a pontos de teste da placa. Ele enumera combinações candidatas de pinos usando scans de **IDCODE** e **BYPASS** e informa os canais correspondentes aos sinais JTAG detectados.

Uma forma mais barata, porém muito mais lenta, de identificar pinouts JTAG é usar o [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) carregado em um microcontrolador compatível com Arduino.

Com o **JTAGenum**, primeiro defina os pinos do microcontrolador de probing usados para a enumeração. Consulte o pinout e conecte esses pinos aos pontos de teste candidatos na placa-alvo.<sup>[[3]](#references)</sup>

Uma **terceira forma** de identificar pinos JTAG é **inspecionar a PCB** em busca de um footprint conhecido. Algumas placas expõem um footprint **Tag-Connect**, embora Tag-Connect seja um sistema de conectores que pode transportar JTAG, SWD, UART ou outra interface — por si só, ele não prova que os pinos sejam JTAG. Os datasheets dos componentes e as medições de continuidade podem então identificar os sinais reais.<sup>[[5]](#references)</sup>

## SDW

SWD é a interface de debug de dois pinos e baseada em pacotes da Arm.<sup>[[4]](#references)</sup>

A interface usa **SWDIO** bidirecional para dados e **SWCLK** para o clock. Muitos dispositivos implementam uma **Serial Wire/JTAG Debug Port (SWJ-DP)** que permite selecionar entre SWD e JTAG em pinos compartilhados.<sup>[[4]](#references)</sup>

## References

- [1] [Grupo de trabalho IEEE 1149.1 — JTAG e boundary scan](https://sagroups.ieee.org/1149/1/)
- [2] [Documentação do JTAGulator](https://github.com/grandideastudio/jtagulator/wiki)
- [3] [JTAGenum — enumeração de pinos JTAG para Arduino](https://github.com/cyphunk/JTAGenum/)
- [4] [Arm — interfaces de debug com poucos pinos para sistemas com múltiplos dispositivos](https://developer.arm.com/-/media/Arm%20Developer%20Community/PDF/Low_Pin-Count_Debug_Interfaces_for_Multi-device_Systems.pdf)
- [5] [Tag-Connect — footprints para debug e programação](https://www.tag-connect.com/info/)
{{#include ../../banners/hacktricks-training.md}}
