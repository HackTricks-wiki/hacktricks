<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Trabalha em uma **empresa de segurança cibernética**? Quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!

- Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)

- **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Compartilhe suas técnicas de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>


#

# JTAG

JTAG permite realizar uma varredura de fronteira. A varredura de fronteira analisa certos circuitos, incluindo células e registradores de varredura de fronteira incorporados para cada pino.

O padrão JTAG define **comandos específicos para conduzir varreduras de fronteira**, incluindo os seguintes:

* **BYPASS** permite testar um chip específico sem a sobrecarga de passar por outros chips.
* **SAMPLE/PRELOAD** faz uma amostra dos dados que entram e saem do dispositivo quando ele está em seu modo de funcionamento normal.
* **EXTEST** define e lê estados de pinos.

Também pode suportar outros comandos, como:

* **IDCODE** para identificar um dispositivo
* **INTEST** para testes internos do dispositivo

Você pode encontrar essas instruções ao usar uma ferramenta como o JTAGulator.

## A porta de acesso ao teste

As varreduras de fronteira incluem testes dos quatro fios da **Porta de Acesso ao Teste (TAP)**, uma porta de propósito geral que fornece **acesso ao suporte de teste JTAG** incorporado em um componente. O TAP usa os seguintes cinco sinais:

* Entrada de relógio de teste (**TCK**) O TCK é o **relógio** que define com que frequência o controlador TAP tomará uma única ação (ou seja, saltar para o próximo estado na máquina de estados).
* Seleção de modo de teste (**TMS**) A entrada TMS controla a **máquina de estados finita**. Em cada batida do relógio, o controlador TAP JTAG do dispositivo verifica a tensão no pino TMS. Se a tensão estiver abaixo de um determinado limite, o sinal é considerado baixo e interpretado como 0, enquanto se a tensão estiver acima de um determinado limite, o sinal é considerado alto e interpretado como 1.
* Entrada de dados de teste (**TDI**) TDI é o pino que envia **dados para o chip por meio das células de varredura**. Cada fornecedor é responsável por definir o protocolo de comunicação sobre este pino, porque o JTAG não define isso.
* Saída de dados de teste (**TDO**) TDO é o pino que envia **dados para fora do chip**.
* Entrada de reset de teste (**TRST**) O reset TRST opcional redefine a máquina de estados finita **para um estado conhecido e bom**. Alternativamente, se o TMS for mantido em 1 por cinco ciclos de relógio consecutivos, ele invoca um reset, da mesma forma que o pino TRST faria, razão pela qual o TRST é opcional.

Às vezes, você poderá encontrar esses pinos marcados na PCB. Em outras ocasiões, você pode precisar **encontrá-los**.

## Identificando pinos JTAG

A maneira mais rápida, mas mais cara, de detectar portas JTAG é usando o **JTAGulator**, um dispositivo criado especificamente para esse fim (embora também possa **detectar pinouts UART**).

Ele tem **24 canais** que você pode conectar aos pinos da placa. Em seguida, ele realiza um **ataque BF** de todas as combinações possíveis enviando comandos de varredura de fronteira **IDCODE** e **BYPASS**. Se receber uma resposta, ele exibe o canal correspondente a cada sinal JTAG.

Uma maneira mais barata, mas muito mais lenta, de identificar pinouts JTAG é usando o [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) carregado em um microcontrolador compatível com Arduino.

Usando o **JTAGenum**, você primeiro **define os pinos da sonda** do dispositivo que você usará para a enumeração. Você terá que fazer referência ao diagrama de pinout do dispositivo e, em seguida, conectar esses pinos aos pontos de teste em seu dispositivo de destino.

Uma **terceira maneira** de identificar pinos JTAG é **inspecionando a PCB** para um dos pinouts. Em alguns casos, as PCBs podem fornecer convenientemente a **interface Tag-Connect**, que é uma indicação clara de que a placa possui um conector JTAG. Você pode ver como essa interface se parece em [https://www.tag-connect.com/info/](https://www.tag-connect.com/info/). Além disso, a inspeção dos **datasheets dos chipsets na PCB** pode revelar diagramas de pinout que apontam para interfaces JTAG.

# SDW

O SWD é um protocolo específico da ARM projetado para depuração.

A interface SWD requer **dois pinos**: um sinal bidirecional **SWDIO**, que é o equivalente aos pinos **TDI e TDO** do JTAG e um relógio, e **SWCLK**, que é o equivalente a **TCK** no JTAG. Muitos dispositivos suportam a **Porta de Depuração Serial ou JTAG (SWJ-DP)**, uma interface JTAG e SWD combinada que permite conectar uma sonda SWD ou JTAG ao alvo.
