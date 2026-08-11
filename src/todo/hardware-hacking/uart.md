# UART

{{#include ../../banners/hacktricks-training.md}}

## Informações básicas

UART é uma interface serial assíncrona que transfere um fluxo de bits enquadrado sem um clock compartilhado. Não confunda UART em nível lógico com RS-232: RS-232 usa níveis de tensão diferentes, frequentemente negativos, e requer um transceiver.<sup>[[1]](#references)[[3]](#references)</sup>

Geralmente, a linha é mantida em nível alto (valor lógico 1) enquanto UART está no estado ocioso. Então, para sinalizar o início de uma transferência de dados, o transmissor envia um bit de início ao receptor, durante o qual o sinal é mantido em nível baixo (valor lógico 0). Em seguida, o transmissor envia de cinco a oito bits de dados contendo a mensagem real, seguidos por um bit de paridade opcional e um ou dois bits de parada (com valor lógico 1), dependendo da configuração. O bit de paridade, usado para verificação de erros, raramente é visto na prática. O bit (ou bits) de parada indica o fim da transmissão.

A configuração mais comum é 8N1: oito bits de dados, sem paridade e um bit de parada. UART envia primeiro o bit de dados menos significativo, portanto, o ASCII `C` (`0x43`) é transmitido como: início `0`; dados `1, 1, 0, 0, 0, 0, 1, 0`; parada `1`.<sup>[[1]](#references)</sup>

![UART: Chamamos a configuração mais comum de 8N1: oito bits de dados, sem paridade e um bit de parada. Por exemplo, se quiséssemos enviar o caractere C, ou 0x43 em ASCII, em uma UART 8N1](<../../images/image (764).png>)

Ferramentas de hardware para se comunicar com UART:

- Adaptador USB para serial
- Adaptadores com os chips CP2102 ou PL2303
- Ferramenta multipropósito, como: Bus Pirate, Adafruit FT232H, Shikra ou Attify Badge

### Identificando portas UART

Um header de debug típico expõe **TX**, **RX** e **GND**; ele também pode expor um pino **Vcc/Vref**, reset ou pinos de controle de fluxo. Vcc não é um sinal UART e normalmente deve ser usado apenas como referência de tensão — não conectado como fonte de alimentação — a menos que o esquema da placa e os requisitos de corrente sejam conhecidos.<sup>[[2]](#references)[[3]](#references)</sup>

Comece com o dispositivo **desligado** e desconectado:

- Identifique **GND** no modo de continuidade em relação a um plano de terra conhecido, à blindagem de um conector ou ao terra da fonte. Nunca use o modo de continuidade/resistência em uma placa energizada.
- Mude para o modo de tensão DC antes de ligar o alvo. Meça os pinos candidatos em relação ao terra para identificar a tensão lógica. Um rail estável pode ser Vcc/Vref; não presuma que seja seguro conectá-lo.
- Observe os candidatos com um analisador lógico ou osciloscópio durante o boot. **TX** normalmente fica em nível alto quando ocioso e apresenta rajadas de dados enquadrados. Um multímetro pode mostrar uma oscilação média, mas não consegue validar o enquadramento ou a baud rate.
- **RX** pode permanecer ocioso e não pode ser identificado com segurança apenas por estar próximo de TX. Rastreie a PCB, consulte o datasheet do SoC ou use um analisador de alta impedância antes de acioná-lo.

A troca de TX e RX normalmente não produz comunicação; confundir alimentação, terra ou níveis de sinal pode danificar permanentemente o alvo ou o adaptador. Conecte o terra primeiro e comece em modo **somente recepção** (TX do alvo para RX do adaptador).

Os fabricantes podem omitir o header, deixar resistores em série sem montagem, desabilitar o console no firmware ou expor apenas TX. Rastreie os test pads e footprints de resistores próximos até o SoC e adicione uma conexão temporária de alta impedância somente após confirmar o nível elétrico. A presença de uma garantia não implica que uma UART acessível necessariamente exista.

### Identificando a baud rate da UART

A maneira mais fácil de identificar a baud rate correta é observar a saída do pino **TX** e tentar ler os dados. Se os dados recebidos não forem legíveis, mude para a próxima baud rate possível até que os dados se tornem legíveis. Você pode usar um adaptador USB para serial ou um dispositivo multipropósito como o Bus Pirate para fazer isso, junto com um helper script, como [baudrate.py](https://github.com/devttys0/baudrate/). As baud rates mais comuns são 9600, 38400, 19200, 57600 e 115200.

> [!CAUTION]
> É importante observar que, neste protocolo, você precisa conectar o TX de um dispositivo ao RX do outro!

## Adaptador CP210X UART para TTY

As bridges USB para UART CP210x aparecem em muitas placas de prototipagem e adaptadores baratos. Módulos comuns expõem pinos de alimentação junto com GND, RXD e TXD, mas seus headers e níveis de I/O variam. Confirme a tensão real com base no design da placa ou no data sheet. Normalmente, conecte apenas GND, RX do adaptador ao TX do alvo e — após a validação em modo somente recepção — TX do adaptador ao RX do alvo. Não conecte o pino de alimentação de 5 V/3,3 V do adaptador, a menos que esteja alimentando intencionalmente um alvo conhecido por tolerá-lo.<sup>[[3]](#references)</sup>

Caso o adaptador não seja detectado, verifique se os drivers CP210X estão instalados no sistema host. Depois que o adaptador for detectado e conectado, ferramentas como picocom, minicom ou screen podem ser usadas.

Para listar os dispositivos conectados a sistemas Linux/MacOS:
```
ls /dev/
```
Para interação básica com a interface UART, use o seguinte comando:
```
picocom /dev/<adapter> --baud <baudrate>
```
Para o minicom, use o seguinte comando para configurá-lo:
```
minicom -s
```
Configure as opções, como baudrate e nome do dispositivo, em `Serial port setup`.

Após a configuração, execute `minicom` para abrir o console UART.

## UART Via Arduino UNO R3 (Placas com Chip Atmel 328p Removível)

Caso adaptadores UART Serial para USB não estejam disponíveis, o Arduino UNO R3 pode ser usado com um hack rápido. Como o Arduino UNO R3 geralmente está disponível em qualquer lugar, isso pode economizar bastante tempo.

O Arduino UNO R3 tem um adaptador USB para Serial integrado na própria placa. Para obter uma conexão UART, basta remover o microcontrolador Atmel 328p da placa. Esse hack funciona nas variantes do Arduino UNO R3 que possuem o Atmel 328p não soldado na placa (a versão SMD o utiliza). Conecte o pino RX do Arduino (Digital Pin 0) ao pino TX da interface UART e o pino TX do Arduino (Digital Pin 1) ao pino RX da interface UART.

Use o **Serial Monitor** da Arduino IDE ou um terminal dedicado com a baudrate de destino. Os sinais seriais do Uno R3 clássico usam lógica de 5 V; portanto, use um level shifter ou divisor antes de conectá-los a um dispositivo de destino de 3,3 V ou com tensão inferior.

## Bus Pirate

A transcrição a seguir usa a interface de firmware legada do Bus Pirate para monitorar a saída UART. Versões mais recentes do firmware do Bus Pirate usam comandos como `m uart`, `{`/`}`, `monitor` ou `bridge`; consulte a documentação da versão instalada.<sup>[[2]](#references)</sup>
```bash
# Check the modes
UART>m
1. HiZ
2. 1-WIRE
3. UART
4. I2C
5. SPI
6. 2WIRE
7. 3WIRE
8. KEYB
9. LCD
10. PIC
11. DIO
x. exit(without change)

# Select UART
(1)>3
Set serial port speed: (bps)
1. 300
2. 1200
3. 2400
4. 4800
5. 9600
6. 19200
7. 38400
8. 57600
9. 115200
10. BRG raw value

# Select the speed the communication is occurring on (you BF all this until you find readable things)
# Or you could later use the macro (4) to try to find the speed
(1)>5
Data bits and parity:
1. 8, NONE *default
2. 8, EVEN
3. 8, ODD
4. 9, NONE

# From now on pulse enter for default
(1)>
Stop bits:
1. 1 *default
2. 2
(1)>
Receive polarity:
1. Idle 1 *default
2. Idle 0
(1)>
Select output type:
1. Open drain (H=Hi-Z, L=GND)
2. Normal (H=3.3V, L=GND)

(1)>
Clutch disengaged!!!
To finish setup, start up the power supplies with command 'W'
Ready

# Start
UART>W
POWER SUPPLIES ON
Clutch engaged!!!

# Use macro (2) to read the data of the bus (live monitor)
UART>(2)
Raw UART input
Any key to exit
Escritura inicial completada:
AAA Hi Dreg! AAA
waiting a few secs to repeat....
```
## Extraindo Firmware com Console UART

Um console UART fornece acesso em tempo de execução aos logs de inicialização e, às vezes, a um shell do bootloader ou do sistema operacional. Mesmo um console somente leitura revela mapas de memória, drivers de flash, argumentos de inicialização, layouts de partições e versões do firmware. O firmware pode estar armazenado em SPI NOR/NAND, eMMC ou outro dispositivo; em geral, ele não é executado a partir de uma EEPROM, e os arquivos gravados em um sistema de arquivos persistente montado não necessariamente desaparecem após uma reinicialização.

Há vários caminhos de aquisição, e a seção sobre SPI aborda leituras diretas de flash externa. A aquisição auxiliada pelo console pode ser menos invasiva quando o bootloader já fornece um comando de leitura seguro, mas qualquer interrupção da inicialização ou comando de flash pode afetar a disponibilidade; portanto, registre o estado original e evite operações de gravação/eliminação.

A extração de firmware auxiliada pelo console geralmente começa interrompendo um bootloader. Muitos dispositivos Linux embarcados usam o **Das U-Boot**, mas outros usam bootloaders proprietários ou desabilitam o console interativo.

Para testar a existência de um bootloader interativo, conecte o caminho de recepção UART e o terminal enquanto o alvo estiver desligado, inicie o registro e ligue-o. Siga o prompt de autoboot exibido; dependendo da compilação, a interrupção pode exigir uma tecla, uma sequência curta ou pode estar totalmente desabilitada.

Se a interrupção for bem-sucedida, use `help`, `printenv` e comandos de descoberta somente leitura para entender o layout de memória e armazenamento específico daquele fornecedor antes de acessar endereços.

No U-Boot, `md` exibe **memória endereçável**, e não automaticamente “a EEPROM”. Primeiro, use comandos específicos da placa, como `mtd list`, `sf probe`, `mmc info`, `part list`, variáveis de ambiente e logs de inicialização para identificar o endereço mapeado correto ou carregar uma região de flash na RAM. Em seguida, exiba um intervalo conhecido byte a byte:<sup>[[4]](#references)</sup>
```
md.b <address> <byte_count>
```
Registre a saída serial antes de iniciar. A saída de `md.b` contém endereços e uma coluna ASCII, portanto é uma representação textual, e não uma imagem ROM bruta.

Remova as colunas de endereço e ASCII, concatene apenas os campos de bytes hexadecimais e decodifique-os para binário (por exemplo, com `xxd -r -p`). Verifique a quantidade esperada de bytes e registre um hash antes da análise:
```
xxd -r -p firmware.hex > firmware.bin
sha256sum firmware.bin
binwalk -e firmware.bin
```
O Binwalk então identifica assinaturas conhecidas no binário reconstruído. Uma leitura direta da flash pela interface SPI/eMMC/NAND apropriada geralmente é mais rápida e menos propensa a erros quando o console não consegue transferir dados de forma confiável.

O U-Boot pode desabilitar a interrupção, exigir uma sequência de teclas específica do vendor ou bloquear comandos de memória/flash. Siga o prompt de autoboot e o log de boot em vez de transmitir caracteres às cegas. Se o console não puder ser interrompido, preserve o log de boot e use um caminho não invasivo para aquisição do firmware.

## References

- [1] [Manual de Referência da Família Microchip PIC32 - UART](https://ww1.microchip.com/downloads/en/DeviceDoc/60001107H.pdf)
- [2] [Documentação do Bus Pirate - modo UART e limites elétricos](https://docs.buspirate.com/docs/command-reference/#uart)
- [3] [Silicon Labs - folha de dados do CP2102C](https://www.silabs.com/documents/public/data-sheets/cp2102c-datasheet.pdf)
- [4] [Documentação do U-Boot - comando `md` para exibição de memória](https://docs.u-boot.org/en/latest/usage/cmd/md.html)
{{#include ../../banners/hacktricks-training.md}}
