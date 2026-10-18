# UART

{{#include ../../banners/hacktricks-training.md}}

## Informações básicas

UART é uma interface serial assíncrona que transfere um fluxo de bits enquadrado sem um clock compartilhado. Não confunda UART em nível lógico com RS-232: RS-232 usa níveis de tensão diferentes, geralmente negativos, e requer um transceiver.<sup>[[1]](#references)[[3]](#references)</sup>

Em geral, a linha permanece em nível alto (valor lógico 1) enquanto a UART está no estado ocioso. Para sinalizar o início de uma transferência de dados, o transmissor envia um bit de início ao receptor, durante o qual o sinal permanece em nível baixo (valor lógico 0). Em seguida, o transmissor envia de cinco a oito bits de dados contendo a mensagem propriamente dita, seguidos por um bit de paridade opcional e um ou dois bits de parada (com valor lógico 1), dependendo da configuração. O bit de paridade, usado para verificar erros, raramente é visto na prática. O(s) bit(s) de parada indicam o fim da transmissão.

A configuração mais comum é 8N1: oito bits de dados, sem paridade e um bit de parada. UART envia primeiro o bit de dados menos significativo, então o caractere ASCII `C` (`0x43`) é transmitido como: início `0`; dados `1, 1, 0, 0, 0, 0, 1, 0`; parada `1`.<sup>[[1]](#references)</sup>

![UART: Chamamos de 8N1 a configuração mais comum: oito bits de dados, sem paridade e um bit de parada. Por exemplo, se quiséssemos enviar o caractere C, ou 0x43 em ASCII, usando UART 8N1](<../../images/image (764).png>)

Ferramentas de hardware para se comunicar com UART:

- Adaptador USB-serial
- Adaptadores com os chips CP2102 ou PL2303
- Ferramenta multifuncional, como: Bus Pirate, Adafruit FT232H, Shikra ou Attify Badge

### Identificando portas UART

Um header de depuração típico expõe **TX**, **RX** e **GND**; ele também pode expor um pino **Vcc/Vref**, reset ou pinos de controle de fluxo. Vcc não é um sinal UART e normalmente deve ser usado apenas como referência de tensão — não conectado como fonte de alimentação — a menos que o esquema da placa e os requisitos de corrente sejam conhecidos.<sup>[[2]](#references)[[3]](#references)</sup>

Comece com o dispositivo **desligado** e desconectado:

- Identifique **GND** no modo de continuidade, comparando-o com um plano de terra conhecido, a blindagem de um conector ou o terra da alimentação. Nunca use o modo de continuidade/resistência em uma placa energizada.
- Mude para o modo de tensão DC antes de ligar o alvo. Meça os pinos candidatos em relação ao terra para identificar a tensão lógica. Um nível de tensão estável pode ser Vcc/Vref; não presuma que seja seguro conectá-lo.
- Observe os pinos candidatos com um analisador lógico ou osciloscópio durante a inicialização. **TX** normalmente fica em nível alto quando ocioso e apresenta rajadas de dados enquadrados. Um multímetro pode mostrar uma variação média, mas não consegue validar o enquadramento nem a baud rate.
- **RX** pode permanecer ocioso e não pode ser identificado com segurança apenas por estar ao lado de TX. Rastreie a PCB, consulte a folha de dados do SoC ou use um analisador de alta impedância antes de aplicar sinais nele.

Trocar TX e RX normalmente resulta em ausência de comunicação; confundir alimentação, terra ou níveis de sinal pode danificar permanentemente o alvo ou o adaptador. Conecte o terra primeiro e comece **somente recebendo** (TX do alvo para RX do adaptador).

Os fabricantes podem omitir o header, deixar resistores em série sem montagem, desativar o console no firmware ou expor apenas TX. Rastreie os test pads próximos e os footprints dos resistores até o SoC e adicione uma conexão temporária de alta impedância somente após confirmar o nível elétrico. A existência de uma garantia não significa que uma UART acessível necessariamente esteja disponível.

### Recuperando um pad TX que parece estar em nível baixo

Um pad TX identificado que permanece em nível baixo na captura inicial do osciloscópio não é motivo suficiente para descartar a possibilidade de UART. Após confirmar a tensão lógica do alvo e uma conexão de terra comum, tente um pull-up fraco (o exemplo documentado usou **10 kΩ para 3.3 V**) e repita a captura enquanto pressiona botões ou inicializa o dispositivo. Use somente o rail lógico verificado do alvo; não conecte um pull-up a um sinal desconhecido ou acionado ativamente. Se surgirem transições enquadradas, meça o período de bit limpo mais curto para estimar a baud rate antes de conectar o pad, somente para recepção, a um adaptador serial. No exemplo, isso recuperou logs de eventos de botões a 115200 baud, mas não expôs um dump de firmware.<sup>[[8]](#references)</sup>

### Identificando a baud rate da UART

A maneira mais fácil de identificar a baud rate correta é observar a saída do pino **TX** e tentar ler os dados. Se os dados recebidos não forem legíveis, tente a próxima baud rate possível até que os dados se tornem legíveis. Você pode usar um adaptador USB-serial ou um dispositivo multifuncional, como o Bus Pirate, junto com um script auxiliar, como [baudrate.py](https://github.com/devttys0/baudrate/). As baud rates mais comuns são 9600, 38400, 19200, 57600 e 115200.

> [!CAUTION]
> É importante lembrar que, neste protocolo, você precisa conectar o TX de um dispositivo ao RX do outro!

### Automatizando a captura UART durante a inicialização com SCPI

Se a saída de inicialização for breve ou o pad TX ainda for desconhecido, automatize várias inicializações em vez de operar a fonte de alimentação e o osciloscópio manualmente. Conecte uma fonte programável com limite de corrente à entrada de alimentação verificada do alvo. Sonde cada pad TX candidato com uma entrada de osciloscópio de alta impedância e terra compartilhado; não acione o pad.<sup>[[5]](#references)</sup>

VISA abre sessões de instrumentos seriais ou Ethernet, enquanto SCPI controla a saída, o trigger e a leitura da forma de onda.<sup>[[5]](#references)[[6]](#references)</sup> Instale `pyvisa` e `pyvisa-py` (além de `pyserial` para recursos VISA seriais); `ResourceManager('@py')` seleciona explicitamente o backend Python.<sup>[[5]](#references)[[7]](#references)</sup> Substitua as strings de recursos e os comandos pelos suportados pelos instrumentos usados.<sup>[[5]](#references)</sup>

No exemplo com o Rigol MSO5000, arme um trigger de borda de descida única antes de ligar a placa: o TX de uma UART normalmente ociosa em nível alto primeiro cai para enviar o bit de início.<sup>[[5]](#references)</sup> Defina o limiar do trigger entre os níveis medidos de ociosidade e baixo, e ajuste a base de tempo para abranger o intervalo de inicialização desejado.<sup>[[5]](#references)[[6]](#references)</sup> `:TRIG:HOLD` pode suprimir bordas repetidas em capturas contínuas, mas não substitui a verificação de que uma captura de disparo único foi concluída de fato.<sup>[[5]](#references)</sup> O código a seguir captura uma inicialização e salva tanto as amostras de bytes sem sinal quanto os metadados de escala; em caso de timeout, desliga o alvo em vez de esperar indefinidamente.<sup>[[5]](#references)[[6]](#references)</sup>

<details>
<summary>Captura de forma de onda UART de disparo único ao ligar usando PyVISA</summary>

```python
import time
from pathlib import Path
import pyvisa

rm = pyvisa.ResourceManager('@py')
psu = rm.open_resource('ASRL/dev/ttyUSB0::INSTR')
scope = rm.open_resource('TCPIP::192.0.2.10::INSTR')
psu.baud_rate = 115200
scope.timeout = 5000
try:
    print(psu.query('*IDN?').strip(), scope.query('*IDN?').strip())
    psu.write('OUTP OFF')
    psu.write('SOUR:VOLT 3.3')
    psu.write('SOUR:CURR 0.5')
    for cmd in (':CHAN1:DISP ON', ':CHAN1:SCAL 0.5',
                ':TIM:MAIN:SCAL 0.05', ':TRIG:MODE EDGE',
                ':TRIG:EDGE:SOUR CHAN1', ':TRIG:EDGE:LEV 1.5',
                ':TRIG:EDGE:SLOP NEG'):
        scope.write(cmd)
    scope.write(':SING')
    psu.write('OUTP ON')
    deadline = time.monotonic() + 30
    while scope.query(':TRIG:STAT?').strip() != 'STOP':
        if time.monotonic() >= deadline:
            raise TimeoutError('No single-shot trigger')
        time.sleep(0.5)
    scope.write(':WAV:SOUR CHAN1')
    scope.write(':WAV:MODE RAW')
    scope.write(':WAV:FORM BYTE')
    preamble = scope.query(':WAV:PRE?').strip()
    points = int(preamble.split(',')[2])
    scope.write(f':WAV:POIN {points}')
    scope.write(':WAV:STAR 1')
    scope.write(f':WAV:STOP {points}')
    scope.timeout = 120000
    raw = scope.query_binary_values(':WAV:DATA?', datatype='B', container=bytes)
    if len(raw) != points:
        raise ValueError('Incomplete waveform; use instrument-specific batch reads')
    Path('capture.bin').write_bytes(raw)
    Path('capture_preamble.txt').write_text(preamble + '\n')
finally:
    psu.write('OUTP OFF')
    scope.close()
    psu.close()
    rm.close()
```

</details>

Para fazer um levantamento dos pads, repita a captura de disparo único após mover a sonda, ou mantenha a sessão de alimentação aberta e alterne a saída, usando um intervalo de boot e um intervalo desligado. Rearme o osciloscópio antes de cada inicialização para que cada arquivo corresponda a um boot e a um pad.<sup>[[5]](#references)</sup>

O preâmbulo Rigol é `<format>,<type>,<points>,<count>,<xincrement>,...`.<sup>[[6]](#references)</sup> O **terceiro** valor é o número de pontos, não a taxa de amostragem, como afirma o artigo.<sup>[[5]](#references)[[6]](#references)</sup> No exemplo, `25,000,000` pontos e `xincrement = 2e-8` segundos implicam `1 / xincrement = 50,000,000` amostras por segundo, não 25 MSa/s.<sup>[[5]](#references)[[6]](#references)</sup> Mantenha o preâmbulo junto ao arquivo binário e verifique se o comprimento dos dados lidos corresponde a `<points>`; o guia documenta leituras segmentadas/em lotes para registros grandes.<sup>[[6]](#references)</sup>

Para decodificar o sinal capturado, importe `capture.bin` no PulseView como **Raw Analog Data Without Header**, selecione valores unsigned de 8 bits (`U8`) e informe a taxa de amostragem calculada a partir de `xincrement`.<sup>[[5]](#references)[[6]](#references)</sup> Aplique **Logic via Threshold** ao canal analógico, escolhendo um limiar entre os valores baixos e altos da amostra.<sup>[[5]](#references)</sup> Meça a largura de um bit de início nítido para estimar a taxa de baud (cerca de 17,36 µs para 57.600 baud); em seguida, aplique o decodificador UART do PulseView e verifique se vários quadros são decodificados de forma consistente.<sup>[[5]](#references)</sup> Uma borda descendente, por si só, não prova que um pad seja UART.

## Adaptador CP210X UART para TTY

As pontes USB para UART CP210x aparecem em muitas placas de prototipagem e adaptadores baratos. Módulos comuns expõem pinos de alimentação junto com GND, RXD e TXD, mas seus headers e níveis de I/O variam. Confirme a tensão real consultando o projeto da placa ou a ficha técnica. Em geral, conecte apenas GND e RX do adaptador a TX do alvo e — após validar somente a recepção — TX do adaptador a RX do alvo. Não conecte o pino de alimentação de 5 V/3,3 V do adaptador, a menos que esteja alimentando intencionalmente um alvo que comprovadamente suporte essa tensão.<sup>[[3]](#references)</sup>

Caso o adaptador não seja detectado, verifique se os drivers CP210X estão instalados no sistema host. Depois que o adaptador for detectado e conectado, podem ser usadas ferramentas como picocom, minicom ou screen.

Para listar os dispositivos conectados a sistemas Linux/MacOS:

```
ls /dev/
```

Para interagir com a interface UART de forma básica, use o seguinte comando:

```
picocom /dev/<adapter> --baud <baudrate>
```

Para configurar o minicom, use o seguinte comando:

```
minicom -s
```

Configure definições como baud rate e nome do dispositivo na opção `Serial port setup`.

Após a configuração, execute `minicom` para abrir o console UART.

## UART via Arduino UNO R3 (placas com chip Atmel 328p removível)

Caso não haja adaptadores UART Serial-USB disponíveis, é possível usar um Arduino UNO R3 com um hack rápido. Como o Arduino UNO R3 costuma estar disponível em qualquer lugar, isso pode economizar bastante tempo.

O Arduino UNO R3 tem um adaptador USB-Serial integrado à própria placa. Para obter uma conexão UART, basta remover da placa o chip microcontrolador Atmel 328p. Este hack funciona com variantes do Arduino UNO R3 em que o Atmel 328p não está soldado à placa (nelas, é usada a versão SMD). Conecte o pino RX do Arduino (pino digital 0) ao pino TX da interface UART e o pino TX do Arduino (pino digital 1) ao pino RX da interface UART.

Use o **Serial Monitor** da Arduino IDE ou um terminal dedicado configurado para a baud rate do dispositivo-alvo. Os sinais seriais do Uno R3 clássico usam lógica de 5 V; portanto, use um conversor de nível lógico ou um divisor de tensão antes de conectá-los a um dispositivo-alvo de 3,3 V ou de tensão inferior.

## Bus Pirate

A transcrição a seguir usa a interface legada do firmware do Bus Pirate para monitorar a saída UART. As versões mais recentes do firmware do Bus Pirate usam comandos como `m uart`, `{`/`}`, `monitor` ou `bridge`; consulte a documentação da versão instalada.<sup>[[2]](#references)</sup>

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

## Extraindo firmware com o console UART

Um console UART oferece acesso em tempo de execução aos logs de inicialização e, às vezes, a um shell do bootloader ou do sistema operacional. Mesmo um console somente leitura revela mapas de memória, drivers de flash, argumentos de inicialização, layouts de partições e versões de firmware. O firmware pode estar em SPI NOR/NAND, eMMC ou outro dispositivo; em geral, ele não é executado a partir de uma EEPROM, e os arquivos gravados em um sistema de arquivos persistente montado não necessariamente desaparecem após a reinicialização.

Há vários métodos de aquisição, e a seção sobre SPI aborda leituras diretas da flash externa. A aquisição assistida pelo console pode ser menos invasiva quando o bootloader já oferece um comando seguro de leitura, mas qualquer interrupção da inicialização ou comando de flash pode afetar a disponibilidade. Portanto, registre o estado original e evite operações de gravação ou apagamento.

A extração de firmware assistida pelo console geralmente começa pela interrupção de um bootloader. Muitos dispositivos Linux embarcados usam o **Das U-Boot**, mas outros usam bootloaders proprietários ou desativam o console interativo.

Para testar se há um bootloader interativo, conecte o caminho de recepção UART e o terminal enquanto o dispositivo-alvo estiver desligado, inicie o registro e ligue-o. Siga o prompt de inicialização automática exibido; dependendo da compilação, a interrupção pode exigir uma tecla, uma sequência curta ou estar totalmente desativada.

Se a interrupção funcionar, use `help`, `printenv` e comandos de descoberta somente leitura para entender o layout de memória e armazenamento daquele fornecedor antes de acessar endereços.

No U-Boot, `md` exibe **memória endereçável**, não automaticamente “a EEPROM”. Primeiro, use comandos específicos da placa, como `mtd list`, `sf probe`, `mmc info`, `part list`, variáveis de ambiente e logs de inicialização para identificar o endereço mapeado correto ou carregar uma região da flash na RAM. Em seguida, exiba um intervalo conhecido byte a byte:<sup>[[4]](#references)</sup>

```
md.b <address> <byte_count>
```

Registre a saída serial antes de começar. A saída de `md.b` contém endereços e uma coluna ASCII, portanto é uma representação textual, não uma imagem ROM bruta.

Remova as colunas de endereço e ASCII, concatene apenas os campos de bytes hexadecimais e decodifique-os para binário (por exemplo, com `xxd -r -p`). Verifique a quantidade de bytes esperada e registre um hash antes da análise:

```
xxd -r -p firmware.hex > firmware.bin
sha256sum firmware.bin
binwalk -e firmware.bin
```

O Binwalk identifica então assinaturas conhecidas no binário reconstruído. Uma leitura direta da flash pela interface SPI/eMMC/NAND apropriada costuma ser mais rápida e menos propensa a erros quando o console não consegue transferir dados de forma confiável.

O U-Boot pode desabilitar a interrupção, exigir uma sequência de teclas específica do fornecedor ou bloquear comandos de memória/flash. Siga o prompt de autoboot e o log de boot em vez de transmitir caracteres às cegas. Se não for possível interromper o console, preserve o log de boot e use um método não invasivo para obter o firmware.

## References

- [1] [Manual de referência da família PIC32 da Microchip - UART](https://ww1.microchip.com/downloads/en/DeviceDoc/60001107H.pdf)
- [2] [Documentação do Bus Pirate - modo UART e limites elétricos](https://docs.buspirate.com/docs/command-reference/#uart)
- [3] [Silicon Labs - folha de dados do CP2102C](https://www.silabs.com/documents/public/data-sheets/cp2102c-datasheet.pdf)
- [4] [Documentação do U-Boot - comando `md` para exibir memória](https://docs.u-boot.org/en/latest/usage/cmd/md.html)
- [5] [VoidStar Security — SCPI e instrumentação de hardware para engenharia reversa, Parte 1](https://voidstarsec.com/blog/scpi-and-hardware-instrumentation-for-reverse-engineers-part-1)
- [6] [Guia de programação do Rigol MSO5000](https://www.batronix.com/files/Rigol/Oszilloskope/MSO5000/MSO5000_ProgrammingGuide_EN-V2.0.pdf)
- [7] [PyVISA — Configuração do backend](https://pyvisa.readthedocs.io/en/latest/introduction/configuring.html)
- [8] [VoidStar Security — Relembrando o hardware hacking, Parte 2](https://voidstarsec.com/blog/brushing-up-part-2)
{{#include ../../banners/hacktricks-training.md}}
