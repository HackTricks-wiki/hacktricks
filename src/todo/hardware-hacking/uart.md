# UART

{{#include ../../banners/hacktricks-training.md}}

## Informações básicas

UART é um protocolo serial, o que significa que transfere dados entre componentes um bit por vez. Em contraste, os protocolos de comunicação paralela transmitem dados simultaneamente por vários canais. Protocolos seriais comuns incluem RS-232, I2C, SPI, CAN, Ethernet, HDMI, PCI Express e USB.

Geralmente, a linha é mantida em nível alto (valor lógico 1) enquanto UART está no estado ocioso. Então, para sinalizar o início de uma transferência de dados, o transmissor envia um bit de início ao receptor, durante o qual o sinal é mantido em nível baixo (valor lógico 0). Em seguida, o transmissor envia de cinco a oito bits de dados contendo a mensagem real, seguidos por um bit de paridade opcional e um ou dois bits de parada (com valor lógico 1), dependendo da configuração. O bit de paridade, usado para verificação de erros, raramente é visto na prática. O bit (ou bits) de parada indica o fim da transmissão.

Chamamos a configuração mais comum de 8N1: oito bits de dados, sem paridade e um bit de parada. Por exemplo, se quiséssemos enviar o caractere C, ou 0x43 em ASCII, em uma configuração UART 8N1, enviaríamos os seguintes bits: 0 (o bit de início); 0, 1, 0, 0, 0, 0, 1, 1 (o valor de 0x43 em binário); e 0 (o bit de parada).

![UART: Chamamos a configuração mais comum de 8N1: oito bits de dados, sem paridade e um bit de parada. Por exemplo, se quiséssemos enviar o caractere C, ou 0x43 em ASCII, em uma configuração UART 8N1](<../../images/image (764).png>)

Ferramentas de hardware para se comunicar com UART:

- Adaptador USB-serial
- Adaptadores com os chips CP2102 ou PL2303
- Ferramenta multipropósito, como: Bus Pirate, Adafruit FT232H, Shikra ou Attify Badge

### Identificando portas UART

UART tem 4 portas: **TX** (Transmissão), **RX** (Recepção), **Vcc** (Tensão) e **GND** (Terra). Você pode conseguir encontrar 4 portas com as letras **`TX`** e **`RX`** **escritas** na PCB. Mas, se não houver indicação, talvez seja necessário tentar encontrá-las usando um **multímetro** ou um **analisador lógico**.

Com um **multímetro** e o dispositivo desligado:

- Para identificar o pino **GND**, use o modo **Teste de Continuidade**, coloque a ponta preta no terra e teste com a vermelha até ouvir um som do multímetro. Vários pinos GND podem ser encontrados na PCB, então você pode ter encontrado ou não o pertencente à UART.
- Para identificar a **porta VCC**, selecione o **modo de tensão DC** e configure-o para 20 V. Coloque a ponta preta no terra e a vermelha no pino. Ligue o dispositivo. Se o multímetro medir uma tensão constante de 3,3 V ou 5 V, você encontrou o pino Vcc. Se obtiver outras tensões, tente novamente com outras portas.
- Para identificar a **porta TX**, use o **modo de tensão DC** de até 20 V, coloque a ponta preta no terra e a vermelha no pino, e ligue o dispositivo. Se a tensão variar por alguns segundos e depois estabilizar no valor de Vcc, provavelmente você encontrou a porta TX. Isso ocorre porque, ao ligar, o dispositivo envia alguns dados de debug.
- A **porta RX** seria a mais próxima das outras 3; ela apresenta a menor variação de tensão e o menor valor geral entre todos os pinos UART.

Você pode confundir as portas TX e RX e nada acontecerá, mas, se confundir as portas GND e VCC, poderá queimar o circuito.

Em alguns dispositivos-alvo, a porta UART é desabilitada pelo fabricante ao desabilitar RX ou TX, ou até mesmo ambos. Nesse caso, pode ser útil rastrear as conexões na placa de circuito e encontrar algum ponto de breakout. Uma forte indicação para confirmar a não detecção de UART e a interrupção do circuito é verificar a garantia do dispositivo. Se o dispositivo tiver sido enviado com alguma garantia, o fabricante deixa algumas interfaces de debug (neste caso, UART) e, portanto, deve ter desconectado a UART, conectando-a novamente durante o debug. Esses pinos de breakout podem ser conectados por soldagem ou fios jumper.

### Identificando a taxa de baud da UART

A maneira mais fácil de identificar a taxa de baud correta é observar a saída do **pino TX e tentar ler os dados**. Se os dados recebidos não forem legíveis, alterne para a próxima taxa de baud possível até que os dados se tornem legíveis. Você pode usar um adaptador USB-serial ou um dispositivo multipropósito, como o Bus Pirate, junto com um script auxiliar, como [baudrate.py](https://github.com/devttys0/baudrate/). As taxas de baud mais comuns são 9600, 38400, 19200, 57600 e 115200.

> [!CAUTION]
> É importante observar que, neste protocolo, você precisa conectar o TX de um dispositivo ao RX do outro!

## Adaptador CP210X UART para TTY

O chip CP210X é usado em muitas placas de prototipagem, como a NodeMCU (com esp8266), para comunicação serial. Esses adaptadores são relativamente baratos e podem ser usados para conectar-se à interface UART do alvo. O dispositivo tem 5 pinos: 5V, GND, RXD, TXD e 3.3V. Certifique-se de conectar a tensão compatível com o alvo para evitar danos. Por fim, conecte o pino RXD do adaptador ao TXD do alvo e o pino TXD do adaptador ao RXD do alvo.

Caso o adaptador não seja detectado, certifique-se de que os drivers CP210X estejam instalados no sistema host. Depois que o adaptador for detectado e conectado, ferramentas como picocom, minicom ou screen podem ser usadas.

Para listar os dispositivos conectados aos sistemas Linux/MacOS:
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
Configure as configurações, como baudrate e nome do dispositivo, na opção `Serial port setup`.

Após a configuração, use o comando `minicom` para iniciar e obter o UART Console.

## UART via Arduino UNO R3 (placas com chip Atmel 328p removível)

Caso adaptadores UART Serial para USB não estejam disponíveis, o Arduino UNO R3 pode ser usado com um hack rápido. Como o Arduino UNO R3 geralmente está disponível em qualquer lugar, isso pode economizar bastante tempo.

O Arduino UNO R3 possui um adaptador USB para Serial integrado à própria placa. Para obter uma conexão UART, basta retirar o chip microcontrolador Atmel 328p da placa. Esse hack funciona nas variantes do Arduino UNO R3 que possuem o Atmel 328p não soldado à placa (a versão SMD é usada nele). Conecte o pino RX do Arduino (pino digital 0) ao pino TX da interface UART e o pino TX do Arduino (pino digital 1) ao pino RX da interface UART.

Por fim, recomenda-se usar o Arduino IDE para obter o Serial Console. Na seção `tools` do menu, selecione a opção `Serial Console` e defina o baud rate de acordo com a interface UART.

## Bus Pirate

Neste cenário, vamos sniffar a comunicação UART do Arduino, que está enviando todas as mensagens do programa para o Serial Monitor.
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
## Dumping Firmware com UART Console

A UART Console oferece uma ótima forma de trabalhar com o firmware subjacente em um ambiente de runtime. Porém, quando o acesso à UART Console é somente leitura, isso pode introduzir muitas restrições. Em muitos dispositivos embarcados, o firmware é armazenado em EEPROMs e executado em processadores que possuem memória volátil. Portanto, o firmware é mantido somente para leitura, pois o firmware original durante a fabricação está dentro da própria EEPROM, e quaisquer arquivos novos seriam perdidos devido à memória volátil. Assim, fazer o dump do firmware é uma atividade valiosa ao trabalhar com firmwares embarcados.

Há várias formas de fazer isso, e a seção sobre SPI aborda métodos para extrair o firmware diretamente da EEPROM usando diversos dispositivos. No entanto, recomenda-se tentar primeiro fazer o dump do firmware com UART, pois fazer o dump do firmware com dispositivos físicos e interações externas pode ser arriscado.

Fazer o dump do firmware a partir da UART Console exige primeiro obter acesso aos bootloaders. Muitos vendors populares usam o uboot (Universal Bootloader) como bootloader para carregar o Linux. Portanto, obter acesso ao uboot é necessário.

Para obter acesso ao bootloader, conecte a porta UART ao computador e use qualquer uma das ferramentas de Serial Console, mantendo a fonte de alimentação do dispositivo desconectada. Quando a configuração estiver pronta, pressione a tecla Enter e mantenha-a pressionada. Por fim, conecte a fonte de alimentação ao dispositivo e deixe-o inicializar.

Isso interromperá o carregamento do uboot e exibirá um menu. Recomenda-se entender os comandos do uboot e usar o menu de ajuda para listá-los. Esse comando pode ser `help`. Como vendors diferentes usam configurações diferentes, é necessário entender cada uma separadamente.

Normalmente, o comando para fazer o dump do firmware é:
```
md
```
que significa "memory dump". Isso exibirá a memória (conteúdo da EEPROM) na tela. É recomendável registrar a saída do Serial Console antes de iniciar o procedimento para capturar o memory dump.

Por fim, basta remover todos os dados desnecessários do arquivo de log, salvá-lo como `filename.rom` e usar o binwalk para extrair o conteúdo:
```
binwalk -e <filename.rom>
```
Isso listará os possíveis conteúdos da EEPROM de acordo com as assinaturas encontradas no arquivo hex.

No entanto, é necessário observar que nem sempre o uboot está desbloqueado, mesmo quando está sendo usado. Se a tecla Enter não fizer nada, verifique outras teclas, como a tecla Espaço, etc. Se o bootloader estiver bloqueado e não for interrompido, este método não funcionará. Para verificar se o uboot é o bootloader do dispositivo, verifique a saída no Console UART durante a inicialização do dispositivo. Ele pode mencionar o uboot durante a inicialização.

{{#include ../../banners/hacktricks-training.md}}
