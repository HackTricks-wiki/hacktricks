# UART

{{#include ../../banners/hacktricks-training.md}}

## Informações Básicas

UART é um protocolo serial, o que significa que transfere dados entre componentes um bit de cada vez. Em contraste, os protocolos de comunicação paralela transmitem dados simultaneamente através de múltiplos canais. Protocolos seriais comuns incluem RS-232, I2C, SPI, CAN, Ethernet, HDMI, PCI Express e USB.

Geralmente, a linha é mantida alta (em um valor lógico 1) enquanto o UART está no estado ocioso. Então, para sinalizar o início de uma transferência de dados, o transmissor envia um bit de início para o receptor, durante o qual o sinal é mantido baixo (em um valor lógico 0). Em seguida, o transmissor envia de cinco a oito bits de dados contendo a mensagem real, seguidos por um bit de paridade opcional e um ou dois bits de parada (com um valor lógico 1), dependendo da configuração. O bit de paridade, usado para verificação de erros, raramente é visto na prática. O bit de parada (ou bits) sinaliza o fim da transmissão.

Chamamos a configuração mais comum de 8N1: oito bits de dados, sem paridade e um bit de parada. Por exemplo, se quisermos enviar o caractere C, ou 0x43 em ASCII, em uma configuração UART 8N1, enviaríamos os seguintes bits: 0 (o bit de início); 0, 1, 0, 0, 0, 0, 1, 1 (o valor de 0x43 em binário), e 0 (o bit de parada).

![](<../../images/image (764).png>)

Ferramentas de hardware para se comunicar com UART:

- Adaptador USB-para-serial
- Adaptadores com os chips CP2102 ou PL2303
- Ferramenta multifuncional como: Bus Pirate, o Adafruit FT232H, o Shikra ou o Attify Badge

### Identificando Portas UART

UART tem 4 portas: **TX**(Transmitir), **RX**(Receber), **Vcc**(Tensão), e **GND**(Terra). Você pode ser capaz de encontrar 4 portas com as letras **`TX`** e **`RX`** **escritas** na PCB. Mas se não houver indicação, você pode precisar tentar encontrá-las usando um **multímetro** ou um **analisador lógico**.

Com um **multímetro** e o dispositivo desligado:

- Para identificar o pino **GND**, use o modo de **Teste de Continuidade**, coloque a ponta de prova preta no terra e teste com a vermelha até ouvir um som do multímetro. Vários pinos GND podem ser encontrados na PCB, então você pode ter encontrado ou não o que pertence ao UART.
- Para identificar a **porta VCC**, configure o **modo de tensão DC** e ajuste para 20 V de tensão. Ponta de prova preta no terra e ponta de prova vermelha no pino. Ligue o dispositivo. Se o multímetro medir uma tensão constante de 3.3 V ou 5 V, você encontrou o pino Vcc. Se você obtiver outras tensões, tente com outras portas.
- Para identificar a **porta TX**, configure o **modo de tensão DC** até 20 V de tensão, ponta de prova preta no terra e ponta de prova vermelha no pino, e ligue o dispositivo. Se você perceber que a tensão flutua por alguns segundos e depois se estabiliza no valor Vcc, você provavelmente encontrou a porta TX. Isso ocorre porque ao ligar, ele envia alguns dados de depuração.
- A **porta RX** seria a mais próxima das outras 3, ela tem a menor flutuação de tensão e o menor valor geral de todos os pinos UART.

Você pode confundir as portas TX e RX e nada aconteceria, mas se confundir a porta GND e a VCC, você pode queimar o circuito.

Em alguns dispositivos-alvo, a porta UART é desativada pelo fabricante desativando RX ou TX ou até mesmo ambos. Nesse caso, pode ser útil rastrear as conexões na placa de circuito e encontrar algum ponto de quebra. Uma forte dica sobre a confirmação da não detecção de UART e a quebra do circuito é verificar a garantia do dispositivo. Se o dispositivo foi enviado com alguma garantia, o fabricante deixa algumas interfaces de depuração (neste caso, UART) e, portanto, deve ter desconectado o UART e o reconectaria durante a depuração. Esses pinos de quebra podem ser conectados por soldagem ou fios jumper.

### Identificando a Taxa de Baud do UART

A maneira mais fácil de identificar a taxa de baud correta é observar a **saída do pino TX e tentar ler os dados**. Se os dados que você recebe não forem legíveis, mude para a próxima taxa de baud possível até que os dados se tornem legíveis. Você pode usar um adaptador USB-para-serial ou um dispositivo multifuncional como o Bus Pirate para fazer isso, emparelhado com um script auxiliar, como [baudrate.py](https://github.com/devttys0/baudrate/). As taxas de baud mais comuns são 9600, 38400, 19200, 57600 e 115200.

> [!CAUTION]
> É importante notar que neste protocolo você precisa conectar o TX de um dispositivo ao RX do outro!

## Adaptador CP210X UART para TTY

O Chip CP210X é usado em muitas placas de prototipagem como NodeMCU (com esp8266) para Comunicação Serial. Esses adaptadores são relativamente baratos e podem ser usados para se conectar à interface UART do alvo. O dispositivo tem 5 pinos: 5V, GND, RXD, TXD, 3.3V. Certifique-se de conectar a tensão conforme suportado pelo alvo para evitar danos. Finalmente, conecte o pino RXD do Adaptador ao TXD do alvo e o pino TXD do Adaptador ao RXD do alvo.

Caso o adaptador não seja detectado, certifique-se de que os drivers CP210X estão instalados no sistema host. Uma vez que o adaptador é detectado e conectado, ferramentas como picocom, minicom ou screen podem ser usadas.

Para listar os dispositivos conectados a sistemas Linux/MacOS:
```
ls /dev/
```
Para interação básica com a interface UART, use o seguinte comando:
```
picocom /dev/<adapter> --baud <baudrate>
```
Para minicom, use o seguinte comando para configurá-lo:
```
minicom -s
```
Configure as configurações, como baudrate e nome do dispositivo na opção `Serial port setup`.

Após a configuração, use o comando `minicom` para iniciar o Console UART.

## UART Via Arduino UNO R3 (Placas de Chip Atmel 328p Removíveis)

Caso adaptadores UART Serial para USB não estejam disponíveis, o Arduino UNO R3 pode ser usado com um hack rápido. Como o Arduino UNO R3 geralmente está disponível em qualquer lugar, isso pode economizar muito tempo.

O Arduino UNO R3 possui um adaptador USB para Serial embutido na própria placa. Para obter a conexão UART, basta retirar o chip microcontrolador Atmel 328p da placa. Este hack funciona em variantes do Arduino UNO R3 que têm o Atmel 328p não soldado na placa (a versão SMD é usada nela). Conecte o pino RX do Arduino (Pino Digital 0) ao pino TX da Interface UART e o pino TX do Arduino (Pino Digital 1) ao pino RX da interface UART.

Finalmente, é recomendado usar o Arduino IDE para obter o Console Serial. Na seção `tools` no menu, selecione a opção `Serial Console` e defina a taxa de transmissão de acordo com a interface UART.

## Bus Pirate

Neste cenário, vamos espionar a comunicação UART do Arduino que está enviando todas as impressões do programa para o Serial Monitor.
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
## Dumping Firmware with UART Console

O Console UART fornece uma ótima maneira de trabalhar com o firmware subjacente em um ambiente de tempo de execução. Mas quando o acesso ao Console UART é somente leitura, isso pode introduzir muitas restrições. Em muitos dispositivos embarcados, o firmware é armazenado em EEPROMs e executado em processadores que têm memória volátil. Portanto, o firmware é mantido como somente leitura, uma vez que o firmware original durante a fabricação está dentro da EEPROM e quaisquer novos arquivos seriam perdidos devido à memória volátil. Assim, fazer o dump do firmware é um esforço valioso ao trabalhar com firmwares embarcados.

Existem muitas maneiras de fazer isso e a seção SPI cobre métodos para extrair firmware diretamente da EEPROM com vários dispositivos. Embora seja recomendado primeiro tentar fazer o dump do firmware com UART, uma vez que fazer o dump do firmware com dispositivos físicos e interações externas pode ser arriscado.

Fazer o dump do firmware do Console UART requer primeiro obter acesso aos bootloaders. Muitos fornecedores populares utilizam o uboot (Universal Bootloader) como seu bootloader para carregar o Linux. Portanto, obter acesso ao uboot é necessário.

Para obter acesso ao bootloader, conecte a porta UART ao computador e use qualquer uma das ferramentas de Console Serial, mantendo a fonte de alimentação do dispositivo desconectada. Uma vez que a configuração esteja pronta, pressione a tecla Enter e mantenha-a pressionada. Finalmente, conecte a fonte de alimentação ao dispositivo e deixe-o inicializar.

Fazer isso interromperá o carregamento do uboot e fornecerá um menu. É recomendado entender os comandos do uboot e usar o menu de ajuda para listá-los. Isso pode ser o comando `help`. Como diferentes fornecedores usam diferentes configurações, é necessário entender cada um deles separadamente.

Geralmente, o comando para fazer o dump do firmware é:
```
md
```
que significa "dump de memória". Isso irá despejar a memória (Conteúdo da EEPROM) na tela. É recomendável registrar a saída do Console Serial antes de iniciar o procedimento para capturar o dump de memória.

Finalmente, basta remover todos os dados desnecessários do arquivo de log e armazenar o arquivo como `filename.rom` e usar binwalk para extrair o conteúdo:
```
binwalk -e <filename.rom>
```
Isso listará os possíveis conteúdos da EEPROM de acordo com as assinaturas encontradas no arquivo hex.

Embora seja necessário notar que nem sempre o uboot está desbloqueado, mesmo que esteja sendo usado. Se a tecla Enter não fizer nada, verifique outras teclas como a tecla Espaço, etc. Se o bootloader estiver bloqueado e não for interrompido, este método não funcionará. Para verificar se o uboot é o bootloader do dispositivo, verifique a saída no Console UART durante a inicialização do dispositivo. Pode mencionar uboot durante a inicialização.

{{#include ../../banners/hacktricks-training.md}}
