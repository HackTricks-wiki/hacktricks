# UART

{{#include ../../banners/hacktricks-training.md}}

## 基本情報

UARTはシリアルプロトコルです。つまり、コンポーネント間で一度に1ビットずつデータを転送します。これに対して、パラレル通信プロトコルは複数のチャネルを通じてデータを同時に送信します。一般的なシリアルプロトコルには、RS-232、I2C、SPI、CAN、Ethernet、HDMI、PCI Express、USBなどがあります。

通常、UARTがアイドル状態のとき、ラインはHigh（論理値1）に保持されます。次に、データ転送の開始を知らせるため、送信側は受信側にstart bitを送信します。この間、信号はLow（論理値0）に保持されます。その後、送信側は実際のメッセージを含む5～8個のdata bitを送信し、設定に応じて、オプションのparity bitと1個または2個のstop bit（論理値1）が続きます。エラーチェックに使用されるparity bitは、実際にはほとんど見られません。stop bit（または複数のstop bit）は送信の終了を示します。

最も一般的な設定を8N1と呼びます。これは、8個のdata bit、parityなし、1個のstop bitを意味します。たとえば、文字C、つまりASCIIで0x43を8N1 UART設定で送信する場合、次のビットを送信します：0（start bit）、0、1、0、0、0、0、1、1（0x43の2進値）、そして0（stop bit）。

![UART: 最も一般的な設定を8N1と呼びます。これは、8個のdata bit、parityなし、1個のstop bitを意味します。たとえば、文字C、つまりASCIIで0x43を8N1 UART設定で送信する場合](<../../images/image (764).png>)

UARTと通信するためのHardware tools：

- USB-to-serial adapter
- CP2102またはPL2303チップを搭載したAdapter
- Bus Pirate、Adafruit FT232H、Shikra、Attify BadgeなどのMultipurpose tool

### UART Portの特定

UARTには4つのportがあります：**TX**（Transmit）、**RX**（Receive）、**Vcc**（Voltage）、**GND**（Ground）です。PCB上に**`TX`**と**`RX`**の文字が**書かれた**4つのportを見つけられる場合があります。しかし、表示がない場合は、**multimeter**または**logic analyzer**を使って自分で特定する必要があります。

デバイスの電源をオフにした状態で**multimeter**を使用します：

- **GND** pinを特定するには、**Continuity Test** modeを使用し、黒のリードをgroundに接続して、multimeterから音が鳴るまで赤のリードでテストします。PCB上には複数のGND pinが存在する可能性があるため、UARTに属するpinを見つけたとは限りません。
- **VCC port**を特定するには、**DC voltage mode**に設定し、電圧を20 Vまでに設定します。黒のprobeをgroundに、赤のprobeをpinに接続します。デバイスの電源を入れます。multimeterが3.3 Vまたは5 Vの一定電圧を測定した場合、Vcc pinが見つかったことになります。それ以外の電圧が得られた場合は、別のportで再試行します。
- **TX** **port**を特定するには、**DC voltage mode**を20 Vまでに設定し、黒のprobeをgroundに、赤のprobeをpinに接続して、デバイスの電源を入れます。電圧が数秒間変動した後、Vccの値で安定する場合、TX portである可能性が高いです。これは、電源投入時にdebug dataが送信されるためです。
- **RX port**は、他の3つに最も近いものです。UART pinの中で電圧変動が最も小さく、全体的な電圧値も最も低くなります。

TXとRX portを取り違えても何も起こりませんが、GNDとVCC portを取り違えると回路を焼損する可能性があります。

一部のtarget deviceでは、manufacturerがRXまたはTX、あるいはその両方を無効にすることでUART portを無効化しています。その場合、circuit board上の接続をたどり、breakout pointを見つけると役立つことがあります。UARTが検出されず、回路が切断されていることを確認する強い手がかりとして、device warrantyを確認できます。deviceにwarrantyが付属して出荷されている場合、manufacturerはdebug interface（この場合はUART）を残しているため、debugging中にUARTを再接続できるよう、あらかじめ切断しているはずです。これらのbreakout pinは、solderingまたはjumper wireで接続できます。

### UART Baud Rateの特定

正しいbaud rateを特定する最も簡単な方法は、**TX pinの出力を確認してdataを読み取ろうとすること**です。受信したdataが読めない場合は、dataが読めるようになるまで、次に考えられるbaud rateへ切り替えます。これにはUSB-to-serial adapterまたはBus Pirateのようなmultipurpose deviceを使用し、[baudrate.py](https://github.com/devttys0/baudrate/)などのhelper scriptと組み合わせます。一般的なbaud rateは9600、38400、19200、57600、115200です。

> [!CAUTION]
> このprotocolでは、一方のdeviceのTXをもう一方のdeviceのRXに接続する必要がある点に注意してください！

## CP210X UART to TTY Adapter

CP210X Chipは、Serial Communication用のNodeMCU（esp8266搭載）のようなprototyping boardで広く使用されています。これらのadapterは比較的安価で、targetのUART interfaceへの接続に使用できます。deviceには5つのpinがあります：5V、GND、RXD、TXD、3.3V。損傷を避けるため、targetがサポートする電圧を接続してください。最後に、AdapterのRXD pinをtargetのTXDに、AdapterのTXD pinをtargetのRXDに接続します。

adapterが検出されない場合は、host systemにCP210X driverがインストールされていることを確認してください。adapterが検出されて接続されたら、picocom、minicom、screenなどのtoolを使用できます。

Linux/MacOS systemに接続されているdeviceを一覧表示するには：
```
ls /dev/
```
UART interfaceとの基本的な対話には、次のコマンドを使用します：
```
picocom /dev/<adapter> --baud <baudrate>
```
minicom では、次のコマンドを使用して設定します：
```
minicom -s
```
`Serial port setup` オプションで、baudrate やデバイス名などの設定を行います。

設定後、`minicom` コマンドを使用して UART Console を起動します。

## Arduino UNO R3 経由の UART（取り外し可能な Atmel 328p チップ搭載ボード）

UART Serial to USB adapters が利用できない場合は、簡単な hack により Arduino UNO R3 を使用できます。Arduino UNO R3 は通常どこでも入手できるため、多くの時間を節約できます。

Arduino UNO R3 には、ボード自体に USB to Serial adapter が組み込まれています。UART 接続を確立するには、ボードから Atmel 328p microcontroller chip を取り外すだけです。この hack は、Atmel 328p がボードに solder されていない Arduino UNO R3 の variant（SMD version が使用されているもの）で機能します。Arduino の RX pin（Digital Pin 0）を UART Interface の TX pin に、Arduino の TX pin（Digital Pin 1）を UART interface の RX pin に接続します。

最後に、Serial Console には Arduino IDE を使用することを推奨します。メニューの `tools` セクションで `Serial Console` オプションを選択し、UART interface に応じて baud rate を設定します。

## Bus Pirate

このシナリオでは、プログラムのすべての print を Serial Monitor に送信している Arduino の UART 通信を sniff します。
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
## UART ConsoleでFirmwareをDumpする

UART Consoleは、runtime environmentで基盤となるfirmwareを扱う優れた方法です。しかし、UART Consoleへのaccessがread-onlyの場合、多くの制約が生じる可能性があります。多くのembedded deviceでは、firmwareはEEPROMに保存され、volatile memoryを持つprocessor上で実行されます。そのため、製造時のoriginal firmware自体がEEPROM内にあり、新しいfileはvolatile memoryのため失われてしまうことから、firmwareはread-onlyのまま保持されます。したがって、embedded firmwareを扱う際、firmwareをdumpすることは有益な作業です。

これを行う方法は数多くあり、SPIセクションでは、さまざまなdeviceを使用してEEPROMからfirmwareを直接extractする方法を説明しています。ただし、physical deviceや外部とのinteractionsを伴うfirmwareのdumpは危険を伴う可能性があるため、まずUARTを使用したfirmwareのdumpを試すことを推奨します。

UART Consoleからfirmwareをdumpするには、まずbootloaderへのaccessを取得する必要があります。多くの主要なvendorは、Linuxをloadするbootloaderとしてuboot (Universal Bootloader)を使用しています。そのため、ubootへのaccessを取得することが必要です。

bootloaderを起動するには、UART portをcomputerに接続し、任意のSerial Console toolを使用します。このとき、deviceへの電源供給は切断したままにします。setupの準備ができたら、Enter Keyを押したままにします。最後に、deviceへの電源供給を接続し、bootさせます。

これにより、ubootのloadがinterruptされ、menuが表示されます。uboot commandを理解し、help menuを使用してcommandを一覧表示することを推奨します。これは`help` commandの場合があります。vendorごとに異なるconfigurationが使用されているため、それぞれを個別に理解する必要があります。

通常、firmwareをdumpするcommandは次のとおりです。
```
md
```
これは「memory dump」を意味します。画面にメモリ（EEPROM Content）をダンプします。memory dumpを取得する手順を開始する前に、Serial Consoleの出力を記録しておくことを推奨します。

最後に、ログファイルから不要なデータをすべて取り除き、ファイルを`filename.rom`として保存して、binwalkを使用して内容を抽出します。
```
binwalk -e <filename.rom>
```
これは、hex file で見つかった signatures に基づいて、EEPROM に含まれている可能性のある内容を一覧表示します。

ただし、uboot が使用されている場合でも、常に unlocked であるとは限らない点に注意が必要です。Enter Key を押しても何も起こらない場合は、Space Key などの別のキーを試してください。bootloader が locked で割り込みを受け付けない場合、この方法は機能しません。uboot がそのデバイスの bootloader かどうかを確認するには、デバイスの boot 中に UART Console の出力を確認してください。boot 中に uboot について表示される場合があります。

{{#include ../../banners/hacktricks-training.md}}
