# UART

{{#include ../../banners/hacktricks-training.md}}

## 基本情報

UARTは、共有クロックなしでフレーム化されたビットストリームを転送する非同期シリアルインターフェースです。ロジックレベルのUARTとRS-232を混同しないでください。RS-232は異なる、しばしば負の電圧レベルを使用し、トランシーバーが必要です。<sup>[[1]](#references)[[3]](#references)</sup>

一般的に、UARTがアイドル状態のとき、ラインはHigh（論理値1）に保たれます。データ転送の開始を知らせるため、送信側は受信側にスタートビットを送信し、その間、信号はLow（論理値0）に保たれます。次に送信側は、実際のメッセージを含む5～8個のデータビットを送信し、設定に応じて、オプションのパリティビットと1個または2個のストップビット（論理値1）を続けます。エラーチェックに使用されるパリティビットは、実際にはほとんど見られません。ストップビットは送信の終了を示します。

最も一般的な設定は8N1です。これは、データビット8個、パリティなし、ストップビット1個を意味します。UARTは最下位データビットから先に送信するため、ASCIIの`C`（`0x43`）は、スタート`0`、データ`1, 1, 0, 0, 0, 0, 1, 0`、ストップ`1`として送信されます。<sup>[[1]](#references)</sup>

![UART: 最も一般的な設定を8N1と呼びます。これは、データビット8個、パリティなし、ストップビット1個です。たとえば、文字C（ASCIIでは0x43）を8N1 UARTで送信する場合](<../../images/image (764).png>)

UARTと通信するためのハードウェアツール：

- USB-to-serial adapter
- CP2102またはPL2303チップを搭載したアダプター
- Bus Pirate、Adafruit FT232H、Shikra、Attify Badgeなどの多目的ツール

### UARTポートの特定

一般的なデバッグヘッダーには、**TX**、**RX**、**GND**があり、さらに**Vcc/Vref**ピン、リセット、またはフロー制御ピンがある場合もあります。VccはUART信号ではないため、通常は電圧リファレンスとしてのみ使用し、電源として接続しないでください。ただし、基板の回路図と電流要件が分かっている場合は例外です。<sup>[[2]](#references)[[3]](#references)</sup>

まず、デバイスの**電源をオフ**にし、接続を外した状態から始めます。

- 既知のグランドプレーン、コネクターシールド、または電源グランドとの導通を、導通モードで確認して**GND**を特定します。電源が入った基板で導通／抵抗モードを使用しないでください。
- ターゲットの電源を入れる前に、DC電圧モードへ切り替えます。候補ピンの電圧をグランド基準で測定し、ロジック電圧を特定します。安定した電源レールはVcc/Vrefである可能性がありますが、安全に接続できると決めつけないでください。
- 起動中にロジックアナライザーまたはオシロスコープで候補ピンを観察します。**TX**は通常アイドル時にHighで、フレーム化されたデータのバーストが現れます。マルチメーターでは平均的な変動を確認できる場合がありますが、フレーム構造やボーレートを検証することはできません。
- **RX**はアイドル状態のままの場合があり、TXの隣にあるというだけで安全に特定することはできません。PCBを追跡し、SoCのデータシートを参照するか、高インピーダンスのアナライザーを使用してから信号を駆動してください。

TXとRXを入れ替えると通常は通信できません。電源、グランド、または信号レベルを取り違えると、ターゲットやアダプターを恒久的に損傷する可能性があります。まずグランドを接続し、**受信専用**（ターゲットTXからアダプターRX）で開始してください。

メーカーがヘッダーを省略したり、シリーズ抵抗を未実装のままにしたり、ファームウェアでコンソールを無効にしたり、TXのみを公開したりする場合があります。近くのテストパッドと抵抗フットプリントをSoCまで追跡し、電気的なレベルを確認してから、一時的な高インピーダンス接続を追加してください。保証が存在するからといって、アクセス可能なUARTが必ず存在するとは限りません。

### UARTのボーレートの特定

正しいボーレートを特定する最も簡単な方法は、**TXピンの出力を確認し、データを読み取ってみること**です。受信したデータが読めない場合は、データが読めるようになるまで、次に考えられるボーレートへ切り替えます。これにはUSB-to-serial adapterやBus Pirateなどの多目的デバイスを使用でき、[baudrate.py](https://github.com/devttys0/baudrate/)のようなヘルパースクリプトと組み合わせます。一般的なボーレートは9600、38400、19200、57600、115200です。

> [!CAUTION]
> このプロトコルでは、一方のデバイスのTXをもう一方のデバイスのRXに接続する必要があることに注意してください！

## CP210X UART to TTYアダプター

CP210x USB-to-UARTブリッジは、多くのプロトタイピングボードや安価なアダプターに搭載されています。一般的なモジュールでは、GND、RXD、TXDとともに電源ピンが公開されていますが、ヘッダーとI/Oレベルは異なります。基板の設計またはデータシートで実際の電圧を確認してください。通常はGND、アダプターRXからターゲットTXのみを接続し、受信専用での検証後に、アダプターTXからターゲットRXを接続します。意図的に電源を供給し、その電圧に耐えられることが分かっているターゲットでない限り、アダプターの5 V／3.3 V電源ピンを接続しないでください。<sup>[[3]](#references)</sup>

アダプターが検出されない場合は、ホストシステムにCP210Xドライバーがインストールされていることを確認してください。アダプターが検出されて接続されたら、picocom、minicom、screenなどのツールを使用できます。

Linux／MacOSシステムに接続されたデバイスを一覧表示するには：
```
ls /dev/
```
UART interface と basic に interaction するには、次の command を使用します：
```
picocom /dev/<adapter> --baud <baudrate>
```
minicomでは、次のコマンドを使用して設定します。
```
minicom -s
```
`Serial port setup`オプションで、baudrateやデバイス名などの設定を行います。

設定後、`minicom`を実行してUARTコンソールを開きます。

## Arduino UNO R3経由のUART（Atmel 328pチップを取り外せるボード）

UART Serial to USB adaptersが利用できない場合は、簡単なhackでArduino UNO R3を使用できます。Arduino UNO R3は通常どこでも入手できるため、多くの時間を節約できます。

Arduino UNO R3には、USB to Serial adapterがボード自体に搭載されています。UART接続を行うには、ボードからAtmel 328p microcontroller chipを取り外すだけです。このhackは、Atmel 328pがボードにはんだ付けされていないArduino UNO R3のvariant（SMD versionが使用されているもの）で動作します。ArduinoのRX pin（Digital Pin 0）をUART InterfaceのTX pinに、ArduinoのTX pin（Digital Pin 1）をUART interfaceのRX pinに接続します。

Arduino IDEの**Serial Monitor**または専用terminalを、targetのbaud rateに設定して使用します。Classic Uno R3のserial signalsは5 V logicであるため、3.3 Vまたはそれ以下の電圧のtargetに接続する前に、level shifterまたはdividerを使用してください。

## Bus Pirate

以下のtranscriptでは、legacy Bus Pirate firmware interfaceを使用してUART outputを監視しています。新しいBus Pirate firmwareでは、`m uart`、`{`/`}`、`monitor`、`bridge`などのcommandsが使用されます。インストールされているversionのdocumentationを確認してください。<sup>[[2]](#references)</sup>
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
## UART ConsoleによるFirmwareのDump

UART consoleは、boot logへのruntime accessと、場合によってはbootloaderまたはoperating-system shellへのaccessを提供します。read-only consoleであっても、memory map、flash driver、boot argument、partition layout、firmware versionが明らかになります。FirmwareはSPI NOR/NAND、eMMC、または別のdeviceに存在する可能性があります。一般にEEPROMから実行されるわけではなく、mountされたpersistent filesystemに書き込んだfileは、reboot時に必ずしも消えるとは限りません。

取得経路はいくつかあり、SPI sectionではexternal flashからの直接readについて説明します。bootloaderが安全なread commandをすでに提供している場合、console-assisted acquisitionはより侵襲性を抑えられます。ただし、bootの中断やflash commandによってavailabilityに影響する可能性があるため、元の状態を記録し、write/erase operationは避けてください。

Console-assisted firmware dumpingは、多くの場合bootloaderを中断することから始まります。多くのembedded Linux deviceは**Das U-Boot**を使用しますが、proprietary bootloaderを使用するdeviceや、interactive consoleを無効化しているdeviceもあります。

interactive bootloaderをテストするには、targetの電源が入っていない状態でUART receive pathとterminalを接続し、loggingを開始してから電源を入れます。表示されるautoboot promptに従ってください。buildによっては、中断にkey、短いsequenceが必要な場合や、完全に無効化されている場合があります。

中断に成功したら、`help`、`printenv`、およびread-onlyのdiscovery commandを使用して、addressにaccessする前に、そのvendorのmemory layoutとstorage layoutを把握します。

U-Bootでは、`md`は自動的に「EEPROM」を表示するのではなく、**addressable memory**を表示します。まず、`mtd list`、`sf probe`、`mmc info`、`part list`などのboard-specific command、environment variable、boot logを使用して、正しいmapped addressを特定するか、flash regionをRAMにloadします。その後、既知のrangeをbyte単位で表示します:<sup>[[4]](#references)</sup>
```
md.b <address> <byte_count>
```
開始前にシリアル出力をログに記録します。`md.b` の出力にはアドレス列と ASCII 列が含まれているため、生の ROM イメージではなく、テキスト表現です。

アドレス列と ASCII 列を削除し、16進バイトフィールドのみを連結して、バイナリにデコードします（たとえば `xxd -r -p` を使用）。解析前に想定バイト数を確認し、ハッシュを記録します:
```
xxd -r -p firmware.hex > firmware.bin
sha256sum firmware.bin
binwalk -e firmware.bin
```
Binwalk は再構成されたバイナリ内の既知のシグネチャを特定します。コンソールでデータを確実に転送できない場合は、適切な SPI/eMMC/NAND インターフェースを介して直接 flash を読み取る方が、通常は高速でエラーも少なくなります。

U-Boot は割り込みを無効化したり、vendor 固有のキーシーケンスを要求したり、memory/flash コマンドをロックしたりする場合があります。文字を無闇に送信するのではなく、autoboot プロンプトと boot log に従ってください。コンソールを中断できない場合は、boot log を保存し、非侵襲的な firmware acquisition 手段に移行してください。

## References

- [1] [Microchip PIC32 Family Reference Manual - UART](https://ww1.microchip.com/downloads/en/DeviceDoc/60001107H.pdf)
- [2] [Bus Pirate documentation - UART mode and electrical limits](https://docs.buspirate.com/docs/command-reference/#uart)
- [3] [Silicon Labs - CP2102C data sheet](https://www.silabs.com/documents/public/data-sheets/cp2102c-datasheet.pdf)
- [4] [U-Boot documentation - `md` memory-display command](https://docs.u-boot.org/en/latest/usage/cmd/md.html)
{{#include ../../banners/hacktricks-training.md}}
