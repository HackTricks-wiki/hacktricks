# UART

{{#include ../../banners/hacktricks-training.md}}

## 基本情報

UARTは、共通のクロックを使わずにフレーム化されたビットストリームを転送する非同期シリアルインターフェースです。ロジックレベルのUARTとRS-232を混同しないでください。RS-232は電圧レベルが異なり、多くの場合は負電圧を使用するため、トランシーバーが必要です。<sup>[[1]](#references)[[3]](#references)</sup>

通常、UARTがアイドル状態のとき、ラインはHigh（論理値1）に保たれます。その後、データ転送の開始を知らせるため、送信側は受信側にスタートビットを送信し、その間、信号はLow（論理値0）に保たれます。次に、送信側は実際のメッセージを含む5～8個のデータビットを送信し、設定に応じてオプションのパリティビットと1～2個のストップビット（論理値1）を送信します。エラーチェックに使われるパリティビットは、実際にはほとんど使われません。ストップビットは送信の終了を示します。

最も一般的な設定は8N1です。これは、データビットが8個、パリティなし、ストップビットが1個という意味です。UARTはデータの最下位ビットから送信するため、ASCIIの`C`（`0x43`）は、スタート`0`、データ`1, 1, 0, 0, 0, 0, 1, 0`、ストップ`1`の順で送信されます。<sup>[[1]](#references)</sup>

![UART: 最も一般的な設定を8N1と呼びます。データビットが8個、パリティなし、ストップビットが1個です。たとえば、8N1 UARTで文字C（ASCIIでは0x43）を送信する場合](<../../images/image (764).png>)

UARTとの通信に使うハードウェアツール:

- USB-to-serialアダプター
- CP2102またはPL2303チップ搭載のアダプター
- Bus Pirate、Adafruit FT232H、Shikra、Attify Badgeなどの多機能ツール

### UARTポートの特定

一般的なデバッグ用ヘッダーには**TX**、**RX**、**GND**があり、**Vcc/Vref**ピン、リセットピン、フロー制御ピンが追加されている場合もあります。VccはUART信号ではありません。基板の回路図と電流要件がわかっている場合を除き、通常は電圧基準としてのみ使い、電源として接続しないでください。<sup>[[2]](#references)[[3]](#references)</sup>

デバイスの**電源を切り**、接続を外した状態から始めます。

- 導通モードを使い、既知のグランドプレーン、コネクターシールド、または電源グランドとの導通を確認して**GND**を特定します。通電中の基板に対して、導通／抵抗モードを使わないでください。
- 対象機器の電源を入れる前に、DC電圧モードに切り替えます。候補のピンとGNDの間を測定し、ロジック電圧を特定します。一定の電圧が見られるピンはVcc/Vrefの可能性がありますが、安全に接続できるとは限りません。
- 起動中にロジックアナライザーまたはオシロスコープで候補のピンを観察します。**TX**は通常アイドル時にHighで、フレーム化されたデータのバーストが見られます。マルチメーターでは電圧の平均的な変動を確認できますが、フレーミングやボーレートは検証できません。
- **RX**はアイドル状態のままの場合があり、TXの隣にあるというだけで安全に特定できるわけではありません。PCB上の配線をたどるか、SoCのデータシートを確認するか、高インピーダンスのアナライザーを使ってから信号を入力してください。

TXとRXを入れ替えても通常は通信できません。電源、グランド、信号レベルを取り違えると、対象機器やアダプターが恒久的に損傷するおそれがあります。まずGNDを接続し、最初は**受信のみ**（対象機器のTXをアダプターのRXに接続）で始めてください。

メーカーによっては、ヘッダーを省略したり、直列抵抗を未実装のままにしたり、ファームウェアでコンソールを無効にしたり、TXのみを公開したりする場合があります。近くのテストパッドや抵抗用フットプリントからSoCまでの配線をたどり、電気的なレベルを確認してから、一時的な高インピーダンス接続を追加してください。保証があるからといって、アクセス可能なUARTが必ず存在するとは限りません。

### UARTのボーレートの特定

正しいボーレートを特定する最も簡単な方法は、**TXピンの出力を確認し、データを読み取ってみること**です。受信したデータが読めない場合は、読めるようになるまで次の候補のボーレートに切り替えます。USB-to-serialアダプターやBus Pirateのような多機能デバイスを、[baudrate.py](https://github.com/devttys0/baudrate/)などの補助スクリプトと組み合わせて使えます。よく使われるボーレートは9600、38400、19200、57600、115200です。

> [!CAUTION]
> このプロトコルでは、一方のデバイスのTXを、もう一方のデバイスのRXに接続する必要がある点に注意してください。

## CP210X UART to TTY Adapter

CP210x USB-to-UARTブリッジは、多くのプロトタイピング用基板や安価なアダプターで使われています。一般的なモジュールでは、GND、RXD、TXDとともに電源ピンも公開されていますが、ヘッダーやI/Oレベルは製品によって異なります。基板の設計またはデータシートで実際の電圧を確認してください。通常はGND、アダプターのRXと対象機器のTXのみを接続し、受信のみの動作を確認した後で、アダプターのTXと対象機器のRXを接続します。対象機器に給電する意図があり、その電圧に対応していることが確認できている場合を除き、アダプターの5 V／3.3 V電源ピンは接続しないでください。<sup>[[3]](#references)</sup>

アダプターが認識されない場合は、ホストシステムにCP210Xドライバーがインストールされていることを確認してください。アダプターが認識され、接続されたら、picocom、minicom、screenなどのツールを使えます。

Linux/MacOSシステムに接続されているデバイスを一覧表示するには:

```
ls /dev/
```

UARTインターフェースとの基本的なやり取りには、次のコマンドを使用します。

```
picocom /dev/<adapter> --baud <baudrate>
```

minicom を設定するには、次のコマンドを使用します:

```
minicom -s
```

ボーレートやデバイス名などの設定は、`Serial port setup` オプションで行います。

設定後、`minicom` を実行して UART コンソールを開きます。

## Arduino UNO R3経由のUART（取り外し可能なAtmel 328pチップ搭載ボード）

UART Serial to USBアダプターが使えない場合は、Arduino UNO R3を簡単なhackで使用できます。Arduino UNO R3はどこでも入手しやすいため、時間を大幅に節約できます。

Arduino UNO R3には、USB to Serialアダプターがボード上に組み込まれています。UART接続を行うには、ボードからAtmel 328pマイクロコントローラーチップを取り外します。このhackは、Atmel 328pがボードにはんだ付けされていないArduino UNO R3のバリエーション（SMD版が使用されているもの）で動作します。ArduinoのRXピン（Digital Pin 0）をUARTインターフェースのTXピンに、ArduinoのTXピン（Digital Pin 1）をUARTインターフェースのRXピンに接続します。

Arduino IDEの**Serial Monitor**または専用のターミナルを、対象のボーレートに設定して使用します。従来のUno R3のシリアル信号は5 Vロジックなので、3.3 V以下の電圧で動作するターゲットに接続する前に、レベルシフターまたは分圧器を使用してください。

## Bus Pirate

以下のトランスクリプトでは、従来のBus Pirateファームウェアインターフェースを使ってUART出力を監視します。新しいBus Pirateファームウェアでは、`m uart`、`{`/`}`、`monitor`、`bridge`などのコマンドが使われます。インストールされているバージョンのドキュメントを参照してください。<sup>[[2]](#references)</sup>

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

## UARTコンソールを使ったファームウェアのダンプ

UARTコンソールを使うと、実行時のブートログや、場合によってはブートローダーまたはOSのシェルにアクセスできます。読み取り専用のコンソールでも、メモリマップ、フラッシュドライバー、ブート引数、パーティションレイアウト、ファームウェアのバージョンが分かることがあります。ファームウェアはSPI NOR/NAND、eMMC、または別のデバイスに格納されている場合があります。通常、EEPROMから直接実行されるわけではなく、マウントされた永続ファイルシステムに書き込まれたファイルが再起動時に必ず消えるわけでもありません。

取得方法はいくつかあります。外部フラッシュから直接読み取る方法については、SPIのセクションで説明します。ブートローダーに安全な読み取りコマンドが用意されている場合、コンソール経由の取得はより低侵襲な方法となることがあります。ただし、起動を中断したりフラッシュコマンドを実行したりすると、可用性に影響する可能性があるため、元の状態を記録し、書き込みや消去の操作は避けてください。

コンソール経由でファームウェアをダンプする場合、まずブートローダーの起動を中断することがよくあります。多くの組み込みLinuxデバイスでは **Das U-Boot** が使われていますが、独自のブートローダーを使うものや、対話型コンソールを無効にしているものもあります。

対話型ブートローダーの有無を確認するには、ターゲットの電源が切れた状態でUARTの受信経路とターミナルを接続し、ログの記録を開始してから電源を入れます。表示される自動起動プロンプトに従ってください。ビルドによっては、起動の中断にキー入力や短いキーシーケンスが必要な場合もあれば、機能自体が無効になっている場合もあります。

中断に成功したら、`help`、`printenv`、読み取り専用の調査コマンドを使い、アドレスにアクセスする前に、そのベンダーのメモリとストレージのレイアウトを把握してください。

U-Bootの`md`が表示するのは**アドレス指定可能なメモリ**であり、自動的に「EEPROM」を表示するわけではありません。まず、`mtd list`、`sf probe`、`mmc info`、`part list`などのボード固有コマンド、環境変数、ブートログを使って、正しいマップ済みアドレスを特定するか、フラッシュ領域をRAMに読み込んでください。その後、既知の範囲をバイト単位で表示します:<sup>[[4]](#references)</sup>

```
md.b <address> <byte_count>
```

開始前にシリアル出力を記録します。`md.b`の出力にはアドレス列とASCII列が含まれるため、生のROMイメージではなくテキスト表現です。

アドレス列とASCII列を取り除き、16進バイト列だけを連結して、バイナリにデコードします（例: `xxd -r -p`）。分析の前に、想定されるバイト数を確認し、ハッシュを記録します。

```
xxd -r -p firmware.hex > firmware.bin
sha256sum firmware.bin
binwalk -e firmware.bin
```

Binwalk は再構築されたバイナリ内の既知のシグネチャを識別します。コンソールでデータを安定して転送できない場合は、適切な SPI/eMMC/NAND インターフェース経由でフラッシュを直接読み取るほうが、通常は高速でエラーも少なくなります。

U-Boot では割り込みが無効化されていたり、ベンダー固有のキーシーケンスが必要だったり、メモリ／フラッシュコマンドがロックされていたりする場合があります。文字をむやみに送信せず、autoboot プロンプトとブートログを確認してください。コンソールで割り込みができない場合は、ブートログを保存し、非侵襲的なファームウェア取得手段に切り替えてください。

## References

- [1] [Microchip PIC32 ファミリー リファレンスマニュアル - UART](https://ww1.microchip.com/downloads/en/DeviceDoc/60001107H.pdf)
- [2] [Bus Pirate ドキュメント - UART モードと電気的制限](https://docs.buspirate.com/docs/command-reference/#uart)
- [3] [Silicon Labs - CP2102C データシート](https://www.silabs.com/documents/public/data-sheets/cp2102c-datasheet.pdf)
- [4] [U-Boot ドキュメント - `md` メモリ表示コマンド](https://docs.u-boot.org/en/latest/usage/cmd/md.html)
{{#include ../../banners/hacktricks-training.md}}
