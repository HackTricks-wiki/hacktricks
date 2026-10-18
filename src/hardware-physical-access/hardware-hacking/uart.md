# UART

{{#include ../../banners/hacktricks-training.md}}

## 基本情報

UARTは、共通クロックを使わずにフレーム化されたビット列を転送する非同期シリアルインターフェースです。ロジックレベルのUARTとRS-232を混同しないでください。RS-232では電圧レベルが異なり、多くの場合は負電圧を使用するため、トランシーバーが必要です。<sup>[[1]](#references)[[3]](#references)</sup>

通常、UARTがアイドル状態のとき、ラインはHigh（論理値1）に保たれます。データ転送の開始を知らせるため、送信側は受信側にスタートビットを送り、その間、信号はLow（論理値0）に保たれます。次に、送信側は実際のメッセージを含む5～8個のデータビットを送り、設定に応じてオプションのパリティビットと1個または2個のストップビット（論理値1）を続けて送信します。エラー検出に使われるパリティビットは、実際にはほとんど使われません。ストップビットは送信の終了を示します。

最も一般的な設定は8N1です。データビット8個、パリティなし、ストップビット1個を意味します。UARTではデータの最下位ビットから送信するため、ASCIIの`C`（`0x43`）は次のように送信されます。スタート`0`、データ`1, 1, 0, 0, 0, 0, 1, 0`、ストップ`1`。<sup>[[1]](#references)</sup>

![UART: 最も一般的な設定は8N1と呼ばれ、データビット8個、パリティなし、ストップビット1個です。たとえば、文字C（ASCIIでは0x43）を8N1 UARTで送信する場合](<../../images/image (764).png>)

UARTとの通信に使うハードウェアツール：

- USB-to-serialアダプター
- CP2102またはPL2303チップ搭載のアダプター
- Bus Pirate、Adafruit FT232H、Shikra、Attify Badgeなどの多機能ツール

### UARTポートの特定

一般的なデバッグヘッダーには**TX**、**RX**、**GND**があり、**Vcc/Vref**ピン、リセットピン、フロー制御ピンが設けられている場合もあります。VccはUART信号ではありません。基板の回路図と必要な電流が分かっている場合を除き、通常は電圧基準としてのみ使用し、電源として接続しないでください。<sup>[[2]](#references)[[3]](#references)</sup>

デバイスの電源を**切り**、接続を外した状態から始めます。

- 既知のグラウンドプレーン、コネクターのシールド、または電源グラウンドとの導通を確認し、**GND**を特定します。電源が入った基板で導通／抵抗モードを使用しないでください。
- ターゲットの電源を入れる前に、DC電圧モードに切り替えます。候補となるピンとグラウンド間の電圧を測定し、ロジック電圧を特定します。安定した電圧レールがVcc/Vrefの可能性がありますが、安全に接続できるとは限りません。
- 起動中にロジックアナライザーまたはオシロスコープで候補ピンを観察します。**TX**は通常アイドル時にHighとなり、フレーム化されたデータのバーストが現れます。マルチメーターでは電圧の平均的な変動を確認できる場合がありますが、フレーミングやボーレートは検証できません。
- **RX**はアイドル状態のままの場合があり、TXの隣にあるという理由だけで安全に特定することはできません。PCBの配線を追跡するか、SoCのデータシートを参照するか、高インピーダンスのアナライザーを使用してから信号を入力してください。

TXとRXを入れ替えても通常は通信できないだけですが、電源、グラウンド、または信号レベルを取り違えると、ターゲットやアダプターが恒久的に損傷するおそれがあります。まずグラウンドを接続し、**受信のみ**（ターゲットのTXからアダプターのRX）で始めてください。

メーカーがヘッダーを省略したり、直列抵抗を未実装にしたり、ファームウェアでコンソールを無効にしたり、TXのみを公開したりすることがあります。近くのテストパッドや抵抗のフットプリントからSoCまで配線を追跡し、電気的なレベルを確認してから一時的な高インピーダンス接続を追加してください。保証が付いているからといって、アクセス可能なUARTが存在するとは限りません。

### UARTのボーレートの特定

正しいボーレートを特定する最も簡単な方法は、**TXピンの出力を確認し、データを読み取ってみること**です。受信したデータが読めない場合は、読めるようになるまで次の候補のボーレートに切り替えます。USB-to-serialアダプターやBus Pirateなどの多機能デバイスを、[baudrate.py](https://github.com/devttys0/baudrate/)などの補助スクリプトと組み合わせて使用できます。最も一般的なボーレートは9600、38400、19200、57600、115200です。

> [!CAUTION]
> このプロトコルでは、一方のデバイスのTXをもう一方のデバイスのRXに接続する必要があることに注意してください。

### SCPIによる起動時UARTキャプチャの自動化

起動時の出力が短い場合や、TXパッドがまだ分からない場合は、電源装置やオシロスコープを手動で操作する代わりに、起動を繰り返す処理を自動化してください。電流制限付きのプログラマブル電源を、確認済みのターゲット電源入力に接続します。共通グラウンドを取り、高インピーダンスのオシロスコープ入力で候補となる各TXパッドを測定します。パッドに信号を入力しないでください。<sup>[[5]](#references)</sup>

VISAはシリアルまたはEthernet経由の計測器セッションを開き、SCPIは出力、トリガー、波形読み出しを制御します。<sup>[[5]](#references)[[6]](#references)</sup> `pyvisa`と`pyvisa-py`（シリアルVISAリソースには`pyserial`も）をインストールしてください。`ResourceManager('@py')`はPythonバックエンドを明示的に選択します。<sup>[[5]](#references)[[7]](#references)</sup> リソース文字列とコマンドは、使用する計測器が対応しているものに置き換えてください。<sup>[[5]](#references)</sup>

Rigol MSO5000の例では、基板に電源を入れる前に、立ち下がりエッジのシングルトリガーを設定します。アイドル時にHighのUART TXは、スタートビットで最初に立ち下がるためです。<sup>[[5]](#references)</sup> トリガーしきい値は、測定したアイドル時とLow時のレベルの間に設定し、タイムベースは確認したい起動区間をカバーするように設定します。<sup>[[5]](#references)[[6]](#references)</sup> `:TRIG:HOLD`は連続キャプチャでトリガーの繰り返しを抑制できますが、シングルショットのキャプチャが実際に完了したことを確認する代わりにはなりません。<sup>[[5]](#references)</sup> 以下のコードは起動を1回キャプチャし、符号なしバイトのサンプルとスケーリングメタデータの両方を保存します。タイムアウト時には、無期限に待機せずターゲットの電源を切ります。<sup>[[5]](#references)[[6]](#references)</sup>

<details>
<summary>PyVISAによる電源投入とシングルショットUART波形キャプチャ</summary>

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

pad調査では、probeを移動させた後にsingle-shot captureを繰り返すか、電源供給セッションを開いたまま、起動時の待機時間と電源オフ時間を設けて出力を切り替えます。電源を入れるたびにscopeを再アームし、各ファイルが1回の起動と1つのpadに対応するようにします。<sup>[[5]](#references)</sup>

Rigolのpreambleは`<format>,<type>,<points>,<count>,<xincrement>,...`です。<sup>[[6]](#references)</sup> **3番目**の値はポイント数であり、記事に記載されているsample rateではありません。<sup>[[5]](#references)[[6]](#references)</sup> 例では、`25,000,000`ポイントと`xincrement = 2e-8`秒から、`1 / xincrement = 50,000,000` samples/secondとなり、25 MSa/sではありません。<sup>[[5]](#references)[[6]](#references)</sup> preambleをbinary fileと一緒に保存し、読み取り長が`<points>`と一致することを確認してください。このガイドでは、大きなrecord向けにsegmented/batched readについて説明しています。<sup>[[6]](#references)</sup>

キャプチャした信号をdecodeするには、PulseViewで`capture.bin`を**Raw Analog Data Without Header**としてインポートし、unsigned 8-bit（`U8`）の値を選択して、`xincrement`から計算したsample rateを入力します。<sup>[[5]](#references)[[6]](#references)</sup> アナログチャンネルに**Logic via Threshold**を適用し、サンプル値のlowとhighの間にthresholdを設定します。<sup>[[5]](#references)</sup> クリーンなstart-bitの幅を測定してbaud rateを推定し（57,600 baudの場合は約17.36 µs）、PulseViewのUART decoderを適用して、複数のframeが一貫してdecodeされることを確認します。<sup>[[5]](#references)</sup> falling edgeだけでは、そのpadがUARTであるとは証明できません。

## CP210X UART to TTY Adapter

CP210x USB-to-UART bridgeは、多くのprototyping boardや安価なadapterに搭載されています。一般的なmoduleでは、GND、RXD、TXDに加えて電源pinも出ていますが、headerとI/O levelはさまざまです。boardの設計またはdata sheetで実際の電圧を確認してください。通常はGNDと、adapterのRXをtargetのTXに接続します。受信専用での検証後に、adapterのTXをtargetのRXに接続します。adapterの5 V/3.3 V電源pinは、対象機器がその電圧に耐えられると確認したうえで意図的に給電する場合を除き、接続しないでください。<sup>[[3]](#references)</sup>

adapterが検出されない場合は、CP210X driverがhost systemにインストールされていることを確認してください。adapterが検出され、接続されたら、picocom、minicom、screenなどのtoolを使用できます。

Linux/MacOS systemに接続されているdeviceを一覧表示するには、次のようにします。

```
ls /dev/
```

UART interfaceを基本的に操作するには、次のコマンドを使用します。

```
picocom /dev/<adapter> --baud <baudrate>
```

minicom を設定するには、次のコマンドを使用します：

```
minicom -s
```

`Serial port setup` オプションで、baudrate やデバイス名などの設定を行います。

設定後、`minicom` を実行して UART コンソールを開きます。

## Arduino UNO R3 経由の UART（取り外し可能な Atmel 328p チップ搭載ボード）

UART Serial to USB アダプターが手元にない場合は、Arduino UNO R3 を使った簡単な hack が可能です。Arduino UNO R3 は多くの場所で入手できるため、時間を大幅に節約できます。

Arduino UNO R3 には、USB-Serial アダプターが基板上に搭載されています。UART 接続を確立するには、基板から Atmel 328p マイクロコントローラーチップを取り外すだけです。この hack は、Atmel 328p が基板にはんだ付けされていない Arduino UNO R3（SMD バージョンを使用）で機能します。Arduino の RX ピン（Digital Pin 0）を UART インターフェースの TX ピンに、Arduino の TX ピン（Digital Pin 1）を UART インターフェースの RX ピンに接続します。

Arduino IDE の **Serial Monitor** または専用のターミナルを、対象の baud rate に設定して使用します。従来の Uno R3 のシリアル信号は 5 V ロジックなので、3.3 V またはそれ以下の電圧の対象機器に接続する前に、レベルシフターまたは分圧器を使用してください。

## Bus Pirate

以下のトランスクリプトでは、従来の Bus Pirate ファームウェアインターフェースを使って UART 出力を監視します。新しい Bus Pirate ファームウェアでは、`m uart`、`{`/`}`、`monitor`、`bridge` などのコマンドを使用します。インストールされているバージョンのドキュメントを参照してください。<sup>[[2]](#references)</sup>

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

## UART コンソールを使ったファームウェアのダンプ

UART コンソールを使うと、実行時のブートログにアクセスでき、場合によってはブートローダーやオペレーティングシステムのシェルにもアクセスできます。読み取り専用のコンソールでも、メモリマップ、フラッシュドライバー、ブート引数、パーティション構成、ファームウェアのバージョンが明らかになることがあります。ファームウェアは SPI NOR/NAND、eMMC、その他のデバイスに格納されている場合があります。一般に EEPROM から直接実行されるわけではなく、マウントされた永続ファイルシステムに書き込まれたファイルが、再起動後に必ず消えるわけでもありません。

取得方法はいくつかあり、外部フラッシュから直接読み出す方法については SPI のセクションで説明します。ブートローダーに安全な読み出しコマンドが用意されている場合、コンソール経由の取得はより侵襲性が低いことがあります。ただし、ブートの中断やフラッシュコマンドは可用性に影響する可能性があるため、元の状態を記録し、書き込みや消去の操作は避けてください。

コンソール経由でファームウェアをダンプする場合、まずブートローダーの起動を中断することがよくあります。多くの組み込み Linux デバイスでは**Das U-Boot**が使われていますが、独自のブートローダーを使用するものや、対話型コンソールが無効になっているものもあります。

対話型ブートローダーが使えるか確認するには、ターゲットの電源がオフの状態で UART の受信経路とターミナルを接続し、ログ記録を開始してから電源を入れます。表示された自動起動プロンプトに従ってください。ビルドによっては、起動の中断にキー入力や短いキー操作が必要な場合があり、機能自体が無効になっている場合もあります。

中断に成功したら、`help`、`printenv`、読み取り専用の調査コマンドを使って、アドレスにアクセスする前に、そのベンダー固有のメモリとストレージの構成を把握してください。

U-Boot の `md` が表示するのは**アドレス指定可能なメモリ**であり、自動的に「EEPROM」が表示されるわけではありません。まず、`mtd list`、`sf probe`、`mmc info`、`part list`などのボード固有コマンド、環境変数、ブートログを使って、正しいマップ済みアドレスを特定するか、フラッシュ領域を RAM に読み込んでください。その後、既知の範囲をバイト単位で表示します:<sup>[[4]](#references)</sup>

```
md.b <address> <byte_count>
```

開始前にシリアル出力を記録します。`md.b` の出力にはアドレスと ASCII の列が含まれるため、raw ROM image ではなくテキスト表現です。

アドレス列と ASCII 列を取り除き、16進数のバイト列だけを連結して、バイナリにデコードします（例：`xxd -r -p`）。解析前に、想定されるバイト数を確認し、ハッシュを記録します。

```
xxd -r -p firmware.hex > firmware.bin
sha256sum firmware.bin
binwalk -e firmware.bin
```

Binwalk は、再構成されたバイナリ内の既知のシグネチャを特定します。コンソールでデータを確実に転送できない場合は、適切な SPI/eMMC/NAND インターフェース経由でフラッシュを直接読み取る方が、通常は高速でエラーも少なくなります。

U-Boot は割り込みを無効にしたり、ベンダー固有のキーシーケンスを要求したり、メモリ／フラッシュのコマンドをロックしたりすることがあります。文字をむやみに送信せず、自動起動プロンプトとブートログに従ってください。コンソールの割り込みができない場合は、ブートログを保存し、非侵襲的なファームウェア取得方法に切り替えてください。

## References

- [1] [Microchip PIC32 ファミリー リファレンスマニュアル - UART](https://ww1.microchip.com/downloads/en/DeviceDoc/60001107H.pdf)
- [2] [Bus Pirate ドキュメント - UART モードと電気的制限](https://docs.buspirate.com/docs/command-reference/#uart)
- [3] [Silicon Labs - CP2102C データシート](https://www.silabs.com/documents/public/data-sheets/cp2102c-datasheet.pdf)
- [4] [U-Boot ドキュメント - メモリ表示コマンド `md`](https://docs.u-boot.org/en/latest/usage/cmd/md.html)
- [5] [VoidStar Security — リバースエンジニア向け SCPI とハードウェア計測器活用、第 1 部](https://voidstarsec.com/blog/scpi-and-hardware-instrumentation-for-reverse-engineers-part-1)
- [6] [Rigol MSO5000 プログラミングガイド](https://www.batronix.com/files/Rigol/Oszilloskope/MSO5000/MSO5000_ProgrammingGuide_EN-V2.0.pdf)
- [7] [PyVISA — バックエンドの設定](https://pyvisa.readthedocs.io/en/latest/introduction/configuring.html)
{{#include ../../banners/hacktricks-training.md}}
