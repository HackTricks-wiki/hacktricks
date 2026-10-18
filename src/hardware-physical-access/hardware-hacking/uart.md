# UART

{{#include ../../banners/hacktricks-training.md}}

## 基本情報

UARTは、共有クロックなしでフレーム化されたビットストリームを転送する非同期シリアルインターフェースです。ロジックレベルUARTをRS-232と混同しないでください。RS-232では電圧レベルが異なり、多くの場合負電圧が使われるため、トランシーバーが必要です。<sup>[[1]](#references)[[3]](#references)</sup>

通常、UARTがアイドル状態の間、ラインはHigh（論理値1）に保たれます。データ転送の開始を知らせるため、送信側は受信側へスタートビットを送信し、その間、信号はLow（論理値0）に保たれます。続いて、送信側は実際のメッセージを含む5〜8個のデータビットを送信し、設定に応じて任意のパリティビットと1個または2個のストップビット（論理値1）を続けます。エラー検出に使われるパリティビットは、実際にはほとんど使われません。ストップビットは送信の終了を示します。

最も一般的な設定は8N1です。データビット8個、パリティなし、ストップビット1個を意味します。UARTは最下位データビットから送信するため、ASCIIの`C`（`0x43`）は、スタート`0`、データ`1, 1, 0, 0, 0, 0, 1, 0`、ストップ`1`として送信されます。<sup>[[1]](#references)</sup>

![UART: 最も一般的な設定は8N1と呼ばれます。データビット8個、パリティなし、ストップビット1個です。たとえば、文字C（ASCIIでは0x43）を8N1 UARTで送信する場合](<../../images/image (764).png>)

UARTで通信するためのハードウェアツール:

- USB-to-serial adapter
- CP2102またはPL2303チップ搭載のアダプター
- Bus Pirate、Adafruit FT232H、Shikra、Attify Badgeなどの多機能ツール

### UARTポートの特定

一般的なデバッグヘッダーには**TX**、**RX**、**GND**があり、**Vcc/Vref**ピン、リセットピン、フロー制御ピンがある場合もあります。VccはUART信号ではありません。通常は電圧の基準としてのみ使用し、基板の回路図と電流要件が分かっていない限り、電源として接続しないでください。<sup>[[2]](#references)[[3]](#references)</sup>

デバイスの電源を**切り**、接続を外した状態から始めます。

- 導通モードを使い、既知のグランドプレーン、コネクターシールド、または電源グランドに対する導通を確認して**GND**を特定します。通電中の基板で導通／抵抗モードを使用しないでください。
- ターゲットの電源を入れる前に、マルチメーターをDC電圧モードに切り替えます。候補ピンとグランド間の電圧を測定し、ロジック電圧を特定します。安定した電源レールはVcc/Vrefの可能性がありますが、安全に接続できるとは限りません。
- 起動中にロジックアナライザーまたはオシロスコープで候補ピンを観測します。**TX**は通常アイドル時にHighで、フレーム化されたデータのバーストが見られます。マルチメーターでは平均値の変動は見られることがありますが、フレーム形式やボーレートは確認できません。
- **RX**はアイドル状態のままの場合があるため、TXの隣にあるというだけで安全に特定することはできません。基板をトレースするか、SoCのデータシートを参照するか、高インピーダンスのアナライザーを使ってから信号を入力します。

TXとRXを入れ替えても通常は通信できませんが、電源、グランド、信号レベルを取り違えると、ターゲットやアダプターに恒久的な損傷を与えるおそれがあります。まずグランドを接続し、**受信のみ**（ターゲットのTXをアダプターのRXに接続）から始めてください。

メーカーはヘッダーを省略したり、直列抵抗を未実装にしたり、ファームウェアでコンソールを無効にしたり、TXだけを露出させたりする場合があります。近くのテストパッドや抵抗フットプリントからSoCまで配線をたどり、電気レベルを確認してから一時的な高インピーダンス接続を追加してください。保証があるからといって、アクセス可能なUARTが必ず存在するとは限りません。

### Lowに見えるTXパッドの復旧

初回のオシロスコープ測定でラベル付きTXパッドがLowのままでも、それだけでUARTを否定することはできません。ターゲットのロジック電圧と共通グランドを確認したうえで、弱いプルアップ（記載例では**10 kΩを3.3 Vに接続**）を試し、ボタン操作またはデバイスの起動中に再度測定します。ターゲットの検証済みロジック電源だけを使い、未知の信号や能動的に駆動されている信号にプルアップを接続しないでください。フレーム化された遷移が現れたら、パッドをシリアルアダプターに受信専用で接続する前に、最短の安定したビット周期を測定してボーレートを推定します。この方法では、例として115200 baudのボタンイベントログを復旧できましたが、ファームウェアダンプは取得できませんでした。<sup>[[8]](#references)</sup>

### UARTのボーレートの特定

適切なボーレートを特定する最も簡単な方法は、**TXピンの出力を確認し、データの読み取りを試すこと**です。受信したデータが読めない場合は、読み取れるようになるまで次の候補ボーレートに切り替えます。USB-to-serial adapter、またはBus Pirateなどの多機能デバイスを、[baudrate.py](https://github.com/devttys0/baudrate/)のような補助スクリプトと組み合わせて使用できます。よく使われるボーレートは9600、38400、19200、57600、115200です。

> [!CAUTION]
> このプロトコルでは、一方のデバイスのTXをもう一方のデバイスのRXに接続する必要があることに注意してください。

### SCPIによる起動時UARTキャプチャの自動化

起動時の出力が短い場合やTXパッドがまだ不明な場合は、電源とオシロスコープを手動で操作する代わりに、起動を繰り返す処理を自動化します。電流制限付きのプログラマブル電源を、確認済みのターゲット電源入力に接続します。候補となる各TXパッドを、共通グランドと高インピーダンスのオシロスコープ入力でプローブします。パッドを駆動しないでください。<sup>[[5]](#references)</sup>

VISAはシリアルまたはEthernetの計測器セッションを開き、SCPIは出力、トリガー、波形の読み出しを制御します。<sup>[[5]](#references)[[6]](#references)</sup> `pyvisa`と`pyvisa-py`（シリアルVISAリソースでは`pyserial`も）をインストールします。`ResourceManager('@py')`はPythonバックエンドを明示的に選択します。<sup>[[5]](#references)[[7]](#references)</sup> リソース文字列とコマンドは、使用する計測器が対応しているものに置き換えてください。<sup>[[5]](#references)</sup>

Rigol MSO5000の例では、基板に電源を入れる前に、立ち下がりエッジのシングルショットトリガーを設定します。アイドル時にHighのUART TXは、スタートビットで最初にLowへ遷移します。<sup>[[5]](#references)</sup> トリガーしきい値は、測定したアイドルレベルとLowレベルの間に設定し、タイムベースは対象の起動時間をカバーするように設定します。<sup>[[5]](#references)[[6]](#references)</sup> `:TRIG:HOLD`を使うと連続キャプチャでのトリガーの繰り返しを抑えられますが、シングルショットのキャプチャが実際に完了したか確認する必要があります。<sup>[[5]](#references)</sup> 以下のコードは起動を1回キャプチャし、符号なしバイトのサンプルとスケーリングメタデータの両方を保存します。タイムアウト時は無期限に待つのではなく、ターゲットの電源を切ります。<sup>[[5]](#references)[[6]](#references)</sup>

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

パッド調査では、プローブを移動した後に単発キャプチャを繰り返すか、電源セッションを開いたまま出力を切り替え、起動時の通電時間とオフ時間を設けます。電源を入れるたびにオシロスコープを再アームし、各ファイルが1回の起動と1つのパッドに対応するようにします。<sup>[[5]](#references)</sup>

Rigolのプリアンブルは`<format>,<type>,<points>,<count>,<xincrement>,...`です。<sup>[[6]](#references)</sup> **3番目**の値はポイント数であり、記事に記載されているサンプルレートではありません。<sup>[[5]](#references)[[6]](#references)</sup> 記事の例では、`25,000,000`ポイントと`xincrement = 2e-8`秒から、`1 / xincrement = 50,000,000`サンプル/秒となり、25 MSa/sではありません。<sup>[[5]](#references)[[6]](#references)</sup> プリアンブルはバイナリファイルと一緒に保存し、読み取り長が`<points>`と一致することを確認してください。このガイドでは、大きな記録向けに分割読み取り／バッチ読み取りの方法を説明しています。<sup>[[6]](#references)</sup>

キャプチャした信号をデコードするには、PulseViewで`capture.bin`を**Raw Analog Data Without Header**としてインポートし、符号なし8ビット（`U8`）の値を選択して、`xincrement`から計算したサンプルレートを入力します。<sup>[[5]](#references)[[6]](#references)</sup> アナログチャンネルに**Logic via Threshold**を適用し、サンプルの低値と高値の間にしきい値を設定します。<sup>[[5]](#references)</sup> きれいなスタートビットの幅を測定してボーレートを推定し（57,600 baudなら約17.36 µs）、PulseViewのUARTデコーダーを適用して、複数のフレームが一貫してデコードされることを確認します。<sup>[[5]](#references)</sup> 立ち下がりエッジだけでは、そのパッドがUARTである証拠にはなりません。

## CP210X UART-TTYアダプター

CP210x USB-to-UARTブリッジは、多くのプロトタイピングボードや安価なアダプターに搭載されています。一般的なモジュールは、GND、RXD、TXDとともに電源ピンも備えていますが、ヘッダーやI/Oレベルはさまざまです。実際の電圧は、ボードの設計またはデータシートで確認してください。通常は、GNDと、アダプターのRXをターゲットのTXに接続します。受信専用での検証を済ませてから、アダプターのTXをターゲットのRXに接続します。対象機器への給電を意図しており、その機器が許容することを確認済みの場合を除き、アダプターの5 V/3.3 V電源ピンは接続しないでください。<sup>[[3]](#references)</sup>

アダプターが検出されない場合は、ホストシステムにCP210Xドライバーがインストールされていることを確認してください。アダプターが検出されて接続されたら、picocom、minicom、screenなどのツールを使用できます。

Linux/MacOSシステムに接続されているデバイスを一覧表示するには、

```
ls /dev/
```

UARTインターフェースを基本的に操作するには、次のコマンドを使用します。

```
picocom /dev/<adapter> --baud <baudrate>
```

minicomを設定するには、次のコマンドを使用します。

```
minicom -s
```

`Serial port setup` オプションで、baudrate やデバイス名などの設定を行います。

設定後、`minicom` を実行して UART コンソールを開きます。

## Arduino UNO R3 経由の UART（Atmel 328p チップを取り外せるボード）

UART Serial to USB アダプターがない場合は、簡単な hack で Arduino UNO R3 を使用できます。Arduino UNO R3 はたいていどこでも入手できるため、大幅な時間の節約になります。

Arduino UNO R3 には、ボード上に USB to Serial アダプターが搭載されています。UART 接続を確立するには、ボードから Atmel 328p マイクロコントローラーチップを取り外すだけです。この hack は、Atmel 328p がボードにはんだ付けされていない（SMD 版が使われている）Arduino UNO R3 のバリエーションで動作します。Arduino の RX ピン（Digital Pin 0）を UART インターフェースの TX ピンに、Arduino の TX ピン（Digital Pin 1）を UART インターフェースの RX ピンに接続します。

Arduino IDE の **Serial Monitor** または専用のターミナルを、ターゲットの baud rate に設定して使用します。標準的な Uno R3 のシリアル信号は 5 V ロジックなので、3.3 V またはそれ以下の電圧のターゲットに接続する前に、レベルシフターまたは分圧器を使用してください。

## Bus Pirate

以下の記録では、旧式の Bus Pirate ファームウェアインターフェースを使って UART の出力を監視しています。新しい Bus Pirate ファームウェアでは、`m uart`、`{`/`}`、`monitor`、`bridge` などのコマンドを使用します。インストールされているバージョンのドキュメントを参照してください。<sup>[[2]](#references)</sup>

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

## UART Consoleを使ったFirmwareのダンプ

UART consoleを使うと、実行時のboot logにアクセスでき、場合によってはbootloaderやoperating-system shellにもアクセスできます。read-only consoleでも、memory map、flash driver、boot argument、partition layout、firmware versionが明らかになることがあります。FirmwareはSPI NOR/NAND、eMMCなどのデバイスに保存されている場合があります。一般にEEPROMから実行されるわけではなく、マウントされた永続filesystemに書き込んだファイルが再起動時に必ず消えるとは限りません。

取得方法はいくつかあり、SPIのセクションでは外部flashから直接読み取る方法を説明します。bootloaderに安全な読み取りコマンドがあれば、consoleを使った取得のほうが侵襲性を抑えられます。ただし、bootの中断やflashコマンドは可用性に影響する場合があるため、元の状態を記録し、write/erase操作は避けてください。

consoleを使ったfirmwareのダンプは、多くの場合bootloaderの起動を中断するところから始まります。多くの組み込みLinuxデバイスでは**Das U-Boot**が使われますが、独自のbootloaderを使うものや、interactive consoleが無効になっているものもあります。

interactive bootloaderの有無を確認するには、対象の電源を切った状態でUARTの受信経路とterminalを接続し、記録を開始してから電源を入れます。表示されるautoboot promptに従ってください。buildによっては、キー入力や短いキー操作が必要な場合も、割り込みが完全に無効な場合もあります。

割り込みに成功したら、`help`、`printenv`、およびread-onlyの確認コマンドを使って、そのvendorのmemoryとstorageのレイアウトを把握してからアドレスにアクセスします。

U-Bootの`md`が表示するのは**アドレス指定可能なメモリ**であり、自動的に「EEPROM」を表示するわけではありません。まず、`mtd list`、`sf probe`、`mmc info`、`part list`などのboard固有コマンド、environment variable、boot logを使い、正しいマップ済みアドレスを特定するか、flash領域をRAMにロードします。その後、既知の範囲をbyte単位で表示します:<sup>[[4]](#references)</sup>

```
md.b <address> <byte_count>
```

開始前にシリアル出力をログに記録してください。`md.b` の出力にはアドレス列と ASCII 列が含まれているため、raw ROM image ではなくテキスト表現です。

アドレス列と ASCII 列を取り除き、16 進数のバイト列だけを連結して、バイナリにデコードしてください（例: `xxd -r -p`）。解析前に、想定されるバイト数を確認し、ハッシュを記録してください。

```
xxd -r -p firmware.hex > firmware.bin
sha256sum firmware.bin
binwalk -e firmware.bin
```

Binwalkは、再構成されたバイナリ内の既知のシグネチャを識別します。コンソールでデータを安定して転送できない場合は、適切なSPI/eMMC/NANDインターフェースを介してflashを直接読み出す方が、通常は高速でエラーも発生しにくくなります。

U-Bootでは、割り込みが無効化されていたり、ベンダー固有のキーシーケンスが必要だったり、メモリ/flashコマンドがロックされていたりすることがあります。文字をむやみに送信せず、autobootのプロンプトとブートログを確認してください。コンソールへの割り込みができない場合は、ブートログを保存し、非侵襲的なファームウェア取得方法に切り替えてください。

## References

- [1] [Microchip PIC32ファミリー リファレンスマニュアル - UART](https://ww1.microchip.com/downloads/en/DeviceDoc/60001107H.pdf)
- [2] [Bus Pirateドキュメント - UARTモードと電気的制限](https://docs.buspirate.com/docs/command-reference/#uart)
- [3] [Silicon Labs - CP2102Cデータシート](https://www.silabs.com/documents/public/data-sheets/cp2102c-datasheet.pdf)
- [4] [U-Bootドキュメント - `md`メモリ表示コマンド](https://docs.u-boot.org/en/latest/usage/cmd/md.html)
- [5] [VoidStar Security — リバースエンジニア向けSCPIとハードウェア計測器、その1](https://voidstarsec.com/blog/scpi-and-hardware-instrumentation-for-reverse-engineers-part-1)
- [6] [Rigol MSO5000プログラミングガイド](https://www.batronix.com/files/Rigol/Oszilloskope/MSO5000/MSO5000_ProgrammingGuide_EN-V2.0.pdf)
- [7] [PyVISA — バックエンドの設定](https://pyvisa.readthedocs.io/en/latest/introduction/configuring.html)
- [8] [VoidStar Security — ハードウェアハッキングの基礎を再確認、その2](https://voidstarsec.com/blog/brushing-up-part-2)
{{#include ../../banners/hacktricks-training.md}}
