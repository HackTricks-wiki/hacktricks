# UART

<details>

<summary><strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFT**](https://opensea.io/collection/the-peass-family)コレクションを見つける
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォロー**する
- **ハッキングトリックを共有するには、PRを** [**HackTricks**](https://github.com/carlospolop/hacktricks) **と** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **のGitHubリポジトリに提出してください。**

</details>

### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io)は、**ダークウェブ**を活用した検索エンジンで、企業やその顧客が**盗聴マルウェア**によって**侵害**されていないかをチェックする**無料**機能を提供しています。

WhiteIntelの主な目標は、情報窃取マルウェアによるアカウント乗っ取りやランサムウェア攻撃に対抗することです。

彼らのウェブサイトをチェックして、**無料**でエンジンを試すことができます：

{% embed url="https://whiteintel.io" %}

---

## 基本情報

UARTはシリアルプロトコルであり、コンポーネント間でデータを1ビットずつ転送します。一方、並列通信プロトコルは複数のチャネルを通じてデータを同時に送信します。一般的なシリアルプロトコルには、RS-232、I2C、SPI、CAN、Ethernet、HDMI、PCI Express、USBなどがあります。

一般的に、UARTがアイドル状態にあるときは、ラインは高い（論理1の値）に保持されます。次に、データ転送の開始を示すために、送信機が受信機にスタートビットを送信します。この間、信号は低い（論理0の値）に保持されます。次に、送信機は、実際のメッセージを含む5〜8ビットのデータビットを送信し、オプションのパリティビットと1または2つのストップビット（論理1の値）が続きます。エラーチェックに使用されるパリティビットは、実際にはほとんど見られません。ストップビット（またはビット）は、送信の終了を示します。

最も一般的な構成を8N1と呼びます：8ビットのデータ、パリティなし、1ビットのストップビット。たとえば、ASCIIコードのC、または0x43を8N1 UART構成で送信する場合、次のビットを送信します：0（スタートビット）；0、1、0、0、0、0、1、1（バイナリでの0x43の値）、および0（ストップビット）。

![](<../../.gitbook/assets/image (761).png>)

UARTと通信するためのハードウェアツール：

- USBシリアルアダプタ
- CP2102またはPL2303チップを搭載したアダプタ
- Bus Pirate、Adafruit FT232H、Shikra、またはAttify Badgeなどの多目的ツール

### UARTポートの識別

UARTには4つのポートがあります：**TX**（送信）、**RX**（受信）、**Vcc**（電圧）、および**GND**（グラウンド）。PCBに**`TX`**と**`RX`**の文字が**書かれている**4つのポートを見つけることができるかもしれません。ただし、指示がない場合は、**マルチメーター**または**ロジックアナライザー**を使用して自分で見つける必要があるかもしれません。

**マルチメーター**とデバイスの電源を切った状態で：

- **GND**ピンを特定するには、**連続性テスト**モードを使用し、バックリードをグラウンドに置き、赤いリードでテストして、マルチメーターから音が聞こえるまで試してください。複数のGNDピンがPCB上に見つかる場合があるため、UARTに属するピンを見つけたかどうかはわかりません。
- **VCCポート**を特定するには、**DC電圧モード**を設定し、20Vの電圧に設定します。黒いプローブをグラウンドに、赤いプローブをピンに置きます。デバイスの電源を入れます。マルチメーターが3.3Vまたは5Vの定電圧を測定した場合、Vccピンを見つけたことになります。他の電圧が表示される場合は、他のポートで再試行してください。
- **TX** **ポート**を特定するには、**DC電圧モード**を20Vの電圧に設定し、黒いプローブをグラウンドに、赤いプローブをピンに置き、デバイスの電源を入れます。電源を入れると、一部のデバッグデータが送信されるため、数秒間電圧が変動し、その後Vcc値に安定する場合、おそらくTXポートを見つけたことになります。
- **RXポート**は他の3つに最も近いポートであり、UARTピンの中で最も低い電圧変動と最も低い全体値を持っています。

TXとRXポートを混同しても何も起こりませんが、GNDとVCCポートを混同すると回路を焼き切る可能性があります。

一部のターゲットデバイスでは、製造元によってUARTポートが無効にされている場合があります。その場合、基板内の接続を追跡し、いくつかのブレイクアウトポイントを見つけることが役立つ場合があります。UARTの検出がないことと回路の切断を確認する強力なヒントは、デバイスの保証を確認することです。デバイスに保証が付属して出荷された場合、製造元はいくつかのデバッグインターフェイス（この場合はUART）を残し、したがって、UARTを切断し、デバッグ中に再接続する必要があります。これらのブレイクアウトピンは、はんだ付けまたはジャンパーワイヤーで接続できます。

### UARTボーレートの識別

正しいボーレートを特定する最も簡単な方法は、**TXピンの出力を見てデータを読み取ろうとする**ことです。受信したデータが読み取れない場合は、データが読み取れるまで次の可能なボーレートに切り替えてください。これには、USBシリアルアダプタやBus Pirateなどの多目的デバイスと、[baudrate.py](https://github.com/devttys0/baudrate/)などのヘルパースクリプトを使用できます。最も一般的なボーレートは9600、38400、19200、57600、115200です。

{% hint style="danger" %}
このプロトコルでは、1つのデバイスのTXを他のデバイスのRXに接続する必要があることに注意してください！
{% endhint %}

## CP210X UART to TTYアダプター

CP210Xチップは、NodeMCU（esp8266搭載）などのプロトタイピングボードでシリアル通信に使用されます。これらのアダプターは比較的安価であり、ターゲットのUARTインターフェースに接続するために使用できます。デバイスには5つのピンがあります：5V、GND、RXD、TXD、3.3V。ターゲットがサポートする電圧に接続するようにして、損傷を防ぐために注意してください。最後に、アダプターのRXDピンをターゲットのTXDに、アダプターのTXDピンをターゲットのRXDに接続してください。

アダプターが検出されない場合は、ホストシステムにCP210Xドライバーがインストールされていることを確認してください。アダプターが検出され、接続されたら、picocom、minicom、またはscreenなどのツールを使用できます。

Linux/MacOSシステムに接続されたデバイスをリストアップするには：
```
ls /dev/
```
UART インターフェースとの基本的なやり取りには、次のコマンドを使用します：
```
picocom /dev/<adapter> --baud <baudrate>
```
minicomを使用する場合は、次のコマンドを使用して構成します：
```
minicom -s
```
```
シリアルポートの設定（ボーレートやデバイス名など）を`Serial port setup`オプションで構成します。

設定後、`minicom`コマンドを使用してUARTコンソールを開始します。

## Arduino UNO R3を使用したUART（取り外し可能なAtmel 328pチップボード）

UARTシリアルからUSBアダプタが利用できない場合、Arduino UNO R3をクイックハックで使用できます。通常、どこでも入手できるArduino UNO R3を使用することで、多くの時間を節約できます。

Arduino UNO R3には、ボード自体にUSBからシリアルへのアダプタが内蔵されています。UART接続を取得するには、ボードからAtmel 328pマイクロコントローラチップを抜き取るだけです。このハックは、ボードにはAtmel 328pがはんだ付けされていないArduino UNO R3バリアントで機能します（SMDバージョンが使用されています）。ArduinoのRXピン（デジタルピン0）をUARTインターフェースのTXピンに接続し、ArduinoのTXピン（デジタルピン1）をUARTインターフェースのRXピンに接続します。

最後に、UARTインターフェースに応じてボーレートを設定して、Arduino IDEを使用することをお勧めします。

## Bus Pirate

このシナリオでは、プログラムのすべての出力をシリアルモニタに送信しているArduinoのUART通信をスニッフすることになります。
```
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
## UARTコンソールを使用してファームウェアをダンプする

UARTコンソールは、ランタイム環境で基盤ファームウェアを操作する優れた方法を提供します。ただし、UARTコンソールへのアクセスが読み取り専用の場合、多くの制約が発生する可能性があります。多くの組み込みデバイスでは、ファームウェアはEEPROMに保存され、揮発性メモリを持つプロセッサで実行されます。したがって、ファームウェアは読み取り専用に保持されており、製造時の元のファームウェアがEEPROM自体に内蔵されており、新しいファイルは揮発性メモリのため失われる可能性があります。そのため、組み込みファームウェアを操作する際にファームウェアをダンプすることは貴重な取り組みです。

これを行うための多くの方法があり、SPIセクションではさまざまなデバイスからファームウェアを直接抽出する方法が説明されています。ただし、物理デバイスや外部インタラクションを使用してファームウェアをダンプする前に、まずUARTを使用してファームウェアをダンプすることが推奨されています。

UARTコンソールからファームウェアをダンプするには、まずブートローダにアクセスする必要があります。多くの人気ベンダーはLinuxをロードするために <b>uboot</b>（Universal Bootloader）を使用しているため、<b>uboot</b>にアクセスすることが必要です。

<b>boot</b>ブートローダにアクセスするには、UARTポートをコンピュータに接続し、任意のシリアルコンソールツールを使用し、デバイスの電源供給を切断します。セットアップが完了したら、Enterキーを押し続けます。最後に、デバイスに電源を供給してブートさせます。

これにより、<b>uboot</b>のロードが中断され、メニューが表示されます。 <b>uboot</b>コマンドを理解し、ヘルプメニューを使用してそれらをリストすることが推奨されます。これはおそらく `help` コマンドになります。異なるベンダーが異なる構成を使用しているため、それぞれを個別に理解する必要があります。

通常、ファームウェアをダンプするためのコマンドは次のとおりです：
```
md
```
which stands for "memory dump". This will dump the memory (EEPROM Content) on the screen. It is recommended to log the Serial Console output before starting the proceedure to capture the memory dump.

Finally, just strip out all the unnecessary data from the log file and store the file as `filename.rom` and use binwalk to extract the contents:
```
binwalk -e <filename.rom>
```
EEPROM内の可能な内容を、ヘックスファイルで見つかったシグネチャに基づいてリストします。

ただし、使用されている場合でも、<b>uboot</b>がアンロックされているとは限らないことに注意する必要があります。Enterキーが機能しない場合は、Spaceキーなどの異なるキーをチェックしてください。ブートローダーがロックされており中断されない場合、この方法は機能しません。デバイスのブート時にUARTコンソールの出力をチェックして、<b>uboot</b>がデバイスのブートローダーであるかどうかを確認してください。ブート時に<b>uboot</b>が言及されるかもしれません。
