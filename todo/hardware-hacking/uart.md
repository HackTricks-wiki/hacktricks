<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong>を通じて、ゼロからヒーローまでAWSハッキングを学びましょう</summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝**したい場合や**HackTricksをPDFでダウンロード**したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションを見つける
- 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)をフォローする
- **ハッキングトリックを共有するには、**[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。

</details>


# 基本情報

UARTはシリアルプロトコルであり、コンポーネント間でデータを1ビットずつ転送します。一方、並列通信プロトコルは複数のチャネルを通じてデータを同時に送信します。一般的なシリアルプロトコルには、RS-232、I2C、SPI、CAN、Ethernet、HDMI、PCI Express、USBなどがあります。

通常、UARTがアイドル状態にあるときは、ラインは高い（論理1の値）に保持されます。次に、データ転送の開始を示すために、送信機が受信機にスタートビットを送信します。この間、信号は低い（論理0の値）に保持されます。次に、送信機は、実際のメッセージを含む5〜8ビットのデータビットを送信し、オプションのパリティビットと1または2ビットのストップビット（論理1の値）が続きます。エラーチェックに使用されるパリティビットは実際にはほとんど見られません。ストップビット（またはビット）は送信の終わりを示します。

最も一般的な構成を8N1と呼びます：8つのデータビット、パリティなし、1つのストップビット。たとえば、8N1 UART構成で文字CまたはASCIIの0x43を送信したい場合、次のビットを送信します：0（スタートビット）；0、1、0、0、0、0、1、1（バイナリでの0x43の値）、および0（ストップビット）。

![](<../../.gitbook/assets/image (648) (1) (1) (1) (1).png>)

UARTと通信するためのハードウェアツール：

- USB-to-serialアダプタ
- CP2102またはPL2303チップを搭載したアダプタ
- Bus Pirate、Adafruit FT232H、Shikra、またはAttify Badgeなどの多目的ツール

## UARTポートの識別

UARTには4つのポートがあります：**TX**（送信）、**RX**（受信）、**Vcc**（電圧）、および**GND**（グラウンド）。PCBに**`TX`**と**`RX`**の文字が**書かれている**4つのポートを見つけることができるかもしれません。ただし、明確な指示がない場合は、**マルチメータ**または**ロジックアナライザ**を使用して自分で見つける必要があるかもしれません。

**マルチメータ**とデバイスの電源を切った状態で：

- **GND**ピンを特定するには、**連続性テスト**モードを使用し、バックリードをグラウンドに置き、赤いリードでテストして、マルチメータから音が聞こえるまで試してください。複数のGNDピンがPCB上に見つかる場合がありますので、UARTに属するピンを見つけたかどうかはわかりません。
- **VCCポート**を特定するには、**DC電圧モード**を設定し、20Vの電圧に設定します。黒いプローブをグラウンドに、赤いプローブをピンに置きます。デバイスの電源を入れます。マルチメータが3.3Vまたは5Vの定電圧を測定した場合、Vccピンを見つけました。他の電圧が表示される場合は、他のポートで再試行してください。
- **TX** **ポート**を特定するには、**DC電圧モード**を20Vの電圧に設定し、黒いプローブをグラウンドに、赤いプローブをピンに置き、デバイスの電源を入れます。電源を入れると、一時的に電圧が変動し、その後Vccの値に安定する場合、おそらくTXポートを見つけた可能性が高いです。これは、電源を入れるとデバッグデータが送信されるためです。
- **RXポート**は他の3つに最も近いものであり、UARTピンの中で最も低い電圧変動と最も低い全体的な値を持っています。

TXとRXポートを混同しても何も起こりませんが、GNDとVCCポートを混同すると回路を破損させる可能性があります。

一部のターゲットデバイスでは、製造元によってUARTポートが無効にされている場合があります。その場合、基板内の接続を追跡し、いくつかのブレイクアウトポイントを見つけることが役立ちます。UARTの検出がないことと回路の切断を確認する強力なヒントは、デバイスの保証を確認することです。デバイスに保証が付属して出荷された場合、製造元はいくつかのデバッグインターフェイス（この場合はUART）を残し、したがってUARTを切断し、デバッグ中に再接続する必要があります。これらのブレイクアウトピンは、はんだ付けまたはジャンパーワイヤーで接続できます。

## UARTボーレートの識別

正しいボーレートを特定する最も簡単な方法は、**TXピンの出力を見てデータを読み取ろうとする**ことです。受信したデータが読み取れない場合は、データが読み取れるまで次の可能なボーレートに切り替えてください。これには、USB-to-serialアダプタやBus Pirateなどの多目的デバイスと、[baudrate.py](https://github.com/devttys0/baudrate/)などのヘルパースクリプトを使用できます。最も一般的なボーレートは9600、38400、19200、57600、115200です。

{% hint style="danger" %}
このプロトコルでは、1つのデバイスのTXを他のデバイスのRXに接続する必要があることに注意してください！
{% endhint %}

# CP210X UART to TTYアダプタ

CP210Xチップは、NodeMCU（esp8266搭載）などのプロトタイピングボードでシリアル通信に使用されます。これらのアダプタは比較的安価であり、ターゲットのUARTインターフェースに接続するために使用できます。デバイスには5つのピンがあります：5V、GND、RXD、TXD、3.3V。損傷を防ぐために、ターゲットがサポートする電圧に接続するように注意してください。最後に、アダプタのRXDピンをターゲットのTXDに、アダプタのTXDピンをターゲットのRXDに接続してください。

アダプタが検出されない場合は、ホストシステムにCP210Xドライバがインストールされていることを確認してください。アダプタが検出され、接続されたら、picocom、minicom、またはscreenなどのツールを使用できます。

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
シリアルポートの設定（ボーレートやデバイス名など）は、「シリアルポートの設定」オプションで行います。

設定後、`minicom`コマンドを使用してUARTコンソールを開始します。

# Bus Pirate

このシナリオでは、ArduinoのUART通信をスニッフすることになります。Arduinoはプログラムのすべての出力をシリアルモニタに送信しています。
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
<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションを見る
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)で**フォロー**してください。
* **ハッキングトリックを共有するために、PRを** [**HackTricks**](https://github.com/carlospolop/hacktricks) **および** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **のGitHubリポジトリに提出してください。**

</details>
