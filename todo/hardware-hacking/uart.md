<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* **HackTricks**の[**GitHubリポジトリ**](https://github.com/carlospolop/hacktricks)や[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出して、あなたのハッキングテクニックを共有する。

</details>


# 基本情報

UARTはシリアルプロトコルで、データを一度に1ビットずつコンポーネント間で転送します。対照的に、並列通信プロトコルは複数のチャネルを通じて同時にデータを送信します。一般的なシリアルプロトコルには、RS-232、I2C、SPI、CAN、Ethernet、HDMI、PCI Express、USBがあります。

通常、UARTがアイドル状態の間、ラインは高い状態（論理値1）に保持されます。次に、データ転送の開始を示すために、送信機はスタートビットを受信機に送信し、その間信号は低い状態（論理値0）に保持されます。その後、送信機は実際のメッセージを含む5から8のデータビットを送信し、オプションでパリティビットと1または2のストップビット（論理値1）を構成に応じて送信します。エラーチェックに使用されるパリティビットは、実際にはほとんど見られません。ストップビット（またはビット）は、送信の終了を示します。

最も一般的な構成を8N1と呼びます：8データビット、パリティなし、1ストップビット。例えば、8N1のUART構成で文字C、またはASCIIでの0x43を送信したい場合、次のビットを送信します：0（スタートビット）；0、1、0、0、0、0、1、1（0x43のバイナリ値）、そして1（ストップビット）。

![](<../../.gitbook/assets/image (648) (1) (1) (1) (1).png>)

UART通信に使用するハードウェアツール：

* USB-to-serialアダプタ
* CP2102またはPL2303チップを搭載したアダプタ
* Bus Pirate、Adafruit FT232H、Shikra、またはAttify Badgeなどの多目的ツール

## UARTポートの特定

UARTには4つのポートがあります：**TX**(送信)、**RX**(受信)、**Vcc**(電圧)、**GND**(グラウンド)。PCBに**`TX`**と**`RX`**の文字が**記載されている**4つのポートを見つけることができるかもしれません。しかし、表示がない場合は、**マルチメーター**や**ロジックアナライザー**を使用して自分で見つける必要があるかもしれません。

**マルチメーター**を使用し、デバイスの電源を切った状態で：

* **GNDピン**を特定するには、**連続テストモード**を使用し、黒リードをグラウンドに置き、赤リードでテストしてマルチメーターから音がするまで試します。PCB上には複数のGNDピンが見つかるので、UARTに属するものを見つけたかもしれませんし、見つけていないかもしれません。
* **VCCポート**を特定するには、**直流電圧モード**を設定し、20Vまでの電圧に設定します。黒プローブをグラウンドに、赤プローブをピンに置きます。デバイスの電源を入れます。マルチメーターが3.3Vまたは5Vの一定の電圧を測定した場合、Vccピンを見つけたことになります。他の電圧が出た場合は、他のポートで再試行してください。
* **TXポート**を特定するには、20Vまでの**直流電圧モード**、黒プローブをグラウンドに、赤プローブをピンに置き、デバイスの電源を入れます。数秒間電圧が変動し、その後Vccの値で安定する場合、TXポートを見つけた可能性が高いです。これは、電源を入れるとデバッグデータを送信するためです。
* **RXポート**は他の3つに最も近いもので、UARTピンの中で最も電圧変動が少なく、全体的な値も最も低いです。

TXとRXポートを間違えても何も起こりませんが、GNDとVCCポートを間違えると回路が焼損する可能性があります。

ロジックアナライザーを使用する場合：

## UARTボーレートの特定

正しいボーレートを特定する最も簡単な方法は、**TXピンの出力を見てデータを読む**ことです。読めるデータが得られない場合は、データが読めるようになるまで次の可能なボーレートに切り替えます。これには、USB-to-serialアダプタやBus Pirateのような多目的デバイスを使用し、[baudrate.py](https://github.com/devttys0/baudrate/)のようなヘルパースクリプトを使用できます。最も一般的なボーレートは9600、38400、19200、57600、115200です。

{% hint style="danger" %}
このプロトコルでは、一方のデバイスのTXを他方のデバイスのRXに接続する必要があることに注意してください！
{% endhint %}

# Bus Pirate

このシナリオでは、プログラムのすべての出力をシリアルモニターに送信しているArduinoのUART通信を嗅ぎ取ります。
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

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**テレグラムグループ**](https://t.me/peass)に参加する、または**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有する**。

</details>
