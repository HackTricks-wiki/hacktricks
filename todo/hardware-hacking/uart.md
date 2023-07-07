<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSを入手したり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**テレグラムグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。**

</details>


# 基本情報

UARTはシリアルプロトコルであり、コンポーネント間でデータを1ビットずつ転送します。一方、並列通信プロトコルは複数のチャネルを介してデータを同時に転送します。一般的なシリアルプロトコルにはRS-232、I2C、SPI、CAN、Ethernet、HDMI、PCI Express、およびUSBがあります。

一般的に、UARTはアイドル状態ではラインが高い（論理1の値）に保持されます。次に、データ転送の開始を示すために、送信機は受信機にスタートビットを送信します。この間、信号は低い（論理0の値）に保持されます。次に、送信機は実際のメッセージを含む5〜8ビットのデータビットを送信し、オプションのパリティビットと1つまたは2つのストップビット（論理1の値）が続きます。エラーチェックに使用されるパリティビットは実際にはほとんど見られません。ストップビット（またはビット）は送信の終わりを示します。

最も一般的な構成は8N1と呼ばれます：8ビットのデータ、パリティなし、および1ビットのストップビットです。たとえば、8N1 UART構成で文字C、またはASCIIの0x43を送信する場合、次のビットを送信します：0（スタートビット）；0、1、0、0、0、0、1、1（バイナリの0x43の値）；0（ストップビット）。

![](<../../.gitbook/assets/image (648) (1) (1) (1) (1).png>)

UARTと通信するためのハードウェアツール：

* USBシリアルアダプタ
* CP2102またはPL2303チップを搭載したアダプタ
* Bus Pirate、Adafruit FT232H、Shikra、またはAttify Badgeなどの多目的ツール

## UARTポートの特定

UARTには**TX**（送信）、**RX**（受信）、**Vcc**（電圧）、および**GND**（グラウンド）の4つのポートがあります。PCBに**`TX`**と**`RX`**の文字が**書かれている**ポートを見つけることができるかもしれません。ただし、表示がない場合は、**マルチメータ**または**ロジックアナライザ**を使用して自分で見つける必要があるかもしれません。

マルチメータとデバイスの電源を切った状態で：

* **GND**ピンを特定するには、**連続性テスト**モードを使用し、バックリードをグラウンドに置き、赤いリードでテストします。マルチメータから音が聞こえるまで、いくつかのGNDピンを見つけることができますが、UARTに属するピンを見つけることができるかもしれません。
* **VCCポート**を特定するには、**DC電圧モード**を設定し、電圧を20Vに設定します。黒いプローブをグラウンドに、赤いプローブをピンに接続します。デバイスの電源をオンにします。マルチメータが3.3Vまたは5Vの一定の電圧を測定する場合、Vccピンを見つけました。他の電圧が表示される場合は、他のポートで再試行します。
* **TXポート**を特定するには、**DC電圧モード**を20Vに設定し、黒いプローブをグラウンドに、赤いプローブをピンに接続し、デバイスの電源をオンにします。電源をオンにすると、一時的に電圧が変動し、その後Vccの値で安定する場合、おそらくTXポートを見つけたと思われます。これは、電源をオンにすると、デバッグデータを送信するためです。
* **RXポート**は他の3つに最も近いものであり、UARTピンの中で最も電圧変動が少なく、最も低い値です。

TXとRXのポートを混同しても何も起こりませんが、GNDとVCCのポートを混同すると回路を破損する可能性があります。

ロジックアナライザを使用する場合：

## UARTボーレートの特定

正しいボーレートを特定する最も簡単な方法は、**TXピンの出力を見てデータを読み取ろうとする**ことです。受け取ったデータが読み取れない場合は、データが読み取れるまで次の可能なボーレートに切り替えます。これにはUSBシリアルアダプタやBus Pirateなどの多目的デバイスと、[baudrate.py](https://github.com/devttys0/baudrate/)などのヘルパースクリプトを使用できます。最も一般的なボーレートは9600、38400、19200、57600、および115200です。

{% hint style="danger" %}
このプロトコルでは、デバイスのTXを他のデバイスのRXに接続する必要があることに注意してください！
{% endhint %}
# Bus Pirate

このシナリオでは、Arduinoがプログラムのすべての出力をシリアルモニターに送信しているUART通信をスニフィングします。
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

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ会社**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSを入手したり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>
