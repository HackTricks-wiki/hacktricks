# UART

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong>を使って、<strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong>！</summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)を入手する
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter**で**@carlospolopm**をフォローする🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
- **ハッキングテクニックを共有するために、[HackTricks](https://github.com/carlospolop/hacktricks)と[HackTricks Cloud](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。**

</details>

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io)は、**ダークウェブ**を活用した検索エンジンで、企業やその顧客が**盗難マルウェア**によって**侵害**されていないかをチェックする**無料**機能を提供しています。

WhiteIntelの主な目標は、情報窃取マルウェアによるアカウント乗っ取りやランサムウェア攻撃に対抗することです。

彼らのウェブサイトをチェックして、**無料**でエンジンを試すことができます：

{% embed url="https://whiteintel.io" %}

***

## 基本情報

UARTはシリアルプロトコルであり、コンポーネント間でデータを1ビットずつ転送します。一方、並列通信プロトコルは複数のチャネルを通じてデータを同時に送信します。一般的なシリアルプロトコルには、RS-232、I2C、SPI、CAN、Ethernet、HDMI、PCI Express、USBなどがあります。

通常、UARTがアイドル状態にあるときは、ラインは高い（論理1の値）に保持されます。次に、データ転送の開始を示すために、送信機が開始ビットを受信機に送信します。この間、信号は低い（論理0の値）に保持されます。次に、送信機は、実際のメッセージを含む5〜8ビットのデータビットを送信し、オプションのパリティビットと1または2ビットのストップビット（論理1の値）が続きます。エラーチェックに使用されるパリティビットは、実際にはほとんど見られません。ストップビット（またはビット）は、送信の終了を示します。

最も一般的な構成を8N1と呼びます：8ビットのデータ、パリティなし、1ビットのストップビット。たとえば、8N1 UART構成で文字CまたはASCIIの0x43を送信したい場合、次のビットを送信します：0（開始ビット）；0、1、0、0、0、0、1、1（バイナリの0x43の値）、および0（ストップビット）。

![](<../../.gitbook/assets/image (764).png>)

UARTと通信するためのハードウェアツール：

- USBシリアルアダプタ
- CP2102またはPL2303チップを搭載したアダプタ
- Bus Pirate、Adafruit FT232H、Shikra、またはAttify Badgeなどの多目的ツール

### UARTポートの識別

UARTには4つのポートがあります：**TX**（送信）、**RX**（受信）、**Vcc**（電圧）、および**GND**（グラウンド）。PCBに**`TX`**と**`RX`**の文字が**書かれている**4つのポートを見つけることができるかもしれません。ただし、指示がない場合は、**マルチメーター**または**ロジックアナライザー**を使用して自分で見つける必要があるかもしれません。

**マルチメーター**とデバイスの電源を切った状態で：

- **GND**ピンを特定するには、**連続性テスト**モードを使用し、バックリードをグラウンドに置き、赤いリードでテストして、マルチメーターから音が聞こえるまで試してください。複数のGNDピンがPCB上に見つかる場合がありますので、UARTに属するものを見つけたかどうかはわかりません。
- **VCCポート**を特定するには、**DC電圧モード**を設定し、20Vの電圧に設定します。黒いプローブをグラウンドに、赤いプローブをピンに置きます。デバイスの電源を入れます。マルチメーターが3.3Vまたは5Vの定電圧を測定した場合、Vccピンを見つけました。他の電圧が表示される場合は、他のポートで再試行してください。
- **TX** **ポート**を特定するには、**DC電圧モード**を20Vの電圧に設定し、黒いプローブをグラウンドに、赤いプローブをピンに置き、デバイスの電源を入れます。電圧が数秒間変動した後、Vcc値で安定する場合、おそらくTXポートを見つけました。これは、電源を入れるときにいくつかのデバッグデータを送信するためです。
- **RXポート**は他の3つに最も近いものであり、UARTピンの中で最も低い電圧変動と最も低い全体的な値を持っています。

TXとRXポートを混同しても何も起こりませんが、GNDとVCCポートを混同すると回路を焼き切る可能性があります。

一部のターゲットデバイスでは、製造業者によってUARTポートが無効にされている場合があります。その場合、基板内の接続を追跡し、いくつかのブレイクアウトポイントを見つけることが役立ちます。UARTの検出がないことと回路の切断を確認する強力なヒントは、デバイスの保証を確認することです。デバイスに保証が付属して出荷された場合、製造業者はいくつかのデバッグインターフェース（この場合はUART）を残し、したがって、UARTを切断し、デバッグ中に再接続する必要があります。これらのブレイクアウトピンは、はんだ付けまたはジャンパーワイヤーで接続できます。

### UARTボーレートの識別

正しいボーレートを特定する最も簡単な方法は、**TXピンの出力を見てデータを読み取ろうとする**ことです。受信したデータが読めない場合は、データが読めるまで次の可能なボーレートに切り替えてください。これには、USBシリアルアダプタやBus Pirateなどの多目的デバイスと、[baudrate.py](https://github.com/devttys0/baudrate/)などのヘルパースクリプトを使用できます。最も一般的なボーレートは9600、38400、19200、57600、115200です。

{% hint style="danger" %}
このプロトコルでは、1つのデバイスのTXを他のデバイスのRXに接続する必要があることに注意してください！
{% endhint %}

## CP210X UART to TTYアダプター

CP210Xチップは、NodeMCU（esp8266搭載）などのプロトタイピングボードでシリアル通信に使用されます。これらのアダプターは比較的安価であり、ターゲットのUARTインターフェースに接続するために使用できます。デバイスには5つのピンがあります：5V、GND、RXD、TXD、3.3V。ターゲットがサポートする電圧に接続するようにして、損傷を防いでください。最後に、アダプターのRXDピンをターゲットのTXDに、アダプターのTXDピンをターゲットのRXDに接続してください。

アダプターが検出されない場合は、ホストシステムにCP210Xドライバーがインストールされていることを確認してください。アダプターが検出され、接続されたら、picocom、minicom、またはscreenなどのツールを使用できます。

Linux/MacOSシステムに接続されたデバイスをリストアップするには：
```
ls /dev/
```
UART インターフェースとの基本的なやり取りには、次のコマンドを使用します:
```
picocom /dev/<adapter> --baud <baudrate>
```
以下のコマンドを使用して、minicomを構成します：

```bash
sudo minicom -s
```
```
minicom -s
```
`シリアルポートの設定`オプションでボーレートやデバイス名などの設定を構成します。

構成後、`minicom`コマンドを使用してUARTコンソールを開始します。

## Arduino UNO R3を介したUART（取り外し可能なAtmel 328pチップボード）

UARTシリアルからUSBアダプタが利用できない場合、Arduino UNO R3をクイックハックとして使用できます。通常、どこでも入手できるArduino UNO R3を使用することで、多くの時間を節約できます。

Arduino UNO R3には、ボード自体にUSBからシリアルへのアダプタが内蔵されています。UART接続を取得するには、ボードからAtmel 328pマイクロコントローラチップを抜き取るだけです。このハックは、Atmel 328pがボードにはんだ付けされていないArduino UNO R3バリアント（SMDバージョンが使用されている）で機能します。ArduinoのRXピン（デジタルピン0）をUARTインターフェースのTXピンに、ArduinoのTXピン（デジタルピン1）をUARTインターフェースのRXピンに接続します。

最後に、UARTインターフェースに応じてボーレートを設定して、Arduino IDEを使用することをお勧めします。

## Bus Pirate

このシナリオでは、プログラムのすべての出力をシリアルモニタに送信しているArduinoのUART通信をスニッフすることになります。
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

UARTコンソールは、ランタイム環境で基礎ファームウェアを操作するための優れた方法を提供します。ただし、UARTコンソールアクセスが読み取り専用の場合、多くの制約が発生する可能性があります。多くの組み込みデバイスでは、ファームウェアはEEPROMに保存され、揮発性メモリを持つプロセッサで実行されます。したがって、ファームウェアは読み取り専用のまま保持されます。製造時の元のファームウェアはEEPROM自体にあり、新しいファイルは揮発性メモリのため失われます。そのため、組み込みファームウェアを操作する際にファームウェアをダンプすることは貴重な取り組みです。

これを行うための多くの方法があり、SPIセクションではさまざまなデバイスからファームウェアを直接抽出する方法が説明されています。ただし、物理デバイスや外部インタラクションを使用してファームウェアをダンプする前に、まずUARTを使用してファームウェアをダンプすることが推奨されています。

UARTコンソールからファームウェアをダンプするには、まずブートローダにアクセスする必要があります。多くの人気ベンダーは、Linuxをロードするためにuboot（Universal Bootloader）を使用しているため、ubootにアクセスすることが必要です。

ブートローダにアクセスするには、UARTポートをコンピュータに接続し、任意のシリアルコンソールツールを使用し、デバイスへの電源供給を切断します。セットアップが完了したら、Enterキーを押して押し続けます。最後に、デバイスに電源を接続してブートさせます。

これにより、ubootのロードが中断され、メニューが表示されます。ubootコマンドを理解し、それらをリストするためにヘルプメニューを使用することが推奨されます。これはおそらく`help`コマンドになるでしょう。異なるベンダーが異なる構成を使用しているため、それぞれを個別に理解する必要があります。

通常、ファームウェアをダンプするためのコマンドは次のとおりです：
```
md
```
which stands for "memory dump". This will dump the memory (EEPROM Content) on the screen. It is recommended to log the Serial Console output before starting the proceedure to capture the memory dump.

Finally, just strip out all the unnecessary data from the log file and store the file as `filename.rom` and use binwalk to extract the contents:
```
binwalk -e <filename.rom>
```
EEPROM内の可能な内容を、hexファイルで見つかったシグネチャに基づいてリストします。

ただし、使用されている場合でも、ubootがアンロックされているとは限らないことに注意する必要があります。Enterキーが機能しない場合は、Spaceキーなどの異なるキーをチェックしてください。ブートローダーがロックされており中断されない場合、この方法は機能しません。デバイスのubootがブートローダーであるかどうかを確認するには、デバイスのブート時にUARTコンソールの出力をチェックしてください。ブート時にubootと言及されるかもしれません。

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io)は、**ダークウェブ**を活用した検索エンジンで、企業やその顧客が**盗難マルウェア**によって**侵害**されていないかをチェックするための**無料**機能を提供しています。

WhiteIntelの主な目標は、情報窃取マルウェアによるアカウント乗っ取りやランサムウェア攻撃と戦うことです。

彼らのウェブサイトをチェックして、**無料**でエンジンを試すことができます：

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>**htARTE（HackTricks AWS Red Team Expert）**で**ゼロからヒーローまでのAWSハッキング**を学ぶ！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝**したい場合や、**PDFでHackTricksをダウンロード**したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[NFTs](https://opensea.io/collection/the-peass-family)コレクションを見つける
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)を**フォロー**してください。
* **HackTricks**と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングトリックを共有してください。

</details>
