<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert) を使ってゼロからヒーローになる AWS ハッキングを学ぶ</strong></a><strong>!</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks にあなたの会社を広告したい**、または **HackTricks を PDF でダウンロードしたい** 場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式 PEASS & HackTricks グッズ**](https://peass.creator-spring.com) を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) を発見する、私たちの独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) のコレクション
* 💬 [**Discord グループ**](https://discord.gg/hRep4RUj7f) に**参加する**か、[**telegram グループ**](https://t.me/peass) に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm) を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) の github リポジトリに PR を提出して、あなたのハッキングのコツを共有する。

</details>


#

# JTAG

JTAG はバウンダリスキャンを実行することができます。バウンダリスキャンは、各ピンの組み込みバウンダリスキャンセルとレジスタを含む特定の回路を分析します。

JTAG 標準は、バウンダリスキャンを実施するための**特定のコマンド**を定義しています。以下を含みます:

* **BYPASS** は他のチップを通過するオーバーヘッドなしで特定のチップをテストすることができます。
* **SAMPLE/PRELOAD** は、デバイスが通常の機能モードにあるときに入出力されるデータのサンプルを取ります。
* **EXTEST** はピンの状態を設定し読み取ります。

また、以下のような他のコマンドもサポートすることができます:

* デバイスを識別するための **IDCODE**
* デバイスの内部テストのための **INTEST**

これらの命令は、JTAGulator のようなツールを使用するときに遭遇するかもしれません。

## テストアクセスポート

バウンダリスキャンには、コンポーネントに組み込まれた JTAG テストサポート機能への**アクセスを提供する**一般的なポートである四線式の**テストアクセスポート (TAP)** のテストが含まれます。TAP は以下の五つのシグナルを使用します:

* テストクロック入力 (**TCK**) TCK は、TAP コントローラが単一のアクションを取る頻度（言い換えると、状態マシンの次の状態に移動する）を定義する**クロック**です。
* テストモード選択 (**TMS**) 入力 TMS は**有限状態マシン**を制御します。クロックの各ビートで、デバイスの JTAG TAP コントローラは TMS ピンの電圧をチェックします。電圧が一定の閾値以下の場合、信号は低いと見なされ 0 と解釈され、電圧が一定の閾値を超えると、信号は高いと見なされ 1 と解釈されます。
* テストデータ入力 (**TDI**) TDI は、スキャンセルを通じてチップに**データを送る**ピンです。JTAG はこのピン上の通信プロトコルを定義していないため、各ベンダーがこのピン上の通信プロトコルを定義する責任があります。
* テストデータ出力 (**TDO**) TDO は、チップから**データを送る**ピンです。
* テストリセット (**TRST**) 入力 オプションの TRST は、有限状態マシンを**既知の良い状態にリセット**します。または、TMS を 5 連続クロックサイクルで 1 に保持すると、TRST ピンがそうであるかのようにリセットを呼び出すため、TRST はオプションです。

時には、これらのピンが PCB にマークされているのを見つけることができます。他の場合では、**見つける**必要があるかもしれません。

## JTAG ピンの特定

JTAG ポートを検出する最も速いが最も高価な方法は、この目的のために特に作られたデバイスである **JTAGulator** を使用することです（ただし、**UART ピンアウトも検出する**ことができます）。

それにはボードのピンに接続できる**24チャンネル**があります。次に、**IDCODE** と **BYPASS** バウンダリスキャンコマンドを送信するすべての可能な組み合わせの**BF攻撃**を実行します。応答を受け取ると、各 JTAG シグナルに対応するチャンネルを表示します。

JTAG ピンアウトを特定する安価だがはるかに遅い方法は、Arduino 互換のマイクロコントローラにロードされた [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) を使用することです。

**JTAGenum** を使用する場合、まず列挙に使用するプロービングデバイスの**ピンを定義**します。デバイスのピンアウト図を参照し、これらのピンをターゲットデバイスのテストポイントに接続する必要があります。

JTAG ピンを特定する**第三の方法**は、PCB を検査してピンアウトの一つを探すことです。場合によっては、PCB が便利にも**Tag-Connect インターフェース**を提供していることがあり、これはボードに JTAG コネクタもある明確な兆候です。そのインターフェースがどのようなものかは [https://www.tag-connect.com/info/](https://www.tag-connect.com/info/) で見ることができます。さらに、PCB 上のチップセットの**データシート**を検査すると、JTAG インターフェースを指し示すピンアウト図が明らかになることがあります。

# SDW

SWD はデバッグ用に設計された ARM 固有のプロトコルです。

SWD インターフェースには**二つのピン**が必要です: 双方向の**SWDIO**信号で、これは JTAG の**TDI と TDO ピンとクロック**に相当し、**SWCLK** は JTAG の **TCK** に相当します。多くのデバイスは、**シリアルワイヤまたは JTAG デバッグポート (SWJ-DP)** をサポートしており、これは JTAG と SWD インターフェースを組み合わせたもので、SWD または JTAG プローブをターゲットに接続することができます。


<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert) を使ってゼロからヒーローになる AWS ハッキングを学ぶ</strong></a><strong>!</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks にあなたの会社を広告したい**、または **HackTricks を PDF でダウンロードしたい** 場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式 PEASS & HackTricks グッズ**](https://peass.creator-spring.com) を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) を発見する、私たちの独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) のコレクション
* 💬 [**Discord グループ**](https://discord.gg/hRep4RUj7f) に**参加する**か、[**telegram グループ**](https://t.me/peass) に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm) を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) の github リポジトリに PR を提出して、あなたのハッキングのコツを共有する。

</details>
