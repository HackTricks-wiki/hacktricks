<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ会社**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- 独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションである[**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見してください。

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- **[💬](https://emojipedia.org/speech-balloon/) Discordグループ**に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter**で**フォロー**する[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください**。

</details>


#

# JTAG

JTAGはバウンダリスキャンを実行することができます。バウンダリスキャンは、各ピンの埋め込みバウンダリスキャンセルとレジスタを含む特定の回路を分析します。

JTAG標準では、次のような**バウンダリスキャンを実行するための特定のコマンド**が定義されています。

* **BYPASS**は、他のチップを経由せずに特定のチップをテストすることができます。
* **SAMPLE/PRELOAD**は、デバイスが通常の動作モードにあるときにデータのサンプルを取得します。
* **EXTEST**は、ピンの状態を設定および読み取ります。

また、次のような他のコマンドもサポートできます。

* デバイスを識別するための**IDCODE**
* デバイスの内部テストのための**INTEST**

JTAGulatorのようなツールを使用すると、これらの命令に遭遇することがあります。

## テストアクセスポート

バウンダリスキャンには、コンポーネントに組み込まれたJTAGテストサポート機能にアクセスするための汎用ポートである**4本のワイヤテストアクセスポート（TAP）**のテストが含まれます。TAPは次の5つの信号を使用します。

* テストクロック入力（**TCK**）TCKは、TAPコントローラが単一のアクションを実行する頻度（つまり、ステートマシンで次の状態にジャンプする頻度）を定義する**クロック**です。
* テストモード選択（**TMS**）入力TMSは**有限状態マシン**を制御します。クロックのビートごとに、デバイスのJTAG TAPコントローラはTMSピンの電圧をチェックします。電圧が一定の閾値以下の場合、信号は低いと見なされ、0と解釈されます。一方、電圧が一定の閾値を超える場合、信号は高いと見なされ、1と解釈されます。
* テストデータ入力（**TDI**）TDIは、スキャンセルを介してチップにデータを送信するピンです。各ベンダーは、このピンを介した通信プロトコルを定義する責任があります。なぜなら、JTAGはこれを定義していないからです。
* テストデータ出力（**TDO**）TDOは、チップからデータを送信するピンです。
* テストリセット（**TRST**）入力オプションのTRSTは、有限状態マシンを**既知の正常な状態**にリセットします。または、TMSが5回の連続したクロックサイクルで1に保持されている場合、リセットが呼び出され、TRSTピンと同じ方法でリセットされます。これがTRSTがオプションである理由です。

場合によっては、これらのピンがPCBにマークされていることがあります。他の場合は、それらを**見つける必要がある**かもしれません。

## JTAGピンの特定

JTAGポートを検出する最も高速で最も高価な方法は、特にこの目的のために作成されたデバイスである**JTAGulator**を使用することです（UARTピン配置も**検出できます**）。

24のチャネルをボードのピンに接続できます。次に、**IDCODE**および**BYPASS**バウンダリスキャンコマンドを送信するすべての可能な組み合わせに対して**BF攻撃**を実行します。応答を受信すると、各JTAG信号に対応するチャネルが表示されます。

JTAGピン配置を特定するための安価で遅い方法は、Arduino互換のマイクロコントローラにロードされた[**JTAGenum**](https://github.com/cyphunk/JTAGenum/)を使用することです。

**JTAGenum**を使用する場合、まず列挙のために使用するプローブデバイスのピンを**定義**する必要があります。デバイスのピン配置図を参照し、これらのピンをターゲットデバイスのテストポイントに接続する必要があります。

JTAGピンを特定するための**3番目の方法**は、PCBを**検査**してピン配置の1つを見つけることです。場合によっては、PCBが便利に**Tag-Connectインターフェース**を提供していることがあります。これは、ボードにJTAGコネクタがあることを明示的に示しています。このインターフェースの外観は[https://www.tag-connect.com/info/](https://www.tag-connect.com/info/)で確認できます。さらに、PCB上のチップセットの**データシート**を調べると、JTAGインタフェースを指すピン配置図が明らかになる場合があります。

# SDW

SWDは、デバッグ用に設計されたARM固有のプロトコルです。

SWDインタフェースには、次の2つのピンが必要です：双方向の**SWDIO**信号（JTAGの**TDI**および**TDO**ピ
- **[💬](https://emojipedia.org/speech-balloon/)Discordグループ**に参加するか、[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter**で私をフォローする[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **あなたのハッキングトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください**。

</details>
