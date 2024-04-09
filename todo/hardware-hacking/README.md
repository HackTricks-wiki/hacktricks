# ハードウェアハッキング

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>でAWSハッキングをゼロからヒーローまで学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝**したい場合や**HackTricksをPDFでダウンロード**したい場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションを見る
- **Discordグループ**に参加💬](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦で私たちをフォローする [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
- **HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出して、あなたのハッキングテクニックを共有してください。

</details>

## JTAG

JTAGはバウンダリスキャンを実行することを可能にします。バウンダリスキャンは、埋め込みバウンダリスキャンセルとレジスタを含む特定の回路を分析します。

JTAG標準は、次のような**特定のコマンド**を定義してバウンダリスキャンを実行します：

- **BYPASS**は、他のチップを経由せずに特定のチップをテストできます。
- **SAMPLE/PRELOAD**は、デバイスが通常の動作モードにあるときに入出力データのサンプルを取ります。
- **EXTEST**はピンの状態を設定および読み取ります。

他のコマンドもサポートできます：

- デバイスを識別するための**IDCODE**
- デバイスの内部テストのための**INTEST**

JTAGulatorのようなツールを使用すると、これらの命令に遭遇することがあります。

### テストアクセスポート

バウンダリスキャンには、コンポーネントに組み込まれたJTAGテストサポート機能にアクセスを提供する汎用ポートである**4本のワイヤーテストアクセスポート（TAP）**のテストが含まれます。TAPは次の5つの信号を使用します：

- テストクロック入力（**TCK**）TCKは、TAPコントローラが単一のアクションを取る頻度を定義する**クロック**です（つまり、ステートマシン内の次の状態に移動します）。
- テストモード選択（**TMS**）入力 TMSは**有限状態マシン**を制御します。クロックのビートごとに、デバイスのJTAG TAPコントローラはTMSピンの電圧をチェックします。電圧がある閾値以下の場合、信号は低いと見なされ、0と解釈されます。一方、電圧がある閾値を超えると、信号は高いと見なされ、1と解釈されます。
- テストデータ入力（**TDI**）TDIは、スキャンセルを介してチップに**データを送信**するピンです。各ベンダーは、このピンを介した通信プロトコルを定義する責任があります。なぜなら、JTAGはこれを定義していないからです。
- テストデータ出力（**TDO**）TDOは、チップから**データを送信**するピンです。
- テストリセット（**TRST**）入力 オプションのTRSTは、有限状態マシンを**既知の正常な状態にリセット**します。代替として、TMSが5つの連続したクロックサイクルで1を保持すると、TRSTピンと同じようにリセットを呼び出します。そのため、TRSTはオプションです。

時々、これらのピンがPCBにマークされていることがあります。他の場合は、それらを**見つける**必要があるかもしれません。

### JTAGピンの識別

JTAGポートを検出する最速で最も高価な方法は、この目的のために作成されたデバイスである**JTAGulator**を使用することです（UARTピン配置も**検出**できます）。

これには、ボードのピンに接続できる**24チャンネル**があります。次に、**IDCODE**および**BYPASS**バウンダリスキャンコマンドを送信するすべての可能な組み合わせのBF攻撃を実行します。応答を受信すると、各JTAG信号に対応するチャンネルが表示されます。

JTAGピン配置を特定するより安価でかなり遅い方法は、Arduino互換のマイクロコントローラにロードされた[JTAGenum](https://github.com/cyphunk/JTAGenum/)を使用することです。

**JTAGenum**を使用すると、まず、列挙に使用するプローブデバイスのピンを**定義**する必要があります。デバイスのピン配置図を参照し、これらのピンをターゲットデバイスのテストポイントに接続する必要があります。

JTAGピンを特定する**3番目の方法**は、PCBを**検査**してピン配置の1つを見つけることです。場合によっては、PCBが**Tag-Connectインターフェース**を提供していることがあり、これはボードにJTAGコネクタがあることを明確に示しています。そのインターフェースの外観は[https://www.tag-connect.com/info/](https://www.tag-connect.com/info/)で確認できます。さらに、PCB上のチップセットの**データシート**を検査すると、JTAGインターフェースを指すピン配置図が明らかになる場合があります。

## SDW

SWDはARM固有のデバッグ用プロトコルです。

SWDインターフェースには**2本のピン**が必要です：双方向の**SWDIO**信号（JTAGの**TDI**および**TDO**ピンに相当）と**クロック**である**SWCLK**（JTAGの**TCK**に相当）。多くのデバイスは、SWDまたはJTAGプローブをターゲットに接続できる**Serial WireまたはJTAGデバッグポート（SWJ-DP）**をサポートしています。
