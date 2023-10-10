# macOSプロセスの乱用

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

## MacOSプロセスの乱用

MacOSは、他のオペレーティングシステムと同様に、**プロセスが相互作用し、通信し、データを共有する**ためのさまざまな方法とメカニズムを提供しています。これらの技術はシステムの効率的な動作に不可欠ですが、脅威行為者によっても**悪意のある活動**に悪用される可能性があります。

### ライブラリインジェクション

ライブラリインジェクションは、攻撃者が**プロセスに悪意のあるライブラリを読み込ませる**技術です。インジェクションされると、ライブラリはターゲットプロセスのコンテキストで実行され、攻撃者にプロセスと同じ権限とアクセス権を提供します。

{% content-ref url="macos-library-injection/" %}
[macos-library-injection](macos-library-injection/)
{% endcontent-ref %}

### 関数フック

関数フックは、ソフトウェアコード内の**関数呼び出し**またはメッセージを**傍受する**ことを意味します。関数をフックすることで、攻撃者はプロセスの動作を**変更**したり、機密データを観察したり、実行フローを制御したりすることができます。

{% content-ref url="../mac-os-architecture/macos-function-hooking.md" %}
[macos-function-hooking.md](../mac-os-architecture/macos-function-hooking.md)
{% endcontent-ref %}

### プロセス間通信

プロセス間通信（IPC）は、別々のプロセスが**データを共有し交換する**さまざまな方法を指します。IPCは多くの正当なアプリケーションにとって基本的ですが、プロセスの分離を逸脱させ、機密情報を漏洩させたり、不正な操作を行ったりするために悪用されることもあります。

{% content-ref url="../mac-os-architecture/macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](../mac-os-architecture/macos-ipc-inter-process-communication/)
{% endcontent-ref %}

### Electronアプリケーションのインジェクション

特定の環境変数で実行されるElectronアプリケーションは、プロセスのインジェクションに対して脆弱性がある場合があります。

{% content-ref url="macos-electron-applications-injection.md" %}
[macos-electron-applications-injection.md](macos-electron-applications-injection.md)
{% endcontent-ref %}

### Dirty NIB

NIBファイルは、アプリケーション内のユーザーインターフェース（UI）要素とその相互作用を**定義**します。ただし、NIBファイルは**任意のコマンドを実行**することができ、**Gatekeeperは**NIBファイルが変更された場合でも、既に実行されているアプリケーションの実行を**停止しません**。したがって、任意のプログラムが任意のコマンドを実行するために使用される可能性があります。

{% content-ref url="macos-dirty-nib.md" %}
[macos-dirty-nib.md](macos-dirty-nib.md)
{% endcontent-ref %}

### .Netアプリケーションのインジェクション

.Netアプリケーションにコードをインジェクションすることができます。これは、macOSの保護（ランタイムハードニングなど）によって保護されていない**.Netデバッグ機能を悪用**することによって行われます。

{% content-ref url="macos-.net-applications-injection.md" %}
[macos-.net-applications-injection.md](macos-.net-applications-injection.md)
{% endcontent-ref %}

### Pythonインジェクション

環境変数**`PYTHONINSPECT`**が設定されている場合、Pythonプロセスは終了後にPython CLIに移行します。

**`PYTHONPATH`**や**`PYTHONHOME`**などの他の環境変数も、Pythonコマンドを実行して任意のコードを実行するのに役立つ場合があります。

なお、**`pyinstaller`**でコンパイルされた実行可能ファイルは、埋め込まれたPythonを使用していても、これらの環境変数を使用しません。

## 検出

### Shield

[**Shield**](https://theevilbit.github.io/shield/)（[**Github**](https://github.com/theevilbit/Shield)）は、プロセスインジェクションのアクションを**検出およびブロック**するオープンソースのアプリケーションです。

* **環境変数の使用**：次の環境変数の存在を監視します：**`DYLD_INSERT_LIBRARIES`**、**`CFNETWORK_LIBRARY_PATH`**、**`RAWCAMERA_BUNDLE_PATH`**、**`ELECTRON_RUN_AS_NODE`**
* **`task_for_pid`**の呼び出しの使用：プロセスが別のプロセスの**タスクポートを取得**しようとする場合に検出します。これにより、コードをプロセスにインジェクションすることができます。
* **Electronアプリのパラメータ**：デバッグモードでElectronアプリを起動するために**`--inspect`**、**`--inspect-brk`**、**`--remote-debugging-port`**コマンドライン引数を使用することができ、それによってコードをインジェクションすることができます。
* **シンボリックリンク**または**ハードリンク**の使用：一般的には、最も一般的な乱用方法は、ユーザー権限でリンクを**配置し**、それを**より高い権限**の場所に**指す**ことです。ハードリンクとシンボリックリンクの両方に対して検出は非常に簡単です。リンクを作
### 他のプロセスによる呼び出し

[**このブログ記事**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)では、関数**`task_name_for_pid`**を使用して、他のプロセスがプロセスにコードを注入していることを検出し、その他のプロセスに関する情報を取得する方法について説明しています。

この関数を呼び出すには、プロセスを実行しているユーザーと**同じuid**であるか、**root**である必要があります（この関数はプロセスに関する情報を返すだけで、コードを注入する方法ではありません）。

## 参考文献

* [https://theevilbit.github.io/shield/](https://theevilbit.github.io/shield/)
* [https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** HackTricksで**会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter**で私をフォローしてください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>
