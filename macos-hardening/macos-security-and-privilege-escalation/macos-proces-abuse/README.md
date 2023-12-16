# macOSプロセスの乱用

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

## MacOSプロセスの乱用

MacOSは、他のオペレーティングシステムと同様に、**プロセスが相互作用し、通信し、データを共有する**ためのさまざまな方法とメカニズムを提供しています。これらの技術はシステムの効率的な動作に不可欠ですが、脅威行為者によっても悪用され、**悪意のある活動**が行われる可能性があります。

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

特定の環境変数で実行されるElectronアプリケーションは、プロセスのインジェクションの脆弱性がある場合があります。

{% content-ref url="macos-electron-applications-injection.md" %}
[macos-electron-applications-injection.md](macos-electron-applications-injection.md)
{% endcontent-ref %}

### Dirty NIB

NIBファイルは、アプリケーション内のユーザーインターフェース（UI）要素とその相互作用を**定義**します。ただし、NIBファイルは**任意のコマンドを実行**することができ、**Gatekeeperは**NIBファイルが変更された場合でも、既に実行されているアプリケーションの実行を**停止しません**。したがって、任意のプログラムが任意のコマンドを実行するために使用される可能性があります。

{% content-ref url="macos-dirty-nib.md" %}
[macos-dirty-nib.md](macos-dirty-nib.md)
{% endcontent-ref %}

### Javaアプリケーションのインジェクション

特定のJavaの機能（**`_JAVA_OPTS`**環境変数など）を悪用することで、Javaアプリケーションが**任意のコード/コマンド**を実行することができます。

{% content-ref url="macos-java-apps-injection.md" %}
[macos-java-apps-injection.md](macos-java-apps-injection.md)
{% endcontent-ref %}

### .Netアプリケーションのインジェクション

.Netアプリケーションにコードをインジェクションすることができます。これは、macOSの保護（ランタイムハードニングなど）によって保護されていない**.Netデバッグ機能を悪用**することで実現できます。

{% content-ref url="macos-.net-applications-injection.md" %}
[macos-.net-applications-injection.md](macos-.net-applications-injection.md)
{% endcontent-ref %}

### Perlインジェクション

Perlスクリプトが任意のコードを実行するためのさまざまなオプションを確認してください。

{% content-ref url="macos-perl-applications-injection.md" %}
[macos-perl-applications-injection.md](macos-perl-applications-injection.md)
{% endcontent-ref %}

### Pythonインジェクション

環境変数**`PYTHONINSPECT`**が設定されている場合、Pythonプロセスは終了後にPython CLIに移行します。また、**`PYTHONSTARTUP`**を使用して、対話セッションの開始時に実行するPythonスクリプトを指定することも可能です。\
ただし、**`PYTHONINSPECT`**が対話セッションを作成する場合、**`PYTHONSTARTUP`**スクリプトは実行されません。

**`PYTHONPATH`**や**`PYTHONHOME`**などの他の環境変数も、Pythonコマンドが任意のコードを実行するのに役立つ場合があります。

**`pyinstaller`**でコンパイルされた実行可能ファイルは、埋め込まれたPythonを使用していても、これらの環境変数を使用しません。

{% hint style="danger" %}
全体的に、環境変数を悪用してPythonが任意のコードを実行する方法は見つかりませんでした。\
ただし、ほとんどの人々は**Hombrew**を使用してPythonをインストールするため、デフォルトの管理者ユーザーの**書き込み可能な場所**にPythonがインストールされます。これを乗っ取ることができます。
```bash
mv /opt/homebrew/bin/python3 /opt/homebrew/bin/python3.old
cat > /opt/homebrew/bin/python3 <<EOF
#!/bin/bash
# Extra hijack code
/opt/homebrew/bin/python3.old "$@"
EOF
chmod +x /opt/homebrew/bin/python3
```
## 検出

### Shield

[**Shield**](https://theevilbit.github.io/shield/) ([**Github**](https://github.com/theevilbit/Shield))は、次のプロセスインジェクションアクションを**検出およびブロック**することができるオープンソースのアプリケーションです：

* **環境変数**の使用：次の環境変数の存在を監視します：**`DYLD_INSERT_LIBRARIES`**、**`CFNETWORK_LIBRARY_PATH`**、**`RAWCAMERA_BUNDLE_PATH`**、および**`ELECTRON_RUN_AS_NODE`**
* **`task_for_pid`**呼び出しの使用：プロセスが別のプロセスの**タスクポートを取得**し、それにコードをインジェクションする場合に検出します。
* **Electronアプリのパラメータ**：デバッグモードでElectronアプリを起動するために、**`--inspect`**、**`--inspect-brk`**、**`--remote-debugging-port`**コマンドライン引数を使用して、コードをインジェクションすることができます。
* **シンボリックリンク**または**ハードリンク**の使用：一般的に最も一般的な乱用は、ユーザー権限で**リンクを配置**し、それをより高い権限の場所に**ポイントする**ことです。ハードリンクとシンボリックリンクの検出は非常に簡単です。リンクを作成するプロセスがターゲットファイルとは**異なる権限レベル**を持っている場合、アラートを作成します。残念ながら、シンボリックリンクのブロックは不可能です。なぜなら、リンクの宛先に関する情報が作成前にはわからないためです。これはAppleのEndpointSecuriyフレームワークの制約です。

### 他のプロセスによる呼び出し

[**このブログ記事**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html)では、関数**`task_name_for_pid`**を使用して、プロセスにコードをインジェクションする他の**プロセスに関する情報**を取得し、その他のプロセスに関する情報を取得する方法について説明しています。

この関数を呼び出すには、プロセスを実行しているユーザーと**同じuid**であるか、**root**である必要があります（コードをインジェクションする方法ではありません）。

## 参考文献

* [https://theevilbit.github.io/shield/](https://theevilbit.github.io/shield/)
* [https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ HackTricksであなたの**会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセス**したり、HackTricksを**PDFでダウンロード**したりしたいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)、私たちの独占的な[**NFT**](https://opensea.io/collection/the-peass-family)コレクションを発見してください。
* [**公式のPEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **ハッキングのトリックを共有するには、**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **および** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出してください。**

</details>
