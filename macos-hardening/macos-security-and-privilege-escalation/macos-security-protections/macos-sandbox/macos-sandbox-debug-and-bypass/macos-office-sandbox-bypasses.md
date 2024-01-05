# macOS Office Sandbox Bypasses

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください。
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* **HackTricks**のPRを[**HackTricks**](https://github.com/carlospolop/hacktricks)および[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリに提出して、あなたのハッキングのコツを共有する。

</details>

### Launch Agentsを介したWord Sandboxバイパス

アプリケーションは、権限 **`com.apple.security.temporary-exception.sbpl`** を使用して**カスタムSandbox**を使用し、このカスタムSandboxはファイル名が `~$` で始まる限り、どこにでもファイルを書き込むことができます：`(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`

したがって、`~/Library/LaunchAgents/~$escape.plist` に**`plist` LaunchAgent**を**書き込む**ことで簡単にエスケープできました。

[**元のレポートはこちら**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/).

### Login Itemsとzipを介したWord Sandboxバイパス

最初のエスケープから、Wordは `~$` で始まる任意のファイル名を書き込むことができますが、前の脆弱性のパッチ後、`/Library/Application Scripts` や `/Library/LaunchAgents` に書き込むことはできませんでした。

サンドボックス内から、ユーザーがログインするときに実行されるアプリケーションである **Login Item** を作成することが可能であることが発見されました。しかし、これらのアプリは、**公証されていない限り実行されません**し、**引数を追加することはできません**（つまり、**`bash`** を使用してリバースシェルを実行することはできません）。

前のSandboxバイパスから、Microsoftは `~/Library/LaunchAgents` にファイルを書き込むオプションを無効にしました。しかし、**zipファイルをLogin Itemとして配置**すると、`Archive Utility` は現在の場所でただ**解凍**することが発見されました。したがって、デフォルトでは `~/Library` の `LaunchAgents` フォルダーが作成されていないため、`LaunchAgents/~$escape.plist` に **plistをzip** して **`~/Library`** に配置すると、解凍すると永続性のある場所に到達します。

[**元のレポートはこちら**](https://objective-see.org/blog/blog\_0x4B.html).

### Login Itemsと.zshenvを介したWord Sandboxバイパス

（最初のエスケープから、Wordは `~$` で始まる任意のファイル名を書き込むことができます）。

しかし、前のテクニックには制限がありました。他のソフトウェアによって作成されたために **`~/Library/LaunchAgents`** フォルダーが存在する場合、それは失敗します。そこで、これに対する異なるLogin Itemsチェーンが発見されました。

攻撃者は、実行するペイロードを含む **`.bash_profile`** と **`.zshenv`** ファイルを作成し、それらをzipして、被害者のユーザーフォルダーにzipを書き込むことができます：**`~/~$escape.zip`**。

次に、zipファイルを **Login Items** に追加し、**`Terminal`** アプリを追加します。ユーザーが再ログインすると、zipファイルがユーザーファイルで解凍され、**`.bash_profile`** と **`.zshenv`** を上書きし、したがって、ターミナルはこれらのファイルのいずれかを実行します（bashまたはzshが使用されているかによります）。

[**元のレポートはこちら**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c).

### Openと環境変数を使用したWord Sandboxバイパス

サンドボックス化されたプロセスからでも、**`open`** ユーティリティを使用して他のプロセスを呼び出すことが可能です。さらに、これらのプロセスは**独自のサンドボックス内で実行されます**。

openユーティリティには、特定の環境変数を持つアプリを実行する **`--env`** オプションがあることが発見されました。したがって、**サンドボックス内**のフォルダーに **`.zshenv` ファイル** を作成し、`--env` を使用して `open` を使用し、そのフォルダーを開く `Terminal` アプリに **`HOME` 変数** を設定することで、`.zshenv` ファイルを実行することが可能でした（何らかの理由で、変数 `__OSINSTALL_ENVIROMENT` も設定する必要がありました）。

[**元のレポートはこちら**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/).

### Openとstdinを使用したWord Sandboxバイパス

**`open`** ユーティリティはまた、**`--stdin`** パラメーターもサポートしていました（そして、前のバイパスの後、`--env` を使用することはできなくなりました）。

Appleによって署名されているにもかかわらず、**`python`** は **`quarantine`** 属性を持つスクリプトを実行**しません**。しかし、stdinからスクリプトを渡すことで、それが隔離されているかどうかをチェックしないため、可能でした：&#x20;

1. 任意のPythonコマンドを含む **`~$exploit.py`** ファイルをドロップします。
2. _open_ **`–stdin='~$exploit.py' -a Python`** を実行します。これにより、Pythonアプリが標準入力としてドロップされたファイルで実行されます。Pythonは喜んでコードを実行し、_launchd_ の子プロセスであるため、WordのSandboxルールには拘束されません。

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください。
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* **HackTricks**のPRを[**HackTricks**](https://github.com/carlospolop/hacktricks)および[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリに提出して、あなたのハッキングのコツを共有する。

</details>
