# macOS Office Sandbox Bypasses

<details>

<summary><strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFT**](https://opensea.io/collection/the-peass-family)コレクションを見つける
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**または[telegramグループ](https://t.me/peass)に**参加**するか、**Twitter** 🐦で私たちを**フォロー**する [**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
- **ハッキングトリックを共有するには、**[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。

</details>

### ランチエージェントを使用したWord Sandboxバイパス

アプリケーションは、**`com.apple.security.temporary-exception.sbpl`**という権限を使用する**カスタムサンドボックス**を使用しており、このカスタムサンドボックスでは、ファイル名が`~$`で始まる限り、どこにでもファイルを書き込むことができます：`(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`

したがって、エスケープは、`~/Library/LaunchAgents/~$escape.plist`に`plist`ランチエージェントを書き込むだけで簡単でした。

[**元のレポートはこちら**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/)を確認してください。

### ログインアイテムとzipを使用したWord Sandboxバイパス

最初のエスケープから、Wordは`~$`で始まる任意のファイルを書き込むことができますが、前の脆弱性のパッチ後は`/Library/Application Scripts`や`/Library/LaunchAgents`に書き込むことはできませんでした。

サンドボックス内からは、**ログインアイテム**（ユーザーがログインすると実行されるアプリ）を作成できることがわかりました。ただし、これらのアプリは**ノータライズされていないと実行されず**、**引数を追加することはできません**（つまり、**`bash`**を使用して逆シェルを実行することはできません）。

前のサンドボックスバイパスから、Microsoftは`~/Library/LaunchAgents`にファイルを書き込むオプションを無効にしました。しかし、`LaunchAgents`フォルダが`~/Library`にデフォルトで作成されないため、`LaunchAgents/~$escape.plist`にplistを**zip**して、zipファイルを**`~/Library`**に配置すると、解凍時に永続的な宛先に到達するようになりました。

[**元のレポートはこちら**](https://objective-see.org/blog/blog_0x4B.html)を確認してください。

### ログインアイテムと.zshenvを使用したWord Sandboxバイパス

（最初のエスケープから、Wordは`~$`で始まる任意のファイルを書き込むことができます）。

ただし、前のテクニックには制限がありました。他のソフトウェアが作成したために`~/Library/LaunchAgents`フォルダが存在する場合、失敗する可能性がありました。このため、このための異なるログインアイテムチェーンが発見されました。

攻撃者は、実行するペイロードを持つ**`.bash_profile`**と**`.zshenv`**ファイルを作成し、それらをzipして、被害者のユーザーフォルダにzipファイルを書き込むことができました：**`~/~$escape.zip`**。

次に、zipファイルを**ログインアイテム**に追加し、**`Terminal`**アプリを追加します。ユーザーが再ログインすると、zipファイルがユーザーのファイルに解凍され、**`.bash_profile`**と**`.zshenv`**が上書きされ、したがって、ターミナルはこれらのファイルのいずれかを実行します（bashまたはzshが使用されているかに応じて）。

[**元のレポートはこちら**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)を確認してください。

### Openと環境変数を使用したWord Sandboxバイパス

サンドボックス化されたプロセスからは、**`open`**ユーティリティを使用して他のプロセスを呼び出すことができます。さらに、これらのプロセスは**独自のサンドボックス内で実行**されます。

`open`ユーティリティには、**特定の環境変数でアプリを実行する**ための**`--env`**オプションがあることがわかりました。したがって、サンドボックス内のフォルダに**`.zshenv`ファイル**を作成し、`HOME`変数をそのフォルダに設定して`Terminal`アプリを開く`open`を使用することで、`.zshenv`ファイルを実行できました（何らかの理由で`__OSINSTALL_ENVIROMENT`変数を設定する必要がありました）。

[**元のレポートはこちら**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/)を確認してください。

### Openとstdinを使用したWord Sandboxバイパス

**`open`**ユーティリティは**`--stdin`**パラメータもサポートしていました（前のバイパス後、`--env`を使用することはできなくなりました）。

重要なのは、Appleによって署名された**`python`**でも、**`quarantine`**属性を持つスクリプトは実行されないことです。ただし、stdinからスクリプトを渡すことで、それが隔離されているかどうかをチェックしないで実行できました：&#x20;

1. 任意のPythonコマンドを含む**`~$exploit.py`**ファイルを作成します。
2. _open_ **`–stdin='~$exploit.py' -a Python`**を実行します。これにより、Pythonアプリが、標準入力として提供されたファイルを使用して実行されます。 Pythonは喜んでコードを実行し、_launchd_の子プロセスであるため、Wordのサンドボックスルールには拘束されません。

<details>

<summary><strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFT**](https://opensea.io/collection/the-peass-family)コレクションを見つける
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**または[telegramグループ](https://t.me/peass)に**参加**するか、**Twitter** 🐦で私たちを**フォロー**する [**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
- **ハッキングトリックを共有するには、**[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。

</details>
