# macOS Office Sandbox Bypasses

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* サイバーセキュリティ会社で働いていますか？ HackTricksであなたの会社を宣伝したいですか？または、PEASSの最新バージョンにアクセスしたいですか、またはHackTricksをPDFでダウンロードしたいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください、私たちの独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクション
* [**公式のPEASS＆HackTricks swag**](https://peass.creator-spring.com)を手に入れましょう
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter**で[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

### Launch Agentsを使用したWord Sandboxバイパス

このアプリケーションは、**`com.apple.security.temporary-exception.sbpl`**という権限を使用した**カスタムサンドボックス**を使用しており、このカスタムサンドボックスでは、ファイル名が`~$`で始まる場合はどこにでもファイルを書き込むことができます：`(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`

したがって、エスケープは、**`plist`**形式のLaunchAgentを`~/Library/LaunchAgents/~$escape.plist`に書き込むだけで簡単でした。

[**オリジナルのレポートはこちら**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/)を確認してください。

### Login Itemsとzipを使用したWord Sandboxバイパス

（最初のエスケープから、Wordは`~$`で始まる任意のファイルを書き込むことができますが、前の脆弱性のパッチ後は`/Library/Application Scripts`または`/Library/LaunchAgents`に書き込むことはできませんでした）。

サンドボックス内からは、**ログインアイテム**（ユーザーがログインすると実行されるアプリ）を作成することができます。ただし、これらのアプリは**ノータライズされていない限りは実行されません**し、**引数を追加することはできません**（つまり、**`bash`**を使用して逆シェルを実行することはできません）。

前のサンドボックスバイパスから、Microsoftは`~/Library/LaunchAgents`にファイルを書き込むオプションを無効にしました。しかし、**zipファイルをログインアイテムとして**使用すると、`Archive Utility`が現在の場所にそれを**解凍**します。したがって、デフォルトでは`~/Library`の`LaunchAgents`フォルダは作成されないため、**`LaunchAgents/~$escape.plist`**にplistをzip化し、zipファイルを**`~/Library`**に配置すると、解凍時に永続性のある場所に到達します。

[**オリジナルのレポートはこちら**](https://objective-see.org/blog/blog\_0x4B.html)を確認してください。

### Login Itemsと.zshenvを使用したWord Sandboxバイパス

（最初のエスケープから、Wordは`~$`で始まる任意のファイルを書き込むことができます）。

ただし、前のテクニックには制限がありました。他のソフトウェアが作成したために**`~/Library/LaunchAgents`**フォルダが存在する場合、失敗する可能性があります。そのため、この問題に対しては異なるLogin Itemsチェーンが見つかりました。

攻撃者は、**`.bash_profile`**と**`.zshenv`**という名前のファイルを作成し、それらをzip化し、**被害者の**ユーザーフォルダにzipファイルを書き込むことができます：**`~/~$escape.zip`**。

次に、zipファイルを**Login Items**に追加し、**`Terminal`**アプリを追加します。ユーザーが再ログインすると、zipファイルがユーザーファイルに解凍され、**`.bash_profile`**と**`.zshenv`**が上書きされるため、ターミナルはこれらのファイルのいずれかを実行します（bashまたはzshが使用されているかに応じて）。

[**オリジナルのレポートはこちら**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)を確認してください。

### Openと環境変数を使用したWord Sandboxバイパス

サンドボックス化されたプロセスからは、**`open`**ユーティリティを使用して他のプロセスを呼び出すことができます。さらに、これらのプロセスは**独自のサンドボックス内で実行**されます。

openユーティリティには、**特定の環境変数**でアプリを実行するための**`--env`**オプションがあることがわかりました。したがって、サンドボックス内のフォルダに**`.zshenv`ファイル**を作成し、`open`を使用して`--env`を設定し、**`HOME`変数**をそのフォルダに設定して`Terminal`アプリを開くことができました。これにより、`.zshenv`ファイルが実行されます（何らかの理由で`__OSINSTALL_ENVIROMENT`変数も設定する必要がありました）。

[**オリジナルのレポートはこちら**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/)を確認してください。

### Openとstdinを使用したWord Sandboxバイパス

**`open`**ユーティリティは**`--stdin`**パラメータもサポートしていました（前のバイパス後、`--env`を使用することはできなくなりました）。

問題は、**`python`**がAppleによって署名されていても、**`quarantine`**属性を持つスクリプトは
* **サイバーセキュリティ会社**で働いていますか？**HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSを入手**したいですか、またはHackTricksをPDFで**ダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で私を[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出**してください。

</details>
