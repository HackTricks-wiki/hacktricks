# macOS Office Sandbox Bypasses

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter**で[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* **ハッキングのトリックを共有する**ために、[**hacktricksリポジトリ**](https://github.com/carlospolop/hacktricks)と[**hacktricks-cloudリポジトリ**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。

</details>

### Launch Agentsを使用したWord Sandboxバイパス

このアプリケーションは、**`com.apple.security.temporary-exception.sbpl`**という権限を使用した**カスタムサンドボックス**を使用しており、このカスタムサンドボックスでは、ファイル名が`~$`で始まる場合にはどこにでもファイルを書き込むことができます：`(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`

したがって、エスケープは、**`plist`**形式のLaunchAgentを`~/Library/LaunchAgents/~$escape.plist`に書き込むだけで簡単でした。

[**元のレポートはこちら**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/)を確認してください。

### Login Itemsとzipを使用したWord Sandboxバイパス

（最初のエスケープから覚えておいてください、Wordは`~$`で始まる任意のファイルを書き込むことができます）。

サンドボックス内からは、**ログインアイテム**（ユーザーがログインすると実行されるアプリ）を作成することができることがわかりました。ただし、これらのアプリは**ノータライズされていない限り実行されません**し、**引数を追加することはできません**（つまり、**`bash`**を使用して逆シェルを実行することはできません）。

前のサンドボックスバイパスから、Microsoftは`~/Library/LaunchAgents`にファイルを書き込むオプションを無効にしました。しかし、**zipファイルをログインアイテムとして追加**すると、`Archive Utility`が現在の場所にそれを解凍するだけです。したがって、デフォルトでは`~/Library`の`LaunchAgents`フォルダが作成されないため、`LaunchAgents/~$escape.plist`にplistをzip化し、zipファイルを**`~/Library`**に配置すると、解凍時に永続化先に到達することができました。

[**元のレポートはこちら**](https://objective-see.org/blog/blog\_0x4B.html)を確認してください。

### Login Itemsと.zshenvを使用したWord Sandboxバイパス

（最初のエスケープから覚えておいてください、Wordは`~$`で始まる任意のファイルを書き込むことができます）。

ただし、前のテクニックには制限があります。他のソフトウェアが作成したために**`~/Library/LaunchAgents`**フォルダが存在する場合、失敗する可能性があります。そのため、この問題に対して異なるLogin Itemsチェーンが見つかりました。

攻撃者は、実行するペイロードを含む**`.bash_profile`**と**`.zshenv`**ファイルを作成し、それらをzip化し、zipファイルを被害者のユーザーフォルダに書き込むことができました：\~/\~$escape.zip。

次に、zipファイルを**Login Items**に追加し、**`Terminal`**アプリを追加します。ユーザーが再ログインすると、zipファイルがユーザーファイルに解凍され、**`.bash_profile`**と**`.zshenv`**が上書きされるため、ターミナルはこれらのファイルのいずれかを実行します（bashまたはzshが使用されているかに応じて）。

[**元のレポートはこちら**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)を確認してください。

### Openと環境変数を使用したWord Sandboxバイパス

サンドボックス化されたプロセスからは、**`open`**ユーティリティを使用して他のプロセスを呼び出すことができます。さらに、これらのプロセスは**独自のサンドボックス内で実行**されます。

openユーティリティには、**特定の環境変数**でアプリを実行するための**`--env`**オプションがあることがわかりました。したがって、サンドボックス内のフォルダ内に**`.zshenv`ファイル**を作成し、`open`を使用して`--env`を設定し、**`HOME`変数**をそのフォルダに設定してその`Terminal`アプリを開くことができました。これにより、`.zshenv`ファイルが実行されます（何らかの理由で`__OSINSTALL_ENVIROMENT`変数も設定する必要がありました）。

[**元のレポートはこちら**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/)を確認してください。

### Openとstdinを使用したWord Sandboxバイパス

**`open`**ユーティリティは**`--stdin`**パラメータもサポートしていました（前のバイパスでは`--env`を使用することはできなくなりました）。

問題は、**`python`**がAppleによって署名されていても
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。これは私たちの独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で私を[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォローしてください**。
* 自分のハッキングテクニックを共有するために、[**hacktricksリポジトリ**](https://github.com/carlospolop/hacktricks)と[**hacktricks-cloudリポジトリ**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。

</details>
