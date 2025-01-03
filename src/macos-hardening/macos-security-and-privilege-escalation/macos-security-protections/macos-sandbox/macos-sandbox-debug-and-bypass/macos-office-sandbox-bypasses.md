# macOS Office Sandbox Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

### Word Sandbox bypass via Launch Agents

アプリケーションは、権限 **`com.apple.security.temporary-exception.sbpl`** を使用した **カスタムサンドボックス** を使用しており、このカスタムサンドボックスでは、ファイル名が `~$` で始まる限り、どこにでもファイルを書き込むことができます: `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`

したがって、エスケープは **`plist`** LaunchAgent を `~/Library/LaunchAgents/~$escape.plist` に書き込むことと同じくらい簡単でした。

[**元のレポートはこちら**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/)を確認してください。

### Word Sandbox bypass via Login Items and zip

最初のエスケープから、Word は `~$` で始まる任意のファイルを書き込むことができることを覚えておいてください。ただし、前の脆弱性のパッチ後は `/Library/Application Scripts` や `/Library/LaunchAgents` に書き込むことはできませんでした。

サンドボックス内から **Login Item**（ユーザーがログインしたときに実行されるアプリ）を作成できることが発見されました。ただし、これらのアプリは **ノータライズされていない限り** 実行されず、**引数を追加することはできません**（したがって、**`bash`** を使用してリバースシェルを実行することはできません）。

前のサンドボックスバイパスから、Microsoft は `~/Library/LaunchAgents` にファイルを書き込むオプションを無効にしました。しかし、**Login Item** として **zip ファイル** を置くと、`Archive Utility` はその現在の場所に **解凍** します。したがって、デフォルトでは `~/Library` の `LaunchAgents` フォルダーが作成されないため、**`LaunchAgents/~$escape.plist`** に plist を **zip** し、**`~/Library`** に zip ファイルを **配置** することで、解凍時に永続性の宛先に到達することができました。

[**元のレポートはこちら**](https://objective-see.org/blog/blog_0x4B.html)を確認してください。

### Word Sandbox bypass via Login Items and .zshenv

（最初のエスケープから、Word は `~$` で始まる任意のファイルを書き込むことができることを覚えておいてください）。

ただし、前の技術には制限があり、**`~/Library/LaunchAgents`** フォルダーが他のソフトウェアによって作成されている場合、失敗します。したがって、これに対する別の Login Items チェーンが発見されました。

攻撃者は、実行するペイロードを含む **`.bash_profile`** と **`.zshenv`** ファイルを作成し、それらを zip して **被害者の** ユーザーフォルダーに書き込むことができます: **`~/~$escape.zip`**。

次に、zip ファイルを **Login Items** に追加し、**`Terminal`** アプリを追加します。ユーザーが再ログインすると、zip ファイルはユーザーファイルに解凍され、**`.bash_profile`** と **`.zshenv`** が上書きされ、そのためターミナルはこれらのファイルのいずれかを実行します（bash または zsh が使用されるかによります）。

[**元のレポートはこちら**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)を確認してください。

### Word Sandbox Bypass with Open and env variables

サンドボックス化されたプロセスからは、**`open`** ユーティリティを使用して他のプロセスを呼び出すことがまだ可能です。さらに、これらのプロセスは **自分自身のサンドボックス内** で実行されます。

open ユーティリティには、**特定の env** 変数でアプリを実行するための **`--env`** オプションがあることが発見されました。したがって、**サンドボックス内のフォルダー** に **`.zshenv` ファイル** を作成し、`--env` を使用して **`HOME` 変数** をそのフォルダーに設定し、その `Terminal` アプリを開くことで、`.zshenv` ファイルを実行します（理由は不明ですが、変数 `__OSINSTALL_ENVIROMENT` を設定する必要もありました）。

[**元のレポートはこちら**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/)を確認してください。

### Word Sandbox Bypass with Open and stdin

**`open`** ユーティリティは、**`--stdin`** パラメータもサポートしていました（前のバイパス後は `--env` を使用することはできなくなりました）。

問題は、**`python`** が Apple によって署名されていても、**`quarantine`** 属性を持つスクリプトは **実行されない** ということです。しかし、stdin からスクリプトを渡すことができたため、クアランティンされているかどうかをチェックしませんでした:&#x20;

1. 任意の Python コマンドを含む **`~$exploit.py`** ファイルをドロップします。
2. _open_ **`–stdin='~$exploit.py' -a Python`** を実行します。これにより、Python アプリが標準入力としてドロップしたファイルを使用して実行されます。Python は喜んで私たちのコードを実行し、これは _launchd_ の子プロセスであるため、Word のサンドボックスルールに束縛されません。

{{#include ../../../../../banners/hacktricks-training.md}}
