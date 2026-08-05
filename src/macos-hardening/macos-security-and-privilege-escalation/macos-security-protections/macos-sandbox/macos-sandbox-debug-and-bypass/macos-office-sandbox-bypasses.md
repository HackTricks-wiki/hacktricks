# macOS Office Sandbox Bypass

{{#include ../../../../../banners/hacktricks-training.md}}

### Word Sandbox bypass via Launch Agents

このアプリケーションは、**`com.apple.security.temporary-exception.sbpl`** entitlement を使用した **custom Sandbox** を利用しています。この custom sandbox では、ファイル名が `~$` で始まる限り、どこにでもファイルを書き込むことができます: `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`

したがって、`~/Library/LaunchAgents/~$escape.plist` に **`plist`** LaunchAgent を **書き込む**だけで、escape が可能でした。

[**original report here**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/) を参照してください。<sup>[1]</sup>

### Word Sandbox bypass via Login Items and zip

最初の escape により、Word は名前が `~$` で始まる任意のファイルを書き込めます。ただし、前述の vuln に対する patch 後は、`/Library/Application Scripts` や `/Library/LaunchAgents` に書き込むことはできませんでした。

sandbox 内から **Login Item**（ユーザーのログイン時に実行されるアプリ）を作成できることが発見されました。しかし、これらのアプリは **notarized** されていなければ **実行されず**、さらに **args を追加することもできません**（そのため、単純に **`bash`** を使用して reverse shell を実行することはできません）。

以前の Sandbox bypass により、Microsoft は `~/Library/LaunchAgents` にファイルを書き込む機能を無効化しました。しかし、**zip file を Login Item として指定すると、`Archive Utility` がその zip file を現在の場所にそのまま **unzip** することが発見されました。デフォルトでは `~/Library` 内の `LaunchAgents` folder は作成されていないため、`LaunchAgents/~$escape.plist` に plist を **zip** し、その zip file を **`~/Library`** に配置することで、展開時に persistence の宛先へ到達させることが可能でした。

[**original report here**](https://objective-see.org/blog/blog_0x4B.html) を参照してください。<sup>[2]</sup>

### Word Sandbox bypass via Login Items and .zshenv

（最初の escape により、Word は名前が `~$` で始まる任意のファイルを書き込めます。）

しかし、前述の technique には制限があり、他の software によって **`~/Library/LaunchAgents`** folder が作成されている場合は失敗します。そこで、別の Login Items chain が発見されました。

attacker は、実行する payload を含む **`.bash_profile`** と **`.zshenv`** を作成して zip し、被害者の user folder に **`~/~$escape.zip`** として **write** できます。

次に、その zip file と **`Terminal`** app を **Login Items** に追加します。ユーザーが再度ログインすると、zip file が user file 内で解凍され、**`.bash_profile`** と **`.zshenv`** が上書きされます。その結果、Terminal はこれらの file のいずれかを実行します（bash と zsh のどちらを使用するかによって異なります）。

[**original report here**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) を参照してください。<sup>[3]</sup>

### Word Sandbox Bypass with Open and env variables

sandboxed process からは、`open` utility を使用して他の process を invoke することが依然として可能です。さらに、これらの process は **独自の sandbox 内で**実行されます。

`open` utility には、特定の env variables を指定して app を実行する **`--env`** option があることが発見されました。そこで、**sandbox 内の folder** に **`.zshenv file`** を作成し、`--env` で **`HOME` variable** をその folder に設定して `Terminal` app を開くことが可能でした。これにより `.zshenv` file が実行されます（なぜか **`__OSINSTALL_ENVIROMENT`** variable の設定も必要でした）。

[**original report here**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/) を参照してください。<sup>[4]</sup>

### Word Sandbox Bypass with Open and stdin

**`open`** utility は **`--stdin`** param もサポートしていました（前述の bypass 後は `--env` を使用できなくなりました）。

Apple によって signed された **`python`** であっても、**`quarantine`** attribute が付いた script は **実行しません**。しかし、stdin から script を渡せば、quarantine 済みかどうかの check を回避できました。

1. 任意の Python commands を含む **`~$exploit.py`** file を drop します。
2. _open_ **`–stdin='~$exploit.py' -a Python`** を実行します。これにより、drop した file が standard input として機能する状態で Python app が実行されます。Python は問題なく code を実行し、さらに _launchd_ の child process であるため、Word の sandbox rules に拘束されません。

## References

- [1] [Escaping the Sandbox – Microsoft Office on macOS](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/)
- [2] [Office Drama on macOS](https://objective-see.org/blog/blog_0x4B.html)
- [3] [Office365 MacOS Sandbox Escape](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)
- [4] [Technical Analysis of CVE-2021-30864](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/)

{{#include ../../../../../banners/hacktricks-training.md}}
