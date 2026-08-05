# macOS Office Sandbox Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

### Word Sandbox bypass via Launch Agents

このアプリケーションは、**`com.apple.security.temporary-exception.sbpl`** entitlement を使用した **custom Sandbox** を使用しており、この custom sandbox では、ファイル名が `~$` で始まる限り、どこにでもファイルを書き込めます: `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`

したがって、`~/Library/LaunchAgents/~$escape.plist` に **`plist`** LaunchAgent を書き込むだけで、escape は容易に実行できました。

Check the [**original report here**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/).<sup>[[1]](#references)</sup>

### Word Sandbox bypass via Login Items and zip

最初の escape により、Word は `~$` で始まる名前の任意のファイルを書き込めます。ただし、前述の vuln に対する patch 後は、`/Library/Application Scripts` または `/Library/LaunchAgents` に書き込むことはできませんでした。

sandbox 内から **Login Item**（ユーザーのログイン時に実行される apps）を作成できることが発見されました。しかし、これらの apps は **notarized** されていない限り実行されず、**args を追加することもできません**（そのため、単に **`bash`** を使って reverse shell を実行することはできません）。

以前の Sandbox bypass により、Microsoft は `~/Library/LaunchAgents` にファイルを書き込む機能を無効化しました。しかし、**Login Item** として **zip file** を置くと、`Archive Utility` がその zip を現在の場所に **unzip** することが発見されました。デフォルトでは `~/Library` 内の `LaunchAgents` folder は作成されていないため、`LaunchAgents/~$escape.plist` に **plist** を zip 化し、その zip file を **`~/Library`** に置くことで、解凍時に persistence の宛先へ到達させることが可能でした。

Check the [**original report here**](https://objective-see.org/blog/blog_0x4B.html).<sup>[[2]](#references)</sup>

### Word Sandbox bypass via Login Items and .zshenv

（最初の escape により、Word は `~$` で始まる名前の任意のファイルを書き込めます。）

ただし、以前の technique には制限があり、他の software によって **`~/Library/LaunchAgents`** folder が作成されている場合は失敗します。そのため、これに対する別の Login Items chain が発見されました。

攻撃者は、実行する payload を含む **`.bash_profile`** と **`.zshenv`** の files を作成し、それらを zip 化して victims の user folder: **`~/~$escape.zip`** に **write** できます。

次に、その zip file と **`Terminal`** app を **Login Items** に追加します。ユーザーが再度ログインすると、zip file が user の folder 内で uncompressed され、**`.bash_profile`** と **`.zshenv`** が overwrite されます。その結果、terminal はこれらの files のいずれかを実行します（bash と zsh のどちらを使用するかによって異なります）。

Check the [**original report here**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c).<sup>[[3]](#references)</sup>

### Word Sandbox Bypass with Open and env variables

sandboxed processes からは、**`open`** utility を使用して他の processes を invoke することが依然として可能です。さらに、これらの processes は **their own sandbox** 内で実行されます。

open utility には、**specific env** variables を指定して app を実行する **`--env`** option があることが発見されました。したがって、**sandbox** 内の folder に **`.zshenv file`** を作成し、`--env` を使用して **`HOME` variable** をその folder に設定した上で `Terminal` app を開くことが可能でした。これにより `.zshenv` file が実行されます（何らかの理由で、variable `__OSINSTALL_ENVIROMENT` の設定も必要でした）。

Check the [**original report here**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/).<sup>[[4]](#references)</sup>

### Word Sandbox Bypass with Open and stdin

**`open`** utility は **`--stdin`** param もサポートしていました（また、前述の bypass 後は `--env` を使用できなくなりました）。

**`python`** は Apple によって signed されていますが、**`quarantine`** attribute が付いた script は実行しません。しかし、stdin から script を渡すことで、quarantine されているかどうかの check を回避できました。

1. 任意の Python commands を含む **`~$exploit.py`** file を drop します。
2. _open_ **`–stdin='~$exploit.py' -a Python`** を実行します。これにより、drop した file を standard input として使用して Python app が実行されます。Python は問題なく code を実行し、さらに _launchd_ の child process であるため、Word の sandbox rules に binding されません。

## References

- [1] [Escaping the Sandbox – Microsoft Office on macOS](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/)
- [2] [Office Drama on macOS](https://objective-see.org/blog/blog_0x4B.html)
- [3] [Office365 MacOS Sandbox Escape](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)
- [4] [Technical Analysis of CVE-2021-30864](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/)

{{#include ../../../../../banners/hacktricks-training.md}}
