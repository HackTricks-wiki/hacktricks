# macOS Office Sandbox Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

以下は**Microsoft Office for Mac の歴史的な sandbox escape**です。再利用可能な trust boundary の問題を記録したものですが、正確なバージョンと policy を再現せずに、patch 済みの Office/macOS の組み合わせが脆弱だと想定してはいけません。

### LaunchAgents による Word sandbox bypass

影響を受けた application は、`com.apple.security.temporary-exception.sbpl` を通じて custom sandbox rule を使用していました。この rule は、basename が `~$` で始まる regular file を許可していました: `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`.<sup>[[1]](#references)</sup>

したがって、`~/Library/LaunchAgents/~$escape.plist` に **`plist` LaunchAgent を書き込む**だけで escape できました。

[**元の report はこちら**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/).<sup>[[1]](#references)</sup>

### Login Items と zip による Word Sandbox bypass

最初の escape で述べたように、Word は名前が `~$` で始まる任意の file を書き込めますが、前の vuln に対する patch 後は `/Library/Application Scripts` や `/Library/LaunchAgents` に書き込むことはできませんでした。

影響を受けた sandbox では、user が login したときに起動する **Login Item** を作成できました。実証された path では、許可される署名済みまたは notarized application が必要で、任意の arguments は許可されなかったため、reverse-shell argument 付きで `bash` を追加するだけでは不十分でした。<sup>[[2]](#references)</sup>

前述の Sandbox bypass を受けて、Microsoft は `~/Library/LaunchAgents` に file を書き込む option を無効化しました。しかし、**zip file を Login Item として指定**すると、`Archive Utility` がそれを現在の location にそのまま**展開**することが発見されました。デフォルトでは `~/Library` 内の `LaunchAgents` folder は作成されていないため、`LaunchAgents/~$escape.plist` にある plist を **zip にして**、zip file を **`~/Library` に配置**すれば、decompress 時に persistence の destination に到達させることができました。

[**元の report はこちら**](https://objective-see.org/blog/blog_0x4B.html).<sup>[[2]](#references)</sup>

### Login Items と .zshenv による Word Sandbox bypass

（最初の escape で述べたように、Word は名前が `~$` で始まる任意の file を書き込めます。）

ただし、前の technique には制限があり、他の software が **`~/Library/LaunchAgents`** folder を作成している場合は失敗しました。そこで、別の Login Items chain が発見されました。

attacker は payload を含む **`.bash_profile`** と **`.zshenv`** を作成して archive 化し、その ZIP を **victim** の home directory に **`~/~$escape.zip`** として書き込むことができました。

次に、その ZIP と **Terminal** を Login Items として追加します。次回の login 時に、Archive Utility が dotfiles を user の home directory に展開し、Terminal の shell が該当する startup file（実証された Bash path では `.bash_profile`、Zsh では `.zshenv`）を評価します。<sup>[[3]](#references)</sup>

[**元の report はこちら**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c).<sup>[[3]](#references)</sup>

### Open と env variables による Word Sandbox Bypass

Sandboxed process は、**`open`** を通じて application の launch を引き続き request できました。launch された application は、Word の正確な sandbox profile を継承するのではなく、独自の security context で実行されました。<sup>[[4]](#references)</sup>

影響を受けた `open` utility には、environment variables を指定するための **`--env`** option がありました。exploit は sandbox 内に `.zshenv` を作成し、`HOME` をその directory に設定して Terminal を launch し、Zsh にそれを評価させました。報告された chain では、スペルミスのある private variable `__OSINSTALL_ENVIROMENT` も設定していました。歴史的な PoC を再現する場合は、この正確なスペルを維持してください。<sup>[[4]](#references)</sup>

[**元の report はこちら**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/).<sup>[[4]](#references)</sup>

### Open と stdin による Word Sandbox Bypass

**`open`** utility は **`--stdin`** param もサポートしていました（前の bypass 後は `--env` を使用できなくなりました）。

Apple の Python application は quarantined script file を reject していましたが、脆弱な workflow では同じ script を standard input 経由で渡すことで、file ベースの quarantine check を回避できました:<sup>[[5]](#references)</sup>

1. 任意の Python commands を含む **`~$exploit.py`** file を drop します。
2. `open --stdin='~$exploit.py' -a Python` を実行します。launch された Python application は drop された code を standard input から受け取り、脆弱な version では、LaunchServices が `launchd` の下で作成するため、Word の sandbox 外で実行します。<sup>[[5]](#references)</sup>

## References

- [1] [Sandbox からの脱出 – macOS 上の Microsoft Office](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/)
- [2] [macOS 上の Office Drama](https://objective-see.org/blog/blog_0x4B.html)
- [3] [Office365 MacOS Sandbox Escape](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)
- [4] [CVE-2021-30864 の Technical Analysis](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/)
- [5] [macOS App Sandbox escape vulnerability の発見: CVE-2022-26706 の詳細な分析 - Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2022/07/13/uncovering-a-macos-app-sandbox-escape-vulnerability-a-deep-dive-into-cve-2022-26706/)
{{#include ../../../../../banners/hacktricks-training.md}}
