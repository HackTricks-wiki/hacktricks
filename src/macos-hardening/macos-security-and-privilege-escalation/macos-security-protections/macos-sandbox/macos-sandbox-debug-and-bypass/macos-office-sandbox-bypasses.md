# macOS Office Sandbox Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

以下是**历史上的 Microsoft Office for Mac sandbox escapes**。它们记录了可复用的 trust boundary 错误，但在未复现确切版本和策略的情况下，不应假定已修复的 Office/macOS 组合仍然存在漏洞。

### 通过 LaunchAgents 绕过 Word sandbox

受影响的应用通过 `com.apple.security.temporary-exception.sbpl` 使用了自定义 sandbox 规则。该规则允许 basename 以 `~$` 开头的常规文件：`(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`.<sup>[[1]](#references)</sup>

因此，escape 只需在 `~/Library/LaunchAgents/~$escape.plist` 中**写入一个 `plist`** LaunchAgent 即可。

查看[**原始报告**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/)。<sup>[[1]](#references)</sup>

### 通过 Login Items 和 zip 绕过 Word Sandbox

请记住，在第一次 escape 中，Word 可以写入名称以 `~$` 开头的任意文件，尽管在修复之前的 vuln 后，已经无法写入 `/Library/Application Scripts` 或 `/Library/LaunchAgents`。

受影响的 sandbox 允许创建一个**Login Item**，该项目会在用户登录时启动。演示的路径要求应用具有有效签名或经过 notarization，并且不允许任意参数，因此添加带有 reverse-shell 参数的 `bash` 不足以完成利用。<sup>[[2]](#references)</sup>

在之前的 Sandbox bypass 中，Microsoft 禁用了向 `~/Library/LaunchAgents` 写入文件的选项。然而，后来发现，如果将一个**zip 文件作为 Login Item**，`Archive Utility` 会直接在其当前位置将其**解压**。因此，由于默认情况下不会创建 `~/Library` 中的 `LaunchAgents` 文件夹，所以可以将 `LaunchAgents/~$escape.plist` 中的 **plist 压缩为 zip**，并将该 zip 文件**放置**在 **`~/Library`** 中，这样解压后就能到达 persistence 目标位置。

查看[**原始报告**](https://objective-see.org/blog/blog_0x4B.html)。<sup>[[2]](#references)</sup>

### 通过 Login Items 和 .zshenv 绕过 Word Sandbox

（请记住，在第一次 escape 中，Word 可以写入名称以 `~$` 开头的任意文件。）

不过，之前的 technique 存在一个限制：如果 **`~/Library/LaunchAgents`** 文件夹已存在（例如由其他软件创建），它就会失败。因此，研究人员为此发现了另一条 Login Items chain。

攻击者可以创建包含 payload 的 **`.bash_profile`** 和 **`.zshenv`**，将它们归档，然后将 ZIP 写入**受害者**的 home directory，即 **`~/~$escape.zip`**。

接着，将该 ZIP 和 **Terminal** 添加为 Login Items。下次登录时，Archive Utility 会将这些 dotfiles 解压到用户的 home directory，而 Terminal 的 shell 会评估适用的 startup file（演示的 Bash 路径使用 `.bash_profile`，Zsh 使用 `.zshenv`）。<sup>[[3]](#references)</sup>

查看[**原始报告**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)。<sup>[[3]](#references)</sup>

### 通过 Open 和 env variables 绕过 Word Sandbox

Sandboxed processes 仍然可以通过 **`open`** 请求启动应用。被启动的应用会在自己的 security context 中运行，而不是继承 Word 的确切 sandbox profile。<sup>[[4]](#references)</sup>

受影响的 `open` utility 具有用于提供 environment variables 的 **`--env`** 选项。该 exploit 会在 sandbox 内创建 `.zshenv`，将 `HOME` 设置为该目录，然后启动 Terminal，使 Zsh 对其进行评估。报告中的 chain 还设置了拼写错误的 private variable `__OSINSTALL_ENVIROMENT`；在复现历史 PoC 时，必须保留这一确切拼写。<sup>[[4]](#references)</sup>

查看[**原始报告**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/)。<sup>[[4]](#references)</sup>

### 通过 Open 和 stdin 绕过 Word Sandbox

**`open`** utility 还支持 **`--stdin`** param（在之前的 bypass 之后，已经无法再使用 `--env`）。

虽然 Apple 的 Python application 会拒绝 quarantined script file，但存在漏洞的 workflow 可以通过 standard input 提供同一个 script，从而绕过基于文件的 quarantine 检查：<sup>[[5]](#references)</sup>

1. 创建一个包含任意 Python commands 的 **`~$exploit.py`** 文件。
2. 运行 `open --stdin='~$exploit.py' -a Python`。启动的 Python application 会通过 standard input 接收该文件中的 code，并且在受影响的版本中，由于 LaunchServices 在 `launchd` 下创建该进程，它会在 Word sandbox 之外运行。<sup>[[5]](#references)</sup>

## References

- [1] [绕过 Sandbox – macOS 上的 Microsoft Office](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/)
- [2] [macOS 上的 Office Drama](https://objective-see.org/blog/blog_0x4B.html)
- [3] [Office365 MacOS Sandbox Escape](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)
- [4] [CVE-2021-30864 技术分析](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/)
- [5] [发现 macOS App Sandbox escape vulnerability：深入分析 CVE-2022-26706 - Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2022/07/13/uncovering-a-macos-app-sandbox-escape-vulnerability-a-deep-dive-into-cve-2022-26706/)
{{#include ../../../../../banners/hacktricks-training.md}}
