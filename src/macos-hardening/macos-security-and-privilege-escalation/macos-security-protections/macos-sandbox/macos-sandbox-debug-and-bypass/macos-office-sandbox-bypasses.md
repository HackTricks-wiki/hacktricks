# macOS Office Sandbox Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

### Word Sandbox bypass via Launch Agents

该应用使用带有 **`com.apple.security.temporary-exception.sbpl`** entitlement 的 **custom Sandbox**，此 custom sandbox 允许写入任意位置的文件，前提是文件名以 `~$` 开头：`(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`

因此，escape 只需在 `~/Library/LaunchAgents/~$escape.plist` 中写入一个 **`plist`** LaunchAgent。

查看[**原始报告**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/)。<sup>[[1]](#references)</sup>

### Word Sandbox bypass via Login Items and zip

请记住，在第一次 escape 中，Word 可以写入文件名以 `~$` 开头的任意文件，尽管在修复之前的 vuln 后，已经无法写入 `/Library/Application Scripts` 或 `/Library/LaunchAgents`。

研究发现，可以在 sandbox 内创建一个 **Login Item**（用户登录时会执行的 apps）。不过，除非这些 apps 已经 **notarized**，否则它们**不会执行**，并且**无法添加 args**（因此不能直接使用 **`bash`** 运行 reverse shell）。

在之前的 Sandbox bypass 中，Microsoft 禁用了写入 `~/Library/LaunchAgents` 的功能。但研究发现，如果将一个 **zip 文件作为 Login Item**，`Archive Utility` 会直接在其当前位置将其**解压**。由于默认情况下 `~/Library` 下的 `LaunchAgents` 文件夹不存在，因此可以将 `LaunchAgents/~$escape.plist` 中的 plist **压缩**，并将 zip 文件放在 **`~/Library`** 中，这样解压后就能到达 persistence 目标位置。

查看[**原始报告**](https://objective-see.org/blog/blog_0x4B.html)。<sup>[[2]](#references)</sup>

### Word Sandbox bypass via Login Items and .zshenv

（请记住，在第一次 escape 中，Word 可以写入文件名以 `~$` 开头的任意文件。）

但是，之前的 technique 存在一个限制：如果 **`~/Library/LaunchAgents`** 文件夹已经被其他 software 创建，则该 technique 会失败。因此，研究人员为此发现了另一条 Login Items chain。

攻击者可以创建包含待执行 payload 的 **`.bash_profile`** 和 **`.zshenv`** 文件，然后将它们压缩，并将 zip 写入受害者的 user 文件夹：**`~/~$escape.zip`**。

然后，将 zip 文件和 **`Terminal`** app 添加到 **Login Items**。当用户重新登录时，zip 文件会被解压到用户文件夹中，覆盖 **`.bash_profile`** 和 **`.zshenv`**，因此 Terminal 会执行其中一个文件（具体取决于使用 bash 还是 zsh）。

查看[**原始报告**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)。<sup>[[3]](#references)</sup>

### Word Sandbox Bypass with Open and env variables

从 sandboxed processes 中仍然可以使用 **`open`** utility 调用其他 processes。此外，这些 processes 会在其自身的 sandbox 中运行。

研究发现，open utility 具有 **`--env`** option，可以使用**指定的 env** variables 运行 app。因此，可以在 **sandbox** 内的某个 folder 中创建 **`.zshenv` 文件**，然后使用 `open` 的 `--env` 将 **`HOME` variable** 设置为该 folder，同时打开 `Terminal` app，使其执行 `.zshenv` 文件（由于某种原因，还需要设置 `__OSINSTALL_ENVIROMENT` variable）。

查看[**原始报告**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/)。<sup>[[4]](#references)</sup>

### Word Sandbox Bypass with Open and stdin

**`open`** utility 还支持 **`--stdin`** param（在之前的 bypass 之后，已经无法再使用 `--env`）。

问题在于，即使 **`python`** 由 Apple 签名，它也**不会执行**带有 **`quarantine`** attribute 的 script。不过，可以从 stdin 向它传递 script，这样它就不会检查该 script 是否带有 quarantine attribute：

1. 创建一个包含任意 Python commands 的 **`~$exploit.py`** 文件。
2. 运行 _open_ **`–stdin='~$exploit.py' -a Python`**，这会运行 Python app，并将创建的文件作为其 standard input。Python 会正常执行我们的 code，并且由于它是 _launchd_ 的 child process，因此不受 Word sandbox rules 的限制。

## References

- [1] [Escaping the Sandbox – Microsoft Office on macOS](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/)
- [2] [Office Drama on macOS](https://objective-see.org/blog/blog_0x4B.html)
- [3] [Office365 MacOS Sandbox Escape](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)
- [4] [Technical Analysis of CVE-2021-30864](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/)

{{#include ../../../../../banners/hacktricks-training.md}}
