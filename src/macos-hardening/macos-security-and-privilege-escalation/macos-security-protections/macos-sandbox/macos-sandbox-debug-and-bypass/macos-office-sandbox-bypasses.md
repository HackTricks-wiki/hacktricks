# macOS Office Sandbox Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

### 通过 Launch Agents 绕过 Word Sandbox

该应用使用基于 entitlement **`com.apple.security.temporary-exception.sbpl`** 的**自定义 Sandbox**，并且这个自定义 Sandbox 允许在任意位置写入文件，只要文件名以 `~$` 开头：`(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`

因此，逃逸过程非常简单，只需在 `~/Library/LaunchAgents/~$escape.plist` 中写入一个 **`plist`** LaunchAgent。

查看[**原始报告**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/)。<sup>[[1]](#references)</sup>

### 通过 Login Items 和 zip 绕过 Word Sandbox

请记住，在第一次逃逸中，Word 可以写入文件名以 `~$` 开头的任意文件，但在修复前一个漏洞后，无法再写入 `/Library/Application Scripts` 或 `/Library/LaunchAgents`。

研究人员发现，在 Sandbox 内可以创建一个 **Login Item**（用户登录时会执行的 app）。但是，这些 app **必须经过 notarized 才会执行**，并且**无法添加 args**（因此不能直接使用 **`bash`** 运行 reverse shell）。

在之前的 Sandbox bypass 中，Microsoft 禁用了写入 `~/Library/LaunchAgents` 的选项。不过，研究人员发现，如果将一个 **zip 文件作为 Login Item**，`Archive Utility` 会直接在其当前位置将其**解压**。由于默认情况下不会创建 `~/Library` 中的 `LaunchAgents` 文件夹，因此可以将 `LaunchAgents/~$escape.plist` 中的 plist **压缩**，并将 zip 文件放在 **`~/Library`** 中，这样解压后就能到达 persistence 目标位置。

查看[**原始报告**](https://objective-see.org/blog/blog_0x4B.html)。<sup>[[2]](#references)</sup>

### 通过 Login Items 和 .zshenv 绕过 Word Sandbox

（请记住，在第一次逃逸中，Word 可以写入文件名以 `~$` 开头的任意文件。）

但是，前一种技术存在限制：如果 **`~/Library/LaunchAgents`** 文件夹已经由其他软件创建，就会失败。因此，研究人员为此发现了另一条 Login Items chain。

攻击者可以创建包含待执行 payload 的 **`.bash_profile`** 和 **`.zshenv`** 文件，然后将它们压缩，并将 zip **写入受害者的**用户文件夹：**`~/~$escape.zip`**。

随后，将该 zip 文件和 **`Terminal`** app 添加到 **Login Items**。用户重新登录时，zip 文件会被解压到用户文件夹中，覆盖 **`.bash_profile`** 和 **`.zshenv`**，因此 Terminal 会执行其中一个文件（具体取决于使用的是 bash 还是 zsh）。

查看[**原始报告**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)。<sup>[[3]](#references)</sup>

### 通过 Open 和 env variables 绕过 Word Sandbox

从 sandboxed processes 中仍然可以使用 **`open`** utility 调用其他 processes。此外，这些 processes 会在**各自的 Sandbox** 中运行。

研究人员发现，open utility 具有 **`--env`** 选项，可以使用**指定的 env** variables 运行 app。因此，可以在 **Sandbox 内部**的某个文件夹中创建 **`.zshenv` 文件**，然后使用 `open` 的 `--env` 将 **`HOME` variable** 设置为该文件夹，同时打开 `Terminal` app；Terminal 会执行 `.zshenv` 文件（出于某种原因，还需要设置 variable `__OSINSTALL_ENVIROMENT`）。

查看[**原始报告**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/)。<sup>[[4]](#references)</sup>

### 通过 Open 和 stdin 绕过 Word Sandbox

**`open`** utility 还支持 **`--stdin`** param（在前一个 bypass 之后，已经无法再使用 `--env`）。

问题在于，即使 **`python`** 由 Apple 签名，它也**不会执行**带有 **`quarantine`** attribute 的 script。不过，可以从 stdin 向它传递 script，这样它就不会检查该 script 是否被 quarantine：

1. 放置一个包含任意 Python commands 的 **`~$exploit.py`** 文件。
2. 运行 _open_ **`–stdin='~$exploit.py' -a Python`**，这会运行 Python app，并将我们放置的文件作为其 standard input。Python 会直接执行我们的 code，而且由于它是 _launchd_ 的 child process，因此不受 Word Sandbox 规则的约束。<sup>[[5]](#references)</sup>

## References

- [1] [Escaping the Sandbox – Microsoft Office on macOS](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/)
- [2] [Office Drama on macOS](https://objective-see.org/blog/blog_0x4B.html)
- [3] [Office365 MacOS Sandbox Escape](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)
- [4] [Technical Analysis of CVE-2021-30864](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/)
- [5] [Uncovering a macOS App Sandbox escape vulnerability: A deep dive into CVE-2022-26706 - Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2022/07/13/uncovering-a-macos-app-sandbox-escape-vulnerability-a-deep-dive-into-cve-2022-26706/)

{{#include ../../../../../banners/hacktricks-training.md}}
