# macOS Office Sandbox Bypasses

{{#include ../../../../../banners/hacktricks-training.md}}

The following are **historical Microsoft Office for Mac sandbox escapes**. They document reusable trust-boundary mistakes, but patched Office/macOS combinations should not be assumed vulnerable without reproducing the exact version and policy.

### Word sandbox bypass via LaunchAgents

The affected application used a custom sandbox rule through `com.apple.security.temporary-exception.sbpl`. It allowed regular files whose basename started with `~$`: `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`.<sup>[[1]](#references)</sup>

Therefore, escaping was as easy as **writing a `plist`** LaunchAgent in `~/Library/LaunchAgents/~$escape.plist`.

Check the [**original report here**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/).<sup>[[1]](#references)</sup>

### Word Sandbox bypass via Login Items and zip

Remember that from the first escape, Word can write arbitrary files whose name start with `~$` although after the patch of the previous vuln it wasn't possible to write in `/Library/Application Scripts` or in `/Library/LaunchAgents`.

The affected sandbox allowed creation of a **Login Item**, which launches when the user logs in. The demonstrated path required an acceptable signed/notarized application and did not permit arbitrary arguments, so adding `bash` with a reverse-shell argument was insufficient.<sup>[[2]](#references)</sup>

From the previous Sandbox bypass, Microsoft disabled the option to write files in `~/Library/LaunchAgents`. However, it was discovered that if you put a **zip file as a Login Item** the `Archive Utility` will just **unzip** it on its current location. So, because by default the folder `LaunchAgents` from `~/Library` is not created, it was possible to **zip a plist in `LaunchAgents/~$escape.plist`** and **place** the zip file in **`~/Library`** so when decompress it will reach the persistence destination.

Check the [**original report here**](https://objective-see.org/blog/blog_0x4B.html).<sup>[[2]](#references)</sup>

### Word Sandbox bypass via Login Items and .zshenv

(Remember that from the first escape, Word can write arbitrary files whose name start with `~$`).

However, the previous technique had a limitation, if the folder **`~/Library/LaunchAgents`** exists because some other software created it, it would fail. So a different Login Items chain was discovered for this.

An attacker could create **`.bash_profile`** and **`.zshenv`** containing the payload, archive them, and write the ZIP to the **victim's** home directory as **`~/~$escape.zip`**.

Then add the ZIP and **Terminal** as Login Items. At the next login, Archive Utility extracts the dotfiles into the user's home directory and Terminal's shell evaluates the applicable startup file (`.bash_profile` for the demonstrated Bash path or `.zshenv` for Zsh).<sup>[[3]](#references)</sup>

Check the [**original report here**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c).<sup>[[3]](#references)</sup>

### Word Sandbox Bypass with Open and env variables

Sandboxed processes could still request application launches through **`open`**. The launched application ran in its own security context rather than inheriting Word's exact sandbox profile.<sup>[[4]](#references)</sup>

The affected `open` utility had an **`--env`** option for supplying environment variables. The exploit created `.zshenv` inside the sandbox, set `HOME` to that directory, and launched Terminal so Zsh evaluated it. The reported chain also set the misspelled private variable `__OSINSTALL_ENVIROMENT`; preserve that exact spelling when reproducing the historical PoC.<sup>[[4]](#references)</sup>

Check the [**original report here**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/).<sup>[[4]](#references)</sup>

### Word Sandbox Bypass with Open and stdin

The **`open`** utility also supported the **`--stdin`** param (and after the previous bypass it was no longer possible to use `--env`).

Although Apple's Python application would reject a quarantined script file, the vulnerable workflow could feed the same script over standard input, avoiding the file-based quarantine check:<sup>[[5]](#references)</sup>

1. Drop a **`~$exploit.py`** file with arbitrary Python commands.
2. Run `open --stdin='~$exploit.py' -a Python`. The launched Python application receives the dropped code on standard input and, in the vulnerable versions, runs outside Word's sandbox because LaunchServices creates it under `launchd`.<sup>[[5]](#references)</sup>

## References

- [1] [Escaping the Sandbox – Microsoft Office on macOS](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/)
- [2] [Office Drama on macOS](https://objective-see.org/blog/blog_0x4B.html)
- [3] [Office365 MacOS Sandbox Escape](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)
- [4] [Technical Analysis of CVE-2021-30864](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/)
- [5] [Uncovering a macOS App Sandbox escape vulnerability: A deep dive into CVE-2022-26706 - Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2022/07/13/uncovering-a-macos-app-sandbox-escape-vulnerability-a-deep-dive-into-cve-2022-26706/)

{{#include ../../../../../banners/hacktricks-training.md}}
