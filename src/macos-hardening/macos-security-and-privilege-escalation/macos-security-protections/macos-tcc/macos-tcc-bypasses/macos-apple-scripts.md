# macOS Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

これは、**リモートプロセスとやり取りしながら**タスクを自動化するために使われるスクリプト言語です。**他のプロセスに処理を実行させる**ことをかなり簡単にします。**Malware** は、他のプロセスが公開している機能を悪用するために、これらの機能を悪用する可能性があります。\
たとえば、malware がブラウザで開かれているページに**任意の JS コードを注入**したり、ユーザーに要求された許可ダイアログを**自動 क्लिक**したりできます。
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
ここではいくつかの例を紹介します: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
AppleScriptsを使用したマルウェアに関する詳細は[**here**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/)で確認できます。

### Automation / TCCのquirks

Apple Events の承認は**方向性**があります: プロンプトは**source process -> target process** のペアに対して表示されます。ユーザーが **Allow** をクリックすると、同じ source から同じ target への今後のリクエストは、そのエントリがリセットされるまで許可されます。テスト中、`Terminal -> Finder` または `Terminal -> System Events` を一度許可すれば、後で別のポップアップなしにその権限を再利用できます。
```bash
# Remove previously granted Automation permissions from Terminal
tccutil reset AppleEvents com.apple.Terminal
```
これは特に **target** が **Finder** の場合に重要です。というのも、Finder は FDA UI に表示されていなくても常に **Full Disk Access** を持っているからです。したがって、Finder に対する Automation をすでに持っている任意のホストは、TCC で保護されたファイルにアクセスするための AppleScript/JXA プロキシとして使えます。汎用の Finder と System Events の payload は、すでに [the main TCC page](../README.md) と [the Apple Events page](../macos-apple-events.md) に文書化されています。

### Modern offensive tradecraft

`/usr/bin/osascript` は、最も目に見えるエントリポイントにすぎません。AppleScript と JXA は、**Mach-O binaries** からも **`NSAppleScript`** / **`OSAScript`** を介して実行でき、これは evasion と、すでに興味深い TCC grants を持つホストの内部に留まることの両方に有用です。
```bash
osascript -l JavaScript <<'EOF'
const app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("id > /tmp/jxa_id");
EOF
```
If you build a custom helper that sends Apple Events directly, giving it a **real app identity** makes testing and operations much more reliable. In practice this means embedding an `Info.plist` with `CFBundleIdentifier` and `NSAppleEventsUsageDescription`, signing the binary, and granting the `com.apple.security.automation.apple-events` entitlement. Otherwise the Apple Events prompt is frequently attributed to the **parent host** (for example `Terminal`) or the `NSAppleScript` execution just fails with confusing `-1750` / `errOSASystemError` errors.

Apple scripts may be easily "**compiled**". These versions can be easily "**decompiled**" with `osadecompile`

However, these scripts can also be **"Read only"としてエクスポート**（"Export..." オプション経由）されます:

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
そしてこの場合、`osadecompile` を使ってもその content は decompile できません

ただし、この種の executables を理解するために使える tool はまだあります。[**詳細についてはこの research を読んでください**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/))。tool [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler) と [**aevt_decompile**](https://github.com/SentineLabs/aevt_decompile) は、script の動作を理解するのに非常に役立ちます。

## References

- [Bypassing macOS TCC User Privacy Protections by Accident and Design](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [Making AppleScript Work in macOS CLI Tools: The Undocumented Parts](https://steipete.me/posts/2025/applescript-cli-macos-complete-guide)

{{#include ../../../../../banners/hacktricks-training.md}}
