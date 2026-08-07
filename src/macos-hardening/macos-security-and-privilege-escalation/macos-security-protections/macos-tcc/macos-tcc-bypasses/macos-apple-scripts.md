# macOS Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

タスクの自動化に使用されるスクリプト言語で、**リモートプロセスとやり取り**できます。他のプロセスに**アクションの実行を依頼する**ことが比較的容易になります。**Malware**は、これらの機能を悪用して、他のプロセスがエクスポートする機能を悪用する可能性があります。\
例えば、Malwareはブラウザで開かれているページに**任意のJS codeをinject**できます。また、ユーザーに要求された許可に対して**auto click**することも可能です。<sup>[[3]](#references)</sup>
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
以下にいくつかの例があります: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
AppleScriptsを使用するmalwareについての詳細は[**こちら**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/)。<sup>[[3]](#references)</sup>

### 自動化 / TCCのquirks

Apple Eventsの承認は**方向性**があります: プロンプトは**source process -> target process**のペアに対して表示されます。ユーザーが**Allow**をクリックすると、同じsourceから同じtargetへの今後のリクエストは、エントリがresetされるまで許可されます。テスト中に一度`Terminal -> Finder`または`Terminal -> System Events`を許可すれば、後で別のポップアップなしにその権限を再利用できます。<sup>[[1]](#references)</sup>
```bash
# Remove previously granted Automation permissions from Terminal
tccutil reset AppleEvents com.apple.Terminal
```
これは特に **target** が **Finder** の場合に重要です。Finder は FDA UI に表示されない場合でも、常に **Full Disk Access** を持っているためです。したがって、すでに Finder に対する Automation を持つ任意のホストを、TCC で保護されたファイルにアクセスするための AppleScript/JXA proxy として使用できます。<sup>[[1]](#references)</sup> 一般的な Finder および System Events の payload については、すでに[メインの TCC ページ](../README.md)と [Apple Events のページ](../macos-apple-events.md)で説明されています。

### Modern offensive tradecraft

`/usr/bin/osascript` は最も目立つ entry point にすぎません。AppleScript と JXA は、**`NSAppleScript`** / **`OSAScript`** を介して **Mach-O binaries** から実行することもできます。これは evasion に役立つだけでなく、すでに興味深い TCC grants を持つ host 内で活動する場合にも有用です。<sup>[[2]](#references)</sup>
```bash
osascript -l JavaScript <<'EOF'
const app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("id > /tmp/jxa_id");
EOF
```
カスタムヘルパーを作成して Apple Events を直接送信する場合、**real app identity** を与えることで、テストと運用の信頼性が大幅に向上します。実際には、`CFBundleIdentifier` と `NSAppleEventsUsageDescription` を含む `Info.plist` を埋め込み、バイナリに署名し、`com.apple.security.automation.apple-events` entitlement を付与します。これを行わない場合、Apple Events のプロンプトが **親ホスト**（例えば `Terminal`）に関連付けられることが多く、または `NSAppleScript` の実行が、分かりにくい `-1750` / `errOSASystemError` エラーで失敗します。<sup>[[2]](#references)</sup>

Apple scripts は簡単に "**compiled**" できます。これらのバージョンは `osadecompile` で簡単に "**decompiled**" できます。

ただし、これらの scripts は（「Export...」オプションから）**「Read only」** として export することもできます。

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
そしてこの場合、`osadecompile`を使っても内容をdecompileできません。

ただし、この種のexecutablesを理解するために使用できるツールはまだいくつかあります。[**詳細についてはこのresearchをお読みください**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)).<sup>[[4]](#references)</sup> [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler)と[aevt_decompile](https://github.com/SentineLabs/aevt_decompile)というtoolは、scriptの動作を理解するうえで非常に役立ちます。

## References

- [1] [macOS TCC User Privacy Protectionsを偶然および意図的にBypassする](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [2] [macOS CLI ToolsでAppleScriptを動作させる：文書化されていない部分](https://steipete.me/posts/2025/applescript-cli-macos-complete-guide)
- [3] [Offensive ActorsがAppleScriptをmacOSへの攻撃に使用する方法](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/)
- [4] [FADE DEAD | Malicious Run-Only AppleScriptsのReversingに関する冒険](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)

{{#include ../../../../../banners/hacktricks-training.md}}
