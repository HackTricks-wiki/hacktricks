# macOS Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

タスク自動化のために使用される、**remote processesと対話する**スクリプト言語です。他のprocessesに**いくつかのアクションを実行するよう依頼する**ことが非常に簡単になります。**Malware**は、これらの機能を悪用して、他のprocessesがexportしている機能を悪用する可能性があります。\
たとえば、Malwareは**browserで開かれているページに任意のJS codeをinject**できます。また、ユーザーに要求された許可を**auto click**することも可能です。<sup>[[3]](#references)</sup>
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
以下にいくつかの例があります: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
AppleScriptを使用する malware に関する詳細情報は[**こちら**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/)をご覧ください。

### Automation / TCC quirks

Apple Events の承認は**方向性があります**: プロンプトは**source process -> target process**のペアに対して表示されます。ユーザーが**Allow**をクリックすると、同じ source から同じ target への今後のリクエストは、エントリがリセットされるまで許可されます。テスト中に一度 `Terminal -> Finder` または `Terminal -> System Events` を許可すれば、後で別のポップアップを表示せずにその権限を再利用できます。<sup>[[1]](#references)</sup>
```bash
# Remove previously granted Automation permissions from Terminal
tccutil reset AppleEvents com.apple.Terminal
```
これは **target** が **Finder** の場合に特に重要です。Finder は FDA UI に表示されない場合でも、常に **Full Disk Access** を持っているためです。したがって、すでに Finder に対する **Automation** が許可されているホストは、TCC によって保護されたファイルへアクセスするための AppleScript/JXA **proxy** として使用できます。<sup>[[1]](#references)</sup> 汎用的な Finder および System Events の payload については、すでに[メインの TCC ページ](../README.md)と [Apple Events ページ](../macos-apple-events.md)で説明されています。

### 現代的な offensive tradecraft

`/usr/bin/osascript` は、最も目立つ entry point にすぎません。AppleScript と JXA は、**`NSAppleScript`** / **`OSAScript`** を介して **Mach-O binaries** から実行することもできます。これは、evasion と、すでに興味深い TCC grants を持つホスト内で活動する場合の両方に役立ちます。<sup>[[2]](#references)</sup>
```bash
osascript -l JavaScript <<'EOF'
const app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("id > /tmp/jxa_id");
EOF
```
カスタム helper を作成して Apple Events を直接送信する場合、**real app identity** を付与すると、testing と operations の信頼性が大幅に向上します。実際には、`CFBundleIdentifier` と `NSAppleEventsUsageDescription` を含む `Info.plist` を埋め込み、binary に署名し、`com.apple.security.automation.apple-events` entitlement を付与します。これを行わない場合、Apple Events の prompt が **parent host**（たとえば `Terminal`）に関連付けられることが多く、または `NSAppleScript` の実行が、分かりにくい `-1750` / `errOSASystemError` エラーで失敗します。<sup>[[2]](#references)</sup>

Apple scripts は簡単に "**compiled**" できます。これらの versions は `osadecompile` で簡単に "**decompiled**" できます。

ただし、これらの scripts は "**Read only**" として export することもできます（"Export..." option 経由）。

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
そしてこの場合、`osadecompile` を使ってもコンテンツを decompile することはできません。

ただし、この種の executable を理解するために使用できるツールはいくつかあります。[**詳細についてはこの research をお読みください**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)).<sup>[[4]](#references)</sup> [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler) と [**aevt_decompile**](https://github.com/SentineLabs/aevt_decompile) は、script の動作を理解するうえで非常に役立ちます。

## References

- [1] [偶然と設計による macOS TCC User Privacy Protections の bypass](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [2] [macOS CLI Tools で AppleScript を動作させる: Undocumented Parts](https://steipete.me/posts/2025/applescript-cli-macos-complete-guide)
- [3] [Offensive Actors は AppleScript を macOS 攻撃にどのように使用するのか](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/)
- [4] [FADE DEAD | Malicious Run-Only AppleScripts の reversing における adventures](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)

{{#include ../../../../../banners/hacktricks-training.md}}
