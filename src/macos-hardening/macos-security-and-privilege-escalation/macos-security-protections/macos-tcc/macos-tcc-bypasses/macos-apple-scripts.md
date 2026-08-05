# macOS Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

これは、**remote processesと対話**しながらタスクを自動化するために使用されるスクリプト言語です。**他のプロセスに何らかのアクションを実行するよう依頼する**ことが非常に容易です。**Malware**は、これらの機能を悪用して、他のプロセスがexportしている機能を悪用する可能性があります。\
たとえば、Malwareはブラウザで開かれているページに**任意のJS codeをinject**したり、ユーザーに要求された許可を**auto click**したりできます。<sup>[3]</sup>
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
以下にいくつかの例があります: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
AppleScriptsを使用するmalwareについての詳細は[**こちら**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/)をご覧ください。

### Automation / TCCの注意点

Apple Eventsの承認は**方向性**があります: プロンプトは**source process -> target process**のペアに対して表示されます。ユーザーが一度**Allow**をクリックすると、同じsourceから同じtargetへの以後のリクエストは、そのエントリがリセットされるまで許可されます。テスト中に`Terminal -> Finder`または`Terminal -> System Events`を一度許可すれば、後で再度ポップアップを表示せずにその権限を再利用できます。<sup>[1]</sup>
```bash
# Remove previously granted Automation permissions from Terminal
tccutil reset AppleEvents com.apple.Terminal
```
これは **target** が **Finder** の場合に特に重要です。Finder は FDA UI に表示されない場合でも、常に **Full Disk Access** を持っているためです。したがって、すでに Finder に対する Automation 権限を持つホストは、TCC で保護されたファイルにアクセスするための AppleScript/JXA proxy として使用できます。<sup>[1]</sup> 汎用的な Finder および System Events の payloads については、[the main TCC page](../README.md) と [the Apple Events page](../macos-apple-events.md) にすでに記載されています。

### Modern offensive tradecraft

`/usr/bin/osascript` は、最も目立つ entry point にすぎません。AppleScript と JXA は、**`NSAppleScript`** / **`OSAScript`** を介して **Mach-O binaries** から実行することもできます。これは、evasion のためだけでなく、すでに興味深い TCC grants を持つホスト内で活動する場合にも有用です。<sup>[2]</sup>
```bash
osascript -l JavaScript <<'EOF'
const app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("id > /tmp/jxa_id");
EOF
```
カスタム helper を作成して Apple Events を直接送信する場合、**real app identity** を持たせることで、testing と運用の信頼性が大幅に向上します。実際には、`CFBundleIdentifier` と `NSAppleEventsUsageDescription` を含む `Info.plist` を埋め込み、binary に署名し、`com.apple.security.automation.apple-events` entitlement を付与することを意味します。そうしないと、Apple Events の prompt が **parent host**（例: `Terminal`）に紐付けられることが多く、または `NSAppleScript` の実行が、分かりにくい `-1750` / `errOSASystemError` エラーで失敗します。<sup>[2]</sup>

Apple scripts は簡単に "**compiled**" できます。これらの version は `osadecompile` で簡単に "**decompiled**" できます。

ただし、これらの scripts は「Export...」オプションを使用して、**"Read only"** として export することもできます。

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
そしてこの場合、`osadecompile` を使用してもコンテンツを decompile できません。

しかし、この種の executables を理解するために使用できるツールはまだいくつかあります。詳細については[**この research を参照してください**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)。<sup>[4]</sup> [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler) と [**aevt_decompile**](https://github.com/SentineLabs/aevt_decompile) を組み合わせると、script の動作を理解するのに非常に役立ちます。

## References

- [1] [macOS TCC User Privacy Protections を Accident と Design により Bypassing する](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [2] [macOS CLI Tools で AppleScript を動作させる：Undocumented Parts](https://steipete.me/posts/2025/applescript-cli-macos-complete-guide)
- [3] [Offensive Actors が macOS を攻撃するために AppleScript を使用する方法](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/)
- [4] [FADE DEAD | Malicious Run-Only AppleScripts の Reversing Adventures](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)

{{#include ../../../../../banners/hacktricks-training.md}}
