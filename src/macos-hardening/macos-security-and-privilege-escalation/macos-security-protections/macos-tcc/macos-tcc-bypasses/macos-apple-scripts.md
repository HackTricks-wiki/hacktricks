# macOS Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

AppleScriptは、scriptable applicationsにApple Eventsを送信できるautomation languageです。適切なgrantがあれば、malwareはscriptable browser tabにJavaScriptをinjectしたり、System Events/Accessibilityを使用してpermission dialogをクリックしたりできます。Apple EventsとAccessibilityは別個のTCC servicesであり、通常はそれぞれユーザーによる承認が必要です。<sup>[[3]](#references)</sup>
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
`abbeycode/AppleScripts` repository には、自動化の例が含まれています。<sup>[[7]](#references)</sup>\
applescripts を使用する malware についての詳細は[**こちら**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/)をご覧ください。<sup>[[3]](#references)</sup>

### Automation / TCC の特徴

Apple Events の承認は**方向性を持ちます**。プロンプトは **source process -> target process** の組み合わせに対して表示されます。ユーザーが **Allow** をクリックすると、同じ source から同じ target への今後のリクエストは、そのエントリがリセットされるまで許可されます。テスト中に一度 `Terminal -> Finder` または `Terminal -> System Events` を許可すれば、後で別のポップアップを表示せずにその権限を再利用できます。<sup>[[1]](#references)</sup>
```bash
# Remove previously granted Automation permissions from Terminal
tccutil reset AppleEvents com.apple.Terminal
```
これは特に **target** が **Finder** の場合に重要です。Finder は FDA UI に表示されない場合でも、常に **Full Disk Access** を保持しているためです。したがって、すでに Finder に対する **Automation** を持つホストは、TCC で保護されたファイルにアクセスするための AppleScript/JXA proxy として使用できます。<sup>[[1]](#references)</sup> Generic Finder および System Events payloads は、すでに[メインの TCC ページ](../README.md)と [Apple Events ページ](../macos-apple-events.md)に記載されています。

### Modern offensive tradecraft

`/usr/bin/osascript` は、最も目立つ entry point にすぎません。AppleScript と JXA は、**`NSAppleScript`** / **`OSAScript`** を介して **Mach-O binaries** から実行することもできます。これは、evasion と、すでに興味深い TCC grants を持つホスト内で活動する目的の両方に有用です。<sup>[[2]](#references)</sup>
```bash
osascript -l JavaScript <<'EOF'
const app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("id > /tmp/jxa_id");
EOF
```
カスタム helper を作成して Apple Events を直接送信する場合、**real app identity** を付与すると、testing と operations の信頼性が大幅に向上します。実際には、`CFBundleIdentifier` と `NSAppleEventsUsageDescription` を含む `Info.plist` を埋め込み、binary に署名し、`com.apple.security.automation.apple-events` entitlement を付与します。そうしないと、Apple Events の prompt が**parent host**（たとえば `Terminal`）に紐づけられることが多く、または `NSAppleScript` の実行が、わかりにくい `-1750` / `errOSASystemError` エラーで失敗します。<sup>[[2]](#references)</sup>

AppleScripts は compiled form で保存でき、通常は `osadecompile` で decompile できます。

ただし、これらの scripts は **"Read only"** として export することもできます（"Export..." オプション経由）：

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
その場合、`osadecompile` は通常のソースの復元を拒否しますが、bytecode と Apple Event の用語は引き続き分析できます。

SentinelOne の run-only に関する研究では、この制限があっても構造を復元する方法が説明されています。`applescript-disassembler` と `aevt_decompile` は、コンパイル済みスクリプトと Apple Event データの調査に役立ちます。<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

## References

- [1] [macOS TCC User Privacy Protections を意図的および偶発的に回避する](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [2] [macOS CLI ツールで AppleScript を動作させる：文書化されていない部分](https://steipete.me/posts/2025/applescript-cli-macos-complete-guide)
- [3] [攻撃者が macOS の攻撃に AppleScript を使用する方法](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/)
- [4] [FADE DEAD | 悪意のある Run-Only AppleScript のリバースに関する冒険](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)
- [5] [Jinmo/applescript-disassembler](https://github.com/Jinmo/applescript-disassembler)
- [6] [SentineLabs/aevt_decompile](https://github.com/SentineLabs/aevt_decompile)
- [7] [abbeycode/AppleScripts の例](https://github.com/abbeycode/AppleScripts)
{{#include ../../../../../banners/hacktricks-training.md}}
