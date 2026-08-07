# macOS Defensive Apps

{{#include ../../banners/hacktricks-training.md}}

## Firewalls

- [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html): 各プロセスが行うすべての接続を監視します。モード（接続をサイレントに許可、接続をサイレントに拒否してアラートを表示）に応じて、新しい接続が確立されるたびに**アラートを表示**します。これらの情報をすべて確認できる非常に優れたGUIも備えています。
- [**LuLu**](https://objective-see.org/products/lulu.html): Objective-Seeのfirewallです。疑わしい接続をアラートで通知する基本的なfirewallです（GUIを備えていますが、Little Snitchほど洗練されていません）。

## Persistence detection

- [**KnockKnock**](https://objective-see.org/products/knockknock.html): **malwareがpersistenceする可能性のある**複数の場所を検索するObjective-Seeのアプリケーションです（monitoring serviceではなく、one-shot toolです）。
- [**BlockBlock**](https://objective-see.org/products/blockblock.html): persistenceを生成するプロセスをmonitoringする、KnockKnockに似たツールです。

## Keyloggers detection

- [**ReiKey**](https://objective-see.org/products/reikey.html): keyboardの「event taps」をインストールする**keyloggers**を検出するObjective-Seeのアプリケーションです。

## Endpoint telemetry / execution control

- [**Santa**](https://santa.dev/): macOS向けのBinary authorizationおよびmonitoring systemです。**Endpoint Security** clientを使用して、codeが実行される前に**`exec`** eventsをauthorizeするため、post-execution detectionだけでなく、**allowlisting/denylisting**を重視するenterprise fleetsで一般的に使用されています。
- [**Mac Monitor**](https://github.com/redcanaryco/mac-monitor): Procmonに似たmacOSのdynamic analysis toolです。**Endpoint Security telemetry**（process、file、interprocess、login、およびXProtect関連のevents）を取り込み、成熟したESベースのsensorが実際に何をobserveできるかを理解するのに役立ちます。<sup>[[2]](#references)</sup>
- [**ProcessMonitor / FileMonitor / DNSMonitor**](https://objective-see.org/products/utilities.html): **process**、**file**、**DNS** telemetry向けの軽量なObjective-See toolsです。modern macOSでは、**root**、**Terminal Full Disk Access**、または**System/Network Extension approval**などの追加prerequisitesがあります。instrumentationのアイデアについては、[macOS app inspection/debuggingに関するこちらの別ページ](macos-apps-inspecting-debugging-and-fuzzing/README.md)を確認してください。

## Quick triage of defensive tooling

現代のmacOS security productsの多くは、**System Extensions / Endpoint Security clients**、**launchd agents/daemons**、およびFull Disk Accessを持つapplicationsの組み合わせとして動作します。operator向けの簡単なchecklist:
```bash
# System / network extensions (EDRs, DNS filters, firewalls, VPNs)
systemextensionsctl list

# Legacy kernel agents on older boxes / upgraded fleets
kmutil showloaded 2>/dev/null | rg -i 'crowdstrike|carbon|sentinel|defender|sophos|eset|symantec|trellix|sentinelone'
# Older releases:
kextstat 2>/dev/null | rg -i 'crowdstrike|carbon|sentinel|defender|sophos|eset|symantec|trellix|sentinelone'

# Userland agents / helpers
launchctl print system | rg -i 'santa|lulu|little snitch|crowdstrike|sentinel|defender|jamf|sophos|eset|symantec'
launchctl print gui/$UID | rg -i 'santa|lulu|little snitch|crowdstrike|sentinel|defender|jamf|sophos|eset|symantec'

# Inspect code-signing and entitlements of a defensive app
codesign -dvv --entitlements :- /Applications/SomeAgent.app

# Check common TCC grants used by sensors / telemetry tools
for db in "$HOME/Library/Application Support/com.apple.TCC/TCC.db" "/Library/Application Support/com.apple.TCC/TCC.db"; do
[ -f "$db" ] || continue
echo "== $db =="
sqlite3 "$db" 'SELECT service,client,auth_value,last_modified FROM access WHERE service IN ("kTCCServiceSystemPolicyAllFiles","kTCCServiceEndpointSecurityClient") ORDER BY last_modified DESC;'
done
```
`systemextensionsctl list` に **`[activated enabled]`** と表示される場合、通常はその extension が実際に稼働中であることを示す最も迅速な指標です。**macOS 15 Sequoia 以降**では、MDM によって特定の security extension を **UI から削除できない状態**にすることもできるため、「System Settings から disable できる」という前提はもはや安全ではありません。内部の仕組みについては、[macOS System Extensions](mac-os-architecture/macos-system-extensions.md) を参照してください。

## defenders が利用できる最近の native telemetry

最近の macOS リリースでは、これまで検出が煩雑だった、ユーザー主導の bypass の一部について、blue team にとってより多くの telemetry が生成されるようになりました。

- **macOS 15+**: Endpoint Security clients は **`gatekeeper_user_override`** events を受信できるため、手動での Gatekeeper bypass を centrally log できます。
- **Current macOS Endpoint Security tooling** は **XProtect malware detection** events も ingest できるため、Apple が endpoint 上ですでに検出した内容を確認しやすくなります。
- **macOS 15.4+**: Endpoint Security に **`tcc_modify`** が追加され、TCC debug logs を scrape する代わりに、defenders がサポートされた方法で **TCC grants/revokes** を monitor できるようになりました。<sup>[[1]](#references)</sup>
```bash
# Gatekeeper user overrides
sudo eslogger gatekeeper_user_override

# XProtect detections
sudo eslogger xp_malware_detected

# macOS 15.4+
sudo eslogger tcc_modify
```
これはdefenderとself-assessmentを行うred teamersの双方に有用です。targetに成熟したESベースのstackがある場合、**user-approvedのGatekeeper / TCC bypass chainsは、以前よりもはるかに可視化されやすくなっている可能性があります**。これらのprotectionの背景については、[Gatekeeper / Quarantine / XProtect](macos-security-protections/macos-gatekeeper.md)および[TCC](macos-security-protections/macos-tcc/README.md)を参照してください。

## 参考資料


- [1] [Objective-See - TCCing is Believing! Apple finally adds TCC events to Endpoint Security!](https://objective-see.org/blog/blog_0x7F.html)
- [2] [Red Canary - Introducing: Mac Monitor](https://redcanary.com/blog/threat-detection/mac-monitor/)

{{#include ../../banners/hacktricks-training.md}}
