# macOS 防御用アプリ

{{#include ../../banners/hacktricks-training.md}}

## Firewalls

- [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html): 各プロセスによって確立されたすべての接続を監視します。モード（接続をサイレントに許可、接続をサイレントに拒否して警告）に応じて、新しい接続が確立されるたびに**アラートを表示**します。これらの情報をすべて確認できる非常に優れた GUI も備えています。
- [**LuLu**](https://objective-see.org/products/lulu.html): Objective-See の firewall です。疑わしい接続を警告する基本的な firewall です（GUI を備えていますが、Little Snitch ほど洗練されていません）。

## Persistence の検出

- [**KnockKnock**](https://objective-see.org/products/knockknock.html): **malware が persistence する可能性のある**複数の場所を検索する Objective-See のアプリケーションです（監視サービスではなく、one-shot tool です）。
- [**BlockBlock**](https://objective-see.org/products/blockblock.html): persistence を生成するプロセスを監視する、KnockKnock に似たツールです。

## Keyloggers の検出

- [**ReiKey**](https://objective-see.org/products/reikey.html): keyboard の「event taps」をインストールする **keyloggers** を検出する Objective-See のアプリケーションです。

## Endpoint telemetry / execution control

- [**Santa**](https://santa.dev/): macOS 用の binary authorization および monitoring system です。コードが実行される前に **Endpoint Security** client を使用して **`exec`** events を承認するため、実行後の検出だけでなく、**allowlisting/denylisting** を重視する enterprise fleet で一般的に使用されています。
- [**Mac Monitor**](https://github.com/redcanaryco/mac-monitor): Procmon に似た macOS の dynamic analysis tool です。**Endpoint Security telemetry**（process、file、interprocess、login、および XProtect 関連の events）を取り込み、成熟した ES ベースの sensor が実際に何を監視できるかを理解するのに役立ちます。<sup>[[2]](#references)</sup>
- [**ProcessMonitor / FileMonitor / DNSMonitor**](https://objective-see.org/products/utilities.html): **process**、**file**、**DNS** telemetry 用の軽量な Objective-See tools です。modern macOS では、**root**、**Terminal Full Disk Access**、または **System/Network Extension approval** などの追加の前提条件があります。instrumentation のアイデアについては、[macOS app inspection/debugging に関するこちらの別ページ](macos-apps-inspecting-debugging-and-fuzzing/README.md)を確認してください。

## Defensive tooling の Quick triage

最新の macOS security products の大半は、**System Extensions / Endpoint Security clients**、**launchd agents/daemons**、および **Full Disk Access** を持つ applications の組み合わせとして動作します。operator 向けの簡易 checklist は次のとおりです。
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
`systemextensionsctl list` に **`[activated enabled]`** と表示される場合、通常は extension が実際に稼働していることを示す最も迅速な指標です。**macOS 15 Sequoia 以降**では、MDM によって特定の security extension を **UI から削除できない状態**にすることもできるため、「System Settings から無効化する」という前提はもはや安全ではありません。内部仕様については、[macOS System Extensions](mac-os-architecture/macos-system-extensions.md) を参照してください。

## defenders が利用できる最近の native telemetry

最近の macOS release では、以前は検出が煩雑だった、user-driven な bypass の一部が blue teams にとって大幅に検出しやすくなりました。

- **macOS 15+**: Endpoint Security clients は **`gatekeeper_user_override`** events を受信できるため、手動による Gatekeeper bypass を中央で logging できます。
- **Current macOS Endpoint Security tooling** は **XProtect malware detection** events も ingest できるため、Apple が endpoint 上ですでに検出した内容を確認しやすくなっています。
- **macOS 15.4+**: Endpoint Security に **`tcc_modify`** が追加され、TCC debug logs を scraping する代わりに、defenders がサポートされた方法で **TCC grants/revokes** を監視できるようになりました。<sup>[[1]](#references)</sup>
```bash
# Gatekeeper user overrides
sudo eslogger gatekeeper_user_override

# XProtect detections
sudo eslogger xp_malware_detected

# macOS 15.4+
sudo eslogger tcc_modify
```
これは防御側にも、self-assessmentを行うレッドチーム担当者にも有用です。対象に成熟したESベースのスタックがある場合、**ユーザー承認型のGatekeeper / TCC bypass chainは、以前よりもはるかに検知されやすくなっている可能性があります**。これらの保護機能の背景については、[Gatekeeper / Quarantine / XProtect](macos-security-protections/macos-gatekeeper.md)および[TCC](macos-security-protections/macos-tcc/README.md)を参照してください。

## References

- [1] [Objective-See - TCCing is Believing! Apple finally adds TCC events to Endpoint Security!](https://objective-see.org/blog/blog_0x7F.html)
- [2] [Red Canary - Introducing: Mac Monitor](https://redcanary.com/blog/threat-detection/mac-monitor/)

{{#include ../../banners/hacktricks-training.md}}
