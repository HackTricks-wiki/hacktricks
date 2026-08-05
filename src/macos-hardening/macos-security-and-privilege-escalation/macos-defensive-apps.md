# macOS 防御アプリ

{{#include ../../banners/hacktricks-training.md}}

## Firewall

- [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html): 各プロセスが行うすべての接続を監視します。モード（接続をサイレントに許可、接続をサイレントに拒否して通知）に応じて、新しい接続が確立されるたびに**アラートを表示**します。これらの情報を確認するための非常に使いやすい GUI も備えています。
- [**LuLu**](https://objective-see.org/products/lulu.html): Objective-See の Firewall です。不審な接続を通知する基本的な Firewall です（GUI はありますが、Little Snitch ほど洗練されていません）。

## Persistence の検出

- [**KnockKnock**](https://objective-see.org/products/knockknock.html): **malware が persistence を確立している可能性のある**複数の場所を検索する Objective-See アプリケーションです（監視サービスではなく、1 回限り実行するツールです）。
- [**BlockBlock**](https://objective-see.org/products/blockblock.html): persistence を生成するプロセスを監視する、KnockKnock に似たツールです。

## keyloggers の検出

- [**ReiKey**](https://objective-see.org/products/reikey.html): キーボードの「event taps」をインストールする**keyloggers**を検出する Objective-See アプリケーションです。

## Endpoint telemetry / execution control

- [**Santa**](https://santa.dev/): macOS 用のバイナリ認証および監視システムです。**Endpoint Security** client を使用して、コードが実行される前に **`exec`** イベントを承認するため、実行後の検出だけでなく、**allowlisting/denylisting** を重視する enterprise fleet でよく利用されます。
- [**Mac Monitor**](https://github.com/redcanaryco/mac-monitor): Procmon に似た macOS の動的分析ツールです。**Endpoint Security telemetry**（process、file、interprocess、login、および XProtect 関連のイベント）を取り込み、成熟した ES ベースの sensor が実際に何を観測できるかを把握するのに役立ちます。<sup>[2]</sup>
- [**ProcessMonitor / FileMonitor / DNSMonitor**](https://objective-see.org/products/utilities.html): **process**、**file**、**DNS** telemetry 用の軽量な Objective-See ツールです。最新の macOS では、**root**、**Terminal Full Disk Access**、または **System/Network Extension approval** などの追加の前提条件があります。その他の instrumentation のアイデアについては、[macOS app inspection/debugging に関するこちらの別ページ](macos-apps-inspecting-debugging-and-fuzzing/README.md)を確認してください。

## Defensive tooling の quick triage

最新の macOS security product の多くは、**System Extensions / Endpoint Security clients**、**launchd agents/daemons**、および **Full Disk Access** を持つアプリケーションを組み合わせて動作します。operator 向けの簡単な checklist は次のとおりです。
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
`systemextensionsctl list` に **`[activated enabled]`** と表示される場合、通常はその extension が実際に稼働していることを示す最も早い指標です。**macOS 15 Sequoia 以降**では、MDM によって特定の security extensions を **UI から削除できない**ように設定することもできます。そのため、「システム設定から無効化できる」という前提は、もはや安全とはいえません。内部の仕組みについては、[macOS System Extensions](mac-os-architecture/macos-system-extensions.md) を参照してください。

## Recent native telemetry defenders can consume

最近の macOS リリースでは、以前は検出が煩雑だった、ユーザー主導の bypass の一部が blue teams にとって大幅に検知しやすくなりました。

- **macOS 15+**: Endpoint Security clients は **`gatekeeper_user_override`** events を受信できるため、手動による Gatekeeper bypass を中央でログに記録できます。
- **Current macOS Endpoint Security tooling** は **XProtect malware detection** events も取り込めるため、Apple がすでに endpoint 上で検出した内容を確認しやすくなっています。
- **macOS 15.4+**: Endpoint Security に **`tcc_modify`** が追加され、TCC debug logs を収集する代わりに、defenders が **TCC grants/revokes** を監視するための supported way がようやく提供されました。<sup>[1]</sup>
```bash
# Gatekeeper user overrides
sudo eslogger gatekeeper_user_override

# XProtect detections
sudo eslogger xp_malware_detected

# macOS 15.4+
sudo eslogger tcc_modify
```
これは、防御側と自己評価を行う red teamers の双方にとって有用です。対象に成熟した ES-based stack がある場合、**user-approved Gatekeeper / TCC bypass chains は、以前よりもはるかに可視化されやすくなっている可能性があります**。これらの保護機能の背景については、[Gatekeeper / Quarantine / XProtect](macos-security-protections/macos-gatekeeper.md) および [TCC](macos-security-protections/macos-tcc/README.md) を参照してください。

## 参考資料

- [1] [Objective-See - TCCing is Believing! Apple finally adds TCC events to Endpoint Security!](https://objective-see.org/blog/blog_0x7F.html)
- [2] [Red Canary - Introducing: Mac Monitor](https://redcanary.com/blog/threat-detection/mac-monitor/)

{{#include ../../banners/hacktricks-training.md}}
