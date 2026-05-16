# macOS Defensive Apps

{{#include ../../banners/hacktricks-training.md}}

## Firewalls

- [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html): 各プロセスが行うすべての接続を監視する。モード（silent allow connections、silent deny connection、alert）に応じて、新しい接続が確立されるたびに**アラートを表示する**。また、これらの情報を確認するための非常に使いやすいGUIもある。
- [**LuLu**](https://objective-see.org/products/lulu.html): Objective-See の firewall。これは基本的な firewall で、疑わしい接続があるとアラートを出す（GUI はあるが Little Snitch ほど洗練されていない）。

## Persistence detection

- [**KnockKnock**](https://objective-see.org/products/knockknock.html): **malware could be persisting** 可能性のある複数の場所を検索する Objective-See のアプリケーション（単発実行のツールで、監視サービスではない）。
- [**BlockBlock**](https://objective-see.org/products/blockblock.html): Persistence を生成するプロセスを監視する点で KnockKnock に似ている。

## Keyloggers detection

- [**ReiKey**](https://objective-see.org/products/reikey.html): キーボードの "event taps" をインストールする **keyloggers** を見つけるための Objective-See のアプリケーション

## Endpoint telemetry / execution control

- [**Santa**](https://santa.dev/): macOS 向けの Binary authorization と監視システム。コードが実行される前に **`exec`** イベントを認可するために **Endpoint Security** クライアントを使用するので、事後検知だけでなく **allowlisting/denylisting** に重点を置く enterprise fleet で一般的である。
- [**Mac Monitor**](https://github.com/redcanaryco/mac-monitor): Procmon のような macOS の動的解析ツール。**Endpoint Security telemetry**（process、file、interprocess、login、XProtect 関連イベント）を取り込み、成熟した ES ベースの sensor が実際に何を観測できるかを理解するのに役立つ。
- [**ProcessMonitor / FileMonitor / DNSMonitor**](https://objective-see.org/products/utilities.html): **process**、**file**、**DNS** telemetry のための軽量な Objective-See ツール。最新の macOS では、**root**、**Terminal Full Disk Access**、または **System/Network Extension approval** などの追加要件がある。より多くの instrumentation のアイデアについては、[macOS app inspection/debugging and fuzzing に関する別ページ](macos-apps-inspecting-debugging-and-fuzzing/README.md) を参照。

## Quick triage of defensive tooling

最新の macOS security product の多くは、**System Extensions / Endpoint Security clients**、**launchd agents/daemons**、および **Full Disk Access** を持つアプリケーションの組み合わせとして動作する。簡単な operator checklist:
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
`systemextensionsctl list` で sensor が **`[activated enabled]`** と表示されている場合、それは通常、その extension が実際に live であることを示す最も速い指標です。**macOS 15 Sequoia 以降**では、MDM が特定の security extensions を **UI から削除不可** にすることもできるため、「System Settings から無効化すればよい」という前提はもはや安全ではありません。内部仕様については、[macOS System Extensions](mac-os-architecture/macos-system-extensions.md) を参照してください。

## Recent native telemetry defenders can consume

最近の macOS releases では、これまで検出しづらかった user-driven bypasses の一部が、blue teams にとってかなり noisy になりました。

- **macOS 15+**: Endpoint Security clients は **`gatekeeper_user_override`** events を受信できるため、手動の Gatekeeper bypasses を中央で記録できます。
- **Current macOS Endpoint Security tooling** は **XProtect malware detection** events も取り込めるため、endpoint 上で Apple がすでに検出した内容を確認しやすくなります。
- **macOS 15.4+**: Endpoint Security に **`tcc_modify`** が追加され、これにより、TCC debug logs を scraping する代わりに、defenders が **TCC grants/revokes** を監視するためのサポート済みの方法がようやく提供されました。
```bash
# Gatekeeper user overrides
sudo eslogger gatekeeper_user_override

# XProtect detections
sudo eslogger xp_malware_detected

# macOS 15.4+
sudo eslogger tcc_modify
```
これは、防御側にとっても自己評価を行う red teamer にとっても有用です。対象に成熟した ES-based stack がある場合、**user-approved Gatekeeper / TCC bypass chains は以前よりかなり見えやすくなっている可能性があります**。これらの保護についての背景は、[Gatekeeper / Quarantine / XProtect](macos-security-protections/macos-gatekeeper.md) と [TCC](macos-security-protections/macos-tcc/README.md) を参照してください。

## References

- [**Objective-See - TCCing is Believing! Apple finally adds TCC events to Endpoint Security!**](https://objective-see.org/blog/blog_0x7F.html)
- [**Red Canary - Introducing: Mac Monitor**](https://redcanary.com/blog/threat-detection/mac-monitor/)

{{#include ../../banners/hacktricks-training.md}}
