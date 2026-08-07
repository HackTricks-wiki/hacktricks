# macOS 방어용 앱

{{#include ../../banners/hacktricks-training.md}}

## Firewall

- [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html): 각 process가 생성하는 모든 connection을 monitor합니다. mode(silent allow connections, silent deny connection and alert)에 따라 새로운 connection이 수립될 때마다 **alert를 표시**합니다. 또한 이 모든 정보를 확인할 수 있는 매우 편리한 GUI도 제공합니다.
- [**LuLu**](https://objective-see.org/products/lulu.html): Objective-See firewall입니다. 의심스러운 connection을 alert로 알려주는 기본적인 firewall입니다(GUI가 있지만 Little Snitch만큼 화려하지는 않습니다).

## Persistence 탐지

- [**KnockKnock**](https://objective-see.org/products/knockknock.html): **malware가 persistence할 수 있는** 여러 위치를 검색하는 Objective-See application입니다(monitoring service가 아닌 one-shot tool입니다).
- [**BlockBlock**](https://objective-see.org/products/blockblock.html): persistence를 생성하는 process를 monitor하는 KnockKnock과 유사한 tool입니다.

## Keylogger 탐지

- [**ReiKey**](https://objective-see.org/products/reikey.html): keyboard "event taps"를 설치하는 **keylogger**를 찾는 Objective-See application입니다.

## Endpoint telemetry / execution control

- [**Santa**](https://santa.dev/): macOS용 binary authorization 및 monitoring system입니다. **Endpoint Security** client를 사용해 code가 실행되기 전에 **`exec`** event를 authorize하므로, execution 후 탐지만 수행하는 대신 **allowlisting/denylisting**에 중점을 두는 enterprise fleet에서 일반적으로 사용됩니다.
- [**Mac Monitor**](https://github.com/redcanaryco/mac-monitor): Procmon과 유사한 macOS dynamic analysis tool입니다. **Endpoint Security telemetry**(process, file, interprocess, login 및 XProtect 관련 event)를 수집하며, mature한 ES-based sensor가 실제로 무엇을 observe할 수 있는지 이해하는 데 유용합니다.<sup>[[2]](#references)</sup>
- [**ProcessMonitor / FileMonitor / DNSMonitor**](https://objective-see.org/products/utilities.html): **process**, **file**, **DNS** telemetry를 위한 경량 Objective-See tool입니다. 최신 macOS에서는 **root**, **Terminal Full Disk Access**, 또는 **System/Network Extension approval**과 같은 추가 prerequisite가 필요합니다. 더 많은 instrumentation 아이디어는 [macOS app inspection/debugging에 관한 다른 페이지](macos-apps-inspecting-debugging-and-fuzzing/README.md)를 참조하세요.

## Defensive tooling 빠른 triage

대부분의 최신 macOS security product는 **System Extensions / Endpoint Security clients**, **launchd agents/daemons**, 그리고 **Full Disk Access**를 보유한 application의 조합으로 실행됩니다. 빠르게 확인할 수 있는 operator checklist는 다음과 같습니다.
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
`systemextensionsctl list`에 **`[activated enabled]`**로 sensor가 표시되면, 해당 extension이 실제로 활성 상태라는 가장 빠른 지표인 경우가 많습니다. **macOS 15 Sequoia 이상**에서는 MDM이 특정 security extension을 UI에서 **제거 불가**로 표시할 수도 있으므로, "System Settings에서 disable하면 된다"라고 더 이상 안전하게 가정할 수 없습니다. 내부 동작은 [macOS System Extensions](mac-os-architecture/macos-system-extensions.md)을 참조하세요.

## Defenders가 수집할 수 있는 최신 native telemetry

최근 macOS 릴리스에서는 이전에 탐지하기 까다로웠던 일부 사용자 주도 bypass가 blue team에 훨씬 더 많은 telemetry를 생성합니다:

- **macOS 15+**: Endpoint Security client는 **`gatekeeper_user_override`** 이벤트를 수신할 수 있으므로, 수동 Gatekeeper bypass를 중앙에서 logging할 수 있습니다.
- **Current macOS Endpoint Security tooling**은 **XProtect malware detection** 이벤트도 ingest할 수 있으므로, Apple이 endpoint에서 이미 탐지한 항목을 더 쉽게 확인할 수 있습니다.
- **macOS 15.4+**: Endpoint Security에 **`tcc_modify`**가 추가되어, defenders가 TCC debug log를 scraping하는 대신 지원되는 방식으로 **TCC grants/revokes**를 모니터링할 수 있게 되었습니다.<sup>[[1]](#references)</sup>
```bash
# Gatekeeper user overrides
sudo eslogger gatekeeper_user_override

# XProtect detections
sudo eslogger xp_malware_detected

# macOS 15.4+
sudo eslogger tcc_modify
```
이는 defenders와 self-assessment를 수행하는 red teamers 모두에게 유용합니다. 대상에 mature한 ES 기반 stack이 있다면, **user-approved Gatekeeper / TCC bypass chains가 예전보다 훨씬 더 잘 탐지될 수 있습니다**. 이러한 보호 기능에 대한 배경 정보는 [Gatekeeper / Quarantine / XProtect](macos-security-protections/macos-gatekeeper.md) 및 [TCC](macos-security-protections/macos-tcc/README.md)를 참조하세요.

## References


- [1] [Objective-See - TCCing is Believing! Apple finally adds TCC events to Endpoint Security!](https://objective-see.org/blog/blog_0x7F.html)
- [2] [Red Canary - Introducing: Mac Monitor](https://redcanary.com/blog/threat-detection/mac-monitor/)

{{#include ../../banners/hacktricks-training.md}}
