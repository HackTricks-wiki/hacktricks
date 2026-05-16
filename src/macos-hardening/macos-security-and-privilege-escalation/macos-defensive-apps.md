# macOS Defensive Apps

{{#include ../../banners/hacktricks-training.md}}

## Firewalls

- [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html): 각 프로세스가 생성하는 모든 연결을 모니터링합니다. 모드에 따라(연결을 조용히 허용, 연결을 조용히 거부 및 알림) 새로운 연결이 설정될 때마다 **알림을 표시**합니다. 또한 이 모든 정보를 보기 위한 매우 좋은 GUI가 있습니다.
- [**LuLu**](https://objective-see.org/products/lulu.html): Objective-See firewall. 의심스러운 연결에 대해 경고하는 기본적인 firewall입니다(GUI는 있지만 Little Snitch만큼 화려하지는 않습니다).

## Persistence detection

- [**KnockKnock**](https://objective-see.org/products/knockknock.html): **malware could be persisting** 할 수 있는 여러 위치를 검색하는 Objective-See 애플리케이션입니다(한 번 실행하는 도구이며, 모니터링 서비스가 아닙니다).
- [**BlockBlock**](https://objective-see.org/products/blockblock.html): persistence를 생성하는 프로세스를 모니터링하는 방식으로 KnockKnock와 비슷합니다.

## Keyloggers detection

- [**ReiKey**](https://objective-see.org/products/reikey.html): 키보드 "event taps"를 설치하는 **keyloggers**를 찾는 Objective-See 애플리케이션입니다.

## Endpoint telemetry / execution control

- [**Santa**](https://santa.dev/): macOS용 binary authorization 및 모니터링 시스템입니다. 코드가 실행되기 전에 **`exec`** 이벤트를 승인하기 위해 **Endpoint Security** 클라이언트를 사용하므로, 실행 후 탐지뿐 아니라 **allowlisting/denylisting**에 중점을 둔 enterprise fleets에서 흔히 사용됩니다.
- [**Mac Monitor**](https://github.com/redcanaryco/mac-monitor): Procmon 같은 macOS 동적 분석 도구입니다. **Endpoint Security telemetry**(process, file, interprocess, login, 그리고 XProtect 관련 이벤트)를 수집하며, 성숙한 ES 기반 sensor가 실제로 무엇을 관찰할 수 있는지 이해하는 데 유용합니다.
- [**ProcessMonitor / FileMonitor / DNSMonitor**](https://objective-see.org/products/utilities.html): **process**, **file**, **DNS** telemetry를 위한 가벼운 Objective-See 도구입니다. 최신 macOS에서는 **root**, **Terminal Full Disk Access**, 또는 **System/Network Extension approval** 같은 추가 조건이 필요합니다. 더 많은 instrumentation 아이디어는 [macos-apps-inspecting-debugging-and-fuzzing/README.md](macos-apps-inspecting-debugging-and-fuzzing/README.md)의 macOS app inspection/debugging 관련 다른 페이지를 참고하세요.

## Quick triage of defensive tooling

대부분의 최신 macOS security products는 **System Extensions / Endpoint Security clients**, **launchd agents/daemons**, 그리고 **Full Disk Access**가 있는 applications의 조합으로 실행됩니다. 빠른 operator checklist:
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
If `systemextensionsctl list` shows a sensor as **`[activated enabled]`**, it is usually the fastest indicator that the extension is actually live. On **macOS 15 Sequoia and later**, MDM can also mark specific security extensions as **non-removable from the UI**, so "disable it from System Settings" is no longer a safe assumption. For internals, see [macOS System Extensions](mac-os-architecture/macos-system-extensions.md).

## Recent native telemetry defenders can consume

Recent macOS releases made some previously annoying-to-detect user-driven bypasses much noisier for blue teams:

- **macOS 15+**: Endpoint Security clients can receive **`gatekeeper_user_override`** events, so manual Gatekeeper bypasses can be centrally logged.
- **Current macOS Endpoint Security tooling** can also ingest **XProtect malware detection** events, making it easier to confirm what Apple already detected on the endpoint.
- **macOS 15.4+**: Endpoint Security adds **`tcc_modify`**, which finally gives defenders a supported way to monitor **TCC grants/revokes** instead of scraping TCC debug logs.
```bash
# Gatekeeper user overrides
sudo eslogger gatekeeper_user_override

# XProtect detections
sudo eslogger xp_malware_detected

# macOS 15.4+
sudo eslogger tcc_modify
```
이는 수비자와 self-assessment를 수행하는 red teamer 모두에게 유용합니다. 대상이 성숙한 ES-based stack을 갖추고 있다면, **user-approved Gatekeeper / TCC bypass chains는 예전보다 훨씬 더 잘 보일 수 있습니다**. 이러한 보호 기능에 대한 배경은 [Gatekeeper / Quarantine / XProtect](macos-security-protections/macos-gatekeeper.md)와 [TCC](macos-security-protections/macos-tcc/README.md)를 참조하세요.

## References

- [**Objective-See - TCCing is Believing! Apple finally adds TCC events to Endpoint Security!**](https://objective-see.org/blog/blog_0x7F.html)
- [**Red Canary - Introducing: Mac Monitor**](https://redcanary.com/blog/threat-detection/mac-monitor/)

{{#include ../../banners/hacktricks-training.md}}
