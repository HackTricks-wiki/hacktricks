# macOS Defensive Apps

{{#include ../../banners/hacktricks-training.md}}

## Firewalls

- [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html): Będzie monitorować każde połączenie wykonywane przez każdy proces. W zależności od trybu (silent allow connections, silent deny connection and alert) **wyświetli alert** za każdym razem, gdy zostanie nawiązane nowe połączenie. Ma też bardzo ładny GUI do przeglądania tych wszystkich informacji.
- [**LuLu**](https://objective-see.org/products/lulu.html): Firewall od Objective-See. To podstawowy firewall, który będzie ostrzegał o podejrzanych połączeniach (ma GUI, ale nie jest tak efektowne jak to w Little Snitch).

## Persistence detection

- [**KnockKnock**](https://objective-see.org/products/knockknock.html): Aplikacja od Objective-See, która przeszuka kilka lokalizacji, gdzie **malware could be persisting** (to narzędzie jednorazowe, nie usługa monitorująca).
- [**BlockBlock**](https://objective-see.org/products/blockblock.html): Jak KnockKnock, ale monitoruje procesy, które generują persistence.

## Keyloggers detection

- [**ReiKey**](https://objective-see.org/products/reikey.html): Aplikacja od Objective-See do znajdowania **keyloggers**, które instalują keyboard "event taps"

## Endpoint telemetry / execution control

- [**Santa**](https://santa.dev/): System autoryzacji binariów i monitorowania dla macOS. Używa klienta **Endpoint Security** do autoryzacji zdarzeń **`exec`** przed uruchomieniem kodu, dlatego jest często stosowany w środowiskach enterprise skupionych na **allowlisting/denylisting** zamiast wyłącznie na wykrywaniu po wykonaniu.
- [**Mac Monitor**](https://github.com/redcanaryco/mac-monitor): Narzędzie do dynamicznej analizy macOS podobne do Procmon. Pobiera telemetry **Endpoint Security** (procesy, pliki, interprocess, logowania oraz zdarzenia związane z XProtect) i jest przydatne do zrozumienia, co naprawdę może obserwować dojrzały sensor oparty na ES.
- [**ProcessMonitor / FileMonitor / DNSMonitor**](https://objective-see.org/products/utilities.html): Lekkie narzędzia Objective-See do telemetrii **process**, **file** i **DNS**. Na nowoczesnym macOS mają dodatkowe wymagania, takie jak **root**, **Terminal Full Disk Access** lub zatwierdzenie **System/Network Extension**. Po więcej pomysłów dotyczących instrumentacji sprawdź [tę inną stronę o inspectowaniu/debugowaniu i fuzzingu aplikacji macOS](macos-apps-inspecting-debugging-and-fuzzing/README.md).

## Quick triage of defensive tooling

Większość nowoczesnych produktów bezpieczeństwa macOS działa jako jakaś kombinacja **System Extensions / Endpoint Security clients**, **launchd agents/daemons** oraz aplikacji z **Full Disk Access**. Szybka checklista operatora:
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
Jeśli `systemextensionsctl list` pokazuje sensor jako **`[activated enabled]`**, to zwykle jest to najszybszy wskaźnik, że extension faktycznie działa. W **macOS 15 Sequoia i nowszych** MDM może też oznaczać określone security extensions jako **nieusuwalne z UI**, więc „wyłącz to w System Settings” nie jest już bezpiecznym założeniem. Szczegóły internals: [macOS System Extensions](mac-os-architecture/macos-system-extensions.md).

## Recent native telemetry defenders can consume

Najnowsze wydania macOS sprawiły, że kilka wcześniej irytujących do wykrycia, wykonywanych przez usera bypasses stało się dużo głośniejszych dla blue teams:

- **macOS 15+**: Endpoint Security clients mogą otrzymywać zdarzenia **`gatekeeper_user_override`**, więc ręczne bypasses Gatekeeper mogą być centralnie logowane.
- **Current macOS Endpoint Security tooling** może też ingestować zdarzenia **XProtect malware detection**, co ułatwia potwierdzenie tego, co Apple już wykryło na endpoint.
- **macOS 15.4+**: Endpoint Security dodaje **`tcc_modify`**, co w końcu daje defenderom wspierany sposób monitorowania **TCC grants/revokes** zamiast zgrywania debug logs TCC.
```bash
# Gatekeeper user overrides
sudo eslogger gatekeeper_user_override

# XProtect detections
sudo eslogger xp_malware_detected

# macOS 15.4+
sudo eslogger tcc_modify
```
To jest przydatne zarówno dla defenderów, jak i dla red teamerów wykonujących self-assessment: jeśli target ma dojrzały stack oparty na ES, **łańcuchy bypass Gatekeeper / TCC zatwierdzone przez usera mogą być znacznie bardziej widoczne niż kiedyś**. Tło dotyczące tych ochron znajdziesz w [Gatekeeper / Quarantine / XProtect](macos-security-protections/macos-gatekeeper.md) oraz [TCC](macos-security-protections/macos-tcc/README.md).

## References

- [**Objective-See - TCCing is Believing! Apple finally adds TCC events to Endpoint Security!**](https://objective-see.org/blog/blog_0x7F.html)
- [**Red Canary - Introducing: Mac Monitor**](https://redcanary.com/blog/threat-detection/mac-monitor/)

{{#include ../../banners/hacktricks-training.md}}
