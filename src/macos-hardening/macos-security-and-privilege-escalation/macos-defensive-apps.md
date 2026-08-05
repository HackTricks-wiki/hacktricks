# Aplikacje defensywne macOS

{{#include ../../banners/hacktricks-training.md}}

## Firewalle

- [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html): Monitoruje każde połączenie nawiązywane przez każdy proces. W zależności od trybu (zezwalanie na połączenia w trybie cichym, odrzucanie połączeń w trybie cichym i wyświetlanie alertów) będzie **wyświetlać alert** za każdym razem, gdy zostanie nawiązane nowe połączenie. Ma również bardzo przyjemny GUI do przeglądania wszystkich tych informacji.
- [**LuLu**](https://objective-see.org/products/lulu.html): Firewall od Objective-See. Jest to podstawowy firewall, który będzie wyświetlać alerty dotyczące podejrzanych połączeń (ma GUI, ale nie jest ono tak dopracowane jak w Little Snitch).

## Wykrywanie persistence

- [**KnockKnock**](https://objective-see.org/products/knockknock.html): Aplikacja Objective-See, która przeszukuje kilka lokalizacji, w których **malware może utrzymywać persistence** (jest to narzędzie jednorazowe, a nie usługa monitorująca).
- [**BlockBlock**](https://objective-see.org/products/blockblock.html): Podobnie jak KnockKnock, monitoruje procesy generujące persistence.

## Wykrywanie keyloggerów

- [**ReiKey**](https://objective-see.org/products/reikey.html): Aplikacja Objective-See służąca do wyszukiwania **keyloggerów**, które instalują keyboard „event taps”

## Telemetria endpointów / kontrola wykonywania

- [**Santa**](https://santa.dev/): System binary authorization i monitorowania dla macOS. Wykorzystuje klienta **Endpoint Security** do autoryzowania zdarzeń **`exec`** przed uruchomieniem kodu, dlatego jest często używany we flotach enterprise skupionych na **allowlisting/denylisting**, zamiast wyłącznie na detekcji post-execution.
- [**Mac Monitor**](https://github.com/redcanaryco/mac-monitor): Narzędzie do dynamicznej analizy macOS podobne do Procmon. Pobiera **telemetrię Endpoint Security** (zdarzenia związane z procesami, plikami, komunikacją międzyprocesową, logowaniem i XProtect) i jest przydatne do zrozumienia, co faktycznie może obserwować dojrzały sensor oparty na ES.<sup>[[2]](#references)</sup>
- [**ProcessMonitor / FileMonitor / DNSMonitor**](https://objective-see.org/products/utilities.html): Lekkie narzędzia Objective-See do zbierania telemetrii **procesów**, **plików** i **DNS**. We współczesnym macOS wymagają dodatkowych uprawnień, takich jak **root**, **Terminal Full Disk Access** lub zatwierdzenie **System/Network Extension**. Więcej pomysłów dotyczących instrumentacji znajdziesz na [tej stronie poświęconej inspekcji/debugowaniu aplikacji macOS](macos-apps-inspecting-debugging-and-fuzzing/README.md).

## Szybki triage narzędzi defensywnych

Większość współczesnych produktów bezpieczeństwa dla macOS działa jako pewna kombinacja **System Extensions / klientów Endpoint Security**, **agentów/daemonów launchd** oraz aplikacji z uprawnieniem **Full Disk Access**. Szybka checklista operatora:
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
Jeśli `systemextensionsctl list` pokazuje sensor jako **`[activated enabled]`**, jest to zwykle najszybszy wskaźnik, że extension faktycznie działa. W **macOS 15 Sequoia i nowszych** MDM może również oznaczać konkretne security extensions jako **niemożliwe do usunięcia z interfejsu użytkownika**, więc założenie, że można je „wyłączyć w Ustawieniach systemowych”, nie jest już bezpieczne. Informacje na temat mechanizmów wewnętrznych znajdziesz w [macOS System Extensions](mac-os-architecture/macos-system-extensions.md).

## Najnowsza natywna telemetria dostępna dla obrońców

Najnowsze wydania macOS sprawiły, że niektóre wcześniej trudne do wykrycia obejścia inicjowane przez użytkownika generują znacznie więcej sygnałów dla blue teams:

- **macOS 15+**: klienci Endpoint Security mogą odbierać zdarzenia **`gatekeeper_user_override`**, dzięki czemu ręczne obejścia Gatekeeper mogą być rejestrowane centralnie.
- **Obecne narzędzia Endpoint Security dla macOS** mogą również pobierać zdarzenia wykrycia malware przez **XProtect**, co ułatwia potwierdzenie, co Apple wykryło już na endpoint.
- **macOS 15.4+**: Endpoint Security dodaje **`tcc_modify`**, zapewniając wreszcie obrońcom obsługiwany sposób monitorowania **przyznawania i odbierania uprawnień TCC**, zamiast odczytywania logów debugowania TCC.<sup>[[1]](#references)</sup>
```bash
# Gatekeeper user overrides
sudo eslogger gatekeeper_user_override

# XProtect detections
sudo eslogger xp_malware_detected

# macOS 15.4+
sudo eslogger tcc_modify
```
Jest to przydatne zarówno dla defenderów, jak i red teamers przeprowadzających samoocenę: jeśli cel ma dojrzały stack oparty na ES, **łańcuchy obejścia Gatekeeper / TCC wymagające akceptacji użytkownika mogą być znacznie bardziej widoczne niż wcześniej**. Informacje kontekstowe dotyczące tych zabezpieczeń znajdziesz tutaj: [Gatekeeper / Quarantine / XProtect](macos-security-protections/macos-gatekeeper.md) oraz [TCC](macos-security-protections/macos-tcc/README.md).

## Referencje

- [1] [Objective-See - TCCing is Believing! Apple finally adds TCC events to Endpoint Security!](https://objective-see.org/blog/blog_0x7F.html)
- [2] [Red Canary - Introducing: Mac Monitor](https://redcanary.com/blog/threat-detection/mac-monitor/)

{{#include ../../banners/hacktricks-training.md}}
