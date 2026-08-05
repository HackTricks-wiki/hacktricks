# Aplikacje defensywne macOS

{{#include ../../banners/hacktricks-training.md}}

## Firewalle

- [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html): Monitoruje każde połączenie nawiązywane przez każdy proces. W zależności od trybu (ciche zezwalanie na połączenia, ciche odrzucanie połączeń i alerty) będzie **wyświetlać alert** za każdym razem, gdy zostanie nawiązane nowe połączenie. Ma również bardzo wygodny GUI do przeglądania wszystkich tych informacji.
- [**LuLu**](https://objective-see.org/products/lulu.html): Firewall firmy Objective-See. Jest to podstawowy firewall, który będzie ostrzegać o podejrzanych połączeniach (ma GUI, ale nie jest on tak dopracowany jak w Little Snitch).

## Wykrywanie Persistence

- [**KnockKnock**](https://objective-see.org/products/knockknock.html): Aplikacja Objective-See, która przeszukuje kilka lokalizacji, w których **malware może utrzymywać persistence** (jest to narzędzie jednorazowe, a nie usługa monitorująca).
- [**BlockBlock**](https://objective-see.org/products/blockblock.html): Podobnie jak KnockKnock, monitoruje procesy generujące persistence.

## Wykrywanie Keyloggerów

- [**ReiKey**](https://objective-see.org/products/reikey.html): Aplikacja Objective-See do znajdowania **keyloggerów**, które instalują keyboard "event taps"

## Telemetria Endpoint / kontrola wykonywania

- [**Santa**](https://santa.dev/): System autoryzacji i monitorowania plików binarnych dla macOS. Wykorzystuje klienta **Endpoint Security** do autoryzowania zdarzeń **`exec`** przed uruchomieniem kodu, dlatego jest często używany we flotach enterprise skupionych na **allowlisting/denylisting**, a nie wyłącznie na wykrywaniu po wykonaniu.
- [**Mac Monitor**](https://github.com/redcanaryco/mac-monitor): Narzędzie do dynamicznej analizy macOS podobne do Procmon. Pobiera **telemetrię Endpoint Security** (zdarzenia dotyczące procesów, plików, komunikacji międzyprocesowej, logowania i XProtect) i pomaga zrozumieć, co rzeczywiście może obserwować dojrzały sensor oparty na ES.<sup>[2]</sup>
- [**ProcessMonitor / FileMonitor / DNSMonitor**](https://objective-see.org/products/utilities.html): Lekkie narzędzia Objective-See do zbierania telemetrii **procesów**, **plików** i **DNS**. We współczesnym macOS wymagają dodatkowych uprawnień, takich jak **root**, **Terminal Full Disk Access** lub zatwierdzenie **System/Network Extension**. Więcej pomysłów dotyczących instrumentacji znajdziesz na [tej innej stronie o inspekcji/debugowaniu aplikacji macOS](macos-apps-inspecting-debugging-and-fuzzing/README.md).

## Szybki triage narzędzi defensywnych

Większość współczesnych produktów bezpieczeństwa dla macOS działa jako połączenie **System Extensions / klientów Endpoint Security**, **agentów/daemonów launchd** oraz aplikacji z uprawnieniem **Full Disk Access**. Szybka checklista operatora:
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
Jeśli `systemextensionsctl list` pokazuje czujnik jako **`[activated enabled]`**, zwykle jest to najszybszy wskaźnik, że rozszerzenie faktycznie działa. W **macOS 15 Sequoia i nowszych** MDM może również oznaczać określone rozszerzenia zabezpieczeń jako **niemożliwe do usunięcia z interfejsu użytkownika**, dlatego założenie, że można je „wyłączyć w Ustawieniach systemowych”, nie jest już bezpieczne. Informacje na temat mechanizmów wewnętrznych znajdziesz w [macOS System Extensions](mac-os-architecture/macos-system-extensions.md).

## Nowsza natywna telemetria dostępna dla obrońców

Nowsze wydania macOS sprawiły, że niektóre wcześniej trudne do wykrycia obejścia inicjowane przez użytkownika generują znacznie więcej szumu dla zespołów blue team:

- **macOS 15+**: klienci Endpoint Security mogą odbierać zdarzenia **`gatekeeper_user_override`**, dzięki czemu ręczne obejścia Gatekeeper mogą być centralnie rejestrowane.
- **Aktualne narzędzia Endpoint Security dla macOS** mogą również pobierać zdarzenia wykrycia malware przez **XProtect**, co ułatwia potwierdzenie, co Apple już wykryło na endpointcie.
- **macOS 15.4+**: Endpoint Security dodaje **`tcc_modify`**, zapewniając wreszcie obrońcom obsługiwany sposób monitorowania **nadań i odbierania uprawnień TCC**, zamiast analizowania logów debugowania TCC.<sup>[1]</sup>
```bash
# Gatekeeper user overrides
sudo eslogger gatekeeper_user_override

# XProtect detections
sudo eslogger xp_malware_detected

# macOS 15.4+
sudo eslogger tcc_modify
```
Jest to przydatne zarówno dla defenderów, jak i red teamerów przeprowadzających self-assessment: jeśli cel ma dojrzały stack oparty na ES, **łańcuchy bypassów Gatekeeper / TCC zatwierdzane przez użytkownika mogą być znacznie bardziej widoczne niż wcześniej**. Informacje ogólne na temat tych zabezpieczeń znajdziesz w sekcjach [Gatekeeper / Quarantine / XProtect](macos-security-protections/macos-gatekeeper.md) i [TCC](macos-security-protections/macos-tcc/README.md).

## Odnośniki

- [1] [Objective-See - TCCing is Believing! Apple finally adds TCC events to Endpoint Security!](https://objective-see.org/blog/blog_0x7F.html)
- [2] [Red Canary - Introducing: Mac Monitor](https://redcanary.com/blog/threat-detection/mac-monitor/)

{{#include ../../banners/hacktricks-training.md}}
