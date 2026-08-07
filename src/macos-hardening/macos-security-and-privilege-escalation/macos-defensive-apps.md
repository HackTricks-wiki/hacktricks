# Aplikacje defensywne macOS

{{#include ../../banners/hacktricks-training.md}}

## Firewalle

- [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html): Monitoruje każde połączenie nawiązywane przez każdy proces. W zależności od trybu (ciche zezwalanie na połączenia, ciche odrzucanie połączeń i alertowanie) będzie **wyświetlać alert** za każdym razem, gdy zostanie nawiązane nowe połączenie. Ma również bardzo dobry interfejs GUI do przeglądania wszystkich tych informacji.
- [**LuLu**](https://objective-see.org/products/lulu.html): Firewall firmy Objective-See. Jest to podstawowy firewall, który będzie alertować o podejrzanych połączeniach (ma GUI, ale nie jest ono tak rozbudowane jak w Little Snitch).

## Wykrywanie persistence

- [**KnockKnock**](https://objective-see.org/products/knockknock.html): Aplikacja firmy Objective-See, która przeszukuje kilka lokalizacji, w których **malware może utrzymywać persistence** (jest to narzędzie jednorazowego użycia, a nie usługa monitorująca).
- [**BlockBlock**](https://objective-see.org/products/blockblock.html): Podobnie jak KnockKnock, monitoruje procesy generujące persistence.

## Wykrywanie keyloggerów

- [**ReiKey**](https://objective-see.org/products/reikey.html): Aplikacja firmy Objective-See służąca do wykrywania **keyloggerów**, które instalują klawiaturowe „event taps”.

## Telemetria endpointów / kontrola wykonywania

- [**Santa**](https://santa.dev/): System autoryzacji plików binarnych i monitorowania dla macOS. Używa klienta **Endpoint Security** do autoryzowania zdarzeń **`exec`** przed uruchomieniem kodu, dlatego jest często stosowany we flotach enterprise skoncentrowanych na **allowlisting/denylisting**, zamiast wyłącznie na wykrywaniu po wykonaniu.
- [**Mac Monitor**](https://github.com/redcanaryco/mac-monitor): Narzędzie do dynamicznej analizy macOS podobne do Procmon. Pobiera **telemetrię Endpoint Security** (zdarzenia dotyczące procesów, plików, komunikacji międzyprocesowej, logowania oraz XProtect) i pomaga zrozumieć, co faktycznie może obserwować dojrzały sensor oparty na ES.<sup>[[2]](#references)</sup>
- [**ProcessMonitor / FileMonitor / DNSMonitor**](https://objective-see.org/products/utilities.html): Lekkie narzędzia Objective-See do zbierania telemetrii **procesów**, **plików** i **DNS**. We współczesnym macOS wymagają dodatkowych uprawnień, takich jak **root**, **Terminal Full Disk Access** lub zatwierdzenia **System/Network Extension**. Więcej pomysłów dotyczących instrumentacji znajdziesz na [tej stronie poświęconej inspekcji, debugowaniu i fuzzingowi aplikacji macOS](macos-apps-inspecting-debugging-and-fuzzing/README.md).

## Szybki triage narzędzi defensywnych

Większość współczesnych produktów bezpieczeństwa dla macOS działa jako kombinacja **System Extensions / klientów Endpoint Security**, **agentów/daemonów launchd** oraz aplikacji z uprawnieniem **Full Disk Access**. Szybka lista kontrolna operatora:
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
Jeśli `systemextensionsctl list` pokazuje sensor jako **`[activated enabled]`**, jest to zwykle najszybszy wskaźnik, że rozszerzenie faktycznie działa. W **macOS 15 Sequoia i nowszych** MDM może również oznaczyć określone rozszerzenia bezpieczeństwa jako **niemożliwe do usunięcia z UI**, więc założenie, że można je „wyłączyć w Ustawieniach systemowych”, nie jest już bezpieczne. Szczegóły wewnętrzne znajdziesz tutaj: [macOS System Extensions](mac-os-architecture/macos-system-extensions.md).

## Najnowsza natywna telemetryka dostępna dla defenderów

Najnowsze wydania macOS sprawiły, że niektóre wcześniej trudne do wykrycia bypasses wykonywane przez użytkowników generują znacznie więcej sygnałów dla blue teams:

- **macOS 15+**: klienci Endpoint Security mogą odbierać zdarzenia **`gatekeeper_user_override`**, dzięki czemu ręczne bypasses Gatekeepera mogą być centralnie rejestrowane.
- **Aktualne narzędzia Endpoint Security dla macOS** mogą również pobierać zdarzenia **wykrycia malware przez XProtect**, co ułatwia potwierdzenie, co Apple już wykryło na endpoincie.
- **macOS 15.4+**: Endpoint Security dodaje **`tcc_modify`**, zapewniając wreszcie defenderom wspierany sposób monitorowania **nadawania i odbierania uprawnień TCC** zamiast pobierania danych z logów debugowania TCC.<sup>[[1]](#references)</sup>
```bash
# Gatekeeper user overrides
sudo eslogger gatekeeper_user_override

# XProtect detections
sudo eslogger xp_malware_detected

# macOS 15.4+
sudo eslogger tcc_modify
```
Jest to przydatne zarówno dla obrońców, jak i dla red teamerów przeprowadzających samoocenę: jeśli cel ma dojrzały stack oparty na ES, **user-approved Gatekeeper / TCC bypass chains mogą być znacznie bardziej widoczne niż wcześniej**. Informacje kontekstowe dotyczące tych zabezpieczeń znajdziesz tutaj: [Gatekeeper / Quarantine / XProtect](macos-security-protections/macos-gatekeeper.md) oraz [TCC](macos-security-protections/macos-tcc/README.md).

## Referencje


- [1] [Objective-See - TCCing is Believing! Apple finally adds TCC events to Endpoint Security!](https://objective-see.org/blog/blog_0x7F.html)
- [2] [Red Canary - Introducing: Mac Monitor](https://redcanary.com/blog/threat-detection/mac-monitor/)

{{#include ../../banners/hacktricks-training.md}}
