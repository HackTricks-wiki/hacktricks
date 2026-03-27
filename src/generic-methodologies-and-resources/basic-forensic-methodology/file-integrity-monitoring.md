# Monitorowanie integralności plików

{{#include ../../banners/hacktricks-training.md}}

## Stan bazowy

Stan bazowy polega na wykonaniu migawki określonych części systemu, aby **porównać ją z przyszłym stanem i uwidocznić zmiany**.

Na przykład możesz obliczyć i zapisać hash każdego pliku w systemie plików, aby móc ustalić, które pliki zostały zmodyfikowane.\
To samo można zrobić z utworzonymi kontami użytkowników, uruchomionymi procesami, działającymi usługami i wszystkim innym, co nie powinno się zbytnio zmieniać — lub wcale.

Przydatny stan bazowy zwykle przechowuje więcej niż tylko skrót: warto też śledzić uprawnienia, właściciela, grupę, znaczniki czasu, inode, symlink target, ACLs oraz wybrane rozszerzone atrybuty. Z perspektywy polowania na atakujących pomaga to wykryć **manipulacje dotyczące wyłącznie uprawnień**, **atomową zamianę pliku** oraz **utrzymywanie dostępu przez zmodyfikowane pliki service/unit** nawet wtedy, gdy hash zawartości nie jest pierwszą rzeczą, która się zmienia.

### File Integrity Monitoring

File Integrity Monitoring (FIM) to krytyczna technika bezpieczeństwa, która chroni środowiska IT i dane poprzez śledzenie zmian w plikach. Zazwyczaj łączy w sobie:

1. **Porównanie ze stanem bazowym:** Zapisuj metadane i kryptograficzne sumy kontrolne (preferuj `SHA-256` lub lepsze) do przyszłych porównań.
2. **Powiadomienia w czasie rzeczywistym:** Subskrybuj natywne zdarzenia plikowe systemu operacyjnego, aby wiedzieć **który plik się zmienił, kiedy i najlepiej jaki proces/użytkownik go zmodyfikował**.
3. **Okresowe ponowne skanowanie:** Odbuduj zaufanie po rebootach, utracie zdarzeń, awariach agenta lub celowej działalności antyforensycznej.

Dla threat huntingu FIM jest zwykle bardziej przydatny, gdy skupia się na ścieżkach o wysokiej wartości, takich jak:

- `/etc`, `/boot`, `/usr/local/bin`, `/usr/local/sbin`
- `systemd` units, cron locations, SSH material, PAM modules, web roots
- Windows persistence locations, service binaries, scheduled task files, startup folders
- Container writable layers and bind-mounted secrets/configuration

## Backendy czasu rzeczywistego i martwe pola

### Linux

To, jaki backend zbierania używasz, ma znaczenie:

- **`inotify` / `fsnotify`**: proste i powszechne, ale limity watch mogą zostać wyczerpane i niektóre przypadki brzegowe są pomijane.
- **`auditd` / audit framework**: lepsze, gdy potrzebujesz wiedzieć **kto zmienił plik** (`auid`, process, pid, executable).
- **`eBPF` / `kprobes`**: nowsze opcje używane przez nowoczesne stosy FIM do wzbogacania zdarzeń i zmniejszania części operacyjnego bólu związanego z prostymi wdrożeniami `inotify`.

Kilka praktycznych pułapek:

- Jeśli program **zastępuje** plik przez `write temp -> rename`, monitorowanie samego pliku może przestać być użyteczne. **Monitoruj katalog nadrzędny**, nie tylko plik.
- Kolektory oparte na `inotify` mogą gubić zdarzenia lub działać gorzej przy **ogromnych drzewach katalogów**, aktywności związanej z **hard-linkami** lub po **usunięciu monitorowanego pliku**.
- Bardzo duże, rekurencyjne zestawy watch mogą cicho zawodzić, jeśli `fs.inotify.max_user_watches`, `max_user_instances` lub `max_queued_events` są ustawione zbyt nisko.
- Systemy plików sieciowych zwykle są złym celem dla FIM przy monitoringu o niskim poziomie szumów.

Przykładowy stan bazowy + weryfikacja z użyciem AIDE:
```bash
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
aide --check
```
Przykładowa konfiguracja `osquery` FIM skoncentrowana na ścieżkach utrzymania dostępu przez atakującego:
```json
{
"schedule": {
"fim": {
"query": "SELECT * FROM file_events;",
"interval": 300,
"removed": false
}
},
"file_paths": {
"etc": ["/etc/%%"],
"systemd": ["/etc/systemd/system/%%", "/usr/lib/systemd/system/%%"],
"ssh": ["/root/.ssh/%%", "/home/%/.ssh/%%"]
}
}
```
Jeśli potrzebujesz **atrybucji procesu** zamiast tylko zmian na poziomie ścieżki, preferuj telemetrię wspieraną audytem, taką jak `osquery` `process_file_events` lub tryb `whodata` w Wazuh.

### Windows

W Windows FIM jest silniejszy, gdy połączysz **change journals** z **high-signal process/file telemetry**:

- **NTFS USN Journal** zapewnia trwały dziennik zmian plików dla każdego woluminu.
- **Sysmon Event ID 11** jest przydatny do wykrywania tworzenia/nadpisywania plików.
- **Sysmon Event ID 2** pomaga wykrywać **timestomping**.
- **Sysmon Event ID 15** jest przydatny do wykrywania **named alternate data streams (ADS)**, takich jak `Zone.Identifier` lub ukryte payload streams.

Szybkie przykłady triage USN:
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
Aby poznać bardziej zaawansowane techniki antyforensyczne dotyczące **timestamp manipulation**, **ADS abuse**, i **USN tampering**, zobacz [Anti-Forensic Techniques](anti-forensic-techniques.md).

### Kontenery

Container FIM często pomija rzeczywistą ścieżkę zapisu. Przy Docker `overlay2` zmiany są zapisywane w **writable upper layer** (`upperdir`/`diff`), a nie w warstwach obrazu tylko do odczytu. W związku z tym:

- Monitorowanie tylko ścieżek z **wewnątrz** krótkotrwałego kontenera może nie wychwycić zmian po ponownym utworzeniu kontenera.
- Często bardziej użyteczne jest monitorowanie **ścieżki hosta** odpowiadającej warstwie zapisywalnej lub odpowiedniego wolumenu zamontowanego przez bind.
- FIM na warstwach obrazu różni się od FIM na systemie plików uruchomionego kontenera.

## Uwagi do poszukiwań ukierunkowanych na atakującego

- Śledź **service definitions** i **task schedulers** równie uważnie jak binaria. Atakujący często uzyskują trwałość przez modyfikację unit file, wpisu cron lub task XML zamiast łatania `/bin/sshd`.
- Sam hash zawartości to za mało. Wiele kompromisów najpierw objawia się jako **owner/mode/xattr/ACL drift**.
- Jeśli podejrzewasz dojrzałe włamanie, rób obie rzeczy: **real-time FIM** dla świeżej aktywności oraz **cold baseline comparison** z zaufanego nośnika.
- Jeśli atakujący ma wykonanie jako root lub w jądrze, załóż, że agent FIM, jego baza danych, a nawet źródło zdarzeń mogą być zmanipulowane. Przechowuj logi i bazowe porównania zdalnie lub na nośnikach tylko do odczytu, kiedy to możliwe.

## Narzędzia

- [AIDE](https://aide.github.io/)
- [osquery](https://osquery.io/)
- [Wazuh FIM / Syscheck](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)
- [Elastic Auditbeat File Integrity Module](https://www.elastic.co/docs/reference/beats/auditbeat/auditbeat-module-file_integrity)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## Źródła

- [https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
- [https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case](https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case)

{{#include ../../banners/hacktricks-training.md}}
