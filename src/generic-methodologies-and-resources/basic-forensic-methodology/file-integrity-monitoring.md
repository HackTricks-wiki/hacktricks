# Monitorowanie integralności plików

{{#include ../../banners/hacktricks-training.md}}

## Baseline

Baseline polega na wykonaniu snapshotu określonych części systemu, aby **porównać go z przyszłym stanem i wykryć zmiany**.

Na przykład można obliczyć i przechowywać hash każdego pliku w systemie plików, aby ustalić, które pliki zostały zmodyfikowane.\
Można to również zrobić dla utworzonych kont użytkowników, uruchomionych procesów, działających usług oraz innych elementów, które nie powinny często się zmieniać lub nie powinny zmieniać się wcale.

**Użyteczny baseline** zwykle przechowuje więcej niż tylko digest: warto również monitorować uprawnienia, właściciela, grupę, znaczniki czasu, inode, cel symlinku, ACL oraz wybrane atrybuty rozszerzone. Z perspektywy polowania na atakujących pomaga to wykrywać **manipulacje ograniczone wyłącznie do uprawnień**, **atomową podmianę plików** oraz **utrwalanie dostępu poprzez zmodyfikowane pliki usług/unitów**, nawet jeśli hash zawartości nie jest pierwszą rzeczą, która się zmienia.

### Monitorowanie integralności plików

File Integrity Monitoring (FIM) to krytyczna technika bezpieczeństwa, która chroni środowiska IT i dane poprzez śledzenie zmian w plikach. Zwykle łączy:

1. **Porównywanie z baseline:** Przechowywanie metadanych i kryptograficznych sum kontrolnych (preferowane `SHA-256` lub lepsze) do późniejszych porównań.
2. **Powiadomienia w czasie rzeczywistym:** Subskrybowanie natywnych dla systemu operacyjnego zdarzeń dotyczących plików, aby wiedzieć, **który plik się zmienił, kiedy to nastąpiło i — najlepiej — który proces/użytkownik go modyfikował**.
3. **Okresowe ponowne skanowanie:** Ponowne zwiększanie pewności po restartach, utracie zdarzeń, awariach agentów lub celowych działaniach anti-forensic.

W threat huntingu FIM jest zwykle bardziej użyteczny, gdy koncentruje się na **ścieżkach o wysokiej wartości**, takich jak:

- `/etc`, `/boot`, `/usr/local/bin`, `/usr/local/sbin`
- unity `systemd`, lokalizacje cron, materiały SSH, moduły PAM, katalogi główne stron WWW
- Lokalizacje persistence w Windows, pliki binarne usług, pliki zaplanowanych zadań, foldery startowe
- Zapisywalne warstwy kontenerów oraz sekrety/konfiguracja montowane przez bind mount

## Backendy czasu rzeczywistego i ślepe punkty

### Linux

Backend zbierający dane ma znaczenie:<sup>[[2]](#references)</sup>

- **`inotify` / `fsnotify`**: łatwe i powszechne rozwiązanie, ale limity monitorowania mogą zostać wyczerpane, a niektóre przypadki brzegowe mogą zostać pominięte.
- **`auditd` / audit framework**: lepsze, gdy trzeba ustalić, **kto zmienił plik** (`auid`, proces, pid, plik wykonywalny).
- **`eBPF` / `kprobes`**: nowsze opcje używane przez nowoczesne stosy FIM w celu wzbogacania zdarzeń i ograniczenia niektórych problemów operacyjnych związanych z wdrożeniami opartymi wyłącznie na `inotify`.

Kilka praktycznych problemów:<sup>[[1]](#references)</sup>

- Jeśli program **zastępuje** plik za pomocą `write temp -> rename`, monitorowanie samego pliku może przestać być użyteczne. **Monitoruj katalog nadrzędny**, a nie tylko plik.
- Collectory oparte na `inotify` mogą pomijać zdarzenia lub działać gorzej w przypadku **ogromnych drzew katalogów**, **operacji na hard linkach** albo po **usunięciu monitorowanego pliku**.
- Bardzo duże rekurencyjne zestawy monitorowania mogą zawieść bez widocznego komunikatu, jeśli `fs.inotify.max_user_watches`, `max_user_instances` lub `max_queued_events` mają zbyt niskie wartości.
- Systemy plików sieciowych zwykle są złymi celami FIM w przypadku monitorowania o niskim poziomie szumu.

Przykład baseline + weryfikacja za pomocą AIDE:
```bash
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
aide --check
```
Przykładowa konfiguracja `osquery` FIM skoncentrowana na ścieżkach persistence atakującego:<sup>[[1]](#references)</sup>
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
Jeśli potrzebujesz **atrybucji procesu**, a nie tylko zmian na poziomie ścieżek, preferuj telemetrykę opartą na audycie, taką jak `osquery` `process_file_events` lub tryb `whodata` Wazuh.<sup>[[1]](#references)[[3]](#references)</sup>

### Windows

W systemie Windows FIM jest skuteczniejsze po połączeniu **dzienników zmian** z **telemetrią procesów/plików o wysokiej wartości sygnału**:

- **NTFS USN Journal** zapewnia trwały dziennik zmian plików dla każdego woluminu.
- **Sysmon Event ID 11** jest przydatny do wykrywania tworzenia/zastępowania plików.
- **Sysmon Event ID 2** pomaga wykrywać **timestomping**.
- **Sysmon Event ID 15** jest przydatny do wykrywania **nazwanych alternatywnych strumieni danych (ADS)**, takich jak `Zone.Identifier` lub ukryte strumienie payloadów.

Szybkie przykłady triage USN:
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
W przypadku bardziej zaawansowanych zagadnień anti-forensics dotyczących **manipulacji znacznikami czasu**, **nadużywania ADS** i **manipulacji USN** sprawdź [Anti-Forensic Techniques](anti-forensic-techniques.md).

### Kontenery

FIM kontenerów często pomija rzeczywistą ścieżkę zapisu. W przypadku Docker `overlay2` zmiany są zapisywane w **zapisywalnej warstwie upper** kontenera (`upperdir`/`diff`), a nie w warstwach obrazu tylko do odczytu. Dlatego:

- Monitorowanie wyłącznie ścieżek **wewnątrz** krótkotrwałego kontenera może nie wykryć zmian po odtworzeniu kontenera.
- Monitorowanie **ścieżki na hoście**, która obsługuje zapisywalną warstwę, lub odpowiedniego woluminu zamontowanego przez bind mount, jest często bardziej użyteczne.
- FIM warstw obrazu różni się od FIM systemu plików działającego kontenera.

## Notatki dotyczące polowania z perspektywy atakującego

- Śledź **definicje usług** i **harmonogramy zadań** równie dokładnie jak pliki binarne. Atakujący często uzyskują persistence, modyfikując plik unit, wpis cron lub XML zadania, zamiast modyfikować `/bin/sshd`.
- Sam hash zawartości jest niewystarczający. Wiele naruszeń bezpieczeństwa po raz pierwszy ujawnia się jako **zmiana właściciela, trybu, xattr lub ACL**.
- Jeśli podejrzewasz zaawansowaną intruzję, wykonaj oba działania: **FIM w czasie rzeczywistym** w celu wykrywania świeżej aktywności oraz **porównanie z zimną bazą wzorcową** z zaufanego nośnika.
- Jeśli atakujący uzyskał root lub wykonuje kod w jądrze, załóż, że agent FIM, jego baza danych, a nawet źródło zdarzeń mogły zostać zmodyfikowane. W miarę możliwości przechowuj logi i bazy wzorcowe zdalnie lub na nośnikach tylko do odczytu.

## Narzędzia

- [AIDE](https://aide.github.io/)
- [osquery](https://osquery.io/)
- [Wazuh FIM / Syscheck](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)<sup>[[3]](#references)</sup>
- [Moduł Elastic Auditbeat File Integrity](https://www.elastic.co/docs/reference/beats/auditbeat/auditbeat-module-file_integrity)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## Odnośniki

- [1] [Monitorowanie integralności plików za pomocą osquery](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
- [2] [Tracing Linux: przypadek użycia monitorowania integralności plików (Elastic)](https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case)
- [3] [Monitorowanie integralności plików Wazuh (tryb Syscheck i whodata)](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)

{{#include ../../banners/hacktricks-training.md}}
