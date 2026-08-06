# Monitorowanie integralności plików

{{#include ../../banners/hacktricks-training.md}}

## Stan bazowy

Stan bazowy polega na wykonaniu migawki określonych części systemu, aby **porównać ją z przyszłym stanem i wykryć zmiany**.

Na przykład można obliczyć i przechowywać hash każdego pliku systemu plików, aby ustalić, które pliki zostały zmodyfikowane.\
Można to również zrobić dla utworzonych kont użytkowników, uruchomionych procesów, uruchomionych usług i wszelkich innych elementów, które nie powinny zmieniać się często lub wcale.

**Przydatny stan bazowy** zwykle przechowuje więcej niż tylko skrót: warto również monitorować uprawnienia, właściciela, grupę, znaczniki czasu, inode, cel dowiązania symbolicznego, ACL oraz wybrane atrybuty rozszerzone. Z perspektywy polowania na atakujących pomaga to wykrywać **manipulowanie wyłącznie uprawnieniami**, **atomową zamianę plików** oraz **utrwalanie dostępu poprzez zmodyfikowane pliki usług/unit**, nawet gdy hash zawartości nie jest pierwszą rzeczą, która ulega zmianie.

### Monitorowanie integralności plików

File Integrity Monitoring (FIM) to krytyczna technika bezpieczeństwa, która chroni środowiska IT i dane poprzez śledzenie zmian w plikach. Zwykle łączy:

1. **Porównywanie ze stanem bazowym:** Przechowywanie metadanych i kryptograficznych sum kontrolnych (preferowane `SHA-256` lub lepsze) do przyszłych porównań.
2. **Powiadomienia w czasie rzeczywistym:** Subskrybowanie natywnych dla systemu operacyjnego zdarzeń dotyczących plików, aby wiedzieć **który plik uległ zmianie, kiedy to nastąpiło i, najlepiej, który proces/użytkownik go zmodyfikował**.
3. **Okresowe ponowne skanowanie:** Odbudowywanie wiarygodności po ponownym uruchomieniu, utracie zdarzeń, awarii agenta lub celowej aktywności antyforensic.

W threat hunting FIM jest zwykle bardziej użyteczny, gdy koncentruje się na **ścieżkach o wysokiej wartości**, takich jak:

- `/etc`, `/boot`, `/usr/local/bin`, `/usr/local/sbin`
- unity `systemd`, lokalizacje cron, materiały SSH, moduły PAM, katalogi główne aplikacji webowych
- Lokalizacje persistence w Windows, pliki binarne usług, pliki zaplanowanych zadań, foldery startowe
- Zapisywalne warstwy kontenerów oraz sekrety/konfiguracja montowane za pomocą bind mount

## Backendy czasu rzeczywistego i ślepe punkty

### Linux

Znaczenie ma backend zbierania danych:<sup>[[2]](#references)</sup>

- **`inotify` / `fsnotify`**: łatwe i powszechne, ale limity watchów mogą zostać wyczerpane, a niektóre przypadki brzegowe mogą zostać pominięte.
- **`auditd` / audit framework**: lepsze rozwiązanie, gdy trzeba wiedzieć, **kto zmienił plik** (`auid`, proces, pid, plik wykonywalny).
- **`eBPF` / `kprobes`**: nowsze opcje używane przez nowoczesne stosy FIM w celu wzbogacania zdarzeń i ograniczenia części problemów operacyjnych typowych dla wdrożeń opartych wyłącznie na `inotify`.

Kilka praktycznych problemów:<sup>[[1]](#references)</sup>

- Jeśli program **zastępuje** plik za pomocą `write temp -> rename`, monitorowanie samego pliku może przestać być użyteczne. **Monitoruj katalog nadrzędny**, a nie tylko plik.
- Collectory oparte na `inotify` mogą pomijać zdarzenia lub działać gorzej w przypadku **ogromnych drzew katalogów**, **operacji na hard linkach** albo po **usunięciu monitorowanego pliku**.
- Bardzo duże zestawy rekursywnych watchów mogą niejawnie przestać działać, jeśli `fs.inotify.max_user_watches`, `max_user_instances` lub `max_queued_events` mają zbyt niskie wartości.
- Systemy plików sieciowych zwykle są złym celem dla FIM wymagającego monitorowania z małą liczbą szumów.

Przykładowy stan bazowy i weryfikacja za pomocą AIDE:
```bash
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
aide --check
```
Przykładowa konfiguracja `osquery` FIM skoncentrowana na ścieżkach trwałości atakującego:<sup>[[1]](#references)</sup>
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
Jeśli potrzebujesz **atrybucji procesu**, a nie tylko zmian na poziomie ścieżek, preferuj telemetrykę opartą na audycie, taką jak `osquery` `process_file_events` lub tryb Wazuh `whodata`.<sup>[[1]](#references)[[3]](#references)</sup>

### Windows

W systemie Windows FIM jest skuteczniejszy, gdy połączysz **dzienniki zmian** z **telemetrią procesów/plików o wysokiej wartości sygnału**:

- **NTFS USN Journal** zapewnia trwały dziennik zmian plików dla każdego woluminu.
- **Sysmon Event ID 11** jest przydatny do wykrywania tworzenia/zastępowania plików.
- **Sysmon Event ID 2** pomaga wykrywać **timestomping**.
- **Sysmon Event ID 15** jest przydatny dla **named alternate data streams (ADS)**, takich jak `Zone.Identifier` lub ukryte strumienie payloadów.

Szybkie przykłady triage USN:
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
W przypadku bardziej zaawansowanych pomysłów anti-forensic dotyczących **timestamp manipulation**, **ADS abuse** i **USN tampering** sprawdź [Anti-Forensic Techniques](anti-forensic-techniques.md).

### Kontenery

FIM kontenerów często pomija rzeczywistą ścieżkę zapisu. W przypadku Docker `overlay2` zmiany są zatwierdzane w **zapisywalnej warstwie upper** kontenera (`upperdir`/`diff`), a nie w warstwach obrazu tylko do odczytu. Dlatego:

- Monitorowanie wyłącznie ścieżek **wewnątrz** krótkotrwałego kontenera może pominąć zmiany po jego ponownym utworzeniu.
- Monitorowanie **ścieżki hosta**, która obsługuje zapisywalną warstwę, lub odpowiedniego woluminu bind-mounted, jest często bardziej użyteczne.
- FIM warstw obrazu różni się od FIM systemu plików działającego kontenera.

## Notatki dotyczące threat huntingu z perspektywy atakującego

- Śledź **definicje usług** i **harmonogramy zadań** równie dokładnie jak pliki binarne. Atakujący często uzyskują persistence, modyfikując plik unit, wpis cron lub XML zadania, zamiast modyfikować `/bin/sshd`.
- Sam hash zawartości jest niewystarczający. Wiele kompromitacji po raz pierwszy ujawnia się jako **odchylenia właściciela/trybu/xattr/ACL**.
- Jeśli podejrzewasz dojrzałą intruzję, wykonaj oba działania: **FIM w czasie rzeczywistym** dla świeżej aktywności oraz **porównanie z zimnym baseline'em** z zaufanego nośnika.
- Jeśli atakujący uzyskał root lub wykonanie kodu w kernelu, załóż, że agent FIM, jego baza danych, a nawet źródło zdarzeń mogły zostać zmodyfikowane. W miarę możliwości przechowuj logi i baseline'y zdalnie lub na nośnikach tylko do odczytu.

## Narzędzia

- [AIDE](https://aide.github.io/)
- [osquery](https://osquery.io/)
- [Wazuh FIM / Syscheck](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)
- [Elastic Auditbeat File Integrity Module](https://www.elastic.co/docs/reference/beats/auditbeat/auditbeat-module-file_integrity)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## Referencje

- [1] [File Integrity Monitoring with osquery](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
- [2] [Tracing Linux: A file integrity monitoring use case (Elastic)](https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case)
- [3] [Wazuh File Integrity Monitoring (Syscheck and whodata mode)](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)

{{#include ../../banners/hacktricks-training.md}}
