# Monitorowanie integralności plików

## Punkt odniesienia

Punkt odniesienia polega na wykonaniu migawki określonych części systemu, aby **porównać ją z przyszłym stanem i wykryć zmiany**.

Na przykład można obliczyć i przechowywać hash każdego pliku systemu plików, aby móc ustalić, które pliki zostały zmodyfikowane.\
Można to również zrobić w przypadku utworzonych kont użytkowników, uruchomionych procesów, działających usług i wszystkich innych elementów, które nie powinny zmieniać się często lub w ogóle.

**Użyteczny punkt odniesienia** zazwyczaj przechowuje więcej niż tylko skrót: warto również śledzić uprawnienia, właściciela, grupę, znaczniki czasu, inode, cel symlink, ACL oraz wybrane atrybuty rozszerzone.<sup>[[4]](#references)</sup> Z perspektywy polowania na attackerów pomaga to wykrywać **manipulacje dotyczące wyłącznie uprawnień**, **atomową wymianę plików** oraz **utrwalanie dostępu za pomocą zmodyfikowanych plików usług/unit**, nawet gdy hash zawartości nie jest pierwszą rzeczą, która się zmienia.

### Monitorowanie integralności plików

File Integrity Monitoring (FIM) to krytyczna technika bezpieczeństwa, która chroni środowiska IT i dane poprzez śledzenie zmian w plikach. Zwykle łączy:<sup>[[1]](#references)[[3]](#references)</sup>

1. **Porównywanie z punktem odniesienia:** Przechowywanie metadanych i kryptograficznych sum kontrolnych (najlepiej `SHA-256` lub lepszych) do przyszłych porównań.
2. **Powiadomienia w czasie rzeczywistym:** Subskrybowanie natywnych dla systemu operacyjnego zdarzeń dotyczących plików, aby wiedzieć **który plik się zmienił, kiedy oraz, najlepiej, który proces/użytkownik go dotknął**.
3. **Okresowe ponowne skanowanie:** Odbudowywanie wiarygodności po ponownym uruchomieniu systemu, utracie zdarzeń, awariach agentów lub celowej aktywności antyforensic.

W threat hunting FIM jest zwykle bardziej użyteczny, gdy koncentruje się na **ścieżkach o wysokiej wartości**, takich jak:

- `/etc`, `/boot`, `/usr/local/bin`, `/usr/local/sbin`
- Jednostki `systemd`, lokalizacje cron, materiały SSH, moduły PAM, katalogi główne witryn internetowych
- Lokalizacje persistence w Windows, pliki binarne usług, pliki zaplanowanych zadań, foldery startowe
- Zapisywalne warstwy kontenerów oraz sekrety/konfiguracje montowane za pomocą bind mount

## Backendy czasu rzeczywistego i martwe punkty

### Linux

Backend zbierania danych ma znaczenie:<sup>[[2]](#references)[[9]](#references)</sup>

- **`inotify` / `fsnotify`**: proste i powszechne, ale limity watchów mogą zostać wyczerpane, a niektóre przypadki brzegowe mogą zostać pominięte.
- **`auditd` / audit framework**: lepsze rozwiązanie, gdy trzeba wiedzieć, **kto zmienił plik** (login UID, ID procesu i nazwa procesu).
- **`eBPF` / `kprobes`**: nowsze opcje używane przez nowoczesne stosy FIM w celu wzbogacania zdarzeń i ograniczenia niektórych problemów operacyjnych typowych dla wdrożeń opartych wyłącznie na `inotify`.

Niektóre praktyczne pułapki:<sup>[[1]](#references)[[5]](#references)</sup>

- Jeśli program **zastępuje** plik za pomocą `write temp -> rename`, obserwowanie samego pliku może przestać być użyteczne. **Obserwuj katalog nadrzędny**, a nie tylko plik.
- Collectory oparte na `inotify` mogą pomijać zdarzenia lub działać gorzej w przypadku **ogromnych drzew katalogów**, **aktywności hard-linków** albo po **usunięciu obserwowanego pliku**.
- Bardzo duże rekurencyjne zestawy watchów mogą niejawnie przestać działać, jeśli wartości `fs.inotify.max_user_watches`, `max_user_instances` lub `max_queued_events` są zbyt niskie.
- W przypadku monitorowania opartego na `inotify` systemy plików sieciowych stanowią martwy punkt, ponieważ zmiany zdalne nie są raportowane.

Przykładowy punkt odniesienia i weryfikacja za pomocą AIDE:<sup>[[4]](#references)</sup>
```bash
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
aide --check
```
Przykładowa konfiguracja FIM w `osquery` koncentrująca się na ścieżkach persistence atakującego:<sup>[[1]](#references)</sup>
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
Jeśli potrzebujesz **przypisania zmian do procesu**, a nie tylko zmian na poziomie ścieżek, preferuj telemetrię opartą na audycie, taką jak `osquery` `process_file_events` lub tryb Wazuh `whodata`.<sup>[[1]](#references)[[3]](#references)[[9]](#references)</sup>

### Windows

W Windows FIM jest skuteczniejszy, gdy połączysz **dzienniki zmian** z **telemetrią procesów/plików o wysokiej wartości sygnału**:<sup>[[6]](#references)[[7]](#references)</sup>

- **NTFS USN Journal** zapewnia trwały dziennik zmian plików dla każdego woluminu.
- **Sysmon Event ID 11** jest przydatny do wykrywania tworzenia i nadpisywania plików.
- **Sysmon Event ID 2** pomaga wykrywać **timestomping**.
- **Sysmon Event ID 15** jest przydatny do wykrywania **nazwanych alternatywnych strumieni danych (ADS)**, takich jak `Zone.Identifier` lub ukryte strumienie z payloadami.

Szybkie przykłady triage z użyciem USN:<sup>[[7]](#references)</sup>
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
Aby poznać bardziej zaawansowane koncepcje anti-forensics dotyczące **manipulacji znacznikami czasu**, **nadużywania ADS** i **manipulacji USN**, sprawdź [Anti-Forensic Techniques](anti-forensic-techniques.md).

### Kontenery

FIM kontenerów często pomija rzeczywistą ścieżkę zapisu. W Dockerze `overlay2` system plików kontenera łączy warstwy obrazu tylko do odczytu `lowerdir` z zapisywalną **warstwą górną** (`upperdir`/`diff`), a zapisy do plików obrazu są kopiowane do tej warstwy.<sup>[[8]](#references)</sup> Dlatego:

- Monitorowanie wyłącznie ścieżek **wewnątrz** krótkotrwałego kontenera może nie wykryć zmian po jego ponownym utworzeniu.
- Monitorowanie **ścieżki hosta**, która obsługuje zapisywalną warstwę, lub odpowiedniego woluminu zamontowanego za pomocą bind mount, jest często bardziej użyteczne.
- FIM warstw obrazu różni się od FIM uruchomionego systemu plików kontenera.

## Uwagi dotyczące polowania ukierunkowanego na atakujących

- Śledź **definicje usług** i **harmonogramy zadań** równie dokładnie jak pliki binarne. Atakujący często uzyskują persistence przez modyfikację pliku jednostki, wpisu cron lub XML zadania, zamiast modyfikowania `/bin/sshd`.
- Sam hash zawartości jest niewystarczający. Wiele kompromitacji początkowo ujawnia się jako **zmiany właściciela, trybu, xattr lub ACL**.
- Jeśli podejrzewasz dojrzałe włamanie, wykonuj oba działania: **FIM w czasie rzeczywistym** w celu wykrywania świeżej aktywności oraz **porównanie z nieaktywną bazą wzorcową** z zaufanego nośnika.
- Jeśli atakujący uzyskał root lub wykonuje kod w jądrze, traktuj agenta FIM i jego bazę danych jako niezaufane. W miarę możliwości przechowuj logi i bazy wzorcowe zdalnie lub na nośnikach tylko do odczytu.<sup>[[4]](#references)</sup>

## Narzędzia

- [AIDE](https://aide.github.io/)
- [osquery](https://osquery.io/)
- [Wazuh FIM / Syscheck](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html).<sup>[[3]](#references)</sup>
- [Elastic Auditbeat File Integrity Module](https://www.elastic.co/docs/reference/beats/auditbeat/auditbeat-module-file_integrity)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## References

- [1] [Monitorowanie integralności plików za pomocą osquery](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
- [2] [Śledzenie systemu Linux: przypadek użycia monitorowania integralności plików (Elastic)](https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case)
- [3] [Monitorowanie integralności plików Wazuh (tryb Syscheck i whodata)](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)
- [4] [Podręcznik AIDE w wersji 0.16.2](https://aide.github.io/doc/)
- [5] [Strona podręcznika systemu Linux inotify(7)](https://man7.org/linux/man-pages/man7/inotify.7.html)
- [6] [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [7] [fsutil usn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-usn)
- [8] [Sterownik pamięci masowej OverlayFS](https://docs.docker.com/engine/storage/drivers/overlayfs-driver/)
- [9] [Zaawansowane ustawienia Wazuh FIM](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/advanced-settings.html)
{{#include ../../banners/hacktricks-training.md}}
