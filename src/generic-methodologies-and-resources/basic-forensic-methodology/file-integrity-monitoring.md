# Monitorowanie integralności plików

{{#include ../../banners/hacktricks-training.md}}

## Punkt odniesienia

Punkt odniesienia polega na wykonaniu migawki określonych części systemu, aby **porównać ją z przyszłym stanem i wykryć zmiany**.

Na przykład można obliczyć i przechowywać hash każdego pliku w systemie plików, aby ustalić, które pliki zostały zmodyfikowane.\
Można to również zrobić dla utworzonych kont użytkowników, uruchomionych procesów, uruchomionych usług oraz każdej innej rzeczy, która nie powinna często się zmieniać lub nie powinna zmieniać się wcale.

**Użyteczny punkt odniesienia** zwykle przechowuje więcej niż tylko digest: warto również śledzić uprawnienia, właściciela, grupę, znaczniki czasu, inode, cel dowiązania symbolicznego, ACL oraz wybrane atrybuty rozszerzone.<sup>[[4]](#references)</sup> Z perspektywy wyszukiwania attackerów pomaga to wykrywać **manipulacje obejmujące wyłącznie uprawnienia**, **atomową podmianę plików** oraz **utrzymywanie persistence za pomocą zmodyfikowanych plików usług/unitów**, nawet gdy hash zawartości nie jest pierwszą rzeczą, która ulega zmianie.

### Monitorowanie integralności plików

File Integrity Monitoring (FIM) to krytyczna technika bezpieczeństwa, która chroni środowiska IT i dane poprzez śledzenie zmian w plikach. Zwykle łączy:<sup>[[1]](#references)[[3]](#references)</sup>

1. **Porównywanie z punktem odniesienia:** Przechowuj metadane i kryptograficzne sumy kontrolne (preferowane `SHA-256` lub lepsze) do przyszłych porównań.
2. **Powiadomienia w czasie rzeczywistym:** Subskrybuj natywne dla systemu operacyjnego zdarzenia dotyczące plików, aby wiedzieć, **który plik się zmienił, kiedy oraz — najlepiej — jaki proces/użytkownik go modyfikował**.
3. **Okresowe ponowne skanowanie:** Odnawiaj poziom zaufania po restartach, utracie zdarzeń, awariach agentów lub celowej aktywności anti-forensic.

W threat hunting FIM jest zwykle bardziej użyteczny, gdy koncentruje się na **ścieżkach o wysokiej wartości**, takich jak:

- `/etc`, `/boot`, `/usr/local/bin`, `/usr/local/sbin`
- unity `systemd`, lokalizacje cron, materiały SSH, moduły PAM, katalogi główne stron WWW
- lokalizacje persistence w Windows, binaria usług, pliki zaplanowanych zadań, foldery startowe
- zapisywalne warstwy kontenerów oraz sekrety/konfiguracja montowane za pomocą bind mountów

## Backendy czasu rzeczywistego i ślepe punkty

### Linux

Znaczenie ma backend gromadzenia danych:<sup>[[2]](#references)[[9]](#references)</sup>

- **`inotify` / `fsnotify`**: łatwe i powszechne, ale limity watchów mogą zostać wyczerpane, a niektóre przypadki brzegowe mogą zostać pominięte.
- **`auditd` / framework audit**: lepsze rozwiązanie, gdy trzeba wiedzieć, **kto zmienił plik** (login UID, ID procesu i nazwa procesu).
- **`eBPF` / `kprobes`**: nowsze opcje używane przez nowoczesne stosy FIM w celu wzbogacania zdarzeń i ograniczenia niektórych problemów operacyjnych związanych ze zwykłymi wdrożeniami `inotify`.

Kilka praktycznych problemów:<sup>[[1]](#references)[[5]](#references)</sup>

- Jeśli program **zastępuje** plik za pomocą `write temp -> rename`, monitorowanie samego pliku może przestać być użyteczne. **Monitoruj katalog nadrzędny**, a nie tylko plik.
- Collectory oparte na `inotify` mogą pomijać zdarzenia lub działać gorzej w przypadku **ogromnych drzew katalogów**, **aktywności związanej z hard linkami** albo po **usunięciu monitorowanego pliku**.
- Bardzo duże zestawy rekursywnych watchów mogą zakończyć się niepowodzeniem bez wyraźnego komunikatu, jeśli `fs.inotify.max_user_watches`, `max_user_instances` lub `max_queued_events` mają zbyt niskie wartości.
- W przypadku monitorowania opartego na `inotify` systemy plików sieciowych stanowią ślepy punkt, ponieważ zmiany zdalne nie są raportowane.

Przykładowy punkt odniesienia i weryfikacja za pomocą AIDE:<sup>[[4]](#references)</sup>
```bash
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
aide --check
```
Przykładowa konfiguracja FIM w `osquery` skoncentrowana na ścieżkach persistence atakującego:<sup>[[1]](#references)</sup>
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
If potrzebujesz **atrybucji procesu**, a nie tylko zmian na poziomie ścieżek, preferuj telemetrię wspieraną przez audyt, taką jak `osquery` `process_file_events` lub tryb Wazuh `whodata`.<sup>[[1]](#references)[[3]](#references)[[9]](#references)</sup>

### Windows

W Windows FIM jest skuteczniejszy, gdy połączysz **dzienniki zmian** z **telemetrią procesów/plików o wysokiej wartości sygnału**:<sup>[[6]](#references)[[7]](#references)</sup>

- **NTFS USN Journal** zapewnia trwały dziennik zmian plików dla każdego woluminu.
- **Sysmon Event ID 11** jest przydatny do wykrywania tworzenia i nadpisywania plików.
- **Sysmon Event ID 2** pomaga wykrywać **timestomping**.
- **Sysmon Event ID 15** jest przydatny do wykrywania **nazwanych alternatywnych strumieni danych (ADS)**, takich jak `Zone.Identifier` lub ukryte strumienie payloadów.

Szybkie przykłady analizy USN:<sup>[[7]](#references)</sup>
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
For deeper anti-forensic ideas around **timestamp manipulation**, **ADS abuse**, and **USN tampering**, check [Anti-Forensic Techniques](anti-forensic-techniques.md).

### Kontenery

Container FIM często pomija rzeczywistą ścieżkę zapisu. W przypadku Docker `overlay2` system plików kontenera łączy warstwy obrazu tylko do odczytu `lowerdir` z zapisywalną **warstwą górną** (`upperdir`/`diff`), a zapisy do plików obrazu są kopiowane do tej warstwy górnej.<sup>[[8]](#references)</sup> Dlatego:

- Monitorowanie wyłącznie ścieżek **wewnątrz** krótkotrwałego kontenera może pomijać zmiany po ponownym utworzeniu kontenera.
- Monitorowanie **ścieżki na hoście**, która obsługuje zapisywalną warstwę, lub odpowiedniego woluminu zamontowanego przez bind mount, jest często bardziej użyteczne.
- FIM na warstwach obrazu różni się od FIM w systemie plików działającego kontenera.

## Notatki dotyczące polowania ukierunkowanego na atakujących

- Śledź **definicje usług** i **harmonogramy zadań** równie dokładnie jak pliki binarne. Atakujący często uzyskują persistence, modyfikując plik unit, wpis cron lub XML zadania, zamiast modyfikować `/bin/sshd`.
- Sam hash zawartości jest niewystarczający. Wiele kompromitacji najpierw ujawnia się jako **odchylenia właściciela/trybu/xattr/ACL**.
- Jeśli podejrzewasz zaawansowaną intruzję, wykonaj oba działania: **FIM w czasie rzeczywistym** dla świeżej aktywności oraz **porównanie z zimną bazą** z zaufanego nośnika.
- Jeśli atakujący uzyskał root lub wykonuje kod w kernelu, traktuj agenta FIM i jego bazę danych jako niezaufane. W miarę możliwości przechowuj logi i bazy bazowe zdalnie lub na nośnikach tylko do odczytu.<sup>[[4]](#references)</sup>

## Narzędzia

- [AIDE](https://aide.github.io/)
- [osquery](https://osquery.io/)
- [Wazuh FIM / Syscheck](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html).<sup>[[3]](#references)</sup>
- [Elastic Auditbeat File Integrity Module](https://www.elastic.co/docs/reference/beats/auditbeat/auditbeat-module-file_integrity)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## References

- [1] [Monitorowanie integralności plików za pomocą osquery](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
- [2] [Śledzenie Linux: przypadek użycia monitorowania integralności plików (Elastic)](https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case)
- [3] [Monitorowanie integralności plików Wazuh (tryb Syscheck i whodata)](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)
- [4] [Podręcznik AIDE w wersji 0.16.2](https://aide.github.io/doc/)
- [5] [Strona podręcznika Linux inotify(7)](https://man7.org/linux/man-pages/man7/inotify.7.html)
- [6] [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [7] [fsutil usn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-usn)
- [8] [Sterownik pamięci masowej OverlayFS](https://docs.docker.com/engine/storage/drivers/overlayfs-driver/)
- [9] [Zaawansowane ustawienia Wazuh FIM](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/advanced-settings.html)
{{#include ../../banners/hacktricks-training.md}}
