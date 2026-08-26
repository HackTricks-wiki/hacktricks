# Monitorowanie integralności plików

{{#include ../../banners/hacktricks-training.md}}

## Baseline

Baseline polega na wykonaniu migawki określonych części systemu, aby **porównać ją z przyszłym stanem i wykryć zmiany**.

Na przykład można obliczyć i zapisać hash każdego pliku w systemie plików, aby ustalić, które pliki zostały zmodyfikowane.\
Można to również zrobić dla utworzonych kont użytkowników, uruchomionych procesów, działających usług oraz wszystkich innych elementów, które nie powinny często się zmieniać lub nie powinny zmieniać się wcale.

**Użyteczny baseline** zwykle przechowuje więcej niż tylko skrót: warto również śledzić uprawnienia, właściciela, grupę, znaczniki czasu, inode, cel dowiązania symbolicznego, listy ACL oraz wybrane atrybuty rozszerzone.<sup>[[4]](#references)</sup> Z perspektywy wyszukiwania aktywności atakujących pomaga to wykrywać **manipulowanie wyłącznie uprawnieniami**, **atomową podmianę pliku** oraz **utrzymywanie dostępu za pomocą zmodyfikowanych plików usług/unitów**, nawet gdy hash zawartości nie jest pierwszą rzeczą, która ulega zmianie.

### Monitorowanie integralności plików

File Integrity Monitoring (FIM) to krytyczna technika bezpieczeństwa, która chroni środowiska IT i dane poprzez śledzenie zmian w plikach. Zwykle łączy:<sup>[[1]](#references)[[3]](#references)</sup>

1. **Porównywanie z baseline:** Przechowywanie metadanych i kryptograficznych sum kontrolnych (najlepiej `SHA-256` lub lepszych) do przyszłych porównań.
2. **Powiadomienia w czasie rzeczywistym:** Subskrybowanie natywnych dla systemu operacyjnego zdarzeń dotyczących plików, aby wiedzieć **który plik się zmienił, kiedy oraz — najlepiej — który proces/użytkownik go modyfikował**.
3. **Okresowe ponowne skanowanie:** Odbudowywanie wiarygodności po ponownym uruchomieniu systemu, utracie zdarzeń, awarii agenta lub celowej aktywności anti-forensic.

W threat hunting FIM jest zwykle bardziej użyteczny, gdy koncentruje się na **ścieżkach o wysokiej wartości**, takich jak:

- `/etc`, `/boot`, `/usr/local/bin`, `/usr/local/sbin`
- unity `systemd`, lokalizacje cron, materiały SSH, moduły PAM, katalogi główne aplikacji webowych
- lokalizacje utrzymywania dostępu w Windows, pliki binarne usług, pliki zaplanowanych zadań, foldery startowe
- zapisywalne warstwy kontenerów oraz sekrety/konfiguracja montowane za pomocą bind mountów

## Backendy czasu rzeczywistego i ślepe punkty

### Linux

Backend gromadzenia danych ma znaczenie:<sup>[[2]](#references)[[9]](#references)</sup>

- **`inotify` / `fsnotify`**: proste i powszechne rozwiązanie, ale limity watchy mogą zostać wyczerpane, a niektóre przypadki brzegowe mogą zostać pominięte.
- **`auditd` / audit framework**: lepsze rozwiązanie, gdy trzeba ustalić **kto zmienił plik** (login UID, ID procesu i nazwa procesu).
- **`eBPF` / `kprobes`**: nowsze opcje używane przez nowoczesne stosy FIM w celu wzbogacania zdarzeń i ograniczenia niektórych problemów operacyjnych typowych dla wdrożeń opartych wyłącznie na `inotify`.

Kilka praktycznych pułapek:<sup>[[1]](#references)[[5]](#references)</sup>

- Jeśli program **zastępuje** plik za pomocą `write temp -> rename`, monitorowanie samego pliku może przestać być użyteczne. **Monitoruj katalog nadrzędny**, a nie tylko plik.
- Collectory oparte na `inotify` mogą pomijać zdarzenia lub działać gorzej w przypadku **ogromnych drzew katalogów**, **aktywności związanej z hard linkami** albo po **usunięciu monitorowanego pliku**.
- Bardzo duże rekurencyjne zestawy watchy mogą kończyć się niepowodzeniem bez wyraźnego komunikatu, jeśli wartości `fs.inotify.max_user_watches`, `max_user_instances` lub `max_queued_events` są zbyt niskie.
- W przypadku monitorowania opartego na `inotify` sieciowe systemy plików stanowią ślepy punkt, ponieważ zmiany zdalne nie są raportowane.

Przykład baseline i weryfikacji za pomocą AIDE:<sup>[[4]](#references)</sup>
```bash
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
aide --check
```
Przykładowa konfiguracja `osquery` FIM skoncentrowana na ścieżkach persystencji atakującego:<sup>[[1]](#references)</sup>
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
Jeśli potrzebujesz **przypisania procesu**, a nie tylko zmian na poziomie ścieżki, preferuj telemetrykę wspieraną przez audit, taką jak `osquery` `process_file_events` lub tryb `whodata` Wazuh.<sup>[[1]](#references)[[3]](#references)[[9]](#references)</sup>

#### `io_uring`: telemetryka syscalli to nie FIM

Na współczesnym Linuxie obserwowanie `openat(2)`, `write(2)` lub innych punktów wejścia syscalli **nie jest równoważne monitorowaniu wynikowej operacji na filesystemie**. Proof of concept **Curing** z 2025 roku kolejkował żądania dotyczące plików i sieci za pośrednictwem `io_uring`, przez co produkty lub policies podłączone wyłącznie do odpowiadających im wpisów syscalli dla poszczególnych operacji traciły telemetrykę procesu. W tych samych testach komponent FIM ograniczony do ścieżki nadal wykrywał modyfikacje plików, pokazując, że jest to **ślepy punkt wynikający z umiejscowienia hooka**, a nie obejście uprawnień ani sposób na pokonanie każdego backendu FIM.<sup>[[10]](#references)</sup>

Podczas walidacji sensora modyfikuj ten sam canary różnymi metodami: zwykłym `write`, `mmap` + `msync`, `truncate`, `sendfile`/`copy_file_range`, atomową podmianą oraz `io_uring`. Sprawdzaj nie tylko, czy wykrywana jest końcowa rozbieżność hasha, ale także czy event zachowuje odpowiedzialny proces, kontener/cgroup, ścieżkę widoczną w namespace, inode oraz parę rename. Brak eventu w czasie rzeczywistym, po którym następuje niezgodność wykryta przez skanowanie okresowe, należy traktować jako **utratę telemetryki**, a nie jako rutynową, niewyjaśnioną zmianę.<sup>[[10]](#references)[[11]](#references)</sup>

W przypadku monitorowania opartego na eBPF preferuj typowe kernelowe punkty egzekwowania zamiast listy sond na wejściu syscalli. Na przykład policy dostępu do plików Tetragon używa `security_file_permission` do obsługi zwykłego I/O, `sendfile`, `copy_file_range`, AIO i `io_uring`; osobno obsługuje mapowania pamięci za pomocą `security_mmap_file`, a zmiany rozmiaru za pomocą `security_path_truncate`. Pokazuje to również, dlaczego jeden hook rzadko zapewnia pełne pokrycie.<sup>[[11]](#references)</sup>

### Windows

W Windows FIM jest skuteczniejszy, gdy połączysz **change journals** z **telemetryką procesów/plików o wysokiej wartości sygnału**:<sup>[[6]](#references)[[7]](#references)</sup>

- **NTFS USN Journal** zapewnia trwały log zmian plików dla każdego woluminu.
- **Sysmon Event ID 11** jest przydatny do wykrywania tworzenia/nadpisywania plików.
- **Sysmon Event ID 2** pomaga wykrywać **timestomping**.
- **Sysmon Event ID 15** jest przydatny do wykrywania **named alternate data streams (ADS)**, takich jak `Zone.Identifier` lub ukryte strumienie payloadów.

Szybkie przykłady triage USN:<sup>[[7]](#references)</sup>
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
W przypadku bardziej zaawansowanych koncepcji anti-forensics dotyczących **timestamp manipulation**, **ADS abuse** i **USN tampering** zobacz [Anti-Forensic Techniques](anti-forensic-techniques.md).

### Kontenery

Container FIM często pomija rzeczywistą ścieżkę zapisu. W Dockerze `overlay2` system plików kontenera łączy warstwy obrazu tylko do odczytu `lowerdir` z zapisywalną **warstwą górną** (`upperdir`/`diff`), a zapisy do plików obrazu są kopiowane do tej warstwy.<sup>[[8]](#references)</sup> Dlatego:

- Monitorowanie wyłącznie ścieżek **wewnątrz** krótkotrwałego kontenera może pominąć zmiany po jego ponownym utworzeniu.
- Monitorowanie **ścieżki hosta**, która obsługuje zapisywalną warstwę, lub odpowiedniego wolumenu montowanego przez bind mount, jest często bardziej użyteczne.
- FIM warstw obrazu różni się od FIM systemu plików uruchomionego kontenera.

## Uwagi dotyczące wykrywania z perspektywy atakującego

- Śledź **definicje usług** i **harmonogramy zadań** równie dokładnie jak pliki binarne. Atakujący często uzyskują persistence, modyfikując plik jednostki, wpis cron lub XML zadania, zamiast modyfikować `/bin/sshd`.
- Sam hash zawartości jest niewystarczający. Wiele naruszeń bezpieczeństwa najpierw ujawnia się jako **odchylenia właściciela/trybu/xattr/ACL**.
- Jeśli podejrzewasz dojrzałą ingerencję, wykonaj oba działania: **FIM w czasie rzeczywistym** dla świeżej aktywności oraz **porównanie z zimną bazą wzorcową** z zaufanego nośnika.
- Jeśli atakujący uzyskał uprawnienia root lub wykonuje kod w jądrze, traktuj agenta FIM i jego bazę danych jako niezaufane. W miarę możliwości przechowuj logi i bazy wzorcowe zdalnie lub na nośnikach tylko do odczytu.<sup>[[4]](#references)</sup>

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
- [5] [Strona podręcznika Linux inotify(7)](https://man7.org/linux/man-pages/man7/inotify.7.html)
- [6] [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [7] [fsutil usn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-usn)
- [8] [Sterownik pamięci masowej OverlayFS](https://docs.docker.com/engine/storage/drivers/overlayfs-driver/)
- [9] [Zaawansowane ustawienia Wazuh FIM](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/advanced-settings.html)
- [10] [Obejścia narzędzi bezpieczeństwa Linux przez rootkit io_uring (ARMO)](https://www.armosec.io/blog/io_uring-rootkit-bypasses-linux-security/)
- [11] [Dostęp do nazw plików: ścieżki synchroniczne, asynchroniczne, mapowane i obcinania (Tetragon)](https://tetragon.io/docs/use-cases/filename-access/)
{{#include ../../banners/hacktricks-training.md}}
