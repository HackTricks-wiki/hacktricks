# Techniki antyforensyczne

{{#include ../../banners/hacktricks-training.md}}

## Znaczniki czasu

Atakujący może chcieć **zmienić znaczniki czasu plików**, aby uniknąć wykrycia.\
Znaczniki czasu można znaleźć w MFT w atrybutach `$STANDARD_INFORMATION` \_\_ i \_\_ `$FILE_NAME`.

Oba atrybuty zawierają 4 znaczniki czasu: **modyfikacji**, **dostępu**, **utworzenia** i **modyfikacji rejestru MFT** (MACE lub MACB).

**Eksplorator Windows** i inne narzędzia wyświetlają informacje z **`$STANDARD_INFORMATION`**.

### TimeStomp - narzędzie antyforensyczne

To narzędzie **modyfikuje** informacje o znacznikach czasu w **`$STANDARD_INFORMATION`**, **ale** **nie** informacje w **`$FILE_NAME`**. Dlatego można **zidentyfikować** **podejrzaną** **aktywność**.

### Usnjrnl

**Dziennik USN** (dziennik numerów sekwencyjnych aktualizacji) to funkcja NTFS (systemu plików Windows NT), która śledzi zmiany na woluminie. Narzędzie [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) umożliwia analizę tych zmian.

![TimeStomp - narzędzie antyforensyczne - Usnjrnl: Dziennik USN (dziennik numerów sekwencyjnych aktualizacji) to funkcja NTFS (systemu plików Windows NT), która śledzi zmiany na woluminie. ...](<../../images/image (801).png>)

Na poprzednim obrazie widać **wynik** działania **narzędzia**, w którym można zauważyć, że w pliku **wprowadzono pewne zmiany**.

### $LogFile

**Wszystkie zmiany metadanych w systemie plików są rejestrowane** w ramach procesu znanego jako [zapisywanie z wyprzedzeniem](https://en.wikipedia.org/wiki/Write-ahead_logging). Zarejestrowane metadane są przechowywane w pliku o nazwie `**$LogFile**`, znajdującym się w katalogu głównym systemu plików NTFS. Do analizy tego pliku i identyfikacji zmian można użyć narzędzi takich jak [LogFileParser](https://github.com/jschicht/LogFileParser).

![Usnjrnl - $LogFile: Wszystkie zmiany metadanych w systemie plików są rejestrowane w ramach procesu znanego jako zapisywanie z wyprzedzeniem. Zarejestrowane metadane są przechowywane w pliku o nazwie $LogFile , znajdującym się w katalogu głównym...](<../../images/image (137).png>)

Ponownie, w wynikach działania narzędzia można zobaczyć, że **wprowadzono pewne zmiany**.

Za pomocą tego samego narzędzia można ustalić, **na jaki czas zmieniono znaczniki czasu**:

![Usnjrnl - $LogFile: Za pomocą tego samego narzędzia można ustalić, na jaki czas zmieniono znaczniki czasu](<../../images/image (1089).png>)

- CTIME: czas utworzenia pliku
- ATIME: czas modyfikacji pliku
- MTIME: czas modyfikacji rejestru MFT pliku
- RTIME: czas dostępu do pliku

### Porównanie `$STANDARD_INFORMATION` i `$FILE_NAME`

Innym sposobem identyfikacji podejrzanie zmodyfikowanych plików jest porównanie czasu w obu atrybutach w poszukiwaniu **niezgodności**.

### Nanosekundy

Znaczniki czasu **NTFS** mają **precyzję** wynoszącą **100 nanosekund**. Dlatego znalezienie plików ze znacznikami czasu takimi jak 2010-10-10 10:10:**00.000:0000 jest bardzo podejrzane**.

### SetMace - narzędzie antyforensyczne

To narzędzie może modyfikować oba atrybuty: `$STARNDAR_INFORMATION` i `$FILE_NAME`. Jednak od systemu Windows Vista do modyfikacji tych informacji wymagany jest działający system operacyjny.

## Ukrywanie danych

NTFS używa klastrów i minimalnego rozmiaru informacji. Oznacza to, że jeśli plik zajmuje półtora klastra, **pozostała połowa nigdy nie zostanie wykorzystana**, dopóki plik nie zostanie usunięty. Można więc **ukrywać dane w tej wolnej przestrzeni**.

Istnieją narzędzia, takie jak slacker, które umożliwiają ukrywanie danych w tej „ukrytej” przestrzeni. Analiza `$logfile` i `$usnjrnl` może jednak ujawnić, że dodano dane:

![SetMace - narzędzie antyforensyczne - Ukrywanie danych: Istnieją narzędzia, takie jak slacker, które umożliwiają ukrywanie danych w tej „ukrytej” przestrzeni. Analiza $logfile i $usnjrnl może jednak ujawnić, że...](<../../images/image (1060).png>)

Wolną przestrzeń można następnie odzyskać za pomocą narzędzi takich jak FTK Imager. Należy pamiętać, że tego typu narzędzia mogą zapisywać zawartość w postaci zaciemnionej lub nawet zaszyfrowanej.

## UsbKill

To narzędzie **wyłączy komputer po wykryciu jakiejkolwiek zmiany w portach USB**.\
Można je wykryć, sprawdzając uruchomione procesy i **analizując każdy uruchomiony skrypt Pythona**.

## Dystrybucje Live Linux

Te dystrybucje są **uruchamiane w pamięci RAM**. Można je wykryć tylko wtedy, **gdy system plików NTFS jest zamontowany z uprawnieniami do zapisu**. Jeśli zostanie zamontowany wyłącznie z uprawnieniami do odczytu, wykrycie włamania nie będzie możliwe.

## Bezpieczne usuwanie

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

### Opóźnione samousuwanie w systemie Windows

Uruchomiony obraz systemu Windows może być zablokowany, dopóki jego proces jest aktywny. Proces może zlecić usunięcie procesowi potomnemu `cmd.exe`, użyć `choice` jako czasomierza i zakończyć działanie, zanim powłoka wykona polecenie `del`. Opóźnienie pozwala pierwotnemu procesowi zwolnić uchwyt do obrazu; jeśli pełna ścieżka zawiera spacje, należy ująć ją w cudzysłowy.<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

```cmd
cmd.exe /C choice /C Y /N /D Y /T 6 ^>nul ^& Del /F /Q "<full-path-of-current-executable>"
```

Gdy ten ciąg jest przekazywany bezpośrednio jako argument do `cmd.exe`, a nie wpisywany w innym interaktywnym wierszu polecenia `cmd`, użyj `&` zamiast `^&` oraz `>nul` zamiast `^>nul`. Usuwa to wpis katalogu; **nie jest to bezpieczne wymazywanie** i nie usuwa śladów wykonania, zadań, dziennika systemu plików ani innych śladów kryminalistycznych. Szukaj krótkotrwałych procesów potomnych `cmd.exe`, których wiersz polecenia łączy `choice /T`, `Del` i ścieżkę obrazu procesu nadrzędnego.<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

## Konfiguracja systemu Windows

Można wyłączyć kilka metod rejestrowania zdarzeń w Windows, aby znacznie utrudnić dochodzenie kryminalistyczne.

### Wyłącz znaczniki czasu - UserAssist

Jest to klucz rejestru przechowujący daty i godziny uruchomienia przez użytkownika poszczególnych plików wykonywalnych.

Wyłączenie UserAssist wymaga dwóch kroków:

1. Ustaw dwa klucze rejestru, `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` oraz `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`, na zero, aby wskazać, że UserAssist ma być wyłączony.
2. Wyczyść poddrzewa rejestru o nazwach podobnych do `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`.

### Wyłącz znaczniki czasu - Prefetch

Funkcja ta zapisuje informacje o uruchomionych aplikacjach, aby poprawić wydajność systemu Windows. Może być jednak również przydatna w badaniach kryminalistycznych.

- Uruchom `regedit`
- Wybierz ścieżkę pliku `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
- Kliknij prawym przyciskiem myszy zarówno `EnablePrefetcher`, jak i `EnableSuperfetch`
- Wybierz dla każdego z nich opcję Modify, aby zmienić wartość z 1 (lub 3) na 0
- Uruchom ponownie system

### Wyłącz znaczniki czasu - Last Access Time

Za każdym razem, gdy folder na woluminie NTFS jest otwierany na serwerze Windows NT, system **aktualizuje pole znacznika czasu w każdym wyświetlonym folderze**, nazywane czasem ostatniego dostępu. Na intensywnie używanym woluminie NTFS może to wpływać na wydajność.

1. Otwórz Edytor rejestru (Regedit.exe).
2. Przejdź do `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`.
3. Poszukaj `NtfsDisableLastAccessUpdate`. Jeśli nie istnieje, dodaj tę wartość DWORD i ustaw ją na 1, aby wyłączyć ten proces.
4. Zamknij Edytor rejestru i uruchom ponownie serwer.

### Usuń historię USB

Wszystkie **wpisy urządzeń USB** są przechowywane w rejestrze systemu Windows pod kluczem **USBSTOR**. Zawiera on podklucze tworzone po podłączeniu urządzenia USB do komputera stacjonarnego lub laptopa. Ten klucz znajduje się tutaj: H`KEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Usunięcie go** spowoduje skasowanie historii USB.\
Możesz też użyć narzędzia [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html), aby upewnić się, że wpisy zostały usunięte (i je usunąć).

Innym plikiem przechowującym informacje o urządzeniach USB jest `setupapi.dev.log` w folderze `C:\Windows\INF`. Ten plik również należy usunąć.

### Wyłącz kopie w tle

**Wyświetl** kopie w tle za pomocą `vssadmin list shadowstorage`\
**Usuń** je, uruchamiając `vssadmin delete shadow`

Możesz je również usunąć przez GUI, wykonując kroki opisane na stronie [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)

Aby wyłączyć kopie w tle, wykonaj [kroki opisane tutaj](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows):

1. Otwórz program Usługi, wpisując „services” w polu wyszukiwania tekstowego po kliknięciu przycisku Start systemu Windows.
2. Na liście znajdź „Volume Shadow Copy”, zaznacz tę pozycję, a następnie otwórz Właściwości, klikając ją prawym przyciskiem myszy.
3. Z listy rozwijanej „Typ uruchomienia” wybierz opcję Disabled, a następnie zatwierdź zmianę, klikając Apply i OK.

Można również zmienić w rejestrze konfigurację plików kopiowanych do kopii w tle: `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`

### Nadpisywanie usuniętych plików

- Możesz użyć **narzędzia Windows**: `cipher /w:C`. Polecenie to nakaże cipher usunąć wszystkie dane z dostępnego, nieużywanego miejsca na dysku C.
- Możesz też użyć narzędzi takich jak [**Eraser**](https://eraser.heidi.ie)

### Usuwanie dzienników zdarzeń Windows

- Windows + R --> eventvwr.msc --> Rozwiń „Dzienniki systemu Windows” --> Kliknij prawym przyciskiem myszy każdą kategorię i wybierz „Wyczyść dziennik”
- `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
- `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

### Wyłącz dzienniki zdarzeń Windows

- `reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\eventlog' /v Start /t REG_DWORD /d 4 /f`
- W sekcji usług wyłącz usługę „Windows Event Log”
- `WEvtUtil.exec clear-log` lub `WEvtUtil.exe cl`

### Wyłącz $UsnJrnl

- `fsutil usn deletejournal /d c:`

---

## Zaawansowane modyfikowanie dzienników i śladów (2023-2025)

### Rejestrowanie skryptów i modułów PowerShell

Nowsze wersje Windows 10/11 i Windows Server przechowują **obszerne artefakty kryminalistyczne PowerShell** w lokalizacji
`Microsoft-Windows-PowerShell/Operational` (zdarzenia 4104/4105/4106).  
Atakujący mogą je wyłączyć lub usunąć na bieżąco:

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

Obrońcy powinni monitorować zmiany tych kluczy rejestru i masowe usuwanie zdarzeń PowerShell.

### ETW (Event Tracing for Windows) Patch

Produkty zabezpieczające punkty końcowe w dużym stopniu polegają na ETW. Popularna metoda omijania zabezpieczeń z 2024 roku polega na patchowaniu `ntdll!EtwEventWrite`/`EtwEventWriteFull` w pamięci, tak aby każde wywołanie ETW zwracało `STATUS_SUCCESS` bez emitowania zdarzenia:<sup>[[5]](#references)</sup>

```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
                   GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
                   patch, sizeof(patch), NULL);
```

Publiczne PoC (np. `EtwTiSwallow`) implementują ten sam mechanizm w PowerShellu lub C++.  
Ponieważ poprawka działa **lokalnie w obrębie procesu**, EDR-y działające w innych procesach mogą jej nie wykryć.<sup>[[5]](#references)</sup>
Wykrywanie: porównaj `ntdll` w pamięci z wersją na dysku lub zainstaluj hook przed przejściem do trybu użytkownika.

### Powrót Alternate Data Streams (ADS)

W kampaniach malware z 2023 r. (np. loaderach **FIN12**) zaobserwowano umieszczanie plików binarnych drugiego etapu w ADS, aby ukryć je przed tradycyjnymi skanerami:

```cmd
rem Hide cobalt.bin inside an ADS of a PDF
type cobalt.bin > report.pdf:win32res.dll
rem Execute directly
wmic process call create "cmd /c report.pdf:win32res.dll"
```

Wylicz strumienie za pomocą `dir /R`, `Get-Item -Stream *` lub Sysinternals `streams64.exe`.
Skopiowanie pliku hosta na FAT/exFAT lub przez SMB usunie ukryty strumień i może umożliwić
śledczym odzyskanie payloadu.

### BYOVD & „AuKill” (2023)

Bring-Your-Own-Vulnerable-Driver jest obecnie rutynowo wykorzystywane do **antyforensics** podczas
ataków ransomware.  
Narzędzie open source **AuKill** ładuje podpisany, ale podatny sterownik (`procexp152.sys`), aby
zawiesić lub zakończyć działanie EDR i czujników kryminalistycznych **przed szyfrowaniem i niszczeniem logów**:<sup>[[1]](#references)</sup>

```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```

Sterownik jest następnie usuwany, pozostawiając minimalną liczbę artefaktów.<sup>[[1]](#references)</sup>  
Środki zaradcze: włącz listę blokowanych podatnych sterowników Microsoftu (HVCI/SAC)
i generuj alerty o tworzeniu usług jądra z zapisywalnych przez użytkownika ścieżek.

---

## Linux Anti-Forensics: Self-Patching and Cloud C2 (2023–2025)

### Self-patching zaatakowanych usług w celu ograniczenia wykrywania (Linux)
Atakujący coraz częściej wykonują self-patch usługi zaraz po jej wykorzystaniu, aby zarówno zapobiec ponownemu wykorzystaniu podatności, jak i ograniczyć wykrywanie oparte na podatnościach. Polega to na zastąpieniu podatnych komponentów najnowszymi, legalnymi binariami/JAR-ami upstream, tak aby skanery zgłaszały, że host jest zaktualizowany, podczas gdy mechanizmy persistence i C2 pozostają aktywne.<sup>[[3]](#references)</sup>

Przykład: Apache ActiveMQ OpenWire RCE (CVE‑2023‑46604).<sup>[[3]](#references)[[4]](#references)</sup>
- Po uzyskaniu dostępu atakujący pobrali legalne JAR-y z Maven Central (repo1.maven.org), usunęli podatne JAR-y z instalacji ActiveMQ i ponownie uruchomili broker.
- Zamknęło to początkową ścieżkę RCE, a jednocześnie pozostawiło inne punkty dostępu (cron, zmiany konfiguracji SSH, oddzielne implanty C2).

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

Wskazówki dotyczące analizy śledczej i wyszukiwania zagrożeń
- Sprawdź katalogi usług pod kątem nieplanowanych podmian plików binarnych/JAR:
  - Debian/Ubuntu: `dpkg -V activemq` i porównaj hashe/ścieżki plików z mirrorami repozytoriów.
  - RHEL/CentOS: `rpm -Va 'activemq*'`
  - Szukaj wersji JAR obecnych na dysku, których nie ma w bazie menedżera pakietów, lub dowiązań symbolicznych zmienionych poza standardowym procesem.
- Oś czasu: `find "$AMQ_DIR" -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort` — skoreluj ctime/mtime z okresem naruszenia bezpieczeństwa.
- Historia powłoki/telemetria procesów: ślady użycia `curl`/`wget` do `repo1.maven.org` lub innych CDN-ów z artefaktami bezpośrednio po początkowej eksploatacji.
- Zarządzanie zmianami: sprawdź, kto zastosował „łatkę” i dlaczego, a nie tylko to, czy obecna jest załatana wersja.

### C2 przez usługi chmurowe z tokenami bearer i stagerami utrudniającymi analizę
Zaobserwowane tradecraft łączyło kilka długotrwałych ścieżek C2 z opakowaniem utrudniającym analizę:<sup>[[3]](#references)</sup>
- Chronione hasłem loadery ELF utworzone za pomocą PyInstaller, utrudniające sandboxing i analizę statyczną (np. zaszyfrowany PYZ, tymczasowe rozpakowywanie w `/_MEI*`).
  - Wskaźniki: wyniki `strings`, takie jak `PyInstaller`, `pyi-archive`, `PYZ-00.pyz`, `MEIPASS`.
  - Artefakty działania: rozpakowywanie do `/tmp/_MEI*` lub niestandardowych ścieżek `--runtime-tmpdir`.
- C2 oparte na Dropbox z zakodowanymi na stałe tokenami OAuth Bearer.
  - Wskaźniki sieciowe: `api.dropboxapi.com` / `content.dropboxapi.com` z `Authorization: Bearer <token>`.
  - Szukaj w proxy/NetFlow/Zeek/Suricata wychodzącego ruchu HTTPS do domen Dropbox z obciążeń serwerowych, które zwykle nie synchronizują plików.
- Równoległe/zapasowe C2 przez tunelowanie (np. Cloudflare Tunnel `cloudflared`), zapewniające kontrolę, jeśli jeden kanał zostanie zablokowany.
  - Hostowe IOC: procesy/jednostki `cloudflared`, konfiguracja w `~/.cloudflared/*.json`, wychodzący ruch na porcie 443 do węzłów brzegowych Cloudflare.

### Utrzymywanie dostępu przez mechanizmy trwałości i „cofanie utwardzania zabezpieczeń” (przykłady dla Linuksa)
Atakujący często łączą samodzielne łatanie z trwałymi ścieżkami dostępu:<sup>[[3]](#references)</sup>
- Cron/Anacron: modyfikacje pliku pośredniczącego `0anacron` w każdym katalogu `/etc/cron.*/` w celu okresowego uruchamiania.
  - Szukaj:
    ```bash
    for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done
    grep -R --line-number -E 'curl|wget|python|/bin/sh' /etc/cron.*/* 2>/dev/null
    ```
- Wycofanie hardeningu konfiguracji SSH: włączenie logowania roota i zmiana domyślnych powłok kont o niskich uprawnieniach.
  - Poszukaj włączenia logowania roota:
    ```bash
    grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config
    # flag values like "yes" or overly permissive settings
    ```
  - Szukaj podejrzanych powłok interaktywnych na kontach systemowych (np. `games`):
    ```bash
    awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
    ```
- Losowe artefakty beacon o krótkich nazwach (8 liter), zapisywane na dysku i łączące się z cloud C2:
  - Wyszukiwanie:
    ```bash
    find / -maxdepth 3 -type f -regextype posix-extended -regex '.*/[A-Za-z]{8}$' \
      -exec stat -c '%n %s %y' {} \; 2>/dev/null | sort
    ```

Obrońcy powinni korelować te artefakty z ekspozycją na zagrożenia zewnętrzne i zdarzeniami aktualizacji usług, aby wykrywać samonaprawianie się w ramach anti-forensics, stosowane do ukrywania początkowego wykorzystania podatności.

## References

- [1] [Sophos X-Ops – AuKill: uzbrojony podatny sterownik służący do wyłączania EDR (marzec 2023)](https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr)
- [2] [Red Canary – Patchowanie EtwEventWrite w celu zapewnienia skrytości: wykrywanie i hunting (czerwiec 2024)](https://redcanary.com/blog/etw-patching-detection)
- [3] [Red Canary – Patchowanie w celu utrzymania dostępu: jak malware DripDropper dla Linuksa rozprzestrzenia się w chmurze](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [4] [CVE‑2023‑46604 – RCE w Apache ActiveMQ OpenWire (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)
- [5] [Ukrywanie .NET — ETW (Adam Chester / XPN)](https://blog.xpnsec.com/hiding-your-dotnet-etw/)
- [6] [FortiGuard Labs – Odkrycie wariantu SectopRAT osadzonego w legalnym oprogramowaniu](https://www.fortinet.com/blog/threat-research/uncovering-a-sectoprat-variant-embedded-in-legitimate-software)
- [7] [Microsoft Learn – polecenie choice](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/choice)
- [8] [Microsoft Learn – polecenie del](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/del)
{{#include ../../banners/hacktricks-training.md}}
