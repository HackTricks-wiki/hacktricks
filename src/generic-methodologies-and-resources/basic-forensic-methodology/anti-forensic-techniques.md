# Techniki Antyforensyczne

{{#include ../../banners/hacktricks-training.md}}

## Znaczniki Czasu

Atakujący może być zainteresowany **zmianą znaczników czasu plików**, aby uniknąć wykrycia.\
Możliwe jest znalezienie znaczników czasu w MFT w atrybutach `$STANDARD_INFORMATION` \_\_ i \_\_ `$FILE_NAME`.

Oba atrybuty mają 4 znaczniki czasu: **Modyfikacja**, **dostęp**, **tworzenie** i **modyfikacja rejestru MFT** (MACE lub MACB).

**Eksplorator Windows** i inne narzędzia pokazują informacje z **`$STANDARD_INFORMATION`**.

### TimeStomp - Narzędzie Antyforensyczne

To narzędzie **modyfikuje** informacje o znaczniku czasu wewnątrz **`$STANDARD_INFORMATION`**, **ale** **nie** modyfikuje informacji wewnątrz **`$FILE_NAME`**. Dlatego możliwe jest **zidentyfikowanie** **podejrzanej** **aktywności**.

### Usnjrnl

**Dziennik USN** (Dziennik Numeru Sekwencyjnego Aktualizacji) to funkcja systemu plików NTFS (Windows NT), która śledzi zmiany w woluminie. Narzędzie [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) umożliwia badanie tych zmian.

![](<../../images/image (801).png>)

Poprzedni obrazek to **wyjście** pokazane przez **narzędzie**, gdzie można zaobserwować, że **wprowadzono pewne zmiany** w pliku.

### $LogFile

**Wszystkie zmiany metadanych w systemie plików są rejestrowane** w procesie znanym jako [logowanie przed zapisaniem](https://en.wikipedia.org/wiki/Write-ahead_logging). Zarejestrowane metadane są przechowywane w pliku o nazwie `**$LogFile**`, znajdującym się w katalogu głównym systemu plików NTFS. Narzędzia takie jak [LogFileParser](https://github.com/jschicht/LogFileParser) mogą być używane do analizy tego pliku i identyfikacji zmian.

![](<../../images/image (137).png>)

Ponownie, w wyjściu narzędzia można zobaczyć, że **wprowadzono pewne zmiany**.

Używając tego samego narzędzia, można zidentyfikować, **do którego czasu zmieniono znaczniki czasu**:

![](<../../images/image (1089).png>)

- CTIME: Czas utworzenia pliku
- ATIME: Czas modyfikacji pliku
- MTIME: Modyfikacja rejestru MFT pliku
- RTIME: Czas dostępu do pliku

### Porównanie `$STANDARD_INFORMATION` i `$FILE_NAME`

Innym sposobem na zidentyfikowanie podejrzanych zmodyfikowanych plików byłoby porównanie czasu w obu atrybutach w poszukiwaniu **rozbieżności**.

### Nanosekundy

**Znaczniki czasu NTFS** mają **precyzję** **100 nanosekund**. Dlatego znalezienie plików z znacznikami czasu takimi jak 2010-10-10 10:10:**00.000:0000 jest bardzo podejrzane**.

### SetMace - Narzędzie Antyforensyczne

To narzędzie może modyfikować oba atrybuty `$STARNDAR_INFORMATION` i `$FILE_NAME`. Jednak od Windows Vista, konieczne jest, aby system operacyjny na żywo modyfikował te informacje.

## Ukrywanie Danych

NFTS używa klastra i minimalnego rozmiaru informacji. Oznacza to, że jeśli plik zajmuje i używa klastra i pół, **pozostała połowa nigdy nie będzie używana** aż do usunięcia pliku. Wtedy możliwe jest **ukrycie danych w tej przestrzeni luzem**.

Istnieją narzędzia takie jak slacker, które pozwalają na ukrywanie danych w tej "ukrytej" przestrzeni. Jednak analiza `$logfile` i `$usnjrnl` może pokazać, że dodano pewne dane:

![](<../../images/image (1060).png>)

Wtedy możliwe jest odzyskanie przestrzeni luzem za pomocą narzędzi takich jak FTK Imager. Należy zauważyć, że tego rodzaju narzędzie może zapisać zawartość w sposób zniekształcony lub nawet zaszyfrowany.

## UsbKill

To narzędzie, które **wyłączy komputer, jeśli wykryje jakiekolwiek zmiany w portach USB**.\
Sposobem na odkrycie tego byłoby sprawdzenie uruchomionych procesów i **przejrzenie każdego uruchomionego skryptu Pythona**.

## Dystrybucje Live Linux

Te dystrybucje są **uruchamiane w pamięci RAM**. Jedynym sposobem na ich wykrycie jest **jeśli system plików NTFS jest zamontowany z uprawnieniami do zapisu**. Jeśli jest zamontowany tylko z uprawnieniami do odczytu, nie będzie możliwe wykrycie intruzji.

## Bezpieczne Usuwanie

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

## Konfiguracja Windows

Możliwe jest wyłączenie kilku metod logowania w Windows, aby znacznie utrudnić dochodzenie forensyczne.

### Wyłącz Znaczniki Czasu - UserAssist

To klucz rejestru, który utrzymuje daty i godziny, kiedy każdy plik wykonywalny był uruchamiany przez użytkownika.

Wyłączenie UserAssist wymaga dwóch kroków:

1. Ustawienie dwóch kluczy rejestru, `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` i `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`, oba na zero, aby sygnalizować, że chcemy wyłączyć UserAssist.
2. Wyczyść swoje poddrzewa rejestru, które wyglądają jak `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`.

### Wyłącz Znaczniki Czasu - Prefetch

To zapisze informacje o aplikacjach uruchamianych w celu poprawy wydajności systemu Windows. Jednak może to być również przydatne w praktykach forensycznych.

- Uruchom `regedit`
- Wybierz ścieżkę pliku `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
- Kliknij prawym przyciskiem myszy na `EnablePrefetcher` i `EnableSuperfetch`
- Wybierz Modyfikuj dla każdego z nich, aby zmienić wartość z 1 (lub 3) na 0
- Uruchom ponownie

### Wyłącz Znaczniki Czasu - Czas Ostatniego Dostępu

Kiedy folder jest otwierany z woluminu NTFS na serwerze Windows NT, system zajmuje czas na **aktualizację pola znacznika czasu w każdym wymienionym folderze**, nazywanego czasem ostatniego dostępu. Na mocno używanym woluminie NTFS może to wpływać na wydajność.

1. Otwórz Edytor rejestru (Regedit.exe).
2. Przejdź do `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`.
3. Poszukaj `NtfsDisableLastAccessUpdate`. Jeśli nie istnieje, dodaj ten DWORD i ustaw jego wartość na 1, co wyłączy ten proces.
4. Zamknij Edytor rejestru i uruchom ponownie serwer.

### Usuń Historię USB

Wszystkie **Wpisy Urządzeń USB** są przechowywane w rejestrze Windows pod kluczem **USBSTOR**, który zawiera podklucze tworzone za każdym razem, gdy podłączasz urządzenie USB do swojego komputera lub laptopa. Możesz znaleźć ten klucz tutaj `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Usunięcie tego** spowoduje usunięcie historii USB.\
Możesz również użyć narzędzia [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html), aby upewnić się, że je usunięto (i aby je usunąć).

Innym plikiem, który zapisuje informacje o USB, jest plik `setupapi.dev.log` w `C:\Windows\INF`. Ten plik również powinien zostać usunięty.

### Wyłącz Kopie Cieni

**Wylistuj** kopie cieni za pomocą `vssadmin list shadowstorage`\
**Usuń** je, uruchamiając `vssadmin delete shadow`

Możesz również usunąć je za pomocą GUI, postępując zgodnie z krokami opisanymi w [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)

Aby wyłączyć kopie cieni, [kroki stąd](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows):

1. Otwórz program Usługi, wpisując "usługi" w polu wyszukiwania tekstu po kliknięciu przycisku start w Windows.
2. Z listy znajdź "Kopia Cienia Woluminu", wybierz ją, a następnie uzyskaj dostęp do Właściwości, klikając prawym przyciskiem myszy.
3. Wybierz Wyłączone z rozwijanego menu "Typ uruchomienia", a następnie potwierdź zmianę, klikając Zastosuj i OK.

Możliwe jest również modyfikowanie konfiguracji, które pliki mają być kopiowane w kopii cienia w rejestrze `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`

### Nadpisz usunięte pliki

- Możesz użyć **narzędzia Windows**: `cipher /w:C` To spowoduje, że cipher usunie wszelkie dane z dostępnej nieużywanej przestrzeni dyskowej wewnątrz dysku C.
- Możesz również użyć narzędzi takich jak [**Eraser**](https://eraser.heidi.ie)

### Usuń dzienniki zdarzeń Windows

- Windows + R --> eventvwr.msc --> Rozwiń "Dzienniki Windows" --> Kliknij prawym przyciskiem myszy na każdą kategorię i wybierz "Wyczyść dziennik"
- `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
- `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

### Wyłącz dzienniki zdarzeń Windows

- `reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\eventlog' /v Start /t REG_DWORD /d 4 /f`
- W sekcji usług wyłącz usługę "Dziennik Zdarzeń Windows"
- `WEvtUtil.exec clear-log` lub `WEvtUtil.exe cl`

### Wyłącz $UsnJrnl

- `fsutil usn deletejournal /d c:`

---

## Zaawansowane Logowanie i Manipulacja Śladami (2023-2025)

### Logowanie Skryptów/Modułów PowerShell

Najnowsze wersje Windows 10/11 i Windows Server przechowują **bogate artefakty forensyczne PowerShell** w
`Microsoft-Windows-PowerShell/Operational` (zdarzenia 4104/4105/4106).
Atakujący mogą je wyłączyć lub usunąć w locie:
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
Obrońcy powinni monitorować zmiany w tych kluczach rejestru oraz wysoką ilość usunięć zdarzeń PowerShell.

### Łatka ETW (Event Tracing for Windows)

Produkty zabezpieczeń punktów końcowych w dużym stopniu polegają na ETW. Popularną metodą unikania wykrycia w 2024 roku jest
łatkowanie `ntdll!EtwEventWrite`/`EtwEventWriteFull` w pamięci, aby każde wywołanie ETW zwracało `STATUS_SUCCESS`
bez emitowania zdarzenia:
```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
patch, sizeof(patch), NULL);
```
Publiczne PoCs (np. `EtwTiSwallow`) implementują tę samą prymitywę w PowerShell lub C++.  
Ponieważ łatka jest **lokalna dla procesu**, EDR-y działające w innych procesach mogą ją przeoczyć.  
Wykrywanie: porównaj `ntdll` w pamięci z tym na dysku lub zainstaluj hook przed trybem użytkownika.

### Odrodzenie Alternatywnych Strumieni Danych (ADS)

Kampanie złośliwego oprogramowania w 2023 roku (np. **FIN12** loadery) były widziane, gdy przygotowywały binaria drugiego etapu wewnątrz ADS, aby pozostać poza zasięgiem tradycyjnych skanerów:
```cmd
rem Hide cobalt.bin inside an ADS of a PDF
type cobalt.bin > report.pdf:win32res.dll
rem Execute directly
wmic process call create "cmd /c report.pdf:win32res.dll"
```
Enumeruj strumienie za pomocą `dir /R`, `Get-Item -Stream *` lub Sysinternals `streams64.exe`. Skopiowanie pliku hosta do FAT/exFAT lub przez SMB usunie ukryty strumień i może być użyte przez śledczych do odzyskania ładunku.

### BYOVD & “AuKill” (2023)

Bring-Your-Own-Vulnerable-Driver jest teraz rutynowo używany do **anti-forensics** w intruzjach ransomware. Narzędzie open-source **AuKill** ładuje podpisany, ale podatny sterownik (`procexp152.sys`), aby wstrzymać lub zakończyć EDR i czujniki forensyczne **przed szyfrowaniem i zniszczeniem logów**:
```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```
Sterownik jest usuwany później, pozostawiając minimalne artefakty.  
Środki zaradcze: włącz blokadę podatnych sterowników Microsoftu (HVCI/SAC) i powiadamiaj o tworzeniu usług jądra z ścieżek zapisywalnych przez użytkownika.

---

## Linux Anti-Forensics: Samopatchowanie i Cloud C2 (2023–2025)

### Samopatchowanie skompromitowanych usług w celu zmniejszenia wykrywalności (Linux)  
Przeciwnicy coraz częściej „samopatchują” usługę tuż po jej wykorzystaniu, aby zapobiec ponownemu wykorzystaniu i stłumić wykrycia oparte na podatnościach. Idea polega na zastąpieniu podatnych komponentów najnowszymi legalnymi binariami/JAR-ami z upstream, aby skanery zgłaszały hosta jako załatwionego, podczas gdy trwałość i C2 pozostają.

Przykład: Apache ActiveMQ OpenWire RCE (CVE‑2023‑46604)  
- Po wykorzystaniu, napastnicy pobrali legalne JAR-y z Maven Central (repo1.maven.org), usunęli podatne JAR-y w instalacji ActiveMQ i ponownie uruchomili brokera.  
- To zamknęło początkowe RCE, jednocześnie utrzymując inne punkty dostępu (cron, zmiany w konfiguracji SSH, oddzielne implanty C2).

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
Forensic/hunting tips
- Przejrzyj katalogi usług w poszukiwaniu nieschedułowanych zamienników binarnych/JAR:
- Debian/Ubuntu: `dpkg -V activemq` i porównaj hashe/ścieżki plików z lustrami repozytoriów.
- RHEL/CentOS: `rpm -Va 'activemq*'`
- Szukaj wersji JAR obecnych na dysku, które nie są własnością menedżera pakietów, lub zaktualizowanych linków symbolicznych.
- Oś czasu: `find "$AMQ_DIR" -type f -printf '%TY-%Tm-%Td %TH:%TM %p\n' | sort` w celu skorelowania ctime/mtime z oknem kompromitacji.
- Historia powłoki/telemetria procesów: dowody użycia `curl`/`wget` do `repo1.maven.org` lub innych CDN artefaktów bezpośrednio po początkowej eksploatacji.
- Zarządzanie zmianami: zweryfikuj, kto zastosował „łatkę” i dlaczego, a nie tylko, że obecna jest wersja z poprawką.

### Cloud‑service C2 with bearer tokens and anti‑analysis stagers
Obserwowana technika łączyła wiele długodystansowych ścieżek C2 i pakowanie antyanalizacyjne:
- Ładowarki ELF PyInstaller chronione hasłem, aby utrudnić sandboxing i analizę statyczną (np. zaszyfrowany PYZ, tymczasowe wydobycie pod `/_MEI*`).
- Wskaźniki: trafienia `strings` takie jak `PyInstaller`, `pyi-archive`, `PYZ-00.pyz`, `MEIPASS`.
- Artefakty czasu wykonywania: wydobycie do `/tmp/_MEI*` lub niestandardowe ścieżki `--runtime-tmpdir`.
- C2 wspierane przez Dropbox z zakodowanymi tokenami OAuth Bearer
- Markery sieciowe: `api.dropboxapi.com` / `content.dropboxapi.com` z `Authorization: Bearer <token>`.
- Poluj w proxy/NetFlow/Zeek/Suricata na wychodzące HTTPS do domen Dropbox z obciążeń serwera, które normalnie nie synchronizują plików.
- Równoległe/zapasowe C2 przez tunelowanie (np. Cloudflare Tunnel `cloudflared`), utrzymując kontrolę, jeśli jeden kanał jest zablokowany.
- IOCs hosta: procesy/jednostki `cloudflared`, konfiguracja w `~/.cloudflared/*.json`, wychodzące 443 do krawędzi Cloudflare.

### Persistence and “hardening rollback” to maintain access (Linux examples)
Napastnicy często łączą samodzielne łatanie z trwałymi ścieżkami dostępu:
- Cron/Anacron: edycje stubu `0anacron` w każdym katalogu `/etc/cron.*/` dla okresowego wykonywania.
- Poluj:
```bash
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done
grep -R --line-number -E 'curl|wget|python|/bin/sh' /etc/cron.*/* 2>/dev/null
```
- Przywracanie twardości konfiguracji SSH: włączanie logowania roota i zmiana domyślnych powłok dla kont o niskich uprawnieniach.
- Poluj na włączenie logowania roota:
```bash
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config
# wartości flag takie jak "yes" lub zbyt liberalne ustawienia
```
- Poluj na podejrzane interaktywne powłoki na kontach systemowych (np. `games`):
```bash
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
- Losowe, krótko nazwane artefakty sygnalizacyjne (8 liter) umieszczane na dysku, które również kontaktują się z chmurą C2:
- Poluj:
```bash
find / -maxdepth 3 -type f -regextype posix-extended -regex '.*/[A-Za-z]{8}$' \
-exec stat -c '%n %s %y' {} \; 2>/dev/null | sort
```

Obrońcy powinni skorelować te artefakty z zewnętrzną ekspozycją i wydarzeniami łatania usług, aby odkryć samoremediację antyforensyczną używaną do ukrycia początkowej eksploatacji.

## References

- Sophos X-Ops – “AuKill: A Weaponized Vulnerable Driver for Disabling EDR” (March 2023)
https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr
- Red Canary – “Patching EtwEventWrite for Stealth: Detection & Hunting” (June 2024)
https://redcanary.com/blog/etw-patching-detection

- [Red Canary – Patching for persistence: How DripDropper Linux malware moves through the cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [CVE‑2023‑46604 – Apache ActiveMQ OpenWire RCE (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)

{{#include ../../banners/hacktricks-training.md}}
