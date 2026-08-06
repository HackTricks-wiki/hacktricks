# Zaštite Windows akreditiva

{{#include ../../banners/hacktricks-training.md}}

## WDigest

Protokol [WDigest](<https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396>), uveden sa operativnim sistemom Windows XP, namenjen je autentikaciji putem HTTP protokola i **podrazumevano je omogućen na operativnim sistemima Windows XP do Windows 8.0 i Windows Server 2003 do Windows Server 2012**. Ova podrazumevana postavka dovodi do **čuvanja lozinki u čistom tekstu u LSASS-u** (Local Security Authority Subsystem Service). Napadač može da koristi Mimikatz za **izvlačenje ovih akreditiva** izvršavanjem:<sup>[[8]](#references)</sup>
```bash
sekurlsa::wdigest
```
Da biste **isključili ili uključili ovu funkciju**, ključevi registra _**UseLogonCredential**_ i _**Negotiate**_ unutar _**HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_ moraju biti postavljeni na „1“. Ako ovi ključevi **ne postoje ili su postavljeni na „0“**, WDigest je **onemogućen**:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## LSA zaštita (procesi zaštićeni pomoću PP i PPL)

**Protected Process (PP)** i **Protected Process Light (PPL)** su **zaštite na nivou Windows kernela** osmišljene da spreče neovlašćen pristup osetljivim procesima kao što je **LSASS**. Uveden u **Windows Vista**, **PP model** je prvobitno kreiran za sprovođenje **DRM** pravila i dozvoljavao je zaštitu samo binarnim datotekama potpisanim pomoću **posebnog medijskog sertifikata**. Proces označen kao **PP** mogu da pristupe samo drugi procesi koji su takođe **PP** i imaju **jednak ili viši nivo zaštite**, a čak i tada, **samo sa ograničenim pravima pristupa**, osim ako pristup nije posebno dozvoljen.

**PPL**, uveden u **Windows 8.1**, fleksibilnija je verzija sistema PP. Omogućava **širu primenu** (npr. LSASS, Defender) uvođenjem **„nivoa zaštite“** zasnovanih na polju **EKU (Enhanced Key Usage)** digitalnog potpisa. Nivo zaštite se čuva u polju `EPROCESS.Protection`, koje je struktura `PS_PROTECTION` sa sledećim elementima:
- **Type** (`Protected` ili `ProtectedLight`)
- **Signer** (npr. `WinTcb`, `Lsa`, `Antimalware` itd.)

Ova struktura je upakovana u jedan bajt i određuje **ko može da pristupi kome**:
- **Više vrednosti signer-a mogu da pristupe nižim vrednostima**
- **PPL procesi ne mogu da pristupe PP procesima**
- **Nezaštićeni procesi ne mogu da pristupe nijednom PPL/PP procesu**

### Šta treba da znate iz ofanzivne perspektive

- Kada **LSASS radi kao PPL**, pokušaji otvaranja pomoću `OpenProcess(PROCESS_VM_READ | QUERY_INFORMATION)` iz normalnog administratorskog konteksta **ne uspevaju uz grešku `0x5 (Access Denied)`**, čak i kada je `SeDebugPrivilege` omogućen.
- **Nivo zaštite LSASS-a** možete proveriti pomoću alata kao što je Process Hacker ili programski, čitanjem vrednosti `EPROCESS.Protection`.
- LSASS će obično imati `PsProtectedSignerLsa-Light` (`0x41`), čemu mogu da pristupe **samo procesi potpisani pomoću signer-a višeg nivoa**, kao što je `WinTcb` (`0x61` ili `0x62`).
- PPL je **ograničenje koje važi samo u Userland-u**; kod na nivou kernela može u potpunosti da ga zaobiđe.
- To što je LSASS PPL **ne sprečava dumpovanje credential-a** ako možete da izvršite kernel shellcode ili da iskoristite proces sa visokim privilegijama i odgovarajućim pristupom.
- **Postavljanje ili uklanjanje PPL-a** zahteva reboot ili podešavanja **Secure Boot/UEFI**, koja mogu da zadrže PPL podešavanje čak i nakon vraćanja izmena u registru.

### Kreiranje PPL procesa prilikom pokretanja (dokumentovani API)

Windows pruža dokumentovan način za zahtev za Protected Process Light nivo za child process tokom kreiranja, pomoću proširene liste atributa za pokretanje. Ovo ne zaobilazi zahteve za potpisivanje — ciljana image datoteka mora biti potpisana za zahtevanu signer klasu.

Minimalni tok u C/C++:
```c
// Request a PPL protection level for the child process at creation time
// Requires Windows 8.1+ and a properly signed image for the selected level
#include <windows.h>

int wmain(int argc, wchar_t **argv) {
STARTUPINFOEXW si = {0};
PROCESS_INFORMATION pi = {0};
si.StartupInfo.cb = sizeof(si);

SIZE_T attrSize = 0;
InitializeProcThreadAttributeList(NULL, 1, 0, &attrSize);
si.lpAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attrSize);
if (!si.lpAttributeList) return 1;

if (!InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attrSize)) return 1;

DWORD level = PROTECTION_LEVEL_ANTIMALWARE_LIGHT; // or WINDOWS_LIGHT/LSA_LIGHT/WINTCB_LIGHT
if (!UpdateProcThreadAttribute(
si.lpAttributeList, 0,
PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL,
&level, sizeof(level), NULL, NULL)) {
return 1;
}

DWORD flags = EXTENDED_STARTUPINFO_PRESENT;
if (!CreateProcessW(L"C\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE,
flags, NULL, NULL, &si.StartupInfo, &pi)) {
// If the image isn't signed appropriately for the requested level,
// CreateProcess will fail with ERROR_INVALID_IMAGE_HASH (577).
return 1;
}

// cleanup
DeleteProcThreadAttributeList(si.lpAttributeList);
HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
CloseHandle(pi.hThread);
CloseHandle(pi.hProcess);
return 0;
}
```
Napomene i ograničenja:
- Koristite `STARTUPINFOEX` sa `InitializeProcThreadAttributeList` i `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL, ...)`, a zatim prosledite `EXTENDED_STARTUPINFO_PRESENT` funkciji `CreateProcess*`.<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup>
- `DWORD` zaštite može biti postavljen na konstante kao što su `PROTECTION_LEVEL_WINTCB_LIGHT`, `PROTECTION_LEVEL_WINDOWS`, `PROTECTION_LEVEL_WINDOWS_LIGHT`, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` ili `PROTECTION_LEVEL_LSA_LIGHT`.
- Child se pokreće kao PPL samo ako je njegov image potpisan za tu signer klasu; u suprotnom kreiranje procesa ne uspeva, najčešće uz `ERROR_INVALID_IMAGE_HASH (577)` / `STATUS_INVALID_IMAGE_HASH (0xC0000428)`.
- Ovo nije bypass — u pitanju je podržani API namenjen odgovarajuće potpisanim image fajlovima. Korisno je za hardening alata ili proveru konfiguracija zaštićenih pomoću PPL-a.

Primer CLI-ja koji koristi minimalni loader:<sup>[[1]](#references)</sup>
- Antimalware signer: `CreateProcessAsPPL.exe 3 C:\Tools\agent.exe --svc`
- LSA-light signer: `CreateProcessAsPPL.exe 4 C:\Windows\System32\notepad.exe`

**Opcije za bypass PPL zaštite:**

Ako želite da uradite dump LSASS-a uprkos PPL-u, imate 3 glavne opcije:
1. **Koristite potpisani kernel driver (npr. Mimikatz + mimidrv.sys)** da biste **uklonili LSASS-ovu zastavicu zaštite**:

![Izlaz Mimikatz mimidrv driver-a koji prikazuje interakciju sa zaštitom kredencijala](../../images/mimidrv.png)

2. **Bring Your Own Vulnerable Driver (BYOVD)** da biste pokrenuli prilagođeni kernel code i onemogućili zaštitu. Alati kao što su **PPLKiller**, **gdrv-loader** ili **kdmapper** čine ovo izvodljivim.
3. **Ukradite postojeći LSASS handle** iz drugog procesa koji ga već ima otvorenog (npr. AV procesa), a zatim ga **duplicirajte** u svoj proces. Ovo je osnova tehnike `pypykatz live lsa --method handledup`.
4. **Zloupotrebite privilegovani proces** koji vam omogućava da učitate proizvoljni code u njegov address space ili unutar drugog privilegovanog procesa, čime se praktično zaobilaze PPL ograničenja. Primer ovoga možete pronaći u [bypassing-lsa-protection-in-userland](https://blog.scrt.ch/2021/04/22/bypassing-lsa-protection-in-userland/) ili na [https://github.com/itm4n/PPLdump](https://github.com/itm4n/PPLdump).

**Provera trenutnog statusa LSA zaštite (PPL/PP) za LSASS**:
```bash
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
Kada pokrenete **`mimikatz privilege::debug sekurlsa::logonpasswords`**, verovatno će doći do greške sa kodom `0x00000005` zbog ovoga.

- Za više informacija o ovoj proveri pogledajte [https://itm4n.github.io/lsass-runasppl/](https://itm4n.github.io/lsass-runasppl/)<sup>[[5]](#references)</sup>


## Credential Guard

**Credential Guard**, funkcija ekskluzivna za **Windows 10 (Enterprise i Education izdanja)**, poboljšava bezbednost akreditiva računara pomoću **Virtual Secure Mode (VSM)** i **Virtualization Based Security (VBS)**. Ona koristi CPU virtualization ekstenzije za izolovanje ključnih procesa unutar zaštićenog memorijskog prostora, van domašaja glavnog operativnog sistema. Ova izolacija obezbeđuje da čak ni kernel ne može da pristupi memoriji u VSM-u, čime se akreditivi efikasno štite od napada kao što je **pass-the-hash**. **Local Security Authority (LSA)** radi unutar ovog bezbednog okruženja kao trustlet, dok **LSASS** proces u glavnom OS-u služi samo kao komunikator sa LSA-om u VSM-u.

Po podrazumevanim podešavanjima, **Credential Guard** nije aktivan i zahteva ručnu aktivaciju unutar organizacije. On je ključan za poboljšanje zaštite od alata kao što je **Mimikatz**, kojima je otežano izvlačenje akreditiva. Međutim, ranjivosti se i dalje mogu iskoristiti dodavanjem prilagođenih **Security Support Providers (SSP)** za prikupljanje akreditiva u clear text formatu tokom pokušaja prijavljivanja.

Da biste proverili status aktivacije funkcije **Credential Guard**, možete pregledati ključ _**LsaCfgFlags**_ u okviru _**HKLM\System\CurrentControlSet\Control\LSA**_. Vrednost "**1**" označava aktivaciju sa **UEFI lock**, "**2**" aktivaciju bez zaključavanja, dok "**0**" označava da funkcija nije omogućena. Ova provera registra, iako predstavlja snažan pokazatelj, nije jedini korak za omogućavanje funkcije Credential Guard. Detaljna uputstva i PowerShell skripta za omogućavanje ove funkcije dostupni su online.
```bash
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
Za sveobuhvatno razumevanje i uputstva za omogućavanje **Credential Guard** u sistemu Windows 10, kao i za njegovo automatsko aktiviranje na kompatibilnim sistemima **Windows 11 Enterprise and Education (version 22H2)**, posetite [Microsoft-ovu dokumentaciju](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage).<sup>[[9]](#references)</sup>

Dodatne informacije o implementaciji prilagođenih SSP-ova za hvatanje credentials pružene su u [ovom vodiču](../active-directory-methodology/custom-ssp.md).

## RDP RestrictedAdmin Mode

**Windows 8.1 and Windows Server 2012 R2** uveli su nekoliko novih bezbednosnih funkcija, uključujući _**Restricted Admin mode for RDP**_. Ovaj režim je osmišljen za poboljšanje bezbednosti ublažavanjem rizika povezanih sa napadima [**pass the hash**](https://blog.ahasayen.com/pass-the-hash/).

Tradicionalno, prilikom povezivanja sa udaljenim računarom putem RDP-a, vaši credentials se čuvaju na ciljnoj mašini. To predstavlja značajan bezbednosni rizik, naročito kada se koriste nalozi sa povišenim privilegijama. Međutim, uvođenjem _**Restricted Admin mode**_, ovaj rizik je znatno smanjen.

Prilikom pokretanja RDP veze pomoću komande **mstsc.exe /RestrictedAdmin**, authentication na udaljenom računaru se obavlja bez čuvanja vaših credentials na njemu. Ovakav pristup obezbeđuje da, u slučaju malware infekcije ili ako zlonamerni korisnik dobije pristup udaljenom serveru, vaši credentials ne budu kompromitovani, jer se ne čuvaju na serveru.

Važno je napomenuti da se u **Restricted Admin mode** pokušaji pristupa network resources iz RDP sesije neće obavljati pomoću vaših ličnih credentials; umesto toga koristi se **machine's identity**.

Ova funkcija predstavlja značajan korak napred u zaštiti udaljenih desktop veza i sprečavanju izlaganja osetljivih informacija u slučaju bezbednosnog incidenta.

![Windows RAM memory diagram for credential extraction context](../../images/RAM.png)

Za detaljnije informacije posetite [ovaj resurs](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/).<sup>[[6]](#references)</sup>

## Cached Credentials

Windows štiti **domain credentials** putem komponente **Local Security Authority (LSA)**, pružajući podršku procesima prijavljivanja pomoću bezbednosnih protokola kao što su **Kerberos** i **NTLM**. Važna funkcija sistema Windows jeste mogućnost keširanja **poslednjih deset domain logins**, kako bi korisnici i dalje mogli da pristupe svojim računarima čak i kada je **domain controller offline** — što je naročito korisno za korisnike laptopova koji se često nalaze van mreže svoje kompanije.

Broj keširanih prijavljivanja može se podesiti putem određenog **registry key or group policy**. Za pregled ili promenu ove postavke koristi se sledeća komanda:
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
Pristup ovim keširanim akreditivima je strogo kontrolisan, pri čemu samo nalog **SYSTEM** ima potrebne dozvole za njihov pregled. Administratori kojima je potreban pristup ovim informacijama moraju to učiniti sa privilegijama SYSTEM korisnika. Akreditivi su sačuvani na lokaciji: `HKEY_LOCAL_MACHINE\SECURITY\Cache`

**Mimikatz** se može koristiti za izdvajanje ovih keširanih akreditiva pomoću komande `lsadump::cache`.

Za dodatne detalje, originalni [izvor](http://juggernaut.wikidot.com/cached-credentials) pruža sveobuhvatne informacije.<sup>[[7]](#references)</sup>

## Protected Users

Članstvo u grupi **Protected Users** uvodi nekoliko bezbednosnih unapređenja za korisnike, obezbeđujući viši nivo zaštite od krađe i zloupotrebe akreditiva:

- **Delegiranje akreditiva (CredSSP)**: Čak i ako je podešavanje Group Policy-ja za **Allow delegating default credentials** omogućeno, akreditivi Protected Users u čistom tekstu neće biti keširani.
- **Windows Digest**: Počev od **Windows 8.1 i Windows Server 2012 R2**, sistem neće keširati akreditive Protected Users u čistom tekstu, bez obzira na status Windows Digest-a.
- **NTLM**: Sistem neće keširati akreditive Protected Users u čistom tekstu niti njihove jednosmerne NT funkcije (NTOWF).
- **Kerberos**: Kod Protected Users korisnika, Kerberos autentifikacija neće generisati **DES** ili **RC4 ključeve**, niti će keširati akreditive u čistom tekstu ili dugoročne ključeve nakon početnog pribavljanja Ticket-Granting Ticket-a (TGT).
- **Prijavljivanje van mreže**: Za Protected Users korisnike, pri prijavljivanju ili otključavanju neće biti kreiran keširani verifikator, što znači da prijavljivanje van mreže nije podržano za ove naloge.

Ove zaštite se aktiviraju u trenutku kada se korisnik, koji je član grupe **Protected Users**, prijavi na uređaj. Time se obezbeđuje da su ključne bezbednosne mere na snazi radi zaštite od različitih metoda kompromitovanja akreditiva.

Za detaljnije informacije pogledajte zvaničnu [dokumentaciju](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group).<sup>[[10]](#references)</sup>

**Tabela iz** [**dokumentacije**](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)**.**<sup>[[11]](#references)</sup>

| Windows Server 2003 RTM | Windows Server 2003 SP1+ | <p>Windows Server 2012,<br>Windows Server 2008 R2,<br>Windows Server 2008</p> | Windows Server 2016          |
| ----------------------- | ------------------------ | ----------------------------------------------------------------------------- | ---------------------------- |
| Account Operators       | Account Operators        | Account Operators                                                             | Account Operators            |
| Administrator           | Administrator            | Administrator                                                                 | Administrator                |
| Administrators          | Administrators           | Administrators                                                                | Administrators               |
| Backup Operators        | Backup Operators         | Backup Operators                                                              | Backup Operators             |
| Cert Publishers         |                          |                                                                               |                              |
| Domain Admins           | Domain Admins            | Domain Admins                                                                 | Domain Admins                |
| Domain Controllers      | Domain Controllers       | Domain Controllers                                                            | Domain Controllers           |
| Enterprise Admins       | Enterprise Admins        | Enterprise Admins                                                             | Enterprise Admins            |
|                         |                          |                                                                               | Enterprise Key Admins        |
|                         |                          |                                                                               | Key Admins                   |
| Krbtgt                  | Krbtgt                   | Krbtgt                                                                        | Krbtgt                       |
| Print Operators         | Print Operators          | Print Operators                                                               | Print Operators              |
|                         |                          | Read-only Domain Controllers                                                  | Read-only Domain Controllers |
| Replicator              | Replicator               | Replicator                                                                    | Replicator                   |
| Schema Admins           | Schema Admins            | Schema Admins                                                                 | Schema Admins                |
| Server Operators        | Server Operators         | Server Operators                                                              | Server Operators             |

## Reference

- [1] [CreateProcessAsPPL – minimalni PPL process launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [2] [STARTUPINFOEX struktura (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-startupinfoexw)
- [3] [InitializeProcThreadAttributeList (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-initializeprocthreadattributelist)
- [4] [UpdateProcThreadAttribute (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)
- [5] [LSASS RunAsPPL – pozadina i interni detalji](https://itm4n.github.io/lsass-runasppl/)
- [6] [Restricted Admin Mode za RDP](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/)
- [7] [Keširani akreditivi - Juggernaut AppSec Wiki](http://juggernaut.wikidot.com/cached-credentials)
- [8] [WDigest Authentication (Microsoft TechNet)](<https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396>)
- [9] [Upravljanje Windows Defender Credential Guard funkcijom (Microsoft Learn)](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage)
- [10] [Protected Users Security Group (Microsoft Learn)](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)
- [11] [Dodatak C: Zaštićeni nalozi i grupe u Active Directory-ju (Microsoft Learn)](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)

{{#include ../../banners/hacktricks-training.md}}
