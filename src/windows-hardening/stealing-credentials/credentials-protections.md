# Windows Credentials Protections

{{#include ../../banners/hacktricks-training.md}}

## WDigest

Protokol [WDigest](<https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396>), uveden sa Windows XP, dizajniran je za autentifikaciju putem HTTP protokola i je **omogućen po defaultu na Windows XP do Windows 8.0 i Windows Server 2003 do Windows Server 2012**. Ova podrazumevana postavka rezultira **čuvanjem lozinki u običnom tekstu u LSASS** (Local Security Authority Subsystem Service). Napadač može koristiti Mimikatz da **izvuče ove kredencijale** izvršavanjem:
```bash
sekurlsa::wdigest
```
Da biste **isključili ili uključili ovu funkciju**, registry ključevi _**UseLogonCredential**_ i _**Negotiate**_ unutar _**HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_ moraju biti postavljeni na "1". Ako su ovi ključevi **odsutni ili postavljeni na "0"**, WDigest je **onemogućen**:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## LSA zaštita (PP i PPL zaštićeni procesi)

**Zaštićeni proces (PP)** i **zaštićeni proces light (PPL)** su **zaštite na nivou Windows jezgra** dizajnirane da spreče neovlašćen pristup osetljivim procesima kao što je **LSASS**. Uvedene u **Windows Vista**, **PP model** je prvobitno stvoren za sprovođenje **DRM** i dozvoljavao je zaštitu samo binarnih datoteka potpisanih sa **posebnim medijskim sertifikatom**. Proces označen kao **PP** može biti pristupljen samo od strane drugih procesa koji su **takođe PP** i imaju **jednak ili viši nivo zaštite**, i čak tada, **samo sa ograničenim pravima pristupa** osim ako nije posebno dozvoljeno.

**PPL**, uveden u **Windows 8.1**, je fleksibilnija verzija PP. Omogućava **šire slučajeve upotrebe** (npr., LSASS, Defender) uvođenjem **"nivoa zaštite"** zasnovanih na **EKU (Enhanced Key Usage)** polju digitalnog potpisa. Nivo zaštite se čuva u `EPROCESS.Protection` polju, koje je `PS_PROTECTION` struktura sa:
- **Tip** (`Protected` ili `ProtectedLight`)
- **Potpisivač** (npr., `WinTcb`, `Lsa`, `Antimalware`, itd.)

Ova struktura je pakovana u jedan bajt i određuje **ko može pristupiti kome**:
- **Viši potpisivači mogu pristupiti nižima**
- **PPL ne može pristupiti PP**
- **Nezaštićeni procesi ne mogu pristupiti nijednom PPL/PP**

### Šta treba da znate iz ofanzivne perspektive

- Kada **LSASS radi kao PPL**, pokušaji da se otvori koristeći `OpenProcess(PROCESS_VM_READ | QUERY_INFORMATION)` iz normalnog admin konteksta **ne uspevaju sa `0x5 (Access Denied)`**, čak i ako je `SeDebugPrivilege` omogućen.
- Možete **proveriti nivo zaštite LSASS** koristeći alate kao što su Process Hacker ili programatski čitajući `EPROCESS.Protection` vrednost.
- LSASS će obično imati `PsProtectedSignerLsa-Light` (`0x41`), koji može biti pristupljen **samo od strane procesa potpisanih sa višim potpisivačem**, kao što je `WinTcb` (`0x61` ili `0x62`).
- PPL je **ograničenje samo za korisnički prostor**; **kod na nivou jezgra može ga potpuno zaobići**.
- LSASS koji je PPL ne **sprečava iskopavanje kredencijala ako možete izvršiti kernel shellcode** ili **iskoristiti proces sa visokim privilegijama sa odgovarajućim pristupom**.
- **Postavljanje ili uklanjanje PPL** zahteva restart ili **Secure Boot/UEFI podešavanja**, koja mogu zadržati PPL podešavanje čak i nakon što su promene u registru poništene.

**Opcije za zaobilaženje PPL zaštita:**

Ako želite da iskopate LSASS uprkos PPL, imate 3 glavne opcije:
1. **Koristite potpisani kernel drajver (npr., Mimikatz + mimidrv.sys)** da **uklonite zaštitnu oznaku LSASS**:

![](../../images/mimidrv.png)

2. **Donosite svoj ranjivi drajver (BYOVD)** da pokrenete prilagođeni kernel kod i onemogućite zaštitu. Alati kao što su **PPLKiller**, **gdrv-loader**, ili **kdmapper** čine ovo izvodljivim.
3. **Ukrao postojeći LSASS handle** iz drugog procesa koji ga ima otvoren (npr., proces AV), a zatim **duplirajte** ga u svoj proces. Ovo je osnova tehnike `pypykatz live lsa --method handledup`.
4. **Zloupotrebljavajte neki privilegovani proces** koji će vam omogućiti da učitate proizvoljni kod u njegov prostor adresa ili unutar drugog privilegovanog procesa, efikasno zaobilazeći PPL ograničenja. Možete proveriti primer ovoga u [bypassing-lsa-protection-in-userland](https://blog.scrt.ch/2021/04/22/bypassing-lsa-protection-in-userland/) ili [https://github.com/itm4n/PPLdump](https://github.com/itm4n/PPLdump).

**Proverite trenutni status LSA zaštite (PPL/PP) za LSASS**:
```bash
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
When you running **`mimikatz privilege::debug sekurlsa::logonpasswords`** it'll probably fail with the error code `0x00000005` becasue of this.

- For more information about this check [https://itm4n.github.io/lsass-runasppl/](https://itm4n.github.io/lsass-runasppl/)


## Credential Guard

**Credential Guard**, funkcija ekskluzivna za **Windows 10 (Enterprise i Education edicije)**, poboljšava bezbednost mašinskih kredencijala koristeći **Virtual Secure Mode (VSM)** i **Virtualization Based Security (VBS)**. Iskorišćava CPU virtuelizacione ekstenzije da izoluje ključne procese unutar zaštićenog memorijskog prostora, daleko od dometa glavnog operativnog sistema. Ova izolacija osigurava da čak ni kernel ne može pristupiti memoriji u VSM, efikasno štiteći kredencijale od napada poput **pass-the-hash**. **Local Security Authority (LSA)** funkcioniše unutar ovog sigurnog okruženja kao trustlet, dok **LSASS** proces u glavnom OS-u deluje samo kao komunikator sa VSM-ovim LSA.

Podrazumevano, **Credential Guard** nije aktivan i zahteva ručnu aktivaciju unutar organizacije. Ključno je za poboljšanje bezbednosti protiv alata poput **Mimikatz**, koji su ometeni u svojoj sposobnosti da izvuku kredencijale. Međutim, ranjivosti se i dalje mogu iskoristiti dodavanjem prilagođenih **Security Support Providers (SSP)** za hvatanje kredencijala u čistom tekstu tokom pokušaja prijavljivanja.

Da biste proverili status aktivacije **Credential Guard**, registry ključ _**LsaCfgFlags**_ pod _**HKLM\System\CurrentControlSet\Control\LSA**_ može se pregledati. Vrednost "**1**" označava aktivaciju sa **UEFI zaključavanjem**, "**2**" bez zaključavanja, a "**0**" označava da nije omogućeno. Ova registry provera, iako je jak pokazatelj, nije jedini korak za omogućavanje Credential Guard. Detaljna uputstva i PowerShell skripta za omogućavanje ove funkcije dostupni su online.
```bash
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
Za sveobuhvatno razumevanje i uputstva o omogućavanju **Credential Guard** u Windows 10 i njegovoj automatskoj aktivaciji u kompatibilnim sistemima **Windows 11 Enterprise i Education (verzija 22H2)**, posetite [Microsoftovu dokumentaciju](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage).

Dalji detalji o implementaciji prilagođenih SSP-ova za hvatanje kredencijala su navedeni u [ovom vodiču](../active-directory-methodology/custom-ssp.md).

## RDP RestrictedAdmin Mode

**Windows 8.1 i Windows Server 2012 R2** su uveli nekoliko novih bezbednosnih funkcija, uključujući _**Restricted Admin mode za RDP**_. Ovaj režim je dizajniran da poboljša bezbednost smanjenjem rizika povezanih sa [**pass the hash**](https://blog.ahasayen.com/pass-the-hash/) napadima.

Tradicionalno, kada se povežete na udaljeni računar putem RDP-a, vaši kredencijali se čuvaju na ciljnim mašinama. Ovo predstavlja značajan bezbednosni rizik, posebno kada se koriste nalozi sa povišenim privilegijama. Međutim, uvođenjem _**Restricted Admin mode**_, ovaj rizik je značajno smanjen.

Kada započnete RDP vezu koristeći komandu **mstsc.exe /RestrictedAdmin**, autentifikacija na udaljeni računar se vrši bez čuvanja vaših kredencijala na njemu. Ovaj pristup osigurava da, u slučaju infekcije malverom ili ako zlonameran korisnik dobije pristup udaljenom serveru, vaši kredencijali nisu kompromitovani, jer nisu sačuvani na serveru.

Važno je napomenuti da u **Restricted Admin mode**, pokušaji pristupa mrežnim resursima iz RDP sesije neće koristiti vaše lične kredencijale; umesto toga, koristi se **identitet mašine**.

Ova funkcija predstavlja značajan korak napred u obezbeđivanju veza sa udaljenim desktopom i zaštiti osetljivih informacija od izlaganja u slučaju bezbednosnog proboja.

![](../../images/RAM.png)

Za detaljnije informacije posetite [ovaj resurs](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/).

## Cached Credentials

Windows obezbeđuje **domen kredencijale** putem **Local Security Authority (LSA)**, podržavajući procese prijavljivanja sa bezbednosnim protokolima kao što su **Kerberos** i **NTLM**. Ključna karakteristika Windows-a je njegova sposobnost da kešira **poslednjih deset domen prijava** kako bi osigurao da korisnici i dalje mogu pristupiti svojim računarima čak i ako je **domen kontroler van mreže**—što je korisno za korisnike laptopova koji često nisu u mreži svoje kompanije.

Broj keširanih prijava se može prilagoditi putem specifičnog **registry ključa ili grupne politike**. Da biste pregledali ili promenili ovu postavku, koristi se sledeća komanda:
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
Pristup ovim keširanim akreditivima je strogo kontrolisan, pri čemu samo **SYSTEM** nalog ima potrebne dozvole za pregled. Administratori koji trebaju pristup ovim informacijama moraju to učiniti sa privilegijama SYSTEM korisnika. Akreditivi se čuvaju na: `HKEY_LOCAL_MACHINE\SECURITY\Cache`

**Mimikatz** se može koristiti za ekstrakciju ovih keširanih akreditiva koristeći komandu `lsadump::cache`.

Za više detalja, originalni [izvor](http://juggernaut.wikidot.com/cached-credentials) pruža sveobuhvatne informacije.

## Zaštićeni korisnici

Članstvo u **grupi zaštićenih korisnika** uvodi nekoliko bezbednosnih poboljšanja za korisnike, osiguravajući viši nivo zaštite od krađe i zloupotrebe akreditiva:

- **Delegacija akreditiva (CredSSP)**: Čak i ako je postavka grupne politike za **Dozvoli delegiranje podrazumevanih akreditiva** omogućena, akreditivi zaštićenih korisnika neće biti keširani u običnom tekstu.
- **Windows Digest**: Počevši od **Windows 8.1 i Windows Server 2012 R2**, sistem neće keširati akreditive zaštićenih korisnika u običnom tekstu, bez obzira na status Windows Digest-a.
- **NTLM**: Sistem neće keširati akreditive zaštićenih korisnika u običnom tekstu ili NT jednosmerne funkcije (NTOWF).
- **Kerberos**: Za zaštićene korisnike, Kerberos autentifikacija neće generisati **DES** ili **RC4 ključeve**, niti će keširati akreditive u običnom tekstu ili dugoročne ključeve nakon inicijalne akvizicije Ticket-Granting Ticket (TGT).
- **Offline prijavljivanje**: Zaštićeni korisnici neće imati keširan verifikator kreiran prilikom prijavljivanja ili otključavanja, što znači da offline prijavljivanje nije podržano za ove naloge.

Ove zaštite se aktiviraju u trenutku kada se korisnik, koji je član **grupe zaštićenih korisnika**, prijavi na uređaj. To osigurava da su kritične bezbednosne mere na snazi kako bi se zaštitili od različitih metoda kompromitacije akreditiva.

Za detaljnije informacije, konsultujte zvaničnu [dokumentaciju](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group).

**Tabela iz** [**dokumentacije**](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)**.**

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

{{#include ../../banners/hacktricks-training.md}}
