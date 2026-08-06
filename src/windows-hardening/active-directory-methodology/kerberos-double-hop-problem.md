# Problem sa Kerberos Double Hop

{{#include ../../banners/hacktricks-training.md}}


## Uvod

Kerberos problem „Double Hop“ pojavljuje se kada attacker pokušava da koristi **Kerberos authentication kroz dva** **hop-a**, na primer koristeći **PowerShell**/**WinRM**.

Kada se **authentication** obavlja preko **Kerberos-a**, **credentials** **se ne** keširaju u **memoriji.** Zato, ako pokrenete mimikatz, **nećete pronaći credentials** korisnika na mašini, čak i ako on na njoj pokreće procese.

To je zato što su koraci prilikom povezivanja sa Kerberos-om sledeći:<sup>[[1]](#references)</sup>

1. User1 prosleđuje credentials, a **domain controller** vraća Kerberos **TGT** korisniku User1.
2. User1 koristi **TGT** da zatraži **service ticket** za **povezivanje** sa Server1.
3. User1 se **povezuje** sa **Server1** i prosleđuje **service ticket**.
4. **Server1** nema keširane **credentials** korisnika User1 niti **TGT** korisnika User1. Zato, kada User1 sa Server1 pokuša da se prijavi na drugi server, **nije u mogućnosti da izvrši authentication**.

### Unconstrained Delegation

Ako je na računaru omogućena **unconstrained delegation**, ovo se neće desiti, jer će **Server** **dobiti** **TGT** svakog korisnika koji mu pristupi. Štaviše, ako se koristi unconstrained delegation, verovatno možete da **kompromitujete Domain Controller** sa tog računara.\
[**Više informacija na stranici o unconstrained delegation**](unconstrained-delegation.md).

### CredSSP

Drugi način za izbegavanje ovog problema, koji je [**naročito nebezbedan**](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/enable-wsmancredssp?view=powershell-7), jeste **Credential Security Support Provider**. Prema Microsoft-u:

> CredSSP authentication prosleđuje korisničke credentials sa lokalnog računara na udaljeni računar. Ova praksa povećava bezbednosni rizik udaljene operacije. Ako je udaljeni računar kompromitovan, credentials se, nakon prosleđivanja, mogu koristiti za kontrolu mrežne sesije.

Preporučuje se da **CredSSP** bude onemogućen na produkcionim sistemima, osetljivim mrežama i u sličnim okruženjima zbog bezbednosnih rizika. Da biste utvrdili da li je **CredSSP** omogućen, možete pokrenuti komandu `Get-WSManCredSSP`. Ova komanda omogućava **proveru statusa CredSSP-a**, a može se izvršiti i udaljeno, pod uslovom da je **WinRM** omogućen.
```bash
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
Get-WSManCredSSP
}
```
### Remote Credential Guard (RCG)

**Remote Credential Guard** zadržava korisnikov TGT na početnoj radnoj stanici, uz istovremeno omogućavanje RDP sesiji da zatraži nove Kerberos servisne tikete na sledećem hopu. Omogućite **Computer Configuration > Administrative Templates > System > Credentials Delegation > Restrict delegation of credentials to remote servers** i izaberite **Require Remote Credential Guard**, zatim se povežite pomoću `mstsc.exe /remoteGuard /v:server1` umesto vraćanja na CredSSP.

Microsoft je pokvario RCG za pristup sa više hopova na sistemima Windows 11 22H2+ sve do **kumulativnih ažuriranja iz aprila 2024.** (KB5036896/KB5036899/KB5036894). Instalirajte zakrpe na klijentu i posredničkom serveru, u suprotnom drugi hop i dalje neće raditi.<sup>[[5]](#references)</sup> Brza provera hotfix-a:
```powershell
("KB5036896","KB5036899","KB5036894") | ForEach-Object {
Get-HotFix -Id $_ -ErrorAction SilentlyContinue
}
```
Sa tim instaliranim buildovima, RDP hop može da odgovori na Kerberos izazove na narednim serverima bez izlaganja ponovo upotrebljivih tajni na prvom serveru.

## Zaobilazna rešenja

### Invoke Command

Da bi se rešio problem double hop-a, predstavljena je metoda koja uključuje ugnježdeni `Invoke-Command`. Ovo ne rešava problem direktno, ali pruža zaobilazno rešenje bez potrebe za posebnom konfiguracijom. Ovaj pristup omogućava izvršavanje komande (`hostname`) na sekundarnom serveru putem PowerShell komande pokrenute sa početne napadačke mašine ili putem prethodno uspostavljene PS-Session sesije sa prvim serverom. Evo kako se to radi:<sup>[[2]](#references)</sup>
```bash
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```
Alternativno, predlaže se uspostavljanje PS-Session veze sa prvim serverom i pokretanje `Invoke-Command` komande pomoću `$cred` radi centralizovanja zadataka.

### Register PSSession Configuration

Jedno rešenje za zaobilaženje problema sa double hop-om podrazumeva korišćenje `Register-PSSessionConfiguration` zajedno sa `Enter-PSSession`. Ovaj metod zahteva drugačiji pristup u odnosu na `evil-winrm` i omogućava sesiju na koju se ograničenje double hop-a ne primenjuje.<sup>[[3]](#references)[[4]](#references)</sup>
```bash
Register-PSSessionConfiguration -Name doublehopsess -RunAsCredential domain_name\username
Restart-Service WinRM
Enter-PSSession -ConfigurationName doublehopsess -ComputerName TARGET_PC -Credential domain_name\username
klist
```
### PortForwarding

Za lokalne administratore na posrednom ciljnom sistemu, port forwarding omogućava slanje zahteva krajnjem serveru. Korišćenjem `netsh` može se dodati pravilo za port forwarding, zajedno sa Windows firewall pravilom kojim se dozvoljava prosleđeni port.<sup>[[2]](#references)</sup>
```bash
netsh interface portproxy add v4tov4 listenport=5446 listenaddress=10.35.8.17 connectport=5985 connectaddress=10.35.8.23
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=5446
```
#### winrs.exe

`winrs.exe` može da se koristi za prosleđivanje WinRM zahteva, potencijalno kao manje uočljiva opcija ako je PowerShell monitoring problem.<sup>[[2]](#references)</sup> Komanda u nastavku prikazuje njegovu upotrebu:
```bash
winrs -r:http://bizintel:5446 -u:ta\redsuit -p:2600leet hostname
```
### OpenSSH

Instaliranje OpenSSH-a na prvom serveru omogućava zaobilazno rešenje za problem double-hop, što je posebno korisno u scenarijima sa jump box-om. Ovaj metod zahteva CLI instalaciju i podešavanje OpenSSH-a za Windows. Kada je konfigurisan za Password Authentication, posrednički server može da dobije TGT u ime user-a.<sup>[[2]](#references)</sup>

#### Koraci za instalaciju OpenSSH-a

1. Preuzmite najnoviji OpenSSH release zip i premestite ga na ciljni server.
2. Raspakujte ga i pokrenite skriptu `Install-sshd.ps1`.
3. Dodajte firewall rule za otvaranje porta 22 i proverite da li SSH services rade.

Da biste rešili greške `Connection reset`, možda je potrebno ažurirati permissions kako bi everyone imao read i execute pristup OpenSSH direktorijumu.
```bash
icacls.exe "C:\Users\redsuit\Documents\ssh\OpenSSH-Win64" /grant Everyone:RX /T
```
### LSA Whisperer CacheLogon (Napredno)

**LSA Whisperer** (2024) izlaže poziv paketa `msv1_0!CacheLogon`, tako da možete da ubacite poznati NT hash u postojeći *network logon*, umesto da kreirate novu sesiju pomoću `LogonUser`. Ubrizgavanjem hash-a u logon sesiju koju je WinRM/PowerShell već otvorio na hop-u #1, taj host može da se autentifikuje na hop-u #2 bez čuvanja eksplicitnih kredencijala ili generisanja dodatnih 4624 događaja.<sup>[[6]](#references)</sup>

1. Dobijte izvršavanje koda unutar LSASS-a (ili onemogućite/zaobiđite PPL ili pokrenite proces na lab VM-u koji kontrolišete).
2. Enumerišite logon sesije (npr. `lsa.exe sessions`) i zabeležite LUID koji odgovara vašem remoting kontekstu.
3. Unapred izračunajte NT hash i prosledite ga funkciji `CacheLogon`, a zatim ga obrišite kada završite.
```powershell
lsa.exe cachelogon --session 0x3e4 --domain ta --username redsuit --nthash a7c5480e8c1ef0ffec54e99275e6e0f7
lsa.exe cacheclear --session 0x3e4
```
Nakon popunjavanja cache-a, ponovo pokrenite `Invoke-Command`/`New-PSSession` sa hop-a #1: LSASS će ponovo koristiti ubačeni hash kako bi zadovoljio Kerberos/NTLM izazove za drugi hop, čime se elegantno zaobilazi ograničenje double hop-a. Kompromis je opsežnija telemetrija (izvršavanje koda u LSASS-u), pa ovo sačuvajte za okruženja sa mnogo prepreka u kojima su CredSSP/RCG nedozvoljeni.

## Reference

- [1] [Razumevanje Kerberos Double Hop-a - Microsoft Community Hub](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20)
- [2] [Zaobilaženja za Kerberos Double-Hop](https://posts.slayerlabs.com/double-hop/)
- [3] [Još jedno rešenje za multi-hop PowerShell remoting](https://learn.microsoft.com/en-gb/archive/blogs/sergey_babkins_blog/another-solution-to-multi-hop-powershell-remoting)
- [4] [Rešite PowerShell multi-hop problem bez korišćenja CredSSP-a](https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/)
- [5] [9. april 2024—KB5036896 (OS Build 17763.5696)](https://support.microsoft.com/en-au/topic/april-9-2024-kb5036896-os-build-17763-5696-efb580f1-2ce4-4695-b76c-d2068a00fb92)
- [6] [LSA Whisperer](https://specterops.io/blog/2024/04/17/lsa-whisperer/)

{{#include ../../banners/hacktricks-training.md}}
