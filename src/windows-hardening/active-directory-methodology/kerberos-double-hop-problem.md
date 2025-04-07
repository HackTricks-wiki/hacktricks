# Kerberos Double Hop Problem

{{#include ../../banners/hacktricks-training.md}}


## Introduction

Kerberos "Double Hop" problem se pojavljuje kada napadač pokušava da koristi **Kerberos autentifikaciju preko dva** **hopa**, na primer koristeći **PowerShell**/**WinRM**.

Kada se **autentifikacija** vrši putem **Kerberos-a**, **akreditivi** **nisu** keširani u **memoriji.** Stoga, ako pokrenete mimikatz nećete naći **akreditive** korisnika na mašini čak i ako on pokreće procese.

To je zato što su koraci prilikom povezivanja sa Kerberos-om sledeći:

1. User1 pruža akreditive i **kontroler domena** vraća Kerberos **TGT** korisniku User1.
2. User1 koristi **TGT** da zatraži **servisni tiket** za **povezivanje** sa Server1.
3. User1 **povezuje** sa **Server1** i pruža **servisni tiket**.
4. **Server1** **nema** **akreditive** korisnika User1 keširane ili **TGT** korisnika User1. Stoga, kada User1 sa Server1 pokušava da se prijavi na drugi server, on **nije u mogućnosti da se autentifikuje**.

### Unconstrained Delegation

Ako je **neograničena delegacija** omogućena na PC-u, to se neće desiti jer će **Server** **dobiti** **TGT** svakog korisnika koji mu pristupa. Štaviše, ako se koristi neograničena delegacija, verovatno možete **kompromitovati Kontroler Domen** iz nje.\
[**Više informacija na stranici o neograničenoj delegaciji**](unconstrained-delegation.md).

### CredSSP

Još jedan način da se izbegne ovaj problem koji je [**značajno nesiguran**](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/enable-wsmancredssp?view=powershell-7) je **Credential Security Support Provider**. Od Microsoft-a:

> CredSSP autentifikacija delegira korisničke akreditive sa lokalnog računara na udaljeni računar. Ova praksa povećava sigurnosni rizik udaljene operacije. Ako je udaljeni računar kompromitovan, kada se akreditive proslede njemu, akreditive se mogu koristiti za kontrolu mrežne sesije.

Preporučuje se da **CredSSP** bude onemogućen na produkcionim sistemima, osetljivim mrežama i sličnim okruženjima zbog sigurnosnih problema. Da biste utvrdili da li je **CredSSP** omogućen, može se pokrenuti komanda `Get-WSManCredSSP`. Ova komanda omogućava **proveru statusa CredSSP** i može se čak izvršiti daljinski, pod uslovom da je **WinRM** omogućen.
```bash
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
Get-WSManCredSSP
}
```
## Workarounds

### Invoke Command

Da bi se rešio problem dvostrukog skoka, predstavljen je metod koji uključuje ugnježdeni `Invoke-Command`. Ovo ne rešava problem direktno, ali nudi rešenje bez potrebe za posebnim konfiguracijama. Pristup omogućava izvršavanje komande (`hostname`) na sekundarnom serveru putem PowerShell komande izvršene sa početne napadačke mašine ili kroz prethodno uspostavljenu PS-Session sa prvim serverom. Evo kako se to radi:
```bash
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```
Alternativno, preporučuje se uspostavljanje PS-Session sa prvim serverom i pokretanje `Invoke-Command` koristeći `$cred` za centralizaciju zadataka.

### Registracija PSSession Konfiguracije

Rešenje za zaobilaženje problema sa dvostrukim skakanjem uključuje korišćenje `Register-PSSessionConfiguration` sa `Enter-PSSession`. Ova metoda zahteva drugačiji pristup od `evil-winrm` i omogućava sesiju koja ne pati od ograničenja dvostrukog skakanja.
```bash
Register-PSSessionConfiguration -Name doublehopsess -RunAsCredential domain_name\username
Restart-Service WinRM
Enter-PSSession -ConfigurationName doublehopsess -ComputerName <pc_name> -Credential domain_name\username
klist
```
### PortForwarding

Za lokalne administratore na posredničkom cilju, prosleđivanje portova omogućava slanje zahteva na konačni server. Koristeći `netsh`, pravilo se može dodati za prosleđivanje portova, zajedno sa pravilom Windows vatrozida koje omogućava prosleđeni port.
```bash
netsh interface portproxy add v4tov4 listenport=5446 listenaddress=10.35.8.17 connectport=5985 connectaddress=10.35.8.23
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=5446
```
#### winrs.exe

`winrs.exe` se može koristiti za prosleđivanje WinRM zahteva, potencijalno kao manje uočljiva opcija ako je praćenje PowerShell-a zabrinjavajuće. Komanda ispod prikazuje njegovu upotrebu:
```bash
winrs -r:http://bizintel:5446 -u:ta\redsuit -p:2600leet hostname
```
### OpenSSH

Instalacija OpenSSH na prvom serveru omogućava rešenje za problem dvostrukog skakanja, posebno korisno za scenarije jump box-a. Ova metoda zahteva CLI instalaciju i podešavanje OpenSSH za Windows. Kada je konfigurisana za autentifikaciju lozinkom, ovo omogućava posredničkom serveru da dobije TGT u ime korisnika.

#### Koraci za instalaciju OpenSSH

1. Preuzmite i premestite najnoviju OpenSSH verziju zip datoteke na ciljni server.
2. Raspakujte i pokrenite `Install-sshd.ps1` skriptu.
3. Dodajte pravilo vatrozida da otvorite port 22 i proverite da li SSH usluge rade.

Da biste rešili greške `Connection reset`, možda će biti potrebno ažurirati dozvole kako bi svako imao pristup za čitanje i izvršavanje u OpenSSH direktorijumu.
```bash
icacls.exe "C:\Users\redsuit\Documents\ssh\OpenSSH-Win64" /grant Everyone:RX /T
```
## Reference

- [https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20)
- [https://posts.slayerlabs.com/double-hop/](https://posts.slayerlabs.com/double-hop/)
- [https://learn.microsoft.com/en-gb/archive/blogs/sergey_babkins_blog/another-solution-to-multi-hop-powershell-remoting](https://learn.microsoft.com/en-gb/archive/blogs/sergey_babkins_blog/another-solution-to-multi-hop-powershell-remoting)
- [https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/](https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/)


{{#include ../../banners/hacktricks-training.md}}
