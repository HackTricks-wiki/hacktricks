# Kerberos Double Hop Problem

{{#include ../../banners/hacktricks-training.md}}


## Introduction

Kerberos "Double Hop" problem pojavljuje se kada napadač pokuša da koristi **Kerberos authentication across two** **hops**, na primer koristeći **PowerShell**/**WinRM**.

Kada se **authentication** obavlja preko **Kerberos**, **credentials** **aren't** cached in **memory.** Zbog toga, ako pokrenete mimikatz nećete naći kredencijale korisnika na mašini čak i ako on pokreće procese.

To je zato što pri konekciji koristeći Kerberos slede koraci:

1. User1 provides credentials and **domain controller** returns a Kerberos **TGT** to the User1.
2. User1 uses **TGT** to request a **service ticket** to **connect** to Server1.
3. User1 **connects** to **Server1** and provides **service ticket**.
4. **Server1** **doesn't** have **credentials** of User1 cached or the **TGT** of User1. Therefore, when User1 from Server1 tries to login to a second server, he is **not able to authenticate**.

### Unconstrained Delegation

If **unconstrained delegation** is enabled in the PC, this won't happen as the **Server** will **get** a **TGT** of each user accessing it. Moreover, if unconstrained delegation is used you probably can **compromise the Domain Controller** from it.\
[**More info in the unconstrained delegation page**](unconstrained-delegation.md).

### CredSSP

Another way to avoid this problem which is [**notably insecure**](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/enable-wsmancredssp?view=powershell-7) is **Credential Security Support Provider**. From Microsoft:

> CredSSP authentication delegates the user credentials from the local computer to a remote computer. This practice increases the security risk of the remote operation. If the remote computer is compromised, when credentials are passed to it, the credentials can be used to control the network session.

Toplo se preporučuje da **CredSSP** bude onemogućen na produkcionim sistemima, osetljivim mrežama i sličnim okruženjima zbog bezbednosnih razloga. Da biste utvrdili da li je **CredSSP** omogućen, može se pokrenuti komanda `Get-WSManCredSSP`. Ova komanda omogućava proveru statusa **CredSSP** i može se čak izvršiti na daljinu, pod uslovom da je **WinRM** omogućen.
```bash
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
Get-WSManCredSSP
}
```
### Remote Credential Guard (RCG)

**Remote Credential Guard** čuva TGT korisnika na izvornom radnom računaru dok i dalje omogućava RDP sesiji da na sledećem hopu zahteva nove Kerberos servisne tikete. Omogućite Computer Configuration > Administrative Templates > System > Credentials Delegation > Restrict delegation of credentials to remote servers i izaberite Require Remote Credential Guard, zatim se povežite sa `mstsc.exe /remoteGuard /v:server1` umesto da se vratite na CredSSP.

Microsoft je pokvario RCG za multi-hop pristup na Windows 11 22H2+ sve do kumulativnih ažuriranja iz aprila 2024. (KB5036896/KB5036899/KB5036894). Zakrpite klijenta i posrednički server, inače drugi hop i dalje neće uspeti. Brza provera hotfix-a:
```powershell
("KB5036896","KB5036899","KB5036894") | ForEach-Object {
Get-HotFix -Id $_ -ErrorAction SilentlyContinue
}
```
Sa instaliranim tim buildovima, RDP hop može zadovoljiti nizvodne Kerberos izazove bez izlaganja tajni koje se mogu ponovo upotrebiti na prvom serveru.

## Zaobilazna rešenja

### Invoke Command

Da bi se rešio problem double hop-a, predstavljen je metod koji uključuje ugnježdeni `Invoke-Command`. Ovo direktno ne rešava problem, ali pruža zaobilazno rešenje bez potrebe za posebnim konfiguracijama. Pristup omogućava izvršavanje komande (`hostname`) na sekundarnom serveru putem PowerShell komande izvršene sa početne mašine napadača ili preko prethodno uspostavljene PS-Session sa prvim serverom. Evo kako se to radi:
```bash
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```
Alternativno, preporučuje se uspostavljanje PS-Session sa prvim serverom i pokretanje `Invoke-Command` koristeći `$cred` radi centralizacije zadataka.

### Registracija PSSession konfiguracije

Rešenje za zaobilaženje problema double hop uključuje korišćenje `Register-PSSessionConfiguration` zajedno sa `Enter-PSSession`. Ovaj metod zahteva drugačiji pristup od `evil-winrm` i omogućava sesiju koja nije pogođena ograničenjem double hop.
```bash
Register-PSSessionConfiguration -Name doublehopsess -RunAsCredential domain_name\username
Restart-Service WinRM
Enter-PSSession -ConfigurationName doublehopsess -ComputerName TARGET_PC -Credential domain_name\username
klist
```
### PortForwarding

Za lokalne administratore na posrednom cilju, port forwarding omogućava da se zahtevi pošalju na krajnji server. Koristeći `netsh`, može se dodati pravilo za port forwarding, zajedno sa pravilom Windows vatrozida koje dozvoljava prosleđeni port.
```bash
netsh interface portproxy add v4tov4 listenport=5446 listenaddress=10.35.8.17 connectport=5985 connectaddress=10.35.8.23
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=5446
```
#### winrs.exe

`winrs.exe` se može koristiti za prosleđivanje WinRM zahteva, potencijalno kao manje otkrivačka opcija ako je nadzor PowerShell-a problem. Komanda ispod prikazuje njegovu upotrebu:
```bash
winrs -r:http://bizintel:5446 -u:ta\redsuit -p:2600leet hostname
```
### OpenSSH

Instalacija OpenSSH na prvom serveru omogućava zaobilazno rešenje za double-hop problem, posebno korisno za jump box scenarije. Ova metoda zahteva CLI instalaciju i podešavanje OpenSSH for Windows. Kada je konfigurisano za Password Authentication, ovo omogućava posredničkom serveru da preuzme TGT u ime korisnika.

#### Koraci instalacije OpenSSH

1. Preuzmite i premestite najnoviji OpenSSH release zip na ciljni server.
2. Otpakujte i pokrenite skriptu `Install-sshd.ps1`.
3. Dodajte firewall pravilo za otvaranje port 22 i proverite da li su SSH servisi pokrenuti.

Da biste rešili greške `Connection reset`, možda će biti potrebno ažurirati permissions tako da Everyone ima read and execute access na OpenSSH direktorijumu.
```bash
icacls.exe "C:\Users\redsuit\Documents\ssh\OpenSSH-Win64" /grant Everyone:RX /T
```
### LSA Whisperer CacheLogon (Napredno)

**LSA Whisperer** (2024) izlaže poziv paketa `msv1_0!CacheLogon` tako da možete inicijalizovati postojeći *network logon* poznatim NT hashom umesto da kreirate novu sesiju sa `LogonUser`. Ubacivanjem hasha u logon session koji je WinRM/PowerShell već otvorio na hop #1, taj host može da se autentifikuje na hop #2 bez čuvanja eksplicitnih kredencijala ili generisanja dodatnih 4624 events.

1. Dobijte izvršenje koda unutar LSASS (ili onemogućite/abuzirajte PPL ili pokrenite na lab VM koji kontrolišete).
2. Enumerišite logon sessions (npr. `lsa.exe sessions`) i zabeležite LUID koji odgovara vašem remoting kontekstu.
3. Pre-računajte NT hash i ubacite ga u `CacheLogon`, pa ga obrišite kada završite.
```powershell
lsa.exe cachelogon --session 0x3e4 --domain ta --username redsuit --nthash a7c5480e8c1ef0ffec54e99275e6e0f7
lsa.exe cacheclear --session 0x3e4
```
Nakon cache seed-a, ponovo pokrenite `Invoke-Command`/`New-PSSession` sa hop #1: LSASS će ponovo koristiti injektovani hash da ispuni Kerberos/NTLM izazove za drugi hop, uredno zaobilazeći ograničenje double hop. Kao kompromis, dolazi do pojačane telemetrije (izvršavanje koda u LSASS), pa ovu tehniku držite za okruženja sa visokim nivoom sigurnosnih ograničenja gde su CredSSP/RCG zabranjeni.

## Izvori

- [https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20)
- [https://posts.slayerlabs.com/double-hop/](https://posts.slayerlabs.com/double-hop/)
- [https://learn.microsoft.com/en-gb/archive/blogs/sergey_babkins_blog/another-solution-to-multi-hop-powershell-remoting](https://learn.microsoft.com/en-gb/archive/blogs/sergey_babkins_blog/another-solution-to-multi-hop-powershell-remoting)
- [https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/](https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/)
- [https://support.microsoft.com/en-au/topic/april-9-2024-kb5036896-os-build-17763-5696-efb580f1-2ce4-4695-b76c-d2068a00fb92](https://support.microsoft.com/en-au/topic/april-9-2024-kb5036896-os-build-17763-5696-efb580f1-2ce4-4695-b76c-d2068a00fb92)
- [https://specterops.io/blog/2024/04/17/lsa-whisperer/](https://specterops.io/blog/2024/04/17/lsa-whisperer/)


{{#include ../../banners/hacktricks-training.md}}
