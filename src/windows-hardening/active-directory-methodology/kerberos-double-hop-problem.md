# Kerberos Double Hop Problem

{{#include ../../banners/hacktricks-training.md}}


## Introduction

Die Kerberos "Double Hop" probleem verskyn wanneer 'n aanvaller probeer om **Kerberos authentication across two** **hops** te gebruik, byvoorbeeld met **PowerShell**/**WinRM**.

Wanneer 'n **authentication** plaasvind via **Kerberos**, word **credentials** **nie** in **memory** gekas nie. Daarom, as jy mimikatz uitvoer sal jy **nie** die gebruiker se credentials op die masjien vind nie, selfs al hardloop hy prosesse.

Dit is omdat wanneer daar met Kerberos gekonnekteer word die stappe soos volg is:

1. User1 verskaf credentials en **domain controller** stuur 'n Kerberos **TGT** aan User1.
2. User1 gebruik die **TGT** om 'n **service ticket** aan te vra om met Server1 te **connect**.
3. User1 **connect** met **Server1** en voorsien die **service ticket**.
4. **Server1** het **nie** User1 se **credentials** of User1 se **TGT** in kas nie. Daarom, wanneer User1 vanaf Server1 probeer aanmeld by 'n tweede server, kan hy **nie** autentikeer nie.

### Unconstrained Delegation

Indien **unconstrained delegation** op die PC geaktiveer is, sal hierdie probleem nie voorkom nie omdat die **Server** 'n **TGT** van elke gebruiker wat toegang kry sal **ontvang**. Verder, as unconstrained delegation gebruik word, kan jy waarskynlik die **Domain Controller** daardeur kompromitteer.\
[**More info in the unconstrained delegation page**](unconstrained-delegation.md).

### CredSSP

Nog 'n manier om hierdie probleem te vermy wat [**duidelik onveilig**](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/enable-wsmancredssp?view=powershell-7) is, is die **Credential Security Support Provider**. Van Microsoft:

> CredSSP authentication delegeteer die user credentials van die lokale rekenaar na 'n remote rekenaar. Hierdie praktyk verhoog die veiligheidsrisiko van die remote operasie. As die remote rekenaar gekompromitteer word, kan die credentials wat aan hom oorgedra is gebruik word om die netwerkessie te beheer.

Dit word sterk aanbeveel dat **CredSSP** gedeaktiveer word op produksie-stelsels, sensitiewe netwerke, en soortgelyke omgewings weens sekuriteitskwaal. Om te bepaal of **CredSSP** geaktiveer is, kan die `Get-WSManCredSSP` opdrag uitgevoer word. Hierdie opdrag laat toe om die **CredSSP status** te kontroleer en kan selfs afgeleë uitgevoer word, mits **WinRM** geaktiveer is.
```bash
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
Get-WSManCredSSP
}
```
### Remote Credential Guard (RCG)

**Remote Credential Guard** hou die gebruiker se TGT op die oorspronklike werkstasie terwyl dit steeds die RDP-sessie toelaat om nuwe Kerberos-dienskaartjies op die volgende hop aan te vra. Skakel **Computer Configuration > Administrative Templates > System > Credentials Delegation > Restrict delegation of credentials to remote servers** in en kies **Require Remote Credential Guard**, en koppel dan met `mstsc.exe /remoteGuard /v:server1` in plaas daarvan om op CredSSP terug te val.

Microsoft het RCG vir multi-hop toegang op Windows 11 22H2+ gebreek totdat die **April 2024 cumulative updates** (KB5036896/KB5036899/KB5036894). Patch die kliënt en die intermediêre bediener, anders sal die tweede hop steeds misluk. Vinnige hotfix-kontrole:
```powershell
("KB5036896","KB5036899","KB5036894") | ForEach-Object {
Get-HotFix -Id $_ -ErrorAction SilentlyContinue
}
```
Met daardie builds geïnstalleer kan die RDP hop downstream Kerberos-uitdagings bevredig sonder om herbruikbare geheime op die eerste bediener bloot te stel.

## Omweë

### Invoke Command

Om die double hop-kwessie aan te spreek, word 'n metode wat 'n geneste `Invoke-Command` betrek, voorgehou. Dit los die probleem nie direk op nie, maar bied 'n ompadoplossing wat geen spesiale konfigurasies vereis nie. Die benadering maak dit moontlik om 'n opdrag (`hostname`) op 'n sekondêre bediener uit te voer deur 'n PowerShell-opdrag wat vanaf 'n aanvanklike aanvalsmachine uitgevoer word of deur 'n vooraf gevestigde PS-Session met die eerste bediener. So word dit gedoen:
```bash
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```
Alternatiewelik word aanbeveel om 'n PS-Session met die eerste bediener op te stel en die `Invoke-Command` met `$cred` uit te voer om take te sentraliseer.

### Register PSSession Configuration

'n Oplossing om die double hop probleem te omseil behels die gebruik van `Register-PSSessionConfiguration` saam met `Enter-PSSession`. Hierdie metode vereis 'n ander benadering as `evil-winrm` en maak 'n sessie moontlik wat nie aan die double hop beperking ly nie.
```bash
Register-PSSessionConfiguration -Name doublehopsess -RunAsCredential domain_name\username
Restart-Service WinRM
Enter-PSSession -ConfigurationName doublehopsess -ComputerName TARGET_PC -Credential domain_name\username
klist
```
### PortForwarding

Vir lokale administrateurs op 'n tussenliggende teiken laat port forwarding toe dat versoeke na 'n eindbediener gestuur word. Deur `netsh` te gebruik kan 'n reël bygevoeg word vir port forwarding, saam met 'n Windows firewall-reël om die voorgestuurde poort toe te laat.
```bash
netsh interface portproxy add v4tov4 listenport=5446 listenaddress=10.35.8.17 connectport=5985 connectaddress=10.35.8.23
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=5446
```
#### winrs.exe

`winrs.exe` kan gebruik word om WinRM-versoeke voort te stuur, moontlik as 'n minder opspoorbare opsie indien PowerShell-monitering 'n bekommernis is. Die onderstaande opdrag demonstreer die gebruik daarvan:
```bash
winrs -r:http://bizintel:5446 -u:ta\redsuit -p:2600leet hostname
```
### OpenSSH

Die installering van OpenSSH op die eerste bediener maak 'n ompad vir die double-hop-kwessie moontlik, veral nuttig vir jump box-scenario's. Hierdie metode vereis 'n CLI-installasie en die opstel van OpenSSH vir Windows. As dit gekonfigureer is vir Password Authentication, kan die tussenliggende bediener 'n TGT namens die gebruiker bekom.

#### OpenSSH Installasiestappe

1. Laai die nuutste OpenSSH-release zip af en skuif dit na die teikenbediener.
2. Pak uit en voer die `Install-sshd.ps1` script uit.
3. Voeg 'n firewall-reël by om poort 22 oop te maak en verifieer dat die SSH-dienste aan die gang is.

Om `Connection reset`-foute op te los, moet magtigings moontlik opgedateer word om almal lees- en uitvoertoegang tot die OpenSSH-gids te gee.
```bash
icacls.exe "C:\Users\redsuit\Documents\ssh\OpenSSH-Win64" /grant Everyone:RX /T
```
### LSA Whisperer CacheLogon (Gevorderd)

**LSA Whisperer** (2024) maak die `msv1_0!CacheLogon` package call sigbaar sodat jy 'n bestaande *network logon* met 'n bekende NT hash kan voorsien in plaas van om 'n nuwe sessie met `LogonUser` te skep. Deur die hash te injekteer in die logon-sessie wat WinRM/PowerShell reeds op hop #1 geopen het, kan daardie gasheer by hop #2 autentiseer sonder om eksplisiete credentials te stoor of ekstra 4624 events te genereer.

1. Kry kode-uitvoering binne LSASS (deaktiveer of misbruik PPL, of hardloop dit op 'n lab VM wat jy beheer).
2. Lys logon-sessies (bv. `lsa.exe sessions`) en vang die LUID vas wat ooreenstem met jou remoting-konteks.
3. Bereken vooraf die NT hash en voer dit in by `CacheLogon`, en verwyder dit dan wanneer jy klaar is.
```powershell
lsa.exe cachelogon --session 0x3e4 --domain ta --username redsuit --nthash a7c5480e8c1ef0ffec54e99275e6e0f7
lsa.exe cacheclear --session 0x3e4
```
Na die cache seed, voer `Invoke-Command`/`New-PSSession` weer uit vanaf hop #1: LSASS sal die geïnjekteerde hash hergebruik om Kerberos/NTLM-uitdagings vir die tweede hop te bevredig, waardeur die double hop-beperking netjies omseil word. Die afruil is swaarder telemetrie (code execution in LSASS), dus gebruik dit net in omgewings met hoë friksie waar CredSSP/RCG nie toegelaat word nie.

## Verwysings

- [https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20)
- [https://posts.slayerlabs.com/double-hop/](https://posts.slayerlabs.com/double-hop/)
- [https://learn.microsoft.com/en-gb/archive/blogs/sergey_babkins_blog/another-solution-to-multi-hop-powershell-remoting](https://learn.microsoft.com/en-gb/archive/blogs/sergey_babkins_blog/another-solution-to-multi-hop-powershell-remoting)
- [https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/](https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/)
- [https://support.microsoft.com/en-au/topic/april-9-2024-kb5036896-os-build-17763-5696-efb580f1-2ce4-4695-b76c-d2068a00fb92](https://support.microsoft.com/en-au/topic/april-9-2024-kb5036896-os-build-17763-5696-efb580f1-2ce4-4695-b76c-d2068a00fb92)
- [https://specterops.io/blog/2024/04/17/lsa-whisperer/](https://specterops.io/blog/2024/04/17/lsa-whisperer/)


{{#include ../../banners/hacktricks-training.md}}
