# Kerberos Double Hop-probleem

{{#include ../../banners/hacktricks-training.md}}


## Inleiding

Die Kerberos "Double Hop"-probleem verskyn wanneer 'n aanvaller probeer om **Kerberos authentication oor twee** **hops** te gebruik, byvoorbeeld deur **PowerShell**/**WinRM** te gebruik.

Wanneer **authentication** deur **Kerberos** plaasvind, word **credentials** **nie** in **memory** gecache nie. Daarom sal jy, as jy mimikatz uitvoer, **nie credentials** van die gebruiker op die masjien vind nie, selfs al voer hy prosesse uit.

Dit is omdat die volgende stappe plaasvind wanneer daar met Kerberos verbind word:<sup>[[1]](#references)</sup>

1. User1 verskaf credentials en die **domain controller** stuur 'n Kerberos **TGT** aan User1 terug.
2. User1 gebruik **TGT** om 'n **service ticket** aan te vra om aan Server1 te **connect**.
3. User1 **connect** aan **Server1** en verskaf **service ticket**.
4. **Server1** het **nie** **credentials** van User1 gecache of die **TGT** van User1 nie. Daarom kan User1, wanneer hy vanaf Server1 by 'n tweede server probeer aanmeld, **nie authenticate** nie.

### Unconstrained Delegation

As **unconstrained delegation** op die PC enabled is, sal dit nie gebeur nie, aangesien die **Server** 'n **TGT** van elke gebruiker wat daaraan toegang verkry, sal **get**. Verder, as unconstrained delegation gebruik word, kan jy waarskynlik die **Domain Controller** van daar af **compromise**.\
[**Meer inligting op die unconstrained delegation-bladsy**](unconstrained-delegation.md).

### CredSSP

'n Ander manier om hierdie probleem te vermy, wat [**besonder onveilig**](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/enable-wsmancredssp?view=powershell-7) is, is **Credential Security Support Provider**. Van Microsoft:

> CredSSP authentication delegeer die gebruiker se credentials vanaf die plaaslike rekenaar na 'n afgeleë rekenaar. Hierdie praktyk verhoog die security risk van die remote operation. As die afgeleë rekenaar gecompromise word wanneer credentials daaraan deurgegee word, kan die credentials gebruik word om die network session te beheer.

Dit word sterk aanbeveel dat **CredSSP** op production systems, sensitiewe netwerke en soortgelyke omgewings disabled word weens security concerns. Om te bepaal of **CredSSP** enabled is, kan die `Get-WSManCredSSP`-command uitgevoer word. Hierdie command laat **checking of CredSSP status** toe en kan selfs remote uitgevoer word, mits **WinRM** enabled is.
```bash
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
Get-WSManCredSSP
}
```
### Remote Credential Guard (RCG)

**Remote Credential Guard** hou die gebruiker se TGT op die oorspronklike werkstasie, terwyl dit steeds die RDP-sessie toelaat om nuwe Kerberos-dienskaartjies op die volgende hop aan te vra. Aktiveer **Computer Configuration > Administrative Templates > System > Credentials Delegation > Restrict delegation of credentials to remote servers** en kies **Require Remote Credential Guard**. Koppel daarna met `mstsc.exe /remoteGuard /v:server1` in plaas daarvan om na CredSSP terug te val.

Microsoft het RCG vir multi-hop-toegang op Windows 11 22H2+ gebreek totdat die **April 2024 cumulative updates** (KB5036896/KB5036899/KB5036894) beskikbaar gestel is. Werk die client en intermediêre server by op, anders sal die tweede hop steeds misluk.<sup>[[5]](#references)</sup> Vinnige hotfix-kontrole:
```powershell
("KB5036896","KB5036899","KB5036894") | ForEach-Object {
Get-HotFix -Id $_ -ErrorAction SilentlyContinue
}
```
Met daardie builds geïnstalleer, kan die RDP-hop aan daaropvolgende Kerberos-uitdagings voldoen sonder om herbruikbare geheime op die eerste bediener bloot te stel.

## Oplossings

### Invoke Command

Om die double hop-probleem aan te spreek, word ’n metode aangebied wat ’n geneste `Invoke-Command` behels. Dit los nie die probleem direk op nie, maar bied ’n workaround sonder dat spesiale konfigurasies nodig is. Die benadering maak dit moontlik om ’n command (`hostname`) op ’n sekondêre bediener uit te voer deur middel van ’n PowerShell-command wat vanaf ’n aanvanklike aanvallende masjien uitgevoer word, of deur ’n vooraf gevestigde PS-Session met die eerste bediener. Só word dit gedoen:<sup>[[2]](#references)</sup>
```bash
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```
Alternatiewelik word voorgestel dat ’n PS-Session met die eerste server gevestig word en dat `Invoke-Command` met behulp van `$cred` uitgevoer word om take te sentraliseer.

### Register PSSession Configuration

’n Oplossing om die double hop-probleem te omseil, behels die gebruik van `Register-PSSessionConfiguration` saam met `Enter-PSSession`. Hierdie metode vereis ’n ander benadering as `evil-winrm` en maak ’n session moontlik wat nie onder die double hop-beperking ly nie.<sup>[[3]](#references)[[4]](#references)</sup>
```bash
Register-PSSessionConfiguration -Name doublehopsess -RunAsCredential domain_name\username
Restart-Service WinRM
Enter-PSSession -ConfigurationName doublehopsess -ComputerName TARGET_PC -Credential domain_name\username
klist
```
### PortForwarding

Vir plaaslike administrators op ’n tussenliggende teiken maak port forwarding dit moontlik om versoeke na ’n finale server te stuur. Deur `netsh` te gebruik, kan ’n reël vir port forwarding bygevoeg word, tesame met ’n Windows-firewallreël om die aangestuurde port toe te laat.<sup>[[2]](#references)</sup>
```bash
netsh interface portproxy add v4tov4 listenport=5446 listenaddress=10.35.8.17 connectport=5985 connectaddress=10.35.8.23
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=5446
```
#### winrs.exe

`winrs.exe` kan gebruik word vir die aanstuur van WinRM-versoeke, moontlik as ’n minder waarneembare opsie indien PowerShell-monitering ’n bekommernis is.<sup>[[2]](#references)</sup> Die opdrag hieronder demonstreer die gebruik daarvan:
```bash
winrs -r:http://bizintel:5446 -u:ta\redsuit -p:2600leet hostname
```
### OpenSSH

Die installering van OpenSSH op die eerste bediener maak 'n oplossing vir die double-hop-kwessie moontlik, wat veral nuttig is vir jump box-scenario's. Hierdie metode vereis CLI-installasie en die opstelling van OpenSSH vir Windows. Wanneer dit vir Password Authentication gekonfigureer is, stel dit die tussenbediener in staat om namens die gebruiker 'n TGT te verkry.<sup>[[2]](#references)</sup>

#### OpenSSH-installasiestappe

1. Laai die nuutste OpenSSH-vrystelling se zip-lêer af en skuif dit na die teikenbediener.
2. Pak dit uit en voer die `Install-sshd.ps1`-skrip uit.
3. Voeg 'n firewall-reël by om poort 22 oop te maak en verifieer dat SSH-dienste loop.

Om `Connection reset`-foute op te los, moet toestemmings moontlik opgedateer word om almal lees- en uitvoertoegang tot die OpenSSH-gids toe te laat.
```bash
icacls.exe "C:\Users\redsuit\Documents\ssh\OpenSSH-Win64" /grant Everyone:RX /T
```
### LSA Whisperer CacheLogon (Gevorderd)

**LSA Whisperer** (2024) stel die `msv1_0!CacheLogon`-pakketoproep bloot, sodat jy ’n bestaande *netwerk-aanmelding* met ’n bekende NT-hash kan saai in plaas daarvan om ’n nuwe sessie met `LogonUser` te skep. Deur die hash in die aanmeldingsessie in te spuit wat WinRM/PowerShell reeds op hop #1 oopgemaak het, kan daardie host by hop #2 authenticateer sonder om eksplisiete credentials te stoor of bykomende 4624-events te genereer.<sup>[[6]](#references)</sup>

1. Kry code execution binne LSASS (deaktiveer/misbruik PPL, of voer dit op ’n lab-VM uit wat jy beheer).
2. Enumerate aanmeldingsessies (bv. `lsa.exe sessions`) en teken die LUID aan wat met jou remoting-konteks ooreenstem.
3. Bereken die NT-hash vooraf en voer dit aan `CacheLogon`, en maak dit skoon wanneer jy klaar is.
```powershell
lsa.exe cachelogon --session 0x3e4 --domain ta --username redsuit --nthash a7c5480e8c1ef0ffec54e99275e6e0f7
lsa.exe cacheclear --session 0x3e4
```
Ná die cache seed, voer `Invoke-Command`/`New-PSSession` weer vanaf hop #1 uit: LSASS sal die injected hash hergebruik om aan Kerberos/NTLM-challenges vir die tweede hop te voldoen, en sodoende die double hop-beperking netjies omseil. Die nadeel is swaarder telemetry (code execution in LSASS), dus moet dit gebruik word vir omgewings met hoë friksie waar CredSSP/RCG nie toegelaat word nie.

## Verwysings

- [1] [Verstaan Kerberos Double Hop - Microsoft Community Hub](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20)
- [2] [Kerberos Double-Hop Workarounds](https://posts.slayerlabs.com/double-hop/)
- [3] [Nog ’n oplossing vir multi-hop PowerShell-remoting](https://learn.microsoft.com/en-gb/archive/blogs/sergey_babkins_blog/another-solution-to-multi-hop-powershell-remoting)
- [4] [Los die PowerShell multi-hop-probleem op sonder om CredSSP te gebruik](https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/)
- [5] [9 April 2024—KB5036896 (OS Build 17763.5696)](https://support.microsoft.com/en-au/topic/april-9-2024-kb5036896-os-build-17763-5696-efb580f1-2ce4-4695-b76c-d2068a00fb92)
- [6] [LSA Whisperer](https://specterops.io/blog/2024/04/17/lsa-whisperer/)

{{#include ../../banners/hacktricks-training.md}}
