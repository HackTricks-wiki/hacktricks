# Kerberos Double Hop Tatizo

{{#include ../../banners/hacktricks-training.md}}


## Utangulizi

Tatizo la Kerberos "Double Hop" linaonekana wakati mshambuliaji anajaribu kutumia **Kerberos authentication across two** **hops**, kwa mfano akitumia **PowerShell**/**WinRM**.

Wakati **authentication** inapotokea kupitia **Kerberos**, **credentials** **hazihifadhiwi** kwenye **memory.** Kwa hivyo, ikiwa utaendesha mimikatz hutaona **credentials** za mtumiaji kwenye mashine hata kama anafanya michakato.

Hii ni kwa sababu wakati wa kuunganishwa kwa Kerberos hatua ni hizi:

1. User1 anatoa **credentials** na **domain controller** hurudisha Kerberos **TGT** kwa User1.
2. User1 anatumia **TGT** kuomba **service ticket** ili **connect** na Server1.
3. User1 **connects** kwa **Server1** na anatoa **service ticket**.
4. **Server1** **haina** **credentials** za User1 zilizohifadhiwa (cached) au **TGT** ya User1. Kwa hivyo, wakati User1 kutoka Server1 anapojaribu kuingia kwenye server ya pili, yeye **hatawezi kuthibitisha utambulisho**.

### Unconstrained Delegation

If **unconstrained delegation** is enabled in the PC, this won't happen as the **Server** will **get** a **TGT** of each user accessing it. Moreover, if unconstrained delegation is used you probably can **compromise the Domain Controller** from it.\
[**More info in the unconstrained delegation page**](unconstrained-delegation.md).

### CredSSP

Another way to avoid this problem which is [**notably insecure**](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/enable-wsmancredssp?view=powershell-7) is **Credential Security Support Provider**. From Microsoft:

> CredSSP authentication inapeleka credentials za mtumiaji kutoka kwenye kompyuta ya eneo hadi kwenye kompyuta ya mbali. Tabia hii inaongeza hatari ya usalama ya operesheni ya mbali. Ikiwa kompyuta ya mbali imevamiwa, wakati credentials zinapopitishwa kwako, credentials zinaweza kutumika kudhibiti kikao cha mtandao.

Inashauriwa sana kwamba **CredSSP** izimwe kwenye systems za production, mitandao yenye hisia, na mazingira yanayofanana kutokana na masuala ya usalama. Ili kubaini kama **CredSSP** imewezeshwa, unaweza kuendesha amri `Get-WSManCredSSP`. Amri hii inaruhusu **checking of CredSSP status** na inaweza hata kuendeshwa kwa mbali, mradi tu **WinRM** imewezeshwa.
```bash
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
Get-WSManCredSSP
}
```
### Remote Credential Guard (RCG)

**Remote Credential Guard** inahifadhi TGT ya mtumiaji kwenye workstation ya asili huku ikiruhusu kikao cha RDP kuomba tiketi mpya za huduma za Kerberos kwenye hop inayofuata. Weka **Computer Configuration > Administrative Templates > System > Credentials Delegation > Restrict delegation of credentials to remote servers** na chagua **Require Remote Credential Guard**, kisha ungane kwa kutumia `mstsc.exe /remoteGuard /v:server1` badala ya kurejea kwa CredSSP.

Microsoft iliharibu RCG kwa ufikiaji wa multi-hop kwenye Windows 11 22H2+ hadi **April 2024 cumulative updates** (KB5036896/KB5036899/KB5036894). Sakinisha patch kwenye client na intermediary server, vinginevyo second hop bado itashindwa. Ukaguzi mfupi wa hotfix:
```powershell
("KB5036896","KB5036899","KB5036894") | ForEach-Object {
Get-HotFix -Id $_ -ErrorAction SilentlyContinue
}
```
Kwa kuwa matoleo hayo yamesanikishwa, RDP hop inaweza kutimiza changamoto za Kerberos zinazofuata bila kufichua siri zinazoweza kutumika tena kwenye server ya kwanza.

## Workarounds

### Invoke Command

Ili kushughulikia tatizo la double hop, inatolewa njia inayohusisha `Invoke-Command` iliyowekwa ndani. Hii haisuluhishi tatizo moja kwa moja lakini inatoa suluhisho la kuzunguka bila kuhitaji usanidi maalum. Njia hii inaruhusu kutekeleza amri (`hostname`) kwenye server ya pili kupitia amri ya PowerShell inayotekelezwa kutoka kwenye attacking machine ya awali au kupitia PS-Session iliyowekwa awali na server ya kwanza. Hapa jinsi inavyofanywa:
```bash
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```
Badala yake, kuanzisha PS-Session na server ya kwanza na kuendesha `Invoke-Command` ukitumia `$cred` kunapendekezwa kwa ajili ya kuzingatia majukumu.

### Register PSSession Configuration

Suluhisho la kukwepa tatizo la double hop linahusisha kutumia `Register-PSSessionConfiguration` pamoja na `Enter-PSSession`. Njia hii inahitaji mbinu tofauti kuliko `evil-winrm` na inaruhusu session ambayo haiko chini ya kikwazo cha double hop.
```bash
Register-PSSessionConfiguration -Name doublehopsess -RunAsCredential domain_name\username
Restart-Service WinRM
Enter-PSSession -ConfigurationName doublehopsess -ComputerName TARGET_PC -Credential domain_name\username
klist
```
### PortForwarding

Kwa wasimamizi wa ndani kwenye lengo la mpatanishi, port forwarding inaruhusu maombi kutumwa kwa seva ya mwisho. Kwa kutumia `netsh`, kanuni inaweza kuongezwa kwa ajili ya port forwarding, pamoja na kanuni ya Windows firewall ili kuruhusu port iliyotumwa.
```bash
netsh interface portproxy add v4tov4 listenport=5446 listenaddress=10.35.8.17 connectport=5985 connectaddress=10.35.8.23
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=5446
```
#### winrs.exe

`winrs.exe` inaweza kutumika kwa forwarding maombi ya WinRM, pengine kama chaguo isiyogundulika ikiwa ufuatiliaji wa PowerShell ni wasiwasi. Amri hapa chini inaonyesha matumizi yake:
```bash
winrs -r:http://bizintel:5446 -u:ta\redsuit -p:2600leet hostname
```
### OpenSSH

Kufunga OpenSSH kwenye seva ya kwanza kunaruhusu njia mbadala kwa tatizo la double-hop, haswa muhimu kwa jump box scenarios. Njia hii inahitaji ufungaji kupitia CLI na usanidi wa OpenSSH kwa Windows. Ikiwa imesanidiwa kwa Password Authentication, hii inamruhusu seva ya kati kupata TGT kwa niaba ya mtumiaji.

#### Hatua za Ufungaji za OpenSSH

1. Pakua na hamisha zip ya toleo la hivi karibuni la OpenSSH kwenye seva lengwa.
2. Toa (unzip) na endesha script ya `Install-sshd.ps1`.
3. Ongeza sheria ya firewall ili kufungua port 22 na hakiki kuwa huduma za SSH zinaendelea kufanya kazi.

Ili kutatua makosa ya `Connection reset`, ruhusa zinaweza kuhitaji kusasishwa ili kumruhusu kila mtu haki za kusoma na kutekeleza kwenye directory ya OpenSSH.
```bash
icacls.exe "C:\Users\redsuit\Documents\ssh\OpenSSH-Win64" /grant Everyone:RX /T
```
### LSA Whisperer CacheLogon (Ya hali ya juu)

**LSA Whisperer** (2024) inafichua mwito wa kifurushi `msv1_0!CacheLogon` ili uweze kupandia *network logon* iliyopo na NT hash inayojulikana badala ya kuunda kikao kipya kwa `LogonUser`. Kwa kuingiza hash ndani ya kikao cha logon ambacho WinRM/PowerShell tayari imefungua kwenye hop #1, host hiyo inaweza ku-authenticate kwa hop #2 bila kuhifadhi explicit credentials au kuzalisha matukio ya ziada ya 4624.

1. Pata utekelezaji wa msimbo ndani ya LSASS (ama uzime/tumia vibaya PPL au endesha kwenye VM ya maabara unayodhibiti).
2. Orodhesha vikao vya logon (mf. `lsa.exe sessions`) na kamata LUID inayolingana na muktadha wako wa remoting.
3. Hesabu mapema NT hash na uipe `CacheLogon`, kisha ufute wakati umemaliza.
```powershell
lsa.exe cachelogon --session 0x3e4 --domain ta --username redsuit --nthash a7c5480e8c1ef0ffec54e99275e6e0f7
lsa.exe cacheclear --session 0x3e4
```
Baada ya kuanzisha cache, endelea tena `Invoke-Command`/`New-PSSession` kutoka hop #1: LSASS itatumia tena hash iliyopachikwa ili kutosheleza changamoto za Kerberos/NTLM kwa hop ya pili, kwa ufanisi kuepuka vikwazo vya double hop. Gharama yake ni telemetry nzito (code execution in LSASS), hivyo uitumie tu kwa mazingira yenye ugumu mkubwa ambapo CredSSP/RCG haziruhusiwi.

## Marejeo

- [https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20)
- [https://posts.slayerlabs.com/double-hop/](https://posts.slayerlabs.com/double-hop/)
- [https://learn.microsoft.com/en-gb/archive/blogs/sergey_babkins_blog/another-solution-to-multi-hop-powershell-remoting](https://learn.microsoft.com/en-gb/archive/blogs/sergey_babkins_blog/another-solution-to-multi-hop-powershell-remoting)
- [https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/](https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/)
- [https://support.microsoft.com/en-au/topic/april-9-2024-kb5036896-os-build-17763-5696-efb580f1-2ce4-4695-b76c-d2068a00fb92](https://support.microsoft.com/en-au/topic/april-9-2024-kb5036896-os-build-17763-5696-efb580f1-2ce4-4695-b76c-d2068a00fb92)
- [https://specterops.io/blog/2024/04/17/lsa-whisperer/](https://specterops.io/blog/2024/04/17/lsa-whisperer/)


{{#include ../../banners/hacktricks-training.md}}
