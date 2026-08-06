# Kerberos Double Hop Problem

{{#include ../../banners/hacktricks-training.md}}


## Utangulizi

Tatizo la Kerberos "Double Hop" hutokea wakati mshambuliaji anapojaribu kutumia **Kerberos authentication kupitia** **hops** mbili, kwa mfano akitumia **PowerShell**/**WinRM**.

Wakati **authentication** inapotokea kupitia **Kerberos**, **credentials** **hazihifadhiwi** kwenye **memory.** Kwa hivyo, ukiendesha mimikatz **hutapata credentials** za mtumiaji kwenye mashine hata kama anaendesha processes.

Hii hutokea kwa sababu wakati wa kuunganisha kwa Kerberos, hatua huwa kama zifuatazo:<sup>[[1]](#references)</sup>

1. User1 hutoa credentials na **domain controller** hurudisha Kerberos **TGT** kwa User1.
2. User1 hutumia **TGT** kuomba **service ticket** ili **kuunganisha** kwenye Server1.
3. User1 **huunganisha** kwenye **Server1** na kutoa **service ticket**.
4. **Server1** **haina** **credentials** za User1 zilizohifadhiwa au **TGT** ya User1. Kwa hivyo, User1 anapojaribu ku-login kwenye server ya pili kutoka Server1, **hawezi kufanya authentication**.

### Unconstrained Delegation

Ikiwa **unconstrained delegation** imewezeshwa kwenye PC, hili halitatokea kwa sababu **Server** **itapata** **TGT** ya kila mtumiaji anayeifikia. Zaidi ya hayo, ikiwa unconstrained delegation inatumika, huenda ukaweza **kucompromise Domain Controller** kutoka humo.\
[**Maelezo zaidi kwenye ukurasa wa unconstrained delegation**](unconstrained-delegation.md).

### CredSSP

Njia nyingine ya kuepuka tatizo hili ambayo ni [**notably insecure**](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/enable-wsmancredssp?view=powershell-7) ni **Credential Security Support Provider**. Kutoka kwa Microsoft:

> CredSSP authentication hukabidhi credentials za mtumiaji kutoka kwenye kompyuta ya ndani kwenda kwenye kompyuta ya mbali. Zoezi hili huongeza security risk ya operesheni ya mbali. Ikiwa kompyuta ya mbali imecompromise, credentials zinapopitishwa kwake, zinaweza kutumiwa kudhibiti network session.

Inapendekezwa sana kwamba **CredSSP** izimwe kwenye production systems, networks nyeti, na mazingira yanayofanana kutokana na security concerns. Ili kubaini ikiwa **CredSSP** imewezeshwa, command ya `Get-WSManCredSSP` inaweza kuendeshwa. Command hii huruhusu **kukagua hali ya CredSSP** na inaweza hata kutekelezwa remotely, mradi **WinRM** imewezeshwa.
```bash
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
Get-WSManCredSSP
}
```
### Remote Credential Guard (RCG)

**Remote Credential Guard** huhifadhi TGT ya mtumiaji kwenye workstation asili huku ikiendelea kuruhusu RDP session kuomba Kerberos service tickets mpya kwenye hop inayofuata. Washa **Computer Configuration > Administrative Templates > System > Credentials Delegation > Restrict delegation of credentials to remote servers** na uchague **Require Remote Credential Guard**, kisha unganisha kwa `mstsc.exe /remoteGuard /v:server1` badala ya kutumia CredSSP.

Microsoft ilivuruga RCG kwa multi-hop access kwenye Windows 11 22H2+ hadi **April 2024 cumulative updates** (KB5036896/KB5036899/KB5036894). Fanya patch client na intermediary server, vinginevyo second hop bado itashindikana.<sup>[[5]](#references)</sup> Ukaguzi wa haraka wa hotfix:
```powershell
("KB5036896","KB5036899","KB5036894") | ForEach-Object {
Get-HotFix -Id $_ -ErrorAction SilentlyContinue
}
```
Kwa builds hizo zikiwa zimesakinishwa, RDP hop inaweza kukidhi Kerberos challenges za downstream bila kufichua secrets zinazoweza kutumika tena kwenye server ya kwanza.

## Workarounds

### Invoke Command

Ili kushughulikia tatizo la double hop, method inayohusisha `Invoke-Command` iliyowekwa ndani ya nyingine inawasilishwa. Hii haisuluhishi tatizo moja kwa moja, lakini hutoa workaround bila kuhitaji configurations maalum. Approach hii inaruhusu kutekeleza command (`hostname`) kwenye server ya pili kupitia PowerShell command inayotekelezwa kutoka kwa attacking machine ya awali au kupitia PS-Session iliyokuwa imeanzishwa awali na server ya kwanza. Hivi ndivyo inavyofanywa:<sup>[[2]](#references)</sup>
```bash
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```
Vinginevyo, inapendekezwa kuanzisha PS-Session na server ya kwanza na kuendesha `Invoke-Command` kwa kutumia `$cred` ili kuweka tasks katika sehemu moja.

### Sajili PSSession Configuration

Suluhisho la kukwepa double hop problem linahusisha kutumia `Register-PSSessionConfiguration` pamoja na `Enter-PSSession`. Mbinu hii inahitaji njia tofauti na `evil-winrm` na inaruhusu session ambayo haiathiriwi na kizuizi cha double hop.<sup>[[3]](#references)[[4]](#references)</sup>
```bash
Register-PSSessionConfiguration -Name doublehopsess -RunAsCredential domain_name\username
Restart-Service WinRM
Enter-PSSession -ConfigurationName doublehopsess -ComputerName TARGET_PC -Credential domain_name\username
klist
```
### PortForwarding

Kwa local administrators kwenye intermediary target, port forwarding huruhusu requests kutumwa kwenye final server. Kwa kutumia `netsh`, rule inaweza kuongezwa kwa port forwarding, pamoja na Windows firewall rule ili kuruhusu forwarded port.<sup>[[2]](#references)</sup>
```bash
netsh interface portproxy add v4tov4 listenport=5446 listenaddress=10.35.8.17 connectport=5985 connectaddress=10.35.8.23
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=5446
```
#### winrs.exe

`winrs.exe` inaweza kutumiwa kusambaza maombi ya WinRM, na huenda ikawa chaguo lisilotambulika kwa urahisi ikiwa ufuatiliaji wa PowerShell ni tatizo.<sup>[[2]](#references)</sup> Amri iliyo hapa chini inaonyesha matumizi yake:
```bash
winrs -r:http://bizintel:5446 -u:ta\redsuit -p:2600leet hostname
```
### OpenSSH

Kusakinisha OpenSSH kwenye server ya kwanza huwezesha workaround ya tatizo la double-hop, ambayo ni muhimu hasa katika hali za jump box. Njia hii inahitaji usakinishaji na usanidi wa OpenSSH for Windows kupitia CLI. Ikisanidiwa kwa Password Authentication, server ya kati inaweza kupata TGT kwa niaba ya mtumiaji.<sup>[[2]](#references)</sup>

#### Hatua za Usakinishaji wa OpenSSH

1. Pakua na uhamishe zip ya toleo jipya zaidi la OpenSSH kwenye server lengwa.
2. Ifungue na uendeshe script ya `Install-sshd.ps1`.
3. Ongeza firewall rule ya kufungua port 22 na uthibitishe kuwa huduma za SSH zinafanya kazi.

Ili kutatua errors za `Connection reset`, huenda ruhusa zikahitaji kusasishwa ili kuruhusu kila mtu kupata ruhusa za kusoma na kutekeleza kwenye directory ya OpenSSH.
```bash
icacls.exe "C:\Users\redsuit\Documents\ssh\OpenSSH-Win64" /grant Everyone:RX /T
```
### LSA Whisperer CacheLogon (Advanced)

**LSA Whisperer** (2024) hufichua package call ya `msv1_0!CacheLogon`, hivyo unaweza ku-seed *network logon* iliyopo kwa kutumia NT hash inayojulikana badala ya kuunda session mpya kwa `LogonUser`. Kwa ku-inject hash hiyo kwenye logon session ambayo WinRM/PowerShell tayari imefungua kwenye hop #1, host hiyo inaweza ku-authenticate kwenye hop #2 bila kuhifadhi credentials za moja kwa moja au kuzalisha events za ziada za 4624.<sup>[[6]](#references)</sup>

1. Pata code execution ndani ya LSASS (ama zima/tumia vibaya PPL au endesha kwenye lab VM unayoidhibiti).
2. Enumerate logon sessions (kwa mfano, `lsa.exe sessions`) na capture LUID inayohusiana na remoting context yako.
3. Pre-compute NT hash na uipe kwa `CacheLogon`, kisha i-clear ukimaliza.
```powershell
lsa.exe cachelogon --session 0x3e4 --domain ta --username redsuit --nthash a7c5480e8c1ef0ffec54e99275e6e0f7
lsa.exe cacheclear --session 0x3e4
```
Baada ya cache seed, endesha tena `Invoke-Command`/`New-PSSession` kutoka hop #1: LSASS itatumia tena hash iliyoingizwa ili kutimiza changamoto za Kerberos/NTLM kwa hop ya pili, na hivyo kukwepa kwa urahisi kizuizi cha double hop. Hasara ni telemetry nyingi zaidi (utekelezaji wa code ndani ya LSASS), kwa hivyo itumie katika mazingira yenye vikwazo vikali ambapo CredSSP/RCG hairuhusiwi.

## Marejeo

- [1] [Kuelewa Kerberos Double Hop - Microsoft Community Hub](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20)
- [2] [Njia Mbadala za Kerberos Double-Hop](https://posts.slayerlabs.com/double-hop/)
- [3] [Suluhisho lingine la multi-hop PowerShell remoting](https://learn.microsoft.com/en-gb/archive/blogs/sergey_babkins_blog/another-solution-to-multi-hop-powershell-remoting)
- [4] [Tatua tatizo la PowerShell multi-hop bila kutumia CredSSP](https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/)
- [5] [Aprili 9, 2024—KB5036896 (OS Build 17763.5696)](https://support.microsoft.com/en-au/topic/april-9-2024-kb5036896-os-build-17763-5696-efb580f1-2ce4-4695-b76c-d2068a00fb92)
- [6] [LSA Whisperer](https://specterops.io/blog/2024/04/17/lsa-whisperer/)

{{#include ../../banners/hacktricks-training.md}}
