# Kerberos Double Hop Problem

{{#include ../../banners/hacktricks-training.md}}


## परिचय

Kerberos "Double Hop" problem तब दिखाई देती है जब attacker **Kerberos authentication को दो** **hops** में उपयोग करने का प्रयास करता है, उदाहरण के लिए **PowerShell**/**WinRM** का उपयोग करके।

जब **authentication** **Kerberos** के माध्यम से होती है, तो **credentials** **memory** में cache **नहीं** होते। इसलिए, यदि आप mimikatz चलाते हैं, तो आपको machine में user के **credentials नहीं मिलेंगे**, भले ही वह processes चला रहा हो।

ऐसा इसलिए होता है क्योंकि Kerberos के साथ connect करते समय ये steps होते हैं:<sup>[[1]](#references)</sup>

1. User1 credentials प्रदान करता है और **domain controller**, User1 को Kerberos **TGT** लौटाता है।
2. User1 Server1 से **connect** करने के लिए **TGT** का उपयोग करके **service ticket** का अनुरोध करता है।
3. User1 **Server1 से connect** करता है और **service ticket** प्रदान करता है।
4. **Server1** के पास User1 के **credentials** cache या User1 का **TGT** **नहीं** होता। इसलिए, जब User1 Server1 से दूसरे server में login करने का प्रयास करता है, तो वह **authenticate करने में सक्षम नहीं** होता।

### Unconstrained Delegation

यदि PC में **unconstrained delegation** enabled है, तो ऐसा नहीं होगा, क्योंकि **Server**, उस तक access करने वाले प्रत्येक user का **TGT** **प्राप्त** कर लेगा। इसके अलावा, यदि unconstrained delegation का उपयोग किया जाता है, तो संभवतः आप उससे **Domain Controller को compromise** कर सकते हैं।\
[**unconstrained delegation page में अधिक जानकारी**](unconstrained-delegation.md)।

### CredSSP

इस problem से बचने का एक अन्य तरीका [**notably insecure**](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/enable-wsmancredssp?view=powershell-7) **Credential Security Support Provider** है। Microsoft के अनुसार:

> CredSSP authentication, local computer से remote computer पर user credentials delegate करता है। इस practice से remote operation का security risk बढ़ जाता है। यदि remote computer compromise हो जाता है, तो credentials उसके पास भेजे जाने पर उनका उपयोग network session को control करने के लिए किया जा सकता है।

Security concerns के कारण production systems, sensitive networks और इसी प्रकार के environments पर **CredSSP** को disabled रखना अत्यधिक recommended है। यह निर्धारित करने के लिए कि **CredSSP** enabled है या नहीं, `Get-WSManCredSSP` command चलाई जा सकती है। यह command **CredSSP status की जाँच** करने की अनुमति देती है और इसे remotely भी execute किया जा सकता है, बशर्ते **WinRM** enabled हो।
```bash
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
Get-WSManCredSSP
}
```
### Remote Credential Guard (RCG)

**Remote Credential Guard** उपयोगकर्ता के TGT को originating workstation पर रखता है, जबकि RDP session को next hop पर नए Kerberos service tickets का अनुरोध करने की अनुमति देता है। **Computer Configuration > Administrative Templates > System > Credentials Delegation > Restrict delegation of credentials to remote servers** को enable करें और **Require Remote Credential Guard** चुनें, फिर CredSSP पर fallback करने के बजाय `mstsc.exe /remoteGuard /v:server1` से connect करें।

Microsoft ने Windows 11 22H2+ पर multi-hop access के लिए RCG को **April 2024 cumulative updates** (KB5036896/KB5036899/KB5036894) तक ठीक नहीं किया था। Client और intermediary server को patch करें, अन्यथा second hop अभी भी fail होगा।<sup>[[5]](#references)</sup> Quick hotfix check:
```powershell
("KB5036896","KB5036899","KB5036894") | ForEach-Object {
Get-HotFix -Id $_ -ErrorAction SilentlyContinue
}
```
इन builds के installed होने पर, RDP hop पहले server पर reusable secrets expose किए बिना downstream Kerberos challenges को satisfy कर सकता है।

## Workarounds

### Invoke Command

double hop issue को address करने के लिए nested `Invoke-Command` से जुड़ा एक method प्रस्तुत किया गया है। यह समस्या को सीधे solve नहीं करता, लेकिन special configurations की आवश्यकता के बिना एक workaround प्रदान करता है। यह approach initial attacking machine से execute की गई PowerShell command या पहले server के साथ पहले से established PS-Session के माध्यम से secondary server पर एक command (`hostname`) execute करने की अनुमति देती है। इसे इस प्रकार किया जाता है:<sup>[[2]](#references)</sup>
```bash
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```
वैकल्पिक रूप से, पहले server के साथ PS-Session स्थापित करना और tasks को centralize करने के लिए `$cred` का उपयोग करके `Invoke-Command` चलाने का सुझाव दिया जाता है।

### Register PSSession Configuration

double hop problem को bypass करने का एक solution `Enter-PSSession` के साथ `Register-PSSessionConfiguration` का उपयोग करना है। इस method के लिए `evil-winrm` की तुलना में अलग approach की आवश्यकता होती है और यह ऐसी session की अनुमति देता है जो double hop limitation से प्रभावित नहीं होती।<sup>[[3]](#references)[[4]](#references)</sup>
```bash
Register-PSSessionConfiguration -Name doublehopsess -RunAsCredential domain_name\username
Restart-Service WinRM
Enter-PSSession -ConfigurationName doublehopsess -ComputerName TARGET_PC -Credential domain_name\username
klist
```
### PortForwarding

किसी intermediary target पर local administrators के लिए, port forwarding requests को final server तक भेजने की अनुमति देता है। `netsh` का उपयोग करके port forwarding के लिए एक rule जोड़ा जा सकता है, साथ ही forwarded port को अनुमति देने के लिए Windows firewall rule भी जोड़ा जा सकता है।<sup>[[2]](#references)</sup>
```bash
netsh interface portproxy add v4tov4 listenport=5446 listenaddress=10.35.8.17 connectport=5985 connectaddress=10.35.8.23
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=5446
```
#### winrs.exe

`winrs.exe` का उपयोग WinRM requests को forward करने के लिए किया जा सकता है, और यदि PowerShell monitoring चिंता का विषय हो, तो यह कम detectable विकल्प हो सकता है।<sup>[[2]](#references)</sup> नीचे दिया गया command इसके उपयोग को प्रदर्शित करता है:
```bash
winrs -r:http://bizintel:5446 -u:ta\redsuit -p:2600leet hostname
```
### OpenSSH

पहले server पर OpenSSH install करने से double-hop समस्या के लिए workaround सक्षम होता है, जो विशेष रूप से jump box scenarios में उपयोगी है। इस method के लिए Windows के लिए OpenSSH की CLI installation और setup आवश्यक है। Password Authentication के साथ configure किए जाने पर, यह intermediary server को user की ओर से TGT प्राप्त करने की अनुमति देता है।<sup>[[2]](#references)</sup>

#### OpenSSH Installation Steps

1. नवीनतम OpenSSH release zip को download करके target server पर move करें।
2. इसे unzip करें और `Install-sshd.ps1` script चलाएँ।
3. port 22 खोलने के लिए firewall rule जोड़ें और verify करें कि SSH services चल रही हैं।

`Connection reset` errors को resolve करने के लिए, OpenSSH directory पर everyone को read और execute access देने हेतु permissions update करने की आवश्यकता हो सकती है।
```bash
icacls.exe "C:\Users\redsuit\Documents\ssh\OpenSSH-Win64" /grant Everyone:RX /T
```
### LSA Whisperer CacheLogon (Advanced)

**LSA Whisperer** (2024) `msv1_0!CacheLogon` package call को expose करता है, जिससे आप `LogonUser` के साथ fresh session बनाने के बजाय किसी मौजूदा *network logon* में ज्ञात NT hash डाल सकते हैं। hop #1 पर WinRM/PowerShell द्वारा पहले से खोले गए logon session में hash inject करने पर वह host explicit credentials store किए बिना या अतिरिक्त 4624 events generate किए बिना hop #2 से authenticate कर सकता है।<sup>[[6]](#references)</sup>

1. LSASS के अंदर code execution प्राप्त करें (या तो PPL को disable/abuse करें या अपने नियंत्रण वाले lab VM पर चलाएँ)।
2. Logon sessions enumerate करें (जैसे `lsa.exe sessions`) और अपने remoting context से संबंधित LUID capture करें।
3. NT hash को pre-compute करके `CacheLogon` में feed करें, फिर काम पूरा होने पर उसे clear कर दें।
```powershell
lsa.exe cachelogon --session 0x3e4 --domain ta --username redsuit --nthash a7c5480e8c1ef0ffec54e99275e6e0f7
lsa.exe cacheclear --session 0x3e4
```
Cache seed के बाद hop #1 से `Invoke-Command`/`New-PSSession` दोबारा चलाएँ: LSASS दूसरे hop के लिए Kerberos/NTLM challenges को पूरा करने हेतु injected hash का फिर से उपयोग करेगा, जिससे double hop constraint आसानी से bypass हो जाता है। इसका trade-off अधिक telemetry है (LSASS में code execution), इसलिए इसे उन high-friction environments के लिए रखें जहाँ CredSSP/RCG disallowed हों।

## References

- [1] [Kerberos Double Hop को समझना - Microsoft Community Hub](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20)
- [2] [Kerberos Double-Hop के Workarounds](https://posts.slayerlabs.com/double-hop/)
- [3] [multi-hop PowerShell remoting का एक अन्य समाधान](https://learn.microsoft.com/en-gb/archive/blogs/sergey_babkins_blog/another-solution-to-multi-hop-powershell-remoting)
- [4] [CredSSP का उपयोग किए बिना PowerShell multi-hop समस्या हल करें](https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/)
- [5] [9 अप्रैल, 2024—KB5036896 (OS Build 17763.5696)](https://support.microsoft.com/en-au/topic/april-9-2024-kb5036896-os-build-17763-5696-efb580f1-2ce4-4695-b76c-d2068a00fb92)
- [6] [LSA Whisperer](https://specterops.io/blog/2024/04/17/lsa-whisperer/)

{{#include ../../banners/hacktricks-training.md}}
