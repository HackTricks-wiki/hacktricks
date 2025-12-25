# Kerberos Double Hop Problem

{{#include ../../banners/hacktricks-training.md}}


## परिचय

The Kerberos "Double Hop" problem तब सामने आती है जब कोई attacker Kerberos authentication को दो hops के पार उपयोग करने का प्रयास करता है, उदाहरण के लिए PowerShell/WinRM का उपयोग करते हुए।

जब Kerberos के माध्यम से authentication होता है, credentials memory में cache नहीं होते। इसलिए, अगर आप mimikatz चलाते हैं तो आपको मशीन में user के credentials नहीं मिलेंगे, भले ही वह processes चला रहा हो।

यह इसलिए है कि Kerberos से कनेक्ट करते समय ये कदम होते हैं:

1. User1 credentials प्रदान करता है और **domain controller** User1 को Kerberos **TGT** लौटाता है।
2. User1 **TGT** का उपयोग Server1 से **connect** करने के लिए **service ticket** का अनुरोध करने में करता है।
3. User1 **Server1** से **connect** करता है और **service ticket** प्रदान करता है।
4. **Server1** के पास User1 के **credentials** cached नहीं होते और न ही User1 का **TGT** होता है। इसलिए, जब Server1 से User1 किसी दूसरे सर्वर में लॉगिन करने की कोशिश करता है, तो वह **authenticate** नहीं कर पाता।

### Unconstrained Delegation

यदि **unconstrained delegation** PC में enabled है, तो यह समस्या नहीं होगी क्योंकि **Server** हर एक पहुँचने वाले user का **TGT** प्राप्त कर लेगा। इसके अलावा, अगर unconstrained delegation का उपयोग किया गया है तो आप संभवतः इससे **Domain Controller** को **compromise** कर सकते हैं।\
[**More info in the unconstrained delegation page**](unconstrained-delegation.md).

### CredSSP

Another way to avoid this problem which is [**notably insecure**](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/enable-wsmancredssp?view=powershell-7) is **Credential Security Support Provider**. Microsoft के अनुसार:

> CredSSP authentication स्थानीय computer से remote computer को user credentials delegate करता है। यह प्रैक्टिस remote operation के security risk को बढ़ाती है। यदि remote computer compromised हो जाता है, तो जब credentials उसे पास किए जाते हैं, तो उन credentials का उपयोग network session को नियंत्रित करने के लिए किया जा सकता है।

सुरक्षा चिंताओं के कारण, production systems, sensitive networks, और समान वातावरण में **CredSSP** को disabled रखने की सलाह दी जाती है। यह पता लगाने के लिए कि **CredSSP** enabled है या नहीं, `Get-WSManCredSSP` command चलायी जा सकती है। यह कमांड **CredSSP status** की जांच करने की अनुमति देती है और यह remotely भी execute की जा सकती है, बशर्ते **WinRM** enabled हो।
```bash
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
Get-WSManCredSSP
}
```
### Remote Credential Guard (RCG)

**Remote Credential Guard** उपयोगकर्ता का TGT मूल वर्कस्टेशन पर रखता है, जबकि RDP सत्र को अगले होप पर नए Kerberos service tickets का अनुरोध करने की अनुमति देता है। Enable **Computer Configuration > Administrative Templates > System > Credentials Delegation > Restrict delegation of credentials to remote servers** और **Require Remote Credential Guard** चुनें, फिर CredSSP पर वापस जाने के बजाय `mstsc.exe /remoteGuard /v:server1` के साथ कनेक्ट करें।

Microsoft ने Windows 11 22H2+ पर multi-hop access के लिए RCG को तब तक तोड़ दिया था जब तक कि **April 2024 cumulative updates** (KB5036896/KB5036899/KB5036894) नहीं आए। क्लाइंट और मध्यवर्ती सर्वर को पैच करें, अन्यथा दूसरा होप अभी भी असफल होगा। त्वरित hotfix चेक:
```powershell
("KB5036896","KB5036899","KB5036894") | ForEach-Object {
Get-HotFix -Id $_ -ErrorAction SilentlyContinue
}
```
उन बिल्ड्स को इंस्टॉल करने के बाद, RDP hop पहले सर्वर पर पुन: उपयोग योग्य रहस्यों को उजागर किए बिना डाउनस्ट्रीम Kerberos चुनौतियों को पूरा कर सकता है।

## समाधान

### Invoke Command

double hop समस्या को संबोधित करने के लिए, एक नेस्टेड `Invoke-Command` को शामिल करने वाला एक तरीका प्रस्तुत किया गया है। यह समस्या का सीधा समाधान नहीं है लेकिन विशेष कॉन्फ़िगरेशन की आवश्यकता के बिना एक वैकल्पिक समाधान प्रदान करता है। यह तरीका प्रारंभिक attacking मशीन से या पहले सर्वर के साथ पहले से स्थापित PS-Session के माध्यम से निष्पादित PowerShell कमांड के माध्यम से एक सेकेंडरी सर्वर पर एक कमांड (`hostname`) चलाने की अनुमति देता है। यहाँ बताया गया है कि इसे कैसे किया जाता है:
```bash
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```
वैकल्पिक रूप से, पहले सर्वर के साथ एक PS-Session स्थापित करना और केंद्रीयकृत कार्यों के लिए `$cred` का उपयोग करते हुए `Invoke-Command` चलाने की सलाह दी जाती है।

### Register PSSession Configuration

double hop problem को बायपास करने का एक समाधान `Register-PSSessionConfiguration` को `Enter-PSSession` के साथ उपयोग करना है। यह विधि `evil-winrm` से अलग तरीका अपनाने की मांग करती है और ऐसे session की अनुमति देती है जो double hop limitation से प्रभावित नहीं होता।
```bash
Register-PSSessionConfiguration -Name doublehopsess -RunAsCredential domain_name\username
Restart-Service WinRM
Enter-PSSession -ConfigurationName doublehopsess -ComputerName TARGET_PC -Credential domain_name\username
klist
```
### PortForwarding

अंतरिम लक्ष्य पर स्थानीय प्रशासकों के लिए, पोर्ट फॉरवर्डिंग अनुरोधों को अंतिम सर्वर पर भेजना संभव बनाती है। `netsh` का उपयोग करके, पोर्ट फॉरवर्डिंग के लिए एक नियम जोड़ा जा सकता है, और अग्रेषित पोर्ट की अनुमति देने के लिए Windows फ़ायरवॉल नियम भी बनाना होगा।
```bash
netsh interface portproxy add v4tov4 listenport=5446 listenaddress=10.35.8.17 connectport=5985 connectaddress=10.35.8.23
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=5446
```
#### winrs.exe

`winrs.exe` का उपयोग WinRM अनुरोधों को आगे भेजने के लिए किया जा सकता है, विशेष रूप से यदि PowerShell मॉनिटरिंग एक चिंता है तो यह कम पता चलने वाला विकल्प हो सकता है। नीचे दिया गया कमांड इसका उपयोग दर्शाता है:
```bash
winrs -r:http://bizintel:5446 -u:ta\redsuit -p:2600leet hostname
```
### OpenSSH

OpenSSH को पहले सर्वर पर इंस्टॉल करने से double-hop समस्या के लिए एक वर्कअराउंड मिल जाता है, जो विशेष रूप से jump box परिदृश्यों के लिए उपयोगी है। यह तरीका CLI द्वारा OpenSSH for Windows की इंस्टॉलेशन और सेटअप की आवश्यकता करता है। जब इसे Password Authentication के लिए कॉन्फ़िगर किया जाता है, तो यह मध्यवर्ती सर्वर को उपयोगकर्ता की ओर से TGT प्राप्त करने की अनुमति देता है।

#### OpenSSH Installation Steps

1. सबसे हाल की OpenSSH रिलीज़ zip फ़ाइल डाउनलोड करके target server पर ले जाएँ।
2. अनजिप करें और `Install-sshd.ps1` स्क्रिप्ट चलाएँ।
3. port 22 खोलने के लिए फ़ायरवॉल नियम जोड़ें और सत्यापित करें कि SSH सेवाएँ चल रही हैं।

To resolve `Connection reset` errors, OpenSSH निर्देशिका पर Everyone को read और execute access देने के लिए permissions अपडेट करने की आवश्यकता हो सकती है।
```bash
icacls.exe "C:\Users\redsuit\Documents\ssh\OpenSSH-Win64" /grant Everyone:RX /T
```
### LSA Whisperer CacheLogon (Advanced)

**LSA Whisperer** (2024) `msv1_0!CacheLogon` package call को प्रकट करता है ताकि आप मौजूद *network logon* को ज्ञात NT hash से seed कर सकें बजाय इसके कि आप `LogonUser` के साथ नया session बनाएं। उस hash को उस logon session में inject करके जिसे WinRM/PowerShell ने पहले hop #1 पर खोल रखा है, वह होस्ट hop #2 पर authenticate कर सकता है बिना explicit credentials को store किए या अतिरिक्त 4624 events उत्पन्न किए।

1. LSASS के अंदर code execution हासिल करें (या तो PPL को disable/abuse करें या अपने नियंत्रित lab VM पर चलाएँ)।
2. logon sessions की enumeration करें (उदा. `lsa.exe sessions`) और अपने remoting context के अनुरूप LUID capture करें।
3. NT hash को पहले से compute करें और उसे `CacheLogon` को feed करें, फिर काम खत्म होने पर उसे clear कर दें।
```powershell
lsa.exe cachelogon --session 0x3e4 --domain ta --username redsuit --nthash a7c5480e8c1ef0ffec54e99275e6e0f7
lsa.exe cacheclear --session 0x3e4
```
कैश सीड के बाद, hop #1 से `Invoke-Command`/`New-PSSession` पुनः चलाएँ: LSASS injected hash को reuse करेगा ताकि Kerberos/NTLM challenges दूसरे hop के लिए पूरा हो सकें, और यह double hop constraint को सुचारू रूप से बायपास कर देता है। इसके बदले में heavier telemetry (code execution in LSASS) होगी, इसलिए इसे उन high-friction environments के लिए रखें जहाँ CredSSP/RCG प्रतिबंधित हैं।

## संदर्भ

- [https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20)
- [https://posts.slayerlabs.com/double-hop/](https://posts.slayerlabs.com/double-hop/)
- [https://learn.microsoft.com/en-gb/archive/blogs/sergey_babkins_blog/another-solution-to-multi-hop-powershell-remoting](https://learn.microsoft.com/en-gb/archive/blogs/sergey_babkins_blog/another-solution-to-multi-hop-powershell-remoting)
- [https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/](https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/)
- [https://support.microsoft.com/en-au/topic/april-9-2024-kb5036896-os-build-17763-5696-efb580f1-2ce4-4695-b76c-d2068a00fb92](https://support.microsoft.com/en-au/topic/april-9-2024-kb5036896-os-build-17763-5696-efb580f1-2ce4-4695-b76c-d2068a00fb92)
- [https://specterops.io/blog/2024/04/17/lsa-whisperer/](https://specterops.io/blog/2024/04/17/lsa-whisperer/)


{{#include ../../banners/hacktricks-training.md}}
