# Kerberos Double Hop Problem

{{#include ../../banners/hacktricks-training.md}}


## Introduction

Kerberos "Double Hop" समस्या तब उत्पन्न होती है जब एक हमलावर **Kerberos प्रमाणीकरण का उपयोग करने** की कोशिश करता है **दो** **हॉप्स** के बीच, उदाहरण के लिए **PowerShell**/**WinRM** का उपयोग करते हुए।

जब **Kerberos** के माध्यम से **प्रमाणीकरण** होता है, तो **क्रेडेंशियल्स** **मेमोरी** में **कैश** नहीं होते। इसलिए, यदि आप mimikatz चलाते हैं, तो आप मशीन में उपयोगकर्ता के **क्रेडेंशियल्स** नहीं पाएंगे, भले ही वह प्रक्रियाएँ चला रहा हो।

यह इस कारण से है कि जब Kerberos के साथ कनेक्ट करते हैं, तो ये कदम होते हैं:

1. User1 क्रेडेंशियल्स प्रदान करता है और **डोमेन कंट्रोलर** User1 को एक Kerberos **TGT** लौटाता है।
2. User1 **TGT** का उपयोग करके **सेवा टिकट** का अनुरोध करता है **Server1** से **कनेक्ट** करने के लिए।
3. User1 **Server1** से **कनेक्ट** होता है और **सेवा टिकट** प्रदान करता है।
4. **Server1** के पास User1 के **क्रेडेंशियल्स** या User1 का **TGT** कैश नहीं होता। इसलिए, जब User1 Server1 से दूसरे सर्वर में लॉगिन करने की कोशिश करता है, तो वह **प्रमाणित** नहीं हो पाता।

### Unconstrained Delegation

यदि PC में **unconstrained delegation** सक्षम है, तो यह नहीं होगा क्योंकि **Server** प्रत्येक उपयोगकर्ता के लिए एक **TGT** प्राप्त करेगा जो इसे एक्सेस करता है। इसके अलावा, यदि unconstrained delegation का उपयोग किया जाता है, तो आप शायद **Domain Controller** को इससे **समझौता** कर सकते हैं।\
[**Unconstrained delegation पृष्ठ पर अधिक जानकारी**](unconstrained-delegation.md).

### CredSSP

इस समस्या से बचने का एक और तरीका है जो [**विशेष रूप से असुरक्षित**](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/enable-wsmancredssp?view=powershell-7) है, वह है **Credential Security Support Provider**। Microsoft से:

> CredSSP प्रमाणीकरण स्थानीय कंप्यूटर से दूरस्थ कंप्यूटर पर उपयोगकर्ता क्रेडेंशियल्स को डेलीगेट करता है। यह प्रथा दूरस्थ संचालन के सुरक्षा जोखिम को बढ़ाती है। यदि दूरस्थ कंप्यूटर से समझौता किया जाता है, तो जब क्रेडेंशियल्स इसे पास किए जाते हैं, तो क्रेडेंशियल्स का उपयोग नेटवर्क सत्र को नियंत्रित करने के लिए किया जा सकता है।

यह अत्यधिक अनुशंसा की जाती है कि **CredSSP** को उत्पादन प्रणालियों, संवेदनशील नेटवर्क और समान वातावरण में सुरक्षा चिंताओं के कारण बंद कर दिया जाए। यह निर्धारित करने के लिए कि **CredSSP** सक्षम है या नहीं, `Get-WSManCredSSP` कमांड चलाया जा सकता है। यह कमांड **CredSSP स्थिति की जांच** करने की अनुमति देता है और इसे दूरस्थ रूप से भी निष्पादित किया जा सकता है, बशर्ते **WinRM** सक्षम हो।
```powershell
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
Get-WSManCredSSP
}
```
## Workarounds

### Invoke Command

डबल हॉप समस्या को हल करने के लिए, एक नेस्टेड `Invoke-Command` शामिल करने वाली एक विधि प्रस्तुत की गई है। यह समस्या को सीधे हल नहीं करती है लेकिन विशेष कॉन्फ़िगरेशन की आवश्यकता के बिना एक वर्कअराउंड प्रदान करती है। यह दृष्टिकोण एक प्रारंभिक हमलावर मशीन से या पहले सर्वर के साथ पहले से स्थापित PS-Session के माध्यम से एक द्वितीयक सर्वर पर एक कमांड (`hostname`) निष्पादित करने की अनुमति देता है। इसे इस प्रकार किया जाता है:
```powershell
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```
वैकल्पिक रूप से, पहले सर्वर के साथ एक PS-Session स्थापित करना और `$cred` का उपयोग करके `Invoke-Command` चलाना कार्यों को केंद्रीकृत करने के लिए सुझावित है।

### PSSession कॉन्फ़िगरेशन पंजीकरण करें

डबल हॉप समस्या को बायपास करने के लिए एक समाधान `Enter-PSSession` के साथ `Register-PSSessionConfiguration` का उपयोग करना है। इस विधि के लिए `evil-winrm` की तुलना में एक अलग दृष्टिकोण की आवश्यकता होती है और यह एक सत्र की अनुमति देती है जो डबल हॉप सीमा से प्रभावित नहीं होती है।
```powershell
Register-PSSessionConfiguration -Name doublehopsess -RunAsCredential domain_name\username
Restart-Service WinRM
Enter-PSSession -ConfigurationName doublehopsess -ComputerName <pc_name> -Credential domain_name\username
klist
```
### PortForwarding

स्थानीय प्रशासकों के लिए एक मध्यवर्ती लक्ष्य पर, पोर्ट फॉरवर्डिंग अंतिम सर्वर पर अनुरोध भेजने की अनुमति देता है। `netsh` का उपयोग करके, पोर्ट फॉरवर्डिंग के लिए एक नियम जोड़ा जा सकता है, साथ ही फॉरवर्डेड पोर्ट की अनुमति देने के लिए एक Windows फ़ायरवॉल नियम भी।
```bash
netsh interface portproxy add v4tov4 listenport=5446 listenaddress=10.35.8.17 connectport=5985 connectaddress=10.35.8.23
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=5446
```
#### winrs.exe

`winrs.exe` का उपयोग WinRM अनुरोधों को अग्रेषित करने के लिए किया जा सकता है, यदि PowerShell निगरानी एक चिंता का विषय है तो यह एक कम पहचानने योग्य विकल्प हो सकता है। नीचे दिए गए कमांड इसका उपयोग दर्शाते हैं:
```bash
winrs -r:http://bizintel:5446 -u:ta\redsuit -p:2600leet hostname
```
### OpenSSH

पहले सर्वर पर OpenSSH स्थापित करना डबल-हॉप समस्या के लिए एक वर्कअराउंड सक्षम करता है, जो विशेष रूप से जंप बॉक्स परिदृश्यों के लिए उपयोगी है। इस विधि के लिए Windows के लिए OpenSSH की CLI स्थापना और सेटअप की आवश्यकता होती है। जब इसे पासवर्ड प्रमाणीकरण के लिए कॉन्फ़िगर किया जाता है, तो यह मध्यवर्ती सर्वर को उपयोगकर्ता की ओर से TGT प्राप्त करने की अनुमति देता है।

#### OpenSSH स्थापना चरण

1. नवीनतम OpenSSH रिलीज़ ज़िप को डाउनलोड करें और लक्षित सर्वर पर स्थानांतरित करें।
2. ज़िप निकालें और `Install-sshd.ps1` स्क्रिप्ट चलाएँ।
3. पोर्ट 22 खोलने के लिए एक फ़ायरवॉल नियम जोड़ें और सुनिश्चित करें कि SSH सेवाएँ चल रही हैं।

`Connection reset` त्रुटियों को हल करने के लिए, अनुमतियों को अपडेट करने की आवश्यकता हो सकती है ताकि सभी को OpenSSH निर्देशिका पर पढ़ने और निष्पादित करने की अनुमति मिल सके।
```bash
icacls.exe "C:\Users\redsuit\Documents\ssh\OpenSSH-Win64" /grant Everyone:RX /T
```
## संदर्भ

- [https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20)
- [https://posts.slayerlabs.com/double-hop/](https://posts.slayerlabs.com/double-hop/)
- [https://learn.microsoft.com/en-gb/archive/blogs/sergey_babkins_blog/another-solution-to-multi-hop-powershell-remoting](https://learn.microsoft.com/en-gb/archive/blogs/sergey_babkins_blog/another-solution-to-multi-hop-powershell-remoting)
- [https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/](https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/)


{{#include ../../banners/hacktricks-training.md}}
