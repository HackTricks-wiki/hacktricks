# AD Dynamic Objects (dynamicObject) Anti-Forensics

{{#include ../../banners/hacktricks-training.md}}

## मैकेनिक्स और डिटेक्शन मूल बातें

- ऑक्सिलियरी क्लास **`dynamicObject`** से बने किसी भी ऑब्जेक्ट को **`entryTTL`** (सेकंड काउंटडाउन) और **`msDS-Entry-Time-To-Die`** (परमापी समाप्ति) मिलते हैं। जब `entryTTL` शून्य हो जाता है तो **Garbage Collector इसे tombstone/recycle-bin के बिना हटाता है**, निर्माता/टाइमस्टैम्प मिट जाते हैं और रिकवरी ब्लॉक हो जाती है।
- TTL को `entryTTL` अपडेट करके रिफ्रेश किया जा सकता है; मिन/डिफ़ॉल्ट मान **Configuration\Services\NTDS Settings → `msDS-Other-Settings` → `DynamicObjectMinTTL` / `DynamicObjectDefaultTTL`** में लागू होते हैं (1s–1y का समर्थन करता है पर आमतौर पर डिफ़ॉल्ट 86,400s/24h होता है)। Dynamic objects को Configuration/Schema partitions में सपोर्ट नहीं किया जाता।
- कुछ मिनटों तक डिलीशन देरी हो सकती है उन DCs पर जिनकी uptime छोटी है (<24h), जिससे एट्रिब्यूट क्वेरी/बैकअप के लिए संकीर्ण विंडो रहता है। नए ऑब्जेक्ट जो `entryTTL`/`msDS-Entry-Time-To-Die` लेते हैं पर अलर्ट देकर और orphan SIDs/broken links के साथ कोरिलेट करके डिटेक्ट करें।

## MAQ Evasion with Self-Deleting Computers

- डिफ़ॉल्ट **`ms-DS-MachineAccountQuota` = 10** किसी भी authenticated user को computers बनाने देता है। निर्माण के दौरान `dynamicObject` जोड़ें ताकि कंप्यूटर self-delete हो जाए और **quota स्लॉट खाली कर दे** जबकि सबूत मिटा दिए जाएँ।
- Powermad tweak `New-MachineAccount` के अंदर (objectClass सूची):
```powershell
$request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
```
- छोटा TTL (उदा., 60s) सामान्य उपयोगकर्ताओं के लिए अक्सर फेल होता है; AD वापस **`DynamicObjectDefaultTTL`** पर लौटता है (उदाहरण: 86,400s)। ADUC `entryTTL` छिपा सकता है, पर LDP/LDAP क्वेरीज इसे प्रकट कर देते हैं।

## Stealth Primary Group Membership

- एक **dynamic security group** बनाएं, फिर किसी यूजर का **`primaryGroupID`** उस समूह के RID पर सेट करें ताकि प्रभावी सदस्यता मिल सके जो **`memberOf` में नहीं दिखती** पर Kerberos/access tokens में मान्य रहती है।
- TTL समाप्ति समूह को हटा देती है भले ही primary-group delete protection हो, जिससे यूजर का `primaryGroupID` एक नॉन-एक्जिस्टेंट RID की ओर भ्रष्ट हो जाता है और कोई tombstone नहीं रहता कि यह अधिकार कैसे दिया गया था।

## AdminSDHolder Orphan-SID Pollution

- एक **शॉर्ट-लिव्ड dynamic user/group** के लिए ACEs जोड़ें `CN=AdminSDHolder,CN=System,...` में। TTL समाप्ति के बाद SID टेम्पलेट ACL में **unresolvable (“Unknown SID”)** बन जाता है, और **SDProp (~60 min)** यह orphan SID सभी प्रोटेक्टेड Tier-0 ऑब्जेक्ट्स पर फैलाता है।
- फॉरेंसिक्स attribution खो देता है क्योंकि प्रिंसिपल जा चुका होता है (कोई deleted-object DN नहीं)। नए dynamic principals + AdminSDHolder/privileged ACLs पर अचानक orphan SIDs के लिए मॉनिटर करें।

## Dynamic GPO Execution with Self-Destructing Evidence

- एक **dynamic `groupPolicyContainer`** ऑब्जेक्ट बनाएं जिसमें malicious **`gPCFileSysPath`** (उदा., SMB share जैसे GPODDITY) हो और इसे `gPLink` के जरिए टार्गेट OU से लिंक करें।
- क्लाइंट पॉलिसी प्रोसेस करते हैं और attacker SMB से कंटेंट खींचते हैं। जब TTL समाप्त होता है, GPO ऑब्जेक्ट (और `gPCFileSysPath`) गायब हो जाता है; केवल एक **broken `gPLink`** GUID बचती है, जो executed payload के LDAP सबूत को हटा देती है।

## Ephemeral AD-Integrated DNS Redirection

- AD DNS रिकॉर्ड्स **`dnsNode`** ऑब्जेक्ट्स होते हैं DomainDnsZones/ForestDnsZones में। इन्हें **dynamic objects** के रूप में बनाने से अस्थायी होस्ट रीडायरेक्शन संभव होता है (credential capture/MITM)। क्लाइंट्स malicious A/AAAA response को कैश करते हैं; रिकॉर्ड बाद में self-delete हो जाता है ताकि ज़ोन साफ़ दिखे (DNS Manager को व्यू रिफ्रेश करने के लिए zone reload की ज़रूरत पड़ सकती है)।
- डिटेक्शन: replication/event logs के माध्यम से **किसी भी DNS रिकॉर्ड पर जो `dynamicObject`/`entryTTL` लेता है** पर अलर्ट करें; अस्थायी रिकॉर्ड सामान्य DNS लॉग्स में शायद ही दिखते हैं।

## Hybrid Entra ID Delta-Sync Gap (Note)

- Entra Connect delta sync deletes का पता लगाने के लिए **tombstones** पर निर्भर करता है। एक **dynamic on-prem user** Entra ID को सिंक कर सकता है, expire हो सकता है, और बिना tombstone के हट सकता है—delta sync क्लाउड अकाउंट को नहीं हटाएगा, जिससे एक **orphaned active Entra user** बचा रह सकता है जब तक कि मैन्युअल **full sync** न चलाया जाए।

## संदर्भ

- [Dynamic Objects in Active Directory: The Stealthy Threat](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)

{{#include ../../banners/hacktricks-training.md}}
