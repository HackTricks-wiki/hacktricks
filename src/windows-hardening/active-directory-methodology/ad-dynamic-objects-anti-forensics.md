# AD Dynamic Objects (dynamicObject) Anti-Forensics

{{#include ../../banners/hacktricks-training.md}}

## कार्यप्रणाली और पहचान की मूल बातें

- कोई भी ऑब्जेक्ट जिसे सहायक क्लास **`dynamicObject`** के साथ बनाया गया है उसे **`entryTTL`** (सेकंड काउंटडाउन) और **`msDS-Entry-Time-To-Die`** (पक्का एक्सपायरी टाइम) मिलता है। जब `entryTTL` 0 पर पहुँचता है तो **Garbage Collector इसे बिना tombstone/recycle-bin के डिलीट कर देता है**, जिससे creator/timestamps हट जाते हैं और recovery अवरुद्ध हो जाती है।
- TTL को `entryTTL` अपडेट करके रिफ्रेश किया जा सकता है; न्यूनतम/डिफ़ॉल्ट मान **Configuration\Services\NTDS Settings → `msDS-Other-Settings` → `DynamicObjectMinTTL` / `DynamicObjectDefaultTTL`** में लागू होते हैं (1s–1y सपोर्ट करता है पर आमतौर पर डिफ़ॉल्ट 86,400s/24h होता है)। Dynamic objects **Configuration/Schema partitions में unsupported** हैं।
- DCs पर डिलीशन में कुछ मिनट का लेग हो सकता है अगर उनकी uptime कम हो (<24h), जो attributes क्वेरी/बैकअप के लिए तंग विंडो छोड़ता है। इसे डिटेक्ट करने के लिए **नए ऑब्जेक्ट्स जिनमें `entryTTL`/`msDS-Entry-Time-To-Die` होता है** पर अलर्ट करें और orphan SIDs/broken links के साथ कोरिलेट करें।

## MAQ एवेशन स्व-डिलीट करने वाले Computers के साथ

- Default **`ms-DS-MachineAccountQuota` = 10** किसी भी authenticated user को computers बनाने देता है। निर्माण के दौरान `dynamicObject` जोड़ने से कंप्यूटर self-delete हो जाता है और **quota स्लॉट खाली कर देता है** साथ ही सबूत मिटा देता है।
- Powermad tweak `New-MachineAccount` के अंदर (objectClass list):
```powershell
$request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
```
- Short TTL (उदा., 60s) अक्सर standard users के लिए विफल रहता है; AD `DynamicObjectDefaultTTL` पर fallback कर लेता है (उदाहरण: 86,400s). ADUC `entryTTL` छुपा सकता है, पर LDP/LDAP क्वेरी इसे दिखाती हैं।

## स्टील्थ Primary Group सदस्यता

- एक **dynamic security group** बनाएं, फिर किसी user का **`primaryGroupID`** उस group के RID पर सेट करें ताकि प्रभावशाली सदस्यता मिल सके जो **`memberOf` में दिखाई नहीं देती** पर Kerberos/access tokens में मान्य होती है।
- TTL एक्सपायर होने पर **group delete हो जाता है भले ही primary-group delete protection हो**, जिससे user का `primaryGroupID` एक नॉन-एक्जिस्टेंट RID की ओर करप्ट हो जाता है और कोई tombstone नहीं होता जिससे जांच करना मुश्किल हो जाता है कि अधिकार कैसे दिए गए थे।

## AdminSDHolder Orphan-SID प्रदूषण

- `CN=AdminSDHolder,CN=System,...` में **short-lived dynamic user/group** के लिए ACEs जोड़ें। TTL एक्सपायर होने के बाद उस SID को template ACL में **unresolvable (“Unknown SID”)** बन जाता है, और **SDProp (~60 min)** वह orphan SID सभी protected Tier-0 objects पर propagate कर देता है।
- फॉरेंसिक्स attribution खो देते हैं क्योंकि principal मौजूद नहीं रहता (कोई deleted-object DN नहीं)। मॉनिटरिंग के लिए **नए dynamic principals + AdminSDHolder/privileged ACLs पर अचानक orphan SIDs** पर अलर्ट करें।

## Self-Destructing सबूत के साथ Dynamic GPO Execution

- एक malicious **dynamic `groupPolicyContainer`** ऑब्जेक्ट बनाएं जिसमें खराब **`gPCFileSysPath`** (उदा., SMB share à la GPODDITY) हो और उसे लक्षित OU में **`gPLink`** के जरिए लिंक करें।
- क्लाइंट पॉलिसी को प्रोसेस करते हैं और attacker SMB से कंटेंट खींचते हैं। जब TTL एक्सपायर हो जाता है, तो GPO ऑब्जेक्ट (और `gPCFileSysPath`) गायब हो जाता है; केवल एक **broken `gPLink`** GUID बचता है, जो executed payload के LDAP साक्ष्यों को हटा देता है।

## Ephemeral AD-Integrated DNS रिडायरेक्शन

- AD DNS रिकॉर्ड्स **`dnsNode`** ऑब्जेक्ट्स होते हैं जो **DomainDnsZones/ForestDnsZones** में होते हैं। उन्हें **dynamic objects** के रूप में बनाने से अस्थायी host redirection संभव होता है (credential capture/MITM)। क्लाइंट्स malicious A/AAAA response को cache कर लेते हैं; बाद में रिकॉर्ड self-delete हो जाता है ताकि zone साफ़ दिखे (DNS Manager को व्यू रिफ्रेश करने के लिए zone reload की ज़रूरत पड़ सकती है)।
- डिटेक्शन: replication/event logs के माध्यम से **किसी भी DNS रिकॉर्ड जो `dynamicObject`/`entryTTL` रखता है** पर अलर्ट करें; अस्थायी रिकॉर्ड स्टैंडर्ड DNS लॉग्स में कम ही दिखाई देते हैं।

## Hybrid Entra ID Delta-Sync Gap (Note)

- Entra Connect delta sync deletes को detect करने के लिए **tombstones** पर निर्भर करता है। एक **dynamic on-prem user** Entra ID में sync हो सकता है, expire हो सकता है, और tombstone के बिना delete हो सकता है—delta sync क्लाउड अकाउंट को नहीं हटा पाएगा, जिससे एक **orphaned active Entra user** रह सकता है जब तक कि मैनुअल **full sync** न किया जाए।

## References

- [Dynamic Objects in Active Directory: The Stealthy Threat](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)

{{#include ../../banners/hacktricks-training.md}}
