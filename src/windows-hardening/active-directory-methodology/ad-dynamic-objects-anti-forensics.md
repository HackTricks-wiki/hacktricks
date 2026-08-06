# AD Dynamic Objects (dynamicObject) Anti-Forensics

{{#include ../../banners/hacktricks-training.md}}

## Mechanics और Detection Basics

- auxiliary class **`dynamicObject`** से बनाया गया कोई भी object **`entryTTL`** (seconds countdown) और **`msDS-Entry-Time-To-Die`** (absolute expiry) प्राप्त करता है। जब **`entryTTL`** 0 तक पहुंचता है, तो **Garbage Collector** इसे tombstone/recycle-bin के बिना delete कर देता है, जिससे creator/timestamps मिट जाते हैं और recovery रुक जाती है।
- **`entryTTL` एक operational/constructed attribute** है: LDAP queries में इसे explicitly request करें। TTL को expiry से पहले **`entryTTL`** update करके या LDAP TTL refresh OID **`1.3.6.1.4.1.1466.101.119.1`** के जरिए refresh किया जा सकता है।
- TTL min/default को **Configuration\Services\NTDS Settings → `msDS-Other-Settings` → `DynamicObjectMinTTL` / `DynamicObjectDefaultTTL`** में enforce किया जाता है। Microsoft **86400s** को default TTL और **900s** को default minimum valid TTL के रूप में document करता है; दोनों **1s–1y** को support करते हैं। Configuration/Schema partitions में dynamic objects **unsupported** हैं।
- **static→dynamic conversion** मौजूद नहीं है और expiry के बाद कोई tombstone phase नहीं होती। IR teams deleted-object controls या Recycle Bin पर निर्भर नहीं रह सकतीं; उन्हें GC द्वारा हटाए जाने से पहले live object/metadata capture करना होगा।
- Refresh **replica-sensitive** होता है: यदि TTL को expiry के बहुत करीब renew किया जाता है, तो कोई अन्य writable replica या GC refresh के replicate होने से पहले object को locally delete कर सकता है। इसलिए बहुत छोटे TTL तब सबसे अच्छे काम करते हैं जब attacker को पता हो कि abuse किस DC द्वारा service किया जाएगा, जबकि defenders को triage के दौरान **सभी naming contexts / replicas** query करने चाहिए।
- Short uptime (<24h) वाले DCs पर deletion में कुछ मिनट की देरी हो सकती है, जिससे attributes को query/backup करने के लिए response की एक संकीर्ण window मिलती है। **`entryTTL`/`msDS-Entry-Time-To-Die`** वाले नए objects पर alerting करके और orphan SIDs/broken links के साथ correlation करके detect करें।<sup>[[1]](#references)</sup>

## Fast Enumeration / Live Triage

- केवल domain NC ही नहीं, **RootDSE** से सभी **`namingContexts`** query करें। Dynamic abuse **`DomainDnsZones`/`ForestDnsZones`** (`dnsNode`) या application partitions में भी मौजूद हो सकता है।
- जब object अभी live हो, तो तुरंत **replication metadata** और सभी linked attributes/ACLs dump करें। Expiry के बाद आपके पास केवल **broken `gPLink` values, orphan SIDs, या cached DNS answers** बच सकते हैं।<sup>[[1]](#references)</sup>
```powershell
$root = Get-ADRootDSE
$root.namingContexts | ForEach-Object {
Get-ADObject -LDAPFilter '(objectClass=dynamicObject)' -SearchBase $_ `
-Properties entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID |
Select-Object DistinguishedName,entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID
}
repadmin /showobjmeta <DC> <distinguishedName>
```
## Self-Deleting Computers के साथ MAQ Evasion

- Default **`ms-DS-MachineAccountQuota` = 10** किसी भी authenticated user को computers create करने देता है। Creation के दौरान `dynamicObject` जोड़ने से computer खुद delete हो जाता है और **quota slot** free कर देता है, साथ ही evidence भी मिटा देता है।
- `New-MachineAccount` के अंदर Powermad tweak (objectClass list):
```powershell
$request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
```
- यदि requested TTL **`DynamicObjectMinTTL`** से कम है, तो creation path के आधार पर server-side adjustment या rejection की अपेक्षा करें; कई domains में effective floor **900s** होता है और fallback/default **86400s** रहता है। ADUC `entryTTL` को छिपा सकता है, लेकिन LDP/LDAP queries इसे दिखाती हैं।
- जब तक object मौजूद रहता है, defenders computer object पर **`msDS-CreatorSID`** से unprivileged creator का पता लगा सकते हैं। Dynamic computer expire होने के बाद वह attribution object के साथ ही गायब हो जाता है।<sup>[[1]](#references)</sup>

## Stealth Primary Group Membership

- एक **dynamic security group** create करें, फिर उस group के RID को user के **`primaryGroupID`** में set करें, ताकि effective membership प्राप्त हो जाए जो **`memberOf`** में दिखाई नहीं देती, लेकिन Kerberos/access tokens में मान्य होती है।<sup>[[1]](#references)</sup>
- TTL expiry **primary-group delete protection** के बावजूद group को delete कर देती है, जिससे user का **`primaryGroupID`** किसी non-existent RID की ओर point करता रहता है और privilege कैसे दिया गया, इसकी जाँच के लिए कोई tombstone नहीं बचता।
- Reporting tool-dependent है: **`Get-ADGroupMember` / `net group`** आमतौर पर primary-group-derived membership को resolve करते हैं, जबकि **`memberOf`** और **`Get-ADGroup -Properties member`** नहीं करते। व्यापक **`primaryGroupID`** tradecraft के लिए [DCShadow और PGID abuse के बारे में यह अन्य page](dcshadow.md) देखें।
- **non-AdminSDHolder-protected** targets के लिए, attackers dynamic-group trick को **`primaryGroupID`** (या group के **`member`** attribute) को पढ़ने पर **DACL deny** के साथ जोड़ सकते हैं, ताकि group expire होने से पहले ही कई LDAP/PowerShell workflows से link छिपाया जा सके।<sup>[[2]](#references)</sup>

## AdminSDHolder Orphan-SID Pollution

- **short-lived dynamic user/group** के लिए **`CN=AdminSDHolder,CN=System,...`** में ACEs जोड़ें। TTL expiry के बाद template ACL में SID **unresolvable (“Unknown SID”)** हो जाता है और **SDProp (~60 min)** उस orphan SID को सभी protected Tier-0 objects में propagate कर देता है।
- Forensics attribution खो देती है क्योंकि principal समाप्त हो चुका होता है (कोई deleted-object DN नहीं)। **AdminSDHolder/privileged ACLs पर नए dynamic principals + अचानक orphan SIDs** के लिए monitor करें।<sup>[[1]](#references)</sup>

## Self-Destructing Evidence के साथ Dynamic GPO Execution

- एक malicious **`gPCFileSysPath`** (जैसे GPODDITY जैसा SMB share) वाला **dynamic `groupPolicyContainer`** object create करें और उसे **`gPLink`** के माध्यम से target OU से link करें।
- Clients policy को process करते हैं और attacker SMB से content pull करते हैं। TTL expire होने पर GPO object (और **`gPCFileSysPath`**) गायब हो जाता है; केवल एक **broken `gPLink`** GUID बचता है, जिससे executed payload का LDAP evidence हट जाता है।
- यह classic **GPODDITY-style** cleanup से operationally अधिक साफ है: original `gPCFileSysPath` को स्वयं restore करने के बजाय, timer expire होने पर AD malicious GPC को automatically remove कर देता है।<sup>[[1]](#references)</sup>

## Ephemeral AD-Integrated DNS Redirection

- AD DNS records **`dnsNode`** objects होते हैं, जो **DomainDnsZones/ForestDnsZones** में स्थित होते हैं। इन्हें **dynamic objects** के रूप में create करने से temporary host redirection (credential capture/MITM) संभव होती है। Clients malicious A/AAAA response को cache कर लेते हैं; बाद में record खुद delete हो जाता है, जिससे zone clean दिखाई देती है (view refresh करने के लिए DNS Manager को zone reload की आवश्यकता हो सकती है)।
- Detection: replication/event logs के माध्यम से **`dynamicObject`/`entryTTL`** रखने वाले **किसी भी DNS record** पर alert करें; transient records standard DNS logs में शायद ही दिखाई देते हैं।<sup>[[1]](#references)</sup>

## Hybrid Entra ID Delta-Sync Gap (Note)

- Entra Connect delta sync deletes का पता लगाने के लिए **tombstones** पर निर्भर करता है। एक **dynamic on-prem user** Entra ID से sync हो सकता है, expire हो सकता है और tombstone के बिना delete हो सकता है—delta sync cloud account को remove नहीं करेगा, जिससे **orphaned active Entra user** तब तक बना रहेगा जब तक **initial/full sync** या manual cloud cleanup force न किया जाए।<sup>[[1]](#references)</sup>

## References

- [1] [Dynamic Objects in Active Directory: The Stealthy Threat](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)
- [2] [Adventures in Primary Group Behavior, Reporting, and Exploitation](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)

{{#include ../../banners/hacktricks-training.md}}
