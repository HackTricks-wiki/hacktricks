# AD Dynamic Objects (dynamicObject) Anti-Forensics

{{#include ../../banners/hacktricks-training.md}}

## Mechanics और Detection Basics

- Auxiliary class **`dynamicObject`** से बनाया गया कोई भी object **`entryTTL`** (seconds countdown) और **`msDS-Entry-Time-To-Die`** (absolute expiry) प्राप्त करता है। जब **`entryTTL`** 0 तक पहुंचता है और object का कोई descendant नहीं होता, तो Garbage Collector उसे tombstone/recycle-bin के बिना delete कर देता है, जिससे creator/timestamps मिट जाते हैं और recovery अवरुद्ध हो जाती है।<sup>[[4]](#references)</sup>
- **`entryTTL` एक operational/constructed attribute है**: LDAP queries में इसे explicitly request करें। TTL को expiry से पहले `entryTTL` update करके या LDAP TTL refresh OID **`1.3.6.1.4.1.1466.101.119.1`** के माध्यम से refresh किया जा सकता है।
- TTL min/default forest-wide AVAs हैं, जो **`CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,...` → `msDS-Other-Settings`** में होते हैं: `DynamicObjectMinTTLSeconds=<seconds>` और `DynamicObjectDefaultTTLSeconds=<seconds>`। Microsoft के अनुसार **86400s** default TTL और **900s** default minimum valid TTL हैं; `entryTTL` schema range **1–31557600s** है (एक second से एक year तक)।<sup>[[3]](#references)</sup> Configuration/Schema partitions में Dynamic objects **unsupported** हैं।
- **static→dynamic conversion नहीं होता** और expiry के बाद कोई tombstone phase नहीं होती। IR teams deleted-object controls या Recycle Bin पर निर्भर नहीं रह सकतीं; उन्हें GC द्वारा हटाए जाने से पहले live object/metadata capture करना होगा।
- Refresh **replica-sensitive** है: यदि TTL को expiry के बहुत करीब renew किया जाता है, तो कोई अन्य writable replica या GC refresh के replicate होने से पहले object को locally delete कर सकता है। इसलिए बहुत short TTLs तब सबसे प्रभावी होते हैं जब attacker को पता हो कि abuse को कौन-सा DC service करेगा, जबकि defenders को triage के दौरान **सभी naming contexts / replicas** query करने चाहिए।
- Short uptime (<24h) वाले DCs पर deletion में कुछ minutes की देरी हो सकती है, जिससे attributes को query/backup करने के लिए एक संकीर्ण response window मिलती है। **`entryTTL`/`msDS-Entry-Time-To-Die` वाले नए objects पर alerting** करके और orphan SIDs/broken links से correlation करके detect करें।<sup>[[1]](#references)</sup>

### Expiry graph और reference-cleanup edge cases

- Dynamic object के नीचे मौजूद हर descendant स्वयं dynamic होना चाहिए। Expired dynamic parent को Garbage Collector तभी collect करता है जब वह leaf बन जाए; यदि किसी descendant का `msDS-Entry-Time-To-Die` बाद का है, तो DC parent की expiration को maximum descendant expiration से आगे बढ़ा देता है। परिणामस्वरूप, writable dynamic subtree ऐसे parent को **pin/extend कर सकता है जो जल्द disappear होता हुआ दिखाई देता है**: इसके पूरे subtree को enumerate करें और parent के observed `entryTTL` को cleanup deadline न मानें।<sup>[[4]](#references)</sup>
- Expiry cleanup **schema-link-aware** है। Replicas deleted dynamic object को reference करने वाले linked attribute values को हटा देती हैं, लेकिन nonlinked values को बनाए रखती हैं। अपेक्षा करें कि सामान्य forward/back-link membership साफ हो जाएगी, जबकि `primaryGroupID`, `nTSecurityDescriptor` में embedded SIDs, या `gPLink` text जैसे integer/SID/string references forensic residue के रूप में बचे रह सकते हैं।<sup>[[4]](#references)</sup>

## Fast Enumeration / Live Triage

- केवल domain NC नहीं, बल्कि **RootDSE से सभी `namingContexts` query करें**। Dynamic abuse **`DomainDnsZones`/`ForestDnsZones`** (`dnsNode`) या application partitions में रह सकता है।
- जब तक object alive है, तुरंत **replication metadata** और सभी linked attributes/ACLs dump करें। Expiry के बाद आपके पास केवल **broken `gPLink` values, orphan SIDs, या cached DNS answers** बचे रह सकते हैं।<sup>[[1]](#references)</sup>
```powershell
(Get-ADForest).Domains | ForEach-Object {
Get-ADDomainController -Filter * -Server $_ | ForEach-Object {
$dc = $_.HostName
(Get-ADRootDSE -Server $dc).namingContexts | ForEach-Object {
Get-ADObject -Server $dc -LDAPFilter '(objectClass=dynamicObject)' -SearchBase $_ `
-Properties entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID |
Select-Object @{n='DC';e={$dc}},DistinguishedName,entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID
}
}
}
repadmin /showobjmeta <DC> <distinguishedName>
```
## Self-Deleting Computers के साथ MAQ Evasion

- Default **`ms-DS-MachineAccountQuota` = 10** किसी भी authenticated user को computers create करने देता है। Creation के दौरान `dynamicObject` जोड़ने पर computer स्वयं delete हो जाता है और **quota slot** को free कर देता है, साथ ही evidence भी मिटा देता है।
- `New-MachineAccount` के अंदर Powermad tweak (objectClass list):
```powershell
$request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
```
- यदि requested TTL **`DynamicObjectMinTTL`** से कम है, तो creation path के आधार पर server-side adjustment या rejection की अपेक्षा करें; कई domains में effective floor **900s** है और fallback/default **86400s** रहता है। ADUC `entryTTL` को छिपा सकता है, लेकिन LDP/LDAP queries इसे दिखा देती हैं।
- Object के मौजूद रहने तक defenders computer object पर **`msDS-CreatorSID`** से unprivileged creator को recover कर सकते हैं। Dynamic computer expire होने के बाद, attribution object के साथ ही गायब हो जाता है।<sup>[[1]](#references)</sup>

## Stealth Primary Group Membership

- एक **dynamic security group** create करें, फिर user के **`primaryGroupID`** को उस group के RID पर set करें, ताकि effective membership प्राप्त हो जाए जो **`memberOf`** में दिखाई नहीं देती, लेकिन Kerberos/access tokens में मान्य रहती है।<sup>[[1]](#references)</sup>
- TTL expiry **primary-group delete protection** के बावजूद group को delete कर देती है, जिससे user का `primaryGroupID` किसी non-existent RID की ओर point करता हुआ corrupted रह जाता है और privilege कैसे grant किया गया, इसकी जांच के लिए कोई tombstone नहीं बचता।
- Reporting tool-dependent है: **`Get-ADGroupMember` / `net group`** आमतौर पर primary-group-derived membership को resolve करते हैं, जबकि **`memberOf`** और **`Get-ADGroup -Properties member`** नहीं करते। व्यापक `primaryGroupID` tradecraft के लिए [DCShadow और PGID abuse के बारे में यह अन्य page](dcshadow.md) देखें।
- **non-AdminSDHolder-protected** targets के लिए attackers dynamic-group trick को **`primaryGroupID` पढ़ने पर DACL deny** (या group के `member` attribute पर deny) के साथ जोड़ सकते हैं, ताकि group expire होने से पहले ही कई LDAP/PowerShell workflows से link छिपाया जा सके।<sup>[[2]](#references)</sup>

## AdminSDHolder Orphan-SID Pollution

- एक **short-lived dynamic user/group** के लिए **`CN=AdminSDHolder,CN=System,...`** में ACEs जोड़ें। TTL expiry के बाद SID template ACL में **unresolvable (“Unknown SID”)** बन जाता है, और **SDProp (~60 min)** उस orphan SID को सभी protected Tier-0 objects में propagate कर देता है।
- Forensics attribution खो देती है क्योंकि principal मौजूद नहीं रहता (कोई deleted-object DN नहीं)। **new dynamic principals + AdminSDHolder/privileged ACLs पर sudden orphan SIDs** की monitoring करें।<sup>[[1]](#references)</sup>

## Self-Destructing Evidence के साथ Dynamic GPO Execution

- एक malicious **`gPCFileSysPath`** (जैसे GPODDITY की तरह SMB share) वाला **dynamic `groupPolicyContainer`** object create करें और उसे **`gPLink`** के माध्यम से target OU से link करें।
- Clients policy को process करते हैं और attacker SMB से content pull करते हैं। TTL expire होने पर GPO object (और **`gPCFileSysPath`**) गायब हो जाता है; केवल एक **broken `gPLink`** GUID बचता है, जिससे executed payload का LDAP evidence हट जाता है।
- यह classic **GPODDITY-style** cleanup से operationally अधिक साफ है: original `gPCFileSysPath` को स्वयं restore करने के बजाय, timer expire होने पर AD malicious GPC को automatically remove कर देता है।<sup>[[1]](#references)</sup> Protocol और tooling details के लिए [ACL persistence abuse](acl-persistence-abuse/README.md#gpcfilesyspath-poisoning-with-gpoddity) देखें, उन्हें यहां दोहराने के बजाय।

## Ephemeral AD-Integrated DNS Redirection

- AD DNS records **`dnsNode`** objects होते हैं, जो **DomainDnsZones/ForestDnsZones** में रहते हैं। इन्हें **dynamic objects** के रूप में create करने पर temporary host redirection (credential capture/MITM) संभव होती है। Clients malicious A/AAAA response को cache कर लेते हैं; record बाद में स्वयं delete हो जाता है, जिससे zone साफ दिखाई देता है (view refresh करने के लिए DNS Manager को zone reload की आवश्यकता हो सकती है)।
- Detection: replication/event logs के माध्यम से **`dynamicObject`/`entryTTL`** रखने वाले **किसी भी DNS record** पर alert करें; transient records standard DNS logs में शायद ही दिखाई देते हैं।<sup>[[1]](#references)</sup>

## Hybrid Entra ID Delta-Sync Gap (Note)

- Entra Connect delta sync deletes का पता लगाने के लिए **tombstones** पर निर्भर करता है। एक **dynamic on-prem user** Entra ID से sync हो सकता है, expire हो सकता है और tombstone के बिना delete हो सकता है—delta sync cloud account को remove नहीं करेगा, जिससे **orphaned active Entra user** तब तक बना रहेगा जब तक **initial/full sync** या manual cloud cleanup force न किया जाए।<sup>[[1]](#references)</sup>



## References

- [1] [Active Directory में Dynamic Objects: Stealthy Threat](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)
- [2] [Primary Group Behavior, Reporting और Exploitation में Adventures](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)
- [3] [TTL Limits का Configuration](https://learn.microsoft.com/en-us/windows/win32/ad/configuration-of-ttl-limits)
- [4] [[MS-ADTS]: DynamicObject Requirements](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a0ea4e75-4b34-4f97-ae06-a8b19a5aaa5b)
{{#include ../../banners/hacktricks-training.md}}
