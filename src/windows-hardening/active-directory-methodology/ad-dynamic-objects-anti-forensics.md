# AD Dynamic Objects (dynamicObject) Anti-Forensics

{{#include ../../banners/hacktricks-training.md}}

## Mechanics & Detection Basics

- **`dynamicObject`** auxiliary class के साथ बनाया गया कोई भी object **`entryTTL`** (seconds countdown) और **`msDS-Entry-Time-To-Die`** (absolute expiry) प्राप्त करता है। जब `entryTTL` 0 तक पहुंचता है, **Garbage Collector** इसे **tombstone/recycle-bin** के बिना delete कर देता है, जिससे creator/timestamps मिट जाते हैं और recovery block हो जाती है।
- **`entryTTL` एक operational/constructed attribute** है: इसे LDAP queries में explicitly request करें। TTL को या तो expiry से पहले `entryTTL` update करके, या LDAP TTL refresh OID **`1.3.6.1.4.1.1466.101.119.1`** के जरिए refresh किया जा सकता है।
- TTL min/default **Configuration\Services\NTDS Settings → `msDS-Other-Settings` → `DynamicObjectMinTTL` / `DynamicObjectDefaultTTL`** में enforced होते हैं। Microsoft default TTL के रूप में **86400s** और default minimum valid TTL के रूप में **900s** document करता है; दोनों **1s–1y** support करते हैं। Dynamic objects **Configuration/Schema partitions** में unsupported हैं।
- Expiry के बाद **static→dynamic conversion** नहीं होती और tombstone phase भी नहीं आता। IR teams deleted-object controls या Recycle Bin पर भरोसा नहीं कर सकतीं; उन्हें GC के object हटाने से पहले live object/metadata capture करना होगा।
- Refresh **replica-sensitive** है: अगर TTL को expiry के बहुत करीब renew किया जाए, तो कोई दूसरी writable replica या GC फिर भी object को locally delete कर सकती है, इससे पहले कि refresh replicate हो। इसलिए बहुत short TTLs तब सबसे अच्छे होते हैं जब attacker को पता हो कि abuse किस DC पर service होगा, जबकि defenders triage के दौरान **all naming contexts / replicas** query करें।
- Short uptime (<24h) वाले DCs पर deletion कुछ मिनट lag कर सकती है, जिससे attributes query/backup करने के लिए एक छोटा response window मिलता है। **new objects carrying `entryTTL`/`msDS-Entry-Time-To-Die`** पर alert करके और orphan SIDs/broken links के साथ correlate करके detect करें।

## Fast Enumeration / Live Triage

- केवल domain NC नहीं, बल्कि RootDSE से **all `namingContexts`** query करें। Dynamic abuse **`DomainDnsZones`/`ForestDnsZones`** (`dnsNode`) या application partitions में हो सकता है।
- Object अभी alive हो तो तुरंत **replication metadata** और linked attributes/ACLs dump करें। Expiry के बाद आपके पास सिर्फ **broken `gPLink` values, orphan SIDs, या cached DNS answers** बच सकते हैं।
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

- Default **`ms-DS-MachineAccountQuota` = 10** किसी भी authenticated user को computers create करने देता है। Creation के दौरान `dynamicObject` जोड़ें ताकि computer self-delete हो जाए और **quota slot free** हो जाए, साथ ही evidence भी wipe हो जाए।
- Powermad tweak inside `New-MachineAccount` (objectClass list):
```powershell
$request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
```
- अगर requested TTL **`DynamicObjectMinTTL`** से नीचे है, तो creation path के हिसाब से server-side adjustment या rejection की उम्मीद करें; कई domains में effective floor **900s** होता है और fallback/default **86400s** रहता है। ADUC `entryTTL` को hide कर सकता है, लेकिन LDP/LDAP queries इसे reveal कर देती हैं।
- Object के exist करने के दौरान, defenders अभी भी computer object पर **`msDS-CreatorSID`** से unprivileged creator recover कर सकते हैं। Dynamic computer expire होने के बाद, यह attribution object के साथ ही disappear हो जाती है।

## Stealth Primary Group Membership

- एक **dynamic security group** बनाएं, फिर user के **`primaryGroupID`** को उस group के RID पर set करें ताकि effective membership मिले जो **`memberOf`** में नहीं दिखती, लेकिन Kerberos/access tokens में honored होती है।
- TTL expiry **primary-group delete protection के बावजूद group को delete** कर देती है, जिससे user के पास एक corrupted **`primaryGroupID`** रह जाता है जो non-existent RID की तरफ point करता है और privilege कैसे दी गई थी यह investigate करने के लिए कोई tombstone नहीं बचता।
- Reporting tool-dependent है: **`Get-ADGroupMember` / `net group`** आमतौर पर primary-group-derived membership resolve करते हैं, जबकि **`memberOf`** और **`Get-ADGroup -Properties member`** नहीं करते। broader `primaryGroupID` tradecraft के लिए, [DCShadow and PGID abuse के बारे में यह दूसरा page](dcshadow.md) देखें।
- **non-AdminSDHolder-protected** targets के लिए, attackers dynamic-group trick को **`primaryGroupID`** (या group `member` attribute) पढ़ने पर **DACL deny** के साथ pair कर सकते हैं ताकि group expire होने से पहले भी कई LDAP/PowerShell workflows से link hide रहे।

## AdminSDHolder Orphan-SID Pollution

- **`CN=AdminSDHolder,CN=System,...`** में **short-lived dynamic user/group** के लिए ACEs जोड़ें। TTL expiry के बाद SID template ACL में **unresolvable (“Unknown SID”)** बन जाता है, और **SDProp (~60 min)** उस orphan SID को सभी protected Tier-0 objects पर propagate कर देता है।
- Forensics attribution खो देती है क्योंकि principal गायब हो चुका होता है (deleted-object DN नहीं होता)। **new dynamic principals + AdminSDHolder/privileged ACLs पर sudden orphan SIDs** के लिए monitor करें।

## Self-Destructing Evidence के साथ Dynamic GPO Execution

- Malicious **`gPCFileSysPath`** के साथ एक **dynamic `groupPolicyContainer`** object बनाएं (जैसे GPODDITY की तरह SMB share) और इसे target OU से **`gPLink`** के जरिए link करें।
- Clients policy process करते हैं और attacker SMB से content pull करते हैं। TTL expire होने पर GPO object (और **`gPCFileSysPath`**) vanish हो जाता है; सिर्फ एक **broken `gPLink`** GUID बचता है, जिससे executed payload का LDAP evidence हट जाता है।
- यह classic **GPODDITY-style** cleanup से operationally cleaner है: original `gPCFileSysPath` खुद restore करने के बजाय, AD timer expire होते ही malicious GPC को automatically remove कर देता है।

## Ephemeral AD-Integrated DNS Redirection

- AD DNS records **`DomainDnsZones/ForestDnsZones`** में **`dnsNode`** objects होते हैं। इन्हें **dynamic objects** की तरह create करने से temporary host redirection (credential capture/MITM) संभव होती है। Clients malicious A/AAAA response cache कर लेते हैं; record बाद में self-delete हो जाता है ताकि zone clean दिखे (DNS Manager को view refresh करने के लिए zone reload की जरूरत पड़ सकती है)।
- Detection: replication/event logs के जरिए **`dynamicObject`/`entryTTL`** वाले किसी भी DNS record पर alert करें; transient records standard DNS logs में rarely दिखाई देते हैं।

## Hybrid Entra ID Delta-Sync Gap (Note)

- Entra Connect delta sync deletes detect करने के लिए **tombstones** पर rely करता है। एक **dynamic on-prem user** Entra ID में sync हो सकता है, expire हो सकता है, और tombstone के बिना delete हो सकता है—delta sync cloud account को remove नहीं करेगा, जिससे **orphaned active Entra user** रह जाएगा जब तक **initial/full sync** या manual cloud cleanup force न की जाए।

## References

- [Dynamic Objects in Active Directory: The Stealthy Threat](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)
- [Adventures in Primary Group Behavior, Reporting, and Exploitation](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)

{{#include ../../banners/hacktricks-training.md}}
