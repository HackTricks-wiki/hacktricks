# AD Dynamic Objects (dynamicObject) Anti-Forensics

{{#include ../../banners/hacktricks-training.md}}

## Mechanics & Detection Basics

- Kitu chochote kilichoundwa kwa auxiliary class **`dynamicObject`** hupata **`entryTTL`** (hesabu ya sekunde zinazobaki) na **`msDS-Entry-Time-To-Die`** (muda halisi wa kuisha). Wakati `entryTTL` inapofika 0, **Garbage Collector huifuta bila tombstone/recycle-bin**, ikifuta creator/timestamps na kuzuia recovery.
- **`entryTTL` ni attribute ya operational/constructed**: iombe wazi kwenye LDAP queries. TTL inaweza kusasishwa ama kwa ku-update `entryTTL` kabla ya kuisha au kupitia LDAP TTL refresh OID **`1.3.6.1.4.1.1466.101.119.1`**.
- TTL min/default zinatekelezwa katika **Configuration\Services\NTDS Settings → `msDS-Other-Settings` → `DynamicObjectMinTTL` / `DynamicObjectDefaultTTL`**. Microsoft inaandika **86400s** kama default TTL na **900s** kama default minimum valid TTL; zote zinaunga mkono **1s–1y**. Dynamic objects **hazitumiki** katika Configuration/Schema partitions.
- Hakuna **static→dynamic conversion** na hakuna tombstone phase baada ya expiration. Timu za IR haziwezi kutegemea deleted-object controls au Recycle Bin; lazima zikamate live object/metadata kabla ya GC kuiondoa.
- Refresh ni **replica-sensitive**: ikiwa TTL inafanywa upya karibu sana na expiration, replica nyingine inayoweza kuandikwa au GC bado inaweza kufuta object kwa locally kabla refresh haijareplicate. Hivyo TTL fupi sana hufanya kazi vizuri zaidi wakati attacker anajua ni DC gani itahudumia abuse, huku defenders wakitakiwa ku-query **all naming contexts / replicas** wakati wa triage.
- Deletion inaweza kuchelewa kwa dakika chache kwenye DCs zenye uptime fupi (<24h), ikiacha dirisha dogo la response la ku-query/backup attributes. Tambua kwa **ku-alert kwenye new objects zenye `entryTTL`/`msDS-Entry-Time-To-Die`** na ku-correlate na orphan SIDs/broken links.

## Fast Enumeration / Live Triage

- Query **all `namingContexts` kutoka RootDSE**, si domain NC tu. Dynamic abuse inaweza kuwepo katika **`DomainDnsZones`/`ForestDnsZones`** (`dnsNode`) au katika application partitions.
- Wakati object bado hai, mara moja dump **replication metadata** na linked attributes/ACLs zozote. Baada ya expiration unaweza kubaki tu na **broken `gPLink` values, orphan SIDs, au cached DNS answers**.
```powershell
$root = Get-ADRootDSE
$root.namingContexts | ForEach-Object {
Get-ADObject -LDAPFilter '(objectClass=dynamicObject)' -SearchBase $_ `
-Properties entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID |
Select-Object DistinguishedName,entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID
}
repadmin /showobjmeta <DC> <distinguishedName>
```
## MAQ Evasion with Self-Deleting Computers

- Default **`ms-DS-MachineAccountQuota` = 10** inaruhusu user yeyote aliye authenticated kuunda computers. Ongeza `dynamicObject` wakati wa creation ili computer ijifute yenyewe na **kuachia quota slot** huku ikifuta evidence.
- Powermad tweak ndani ya `New-MachineAccount` (objectClass list):
```powershell
$request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
```
- Ikiwa requested TTL ni **chini ya `DynamicObjectMinTTL`**, tarajia server-side adjustment au rejection kutegemea creation path; kwenye domains nyingi effective floor ni **900s** na fallback/default hubaki **86400s**. ADUC inaweza kuficha `entryTTL`, lakini LDP/LDAP queries huionyesha.
- Wakati object ipo, defenders bado wanaweza kurecover unprivileged creator kutoka **`msDS-CreatorSID`** kwenye computer object. Mara dynamic computer inapoexpire, attribution hiyo inapotea pamoja na object.

## Stealth Primary Group Membership

- Create a **dynamic security group**, kisha set `primaryGroupID` ya user kwenda RID ya group hilo ili kupata effective membership ambayo **haionekani kwenye `memberOf`** lakini inaheshimiwa kwenye Kerberos/access tokens.
- TTL expiry **hufuta group licha ya primary-group delete protection**, na kumuacha user akiwa na `primaryGroupID` iliyoharibika inayolenga non-existent RID na hakuna tombstone ya kuchunguza jinsi privilege ilivyotolewa.
- Reporting inategemea tool: **`Get-ADGroupMember` / `net group`** kawaida hu-resolve primary-group-derived membership, wakati **`memberOf`** na **`Get-ADGroup -Properties member`** hazifanyi hivyo. Kwa broader `primaryGroupID` tradecraft, ona [this other page about DCShadow and PGID abuse](dcshadow.md).
- Kwa targets **zisizo na `AdminSDHolder` protection**, attackers wanaweza kuchanganya dynamic-group trick na **DACL deny on reading `primaryGroupID`** (au group `member` attribute) ili kuficha link kutoka kwa workflows nyingi za LDAP/PowerShell hata kabla group halijaexpire.

## AdminSDHolder Orphan-SID Pollution

- Ongeza ACEs kwa **short-lived dynamic user/group** kwenye **`CN=AdminSDHolder,CN=System,...`**. Baada ya TTL expiry SID inakuwa **unresolvable (“Unknown SID”)** kwenye template ACL, na **SDProp (~60 min)** hueneza orphan SID hiyo kwenye protected Tier-0 objects zote.
- Forensics hupoteza attribution kwa sababu principal hayupo tena (hakuna deleted-object DN). Monitor kwa **new dynamic principals + sudden orphan SIDs on AdminSDHolder/privileged ACLs**.

## Dynamic GPO Execution with Self-Destructing Evidence

- Create a **dynamic `groupPolicyContainer`** object yenye malicious **`gPCFileSysPath`** (kwa mfano, SMB share kama GPODDITY) na **link it via `gPLink`** kwa target OU.
- Clients husindika policy na kuvuta content kutoka attacker SMB. TTL ikiexpire, GPO object (na `gPCFileSysPath`) hutoweka; kinachobaki ni **broken `gPLink`** GUID pekee, ikiondoa LDAP evidence ya payload iliyotekelezwa.
- Hii ni operationally cleaner kuliko classic **GPODDITY-style** cleanup: badala ya kurestore original `gPCFileSysPath` mwenyewe, AD huondoa malicious GPC automatically mara timer inapoexpire.

## Ephemeral AD-Integrated DNS Redirection

- AD DNS records ni **`dnsNode`** objects ndani ya **DomainDnsZones/ForestDnsZones**. Kuzitengeneza kama **dynamic objects** kunaruhusu temporary host redirection (credential capture/MITM). Clients huhifadhi malicious A/AAAA response; record baadaye inajifuta yenyewe hivyo zone inaonekana clean (DNS Manager inaweza kuhitaji zone reload ili ku-refresh view).
- Detection: alert on **any DNS record carrying `dynamicObject`/`entryTTL`** kupitia replication/event logs; transient records mara chache huonekana kwenye standard DNS logs.

## Hybrid Entra ID Delta-Sync Gap (Note)

- Entra Connect delta sync hutegemea **tombstones** kugundua deletes. A **dynamic on-prem user** anaweza kusync kwenda Entra ID, expire, na kufuta bila tombstone—delta sync haitaoondoa cloud account, na kuacha **orphaned active Entra user** hadi **initial/full sync** au manual cloud cleanup ifanyike kwa force.

## References

- [Dynamic Objects in Active Directory: The Stealthy Threat](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)
- [Adventures in Primary Group Behavior, Reporting, and Exploitation](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)

{{#include ../../banners/hacktricks-training.md}}
