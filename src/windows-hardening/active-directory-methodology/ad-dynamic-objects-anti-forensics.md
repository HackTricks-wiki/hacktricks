# AD Dynamic Objects (dynamicObject) Anti-Forensics

{{#include ../../banners/hacktricks-training.md}}

## Misingi ya Mechanics & Detection

- Object yoyote iliyoundwa kwa auxiliary class **`dynamicObject`** hupata **`entryTTL`** (countdown ya sekunde) na **`msDS-Entry-Time-To-Die`** (muda wa mwisho wa ku-expire ulio kamili). **`entryTTL`** inapofika 0, **Garbage Collector huifuta bila tombstone/recycle-bin**, na hivyo kufuta creator/timestamps na kuzuia recovery.
- **`entryTTL` ni operational/constructed attribute**: iombe wazi katika LDAP queries. TTL inaweza kurefresh kwa ku-update **`entryTTL`** kabla ya ku-expire au kupitia LDAP TTL refresh OID **`1.3.6.1.4.1.1466.101.119.1`**.
- TTL min/default zinatekelezwa katika **Configuration\Services\NTDS Settings → `msDS-Other-Settings` → `DynamicObjectMinTTL` / `DynamicObjectDefaultTTL`**. Microsoft inaandika **86400s** kama default TTL na **900s** kama default minimum valid TTL; zote zinaunga mkono **1s–1y**. Dynamic objects **hazitumiki** katika Configuration/Schema partitions.
- Hakuna **static→dynamic conversion** na hakuna tombstone phase baada ya expiry. IR teams haziwezi kutegemea deleted-object controls au Recycle Bin; zinapaswa kunasa object/metadata iliyo hai kabla GC haijaiondoa.
- Refresh inategemea replica: ikiwa TTL imehuishwa karibu sana na expiry, writable replica nyingine au GC bado inaweza kuifuta object hiyo locally kabla refresh haijareplica. Kwa hivyo TTL fupi sana hufanya kazi vizuri zaidi attacker anapojua ni DC gani itakayohudumia abuse, huku defenders wakipaswa ku-query **naming contexts / replicas** zote wakati wa triage.
- Deletion inaweza kuchelewa kwa dakika chache kwenye DC zenye uptime fupi (<24h), na kuacha response window ndogo ya ku-query/backup attributes. Detect kwa kuweka alert kwenye objects mpya zinazobeba **`entryTTL`/`msDS-Entry-Time-To-Die`** na ku-correlate na orphan SIDs/broken links.<sup>[[1]](#references)</sup>

## Fast Enumeration / Live Triage

- Query **`namingContexts` zote kutoka RootDSE**, si domain NC pekee. Dynamic abuse inaweza kuwa katika **`DomainDnsZones`/`ForestDnsZones`** (`dnsNode`) au application partitions.
- Wakati object bado iko hai, dump mara moja **replication metadata** na linked attributes/ACLs zote. Baada ya expiry unaweza kubaki na **broken `gPLink` values, orphan SIDs, au cached DNS answers** pekee.<sup>[[1]](#references)</sup>
```powershell
$root = Get-ADRootDSE
$root.namingContexts | ForEach-Object {
Get-ADObject -LDAPFilter '(objectClass=dynamicObject)' -SearchBase $_ `
-Properties entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID |
Select-Object DistinguishedName,entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID
}
repadmin /showobjmeta <DC> <distinguishedName>
```
## MAQ Evasion na Self-Deleting Computers

- Default **`ms-DS-MachineAccountQuota` = 10** humruhusu mtumiaji yeyote aliyethibitishwa kuunda computers. Ongeza `dynamicObject` wakati wa uundaji ili computer ijifute yenyewe na **free quota slot**, huku ikifuta ushahidi.
- Marekebisho ya Powermad ndani ya `New-MachineAccount` (orodha ya objectClass):
```powershell
$request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
```
- Ikiwa TTL iliyoombwa iko chini ya `DynamicObjectMinTTL`, tarajia marekebisho au kukataliwa upande wa server, kulingana na njia ya uundaji; katika domains nyingi kiwango cha chini kinachotumika ni **900s**, na fallback/default hubaki **86400s**. ADUC inaweza kuficha `entryTTL`, lakini LDP/LDAP queries huionyesha.
- Wakati object bado ipo, defenders bado wanaweza kupata creator asiye na privileges kupitia **`msDS-CreatorSID`** kwenye computer object. Computer dynamic iki-expire, attribution hiyo hupotea pamoja na object.<sup>[[1]](#references)</sup>

## Stealth Primary Group Membership

- Unda **dynamic security group**, kisha weka **`primaryGroupID`** ya user iwe RID ya group hiyo ili kupata effective membership ambayo **haionekani kwenye `memberOf`** lakini inaheshimiwa katika Kerberos/access tokens.<sup>[[1]](#references)</sup>
- TTL iki-expire **group hufutwa licha ya primary-group delete protection**, na kumuacha user akiwa na `primaryGroupID` iliyoharibika inayoelekeza kwenye RID ambayo haipo, bila tombstone ya kuchunguza jinsi privilege hiyo ilivyotolewa.
- Reporting hutegemea tool: **`Get-ADGroupMember` / `net group`** kwa kawaida hutambua membership inayotokana na primary group, ilhali **`memberOf`** na **`Get-ADGroup -Properties member`** hazifanyi hivyo. Kwa tradecraft pana zaidi kuhusu `primaryGroupID`, tazama [ukurasa huu mwingine kuhusu DCShadow na PGID abuse](dcshadow.md).
- Kwa targets **zisizolindwa na AdminSDHolder**, attackers wanaweza kuunganisha mbinu ya dynamic-group na **DACL deny ya kusoma `primaryGroupID`** (au attribute ya group `member`) ili kuficha uhusiano huo kutoka kwa workflows nyingi za LDAP/PowerShell hata kabla group haija-expire.<sup>[[2]](#references)</sup>

## AdminSDHolder Orphan-SID Pollution

- Ongeza ACEs za **dynamic user/group yenye muda mfupi** kwenye **`CN=AdminSDHolder,CN=System,...`**. Baada ya TTL ku-expire, SID huwa **isiyoweza kutatuliwa (“Unknown SID”)** katika template ACL, na **SDProp (~60 min)** husambaza orphan SID hiyo kwenye Tier-0 objects zote zinazolindwa.
- Forensics hupoteza attribution kwa sababu principal haipo tena (hakuna deleted-object DN). Fuatilia **dynamic principals mpya + orphan SIDs zinazotokea ghafla kwenye AdminSDHolder/privileged ACLs**.<sup>[[1]](#references)</sup>

## Dynamic GPO Execution yenye Self-Destructing Evidence

- Unda object ya **dynamic `groupPolicyContainer`** yenye **`gPCFileSysPath`** hasidi (kwa mfano SMB share à la GPODDITY) na **iunganishe kupitia `gPLink`** na target OU.
- Clients huchakata policy na kuvuta content kutoka kwa attacker SMB. TTL iki-expire, GPO object (na **`gPCFileSysPath`**) hutoweka; kinachobaki ni **GUID ya `gPLink` iliyovunjika**, na hivyo kuondoa LDAP evidence ya payload iliyotekelezwa.
- Hii ni safi zaidi kiutendaji kuliko cleanup ya kawaida ya **GPODDITY-style**: badala ya kurejesha **`gPCFileSysPath`** ya awali wewe mwenyewe, AD huondoa malicious GPC automatically timer iki-expire.<sup>[[1]](#references)</sup>

## Ephemeral AD-Integrated DNS Redirection

- AD DNS records ni objects za **`dnsNode`** katika **DomainDnsZones/ForestDnsZones**. Kuziumba kama dynamic objects huruhusu host redirection ya muda (credential capture/MITM). Clients huhifadhi malicious A/AAAA response kwenye cache; record baadaye hujifuta yenyewe ili zone ionekane safi (DNS Manager inaweza kuhitaji zone reload ili ku-refresh view).
- Detection: toa alert kwa **DNS record yoyote yenye `dynamicObject`/`entryTTL`** kupitia replication/event logs; transient records mara chache huonekana katika standard DNS logs.<sup>[[1]](#references)</sup>

## Hybrid Entra ID Delta-Sync Gap (Note)

- Entra Connect delta sync hutegemea **tombstones** ili kugundua deletes. **Dynamic on-prem user** anaweza kusync kwenda Entra ID, aka-expire, na kufutwa bila tombstone—delta sync haitafuta cloud account, na hivyo kuacha **orphaned active Entra user** hadi **initial/full sync** au manual cloud cleanup ilazimishwe.<sup>[[1]](#references)</sup>

## References

- [1] [Dynamic Objects in Active Directory: The Stealthy Threat](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)
- [2] [Adventures in Primary Group Behavior, Reporting, and Exploitation](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)

{{#include ../../banners/hacktricks-training.md}}
