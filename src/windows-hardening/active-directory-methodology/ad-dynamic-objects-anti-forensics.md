# AD Dynamic Objects (dynamicObject) Anti-Forensics

{{#include ../../banners/hacktricks-training.md}}

## Mechanics & Detection Basics

- Kitu chochote kilichoundwa kwa auxiliary class **`dynamicObject`** hupata **`entryTTL`** (hesabu ya sekunde zinazoisha) na **`msDS-Entry-Time-To-Die`** (muda kamili wa kuisha). `entryTTL` inapofika 0, **Garbage Collector huifuta bila tombstone/recycle-bin**, ikifuta creator/timestamps na kuzuia recovery.
- **`entryTTL` ni operational/constructed attribute**: iombe wazi kwenye LDAP queries. TTL inaweza kufreshishwa kwa kusasisha `entryTTL` kabla ya kuisha au kupitia LDAP TTL refresh OID **`1.3.6.1.4.1.1466.101.119.1`**.
- TTL min/default zinatekelezwa kwenye **Configuration\Services\NTDS Settings → `msDS-Other-Settings` → `DynamicObjectMinTTL` / `DynamicObjectDefaultTTL`**. Microsoft inaandika **86400s** kama default TTL na **900s** kama default minimum valid TTL; vyote vinaunga mkono **1s–1y**. Dynamic objects **hazitumiki** katika Configuration/Schema partitions.
- **Hakuna static→dynamic conversion** na hakuna tombstone phase baada ya kuisha. Timu za IR haziwezi kutegemea deleted-object controls au Recycle Bin; lazima zinasa live object/metadata kabla GC haijaiondoa.
- Refresh ni **replica-sensitive**: TTL ikifanywa upya karibu sana na muda wa kuisha, replica nyingine writable au GC bado inaweza kufuta object hiyo locally kabla refresh haijareplica. Hivyo TTL fupi sana hufanya kazi vizuri zaidi attacker anapojua DC gani itahudumia abuse, wakati defenders wanapaswa kuquery **all naming contexts / replicas** wakati wa triage.
- Ufutaji unaweza kuchelewa kwa dakika chache kwenye DCs zenye uptime fupi (<24h), hivyo kuna dirisha jembamba la response la kuquery/backup attributes. Tambua kwa **alerting on new objects carrying `entryTTL`/`msDS-Entry-Time-To-Die`** na ku-correlate na orphan SIDs/broken links.

## Fast Enumeration / Live Triage

- Query **all `namingContexts` from RootDSE**, si domain NC pekee. Dynamic abuse inaweza kuwepo kwenye **`DomainDnsZones`/`ForestDnsZones`** (`dnsNode`) au kwenye application partitions.
- Wakati object bado iko hai, mara moja dump **replication metadata** na linked attributes/ACLs zozote. Baada ya kuisha unaweza kubaki na **broken `gPLink` values, orphan SIDs, au cached DNS answers**.
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

- Default **`ms-DS-MachineAccountQuota` = 10** inaruhusu mtumiaji yeyote aliyeauthenticatwe kuunda computers. Ongeza `dynamicObject` wakati wa creation ili computer ijifute yenyewe na **kufree quota slot** huku ikifuta ushahidi.
- Powermad tweak ndani ya `New-MachineAccount` (objectClass list):
```powershell
$request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
```
- Ikiwa TTL iliyoombwa ni **chini ya `DynamicObjectMinTTL`**, tarajia marekebisho ya server-side au kukataliwa kulingana na creation path; katika domains nyingi floor halisi ni **900s** na fallback/default inabaki **86400s**. ADUC inaweza kuficha `entryTTL`, lakini LDP/LDAP queries huionyesha.
- Wakati object ipo, defenders bado wanaweza kurecover creator asiye na privilege kutoka **`msDS-CreatorSID`** kwenye computer object. Mara dynamic computer inapokwisha, attribution hiyo hupotea pamoja na object.

## Stealth Primary Group Membership

- Unda **dynamic security group**, kisha weka **`primaryGroupID`** ya user kuwa RID ya group hilo ili kupata effective membership ambayo **haionekani kwenye `memberOf`** lakini inatambuliwa katika Kerberos/access tokens.
- TTL expiry **hufuta group licha ya primary-group delete protection**, na kumuacha user akiwa na `primaryGroupID` iliyoharibika inayoelekeza kwenye RID isiyokuwepo na bila tombstone ya kuchunguza jinsi privilege ilivyotolewa.
- Reporting inategemea tool: **`Get-ADGroupMember` / `net group`** kwa kawaida huresolve primary-group-derived membership, wakati **`memberOf`** na **`Get-ADGroup -Properties member`** havifanyi hivyo. Kwa broader `primaryGroupID` tradecraft, angalia [this other page about DCShadow and PGID abuse](dcshadow.md).
- Kwa targets **zisizolindwa na AdminSDHolder**, attackers wanaweza kuunganisha dynamic-group trick na **DACL deny on reading `primaryGroupID`** (au group `member` attribute) ili kuficha link kutoka kwa workflows nyingi za LDAP/PowerShell hata kabla group halijaisha.

## AdminSDHolder Orphan-SID Pollution

- Ongeza ACEs kwa **short-lived dynamic user/group** kwenye **`CN=AdminSDHolder,CN=System,...`**. Baada ya TTL expiry SID inakuwa **isiyoweza kuresolvwa (“Unknown SID”)** ndani ya template ACL, na **SDProp (~60 min)** husambaza orphan SID hiyo kwenye protected Tier-0 objects zote.
- Forensics hupoteza attribution kwa sababu principal ameondoka (hakuna deleted-object DN). Fuatilia **new dynamic principals + sudden orphan SIDs on AdminSDHolder/privileged ACLs**.

## Dynamic GPO Execution with Self-Destructing Evidence

- Unda **dynamic `groupPolicyContainer`** object yenye malicious **`gPCFileSysPath`** (mfano, SMB share kama GPODDITY) na **i-link kupitia `gPLink`** kwenye target OU.
- Clients huchakata policy na kuvuta content kutoka attacker SMB. TTL ikikwisha, GPO object (na `gPCFileSysPath`) hutoweka; hubaki tu **broken `gPLink`** GUID, na kuondoa LDAP evidence ya payload iliyotekelezwa.
- Hii ni operationally cleaner kuliko classic **GPODDITY-style** cleanup: badala ya kurudisha `gPCFileSysPath` ya awali wewe mwenyewe, AD huondoa malicious GPC kiotomatiki timer ikikwisha.

## Ephemeral AD-Integrated DNS Redirection

- AD DNS records ni **`dnsNode`** objects ndani ya **DomainDnsZones/ForestDnsZones**. Kuziumba kama **dynamic objects** kunaruhusu temporary host redirection (credential capture/MITM). Clients hu-cache malicious A/AAAA response; baadaye record hufuta yenyewe hivyo zone inaonekana safi (DNS Manager inaweza kuhitaji zone reload ili view isasishwe).
- Detection: alert kwenye **any DNS record carrying `dynamicObject`/`entryTTL`** kupitia replication/event logs; transient records mara chache huonekana kwenye standard DNS logs.

## Hybrid Entra ID Delta-Sync Gap (Note)

- Entra Connect delta sync hutegemea **tombstones** kugundua deletes. **Dynamic on-prem user** anaweza kusync hadi Entra ID, ku-expire, na kufuta bila tombstone—delta sync haitatoa cloud account, na kuacha **orphaned active Entra user** hadi **initial/full sync** au manual cloud cleanup ilazimishwe.

## References

- [Dynamic Objects in Active Directory: The Stealthy Threat](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)
- [Adventures in Primary Group Behavior, Reporting, and Exploitation](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)

{{#include ../../banners/hacktricks-training.md}}
