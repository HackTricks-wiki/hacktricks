# AD Dynamic Objects (dynamicObject) Anti-Forensics

{{#include ../../banners/hacktricks-training.md}}

## Misingi ya Mechanics na Detection

- Object yoyote iliyoundwa kwa auxiliary class **`dynamicObject`** hupata **`entryTTL`** (muda wa kuhesabu kushuka kwa sekunde) na **`msDS-Entry-Time-To-Die`** (muda kamili wa ku-expire). `entryTTL` inapofikia 0 **na object hiyo haina descendants**, Garbage Collector huifuta bila tombstone/recycle-bin, na hivyo kufuta taarifa za creator/timestamps na kuzuia recovery.<sup>[[4]](#references)</sup>
- **`entryTTL` ni operational/constructed attribute**: iombe waziwazi katika LDAP queries. TTL inaweza kurefreshiwa kwa kusasisha `entryTTL` kabla haija-expire au kupitia LDAP TTL refresh OID **`1.3.6.1.4.1.1466.101.119.1`**.
- TTL min/default ni AVAs za forest-wide zilizo katika **`CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,...` → `msDS-Other-Settings`**: `DynamicObjectMinTTLSeconds=<seconds>` na `DynamicObjectDefaultTTLSeconds=<seconds>`. Microsoft inaandika **86400s** kama default TTL na **900s** kama default minimum valid TTL; schema range ya `entryTTL` ni **1–31557600s** (sekunde moja hadi mwaka mmoja).<sup>[[3]](#references)</sup> Dynamic objects **hazitumiki katika Configuration/Schema partitions**.
- Hakuna **static→dynamic conversion** na hakuna tombstone phase baada ya expiry. Timu za IR haziwezi kutegemea deleted-object controls au Recycle Bin; lazima zichukue object/metadata ambayo bado iko hai kabla GC haijaiondoa.
- Refresh inategemea replica: ikiwa TTL imehuishwa karibu sana na expiry, writable replica nyingine au GC bado inaweza kufuta object hiyo locally kabla refresh haijareplica. Kwa hiyo, TTL fupi sana hufanya kazi vizuri zaidi wakati attacker anajua ni DC ipi itahudumia abuse hiyo, ilhali defenders wanapaswa ku-query **naming contexts / replicas zote** wakati wa triage.
- Deletion inaweza kuchelewa kwa dakika chache kwenye DC zenye uptime fupi (<24h), na kuacha response window finyu ya ku-query/backup attributes. Tambua hali hii kwa **kuweka alert kwenye objects mpya zenye `entryTTL`/`msDS-Entry-Time-To-Die`** na kuzihusianisha na orphan SIDs/broken links.<sup>[[1]](#references)</sup>

### Expiry graph na edge cases za reference-cleanup

- Kila descendant aliye chini ya dynamic object lazima awe dynamic mwenyewe. Dynamic parent iliyokwisha-expire hukusanywa na Garbage Collector tu baada ya kuwa leaf; ikiwa descendant ana `msDS-Entry-Time-To-Die` ya baadaye, DC huongeza expiry ya parent zaidi ya expiry ya descendant aliye na expiry ya mwisho. Kwa hiyo, writable dynamic subtree inaweza **ku-pin/ku-extend parent inayoonekana kuwa karibu kutoweka**: enumerate subtree yake yote na usitumie `entryTTL` iliyoonekana ya parent kama deadline ya cleanup.<sup>[[4]](#references)</sup>
- Expiry cleanup **inazingatia schema links**. Replicas huondoa linked attribute values zinazo-reference dynamic object iliyofutwa, lakini huhifadhi nonlinked values. Tarajia ordinary forward/back-link membership kusafishwa, huku references za integer/SID/string kama `primaryGroupID`, SIDs zilizowekwa ndani ya `nTSecurityDescriptor`, au maandishi ya `gPLink` zikiweza kubaki kama forensic residue.<sup>[[4]](#references)</sup>

## Fast Enumeration / Live Triage

- Query **`namingContexts` zote kutoka RootDSE**, si domain NC pekee. Dynamic abuse inaweza kuwa katika **`DomainDnsZones`/`ForestDnsZones`** (`dnsNode`) au application partitions.
- Wakati object bado iko hai, dump mara moja **replication metadata** na linked attributes/ACLs zote. Baada ya expiry unaweza kubaki na **broken `gPLink` values, orphan SIDs, au cached DNS answers** pekee.<sup>[[1]](#references)</sup>
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
## MAQ Evasion with Self-Deleting Computers

- **`ms-DS-MachineAccountQuota` = 10** ya kawaida huruhusu mtumiaji yeyote aliye-authenticated kuunda computers. Ongeza `dynamicObject` wakati wa kuunda ili computer ijifute yenyewe na **ifungue nafasi ya quota** huku ikifuta ushahidi.
- Marekebisho ya Powermad ndani ya `New-MachineAccount` (orodha ya objectClass):
```powershell
$request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
```
- Ikiwa TTL iliyoombwa iko **chini ya `DynamicObjectMinTTL`**, tarajia server kuirekebisha au kuikataa kulingana na njia ya uundaji; katika domains nyingi kiwango cha chini kinachotumika ni **900s**, na fallback/default inabaki **86400s**. ADUC inaweza kuficha `entryTTL`, lakini LDP/LDAP queries huionyesha.
- Object inapokuwa bado ipo, defenders bado wanaweza kubaini creator asiye na privileges kupitia **`msDS-CreatorSID`** kwenye computer object. Computer dynamic iki-expire, attribution hiyo hupotea pamoja na object.<sup>[[1]](#references)</sup>

## Stealth Primary Group Membership

- Unda **dynamic security group**, kisha weka **`primaryGroupID`** ya user iwe RID ya group hiyo ili kupata effective membership ambayo **haionekani kwenye `memberOf`**, lakini hutambuliwa katika Kerberos/access tokens.<sup>[[1]](#references)</sup>
- TTL iki-expire **hufuta group licha ya primary-group delete protection**, na kumwacha user akiwa na `primaryGroupID` iliyoharibika inayoelekeza kwenye RID ambayo haipo, bila tombstone ya kuchunguza jinsi privilege ilivyotolewa.
- Reporting hutegemea tool: **`Get-ADGroupMember` / `net group`** kwa kawaida hutambua membership inayotokana na primary group, lakini **`memberOf`** na **`Get-ADGroup -Properties member`** hazifanyi hivyo. Kwa tradecraft pana zaidi ya `primaryGroupID`, tazama [ukurasa huu mwingine kuhusu DCShadow na PGID abuse](dcshadow.md).
- Kwa targets **ambazo hazijalindwa na AdminSDHolder**, attackers wanaweza kuunganisha dynamic-group trick na **DACL deny ya kusoma `primaryGroupID`** (au attribute ya group `member`) ili kuficha uhusiano huo kutoka kwa workflows nyingi za LDAP/PowerShell hata kabla group haija-expire.<sup>[[2]](#references)</sup>

## AdminSDHolder Orphan-SID Pollution

- Ongeza ACEs za **dynamic user/group yenye maisha mafupi** kwenye **`CN=AdminSDHolder,CN=System,...`**. Baada ya TTL ku-expire, SID huwa **isiyoweza kutatuliwa (“Unknown SID”)** katika template ACL, na **SDProp (~60 min)** hueneza orphan SID hiyo kwenye Tier-0 objects zote zilizolindwa.
- Forensics hupoteza attribution kwa sababu principal haipo tena (hakuna deleted-object DN). Fuatilia **dynamic principals mpya + orphan SIDs zinazoonekana ghafla kwenye AdminSDHolder/privileged ACLs**.<sup>[[1]](#references)</sup>

## Dynamic GPO Execution with Self-Destructing Evidence

- Unda object ya **dynamic `groupPolicyContainer`** yenye **`gPCFileSysPath`** hasidi (kwa mfano SMB share kama ilivyo kwa GPODDITY) na **uiunganishe kupitia `gPLink`** kwenye target OU.
- Clients huchakata policy na kuvuta content kutoka kwa attacker SMB. TTL iki-expire, GPO object (na `gPCFileSysPath`) hutoweka; kinachobaki ni **GUID ya `gPLink` iliyovunjika**, hivyo kuondoa ushahidi wa LDAP wa payload iliyotekelezwa.
- Hii ni safi zaidi kiutendaji kuliko cleanup ya kawaida ya **GPODDITY-style**: badala ya kurejesha mwenyewe `gPCFileSysPath` ya awali, AD huondoa GPC hasidi kiotomatiki timer inapo-expire.<sup>[[1]](#references)</sup> Tazama [ACL persistence abuse](acl-persistence-abuse/README.md#gpcfilesyspath-poisoning-with-gpoddity) kwa maelezo ya protocol na tooling badala ya kuyarudia hapa.

## Ephemeral AD-Integrated DNS Redirection

- AD DNS records ni objects za **`dnsNode`** ndani ya **DomainDnsZones/ForestDnsZones**. Kuziumba kama **dynamic objects** huruhusu host redirection ya muda (credential capture/MITM). Clients huhifadhi kwenye cache jibu hasidi la A/AAAA; baadaye record hujifuta yenyewe ili zone ionekane safi (DNS Manager inaweza kuhitaji zone reload ili kuonyesha hali mpya).
- Detection: toa alert kwa **DNS record yoyote yenye `dynamicObject`/`entryTTL`** kupitia replication/event logs; transient records mara chache huonekana kwenye DNS logs za kawaida.<sup>[[1]](#references)</sup>

## Hybrid Entra ID Delta-Sync Gap (Note)

- Entra Connect delta sync hutegemea **tombstones** kugundua deletes. **Dynamic on-prem user** inaweza kusync kwenda Entra ID, ika-expire, na kujifuta bila tombstone—delta sync haitaondoa cloud account, na kuacha **orphaned active Entra user** hadi **initial/full sync** au cloud cleanup ya manual ilazimishwe.<sup>[[1]](#references)</sup>



## References

- [1] [Dynamic Objects in Active Directory: Tishio la Kijanja](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)
- [2] [Adventures in Primary Group Behavior, Reporting, and Exploitation](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)
- [3] [Configuration of TTL Limits](https://learn.microsoft.com/en-us/windows/win32/ad/configuration-of-ttl-limits)
- [4] [[MS-ADTS]: DynamicObject Requirements](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a0ea4e75-4b34-4f97-ae06-a8b19a5aaa5b)
{{#include ../../banners/hacktricks-training.md}}
