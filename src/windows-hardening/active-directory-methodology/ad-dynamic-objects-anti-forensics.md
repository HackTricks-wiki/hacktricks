# AD Dynamic Objects (dynamicObject) Anti-Forensics

{{#include ../../banners/hacktricks-training.md}}

## Mekaniki & Misingi ya Utambuzi

- Kifaa chochote kinachoundwa kwa class ya ziada **`dynamicObject`** hupata **`entryTTL`** (kuhesabu chini kwa sekunde) na **`msDS-Entry-Time-To-Die`** (muda wa kumalizika wa kudumu). Wakati `entryTTL` inafikia 0 **Garbage Collector** inakiangamiza bila tombstone/recycle-bin, ikifuta muundaji/muda wa matukio na kuzuia urejeshaji.
- TTL inaweza kusasishwa kwa kubadilisha `entryTTL`; min/default zinatekelezwa katika **Configuration\Services\NTDS Settings → `msDS-Other-Settings` → `DynamicObjectMinTTL` / `DynamicObjectDefaultTTL`** (inaunga mkono 1s–1y lakini kawaida default ni 86,400s/24h). Dynamic objects hazitumiwi katika partishi za **Configuration/Schema**.
- Uondoshaji unaweza kuchelewa kwa dakika chache kwenye DCs zenye uptime fupi (<24h), na kuacha dirisha dogo la kujibu kwa kuuliza/ku-backup sifa. Tambua kwa **kutuma onyo kwa vitu vipya vinavyoabeba `entryTTL`/`msDS-Entry-Time-To-Die`** na kuviunganisha na orphan SIDs/viungo vilivyovunjika.

## MAQ Evasion with Self-Deleting Computers

- Default ya **`ms-DS-MachineAccountQuota` = 10** inaruhusu mtumiaji yeyote aliye-authenticated kuunda computers. Ongeza `dynamicObject` wakati wa uundaji ili kompyuta ijifute yenyewe na **kuachilia nafasi ya quota** huku ikifuta ushahidi.
- Mabadiliko ya Powermad ndani ya `New-MachineAccount` (objectClass list):
```powershell
$request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
```
- TTL fupi (mfano, 60s) mara nyingi hashindani kwa watumiaji wa kawaida; AD inarejea kwa **`DynamicObjectDefaultTTL`** (mfano: 86,400s). ADUC inaweza kuficha `entryTTL`, lakini maswali ya LDP/LDAP yanaifunua.

## Stealth Primary Group Membership

- Unda **dynamic security group**, kisha weka `primaryGroupID` ya mtumiaji kwa RID ya kundi hilo ili kupata uanachama wa ufanisi ambao **hauonekani katika `memberOf`** lakini unaheshimiwa katika Kerberos/token za ufikiaji.
- Mara TTL inapomalizika **kundi linafuta licha ya ulinzi wa kuondoa primary-group**, na kumwacha mtumiaji na `primaryGroupID` mbovu inayorejelea RID isiyokuwepo na hakuna tombstone ya kuchunguza jinsi mamlaka ilivyotolewa.

## AdminSDHolder Orphan-SID Pollution

- Ongeza ACEs kwa **mtu/kundi mfupi wa muda (dynamic)** kwenye **`CN=AdminSDHolder,CN=System,...`**. Baada ya TTL kuisha SID inakuwa **hairejesheki (“Unknown SID”)** kwenye template ACL, na **SDProp (~60 min)** inapita SID hiyo ya mfaapala kwenye vitu vyote vilivyolindwa vya Tier-0.
- Forensiki hupoteza utekelezaji kwa sababu mtendaji ameondoka (hakuna deleted-object DN). Simamia kwa kuangalia **principals dynamic mpya + SID za mfaapala ghafla kwenye AdminSDHolder/ACL zenye mamlaka**.

## Dynamic GPO Execution with Self-Destructing Evidence

- Unda kitu cha **dynamic `groupPolicyContainer`** chenye `gPCFileSysPath` mabaya (mfano, SMB share kama GPODDITY) na **kiunganishe kupitia `gPLink`** kwenye OU lengwa.
- Wateja huteua policy na kupakua yaliyomo kutoka SMB ya mshambuliaji. Wakati TTL inapomalizika, kitu cha GPO (na `gPCFileSysPath`) kinapotea; kinabaki tu **GUID ya `gPLink` iliyovunjika**, ikitoa ushahidi wa LDAP wa payload iliyotekelezwa.

## Ephemeral AD-Integrated DNS Redirection

- Rekodi za DNS za AD ni vitu vya **`dnsNode`** katika **DomainDnsZones/ForestDnsZones**. Kuziunda kama **dynamic objects** kunaruhusu uelekeo wa muda mfupi wa host (kukamata credentials/MITM). Wateja huhifadhi cache ya jibu la A/AAAA la mnafiki; rekodi baadaye inajifuta yenyewe hivyo zone inaonekana safi (DNS Manager inaweza kuhitaji reload ya zone ili kusasisha mwonekano).
- Utambuzi: tuma onyo kwa **rekodi yoyote ya DNS inayobeba `dynamicObject`/`entryTTL`** kupitia replication/event logs; rekodi za muda mfupi kwa nadra huonekana katika DNS logs za kawaida.

## Hybrid Entra ID Delta-Sync Gap (Note)

- Entra Connect delta sync inategemea **tombstones** kugundua ufutaji. **dynamic on-prem user** anaweza kusync kwenye Entra ID, kuisha TTL, na kufuta bila tombstone—delta sync haitafuta akaunti ya cloud, ikiacha **mtumiaji wa Entra aliyefunguliwa bila msaidizi** hadi full sync ya mkono itakapofanywa.

## Marejeo

- [Dynamic Objects in Active Directory: The Stealthy Threat](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)

{{#include ../../banners/hacktricks-training.md}}
