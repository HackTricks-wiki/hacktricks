# AD Dynamic Objects (dynamicObject) Anti-Forensics

{{#include ../../banners/hacktricks-training.md}}

## Mekanikler & Tespit Temelleri

- Auxiliary class **`dynamicObject`** ile oluşturulan herhangi bir nesne, **`entryTTL`** (saniye geri sayımı) ve **`msDS-Entry-Time-To-Die`** (mutlak sonlanma) kazanır. `entryTTL` 0'a ulaştığında **Garbage Collector** onu tombstone/recycle-bin olmadan siler, oluşturucu/timestamp bilgilerini siler ve kurtarmayı engeller.
- **`entryTTL` operasyonel/constructed bir attribute**'tur: LDAP sorgularında bunu açıkça isteyin. TTL, `entryTTL` sonlanmadan önce güncellenerek veya LDAP TTL refresh OID **`1.3.6.1.4.1.1466.101.119.1`** üzerinden yenilenebilir.
- TTL minimum/default değerleri **Configuration\Services\NTDS Settings → `msDS-Other-Settings` → `DynamicObjectMinTTL` / `DynamicObjectDefaultTTL`** içinde uygulanır. Microsoft, varsayılan TTL olarak **86400s** ve varsayılan minimum geçerli TTL olarak **900s** dokümante eder; ikisi de **1s–1y** aralığını destekler. Dynamic objects, **Configuration/Schema partitions** içinde desteklenmez.
- Süre dolduktan sonra **static→dynamic conversion** yoktur ve tombstone aşaması da yoktur. IR ekipleri deleted-object kontrollerine veya Recycle Bin'e güvenemez; GC nesneyi kaldırmadan önce canlı nesneyi/metadata'yı toplamalıdır.
- Yenileme **replica-sensitive**'dir: TTL sonlanmaya çok yakın yenilenirse, başka bir writable replica veya GC yine de nesneyi yerel olarak silebilir. Bu yüzden çok kısa TTL'ler, saldırganın abuse'u hangi DC'nin işleyeceğini bildiği durumlarda en iyi sonucu verir; savunmacılar ise triage sırasında **tüm naming contexts / replicas**'ı sorgulamalıdır.
- Kısa uptime'a sahip DC'lerde (<24h) silme işlemi birkaç dakika gecikebilir ve attribute'ları sorgulamak/yedeklemek için dar bir yanıt penceresi bırakır. **`entryTTL`/`msDS-Entry-Time-To-Die`** taşıyan yeni nesneleri alarmleyerek ve orphan SID'ler/broken links ile korele ederek tespit edin.

## Hızlı Envanter / Canlı Triage

- Yalnızca domain NC'yi değil, RootDSE'den **tüm `namingContexts`**'leri sorgulayın. Dynamic abuse, **`DomainDnsZones`/`ForestDnsZones`** (`dnsNode`) içinde veya application partitions'da yaşayabilir.
- Nesne hâlâ canlıyken hemen **replication metadata** ve bağlı attribute'ları/ACL'leri dökümleyin. Süre dolduktan sonra elinizde yalnızca **broken `gPLink` values, orphan SIDs, or cached DNS answers** kalabilir.
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

- Default **`ms-DS-MachineAccountQuota` = 10** lets any authenticated user create computers. Oluşturma sırasında **`dynamicObject`** ekleyerek computer’ın kendi kendini silmesini ve **quota slot’unu serbest bırakmasını** sağlayabilir, aynı zamanda izleri de temizleyebilirsiniz.
- Powermad tweak inside `New-MachineAccount` (objectClass list):
```powershell
$request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
```
- Eğer istenen TTL **`DynamicObjectMinTTL`** altında ise, creation path’e bağlı olarak server-side adjustment veya rejection bekleyin; birçok domain’de efektif alt sınır **900s**’dir ve fallback/default değer **86400s** olarak kalır. ADUC `entryTTL`’yi gizleyebilir, ancak LDP/LDAP queries bunu ortaya çıkarır.
- Object var olduğu sürece defenders, computer object üzerindeki **`msDS-CreatorSID`** ile ayrıcalıksız creator’ı yine de kurtarabilir. Dynamic computer expire olduğunda bu attribution object ile birlikte kaybolur.

## Stealth Primary Group Membership

- Bir **dynamic security group** oluşturun, ardından bir user’ın **`primaryGroupID`** değerini o group’un RID’sine ayarlayarak, **`memberOf`** içinde görünmeyen ama Kerberos/access tokens tarafından kabul edilen etkili membership elde edin.
- TTL expiry, primary-group delete protection’a rağmen **group’u siler**; geriye user’ın **`primaryGroupID`** değerinin var olmayan bir RID’ye işaret ettiği bozuk bir durum kalır ve privilege’ın nasıl verildiğini incelemek için tombstone oluşmaz.
- Reporting tool’a bağlıdır: **`Get-ADGroupMember` / `net group`** genellikle primary-group-derived membership’i çözerken, **`memberOf`** ve **`Get-ADGroup -Properties member`** bunu yapmaz. Daha geniş `primaryGroupID` tradecraft için [DCShadow ve PGID abuse hakkında bu diğer sayfaya](dcshadow.md) bakın.
- **Non-AdminSDHolder-protected** targets için attackers, dynamic-group trick’i **`primaryGroupID`** okuma üzerinde bir **DACL deny** ile (veya group `member` attribute’u üzerinde) birleştirerek, group expire olmadan önce bile link’i birçok LDAP/PowerShell workflow’undan gizleyebilir.

## AdminSDHolder Orphan-SID Pollution

- **`CN=AdminSDHolder,CN=System,...`** içine **short-lived dynamic user/group** için ACE’ler ekleyin. TTL expiry’den sonra SID, template ACL içinde **çözümlenemez (“Unknown SID”)** hale gelir ve **SDProp (~60 min)** bu orphan SID’yi tüm protected Tier-0 objects’e yayar.
- Principal ortadan kaybolduğu için forensics attribution’ı kaybeder (deleted-object DN yok). **Yeni dynamic principals + AdminSDHolder/privileged ACL’lerde ani orphan SIDs** için izleme yapın.

## Dynamic GPO Execution with Self-Destructing Evidence

- Malicious **`gPCFileSysPath`** (ör. GPODDITY benzeri bir SMB share) içeren **dynamic `groupPolicyContainer`** object oluşturun ve bunu hedef OU’ya **`gPLink`** ile bağlayın.
- Clients policy’yi işler ve içeriği attacker SMB’den çeker. TTL expire olduğunda GPO object (ve **`gPCFileSysPath`**) kaybolur; geriye yalnızca **broken `gPLink`** GUID kalır ve çalıştırılan payload’a dair LDAP evidence ortadan kalkar.
- Bu, klasik **GPODDITY-style** cleanup’a göre operasyonel olarak daha temizdir: orijinal **`gPCFileSysPath`**’i manuel olarak geri yüklemek yerine, AD timer dolunca malicious GPC’yi otomatik olarak kaldırır.

## Ephemeral AD-Integrated DNS Redirection

- AD DNS records, **DomainDnsZones/ForestDnsZones** içinde bulunan **`dnsNode`** objects’tir. Bunları **dynamic objects** olarak oluşturmak, geçici host redirection’a (credential capture/MITM) izin verir. Clients malicious A/AAAA response’u cache’ler; record daha sonra kendi kendini siler, böylece zone temiz görünür (görünümü yenilemek için DNS Manager zone reload gerektirebilir).
- Detection: replication/event logs üzerinden **`dynamicObject`**/**`entryTTL`** taşıyan herhangi bir DNS record için alert üretin; transient records standart DNS logs’ta nadiren görünür.

## Hybrid Entra ID Delta-Sync Gap (Note)

- Entra Connect delta sync, delete’leri tespit etmek için **tombstones**’a güvenir. Bir **dynamic on-prem user**, Entra ID’ye sync olabilir, expire olup silinebilir ama tombstone oluşmaz; bu durumda delta sync cloud account’u kaldırmaz ve bir **orphaned active Entra user** bırakır. Bu durum, **initial/full sync** yapılana veya manual cloud cleanup zorlanana kadar sürer.

## References

- [Dynamic Objects in Active Directory: The Stealthy Threat](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)
- [Adventures in Primary Group Behavior, Reporting, and Exploitation](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)

{{#include ../../banners/hacktricks-training.md}}
