# AD Dynamic Objects (dynamicObject) Anti-Forensics

{{#include ../../banners/hacktricks-training.md}}

## Mekanikler & Detection Temelleri

- auxiliary class **`dynamicObject`** ile oluşturulan herhangi bir nesne, **`entryTTL`** (saniye geri sayımı) ve **`msDS-Entry-Time-To-Die`** (mutlak sona erme) kazanır. `entryTTL` 0 olduğunda **Garbage Collector** nesneyi **tombstone/recycle-bin olmadan** siler; bu da oluşturucu/zaman damgalarını siler ve kurtarmayı engeller.
- **`entryTTL` operasyonel/constructed bir attribute**'tur: LDAP sorgularında bunu özellikle isteyin. TTL, ya sona ermeden önce `entryTTL` güncellenerek ya da LDAP TTL refresh OID **`1.3.6.1.4.1.1466.101.119.1`** üzerinden yenilenebilir.
- TTL min/default değerleri **Configuration\Services\NTDS Settings → `msDS-Other-Settings` → `DynamicObjectMinTTL` / `DynamicObjectDefaultTTL`** içinde zorlanır. Microsoft varsayılan TTL olarak **86400s** ve varsayılan minimum geçerli TTL olarak **900s** belirtir; her ikisi de **1s–1y** destekler. Dynamic objects, **Configuration/Schema partitions** içinde desteklenmez.
- Static→dynamic dönüşüm yoktur ve sona ermeden sonra tombstone aşaması da yoktur. IR ekipleri deleted-object kontrollerine veya Recycle Bin'e güvenemez; Garbage Collector nesneyi kaldırmadan önce canlı nesneyi/metadata'yı yakalamalıdır.
- Yenileme **replica-sensitive**'dir: TTL sona erme anına çok yakın yenilenirse, başka bir writable replica veya GC nesneyi refresh replikasyonundan önce yerel olarak yine de silebilir. Bu yüzden çok kısa TTL'ler, saldırganın abuse'u hangi DC'nin servis edeceğini bildiği durumlarda en iyi çalışır; savunucular ise triage sırasında **tüm naming context'leri / replica'ları** sorgulamalıdır.
- Silme, kısa uptime'a (<24h) sahip DC'lerde birkaç dakika gecikebilir; bu da attribute sorgulamak/backup almak için dar bir response window bırakır. **Yeni nesnelerde `entryTTL`/`msDS-Entry-Time-To-Die` bulunmasına alarm vererek** ve orphan SID'ler/broken link'lerle korelasyon yaparak tespit edin.

## Hızlı Enumeration / Live Triage

- Yalnızca domain NC değil, RootDSE'den **tüm `namingContexts`**'i sorgulayın. Dynamic abuse, **`DomainDnsZones`/`ForestDnsZones`** (`dnsNode`) içinde veya application partitions'ta bulunabilir.
- Nesne hala canlıyken, hemen **replication metadata** ve bağlantılı attribute'ları/ACL'leri dökün. Süre dolduktan sonra elinizde sadece **broken `gPLink` values, orphan SIDs veya cached DNS answers** kalabilir.
```powershell
$root = Get-ADRootDSE
$root.namingContexts | ForEach-Object {
Get-ADObject -LDAPFilter '(objectClass=dynamicObject)' -SearchBase $_ `
-Properties entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID |
Select-Object DistinguishedName,entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID
}
repadmin /showobjmeta <DC> <distinguishedName>
```
## Kendi Kendini Silen Computer’larla MAQ Evasion

- Varsayılan **`ms-DS-MachineAccountQuota` = 10** herhangi bir kimliği doğrulanmış kullanıcının computer oluşturmasına izin verir. Oluşturma sırasında `dynamicObject` ekleyerek computer’ın kendi kendini silmesini ve **quota slot’unu serbest bırakmasını** sağlayabilir, aynı anda kanıtları da silebilirsiniz.
- Powermad içinde `New-MachineAccount` ayarı (objectClass listesi):
```powershell
$request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
```
- İstenen TTL, **`DynamicObjectMinTTL`** değerinin **altındaysa**, oluşturma yoluna bağlı olarak server-side ayarlama veya reddedilme bekleyin; birçok domain’de etkin alt sınır **900s** ve fallback/default değer **86400s** kalır. ADUC `entryTTL` alanını gizleyebilir, ancak LDP/LDAP sorguları bunu gösterir.
- Object var olduğu sürece, defenders yine de computer object üzerindeki **`msDS-CreatorSID`** ile ayrıcalıksız oluşturucuyu kurtarabilir. Dynamic computer süresi dolduğunda bu attribution object ile birlikte kaybolur.

## Gizli Primary Group Membership

- Bir **dynamic security group** oluşturun, ardından bir user’ın **`primaryGroupID`** değerini o group’un RID’sine ayarlayarak **`memberOf` içinde görünmeyen** ama Kerberos/access tokens tarafından kabul edilen etkin membership elde edin.
- TTL süresi dolduğunda, **primary-group delete protection’a rağmen group silinir**; user üzerinde, privilege’ın nasıl verildiğini araştırmak için tombstone bırakmadan var olmayan bir RID’ye işaret eden bozuk bir `primaryGroupID` kalır.
- Raporlama tool’a bağlıdır: **`Get-ADGroupMember` / `net group`** genelde primary-group kaynaklı membership’i çözer, **`memberOf`** ve **`Get-ADGroup -Properties member`** ise çözmez. Daha geniş `primaryGroupID` tradecraft için [DCShadow ve PGID abuse hakkında bu diğer sayfaya](dcshadow.md) bakın.
- **AdminSDHolder ile korunmayan** hedefler için attackers, dynamic-group hilesini **`primaryGroupID` okunmasına DACL deny** (veya group `member` attribute’una) ile eşleştirerek group süresi dolmadan önce bile link’i birçok LDAP/PowerShell workflow’undan gizleyebilir.

## AdminSDHolder Yetim-SID Kirliliği

- **Kısa ömürlü dynamic user/group** için **`CN=AdminSDHolder,CN=System,...`** içine ACE’ler ekleyin. TTL süresi dolduktan sonra SID, template ACL içinde **çözümlenemez (“Unknown SID”)** hale gelir ve **SDProp (~60 min)** bu yetim SID’yi tüm protected Tier-0 object’lere yayar.
- Forensics attribution’u kaybeder çünkü principal artık yoktur (silinmiş object DN’si yok). **Yeni dynamic principal’lar + AdminSDHolder/privileged ACL’lerde ani yetim SID’ler** için izleme yapın.

## Kendi Kendini Yok Eden Kanıtlarla Dynamic GPO Execution

- Kötü amaçlı **`gPCFileSysPath`** içeren bir **dynamic `groupPolicyContainer`** object oluşturun (ör. GPODDITY benzeri bir SMB share) ve bunu bir target OU’ya **`gPLink`** ile bağlayın.
- Clients policy’yi işler ve content’i attacker SMB’den çeker. TTL süresi dolduğunda GPO object’i (ve `gPCFileSysPath`) kaybolur; yalnızca **bozuk bir `gPLink`** GUID’si kalır ve executed payload’ın LDAP kanıtı ortadan kalkar.
- Bu, klasik **GPODDITY-style** cleanup’a göre operasyonel olarak daha temizdir: `gPCFileSysPath`’i kendiniz geri yüklemek yerine, süre dolunca AD malicious GPC’yi otomatik olarak kaldırır.

## Geçici AD-Integrated DNS Redirection

- AD DNS kayıtları **DomainDnsZones/ForestDnsZones** içinde **`dnsNode`** object’leridir. Bunları **dynamic objects** olarak oluşturmak geçici host redirection’a (credential capture/MITM) izin verir. Clients malicious A/AAAA response’u cache’ler; kayıt daha sonra kendi kendini siler, böylece zone temiz görünür (görünümü yenilemek için DNS Manager zone reload isteyebilir).
- Detection: replication/event logs üzerinden **`dynamicObject`/`entryTTL`** taşıyan herhangi bir DNS kaydı için alarm verin; geçici kayıtlar standart DNS logs’larda nadiren görünür.

## Hybrid Entra ID Delta-Sync Gap (Not)

- Entra Connect delta sync, silmeleri tespit etmek için **tombstone**’lara dayanır. **On-prem dynamic user** Entra ID’ye sync olabilir, süresi dolup silinebilir ama tombstone bırakmaz—delta sync cloud account’u kaldırmaz ve **orphaned active Entra user** bırakır; bu durum ancak **initial/full sync** veya manual cloud cleanup zorlanınca düzelir.

## References

- [Dynamic Objects in Active Directory: The Stealthy Threat](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)
- [Adventures in Primary Group Behavior, Reporting, and Exploitation](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)

{{#include ../../banners/hacktricks-training.md}}
