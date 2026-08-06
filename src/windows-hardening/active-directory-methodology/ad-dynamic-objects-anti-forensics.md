# AD Dynamic Objects (dynamicObject) Anti-Forensics

{{#include ../../banners/hacktricks-training.md}}

## Mekanik ve Detection Temelleri

- **`dynamicObject`** auxiliary class'ı ile oluşturulan her object, **`entryTTL`** (saniye cinsinden geri sayım) ve **`msDS-Entry-Time-To-Die`** (mutlak sona erme zamanı) değerlerini kazanır. `entryTTL` 0'a ulaştığında **Garbage Collector**, object'i tombstone/recycle-bin olmadan siler; böylece creator ve timestamp bilgileri silinir ve recovery engellenir.
- **`entryTTL` bir operational/constructed attribute'tur**: LDAP query'lerinde bunu açıkça isteyin. TTL, sona ermeden önce `entryTTL` güncellenerek veya LDAP TTL refresh OID'si **`1.3.6.1.4.1.1466.101.119.1`** aracılığıyla yenilenebilir.
- TTL minimum/default değerleri **Configuration\Services\NTDS Settings → `msDS-Other-Settings` → `DynamicObjectMinTTL` / `DynamicObjectDefaultTTL`** altında uygulanır. Microsoft, varsayılan TTL değerini **86400s**, geçerli varsayılan minimum TTL değerini ise **900s** olarak belgeler; her ikisi de **1s–1y** aralığını destekler. Dynamic object'ler **Configuration/Schema partition**'larında desteklenmez.
- **Static→dynamic conversion** yoktur ve sona ermeden sonra tombstone aşaması gerçekleşmez. IR ekipleri deleted-object kontrollerine veya Recycle Bin'e güvenemez; GC kaldırmadan önce canlı object'i/metadata'yı yakalamaları gerekir.
- Refresh, **replica-sensitive** bir işlemdir: TTL sona ermeye çok yakın yenilenirse başka bir writable replica veya GC, refresh replicate edilmeden önce object'i yerel olarak silebilir. Bu nedenle çok kısa TTL'ler, attacker'ın abuse işlemini hangi DC'nin sunacağını bildiği durumlarda daha iyi çalışır; defender'lar ise triage sırasında **tüm naming context / replica**'ları query etmelidir.
- Deletion, kısa uptime'a (<24h) sahip DC'lerde birkaç dakika gecikebilir ve attribute'ları query/backup etmek için dar bir response window bırakabilir. **`entryTTL`/`msDS-Entry-Time-To-Die` taşıyan yeni object'ler** için alert oluşturarak ve bunları orphan SID'ler/broken link'lerle ilişkilendirerek detection yapın.<sup>[[1]](#references)</sup>

## Fast Enumeration / Live Triage

- Yalnızca domain NC'yi değil, **RootDSE'den tüm `namingContexts` değerlerini** query edin. Dynamic abuse, **`DomainDnsZones`/`ForestDnsZones`** (`dnsNode`) içinde veya application partition'larında bulunabilir.
- Object hâlâ canlıyken hemen **replication metadata** ile tüm linked attribute/ACL'leri dump edin. Expiry sonrasında geriye yalnızca **broken `gPLink` değerleri, orphan SID'ler veya cached DNS yanıtları** kalabilir.<sup>[[1]](#references)</sup>
```powershell
$root = Get-ADRootDSE
$root.namingContexts | ForEach-Object {
Get-ADObject -LDAPFilter '(objectClass=dynamicObject)' -SearchBase $_ `
-Properties entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID |
Select-Object DistinguishedName,entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID
}
repadmin /showobjmeta <DC> <distinguishedName>
```
## Self-Deleting Computers ile MAQ Evasion

- Varsayılan **`ms-DS-MachineAccountQuota` = 10**, kimliği doğrulanmış herhangi bir kullanıcının bilgisayar oluşturmasına izin verir. Oluşturma sırasında `dynamicObject` eklenerek bilgisayarın kendini silmesi ve kanıtları temizlerken quota slotunu serbest bırakması sağlanabilir.
- `New-MachineAccount` içindeki Powermad değişikliği (objectClass listesi):
```powershell
$request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
```
- İstenen TTL `DynamicObjectMinTTL` değerinin altındaysa, oluşturma yoluna bağlı olarak server-side adjustment veya rejection bekleyin; birçok domain'de etkin alt sınır **900s** ve fallback/default değeri **86400s** olarak kalır. ADUC `entryTTL` değerini gizleyebilir, ancak LDP/LDAP sorguları bunu gösterir.
- Nesne mevcutken defenders, bilgisayar nesnesindeki **`msDS-CreatorSID`** üzerinden unprivileged creator'ı yine de tespit edebilir. Dynamic computer'ın süresi dolduğunda bu attribution nesneyle birlikte kaybolur.<sup>[[1]](#references)</sup>

## Stealth Primary Group Membership

- Bir **dynamic security group** oluşturun, ardından etkin üyelik kazanmak için bir kullanıcının **`primaryGroupID`** değerini bu grubun RID'si olarak ayarlayın; bu üyelik **`memberOf`** içinde görünmez, ancak Kerberos/access token'larında dikkate alınır.<sup>[[1]](#references)</sup>
- TTL expiry, primary-group delete protection'a rağmen grubu siler; kullanıcıda var olmayan bir RID'yi gösteren bozulmuş bir **`primaryGroupID`** kalır ve ayrıcalığın nasıl verildiğini araştırmak için tombstone bulunmaz.
- Reporting tool'a bağlıdır: **`Get-ADGroupMember` / `net group`** genellikle primary-group-derived membership'ı çözerken, **`memberOf`** ve **`Get-ADGroup -Properties member`** bunu yapmaz. Daha geniş **`primaryGroupID`** tradecraft bilgisi için [this other page about DCShadow and PGID abuse](dcshadow.md) sayfasına bakın.
- **AdminSDHolder-protected** olmayan hedeflerde attackers, grup süresi dolmadan önce bile birçok LDAP/PowerShell workflow'undan bağlantıyı gizlemek için dynamic-group trick'i **`primaryGroupID`** okumasına (veya grubun **`member`** attribute'una) yönelik bir **DACL deny** ile birleştirebilir.<sup>[[2]](#references)</sup>

## AdminSDHolder Orphan-SID Pollution

- **`CN=AdminSDHolder,CN=System,...`** altındaki bir **short-lived dynamic user/group** için ACE'ler ekleyin. TTL expiry sonrasında SID, template ACL içinde **unresolvable (“Unknown SID”)** hale gelir ve **SDProp (~60 min)** bu orphan SID'yi tüm protected Tier-0 nesnelerine yayar.
- Forensics attribution'ı kaybeder, çünkü principal ortadan kalkmıştır (deleted-object DN yoktur). **Yeni dynamic principal'lar + AdminSDHolder/privileged ACL'lerinde ani orphan SID'ler** için monitoring yapın.<sup>[[1]](#references)</sup>

## Self-Destructing Evidence ile Dynamic GPO Execution

- Kötü amaçlı bir **`gPCFileSysPath`** içeren (ör. GPODDITY tarzı SMB share) **dynamic `groupPolicyContainer`** nesnesi oluşturun ve bunu **`gPLink`** üzerinden hedef bir OU'ya linkleyin.
- Client'lar policy'yi işler ve içeriği attacker SMB'den çeker. TTL expiry olduğunda GPO nesnesi (ve **`gPCFileSysPath`**) ortadan kalkar; geriye yalnızca bir **broken `gPLink`** GUID'i kalır ve çalıştırılan payload'a ilişkin LDAP evidence kaldırılır.
- Bu yaklaşım, classic **GPODDITY-style** cleanup'tan operational olarak daha temizdir: orijinal **`gPCFileSysPath`** değerini kendiniz geri yüklemek yerine AD, timer sona erdiğinde malicious GPC'yi otomatik olarak kaldırır.<sup>[[1]](#references)</sup>

## Ephemeral AD-Integrated DNS Redirection

- AD DNS records, **DomainDnsZones/ForestDnsZones** içindeki **`dnsNode`** nesneleridir. Bunların **dynamic objects** olarak oluşturulması, geçici host redirection'a (credential capture/MITM) olanak tanır. Client'lar malicious A/AAAA response'u cache'ler; record daha sonra kendini silerek zone'un temiz görünmesini sağlar (görünümü yenilemek için DNS Manager'da zone reload gerekebilir).
- Detection: replication/event logs üzerinden **`dynamicObject`/`entryTTL`** taşıyan **herhangi bir DNS record** için alert oluşturun; transient record'lar standard DNS logs içinde nadiren görünür.<sup>[[1]](#references)</sup>

## Hybrid Entra ID Delta-Sync Gap (Note)

- Entra Connect delta sync, silmeleri tespit etmek için **tombstone**'lara güvenir. **Dynamic on-prem user**, Entra ID ile sync olabilir, süresi dolabilir ve tombstone olmadan silinebilir; delta sync cloud account'u kaldırmaz ve **orphaned active Entra user** bırakır. Bu durum, bir **initial/full sync** veya manuel cloud cleanup zorlanana kadar devam eder.<sup>[[1]](#references)</sup>

## References

- [1] [Dynamic Objects in Active Directory: The Stealthy Threat](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)
- [2] [Adventures in Primary Group Behavior, Reporting, and Exploitation](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)

{{#include ../../banners/hacktricks-training.md}}
