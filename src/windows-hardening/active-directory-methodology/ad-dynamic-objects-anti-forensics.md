# AD Dynamic Objects (dynamicObject) Anti-Forensics

{{#include ../../banners/hacktricks-training.md}}

## Mekanik ve Tespit Temelleri

- Yardımcı sınıf **`dynamicObject`** ile oluşturulan her nesne **`entryTTL`** (saniye cinsinden geri sayım) ve **`msDS-Entry-Time-To-Die`** (mutlak sona erme zamanı) kazanır. `entryTTL` 0'a ulaştığında **ve nesnenin alt öğeleri olmadığında**, Garbage Collector nesneyi tombstone/recycle-bin olmadan siler; oluşturucuyu ve zaman damgalarını ortadan kaldırır ve kurtarmayı engeller.<sup>[[4]](#references)</sup>
- **`entryTTL` operasyonel/oluşturulmuş bir attribute'tur**: LDAP sorgularında açıkça istenmelidir. TTL, sona ermeden önce `entryTTL` güncellenerek veya LDAP TTL yenileme OID'si **`1.3.6.1.4.1.1466.101.119.1`** aracılığıyla yenilenebilir.
- TTL minimum ve varsayılan değerleri, **`CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,...` → `msDS-Other-Settings`** konumundaki forest genelindeki AVA'lardır: `DynamicObjectMinTTLSeconds=<seconds>` ve `DynamicObjectDefaultTTLSeconds=<seconds>`. Microsoft, varsayılan TTL olarak **86400s** ve geçerli TTL için varsayılan minimum değer olarak **900s** belgeler; `entryTTL` schema aralığı **1–31557600s**'dir (bir saniyeden bir yıla kadar).<sup>[[3]](#references)</sup> Dynamic objects, **Configuration/Schema partition'larında desteklenmez**.
- **Static→dynamic dönüşümü yoktur** ve sona erme sonrasında tombstone aşaması bulunmaz. IR ekipleri, silinen nesne kontrollerine veya Recycle Bin'e güvenemez; GC nesneyi kaldırmadan önce canlı nesneyi/metadata'yı yakalamalıdır.
- Yenileme **replica'ya duyarlıdır**: TTL sona ermeye çok yakın bir zamanda yenilenirse, başka bir writable replica veya GC, yenileme replike edilmeden önce nesneyi yerel olarak silebilir. Bu nedenle çok kısa TTL'ler, saldırganın kötüye kullanımı hangi DC'nin sunacağını bildiği durumlarda en iyi sonucu verir; savunmacılar ise triage sırasında **tüm naming context'leri / replica'ları** sorgulamalıdır.
- DC'lerde kısa uptime (<24h) durumunda silme birkaç dakika gecikebilir ve bu durum attribute'ları sorgulamak/backup almak için dar bir müdahale penceresi bırakır. **`entryTTL`/`msDS-Entry-Time-To-Die` taşıyan yeni nesneler** için alert oluşturarak ve bunları orphan SID'ler/broken link'ler ile ilişkilendirerek tespit edin.<sup>[[1]](#references)</sup>

### Sona erme grafiği ve referans temizleme edge case'leri

- Dynamic object altındaki her alt öğe kendisi de dynamic olmalıdır. Sona ermiş bir dynamic parent, yalnızca leaf haline geldikten sonra garbage collection'a alınır; bir alt öğenin daha sonraki bir `msDS-Entry-Time-To-Die` değeri varsa DC, parent'ın sona erme zamanını en uzun alt öğenin sona erme zamanının ötesine taşır. Sonuç olarak writable bir dynamic subtree, **kaybolmak üzere görünen bir parent'ı sabitleyebilir/uzatabilir**: tüm subtree'yi enumerate edin ve parent'ın gözlemlenen `entryTTL` değerini cleanup deadline olarak kullanmayın.<sup>[[4]](#references)</sup>
- Sona erme temizliği **schema-link-aware'dir**. Replica'lar, silinen dynamic object'i referanslayan linked attribute değerlerini kaldırır, ancak nonlinked değerleri korur. Normal forward/back-link üyeliğinin temizlenmesini bekleyin; buna karşılık `primaryGroupID`, `nTSecurityDescriptor` içine gömülü SID'ler veya `gPLink` metni gibi integer/SID/string referansları forensic residue olarak kalabilir.<sup>[[4]](#references)</sup>

## Hızlı Enumeration / Canlı Triage

- Yalnızca domain NC'yi değil, **RootDSE'den tüm `namingContexts` değerlerini** sorgulayın. Dynamic abuse, **`DomainDnsZones`/`ForestDnsZones`** (`dnsNode`) içinde veya application partition'larda bulunabilir.
- Nesne hâlâ canlıyken hemen **replication metadata**'yı ve linked attribute/ACL'leri dump edin. Sona ermeden sonra geriye yalnızca **bozuk `gPLink` değerleri, orphan SID'ler veya cache'lenmiş DNS yanıtları** kalabilir.<sup>[[1]](#references)</sup>
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
## Self-Deleting Computers ile MAQ Evasion

- Varsayılan **`ms-DS-MachineAccountQuota` = 10**, kimliği doğrulanmış herhangi bir kullanıcının computer oluşturmasına izin verir. Oluşturma sırasında `dynamicObject` eklenirse computer kendini siler ve **quota slot**'unu serbest bırakırken kanıtları da temizler.
- `New-MachineAccount` içindeki Powermad değişikliği (`objectClass` listesi):
```powershell
$request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
```
- İstenen TTL, **`DynamicObjectMinTTL`** değerinin altındaysa, oluşturma yoluna bağlı olarak server-side adjustment veya rejection bekleyin; birçok domain'de etkin alt sınır **900s**, fallback/default değeri ise **86400s** olarak kalır. ADUC `entryTTL` değerini gizleyebilir, ancak LDP/LDAP queries bunu ortaya çıkarır.
- Object mevcut olduğu sürece defender'lar, computer object üzerindeki **`msDS-CreatorSID`** üzerinden unprivileged creator'ı yine tespit edebilir. Dynamic computer süresi dolduğunda bu attribution object ile birlikte ortadan kalkar.<sup>[[1]](#references)</sup>

## Stealth Primary Group Membership

- Bir **dynamic security group** oluşturun, ardından etkin membership elde etmek için bir kullanıcının **`primaryGroupID`** değerini bu group'un RID'si olarak ayarlayın; bu membership **`memberOf`** içinde görünmez, ancak Kerberos/access token'larda dikkate alınır.<sup>[[1]](#references)</sup>
- TTL expiry, **primary-group delete protection**'a rağmen group'u siler; geride, var olmayan bir RID'ye işaret eden bozulmuş bir **`primaryGroupID`** bırakır ve privilege'ın nasıl verildiğini araştırmak için tombstone kalmaz.
- Reporting tool'a bağlıdır: **`Get-ADGroupMember` / `net group`** genellikle primary-group-derived membership'ı çözümler; **`memberOf`** ve **`Get-ADGroup -Properties member`** ise çözümlemez. Daha kapsamlı **`primaryGroupID`** tradecraft için [DCShadow ve PGID abuse hakkındaki diğer sayfaya](dcshadow.md) bakın.
- **AdminSDHolder-protected olmayan** hedeflerde attacker'lar, group expire olmadan önce bile birçok LDAP/PowerShell workflow'unda link'i gizlemek için dynamic-group trick'i **`primaryGroupID`** okumasına (veya group'un `member` attribute'una) yönelik bir **DACL deny** ile birleştirebilir.<sup>[[2]](#references)</sup>

## AdminSDHolder Orphan-SID Pollution

- **Kısa ömürlü bir dynamic user/group** için **`CN=AdminSDHolder,CN=System,...`** üzerine ACE'ler ekleyin. TTL expiry sonrasında SID, template ACL içinde **çözümlenemeyen (“Unknown SID”)** hale gelir ve **SDProp (~60 min)** bu orphan SID'yi tüm protected Tier-0 object'lerine yayar.
- Principal ortadan kalktığı için (deleted-object DN yoktur) forensics attribution'ı kaybeder. **Yeni dynamic principal'lar + AdminSDHolder/privileged ACL'lerinde ani orphan SID'ler** için monitoring yapın.<sup>[[1]](#references)</sup>

## Self-Destructing Evidence ile Dynamic GPO Execution

- Kötü amaçlı bir **`gPCFileSysPath`** içeren (ör. GPODDITY tarzı SMB share) **dynamic `groupPolicyContainer`** object'i oluşturun ve bunu **`gPLink`** üzerinden hedef OU'ya linkleyin.
- Client'lar policy'yi işler ve içeriği attacker SMB'sinden çeker. TTL expire olduğunda GPO object'i (ve **`gPCFileSysPath`**) ortadan kalkar; yalnızca bir **broken `gPLink`** GUID'i kalır ve çalıştırılan payload'a ilişkin LDAP evidence'ı kaldırır.
- Bu yöntem, klasik **GPODDITY-style** cleanup'tan operasyonel olarak daha temizdir: Orijinal `gPCFileSysPath` değerini kendiniz geri yüklemek yerine AD, timer expire olduğunda malicious GPC'yi otomatik olarak kaldırır.<sup>[[1]](#references)</sup> Protocol ve tooling ayrıntılarını burada tekrarlamak yerine [ACL persistence abuse](acl-persistence-abuse/README.md#gpcfilesyspath-poisoning-with-gpoddity) sayfasına bakın.

## Ephemeral AD-Integrated DNS Redirection

- AD DNS records, **DomainDnsZones/ForestDnsZones** içindeki **`dnsNode`** object'leridir. Bunları **dynamic object** olarak oluşturmak, temporary host redirection'a (credential capture/MITM) olanak tanır. Client'lar malicious A/AAAA response'u cache'ler; record daha sonra kendini siler ve zone temiz görünür (view'u yenilemek için DNS Manager'da zone reload gerekebilir).
- Detection: replication/event logs üzerinden **`dynamicObject`/`entryTTL`** taşıyan **herhangi bir DNS record** için alert üretin; transient record'lar standart DNS logs içinde nadiren görünür.<sup>[[1]](#references)</sup>

## Hybrid Entra ID Delta-Sync Gap (Note)

- Entra Connect delta sync, delete işlemlerini algılamak için **tombstone**'lara dayanır. **Dynamic on-prem user**, Entra ID'ye sync olabilir, süresi dolabilir ve tombstone olmadan silinebilir; delta sync cloud account'u kaldırmaz ve **initial/full sync** yapılana veya manual cloud cleanup zorlanana kadar **orphaned active Entra user** bırakır.<sup>[[1]](#references)</sup>



## References

- [1] [Active Directory'de Dynamic Objects: Stealthy Threat](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)
- [2] [Primary Group Behavior, Reporting ve Exploitation Maceraları](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)
- [3] [TTL Limits Configuration](https://learn.microsoft.com/en-us/windows/win32/ad/configuration-of-ttl-limits)
- [4] [[MS-ADTS]: DynamicObject Requirements](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a0ea4e75-4b34-4f97-ae06-a8b19a5aaa5b)
{{#include ../../banners/hacktricks-training.md}}
