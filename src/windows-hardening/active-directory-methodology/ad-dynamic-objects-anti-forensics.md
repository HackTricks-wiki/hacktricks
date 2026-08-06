# AD Dynamic Objects (dynamicObject) Anti-Forensics

{{#include ../../banners/hacktricks-training.md}}

## Osnove mehanizma i detekcije

- Svaki objekat kreiran sa pomoćnom klasom **`dynamicObject`** dobija **`entryTTL`** (odbrojavanje u sekundama) i **`msDS-Entry-Time-To-Die`** (apsolutno vreme isteka). Kada **`entryTTL`** dostigne 0, **Garbage Collector** ga briše bez tombstone/recycle-bin faze, uklanjajući podatke o kreatoru i vremenske oznake i onemogućavajući oporavak.
- **`entryTTL`** je operational/constructed atribut: eksplicitno ga zatražite u LDAP upitima. TTL se može osvežiti ažuriranjem **`entryTTL`** pre isteka ili putem LDAP TTL refresh OID-a **`1.3.6.1.4.1.1466.101.119.1`**.
- Minimalne i podrazumevane TTL vrednosti primenjuju se u **Configuration\Services\NTDS Settings → `msDS-Other-Settings` → `DynamicObjectMinTTL` / `DynamicObjectDefaultTTL`**. Microsoft navodi **86400s** kao podrazumevani TTL i **900s** kao podrazumevani minimalni važeći TTL; obe vrednosti podržavaju opseg od **1s do 1y**. Dynamic objects nisu podržani u Configuration/Schema particijama.
- Ne postoji konverzija static→dynamic niti tombstone faza nakon isteka. IR timovi ne mogu da se oslone na kontrole za obrisane objekte ili Recycle Bin; moraju da prikupe aktivni objekat/metapodatke pre nego što ih GC ukloni.
- Osvežavanje zavisi od replike: ako se TTL obnovi preblizu isteku, druga writable replika ili GC i dalje mogu lokalno da obrišu objekat pre nego što se osvežavanje replicira. Zbog toga vrlo kratki TTL-ovi najbolje funkcionišu kada attacker zna koji će DC obraditi abuse, dok defenders tokom triage-a treba da upite pošalju svim naming context-ima / replikama.
- Brisanje može kasniti nekoliko minuta na DC-ovima sa kratkim uptime-om (<24h), ostavljajući uzak response window za upite ili backup atributa. Detekciju omogućite postavljanjem alert-a za nove objekte koji sadrže **`entryTTL`**/ **`msDS-Entry-Time-To-Die`** i korelacijom sa orphan SID-ovima/broken link-ovima.<sup>[[1]](#references)</sup>

## Fast Enumeration / Live Triage

- Pribavite sve **`namingContexts`** iz RootDSE-a, a ne samo domain NC. Dynamic abuse može da se nalazi u **`DomainDnsZones`**/`ForestDnsZones`** (`dnsNode`) ili u application particijama.
- Dok je objekat još aktivan, odmah sačuvajte **replication metadata** i sve linked attributes/ACL-ove. Nakon isteka mogu vam preostati samo **broken `gPLink`** vrednosti, orphan SID-ovi ili keširani DNS odgovori.<sup>[[1]](#references)</sup>
```powershell
$root = Get-ADRootDSE
$root.namingContexts | ForEach-Object {
Get-ADObject -LDAPFilter '(objectClass=dynamicObject)' -SearchBase $_ `
-Properties entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID |
Select-Object DistinguishedName,entryTTL,msDS-Entry-Time-To-Die,gPCFileSysPath,msDS-CreatorSID
}
repadmin /showobjmeta <DC> <distinguishedName>
```
## MAQ Evasion sa računarima koji se sami brišu

- Podrazumevani **`ms-DS-MachineAccountQuota` = 10** omogućava svakom autentifikovanom korisniku da kreira računare. Dodajte `dynamicObject` tokom kreiranja kako bi se računar sam obrisao i oslobodio quota slot, uz brisanje tragova.
- Powermad izmena unutar `New-MachineAccount` (lista objectClass):
```powershell
$request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
```
- Ako je zahtevani TTL **ispod `DynamicObjectMinTTL`**, očekujte serversko prilagođavanje ili odbijanje, u zavisnosti od putanje kreiranja; u mnogim domenima efektivni minimum je **900s**, dok fallback/default ostaje **86400s**. ADUC može sakriti `entryTTL`, ali LDP/LDAP upiti ga otkrivaju.
- Dok objekat postoji, defenders i dalje mogu pronaći neprivilegovanog kreatora u atributu **`msDS-CreatorSID`** na objektu računara. Kada dynamic računar istekne, ta atribucija nestaje zajedno sa objektom.<sup>[[1]](#references)</sup>

## Stealth članstvo u primarnoj grupi

- Kreirajte **dynamic security group**, zatim postavite korisnikov **`primaryGroupID`** na RID te grupe da biste dobili efektivno članstvo koje se **ne prikazuje u `memberOf`**, ali se uvažava u Kerberos/access tokenima.<sup>[[1]](#references)</sup>
- Istek TTL-a **briše grupu uprkos zaštiti od brisanja primarne grupe**, ostavljajući korisnika sa oštećenim **`primaryGroupID`** koji pokazuje na nepostojeći RID i bez tombstone-a koji bi omogućio istragu o tome kako je privilegija dodeljena.
- Izveštavanje zavisi od alata: **`Get-ADGroupMember` / `net group`** obično razrešavaju članstvo izvedeno iz primarne grupe, dok **`memberOf`** i **`Get-ADGroup -Properties member`** to ne rade. Za širu tradecraft upotrebu **`primaryGroupID`**, pogledajte [ovu drugu stranicu o DCShadow i PGID abuse](dcshadow.md).
- Za ciljeve koji **nisu zaštićeni AdminSDHolder-om**, attackers mogu upariti dynamic-group trik sa **DACL deny** pravilom za čitanje **`primaryGroupID`** (ili atributa grupe `member`) kako bi sakrili vezu od mnogih LDAP/PowerShell workflow-a čak i pre isteka grupe.<sup>[[2]](#references)</sup>

## AdminSDHolder Orphan-SID zagađenje

- Dodajte ACE-ove za **kratkotrajni dynamic user/group** u **`CN=AdminSDHolder,CN=System,...`**. Nakon isteka TTL-a SID postaje **nerešiv („Unknown SID“)** u template ACL-u, a **SDProp (~60 min)** propagira taj orphan SID kroz sve zaštićene Tier-0 objekte.
- Forensics gubi atribuciju jer principal više ne postoji (nema DN-a obrisanog objekta). Nadgledajte **nove dynamic principals + iznenadne orphan SID-ove na AdminSDHolder/privileged ACL-ovima**.<sup>[[1]](#references)</sup>

## Dynamic GPO izvršavanje sa dokazima koji se sami uništavaju

- Kreirajte **dynamic `groupPolicyContainer`** objekat sa zlonamernim **`gPCFileSysPath`** (npr. SMB share u stilu GPODDITY) i povežite ga putem **`gPLink`** sa ciljnim OU-om.
- Clients obrađuju policy i preuzimaju sadržaj sa attacker SMB-a. Kada TTL istekne, GPO objekat (i **`gPCFileSysPath`**) nestaje; ostaje samo **neispravan `gPLink`** GUID, čime se uklanjaju LDAP dokazi o izvršenom payload-u.
- Ovo je operativno čistije od klasičnog **GPODDITY-style** cleanup-a: umesto da sami vraćate originalni `gPCFileSysPath`, AD automatski uklanja zlonamerni GPC kada timer istekne.<sup>[[1]](#references)</sup>

## Ephemeral AD-integrisano DNS preusmeravanje

- AD DNS zapisi su **`dnsNode`** objekti u **DomainDnsZones/ForestDnsZones**. Njihovo kreiranje kao dynamic objekata omogućava privremeno preusmeravanje hosta (credential capture/MITM). Clients keširaju zlonamerni A/AAAA odgovor; zapis se kasnije sam briše, pa zona izgleda čisto (DNS Manager-u će možda biti potrebno ponovno učitavanje zone da bi se prikaz osvežio).
- Detekcija: alarmirajte na **bilo koji DNS zapis koji sadrži `dynamicObject`/`entryTTL`** putem replication/event logova; transient zapisi se retko pojavljuju u standardnim DNS logovima.<sup>[[1]](#references)</sup>

## Hybrid Entra ID Delta-Sync praznina (napomena)

- Entra Connect delta sync se oslanja na **tombstone** objekte za detekciju brisanja. **Dynamic on-prem user** može da se sinhronizuje u Entra ID, istekne i bude obrisan bez tombstone-a — delta sync neće ukloniti cloud account, ostavljajući **orphaned active Entra user** sve dok se ne pokrene **initial/full sync** ili ne izvrši ručno cloud cleanup.<sup>[[1]](#references)</sup>

## Reference

- [1] [Dynamic Objects in Active Directory: The Stealthy Threat](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)
- [2] [Adventures in Primary Group Behavior, Reporting, and Exploitation](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)

{{#include ../../banners/hacktricks-training.md}}
