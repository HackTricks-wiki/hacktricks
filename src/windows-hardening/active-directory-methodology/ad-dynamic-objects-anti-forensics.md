# AD Dynamic Objects (dynamicObject) Anti-Forensics

{{#include ../../banners/hacktricks-training.md}}

## Mechanics & Detection Basics

- Any object created with the auxiliary class **`dynamicObject`** gains **`entryTTL`** (brojanje unazad u sekundama) and **`msDS-Entry-Time-To-Die`** (apsolutni trenutak isteka). Kada `entryTTL` dosegne 0, **Garbage Collector ga briše bez tombstone/recycle-bin**, čime se brišu creator/timestamps i blokira recovery.
- **`entryTTL` je operational/constructed atribut**: zatraži ga eksplicitno u LDAP upitima. TTL se može osvežiti ili ažuriranjem `entryTTL` pre isteka ili preko LDAP TTL refresh OID **`1.3.6.1.4.1.1466.101.119.1`**.
- TTL min/default se primenjuju u **Configuration\Services\NTDS Settings → `msDS-Other-Settings` → `DynamicObjectMinTTL` / `DynamicObjectDefaultTTL`**. Microsoft dokumentuje **86400s** kao podrazumevani TTL i **900s** kao podrazumevani minimalni važeći TTL; oba podržavaju **1s–1y**. Dynamic objects su **unsupported u Configuration/Schema partitions**.
- Ne postoji **static→dynamic conversion** i nema tombstone faze nakon isteka. IR timovi ne mogu da se oslanjaju na deleted-object kontrole ili Recycle Bin; moraju da uhvate live object/metadata pre nego što GC ukloni objekat.
- Refresh je **replica-sensitive**: ako se TTL obnovi preblizu isteka, drugi writable replica ili GC i dalje može lokalno obrisati objekat pre nego što se refresh replicira. Veoma kratki TTL-ovi zato najbolje rade kada napadač zna koji će DC obrađivati abuse, dok bi defanzivci trebalo da upitaju **sve naming contexts / replicas** tokom triage.
- Brisanje može kasniti nekoliko minuta na DC-jevima sa kratkim uptime (<24h), ostavljajući uzak response window za upit/backup atributa. Detektuj tako što ćeš **alertovati na nove objekte koji nose `entryTTL`/`msDS-Entry-Time-To-Die`** i korelisati ih sa orphan SIDs/broken links.

## Fast Enumeration / Live Triage

- Upituj **sve `namingContexts` iz RootDSE**, ne samo domain NC. Dynamic abuse može postojati u **`DomainDnsZones`/`ForestDnsZones`** (`dnsNode`) ili u application partitions.
- Dok je objekat još živ, odmah dump-uj **replication metadata** i sve linked attributes/ACLs. Nakon isteka možda će ostati samo **broken `gPLink` values, orphan SIDs, ili cached DNS answers**.
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

- Podrazumevani **`ms-DS-MachineAccountQuota` = 10** omogućava svakom autentifikovanom korisniku da kreira računare. Dodajte `dynamicObject` tokom kreiranja da bi se računar sam obrisao i **oslobodio quota slot**, uz brisanje tragova.
- Powermad podešavanje unutar `New-MachineAccount` (objectClass lista):
```powershell
$request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
```
- Ako je traženi TTL **ispod `DynamicObjectMinTTL`**, očekujte server-side prilagođavanje ili odbijanje u zavisnosti od puta kreiranja; u mnogim domenima efektivni minimum je **900s**, a fallback/default ostaje **86400s**. ADUC može sakriti `entryTTL`, ali LDP/LDAP upiti ga otkrivaju.
- Dok objekat postoji, defanzivci i dalje mogu da izvuku neprivilegovanog kreatora iz **`msDS-CreatorSID`** na computer objektu. Kada dynamic computer istekne, ta atribucija nestaje zajedno sa objektom.

## Stealth Primary Group Membership

- Kreirajte **dynamic security group**, zatim postavite korisnikov **`primaryGroupID`** na RID te grupe da biste dobili efektivno članstvo koje se **ne vidi u `memberOf`**, ali se poštuje u Kerberos/access tokens.
- Istek TTL-a **briše grupu uprkos primary-group delete protection**, ostavljajući korisniku oštećen `primaryGroupID` koji pokazuje na nepostojeći RID i bez tombstone zapisa za istragu kako je privilegija dodeljena.
- Izveštavanje zavisi od alata: **`Get-ADGroupMember` / `net group`** obično razrešavaju članstvo izvedeno iz primary group, dok **`memberOf`** i **`Get-ADGroup -Properties member`** to ne rade. Za širi `primaryGroupID` tradecraft, pogledajte [ovu drugu stranicu o DCShadow i PGID abuse](dcshadow.md).
- Za mete koje nisu zaštićene sa **AdminSDHolder**, napadači mogu da spoje trik sa dynamic group i **DACL deny na čitanje `primaryGroupID`** (ili `member` atributa grupe) da sakriju vezu od mnogih LDAP/PowerShell workflow-a čak i pre nego što grupa istekne.

## AdminSDHolder Orphan-SID Pollution

- Dodajte ACE-ove za **kratkotrajni dynamic user/group** u **`CN=AdminSDHolder,CN=System,...`**. Nakon isteka TTL-a SID postaje **nerazrešiv (“Unknown SID”)** u template ACL-u, a **SDProp (~60 min)** propagira taj orphan SID kroz sve zaštićene Tier-0 objekte.
- Forenzika gubi atribuciju jer principal nestaje (nema obrisanog-object DN). Pratite **nove dynamic principals + iznenadne orphan SID-ove na AdminSDHolder/privileged ACL-ovima**.

## Dynamic GPO Execution with Self-Destructing Evidence

- Kreirajte **dynamic `groupPolicyContainer`** objekat sa malicioznim **`gPCFileSysPath`** (npr. SMB share à la GPODDITY) i **povežite ga preko `gPLink`** sa ciljanim OU.
- Klijenti obrađuju policy i povlače sadržaj sa napadačevog SMB. Kada TTL istekne, GPO objekat (i `gPCFileSysPath`) nestaje; ostaje samo **oštećen `gPLink`** GUID, čime se uklanja LDAP trag izvršenog payload-a.
- Ovo je operativno čistije od klasičnog čišćenja u stilu **GPODDITY**: umesto da sami vraćate originalni `gPCFileSysPath`, AD automatski uklanja maliciozni GPC kada tajmer istekne.

## Ephemeral AD-Integrated DNS Redirection

- AD DNS zapisi su objekti **`dnsNode`** u **DomainDnsZones/ForestDnsZones**. Njihovo kreiranje kao **dynamic objects** omogućava privremeno preusmeravanje hosta (credential capture/MITM). Klijenti keširaju maliciozni A/AAAA odgovor; zapis se kasnije sam briše, pa zona izgleda čisto (DNS Manageru može biti potreban reload zone da osveži prikaz).
- Detekcija: alarm na **bilo koji DNS zapis sa `dynamicObject`/`entryTTL`** kroz replication/event logove; prolazni zapisi se retko pojavljuju u standardnim DNS logovima.

## Hybrid Entra ID Delta-Sync Gap (Note)

- Entra Connect delta sync se oslanja na **tombstones** za detekciju brisanja. **Dynamic on-prem user** može da se sinhronizuje u Entra ID, istekne i obriše bez tombstone-a — delta sync neće ukloniti cloud nalog, ostavljajući **orphaned active Entra user** sve dok se ne pokrene **initial/full sync** ili ručno cloud čišćenje.

## References

- [Dynamic Objects in Active Directory: The Stealthy Threat](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)
- [Adventures in Primary Group Behavior, Reporting, and Exploitation](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)

{{#include ../../banners/hacktricks-training.md}}
