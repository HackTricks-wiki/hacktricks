# AD Dynamic Objects (dynamicObject) Anti-Forensics

{{#include ../../banners/hacktricks-training.md}}

## Osnove mehanike i detekcije

- Svaki objekat kreiran pomoćnom klasom **`dynamicObject`** dobija **`entryTTL`** (odbrojavanje u sekundama) i **`msDS-Entry-Time-To-Die`** (apsolutni rok isteka). Kada **`entryTTL`** dostigne 0 **i objekat nema potomke**, Garbage Collector ga briše bez tombstone/recycle-bin faze, uklanjajući podatke o kreatoru i vremenske oznake i onemogućavajući oporavak.<sup>[[4]](#references)</sup>
- **`entryTTL` je operativni/konstruisani atribut**: eksplicitno ga navedite u LDAP upitima. TTL se može osvežiti ažuriranjem **`entryTTL`** pre isteka ili putem LDAP TTL refresh OID-a **`1.3.6.1.4.1.1466.101.119.1`**.
- Minimalne i podrazumevane TTL vrednosti su forest-wide AVA vrednosti u **`CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,...` → `msDS-Other-Settings`**: `DynamicObjectMinTTLSeconds=<seconds>` i `DynamicObjectDefaultTTLSeconds=<seconds>`. Microsoft navodi **86400s** kao podrazumevani TTL i **900s** kao podrazumevani minimalni važeći TTL; opseg `entryTTL` schema-e je **1–31557600s** (od jedne sekunde do jedne godine).<sup>[[3]](#references)</sup> Dynamic objects nisu **podržani u Configuration/Schema particijama**.
- Ne postoji konverzija **static→dynamic** niti tombstone faza nakon isteka. IR timovi ne mogu da se oslone na kontrole obrisanih objekata ili Recycle Bin; moraju da sačuvaju živi objekat/metapodatke pre nego što ga GC ukloni.
- Osvežavanje zavisi od replike: ako se TTL obnovi preblizu isteku, druga writable replika ili GC i dalje mogu lokalno obrisati objekat pre nego što se osvežavanje replicira. Zbog toga veoma kratki TTL-ovi najbolje funkcionišu kada attacker zna koji će DC opslužiti zloupotrebu, dok defenders tokom triage-a treba da upite šalju svim naming contexts / replikama.
- Brisanje može kasniti nekoliko minuta na DC-ovima sa kratkim uptime-om (<24h), ostavljajući uzak prozor za odgovor tokom kog je moguće upitati/backup-ovati atribute. Detektujte ovo postavljanjem **alerta na nove objekte koji sadrže `entryTTL`/`msDS-Entry-Time-To-Die`** i korelacijom sa orphan SID-ovima/broken linkovima.<sup>[[1]](#references)</sup>

### Edge case-ovi expiry graph-a i reference-cleanup-a

- Svaki potomak ispod dynamic objekta mora i sam biti dynamic. Expired dynamic parent se garbage-collectuje tek kada postane leaf; ako potomak ima kasniji `msDS-Entry-Time-To-Die`, DC pomera istek parent-a nakon isteka najkasnijeg potomka. Posledično, writable dynamic subtree može **pin/extend parent koji izgleda kao da će uskoro nestati**: enumerišite celo stablo i nemojte koristiti uočeni `entryTTL` parent-a kao rok za cleanup.<sup>[[4]](#references)</sup>
- Expiry cleanup je **schema-link-aware**. Replike uklanjaju linked attribute vrednosti koje upućuju na obrisani dynamic object, ali zadržavaju nonlinked vrednosti. Očekujte da se uobičajeno forward/back-link članstvo očisti, dok integer/SID/string reference kao što su `primaryGroupID`, SID-ovi ugrađeni u `nTSecurityDescriptor` ili tekst `gPLink` mogu preživeti kao forenzički tragovi.<sup>[[4]](#references)</sup>

## Brza enumeracija / Live Triage

- Iz RootDSE upitajte **sve `namingContexts`**, a ne samo domain NC. Dynamic abuse može postojati u **`DomainDnsZones`/`ForestDnsZones`** (`dnsNode`) ili u application particijama.
- Dok je objekat još živ, odmah preuzmite **replication metadata** i sve linked atribute/ACL-ove. Nakon isteka mogu vam ostati samo **broken `gPLink` vrednosti, orphan SID-ovi ili keširani DNS odgovori**.<sup>[[1]](#references)</sup>
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
## Izbegavanje MAQ ograničenja pomoću računara koji se sami brišu

- Podrazumevani **`ms-DS-MachineAccountQuota` = 10** omogućava svakom autentifikovanom korisniku da kreira računare. Dodajte `dynamicObject` tokom kreiranja kako bi se računar sam obrisao i **oslobodio quota slot**, uz brisanje tragova.
- Powermad izmena unutar `New-MachineAccount` (lista objectClass):
```powershell
$request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
```
- Ako je zahtevani TTL **ispod `DynamicObjectMinTTL`**, očekujte serversko prilagođavanje ili odbijanje, u zavisnosti od putanje kreiranja; u mnogim domenima efektivni minimum je **900s**, a fallback/default ostaje **86400s**. ADUC može sakriti `entryTTL`, ali LDP/LDAP upiti ga otkrivaju.
- Dok objekat postoji, defenders i dalje mogu utvrditi neprivilegovanog kreatora iz atributa **`msDS-CreatorSID`** na objektu računara. Kada dynamic computer istekne, ta atribucija nestaje zajedno sa objektom.<sup>[[1]](#references)</sup>

## Skriveno članstvo u primarnoj grupi

- Kreirajte **dynamic security group**, a zatim postavite korisnikov **`primaryGroupID`** na RID te grupe kako biste dobili efektivno članstvo koje se **ne prikazuje u `memberOf`**, ali se uvažava u Kerberos/access tokens.<sup>[[1]](#references)</sup>
- Istek TTL-a **briše grupu uprkos zaštiti od brisanja primarne grupe**, ostavljajući korisnika sa oštećenim **`primaryGroupID`** koji pokazuje na nepostojeći RID, bez tombstone-a za utvrđivanje načina na koji je privilegija dodeljena.
- Izveštavanje zavisi od alata: **`Get-ADGroupMember` / `net group`** obično razrešavaju članstvo izvedeno iz primarne grupe, dok **`memberOf`** i **`Get-ADGroup -Properties member`** to ne rade. Za šire tradecraft u vezi sa **`primaryGroupID`**, pogledajte [ovu drugu stranicu o DCShadow i PGID abuse](dcshadow.md).
- Za ciljeve koji **nisu zaštićeni mehanizmom AdminSDHolder**, attackers mogu kombinovati dynamic-group trik sa **DACL deny** pravilom za čitanje **`primaryGroupID`** (ili atributa grupe **`member`**) kako bi sakrili vezu iz mnogih LDAP/PowerShell workflow-a čak i pre isteka grupe.<sup>[[2]](#references)</sup>

## Zagađenje AdminSDHolder orphan-SID vrednostima

- Dodajte ACE-ove za **short-lived dynamic user/group** u **`CN=AdminSDHolder,CN=System,...`**. Nakon isteka TTL-a, SID postaje **nerazrešiv („Unknown SID“)** u template ACL-u, a **SDProp (~60 min)** propagira taj orphan SID kroz sve zaštićene Tier-0 objekte.
- Forensics gubi atribuciju jer principal više ne postoji (nema DN-a obrisanog objekta). Pratite pojavu **novih dynamic principal-a + iznenadnih orphan SID-ova na AdminSDHolder/privileged ACL-ovima**.<sup>[[1]](#references)</sup>

## Izvršavanje dynamic GPO-a sa dokazima koji se sami uništavaju

- Kreirajte **dynamic `groupPolicyContainer`** objekat sa zlonamernim **`gPCFileSysPath`** (npr. SMB share à la GPODDITY) i povežite ga pomoću **`gPLink`** sa ciljnim OU-om.
- Klijenti obrađuju policy i preuzimaju sadržaj sa attacker SMB-a. Kada TTL istekne, GPO objekat (i **`gPCFileSysPath`**) nestaje; ostaje samo **nevažeći `gPLink`** GUID, čime se uklanjaju LDAP dokazi o izvršenom payload-u.
- Ovo je operativno čistije od klasičnog **GPODDITY-style** čišćenja: umesto da sami vraćate originalni `gPCFileSysPath`, AD automatski uklanja zlonamerni GPC kada timer istekne.<sup>[[1]](#references)</sup> Pogledajte [ACL persistence abuse](acl-persistence-abuse/README.md#gpcfilesyspath-poisoning-with-gpoddity) za detalje protokola i tooling-a, umesto da ih ovde dupliramo.

## Privremeno preusmeravanje DNS-a integrisanog sa AD-om

- AD DNS records su **`dnsNode`** objekti u **DomainDnsZones/ForestDnsZones**. Njihovo kreiranje kao **dynamic objects** omogućava privremeno preusmeravanje hostova (credential capture/MITM). Klijenti keširaju zlonamerni A/AAAA odgovor; zapis se kasnije sam briše, tako da zona izgleda čisto (DNS Manager-u će možda biti potrebno ponovno učitavanje zone radi osvežavanja prikaza).
- Detection: alarmirajte na **svaki DNS record koji sadrži `dynamicObject`/`entryTTL`** putem replication/event logs; transient records se retko pojavljuju u standardnim DNS logovima.<sup>[[1]](#references)</sup>

## Hybrid Entra ID delta-sync praznina (napomena)

- Entra Connect delta sync se oslanja na **tombstones** za otkrivanje brisanja. **Dynamic on-prem user** može da se sinhronizuje u Entra ID, istekne i bude obrisan bez tombstone-a — delta sync ga neće ukloniti iz clouda, ostavljajući **orphaned active Entra user** sve dok se ne pokrene **initial/full sync** ili ne izvrši ručno cloud čišćenje.<sup>[[1]](#references)</sup>



## References

- [1] [Dynamic Objects u Active Directory-ju: prikrivena pretnja](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)
- [2] [Avanture u ponašanju, izveštavanju i eksploataciji primarnih grupa](https://trustedsec.com/blog/adventures-in-primary-group-behavior-reporting-and-exploitation)
- [3] [Konfiguracija TTL ograničenja](https://learn.microsoft.com/en-us/windows/win32/ad/configuration-of-ttl-limits)
- [4] [[MS-ADTS]: Zahtevi za DynamicObject](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a0ea4e75-4b34-4f97-ae06-a8b19a5aaa5b)
{{#include ../../banners/hacktricks-training.md}}
