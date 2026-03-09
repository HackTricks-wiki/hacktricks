# AD Dinamički objekti (dynamicObject) Anti-forenzika

{{#include ../../banners/hacktricks-training.md}}

## Mehanika i osnove detekcije

- Bilo koji objekat kreiran sa pomoćnom klasom **`dynamicObject`** dobija **`entryTTL`** (odbrojavanje u sekundama) i **`msDS-Entry-Time-To-Die`** (apsolutni datum isteka). Kada `entryTTL` dostigne 0, **Garbage Collector ga briše bez tombstone/recycle-bin**, brišući podatke o kreatoru/timestamp-ove i onemogućavajući oporavak.
- TTL se može osvežiti ažuriranjem `entryTTL`; min/default vrednosti se nameću u **Configuration\Services\NTDS Settings → `msDS-Other-Settings` → `DynamicObjectMinTTL` / `DynamicObjectDefaultTTL`** (podržava 1s–1y ali često podrazumevano iznosi 86,400s/24h). Dinamički objekti su **neosnovani u Configuration/Schema particijama**.
- Brisanje može kasniti nekoliko minuta na DC-ovima sa kratkim uptime-om (<24h), ostavljajući uski vremenski prozor za upit/backup atributa. Detektujte to **alertovanjem na nove objekte koji nose `entryTTL`/`msDS-Entry-Time-To-Die`** i korelacijom sa napuštenim SID-ovima/pokidanim linkovima.

## MAQ izbegavanje pomoću samouništavajućih računara

- Podrazumevano **`ms-DS-MachineAccountQuota` = 10** dozvoljava bilo kojem autentifikovanom korisniku da kreira računare. Dodajte `dynamicObject` tokom kreacije da računar samouništavajuće obriše i **oslobodi slot MAQ-a** dok briše dokaze.
- Powermad prilagođavanje unutar `New-MachineAccount` (objectClass lista):
```powershell
$request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
```
- Kratak TTL (npr. 60s) često ne uspeva za standardne korisnike; AD pada na **`DynamicObjectDefaultTTL`** (primer: 86,400s). ADUC može skrivati `entryTTL`, ali LDP/LDAP upiti to otkrivaju.

## Neprimetno članstvo u primarnoj grupi

- Kreirajte **dinamičku sigurnosnu grupu**, zatim podesite korisnikov **`primaryGroupID`** na RID te grupe da biste dobili efektivno članstvo koje **se ne prikazuje u `memberOf`**, ali se poštuje u Kerberos/access token-ima.
- Istek TTL-a **briše grupu uprkos zaštiti od brisanja primarne grupe**, ostavljajući korisnika sa korumpiranim `primaryGroupID` koji pokazuje na nepostojeći RID i bez tombstone-a da se istraži kako je privilegija dodeljena.

## Kontaminacija AdminSDHolder-a napuštenim SID-ovima

- Dodajte ACE-e za **kratkotrajnog dinamičkog korisnika/grupu** u **`CN=AdminSDHolder,CN=System,...`**. Nakon isteka TTL-a SID postaje **nerazrešiv (“Unknown SID”)** u šablonu ACL-a, i **SDProp (~60 min)** propagira taj napušteni SID preko svih zaštićenih Tier-0 objekata.
- Forenzika gubi atribuciju zato što principal više ne postoji (nema obrisanog DN-a objekta). Monitorišite za **nove dinamičke principe + nagle napuštene SID-ove na AdminSDHolder/privilegovanim ACL-ovima**.

## Dinamičko izvršavanje GPO sa samouništavajućim dokazima

- Kreirajte **dinamički `groupPolicyContainer`** objekat sa zlonamernim **`gPCFileSysPath`** (npr. SMB share ala GPODDITY) i **povežite ga preko `gPLink`** na ciljnu OU.
- Klijenti procesuiraju politiku i povlače sadržaj sa attacker SMB-a. Kada TTL istekne, GPO objekat (i `gPCFileSysPath`) nestane; ostaje samo **pokidani `gPLink`** GUID, uklanjajući LDAP dokaze o izvršenom payload-u.

## Privremeno AD-integrisano DNS preusmeravanje

- AD DNS zapisi su **`dnsNode`** objekti u **DomainDnsZones/ForestDnsZones**. Kreiranje ih kao **dinamičkih objekata** omogućava privremeno preusmeravanje hosta (credential capture/MITM). Klijenti keširaju zlonamerni A/AAAA odgovor; zapis se kasnije samobriše tako da zona izgleda čisto (DNS Manager možda treba reload zone da osveži prikaz).
- Detekcija: alertujte na **bilo koji DNS zapis koji nosi `dynamicObject`/`entryTTL`** preko replikacije/event log-ova; tranzijentni zapisi se retko pojavljuju u standardnim DNS log-ovima.

## Hybridni Entra ID delta-sync jaz (Napomena)

- Entra Connect delta sync oslanja se na **tombstone** zapise da detektuje brisanja. **Dinamički on-prem korisnik** može se sinhronizovati u Entra ID, isteći i obrisati bez tombstone-a — delta sync neće ukloniti cloud nalog, ostavljajući **napuštenog aktivnog Entra korisnika** sve dok se ne pokrene manuelni **full sync**.

## Reference

- [Dynamic Objects in Active Directory: The Stealthy Threat](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)

{{#include ../../banners/hacktricks-training.md}}
