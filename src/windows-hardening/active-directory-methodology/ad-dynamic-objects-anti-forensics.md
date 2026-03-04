# AD Dinamički objekti (dynamicObject) — Anti-forenzika

{{#include ../../banners/hacktricks-training.md}}

## Mehanika i osnovi detekcije

- Bilo koji objekat kreiran sa pomoćnom klasom **`dynamicObject`** dobija **`entryTTL`** (odbrojavanje u sekundama) i **`msDS-Entry-Time-To-Die`** (apsolutni rok isteka). Kada `entryTTL` dostigne 0, **Garbage Collector ga briše bez tombstone/recycle-bin**, brišući informacije o kreatoru/vremenima i onemogućavajući oporavak.
- TTL se može osvežiti ažuriranjem `entryTTL`; min/default vrednosti se nameću u **Configuration\Services\NTDS Settings → `msDS-Other-Settings` → `DynamicObjectMinTTL` / `DynamicObjectDefaultTTL`** (podržava 1s–1g, ali često podrazumevano 86,400s/24h). Dinamički objekti su **neosnaženi u Configuration/Schema particijama**.
- Brisanje može zakasniti nekoliko minuta na DC-evima sa kratkim uptime-om (<24h), ostavljajući uzak prozor za upit/backup atributa. Detektujte to **alertovanjem na nove objekte koji nose `entryTTL`/`msDS-Entry-Time-To-Die`** i korelacijom sa orphan SIDs/broken linkovima.

## Evadiranje MAQ-a pomoću računara koji se sami brišu

- Podrazumevano **`ms-DS-MachineAccountQuota` = 10** dozvoljava bilo kom autentifikovanom korisniku da kreira računare. Dodajte `dynamicObject` tokom kreiranja da bi računar sam sebe obrisao i **oslobađajući MAQ slot** dok briše dokaze.
- Powermad tweak unutar `New-MachineAccount` (lista objectClass):
```powershell
$request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
```
- Kratak TTL (npr. 60s) često ne uspeva za standardne korisnike; AD pada na **`DynamicObjectDefaultTTL`** (primer: 86,400s). ADUC može sakriti `entryTTL`, ali LDP/LDAP upiti ga otkrivaju.

## Prikriveno članstvo u primarnoj grupi

- Kreirajte **dinamičku security grupu**, zatim postavite `primaryGroupID` korisnika na RID te grupe da biste dobili efektivno članstvo koje **se ne pojavljuje u `memberOf`**, ali se poštuje u Kerberos/tokenima pristupa.
- Istek TTL-a **briše grupu uprkos zaštiti protiv brisanja primarne grupe**, ostavljajući korisnika sa korumpiranim `primaryGroupID` koji pokazuje na nepostojeći RID i bez tombstone-a za istragu kako je privilegija dodeljena.

## Zagađenje AdminSDHolder sa orphan SID-ovima

- Dodajte ACE-e za **kratkotrajnog dinamičkog korisnika/grupu** u **`CN=AdminSDHolder,CN=System,...`**. Nakon isteka TTL-a SID postaje **nerazrešiv (“Unknown SID”)** u predlošku ACL-a, i **SDProp (~60 min)** propagira taj orphan SID preko svih zaštićenih Tier-0 objekata.
- Forenzika gubi atribuciju zato što akter ne postoji (nema deleted-object DN). Monitorujte za **nove dynamic principe + nagle orphan SID-ove na AdminSDHolder/privileged ACL-ovima**.

## Dinamičko izvršavanje GPO sa samouništavajućim dokazima

- Kreirajte **dinamički `groupPolicyContainer`** objekat sa malicioznim **`gPCFileSysPath`** (npr. SMB share kao GPODDITY) i **linkujte ga preko `gPLink`** na ciljani OU.
- Klijenti obrađuju politiku i vuku sadržaj sa attacker SMB-a. Kada TTL istekne, GPO objekat (i `gPCFileSysPath`) nestaje; ostaje samo **pokidan `gPLink`** GUID, uklanjajući LDAP dokaze izvršenog payload-a.

## Kratkotrajno AD-integrisano DNS preusmeravanje

- AD DNS zapisi su **`dnsNode`** objekti u **DomainDnsZones/ForestDnsZones**. Kreiranjem kao **dynamic objects** omogućava se privremeno preusmeravanje hosta (credential capture/MITM). Klijenti keširaju maliciozni A/AAAA odgovor; zapis se kasnije samobriše pa zona izgleda čisto (DNS Manager može zahtevati reload zone da osveži prikaz).
- Detekcija: alertujte na **bilo koji DNS zapis koji nosi `dynamicObject`/`entryTTL`** preko replike/događaja; tranzijentni zapisi retko se pojavljuju u standardnim DNS logovima.

## Rupa u delta-sinhronizaciji hibridnog Entra ID (Napomena)

- Entra Connect delta sync se oslanja na **tombstone-e** da detektuje brisanja. **Dynamic on-prem user** može sinhronizovati se u Entra ID, isteći i obrisati bez tombstone-a — delta sync neće ukloniti cloud nalog, ostavljajući **siročad aktivnog Entra korisnika** dok se ne pokrene ručni **full sync**.

## References

- [Dynamic Objects in Active Directory: The Stealthy Threat](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)

{{#include ../../banners/hacktricks-training.md}}
