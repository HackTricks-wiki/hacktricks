# BloodHound & Other AD Enum Tools

{{#include ../../banners/hacktricks-training.md}}

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) je iz Sysinternal Suite:

> Napredni preglednik i uređivač Active Directory (AD). Možete koristiti AD Explorer za lako navigiranje AD bazom podataka, definisanje omiljenih lokacija, pregled svojstava objekata i atributa bez otvaranja dijaloga, uređivanje dozvola, pregled sheme objekta i izvršavanje složenih pretraga koje možete sačuvati i ponovo izvršiti.

### Snapshots

AD Explorer može kreirati snimke AD-a kako biste mogli da ga proverite offline.\
Može se koristiti za otkrivanje ranjivosti offline ili za upoređivanje različitih stanja AD DB-a tokom vremena.

Biće vam potrebni korisničko ime, lozinka i pravac za povezivanje (bilo koji AD korisnik je potreban).

Da biste napravili snimak AD-a, idite na `File` --> `Create Snapshot` i unesite ime za snimak.

## ADRecon

[**ADRecon**](https://github.com/adrecon/ADRecon) je alat koji izvlači i kombinuje razne artefakte iz AD okruženja. Informacije se mogu predstaviti u **posebno formatiranom** Microsoft Excel **izveštaju** koji uključuje sažetke sa metrikama kako bi olakšao analizu i pružio celovitu sliku trenutnog stanja ciljnog AD okruženja.
```bash
# Run it
.\ADRecon.ps1
```
## BloodHound

From [https://github.com/BloodHoundAD/BloodHound](https://github.com/BloodHoundAD/BloodHound)

> BloodHound je jednostavna Javascript web aplikacija, izgrađena na [Linkurious](http://linkurio.us/), kompajlirana sa [Electron](http://electron.atom.io/), sa [Neo4j](https://neo4j.com/) bazom podataka koju napaja C# sakupljač podataka.

BloodHound koristi teoriju grafova da otkrije skrivene i često nenamerne odnose unutar Active Directory ili Azure okruženja. Napadači mogu koristiti BloodHound da lako identifikuju veoma složene puteve napada koji bi inače bili nemogući za brzo identifikovanje. Branitelji mogu koristiti BloodHound da identifikuju i eliminišu iste te puteve napada. I plave i crvene ekipe mogu koristiti BloodHound da lako steknu dublje razumevanje odnosa privilegija u Active Directory ili Azure okruženju.

Dakle, [Bloodhound ](https://github.com/BloodHoundAD/BloodHound) je neverovatan alat koji može automatski enumerisati domen, sačuvati sve informacije, pronaći moguće puteve za eskalaciju privilegija i prikazati sve informacije koristeći grafove.

Booldhound se sastoji od 2 glavna dela: **ingestors** i **aplikacija za vizualizaciju**.

**Ingestors** se koriste za **enumerisanje domena i ekstrakciju svih informacija** u formatu koji aplikacija za vizualizaciju može razumeti.

**Aplikacija za vizualizaciju koristi neo4j** da prikaže kako su sve informacije povezane i da pokaže različite načine za eskalaciju privilegija u domenu.

### Instalacija

Nakon kreiranja BloodHound CE, ceo projekat je ažuriran radi lakšeg korišćenja sa Docker-om. Najlakši način da se započne je korišćenje njegove unapred konfigurirane Docker Compose konfiguracije.

1. Instalirajte Docker Compose. Ovo bi trebalo da bude uključeno u [Docker Desktop](https://www.docker.com/products/docker-desktop/) instalaciju.
2. Pokrenite:
```
curl -L https://ghst.ly/getbhce | docker compose -f - up
```
3. Pronađite nasumično generisanu lozinku u izlazu terminala Docker Compose.  
4. U pretraživaču idite na http://localhost:8080/ui/login. Prijavite se sa korisničkim imenom admin i nasumično generisanom lozinkom iz logova.  

Nakon toga, moraćete da promenite nasumično generisanu lozinku i bićete spremni sa novim interfejsom, iz kojeg možete direktno preuzeti ingestor-e.  

### SharpHound  

Imaju nekoliko opcija, ali ako želite da pokrenete SharpHound sa PC-a koji je pridružen domeni, koristeći svog trenutnog korisnika i izvučete sve informacije, možete to učiniti:
```
./SharpHound.exe --CollectionMethods All
Invoke-BloodHound -CollectionMethod All
```
> Možete pročitati više o **CollectionMethod** i loop sesiji [ovde](https://support.bloodhoundenterprise.io/hc/en-us/articles/17481375424795-All-SharpHound-Community-Edition-Flags-Explained)

Ako želite da izvršite SharpHound koristeći različite akreditive, možete kreirati CMD netonly sesiju i pokrenuti SharpHound odatle:
```
runas /netonly /user:domain\user "powershell.exe -exec bypass"
```
[**Saznajte više o Bloodhound-u na ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-with-bloodhound-on-kali-linux)

## Group3r

[**Group3r**](https://github.com/Group3r/Group3r) je alat za pronalaženje **ranjivosti** u Active Directory-ju povezanih sa **Group Policy**. \
Morate **pokrenuti group3r** sa hosta unutar domena koristeći **bilo kog korisnika domena**.
```bash
group3r.exe -f <filepath-name.log>
# -s sends results to stdin
# -f send results to file
```
## PingCastle

[**PingCastle**](https://www.pingcastle.com/documentation/) **procjenjuje bezbednosni položaj AD okruženja** i pruža lep **izveštaj** sa grafikonima.

Da biste ga pokrenuli, možete izvršiti binarni fajl `PingCastle.exe` i započeće **interaktivnu sesiju** koja prikazuje meni opcija. Podrazumevana opcija koju treba koristiti je **`healthcheck`** koja će uspostaviti osnovnu **pregled** **domena**, i pronaći **neispravne konfiguracije** i **ranjivosti**.&#x20;

{{#include ../../banners/hacktricks-training.md}}
