# ACLs - DACLs/SACLs/ACEs

{{#include ../../banners/hacktricks-training.md}}

## **Access Control List (ACL)**

Access Control List (ACL) sastoji se od uređenog skupa Access Control Entries (ACE) koje određuju zaštitu objekta i njegovih svojstava. U suštini, ACL definiše koje radnje koji bezbednosni subjekti (korisnici ili grupe) mogu ili ne mogu da izvrše nad određenim objektom.

Postoje dve vrste ACL-ova:

- **Discretionary Access Control List (DACL):** Navodi koji korisnici i grupe imaju ili nemaju pristup objektu.
- **System Access Control List (SACL):** Upravlja revizijom pokušaja pristupa objektu.

Proces pristupa datoteci podrazumeva da sistem proverava bezbednosni deskriptor objekta u odnosu na korisnikov access token kako bi utvrdio da li pristup treba odobriti i koji je njegov obim, na osnovu ACE-ova.<sup>[[1]](#references)</sup>

### **Ključne komponente**

- **DACL:** Sadrži ACE-ove koji korisnicima i grupama odobravaju ili uskraćuju dozvole pristupa objektu. To je u suštini glavni ACL koji određuje prava pristupa.
- **SACL:** Koristi se za reviziju pristupa objektima, pri čemu ACE-ovi definišu vrste pristupa koje treba evidentirati u Security Event Log-u. Ovo može biti veoma korisno za otkrivanje neovlašćenih pokušaja pristupa ili rešavanje problema sa pristupom.<sup>[[1]](#references)</sup>

### **Interakcija sistema sa ACL-ovima**

Svaka korisnička sesija povezana je sa access token-om koji sadrži bezbednosne informacije relevantne za tu sesiju, uključujući identitete korisnika i grupa, kao i privilegije. Ovaj token takođe sadrži logon SID koji jedinstveno identifikuje sesiju.

Local Security Authority (LSASS) obrađuje zahteve za pristup objektima tako što proverava DACL u potrazi za ACE-ovima koji odgovaraju bezbednosnom subjektu koji pokušava da pristupi objektu. Pristup se odmah odobrava ako nisu pronađeni relevantni ACE-ovi. U suprotnom, LSASS upoređuje ACE-ove sa SID-om bezbednosnog subjekta u access token-u kako bi utvrdio da li pristup može biti odobren.<sup>[[1]](#references)</sup>

### **Sažeti proces**

- **ACL-ovi:** Definišu dozvole pristupa putem DACL-ova i pravila revizije putem SACL-ova.
- **Access Token:** Sadrži informacije o korisniku, grupama i privilegijama za jednu sesiju.
- **Odluka o pristupu:** Donosi se poređenjem ACE-ova u DACL-u sa access token-om; SACL-ovi se koriste za reviziju.<sup>[[1]](#references)</sup>

### ACE-ovi

Postoje **tri glavne vrste Access Control Entries (ACE-ova)**:<sup>[[1]](#references)</sup>

- **Access Denied ACE**: Ovaj ACE eksplicitno uskraćuje pristup objektu određenim korisnicima ili grupama (u okviru DACL-a).
- **Access Allowed ACE**: Ovaj ACE eksplicitno odobrava pristup objektu određenim korisnicima ili grupama (u okviru DACL-a).
- **System Audit ACE**: Ovaj ACE, smešten u okviru System Access Control List-a (SACL), odgovoran je za generisanje audit logova prilikom pokušaja pristupa objektu od strane korisnika ili grupa. Beleži da li je pristup odobren ili odbijen, kao i prirodu pristupa.

Svaki ACE ima **četiri ključne komponente**:<sup>[[1]](#references)</sup>

1. **Security Identifier (SID)** korisnika ili grupe (ili njihov principal name u grafičkom prikazu).
2. **Zastavicu** koja identifikuje tip ACE-a (access denied, allowed ili system audit).
3. **Zastavice nasleđivanja** koje određuju da li child objekti mogu da naslede ACE od svog parent objekta.
4. [**Access mask**](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b?redirectedfrom=MSDN), 32-bitnu vrednost koja određuje odobrena prava nad objektom.

Utvrđivanje pristupa vrši se sekvencijalnim ispitivanjem svakog ACE-a sve dok:<sup>[[1]](#references)</sup>

- **Access-Denied ACE** eksplicitno ne uskrati zahtevana prava trustee-u identifikovanom u access token-u.
- Jedan ili više **Access-Allowed ACE-ova** eksplicitno ne odobre sva zahtevana prava trustee-u koji se nalazi u access token-u.
- Nakon provere svih ACE-ova, ako neko zahtevano pravo nije eksplicitno odobreno, pristup se implicitno **uskraćuje**.

### Redosled ACE-ova

Način na koji su **ACE-ovi** (pravila koja određuju ko može ili ne može da pristupi nečemu) raspoređeni u listi koja se naziva **DACL** veoma je važan. Kada sistem na osnovu ovih pravila odobri ili odbije pristup, prestaje da proverava ostatak liste.<sup>[[1]](#references)</sup>

Postoji najbolji način za organizovanje ovih ACE-ova, koji se naziva **„canonical order“**. Ovaj metod pomaže da sve funkcioniše pravilno i predvidljivo. Za sisteme kao što su **Windows 2000** i **Windows Server 2003**, redosled je sledeći:

- Najpre postavite sva pravila koja su napravljena **posebno za ovu stavku**, a zatim pravila koja dolaze iz nekog drugog izvora, kao što je parent folder.
- Među tim specifičnim pravilima, pravila koja kažu **„ne“ (deny)** postavite pre pravila koja kažu **„da“ (allow)**.
- Kod pravila koja dolaze iz drugog izvora, prvo postavite pravila iz **najbližeg izvora**, kao što je parent, a zatim nastavite prema udaljenijim izvorima. I ovde pravila **„ne“** treba postaviti pre pravila **„da“**.

Ovakva postavka ima dve velike prednosti:

- Obezbeđuje da se konkretno pravilo **„ne“** poštuje bez obzira na to koja druga pravila **„da“** postoje.
- Omogućava vlasniku stavke da poslednji odluči ko dobija pristup, pre nego što na snagu stupe pravila iz parent foldera ili udaljenijih izvora.

Na ovaj način vlasnik datoteke ili foldera može veoma precizno da odredi ko dobija pristup, obezbeđujući da odgovarajuće osobe mogu da pristupe, a neodgovarajuće ne mogu.

![Dijagram redosleda NTFS access control entry-ja](https://www.ntfs.com/images/screenshots/ACEs.gif)

Dakle, **„canonical order“** služi tome da pravila pristupa budu jasna i pravilno funkcionišu, tako što se specifična pravila postavljaju prva i sve organizuje na promišljen način.

### GUI primer

[**Primer odavde**](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)<sup>[[2]](#references)</sup>

Ovo je klasična security kartica foldera koja prikazuje ACL, DACL i ACE-ove:

![http://secureidentity.se/wp-content/uploads/2014/04/classicsectab.jpg](../../images/classicsectab.jpg)

Ako kliknemo na **Advanced dugme**, dobićemo više opcija, kao što je nasleđivanje:

![http://secureidentity.se/wp-content/uploads/2014/04/aceinheritance.jpg](../../images/aceinheritance.jpg)

A ako dodate ili izmenite Security Principal:

![http://secureidentity.se/wp-content/uploads/2014/04/editseprincipalpointers1.jpg](../../images/editseprincipalpointers1.jpg)

Na kraju imamo SACL u Auditing kartici:

![http://secureidentity.se/wp-content/uploads/2014/04/audit-tab.jpg](../../images/audit-tab.jpg)

### Objašnjenje Access Control-a na pojednostavljen način

Prilikom upravljanja pristupom resursima, kao što je folder, koristimo liste i pravila poznata kao Access Control Lists (ACL-ovi) i Access Control Entries (ACE-ovi). Ona određuju ko može, a ko ne može da pristupi određenim podacima.<sup>[[1]](#references)</sup>

#### Uskraćivanje pristupa određenoj grupi

Zamislite da imate folder pod nazivom Cost i želite da svi mogu da mu pristupe osim marketing tima. Pravilnim podešavanjem pravila možemo obezbediti da marketing timu pristup bude eksplicitno uskraćen pre nego što se pristup odobri svima ostalima. To se postiže postavljanjem pravila koje uskraćuje pristup marketing timu pre pravila koje odobrava pristup svima.

#### Omogućavanje pristupa određenom članu grupe kojoj je pristup uskraćen

Recimo da Bob, direktor marketinga, treba da pristupi folderu Cost, iako marketing tim uopšteno ne bi trebalo da ima pristup. Možemo dodati posebno pravilo (ACE) za Boba koje mu odobrava pristup i postaviti ga pre pravila koje uskraćuje pristup marketing timu. Na taj način Bob dobija pristup uprkos opštem ograničenju za njegov tim.

#### Razumevanje Access Control Entry-ja

ACE-ovi su pojedinačna pravila u okviru ACL-a. Oni identifikuju korisnike ili grupe, određuju koji pristup je dozvoljen ili zabranjen i utvrđuju kako se ova pravila primenjuju na podstavke (nasleđivanje). Postoje dve glavne vrste ACE-ova:

- **Generic ACE-ovi**: Primenjuju se široko, tako što obuhvataju sve vrste objekata ili razlikuju samo containere (kao što su folderi) od objekata koji nisu containere (kao što su datoteke). Na primer, pravilo koje korisnicima omogućava da vide sadržaj foldera, ali ne i da pristupe datotekama unutar njega.
- **Object-Specific ACE-ovi**: Omogućavaju precizniju kontrolu, tako što se pravila mogu podesiti za određene vrste objekata ili čak pojedinačna svojstva unutar objekta. Na primer, u direktorijumu korisnika pravilo može korisniku dozvoliti da izmeni svoj broj telefona, ali ne i svoje login hours.

Svaki ACE sadrži važne informacije, kao što su na koga se pravilo odnosi (korišćenjem Security Identifier-a ili SID-a), šta pravilo dozvoljava ili uskraćuje (korišćenjem access mask-e) i kako ga drugi objekti nasleđuju.

#### Ključne razlike između tipova ACE-ova

- **Generic ACE-ovi** su pogodni za jednostavne scenarije kontrole pristupa, u kojima se isto pravilo primenjuje na sve aspekte objekta ili na sve objekte unutar containera.
- **Object-Specific ACE-ovi** koriste se za složenije scenarije, naročito u okruženjima kao što je Active Directory, gde može biti potrebno različito kontrolisati pristup određenim svojstvima objekta.

Ukratko, ACL-ovi i ACE-ovi pomažu u definisanju preciznih kontrola pristupa, obezbeđujući da samo odgovarajuće osobe ili grupe imaju pristup osetljivim informacijama ili resursima, uz mogućnost podešavanja prava pristupa sve do nivoa pojedinačnih svojstava ili tipova objekata.

### Raspored Access Control Entry-ja

| ACE polje   | Opis                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Tip        | Zastavica koja označava tip ACE-a. Windows 2000 i Windows Server 2003 podržavaju šest tipova ACE-ova: tri generička tipa ACE-ova koji se pridružuju svim objektima nad kojima se može primeniti zaštita i tri object-specific tipa ACE-ova koji se mogu pojaviti kod Active Directory objekata.                                                                                                                                                                                                                                                            |
| Zastavice       | Skup bit zastavica koje kontrolišu nasleđivanje i reviziju.                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Veličina        | Broj bajtova memorije alociranih za ACE.                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Access maska | 32-bitna vrednost čiji bitovi odgovaraju pravima pristupa objektu. Bitovi mogu biti uključeni ili isključeni, ali značenje podešavanja zavisi od tipa ACE-a. Na primer, ako je bit koji odgovara pravu za čitanje dozvola uključen, a tip ACE-a je Deny, ACE uskraćuje pravo čitanja dozvola objekta. Ako je isti bit uključen, ali je tip ACE-a Allow, ACE odobrava pravo čitanja dozvola objekta. Više detalja o Access mask-i nalazi se u sledećoj tabeli. |
| SID         | Identifikuje korisnika ili grupu čiji se pristup kontroliše ili nadgleda ovim ACE-om.                                                                                                                                                                                                                                                                                                                                                                                                                                 |

### Raspored Access mask-e

| Bit (opseg) | Značenje                            | Opis/primer                       |
| ----------- | ---------------------------------- | ----------------------------------------- |
| 0 - 15      | Object Specific Access Rights      | Čitanje podataka, izvršavanje, dodavanje podataka           |
| 16 - 22     | Standard Access Rights             | Brisanje, upis ACL-a, upis vlasnika            |
| 23          | Može da pristupi security ACL-u            |                                           |
| 24 - 27     | Rezervisano                           |                                           |
| 28          | Generic ALL (čitanje, upis, izvršavanje) | Sve navedeno ispod                          |
| 29          | Generic Execute                    | Sve što je potrebno za izvršavanje programa |
| 30          | Generic Write                      | Sve što je potrebno za upis u datoteku   |
| 31          | Generic Read                       | Sve što je potrebno za čitanje datoteke       |

## References

- [1] [How the System Uses ACLs - NTFS.com](https://www.ntfs.com/ntfs-permissions-acl-use.htm)
- [2] [ACL, DACL, SACL and the ACE - secureidentity.se](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)

{{#include ../../banners/hacktricks-training.md}}
