# ACLs - DACLs/SACLs/ACEs

{{#include ../../banners/hacktricks-training.md}}

## **Access Control List (ACL)**

Access Control List (ACL) sastoji se od uređenog skupa Access Control Entries (ACE) koje određuju zaštitu objekta i njegovih svojstava. U suštini, ACL definiše koje radnje bezbednosni principi (korisnici ili grupe) mogu ili ne mogu da izvrše nad datim objektom.

Postoje dve vrste ACL-a:

- **Discretionary Access Control List (DACL):** Određuje koji korisnici i grupe imaju ili nemaju pristup objektu.
- **System Access Control List (SACL):** Uređuje reviziju pokušaja pristupa objektu.

Prilikom pristupa datoteci, sistem proverava bezbednosni deskriptor objekta u odnosu na korisnikov access token da bi utvrdio da li pristup treba odobriti i u kom obimu, na osnovu ACE-ova.<sup>[[1]](#references)</sup>

Kada nadređeni direktorijum daje Full Control, ali podređena datoteka zabranjuje čitanje, zasebno proverite efektivni DACL, vlasnika i nasleđivanje **podređene datoteke**. Za izmenu DACL-a te datoteke potreban je `WRITE_DAC` nad datotekom ili odgovarajuće pravo vlasnika; [Microsoft definiše `WRITE_DAC`](https://learn.microsoft.com/en-us/windows/win32/secauthz/standard-access-rights) i [dokumentuje implicitni pristup vlasnika](https://learn.microsoft.com/en-us/windows/win32/secauthz/owner-of-a-new-object). Dozvole nadređenog direktorijuma same po sebi ne znače da se podređena datoteka može čitati niti da se njen DACL može izmeniti.

### **Key Components**

- **DACL:** Sadrži ACE-ove koji korisnicima i grupama odobravaju ili uskraćuju dozvole za pristup objektu. To je, u suštini, glavni ACL koji određuje prava pristupa.
- **SACL:** Koristi se za reviziju pristupa objektima; ACE-ovi određuju koje vrste pristupa se beleže u Security Event Log. Ovo može biti veoma korisno za otkrivanje neovlašćenih pokušaja pristupa ili rešavanje problema sa pristupom.<sup>[[1]](#references)</sup>

### **System Interaction with ACLs**

Svaka korisnička sesija povezana je sa access token-om koji sadrži bezbednosne informacije relevantne za tu sesiju, uključujući identitete korisnika i grupa, kao i privilegije. Ovaj token sadrži i logon SID koji jedinstveno identifikuje sesiju.

Local Security Authority (LSASS) obrađuje zahteve za pristup objektima tako što proverava DACL da bi pronašao ACE-ove koji odgovaraju bezbednosnom principu koji pokušava da pristupi objektu. Pristup se odmah odobrava ako nisu pronađeni odgovarajući ACE-ovi. U suprotnom, LSASS upoređuje ACE-ove sa SID-om bezbednosnog principa u access token-u da bi utvrdio da li je pristup dozvoljen.<sup>[[1]](#references)</sup>

### **Summarized Process**

- **ACLs:** Definišu dozvole za pristup putem DACL-ova i pravila revizije putem SACL-ova.
- **Access Token:** Sadrži informacije o korisniku, grupama i privilegijama za sesiju.
- **Access Decision:** Donosi se poređenjem DACL ACE-ova sa access token-om; SACL-ovi se koriste za reviziju.<sup>[[1]](#references)</sup>

### ACEs

Postoje **tri glavne vrste Access Control Entries (ACE)**:<sup>[[1]](#references)</sup>

- **Access Denied ACE**: Ovaj ACE izričito uskraćuje pristup objektu navedenim korisnicima ili grupama (u DACL-u).
- **Access Allowed ACE**: Ovaj ACE izričito odobrava pristup objektu navedenim korisnicima ili grupama (u DACL-u).
- **System Audit ACE**: Ovaj ACE, smešten u System Access Control List (SACL), generiše zapise revizije kada korisnici ili grupe pokušaju da pristupe objektu. Beleži da li je pristup odobren ili uskraćen i vrstu pristupa.

Svaki ACE ima **četiri ključne komponente**:<sup>[[1]](#references)</sup>

1. **Security Identifier (SID)** korisnika ili grupe (ili naziv principala u grafičkom prikazu).
2. **Oznaku** koja određuje tip ACE-a (pristup uskraćen, dozvoljen ili revizija sistema).
3. **Oznake nasleđivanja** koje određuju da li podređeni objekti mogu da naslede ACE od nadređenog objekta.
4. [**Access mask**](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b?redirectedfrom=MSDN), 32-bitnu vrednost koja određuje prava dodeljena nad objektom.

Pristup se utvrđuje uzastopnim pregledanjem svakog ACE-a dok se ne ispuni jedan od sledećih uslova:<sup>[[1]](#references)</sup>

- **Access-Denied ACE** izričito uskraćuje tražena prava trustee-ju identifikovanom u access token-u.
- **Access-Allowed ACE-ovi** izričito odobravaju sva tražena prava trustee-ju u access token-u.
- Nakon provere svih ACE-ova, ako neko traženo pravo **nije izričito odobreno**, pristup se implicitno **uskraćuje**.

### Order of ACEs

Način na koji su **ACE-ovi** (pravila koja određuju ko može ili ne može da pristupi nečemu) poređani na listi zvanoj **DACL** veoma je važan. To je zato što sistem, nakon što na osnovu ovih pravila odobri ili uskrati pristup, prestaje da proverava ostala pravila.<sup>[[1]](#references)</sup>

Postoji najbolji način za organizovanje ovih ACE-ova, koji se naziva **„kanonski redosled“**. Ovaj način pomaže da sve funkcioniše glatko i dosledno. Evo kako to izgleda na sistemima kao što su **Windows 2000** i **Windows Server 2003**:

- Najpre stavite sva pravila koja su napravljena **posebno za ovaj objekat**, ispred onih koja potiču odnekud drugde, na primer iz nadređenog foldera.
- Među tim posebnim pravilima, pravila koja kažu **„ne“ (deny)** stavite pre onih koja kažu **„da“ (allow)**.
- Za pravila koja potiču odnekud drugde, počnite od onih iz **najbližeg izvora**, kao što je nadređeni objekat, pa nastavite dalje. Ponovo, pravila **„ne“** stavite pre pravila **„da“**.

Ovakva postavka ima dve važne prednosti:

- Obezbeđuje da se određeno **„ne“** poštuje, bez obzira na druga pravila **„da“**.
- Omogućava vlasniku objekta da **poslednji odlučuje** ko ima pristup, pre nego što se primene pravila iz nadređenih foldera ili udaljenijih izvora.

Tako vlasnik datoteke ili foldera može precizno da odredi ko ima pristup, da bi prave osobe mogle da pristupe, a pogrešne ne.

![Dijagram redosleda NTFS access control entry-ja](https://www.ntfs.com/images/screenshots/ACEs.gif)

Dakle, ovaj **„kanonski redosled“** služi tome da pravila pristupa budu jasna i funkcionalna: posebna pravila se stavljaju na početak, a ostala se organizuju na smislen način.

### GUI Example

[**Primer odavde**](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)<sup>[[2]](#references)</sup>

Ovo je klasična kartica za bezbednost foldera koja prikazuje ACL, DACL i ACE-ove:

![http://secureidentity.se/wp-content/uploads/2014/04/classicsectab.jpg](../../images/classicsectab.jpg)

Ako kliknemo na dugme **Advanced**, dobićemo dodatne opcije, kao što je nasleđivanje:

![http://secureidentity.se/wp-content/uploads/2014/04/aceinheritance.jpg](../../images/aceinheritance.jpg)

A ako dodamo ili izmenimo Security Principal:

![http://secureidentity.se/wp-content/uploads/2014/04/editseprincipalpointers1.jpg](../../images/editseprincipalpointers1.jpg)

Na kraju, tu je SACL na kartici Auditing:

![http://secureidentity.se/wp-content/uploads/2014/04/audit-tab.jpg](../../images/audit-tab.jpg)

### Explaining Access Control in a Simplified Manner

Kada upravljamo pristupom resursima, kao što je folder, koristimo liste i pravila poznata kao Access Control Lists (ACL) i Access Control Entries (ACE). Ona određuju ko može, a ko ne može da pristupi određenim podacima.<sup>[[1]](#references)</sup>

#### Uskraćivanje pristupa određenoj grupi

Zamislite da imate folder pod nazivom Cost i želite da svi osim marketinškog tima mogu da mu pristupe. Pravilnim podešavanjem pravila možemo obezbediti da se pristup marketinškom timu izričito uskrati pre nego što se pristup dozvoli svima ostalima. To se postiže postavljanjem pravila kojim se marketinškom timu uskraćuje pristup ispred pravila kojim se pristup dozvoljava svima.

#### Dozvoljavanje pristupa određenom članu grupe kojoj je pristup uskraćen

Pretpostavimo da Bob, direktor marketinga, mora da ima pristup folderu Cost, iako marketinški tim generalno ne bi trebalo da mu pristupa. Možemo dodati posebno pravilo (ACE) za Boba kojim mu se odobrava pristup i postaviti ga ispred pravila kojim se marketinškom timu uskraćuje pristup. Tako Bob dobija pristup uprkos opštem ograničenju za njegov tim.

#### Razumevanje Access Control Entries

ACE-ovi su pojedinačna pravila u ACL-u. Oni identifikuju korisnike ili grupe, određuju koji pristup je dozvoljen ili uskraćen i definišu kako se pravila primenjuju na podređene stavke (nasleđivanje). Postoje dve glavne vrste ACE-ova:

- **Generic ACEs**: Primenjuju se široko, tako da obuhvataju sve vrste objekata ili razlikuju samo kontejnere (kao što su folderi) od objekata koji nisu kontejneri (kao što su datoteke). Na primer, pravilo koje korisnicima dozvoljava da vide sadržaj foldera, ali ne i da pristupe datotekama u njemu.
- **Object-Specific ACEs**: Omogućavaju precizniju kontrolu, jer se pravila mogu podesiti za određene vrste objekata ili čak pojedinačna svojstva objekta. Na primer, u direktorijumu korisnika, pravilo može korisniku da dozvoli da ažurira svoj broj telefona, ali ne i svoje sate za prijavu.

Svaki ACE sadrži važne informacije, kao što su na koga se pravilo odnosi (pomoću Security Identifier-a ili SID-a), šta pravilo dozvoljava ili uskraćuje (pomoću access mask-a) i kako ga nasleđuju drugi objekti.

#### Ključne razlike između tipova ACE-a

- **Generic ACEs** su pogodni za jednostavne scenarije kontrole pristupa, gde se isto pravilo primenjuje na sve delove objekta ili na sve objekte u kontejneru.
- **Object-Specific ACEs** koriste se u složenijim scenarijima, naročito u okruženjima kao što je Active Directory, gde je možda potrebno različito kontrolisati pristup pojedinačnim svojstvima objekta.

Ukratko, ACL-ovi i ACE-ovi omogućavaju definisanje precizne kontrole pristupa, čime se obezbeđuje da samo odgovarajući pojedinci ili grupe mogu pristupiti osetljivim informacijama ili resursima. Prava pristupa mogu se prilagoditi sve do nivoa pojedinačnih svojstava ili tipova objekata.

### Access Control Entry Layout

| Polje ACE-a | Opis                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Tip         | Oznaka koja označava tip ACE-a. Windows 2000 i Windows Server 2003 podržavaju šest tipova ACE-a: tri generička tipa ACE-a koja se dodaju svim objektima koji mogu da se obezbede i tri tipa ACE-a specifična za objekte, koji se mogu pojaviti kod Active Directory objekata.                                                                                                                                                                                                                                  |
| Oznake      | Skup bit-oznaka koje upravljaju nasleđivanjem i revizijom.                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Veličina    | Broj bajtova memorije dodeljenih za ACE.                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Access mask | 32-bitna vrednost čiji bitovi odgovaraju pravima pristupa objektu. Bitovi mogu biti uključeni ili isključeni, ali značenje njihovih vrednosti zavisi od tipa ACE-a. Na primer, ako je uključen bit koji odgovara pravu za čitanje dozvola, a tip ACE-a je Deny, ACE uskraćuje pravo čitanja dozvola objekta. Ako je isti bit uključen, a tip ACE-a je Allow, ACE odobrava pravo čitanja dozvola objekta. Više detalja o Access mask-u dato je u sledećoj tabeli. |
| SID         | Identifikuje korisnika ili grupu čiji pristup ovaj ACE kontroliše ili prati.                                                                                                                                                                                                                                                                                                                                                                                                                                 |

### Access Mask Layout

| Bit (opseg) | Značenje                           | Opis/primer                                |
| ----------- | ---------------------------------- | ------------------------------------------ |
| 0 - 15      | Prava pristupa specifična za objekat | Čitanje podataka, izvršavanje, dodavanje podataka |
| 16 - 22     | Standardna prava pristupa          | Brisanje, upis ACL-a, upis vlasnika        |
| 23          | Može da pristupi bezbednosnom ACL-u |                                            |
| 24 - 27     | Rezervisano                        |                                            |
| 28          | Generic ALL (čitanje, upis, izvršavanje) | Sve navedeno ispod                     |
| 29          | Generic Execute                    | Sve što je potrebno za izvršavanje programa |
| 30          | Generic Write                      | Sve što je potrebno za upis u datoteku    |
| 31          | Generic Read                       | Sve što je potrebno za čitanje datoteke   |

## References

- [1] [Kako sistem koristi ACL-ove - NTFS.com](https://www.ntfs.com/ntfs-permissions-acl-use.htm)
- [2] [ACL, DACL, SACL i ACE - secureidentity.se](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)
{{#include ../../banners/hacktricks-training.md}}
