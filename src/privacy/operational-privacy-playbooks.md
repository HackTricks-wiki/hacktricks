# Operativni playbook-ovi za privatnost

Ovi playbook-ovi objedinjuju kontrole iz ostatka ovog odeljka. Oni su polazne tačke, a ne garancije: ažurirajte model pretnji svaki put kada novi posmatrač, nalog, uređaj, lokacija, plaćanje, fajl ili druga strana uđe u workflow.

## Univerzalna provera pre početka

1. Zapišite legitimni cilj i šta mora ostati privatno **od koga**.
2. Zabeležite identitete, uređaje, mreže, naloge, payment rail-ove, druge strane, fizičke lokacije i podatke koje će aktivnost obuhvatiti.
3. Identifikujte najjačeg verovatnog posmatrača i posledicu neuspeha.
4. Potvrdite ovlašćenje, primenljivi zakon, uslove provajdera i organizacionu politiku.
5. Odlučite šta interno mora ostati pripisivo radi bezbednosti, odgovora na incidente, računovodstva i revizije.
6. Izaberite najmanji funkcionalni compartment; pre upotrebe uspostavite njegove putanje za oporavak i gašenje.
7. Testirajte compartment protiv kontrolisanog servisa, uključujući IP/DNS/IPv6, identitet browser-a, metadata dokumenata, payment statement i curenje obaveštenja.

Koristite detaljni model u [Threat Modeling and Identity Separation](threat-modeling-and-identity-separation.md).

## Osnovni nivo svakodnevne privatnosti

Cilj: smanjiti komercijalno praćenje, preuzimanje naloga i nepotrebnu izloženost bez pokušaja da postanete anonimni.

- Koristite održavan OS sa full-disk encryption-om, automatskim ažuriranjima, zaključavanjem ekrana i secure boot-om gde je dostupan.
- Najpre podesite password manager, recovery email i phishing-resistant MFA/security keys.
- Proverite dozvole aplikacija, istoriju lokacije, advertising identifiers, cloud sync i konekcije sa nalozima trećih strana.
- Koristite mainstream browser sa malo ekstenzija, tracking protection-om, HTTPS-om i odvojenim profilima za poslovno/privatno/high-risk browsing.
- Koristite private relay aliases ili različite email adrese po odnosu; nemojte koristiti lični broj telefona kada je samo opcionalan.
- Prednost dajte end-to-end encrypted messaging-u za sadržaj, uz podsećanje da učesnici, vreme, grupe i endpoint-i ostaju metadata.
- Namerno uklonite metadata iz fajlova i pregledajte eksportovanu kopiju — ne original — pre objavljivanja.
- Koristite virtual-card ili wallet tokene za compartmentalization payment credentials; nemojte ih nazivati anonimnim.
- Napravite backup enkriptovanog materijala za oporavak i testirajte restauraciju.

## Pseudonimno objavljivanje

Cilj: sprečiti da čitaoci i platforme trivijalno povežu publikaciju sa građanskim identitetom. Ovo ne zaustavlja sposobnu ciljanu istragu.

1. Definišite da li su platforma, hosting provajder, čitaoci, kontakti, lokalna mreža, payment provajder ili pravni postupak deo modela pretnji.
2. Kreirajte namenski endpoint/account context iz čistog baseline-a. Isključite personal browser sync, cloud documents, upload kontakata i preglede obaveštenja.
3. Kreirajte pseudonimni nalog kroz izabrani network compartment. Nemojte ponovo koristiti korisnička imena, avatare, recovery kanale, writing boilerplate ili prijavu preko ličnog identity-provider-a.
4. Koristite Tor Browser kada je unlinkability odredišta važnija od brzine; nemojte dodavati ekstenzije, značajno menjati veličinu/podešavanja ili otvarati preuzete dokumente dok ste online u običnoj desktop sesiji.
5. Pišite uz proces koji ne ugrađuje lična imena template-a, autore revizija, putanje štampača, GPS/EXIF, thumbnails ili skrivene layers. Eksportujte kopiju i pregledajte je odgovarajućim metadata alatima.
6. Proverite sadržaj na činjenice koje otkrivaju identitet: jedinstvene datume, detalje o radnom mestu, lokalno vreme/vremensku zonu, odraze, pozadinski audio, lingvističke navike i ponovnu upotrebu teksta iz ranijih publikacija.
7. Koristite odvojeni reply kanal. Svaki direktni kontakt, attachment i link tretirajte kao potencijalni pokušaj korelacije ili phishing-a.
8. Ako je uključen novac, koristite zakonit metod koji otkriva samo neophodne podatke. Pretpostavite da platforma i regulisani posrednik mogu znati primaoca plaćanja čak i ako čitaoci ne znaju.
9. Objavite, a zatim pregledajte javni rezultat iz drugog čistog context-a. Zabeležite šta je platforma dodala ili izmenila.
10. Održavajte planiranu učestalost samo ako ne stvara stabilan behavioral fingerprint; ugasite compartment umesto da ga neprimetno prenamenite.

Za ozbiljno novinarstvo, activism, domestic abuse ili rizik na nivou države, potražite prilagođenu pomoć iskusne organizacije za digitalnu bezbednost; statična checklista ne može modelovati lokalni zakon ili aktivnog protivnika.

## Ovlašćeni red-team angažman

Cilj: držati lične identitete operatora i kućne mreže van telemetry-ja cilja, uz očuvanje ovlašćenja, kontrole i odgovora na incidente.

### Pre početnog prozora

- Završite ROE infrastructure annex, ciljeve/isključenja, source ranges, datume, emergency stop i dozvole trećih strana/provajdera.
- Dodelite namenski operator profile ili VM, engagement secrets, evidence store, cloud project, domene i budžet.
- Prednost dajte client-provided egress-u ili fiksnom bastionu pod kontrolom organizacije. Testirajte full-tunnel IPv4/IPv6/DNS ponašanje i fail-closed policy.
- Čuvajte mapiranje operatora na javnu infrastrukturu kod exercise controller-a ili dogovorenog escrow kontakta.
- Uspostavite rate limits, destination allowlists i odvojeno odobrenje za destruktivne, wireless, fizičke, phishing ili credential-collection akcije.
- Koristite payment rail pod kontrolom organizacije i interno evidentirajte odobrenja.

### Tokom angažmana

- Počnite sa odobrenog endpoint-a i tunnel-a; proverite posmatrani egress pre assessment saobraćaja.
- Lične naloge, uređaje, brojeve telefona, repozitorijume, SSH/GPG ključeve i cloud sync držite van compartment-a.
- Logujte operator/job, početak/kraj, source, scoped destination i promenu konfiguracije bez prikupljanja nepotrebnog sadržaja klijenta.
- Zaustavite se kod nejasnog scope-a, neočekivanih sistema trećih strana, provider abuse notification-a, bezbednosnog uticaja, gubitka opreme ili gubitka kontakta sa controller-om.
- Nikada nemojte improvizovati korišćenjem Wi-Fi mreže komšije, ukradenih credentials-a, neodobrenog SIM/account-a ili hardware-a sakrivenog na lokaciji.

### Kraj angažmana

- Zaustavite job-ove i C2; vratite odobrene drop uređaje; opozovite tokene, credentials i certificates.
- Uskladite infrastrukturu, domene, source adrese, troškove, podatke i slučajeve kod provajdera sa inventarom.
- Vratite/obrišite/zadržite podatke klijenta u skladu sa ugovorom, sačuvajte minimum potrebnih audit dokaza i prepustite drugom operatoru proveru gašenja.

Pogledajte [Authorized Red-Team Infrastructure](authorized-red-team-infrastructure.md) za kompletan vodič za izgradnju i uklanjanje.

## Zakonita privatna kupovina ili donacija

Cilj: smanjiti otkrivanje podataka trgovcu ili javnosti uz ispunjavanje obaveza prema izdavaocu, računovodstvu, poreskim organima i sankcijama.

1. Navedite ko ne sme saznati šta: javna publika, trgovac, payment intermediary, delegat employer/family account-a, delivery service ili blockchain observer.
2. Proverite lokalna pravila, primaoca/drugu stranu, uslove provajdera, cash limite i potrebe za vođenjem evidencije.
3. Izaberite rail:
- gotovina za prihvaćena zakonita lokalna plaćanja bez zapisa payment network-a;
- regulisana virtual/merchant-specific kartica za online credential separation;
- cryptocurrency tek nakon analize acquisition-a, ledger-a, wallet backend-a, network-a, druge strane i veza sa kasnijom potrošnjom.
4. Koristite istinite zahtevane podatke i izostavite samo opcione loyalty/marketing informacije. Nemojte koristiti identitet/adresu druge osobe niti deliti transakciju oko praga.
5. Odvojite merchant browser/account context i izbegavajte nepovezani social login, loyalty ili lične recovery kanale.
6. Potvrdite šta se pojavljuje na statement-ima, računima, obaveštenjima, isporuci i javnim listama donatora.
7. Obavezne receipt/tax/authorization dokaze čuvajte enkriptovano; opozovite jednokratne payment credentials nakon isteka perioda za refund.

Pogledajte [Private Digital Payments](private-digital-payments.md) i [Cryptocurrency Privacy](cryptocurrency-privacy.md).

## Putovanja i nepouzdane mreže

Cilj: zaštititi podatke i naloge na mrežama kojima korisnik ne upravlja — ne prikriti neovlašćenu aktivnost.

- Ažurirajte uređaje i pre putovanja preuzmite potrebne credentials/maps.
- Smanjite količinu sačuvanih podataka; koristite full-disk encryption, snažno otključavanje, planiranje daljinskog oporavka i procedure za isključen uređaj pri prelasku granice/fizičkom riziku, u skladu sa pravnim savetom.
- Proverite venue SSID/captive portal. Kada je prikladno, prednost dajte ličnom hotspot-u, ali imajte na umu subscriber i location records mobilnog operatera.
- Koristite full/forced approved VPN za organizacione podatke; proverite da ga tethered uređaji dele i testirajte IPv6/DNS ponašanje.
- Koristite travel router radi client isolation-a i ponovljive policy konfiguracije, a ne kao garanciju anonimnosti.
- Javno USB punjenje, pozajmljene računare, javne štampače i zajedničke sisteme u salama za sastanke tretirajte kao odvojene pretnje.
- Pretpostavite da fizičko prisustvo, radio identifikatori, portal login, kamere i payment/location records mogu povezati posetu.

Detalji poređenja i podešavanja nalaze se u [Network Privacy and Anonymous Connectivity](network-privacy-and-anonymous-connectivity.md).

## Odgovor na neuspeh i izloženost

Kada compartment ima leak ili može biti povezan:

1. Zaustavite aktivnost ako nastavak povećava štetu; tamo gde je primenljivo, koristite engagement emergency stop.
2. Sačuvajte neophodne dokaze bez širenja osetljivih podataka. Zabeležite tačno vreme, uočeni indikator i pogođene assets.
3. Obavestite odgovarajućeg vlasnika/controller-a/security kontakt. Nemojte skrivati incident radi očuvanja narativa o privatnosti.
4. Opozovite sesije, tokene, payment credentials i pristup infrastrukturi; rotirajte secrets sa poznato čistog endpoint-a.
5. Utvrdite koje su ivice povezale elemente: endpoint, account recovery, network, payment, metadata, content, behavior, counterparty ili physical presence.
6. Ceo pogođeni compartment tretirajte kao burned. Nemojte samo promeniti njegovo korisničko ime ili izlazni IP.
7. Ispunite obaveze obaveštavanja o breach-u, prema provajderu, klijentu, finansijskim i pravnim obavezama.
8. Ponovo izgradite sistem tek nakon izmene procesa koji je izazvao povezivanje; dokumentujte kontrolu i testirajte je.

## Periodična revizija

- [ ] Model pretnji i pravne pretpostavke/pretpostavke provajdera pregledaju se prema utvrđenom rasporedu.
- [ ] Uređaji, nalozi, aliases, domeni, network paths i payment credentials popisani su u inventaru.
- [ ] Recovery paths ne prelaze neočekivano između compartment-a.
- [ ] Full-tunnel, DNS, IPv6 i fail-closed ponašanje su testirani.
- [ ] Javni fajlovi i profili provereni su na metadata/content reuse.
- [ ] Wallet nodes/backends i pretpostavke crypto protokola ostaju ažurni.
- [ ] Logovi i računi su minimalni, enkriptovani, sa kontrolisanim pristupom i u okviru perioda čuvanja.
- [ ] Stari compartment-i i engagement infrastruktura potpuno su ugašeni.
