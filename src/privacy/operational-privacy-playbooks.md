# Priručnici za operativnu privatnost

{{#include ../banners/hacktricks-training.md}}

Ovi priručnici objedinjuju kontrole iz ostatka ovog odeljka. Oni predstavljaju početne tačke, a ne garancije: ažurirajte model pretnji svaki put kada u workflow uđe novi posmatrač, nalog, uređaj, lokacija, plaćanje, fajl ili druga strana.

## Univerzalna provera pre početka

1. Zapišite legitimni cilj i šta mora ostati privatno **od koga**.
2. Evidentirajte identitete, uređaje, mreže, naloge, payment rails, druge strane, fizičke lokacije i podatke koje će aktivnost obuhvatiti.
3. Identifikujte najjačeg verovatnog posmatrača i posledicu neuspeha.
4. Potvrdite ovlašćenje, primenljivo pravo, uslove provajdera i organizacionu politiku.
5. Odlučite šta interno mora ostati povezivo sa identitetom radi bezbednosti, odgovora na incidente, računovodstva i audita.
6. Izaberite najmanji funkcionalni compartment; pre upotrebe utvrdite načine njegovog oporavka i gašenja.
7. Testirajte compartment protiv kontrolisanog servisa, uključujući IP/DNS/IPv6, identitet browsera, metadata dokumenata, izvod plaćanja i curenje obaveštenja.

Koristite detaljni model u [Modeliranje pretnji i razdvajanje identiteta](threat-modeling-and-identity-separation.md).

## Osnovni nivo svakodnevne privatnosti

Cilj: smanjiti komercijalno praćenje, preuzimanje naloga i nepotrebno izlaganje bez pokušaja da postanete anonimni.

- Koristite održavan OS sa enkripcijom celog diska, automatskim ažuriranjima, zaključavanjem ekrana i secure boot funkcijom, gde je dostupna.
- Najpre sredite password manager, recovery email i phishing-resistant MFA/security keys.
- Proverite dozvole aplikacija, istoriju lokacije, advertising identifiers, cloud sync i konekcije sa nalozima trećih strana.
- Koristite mainstream browser sa malo ekstenzija, zaštitom od praćenja, HTTPS-om i odvojenim profilima za poslovno, lično i visokorizično browsing korišćenje.
- Koristite private relay aliases ili različite email adrese prema odnosu sa drugom stranom; ne koristite lični broj telefona kada je samo opcion.
- Dajte prednost end-to-end encrypted messaging-u za sadržaj, uz svest da učesnici, vreme, grupe i endpointi ostaju metadata.
- Namerno uklonite metadata iz fajlova i pregledajte izvezenu kopiju — ne original — pre objavljivanja.
- Koristite virtual-card ili wallet tokens za compartmentalization payment credentials; ne nazivajte ih anonimnim.
- Napravite backup enkriptovanog recovery materijala i testirajte njegovo vraćanje.

## Pseudonimno objavljivanje

Cilj: sprečiti da čitaoci i platforme bez većeg napora povežu objavu sa građanskim identitetom. Ovo ne sprečava sposobnu ciljanu istragu.

1. Definišite da li su platforma, hosting provider, čitaoci, kontakti, lokalna mreža, payment provider ili pravni postupak deo modela pretnji.
2. Kreirajte namenski endpoint/account context iz čistog baseline-a. Onemogućite lični browser sync, cloud documents, upload kontakata i prikaz pregleda obaveštenja.
3. Kreirajte pseudonimni nalog kroz izabrani network compartment. Nemojte ponovo koristiti usernames, avatare, recovery channels, writing boilerplate ili lični identity-provider login.
4. Koristite Tor Browser kada je unlinkability odredišta važnija od brzine; nemojte dodavati ekstenzije, značajno menjati veličinu ili podešavanja, niti otvarati preuzete dokumente dok ste online u običnoj desktop sesiji.
5. Pišite uz proces koji ne ugrađuje lične nazive template-a, autore revizija, putanje štampača, GPS/EXIF, thumbnails ili skrivene slojeve. Izvezite kopiju i pregledajte je odgovarajućim metadata alatima.
6. Proverite sadržaj u potrazi za činjenicama koje otkrivaju identitet: jedinstveni datumi, detalji o radnom mestu, lokalno vreme/vremenska zona, refleksije, pozadinski zvuk, jezičke navike i ponovna upotreba teksta iz prethodnih objava.
7. Koristite odvojen reply channel. Svaki direktni kontakt, attachment i link tretirajte kao potencijalni correlation ili phishing pokušaj.
8. Ako je uključen novac, koristite zakonit metod koji otkriva samo neophodne podatke. Pretpostavite da platforma i regulisani intermediary mogu znati primaoca plaćanja čak i ako čitaoci ne znaju.
9. Objavite, a zatim pregledajte javni rezultat iz drugog čistog context-a. Zabeležite šta je platforma dodala ili promenila.
10. Održavajte planiranu učestalost samo ako ona ne stvara stabilan behavioral fingerprint; ugasite compartment umesto da ga neprimetno prenamenite.

Za ozbiljno novinarstvo, aktivizam, nasilje u porodici ili rizik na državnom nivou, zatražite prilagođenu pomoć od iskusne organizacije za digitalnu bezbednost; statična checklist-a ne može modelovati lokalno pravo ili aktivnog protivnika.

## Ovlašćeni red-team angažman

Cilj: držati lične identitete operatora i njihove kućne mreže van telemetrije cilja, uz očuvanje ovlašćenja, kontrole i odgovora na incidente.

### Pre početka vremenskog prozora

- Finalizujte ROE infrastructure annex, ciljeve/isključenja, source ranges, datume, emergency stop i dozvole trećih strana/provajdera.
- Dodelite namenski operator profile ili VM, engagement secrets, evidence store, cloud project, domene i budžet.
- Dajte prednost client-provided egress-u ili fiksnom bastionu pod kontrolom organizacije. Testirajte full-tunnel IPv4/IPv6/DNS ponašanje i fail-closed policy.
- Čuvajte mapiranje operatora prema javnoj infrastrukturi kod exercise controllera ili dogovorenog escrow kontakta.
- Uspostavite rate limits, destination allowlists i odvojeno odobrenje za destruktivne, wireless, fizičke, phishing ili credential-collection akcije.
- Koristite payment rail pod kontrolom organizacije i interno evidentirajte odobrenja.

### Tokom angažmana

- Počnite sa odobrenog endpointa i tunnela; proverite uočeni egress pre assessment saobraćaja.
- Lične naloge, uređaje, brojeve telefona, repozitorijume, SSH/GPG ključeve i cloud sync držite van compartment-a.
- Logujte operator/job, početak/kraj, source, scoped destination i promene konfiguracije bez prikupljanja nepotrebnog sadržaja klijenta.
- Zaustavite se kod nejasnog scope-a, neočekivanih sistema trećih strana, provider abuse obaveštenja, bezbednosnog uticaja, gubitka opreme ili gubitka kontakta sa controllerom.
- Nikada ne improvizujte korišćenjem Wi-Fi mreže komšije, ukradenih credentials, neodobrenog SIM-a/naloga ili hardvera sakrivenog na lokaciji.

### Kraj angažmana

- Zaustavite jobs i C2; preuzmite odobrene drop uređaje; opozovite tokene, credentials i sertifikate.
- Uskladite infrastrukturu, domene, source addresses, troškove, podatke i slučajeve kod provajdera sa inventarom.
- Vratite/obrišite/zadržite podatke klijenta u skladu sa ugovorom, sačuvajte minimum potrebnih audit dokaza i zatražite od drugog operatora da proveri gašenje.

Pogledajte [Infrastruktura za ovlašćeni Red-Team](authorized-red-team-infrastructure.md) za kompletan vodič za izgradnju i uklanjanje.

## Zakonita privatna kupovina ili donacija

Cilj: smanjiti otkrivanje podataka trgovcu ili javnosti uz ispunjavanje obaveza prema izdavaocu, računovodstvu, porezima i sankcijama.

1. Navedite ko ne sme saznati šta: javnost, trgovac, payment intermediary, poslodavac/familijarni delegate naloga, dostavna služba ili blockchain posmatrač.
2. Proverite lokalna pravila, primaoca/drugu stranu, uslove provajdera, cash limits i potrebe vođenja evidencije.
3. Izaberite rail:
- gotovinu za prihvaćena zakonita lokalna plaćanja bez zapisa payment network-a;
- regulisanu virtuelnu karticu ili karticu specifičnu za trgovca za online credential separation;
- cryptocurrency tek nakon analize acquisition, ledger, wallet backend, network, counterparty i veza sa kasnijom potrošnjom.
4. Koristite tačne obavezne podatke i izostavite samo opcione loyalty/marketing podatke. Nemojte koristiti identitet/adresu druge osobe niti deliti transakciju oko praga.
5. Odvojite merchant browser/account context i izbegavajte nepovezani social login, loyalty ili lične recovery channels.
6. Potvrdite šta se pojavljuje na izvodima, računima, obaveštenjima, dostavi i javnim listama donatora.
7. Obavezne receipts/tax/authorization dokaze čuvajte enkriptovano; opozovite disposable payment credentials nakon isteka perioda za refund.

Pogledajte [Privatna digitalna plaćanja](private-digital-payments.md) i [Privatnost cryptocurrency-ja](cryptocurrency-privacy.md).

## Putovanja i nepouzdane mreže

Cilj: zaštititi podatke i naloge na mrežama kojima korisnik ne upravlja — a ne prikriti neovlašćenu aktivnost.

- Ažurirajte uređaje i pre putovanja preuzmite potrebne credentials/maps.
- Smanjite količinu sačuvanih podataka; koristite enkripciju celog diska, snažno otključavanje, planiranje udaljenog recovery-ja i procedure za isključen uređaj pri prelasku granice/fizičkom riziku, u skladu sa pravnim savetom.
- Proverite venue SSID/captive portal. Kada je odgovarajuće, dajte prednost ličnom hotspot-u, ali imajte na umu evidencije cellular subscriber-a i lokacije.
- Koristite full/forced approved VPN za organizacione podatke; proverite da ga tethered uređaji dele i testirajte IPv6/DNS ponašanje.
- Koristite travel router za client isolation i ponovljivu policy, a ne kao garanciju anonimnosti.
- Javno USB punjenje, pozajmljene računare, javne štampače i deljene sisteme u salama za sastanke tretirajte kao odvojene pretnje.
- Pretpostavite da fizičko prisustvo, radio identifiers, prijava na portal, kamere i evidencije plaćanja/lokacije mogu povezati posetu.

Detalji poređenja i podešavanja nalaze se u [Mrežna privatnost i anonimna konektivnost](network-privacy-and-anonymous-connectivity.md).

## Odgovor na neuspeh i izlaganje

Kada compartment procure ili može biti povezan:

1. Zaustavite aktivnost ako nastavak povećava štetu; gde je primenljivo, koristite emergency stop angažmana.
2. Sačuvajte neophodne dokaze bez širenja osetljivih podataka. Zabeležite tačno vreme, uočeni indikator i pogođene assete.
3. Obavestite odgovarajućeg vlasnika/controller-a/security kontakt. Ne prikrivajte incident radi očuvanja narativa o privatnosti.
4. Opozovite sesije, tokene, payment credentials i pristup infrastrukturi; rotirajte secrets sa poznatog čistog endpointa.
5. Utvrdite koje su ivice omogućile povezivanje: endpoint, account recovery, network, payment, metadata, content, behavior, counterparty ili physical presence.
6. Ceo pogođeni compartment tretirajte kao kompromitovan. Nemojte samo promeniti njegov username ili exit IP.
7. Ispunite obaveze obaveštavanja o breach-u, prema provajderu, klijentu, finansijskim i pravnim obavezama.
8. Ponovo izgradite sistem tek nakon promene procesa koji je doveo do povezivanja; dokumentujte kontrolu i testirajte je.

## Periodični audit

- [ ] Model pretnji i pravne/provider pretpostavke pregledaju se prema utvrđenom rasporedu.
- [ ] Uređaji, nalozi, aliases, domene, network paths i payment credentials su inventarisani.
- [ ] Recovery paths ne prelaze neočekivano između compartment-a.
- [ ] Full-tunnel, DNS, IPv6 i fail-closed ponašanje su testirani.
- [ ] Javni fajlovi i profili provereni su u pogledu metadata i ponovne upotrebe sadržaja.
- [ ] Wallet nodes/backends i pretpostavke crypto protokola ostaju ažurni.
- [ ] Logovi i računi su minimalni, enkriptovani, pod kontrolom pristupa i u okviru perioda čuvanja.
- [ ] Stari compartment-i i engagement infrastruktura u potpunosti su povučeni.
{{#include ../banners/hacktricks-training.md}}
