# AI Rizici

{{#include ../banners/hacktricks-training.md}}

## OWASP Top 10 Ranljivosti Mašinskog Učenja

Owasp je identifikovao top 10 ranljivosti mašinskog učenja koje mogu uticati na AI sisteme. Ove ranljivosti mogu dovesti do različitih bezbednosnih problema, uključujući trovanje podacima, inverziju modela i protivničke napade. Razumevanje ovih ranljivosti je ključno za izgradnju sigurnih AI sistema.

Za ažuriranu i detaljnu listu top 10 ranljivosti mašinskog učenja, pogledajte projekat [OWASP Top 10 Machine Learning Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/).

- **Napad Manipulacije Ulazom**: Napadač dodaje sitne, često nevidljive promene u **dolazne podatke** kako bi model doneo pogrešnu odluku.\
*Primer*: Nekoliko mrlja boje na znak stopa prevari autonomni automobil da "vidi" znak za ograničenje brzine.

- **Napad Trovanja Podacima**: **Trening set** je namerno zagađen lošim uzorcima, učeći model štetnim pravilima.\
*Primer*: Zlonamerni binarni fajlovi su pogrešno označeni kao "benigni" u antivirusnom trening skupu, omogućavajući sličnom zlonamernom softveru da prođe kasnije.

- **Napad Inverzije Modela**: Istražujući izlaze, napadač gradi **obrnuti model** koji rekonstruiše osetljive karakteristike originalnih ulaza.\
*Primer*: Ponovno kreiranje MRI slike pacijenta na osnovu predikcija modela za otkrivanje raka.

- **Napad Inference Članstva**: Protivnik testira da li je **određeni zapis** korišćen tokom treninga uočavajući razlike u poverenju.\
*Primer*: Potvrđivanje da se bankovna transakcija osobe pojavljuje u podacima za obuku modela za otkrivanje prevara.

- **Krađa Modela**: Ponovnim postavljanjem upita napadač može naučiti granice odluka i **klonirati ponašanje modela** (i IP).\
*Primer*: Prikupljanje dovoljno Q&A parova sa ML‑as‑a‑Service API-ja da bi se izgradio gotovo ekvivalentan lokalni model.

- **Napad na AI Lanac Snabdevanja**: Kompromitovanje bilo kojeg dela (podaci, biblioteke, unapred obučene težine, CI/CD) u **ML lancu** kako bi se korumpirali modeli nizvodno.\
*Primer*: Zagađena zavisnost na model‑hub instalira model analize sentimenta sa zadnjim ulazom u mnogim aplikacijama.

- **Napad Prenosa Učenja**: Zlonamerna logika je usađena u **unapred obučeni model** i opstaje tokom fino podešavanja na zadatku žrtve.\
*Primer*: Vizuelna osnova sa skrivenim okidačem i dalje menja oznake nakon što je prilagođena za medicinsko snimanje.

- **Iskrivljavanje Modela**: Suptilno pristrasni ili pogrešno označeni podaci **pomera izlaze modela** u korist agende napadača.\
*Primer*: Umetanje "čistih" spam e-mailova označenih kao ham tako da spam filter propušta slične buduće e-mailove.

- **Napad na Integritet Izlaza**: Napadač **menja predikcije modela u tranzitu**, a ne sam model, obmanjujući nizvodne sisteme.\
*Primer*: Promena "maliciozne" presude klasifikatora zlonamernog softvera u "benignu" pre nego što faza karantina fajla to vidi.

- **Trovanje Modela** --- Direktne, ciljne promene u **parametrima modela** samih, često nakon sticanja pristupa za pisanje, kako bi se promenilo ponašanje.\
*Primer*: Podešavanje težina na modelu za otkrivanje prevara u produkciji tako da transakcije sa određenih kartica uvek budu odobrene.


## Google SAIF Rizici

Googleov [SAIF (Security AI Framework)](https://saif.google/secure-ai-framework/risks) opisuje različite rizike povezane sa AI sistemima:

- **Trovanje Podacima**: Zlonamerni akteri menjaju ili umetnuju podatke za obuku/podešavanje kako bi smanjili tačnost, implantirali zadnje ulaze ili iskrivili rezultate, potkopavajući integritet modela kroz ceo životni ciklus podataka.

- **Neovlašćeni Podaci za Obuku**: Uzimanje zaštićenih, osetljivih ili neodobrenih skupova podataka stvara pravne, etičke i performansne obaveze jer model uči iz podataka koje nikada nije smeo da koristi.

- **Manipulacija Izvorom Modela**: Manipulacija kodom modela, zavisnostima ili težinama u lancu snabdevanja ili od strane insajdera pre ili tokom obuke može ugraditi skrivenu logiku koja opstaje čak i nakon ponovne obuke.

- **Prekomerno Rukovanje Podacima**: Slabi kontrole zadržavanja i upravljanja podacima dovode sisteme da čuvaju ili obrađuju više ličnih podataka nego što je potrebno, povećavajući izloženost i rizik od usklađenosti.

- **Ekstrakcija Modela**: Napadači kradu fajlove/težine modela, uzrokujući gubitak intelektualne svojine i omogućavajući usluge imitacije ili naknadne napade.

- **Manipulacija Implementacijom Modela**: Protivnici menjaju artefakte modela ili infrastrukturu za pružanje tako da se pokreće model razlikuje od odobrene verzije, potencijalno menjajući ponašanje.

- **Odbijanje ML Usluge**: Preplavljivanje API-ja ili slanje "sponge" ulaza može iscrpiti računarske/energetske resurse i isključiti model, odražavajući klasične DoS napade.

- **Obrnuto Inženjerstvo Modela**: Prikupljanjem velikog broja parova ulaz-izlaz, napadači mogu klonirati ili destilovati model, podstičući imitacione proizvode i prilagođene protivničke napade.

- **Neosigurana Integrisana Komponenta**: Ranjivi dodaci, agenti ili uzvodne usluge omogućavaju napadačima da umetnu kod ili eskaliraju privilegije unutar AI lanca.

- **Umetanje Upita**: Kreiranje upita (direktno ili indirektno) kako bi se prokrijumčarile instrukcije koje nadmašuju nameru sistema, čineći da model izvršava nepredviđene komande.

- **Izbegavanje Modela**: Pažljivo dizajnirani ulazi pokreću model da pogrešno klasifikuje, halucinira ili izbacuje zabranjeni sadržaj, erodirajući bezbednost i poverenje.

- **Otkrivanje Osetljivih Podataka**: Model otkriva privatne ili poverljive informacije iz svojih podataka za obuku ili korisničkog konteksta, kršeći privatnost i propise.

- **Inferisani Osetljivi Podaci**: Model dedukuje lične atribute koji nikada nisu pruženi, stvarajući nove povrede privatnosti kroz inferenciju.

- **Neosigurani Izlaz Modela**: Nečist odgovori prenose štetni kod, dezinformacije ili neprimeren sadržaj korisnicima ili nizvodnim sistemima.

- **Rogue Akcije**: Autonomno integrisani agenti izvršavaju nepredviđene operacije u stvarnom svetu (pisanje fajlova, API pozivi, kupovine itd.) bez adekvatnog nadzora korisnika.

## Mitre AI ATLAS Matriks

[MITRE AI ATLAS Matriks](https://atlas.mitre.org/matrices/ATLAS) pruža sveobuhvatan okvir za razumevanje i ublažavanje rizika povezanih sa AI sistemima. Kategorizuje različite tehnike napada i taktike koje protivnici mogu koristiti protiv AI modela, kao i kako koristiti AI sisteme za izvođenje različitih napada.


{{#include ../banners/hacktricks-training.md}}
