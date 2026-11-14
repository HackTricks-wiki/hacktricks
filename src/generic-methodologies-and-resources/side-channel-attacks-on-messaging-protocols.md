# Napadi bočnim kanalom preko potvrda isporuke u E2EE messengerima

{{#include ../banners/hacktricks-training.md}}

Potvrde isporuke su obavezne u modernim end-to-end enkriptovanim (E2EE) messengerima jer klijenti moraju da znaju kada je šifrat dekriptovan kako bi mogli da odbace stanje ratchet-a i ephemeral ključeve. Server prosleđuje neprozirne blobove, pa uređaj primaoca šalje potvrde (dvostruke kvačice) nakon uspešne dekripcije. Merenje vremena povratnog puta (RTT) između radnje koju pokrene napadač i odgovarajuće potvrde isporuke otkriva kanal za vremensko merenje visoke rezolucije koji odaje stanje uređaja i prisustvo na mreži, a može se zloupotrebiti i za covert DoS. Implementacije sa više uređaja i „client-fanout“ pojačavaju curenje jer svaki registrovani uređaj dekriptuje probu i vraća sopstvenu potvrdu.<sup>[[1]](#references)</sup>

## Izvori potvrda isporuke naspram signala vidljivih korisniku

Birajte tipove poruka koji uvek šalju potvrdu isporuke, ali ne stvaraju vidljive UI artefakte na uređaju žrtve. Tabela u nastavku sumira empirijski potvrđeno ponašanje:<sup>[[1]](#references)</sup>

| Messenger | Radnja | Potvrda isporuke | Obaveštenje žrtve | Napomene |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Tekstualna poruka | ● | ● | Uvek upadljivo → korisno samo za početno utvrđivanje stanja. |
| | Reakcija | ● | ◐ (samo ako se reaguje na poruku žrtve) | Sopstvene reakcije i njihovo uklanjanje ostaju nevidljivi. |
| | Izmena | ● | Tiha push notifikacija, zavisno od platforme | Vreme za izmenu ≈20 min; potvrda se i dalje šalje nakon isteka. |
| | Brisanje za sve | ● | ○ | UI dozvoljava ~60 h, ali se potvrde i dalje šalju za kasnije pakete. |
| **Signal** | Tekstualna poruka | ● | ● | Ista ograničenja kao kod WhatsApp-a. |
| | Reakcija | ● | ◐ | Sopstvene reakcije su nevidljive žrtvi. |
| | Izmena/brisanje | ● | ○ | Server sprovodi ograničenje od ~48 h, dozvoljava do 10 izmena, ali se potvrde i dalje šalju za zakašnjele pakete. |
| **Threema** | Tekstualna poruka | ● | ● | Potvrde sa više uređaja se objedinjuju, pa je vidljiv samo jedan RTT po probi. |

Legenda: ● = uvek, ◐ = uslovno, ○ = nikad. Ponašanje UI-ja koje zavisi od platforme navedeno je u napomenama. Po potrebi isključite potvrde čitanja, ali potvrde isporuke ne mogu da se isključe u WhatsApp-u ili Signalu.<sup>[[1]](#references)</sup>

## Ciljevi i modeli napadača

* **G1 – Otisak uređaja:** Prebrojite koliko potvrda stiže po probi, grupišite RTT-ove da biste zaključili koji se OS/klijent koristi (Android naspram iOS-a ili desktopa) i pratite prelaze između stanja na mreži i van mreže.
* **G2 – Praćenje ponašanja:** Tretirajte seriju RTT-ova visoke frekvencije (≈1 Hz je stabilno) kao vremenski niz i zaključujte da li je ekran uključen/isključen, da li je aplikacija u prvom planu ili pozadini, da li je žrtva na putu ili radi u uobičajeno vreme i slično.
* **G3 – Iscrpljivanje resursa:** Održavajte radio-veze/CPU-e svih uređaja žrtve aktivnim slanjem beskonačnih tihih proba, trošeći bateriju/podatke i pogoršavajući kvalitet video-poziva.<sup>[[1]](#references)</sup>

Dva aktera pretnje dovoljna su da opišu površinu zloupotrebe:<sup>[[1]](#references)</sup>

1. **Jezivi pratilac:** Već deli razgovor sa žrtvom i zloupotrebljava sopstvene reakcije, uklanjanje reakcija ili ponovljene izmene/brisanja vezane za postojeće ID-jeve poruka.
2. **Sablasni stranac:** Registruje burner nalog i šalje reakcije koje referenciraju ID-jeve poruka koje nikad nisu postojale u lokalnom razgovoru; WhatsApp i Signal ih i dalje dekriptuju i potvrđuju iako UI odbacuje promenu stanja, pa prethodni razgovor nije potreban.

## Alati za pristup sirovom protokolu

Koristite klijente koji izlažu dovoljno osnovnog E2EE protokola da biste mogli da kreirate podržane pakete izvan UI ograničenja i beležite precizne vremenske oznake; podršku za proizvoljne ID-jeve poruka potrebno je proveriti u svakoj implementaciji:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, WhatsApp Web API za više uređaja) dokumentuje slanje i prijem potvrda isporuke; [Cobalt](https://github.com/Auties00/Cobalt) (nezvanični Java/Kotlin Web i mobilni API) dokumentuje radnje nad porukama kao što su reagovanje, izmena i brisanje. Koristite njihove dokumentovane API-je umesto da pretpostavljate da je svaki interni frame dostupan.<sup>[[3]](#references)[[4]](#references)</sup>
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) nudi CLI, JSON-RPC i D-Bus interfejse, dok je [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) Java biblioteka za komunikaciju sa Signalom.<sup>[[5]](#references)[[7]](#references)</sup> Trenutna sintaksa za `signal-cli` koristi `sendReaction RECIPIENT --target-author --target-timestamp`; ostavite `receive` ili `daemon` pokrenutim kako bi se ažuriranja protokola i dalje obrađivala.<sup>[[6]](#references)</sup> Primer prebacivanja sopstvene reakcije:
  ```bash
  signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
      --target-timestamp 1712345678901 --emoji "👍"
  signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
      --target-timestamp 1712345678901 --remove
  ```
* **Threema:** Merenja iz rada Careless Whisper pokazala su da se potvrde o isporuci sinhronizuju na svim uređajima, pa se otkriva samo jedna potvrda po poruci, čak i u konfiguraciji sa više uređaja.<sup>[[1]](#references)</sup>
* **Turnkey PoCs:** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker) isporučuje WhatsApp/Signal backende, podrazumevano koristi tihe probe brisanja i označava `active` naspram `standby` pomoću praga zasnovanog na kliznoj medijani (`RTT < 0.9 * median`).<sup>[[8]](#references)</sup> [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python) je jednostavniji CLI prvenstveno za WhatsApp, sa opcijama `--delay`, `--concurrent`, CSV/Prometheus izvozom i izlazom pogodnim za Grafana.<sup>[[9]](#references)</sup> Obe alatke smatrajte pomoćnim alatkama za izviđanje, a ne referencama za protokol; važno je to koliko je malo koda potrebno kada je dostupan direktan pristup klijentu.

Kada prilagođeni alati nisu dostupni, zvanični klijenti ili razvojni alati pregledača i dalje mogu da pokrenu tihe radnje i otkriju vremenske karakteristike šifrovanog saobraćaja; direktni API-ji uklanjaju kašnjenja UI-ja i omogućavaju nevažeće operacije.<sup>[[1]](#references)</sup>

## Jezivi pratilac: petlja tihog uzorkovanja

1. Izaberite bilo koju stariju poruku koju ste poslali u razgovoru kako žrtva nikada ne bi videla da se balončići za „reakcije“ menjaju.
2. Naizmenično šaljite vidljivi emoji i prazan sadržaj reakcije (kodiran kao `""` u WhatsApp protobufovima ili kao `--remove` u signal-cli). Svako slanje daje potvrdu uređaja, iako žrtva ne vidi nikakvu promenu u UI-ju.
3. Zabeležite vreme slanja i dolazak svake potvrde o isporuci. Petlja od 1 Hz, poput sledeće, daje neprekidne RTT tragove po uređaju:
   ```python
   while True:
       send_reaction(msg_id, "👍")
       log_receipts()
       send_reaction(msg_id, "")  # removal
       log_receipts()
       time.sleep(0.5)
   ```
4. Pošto WhatsApp/Signal prihvataju neograničen broj ažuriranja reakcija, napadač nikada ne mora da objavljuje novi sadržaj u razgovoru niti da brine o vremenskim ograničenjima za izmenu.<sup>[[1]](#references)</sup>

## Sablasni stranac: ispitivanje proizvoljnih telefonskih brojeva

1. Registrujte novi WhatsApp/Signal nalog i preuzmite javne ključeve identiteta za ciljni broj (to se automatski obavlja tokom podešavanja sesije).
2. Napravite paket reakcije koji upućuje na nasumični `message_id` koji nijedna strana nikada nije videla; rad navodi da i WhatsApp i Signal prihvataju takve reakcije i ipak generišu potvrde isporuke.<sup>[[1]](#references)</sup>
3. Pošaljite paket iako ne postoji nijedna nit razgovora. Uređaji žrtve ga dešifruju, ne uspevaju da pronađu osnovnu poruku, odbacuju promenu stanja, ali ipak potvrđuju prijem dolaznog šifratnog teksta slanjem potvrda uređaja napadaču.
4. Ponavljajte postupak da biste prikupili nizove RTT-a bez prethodnog razgovora ili vidljivog obaveštenja.<sup>[[1]](#references)</sup>

Ako prvo treba da otkrijete koji su brojevi registrovani ili želite da unapred prikupite inventare uređaja u velikom obimu, povežite ovo sa [otkrivanjem kontakata / registration oracles](../pentesting-web/registration-vulnerabilities.md), umesto da ručno nagađate nasumične E.164 opsege.

Objavljeni radovi o otkrivanju kontakata pokazali su zašto je to operativno važno: uz tačne tabele telefonskih prefiksa i skromne resurse, istraživači su mogli da upitaju približno `10%` američkih mobilnih brojeva na WhatsApp-u i `100%` na Signal-u pre nego što pređu na ciljano ispitivanje.<sup>[[11]](#references)</sup> U praksi, prethodno filtriranje aktivnih naloga usmerava budžet za tihe probe na brojeve koji će zaista dešifrovati pakete.

Novije verzije WhatsApp-a takođe nude `Settings -> Privacy -> Advanced -> Block unknown account messages`.<sup>[[10]](#references)</sup> Posmatrajte ovo kao ograničenje protoka: dokumentacija trackera navodi da WhatsApp blokira veliki broj poruka sa nepoznatih naloga, ali ne otkriva prag, tako da ova opcija ne sprečava u potpunosti probe reakcijama.<sup>[[8]](#references)</sup>

## Recikliranje izmena i brisanja kao skrivenih okidača

* **Ponovljena brisanja:** Kada je poruka jednom obrisana za sve, dodatni paketi za brisanje koji upućuju na isti `message_id` nemaju efekta u UI-ju, ali ih svaki uređaj i dalje dešifruje i potvrđuje.
* **Operacije van vremenskog ograničenja:** WhatsApp u UI-ju nameće vremenske rokove od ~60 h za brisanje i ~20 min za izmenu; Signal nameće rok od ~48 h. Napravljene protokolarne poruke van ovih rokova tiho se ignorišu na uređaju žrtve, ali se potvrde ipak šalju, pa napadači mogu da vrše probe neograničeno dugo nakon završetka razgovora.
* **Nevažeći payload-i:** Rad navodi da se nevažeće poruke i dalje mogu potvrditi; tačno ponašanje za neispravna tela poruka ili uklonjene ID-jeve zavisi od implementacije, zato testirajte pre nego što se oslonite na to.<sup>[[1]](#references)</sup>

## Umnožavanje na više uređaja i fingerprinting

* Na WhatsApp-u i Signal-u svaki povezani uređaj (telefon, desktop aplikacija, prateći pregledač) nezavisno dešifruje probu i vraća sopstveni ack. Brojanje potvrda za svaku probu otkriva tačan broj uređaja.<sup>[[1]](#references)</sup>
* Ako je uređaj van mreže, njegova potvrda se stavlja u red čekanja i šalje po ponovnom povezivanju. Zato prekidi otkrivaju cikluse povezanosti i nepovezanosti, pa čak i raspored kretanja (npr. potvrde sa desktop računara prestaju tokom putovanja).
* Raspodele RTT-a razlikuju se u zavisnosti od platforme i okruženja jer OS, model, klijent i uslovi mreže utiču na vreme odziva. Grupisanje RTT-a (npr. k-means nad karakteristikama medijane/varijanse) može da označi uređaje kao „Android telefon“, „iOS telefon“, „Electron desktop“ itd.
* Pošto pošiljalac mora da preuzme inventar ključeva primaoca pre šifrovanja, napadač može da prati i kada se uparuju novi uređaji; nagli porast broja uređaja ili pojava novog RTT klastera snažan je pokazatelj.<sup>[[1]](#references)</sup>

**Fingerprinting na osnovu potvrda iz reda čekanja:** Pošaljite nekoliko proba sa različitim ID-jevima poruka dok je ciljni uređaj van mreže. Kada se ponovo poveže, povežite ID-jeve iz vraćenih potvrda isporuke i proverite da li su odvojene ili grupisane u jednoj potvrdi, kao i da li grupisani ID-jevi zadržavaju ili obrću redosled slanja. U testiranim klijentima, WhatsApp za Android/iOS vraćao je odvojene potvrde isporuke, dok su ih Web, Windows i macOS grupisali; macOS je obrtao redosled grupisanih ID-jeva. Signal Desktop je grupisao potvrde, za razliku od svojih mobilnih klijenata. Ovo može da klasifikuje klijent koji se ponovo povezuje čak i kada se raspodele RTT-a preklapaju. Nemojte mešati potvrde isporuke sa potvrdama čitanja, koje imaju drugačija pravila grupisanja.<sup>[[1]](#references)</sup>

Za odvojenu WhatsApp probu koja čita **server-side dopunjavanja prekey-a** bez isporuke poruka, pogledajte [Side Channel pražnjenja i dopunjavanja Prekey Bundle-a](whatsapp-prekey-bundle-side-channel.md).

## Učestalost uzorkovanja, redovi čekanja i grupisane potvrde

* **Tolerancija WhatsApp-a na burst:** Objavljena merenja navode da je WhatsApp prihvatao burst-e tihih reakcija brzinom do jedne probe na svakih `50 ms` bez očiglednog server-side čekanja u redu. To je korisno za kratke burst-e za kalibraciju, brzo brojanje uređaja ili brzo pokretanje drain attack-a.
* **Dugotrajno čekanje u redu na Signal-u:** Signal je podnosio kratke burst-e, ali je počinjao da stavlja saobraćaj od više proba u sekundi u red čekanja kada bi se takav saobraćaj održavao. Za dugotrajno praćenje, održavajte učestalost oko `1 Hz` (ili nižu) kako bi svaka potvrda odražavala trenutno stanje uređaja, a ne pražnjenje reda.
* **Artefakti ponovnog povezivanja:** Kada se uređaj ponovo poveže, neki klijenti grupišu ili brzo šalju više odloženih potvrda. Tretirajte te burst-e potvrda kao oznaku promene stanja, a ne kao nezavisne RTT uzorke, jer će se u suprotnom vaše grupisanje / klasifikator `active` naspram `idle` previše prilagoditi šumu pri ponovnom povezivanju.<sup>[[1]](#references)</sup>

## Zaključivanje o ponašanju iz RTT tragova

1. Uzorkujte frekvencijom ≥1 Hz da biste obuhvatili efekte raspoređivanja OS-a. Na WhatsApp-u za iOS, RTT ispod 1 s snažno korelira sa uključenim ekranom/aplikacijom u prvom planu, a RTT iznad 1 s sa isključenim ekranom/ograničavanjem rada u pozadini.
2. Napravite jednostavne klasifikatore (pragovanje ili k-means sa dva klastera) koji svaki RTT označavaju kao „aktivan“ ili „neaktivan“. Grupisanje oznaka u nizove može da otkrije vreme spavanja, putovanja na posao, radno vreme ili periode aktivnosti pratećeg desktop uređaja.
3. Uporedite istovremene probe upućene svakom uređaju da biste utvrdili kada korisnici prelaze sa mobilnog na desktop, kada prateći uređaji izlaze iz mreže i da li se aplikacija ograničava preko push-a ili trajnog socket-a.
4. U stvarnim mrežama izbegavajte jedan fiksni prag od `1 s`. Inicijalizujte svaki uređaj kratkim periodom zagrevanja i održavajte pokretnu osnovnu vrednost (na primer, PoC device-activity-tracker koristi `threshold = 0.9 * median RTT`) da promene između Wi-Fi-ja i mobilne mreže ne bi poremetile klasifikator.<sup>[[1]](#references)[[8]](#references)</sup>

## Zaključivanje o lokaciji iz RTT-a isporuke

Isti vremenski mehanizam može da se iskoristi za zaključivanje o tome gde se primalac nalazi, a ne samo o tome da li je aktivan. Rad `Hope of Delivery` pokazao je da obučavanje na raspodelama RTT-a za poznate lokacije primaoca omogućava napadaču da kasnije klasifikuje lokaciju žrtve samo na osnovu potvrda isporuke:<sup>[[2]](#references)</sup>

* Napravite osnovnu vrednost za istu ciljnu osobu dok se nalazi na nekoliko poznatih mesta (kod kuće, u kancelariji, na kampusu, u zemlji A naspram zemlje B itd.).
* Za svaku lokaciju prikupite mnogo uobičajenih RTT-ova poruka i izdvojte jednostavne karakteristike kao što su medijana, varijansa ili percentilni opsezi.
* Tokom stvarnog napada uporedite novi niz proba sa obučenim klasterima. Rad navodi da se često mogu razlikovati čak i lokacije u istom gradu, uz tačnost od `>80%` u scenariju sa 3 lokacije.
* Ovo najbolje funkcioniše kada napadač kontroliše okruženje pošiljaoca i šalje probe u sličnim mrežnim uslovima, jer izmerena putanja obuhvata pristupnu mrežu primaoca, kašnjenje pri buđenju i infrastrukturu aplikacije za razmenu poruka.<sup>[[2]](#references)</sup>

Za razliku od tihih napada reakcijama/izmenama/brisanjima opisanih iznad, zaključivanje o lokaciji ne zahteva nevažeće ID-jeve poruka niti prikrivene pakete koji menjaju stanje. Dovoljne su obične poruke sa uobičajenim potvrdama isporuke, pa je kompromis manja prikrivenost, ali šira primenljivost na različite aplikacije za razmenu poruka.

## Prikriveno iscrpljivanje resursa

Pošto svaku tihu probu treba dešifrovati i potvrditi, neprekidno slanje promena reakcija, nevažećih izmena ili paketa za brisanje za sve izaziva DoS na aplikacionom sloju:<sup>[[1]](#references)</sup>

* Primorava radio/modem da svake sekunde šalje/prima podatke → primetno pražnjenje baterije, naročito na telefonima u stanju mirovanja.
* Stvara odlazni/dolazni saobraćaj koji troši mobilni internet i može da ometa funkcije osetljive na kašnjenje, kao što su video-pozivi.<sup>[[1]](#references)</sup>
* Veliki nevažeći payload-i povećavaju obim obrade, ali rad navodi da kriptografija čini zanemarljiv deo troška baterije.<sup>[[1]](#references)</sup>
* Na WhatsApp-u nevažeće reakcije prihvataju mnogo više podataka nego što bi se očekivalo od običnog emoji-ja: objavljena merenja utvrdila su da prihvatanje na serverskoj strani ide do približno `1 MB` po reakciji.
* Prevelike reakcije prestaju da daju pouzdane potvrde isporuke kada telo poruke pređe približno `30 bytes`, ali se i dalje prosleđuju i obrađuju pre odbacivanja. Neka tela reakcija budu mala kada su vam potrebni ACK-ovi; povećajte ih samo kada je cilj isključivo pražnjenje resursa ili prikriveni jednosmerni prenos.
* Javna merenja dostigla su oko `3.7 MB/s` (`~13.3 GB/h`) saobraćaja na uređaju žrtve u ovom režimu.



## References

- [1] [Careless Whisper: Iskorišćavanje tihih potvrda isporuke za praćenje korisnika u mobilnim aplikacijama za razmenu trenutnih poruka](https://arxiv.org/html/2411.11194v4)
- [2] [Hope of Delivery: Izdvajanje lokacija korisnika iz mobilnih aplikacija za razmenu trenutnih poruka](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [3] [whatsmeow](https://github.com/tulir/whatsmeow)
- [4] [Cobalt](https://github.com/Auties00/Cobalt)
- [5] [signal-cli](https://github.com/AsamK/signal-cli)
- [6] [signal-cli manpage](https://github.com/AsamK/signal-cli/blob/master/man/signal-cli.1.adoc)
- [7] [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [8] [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)
- [9] [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python)
- [10] [Kako blokirati veliki broj poruka sa nepoznatih naloga | WhatsApp Help Center](https://faq.whatsapp.com/3379690015658337)
- [11] [Svi brojevi su iz SAD: Zloupotreba otkrivanja kontakata velikih razmera u mobilnim aplikacijama za razmenu trenutnih poruka](https://www.ndss-symposium.org/ndss-paper/all-the-numbers-are-us-large-scale-abuse-of-contact-discovery-in-mobile-messengers/)
{{#include ../banners/hacktricks-training.md}}
