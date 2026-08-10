# Side-Channel napadi pomoću potvrda isporuke u E2EE messengerima

Potvrde isporuke su obavezne u modernim end-to-end encrypted (E2EE) messengerima jer klijenti moraju da znaju kada je ciphertext dešifrovan kako bi mogli da odbace stanje ratchetinga i ephemeral ključeve. Server prosleđuje opaque blobove, pa acknowledgements uređaja (dvostruke kvačice) emituje primalac nakon uspešnog dešifrovanja. Merenje round-trip vremena (RTT) između akcije koju pokrene attacker i odgovarajuće potvrde isporuke otkriva timing channel visoke rezolucije koji leak-uje stanje uređaja i online prisustvo, a može se zloupotrebiti i za covert DoS. Multi-device „client-fanout“ deployment-i dodatno pojačavaju leak jer svaki registrovani uređaj dešifruje probe i vraća sopstvenu potvrdu.<sup>[[1]](#references)</sup>

## Izvori potvrda isporuke naspram signala vidljivih korisniku

Izaberite tipove poruka koji uvek emituju potvrdu isporuke, ali žrtvi ne prikazuju UI artefakte. Tabela u nastavku sažima empirijski potvrđeno ponašanje:<sup>[[1]](#references)</sup>

| Messenger | Akcija | Potvrda isporuke | Obaveštenje žrtvi | Napomene |
|-----------|--------|------------------|-------------------|-------|
| **WhatsApp** | Tekstualna poruka | ● | ● | Uvek bučno → korisno samo za inicijalizaciju stanja. |
| | Reaction | ● | ◐ (samo pri reagovanju na poruku žrtve) | Self-reactions i uklanjanja ostaju neprimetni. |
| | Izmena | ● | Platform-dependent silent push | Window za izmenu ≈20 min; potvrda se i dalje šalje nakon isteka. |
| | Brisanje za sve | ● | ○ | UI dozvoljava ~60 h, ali se kasniji paketi i dalje potvrđuju. |
| **Signal** | Tekstualna poruka | ● | ● | Ista ograničenja kao kod WhatsApp-a. |
| | Reaction | ● | ◐ | Self-reactions su nevidljive žrtvi. |
| | Izmena/brisanje | ● | ○ | Server nameće window od ~48 h i dozvoljava najviše 10 izmena, ali se kasni paketi i dalje potvrđuju. |
| **Threema** | Tekstualna poruka | ● | ● | Multi-device potvrde se agregiraju, pa je vidljiv samo jedan RTT po probe-u. |

Legenda: ● = uvek, ◐ = uslovno, ○ = nikad. Platform-dependent UI ponašanje navedeno je u napomenama. Po potrebi isključite read receipts, ali delivery receipts nije moguće isključiti u WhatsApp-u ili Signal-u.<sup>[[1]](#references)</sup>

## Ciljevi i modeli attackera

* **G1 – Fingerprinting uređaja:** Prebrojte koliko potvrda stiže po probe-u, grupišite RTT-ove da biste zaključili koji se OS/client koristi (Android naspram iOS-a ili desktopa) i pratite prelaze između online i offline stanja.
* **G2 – Praćenje ponašanja:** Tretirajte seriju RTT-ova visoke frekvencije (≈1 Hz je stabilno) kao time-series i zaključujte da li je ekran uključen/isključen, da li je aplikacija u foreground/background režimu, da li je vreme putovanja ili radno vreme itd.
* **G3 – Iscrpljivanje resursa:** Održavajte radio/CPU svakog uređaja žrtve aktivnim slanjem neprekidnih silent probe-ova, čime se prazne baterija i data saobraćaj i pogoršava kvalitet video-poziva.<sup>[[1]](#references)</sup>

Dva threat actora dovoljna su za opis abuse surface-a:<sup>[[1]](#references)</sup>

1. **Creepy companion:** već deli chat sa žrtvom i zloupotrebljava self-reactions, uklanjanja reakcija ili ponovljene izmene/brisanja povezana sa postojećim ID-jevima poruka.
2. **Spooky stranger:** registruje burner account i šalje reakcije koje referenciraju ID-jeve poruka koji nikada nisu postojali u lokalnoj konverzaciji; WhatsApp i Signal ih i dalje dešifruju i potvrđuju iako UI odbacuje promenu stanja, pa prethodna konverzacija nije potrebna.

## Alati za raw protocol access

Oslonite se na klijente koji izlažu dovoljno osnovnog E2EE protokola za izradu podržanih paketa izvan UI ograničenja i beleženje preciznih timestamps; za proizvoljne ID-jeve poruka potrebno je proveriti svaku implementaciju:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, WhatsApp Web multidevice API) dokumentuje slanje i prijem delivery receipts; [Cobalt](https://github.com/Auties00/Cobalt) (nezvanični Java/Kotlin Web i mobile API) dokumentuje operacije nad porukama kao što su reagovanje, izmena i brisanje. Koristite njihove dokumentovane API-je umesto pretpostavke da je svaki interni frame izložen.<sup>[[3]](#references)[[4]](#references)</sup>
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) izlaže CLI, JSON-RPC i D-Bus interfejse, dok je [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) Java biblioteka za komunikaciju sa Signal-om.<sup>[[5]](#references)[[7]](#references)</sup> Trenutna sintaksa `signal-cli` koristi `sendReaction RECIPIENT --target-author --target-timestamp`; održavajte `receive` ili `daemon` pokrenutim kako bi se protocol updates i dalje obrađivali.<sup>[[6]](#references)</sup> Primer toggle-a self-reaction:
```bash
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --emoji "👍"
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --remove
```
* **Threema:** Merenja u radu Careless Whisper pokazala su da se delivery receipts sinhronizuju između uređaja, pa je čak i u multi-device setup-u izložena samo jedna potvrda po poruci.<sup>[[1]](#references)</sup>
* **Turnkey PoCs:** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker) sadrži WhatsApp/Signal backende, podrazumevano koristi silent delete probe-ove i označava `active` naspram `standby` pomoću rolling-median praga (`RTT < 0.9 * median`).<sup>[[8]](#references)</sup> [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python) je jednostavniji WhatsApp-first CLI sa opcijama `--delay`, `--concurrent`, CSV/Prometheus exporterima i Grafana-friendly izlazom.<sup>[[9]](#references)</sup> Oba tretirajte kao reconnaissance helper-e, a ne kao protocol reference; najvažniji zaključak je koliko je malo koda potrebno kada raw client access već postoji.

Kada custom tooling nije dostupno, official clients ili browser developer tools i dalje mogu da pokrenu silent akcije i otkriju timing encrypted saobraćaja; raw API-ji uklanjaju UI kašnjenja i omogućavaju invalid operations.<sup>[[1]](#references)</sup>

## Creepy companion: silent sampling loop

1. Izaberite bilo koju istorijsku poruku koju ste poslali u chat, tako da žrtva nikada ne vidi promenu „reaction“ balončića.
2. Naizmenično šaljite vidljivi emoji i prazan reaction payload (kodiran kao `""` u WhatsApp protobuf-ima ili kao `--remove` u signal-cli). Svaki prenos proizvodi device ack iako kod žrtve nema UI promene.
3. Zabeležite vreme slanja i svaki dolazak delivery receipt-a. Loop od 1 Hz, poput sledećeg, daje neograničene RTT tragove po uređaju:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. Pošto WhatsApp/Signal prihvataju neograničene reaction updates, attacker nikada ne mora da objavi novi chat sadržaj niti da brine o edit windows.<sup>[[1]](#references)</sup>

## Spooky stranger: probing proizvoljnih telefonskih brojeva

1. Registrujte novi WhatsApp/Signal account i preuzmite javne identity keys za ciljani broj (to se automatski obavlja tokom session setup-a).
2. Izradite reaction packet koji referencira nasumični `message_id` koji nijedna strana nikada nije videla; rad navodi da i WhatsApp i Signal prihvataju takve reakcije i i dalje generišu delivery receipts.<sup>[[1]](#references)</sup>
3. Pošaljite paket iako thread ne postoji. Uređaji žrtve ga dešifruju, ne uspevaju da pronađu osnovnu poruku, odbacuju promenu stanja, ali i dalje potvrđuju dolazni ciphertext i šalju device receipts attacker-u.
4. Ponavljajte neprekidno da biste izgradili RTT serije bez prethodne konverzacije ili vidljivog obaveštenja.<sup>[[1]](#references)</sup>

Ako prvo morate da otkrijete koji su brojevi registrovani ili želite da unapred prikupite inventare uređaja u velikom obimu, povežite ovo sa [contact-discovery / registration oracles](../pentesting-web/registration-vulnerabilities.md), umesto da ručno pogađate nasumične E.164 opsege.

Objavljeni rad o contact-discovery pokazao je zašto je ovo operativno važno: pomoću preciznih tabela telefonskih prefiksa i umerenih resursa, istraživači su mogli da upitaju približno `10%` mobilnih brojeva u SAD na WhatsApp-u i `100%` na Signal-u pre prelaska na ciljano probing.<sup>[[11]](#references)</sup> U praksi, prethodno filtriranje aktivnih account-a održava budžet za silent probe-ove fokusiranim na brojeve koji će zaista dešifrovati pakete.

Novije WhatsApp verzije takođe izlažu `Settings -> Privacy -> Advanced -> Block unknown account messages`.<sup>[[10]](#references)</sup> Tretirajte ovo kao limiter propusnosti: dokumentacija tracker-a navodi da WhatsApp blokira poruke velikog obima sa nepoznatih account-a, ali ne otkriva prag, pa to ne sprečava u potpunosti probe reactions.<sup>[[8]](#references)</sup>

## Recikliranje izmena i brisanja kao covert trigger-a

* **Ponovljena brisanja:** Nakon što je poruka jednom obrisana za sve, dalji delete paketi koji referenciraju isti `message_id` nemaju UI efekat, ali ih svaki uređaj i dalje dešifruje i potvrđuje.
* **Operacije izvan window-a:** WhatsApp u UI-ju nameće ~60 h za brisanje / ~20 min za izmenu; Signal nameće ~48 h. Crafted protocol messages izvan ovih window-a tiho se ignorišu na uređaju žrtve, ali se receipts ipak šalju, pa attacker može neograničeno dugo da probe-uje nakon završetka konverzacije.
* **Invalid payloads:** Rad navodi da se invalid poruke i dalje mogu potvrditi; tačno ponašanje za malformed bodies ili purged IDs zavisi od implementacije, pa testirajte pre oslanjanja na to.<sup>[[1]](#references)</sup>

## Multi-device amplification & fingerprinting

* Na WhatsApp-u i Signal-u svaki povezani uređaj (telefon, desktop aplikacija, browser companion) nezavisno dešifruje probe i vraća sopstveni ack. Brojanje potvrda po probe-u otkriva tačan broj uređaja.<sup>[[1]](#references)</sup>
* Ako je uređaj offline, njegova potvrda se stavlja u queue i emituje pri ponovnom povezivanju. Praznine zato leak-uju online/offline cikluse, pa čak i rasporede putovanja (npr. desktop receipts prestaju tokom putovanja).
* RTT distribucije se razlikuju po platformi i okruženju jer OS, model, client i network conditions utiču na timing. Grupisanje RTT-ova (npr. k-means na karakteristikama medijane/varijanse) omogućava označavanje uređaja kao „Android handset“, „iOS handset“, „Electron desktop“ itd.
* Pošto sender mora da preuzme inventar ključeva primaoca pre encryption-a, attacker takođe može da prati kada se uparuju novi uređaji; nagli porast broja uređaja ili nova RTT grupa snažan je indikator.<sup>[[1]](#references)</sup>

## Sampling cadence, queueing i stacked receipts

* **WhatsApp burst tolerance:** Objavljena merenja navode da je WhatsApp prihvatao silent-reaction burst-ove brzinom od jednog probe-a na svakih `50 ms`, bez očiglednog server-side queueing-a. To je korisno za kratke calibration burst-ove, brzo prebrojavanje uređaja ili brzo pokretanje drain attack-a.
* **Signal long-run queueing:** Signal je tolerisao kratke burst-ove, ali je počinjao da stavlja u queue saobraćaj koji je trajao i sadržao više probe-ova u sekundi. Za dugotrajno monitoring održavajte cadence oko `1 Hz` (ili niže), tako da svaka potvrda i dalje odražava trenutno stanje uređaja, umesto pražnjenja backlog-a.
* **Reconnect artefacts:** Kada se uređaj vrati online, neki klijenti grupišu ili ubrzano šalju više odloženih potvrda. Tretirajte te burst-ove potvrda kao marker promene stanja, a ne kao nezavisne RTT uzorke, u suprotnom će vaš clustering / `active` naspram `idle` classifier previše odgovarati reconnect šumu.<sup>[[1]](#references)</sup>

## Zaključivanje ponašanja iz RTT tragova

1. Uzorkujte na ≥1 Hz da biste uhvatili efekte OS scheduling-a. Kod WhatsApp-a na iOS-u, RTT-ovi <1 s snažno koreliraju sa uključenim ekranom/foreground-om, dok RTT-ovi >1 s koreliraju sa isključenim ekranom/background throttling-om.
2. Izgradite jednostavne classifiers (thresholding ili two-cluster k-means) koji svaki RTT označavaju kao „active“ ili „idle“. Grupisanje oznaka u streak-ove omogućava zaključivanje vremena odlaska na spavanje, putovanja, radnog vremena ili aktivnosti desktop companion-a.
3. Korelirajte istovremene probe-ove usmerene ka svakom uređaju da biste videli kada korisnici prelaze sa mobile-a na desktop, kada companions odlaze offline i da li aplikacija primenjuje rate limiting preko push-a ili persistent socket-a.
4. U realnim mrežama izbegavajte jedan hardcoded prag od `1 s`. Bootstrap-ujte svaki uređaj kratkim warm-up window-om i održavajte rolling baseline (na primer, device-activity-tracker PoC koristi `threshold = 0.9 * median RTT`), tako da Wi-Fi/cellular drift ne obori vaš classifier.<sup>[[1]](#references)[[8]](#references)</sup>

## Zaključivanje lokacije iz RTT-a isporuke

Isti timing primitive može se ponovo iskoristiti za zaključivanje gde se primalac nalazi, a ne samo da li je aktivan. Rad `Hope of Delivery` pokazao je da training na RTT distribucijama za poznate lokacije primaoca omogućava attacker-u da kasnije klasifikuje lokaciju žrtve samo na osnovu delivery confirmations:<sup>[[2]](#references)</sup>

* Izgradite baseline za istu metu dok se nalazi na nekoliko poznatih mesta (kuća, kancelarija, kampus, država A naspram države B itd.).
* Za svaku lokaciju prikupite mnogo normalnih message RTT-ova i izvucite jednostavne features kao što su medijana, varijansa ili percentile buckets.
* Tokom stvarnog attack-a uporedite novu probe seriju sa trained clusters. Rad navodi da se često mogu razlikovati čak i lokacije u istom gradu, sa tačnošću od `>80%` u scenariju sa 3 lokacije.
* Ovo najbolje funkcioniše kada attacker kontroliše sender environment i probe-uje pod sličnim network conditions, jer izmerena putanja uključuje access network primaoca, wake-up latency i messenger infrastrukturu.<sup>[[2]](#references)</sup>

Za razliku od silent reaction/edit/delete attack-ova iznad, location inference ne zahteva invalid message IDs niti stealthy state-changing packets. Dovoljne su obične poruke sa normalnim delivery confirmations, pa je kompromis manji stealth, ali šira primenljivost među messengerima.

## Stealthy resource exhaustion

Pošto svaki silent probe mora da bude dešifrovan i potvrđen, neprekidno slanje reaction toggle-ova, invalid edit-ova ili delete-for-everyone paketa stvara application-layer DoS:<sup>[[1]](#references)</sup>

* Primorava radio/modem da svake sekunde šalje/prima podatke → primetno pražnjenje baterije, naročito na idle handset-ima.
* Generiše upstream/downstream saobraćaj koji troši mobile data planove i može da se nadmeće sa latency-sensitive funkcijama kao što su video-pozivi.<sup>[[1]](#references)</sup>
* Veliki invalid payload-i povećavaju processing work, ali rad navodi da je sama kriptografija zanemarljiv deo troška baterije.<sup>[[1]](#references)</sup>
* Na WhatsApp-u invalid reactions prihvataju znatno više podataka nego što normalan emoji sugeriše: objavljena merenja utvrdila su server-side acceptance do približno `1 MB` po reakciji.
* Oversized reactions prestaju da proizvode pouzdane delivery receipts kada body naraste iznad približno `30 bytes`, ali se i dalje prosleđuju i obrađuju pre odbacivanja. Reaction bodies neka budu mali kada su vam potrebni ACK-ovi; povećajte ih samo kada je cilj čisto drain-ovanje ili covert one-way transport.
* Javna merenja dostigla su približno `3.7 MB/s` (`~13.3 GB/h`) saobraćaja žrtve u ovom režimu.

## References

- [1] [Careless Whisper: Iskorišćavanje tihih potvrda isporuke za praćenje korisnika u mobilnim Instant Messenger-ima](https://arxiv.org/html/2411.11194v4)
- [2] [Hope of Delivery: Izdvajanje lokacija korisnika iz mobilnih Instant Messenger-a](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [3] [whatsmeow](https://github.com/tulir/whatsmeow)
- [4] [Cobalt](https://github.com/Auties00/Cobalt)
- [5] [signal-cli](https://github.com/AsamK/signal-cli)
- [6] [signal-cli manpage](https://github.com/AsamK/signal-cli/blob/master/man/signal-cli.1.adoc)
- [7] [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [8] [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)
- [9] [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python)
- [10] [Kako blokirati veliki broj nepoznatih poruka | WhatsApp Help Center](https://faq.whatsapp.com/3379690015658337)
- [11] [Svi brojevi su iz SAD: Zloupotreba contact discovery-ja velikih razmera u mobilnim messengerima](https://www.ndss-symposium.org/ndss-paper/all-the-numbers-are-us-large-scale-abuse-of-contact-discovery-in-mobile-messengers/)
{{#include ../banners/hacktricks-training.md}}
