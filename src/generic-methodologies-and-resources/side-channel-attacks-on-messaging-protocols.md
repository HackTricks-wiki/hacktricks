# Side-Channel napadi na potvrde isporuke u E2EE messengerima

{{#include ../banners/hacktricks-training.md}}

Potvrde isporuke su obavezne u modernim end-to-end encrypted (E2EE) messengerima jer klijenti moraju da znaju kada je ciphertext dešifrovan, kako bi mogli da odbace stanje ratcheting-a i ephemeral ključeve. Server prosleđuje opaque blob-ove, pa acknowledgements uređaja (dvostruke kvačice) emituje primalac nakon uspešnog dešifrovanja. Merenje round-trip vremena (RTT) između akcije koju pokrene attacker i odgovarajuće potvrde isporuke otkriva timing channel visoke rezolucije koji leak-uje stanje uređaja i online prisutnost i može se zloupotrebiti za covert DoS. Multi-device "client-fanout" deployment-i pojačavaju leakage jer svaki registrovani uređaj dešifruje probe i vraća sopstvenu potvrdu.<sup>[[1]](#references)</sup>

## Izvori potvrda isporuke naspram signala vidljivih korisniku

Izaberite tipove poruka koji uvek emituju potvrdu isporuke, ali žrtvi ne prikazuju UI artefakte. Tabela u nastavku sumira empirijski potvrđeno ponašanje:<sup>[[1]](#references)</sup>

| Messenger | Akcija | Potvrda isporuke | Obaveštenje žrtvi | Napomene |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Tekstualna poruka | ● | ● | Uvek proizvodi šum → korisno samo za bootstrap stanja. |
| | Reaction | ● | ◐ (samo kada se reaguje na poruku žrtve) | Self-reactions i uklanjanja ostaju nečujni. |
| | Izmena | ● | Platform-dependent silent push | Prozor za izmenu ≈20 min; potvrda se i dalje vraća nakon isteka. |
| | Brisanje za sve | ● | ○ | UI dozvoljava ~60 h, ali se kasniji paketi i dalje potvrđuju. |
| **Signal** | Tekstualna poruka | ● | ● | Ista ograničenja kao kod WhatsApp-a. |
| | Reaction | ● | ◐ | Self-reactions su nevidljive žrtvi. |
| | Izmena/brisanje | ● | ○ | Server nameće prozor od ~48 h i dozvoljava do 10 izmena, ali se kasni paketi i dalje potvrđuju. |
| **Threema** | Tekstualna poruka | ● | ● | Potvrde sa više uređaja se agregiraju, pa je vidljiv samo jedan RTT po probe-u. |

Legenda: ● = uvek, ◐ = uslovno, ○ = nikada. Platform-dependent ponašanje UI-ja navedeno je u tekstu. Po potrebi isključite read receipts, ali delivery receipts nije moguće isključiti u WhatsApp-u ili Signal-u.<sup>[[1]](#references)</sup>

## Ciljevi i modeli attackera

* **G1 – Fingerprinting uređaja:** Prebrojte koliko potvrda stiže po probe-u, grupišite RTT-ove da biste zaključili koji se OS/client koristi (Android naspram iOS-a naspram desktopa) i pratite prelaze online/offline.
* **G2 – Behavioral monitoring:** Posmatrajte visokofrekventnu RTT seriju (≈1 Hz je stabilan) kao time-series i zaključujte da li je ekran uključen/isključen, da li je aplikacija u foreground/background režimu, vreme putovanja na posao naspram radnog vremena itd.
* **G3 – Resource exhaustion:** Održavajte radio/CPU svakog uređaja žrtve budnim slanjem neprekidnih silent probe-ova, praznite bateriju i data saobraćaj i pogoršavajte kvalitet VoIP/RTC-a.<sup>[[1]](#references)</sup>

Dva threat actor-a dovoljna su za opis abuse surface-a:<sup>[[1]](#references)</sup>

1. **Creepy companion:** već deli chat sa žrtvom i zloupotrebljava self-reactions, uklanjanja reakcija ili ponovljene izmene/brisanja povezana sa postojećim message ID-jevima.
2. **Spooky stranger:** registruje burner account i šalje reakcije koje referenciraju message ID-jeve koji nikada nisu postojali u lokalnoj konverzaciji; WhatsApp i Signal ih i dalje dešifruju i potvrđuju iako UI odbacuje promenu stanja, pa prethodna konverzacija nije potrebna.

## Tooling za raw protocol pristup

Oslonite se na klijente koji izlažu osnovni E2EE protocol kako biste mogli da kreirate pakete izvan UI ograničenja, navedete proizvoljne `message_id` vrednosti i beležite precizne timestamp-ove:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, WhatsApp Web protocol) ili [Cobalt](https://github.com/Auties00/Cobalt) (mobile-oriented) omogućavaju emitovanje sirovih `ReactionMessage`, `ProtocolMessage` (edit/delete) i `Receipt` frame-ova uz održavanje stanja double-ratchet-a sinhronizovanim.<sup>[[3]](#references)[[4]](#references)</sup>
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) u kombinaciji sa [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) izlaže svaki tip poruke putem CLI/API-ja.<sup>[[5]](#references)[[7]](#references)</sup> Trenutna `signal-cli` sintaksa koristi `sendReaction RECIPIENT --target-author --target-timestamp`; održavajte `receive` ili `daemon` pokrenutim kako bi se delivery receipts zaista prikupljale.<sup>[[6]](#references)</sup> Primer self-reaction toggle-a:
```bash
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --emoji "👍"
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --remove
```
* **Threema:** Source Android client-a dokumentuje kako se delivery receipts konsoliduju pre nego što napuste uređaj, objašnjavajući zašto side channel tamo ima zanemarljiv bandwidth.<sup>[[1]](#references)</sup>
* **Turnkey PoCs:** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker) isporučuje WhatsApp/Signal backends, podrazumevano koristi silent delete probe-ove i označava `active` naspram `standby` pomoću rolling-median threshold-a (`RTT < 0.9 * median`).<sup>[[8]](#references)</sup> [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python) je jednostavniji WhatsApp-first CLI sa opcijama `--delay`, `--concurrent`, CSV/Prometheus exporter-ima i Grafana-friendly output-om.<sup>[[9]](#references)</sup> Oba alata tretirajte kao reconnaissance helpers, a ne kao protocol reference; važan zaključak je koliko je malo koda potrebno kada postoji raw client pristup.

Kada custom tooling nije dostupan, i dalje možete pokretati silent akcije iz WhatsApp Web-a ili Signal Desktop-a i sniff-ovati encrypted websocket/WebRTC channel, ali raw API-ji uklanjaju UI kašnjenja i omogućavaju nevažeće operacije.

## Creepy companion: silent sampling loop

1. Izaberite bilo koju istorijsku poruku koju ste vi poslali u chatu, tako da žrtva nikada ne vidi promenu "reaction" balončića.
2. Naizmenično šaljite vidljivi emoji i prazan reaction payload (kodiran kao `""` u WhatsApp protobuf-ima ili kao `--remove` u signal-cli-ju). Svaki prenos proizvodi device ack uprkos tome što za žrtvu nema UI delta-e.
3. Zabeležite vreme slanja i svaki dolazak delivery receipt-a. 1 Hz loop poput sledećeg daje per-device RTT tragove neograničeno:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. Pošto WhatsApp/Signal prihvataju neograničene reaction update-e, attacker nikada ne mora da objavi novi chat sadržaj niti da brine o edit window-ima.<sup>[[1]](#references)</sup>

## Spooky stranger: probing proizvoljnih telefonskih brojeva

1. Registrujte novi WhatsApp/Signal account i preuzmite javne identity ključeve za ciljani broj (to se automatski obavlja tokom session setup-a).
2. Kreirajte reaction/edit/delete paket koji referencira nasumični `message_id` koji nijedna strana nikada nije videla (WhatsApp prihvata proizvoljne `key.id` GUID-ove; Signal koristi timestamp-ove u milisekundama).
3. Pošaljite paket iako ne postoji thread. Uređaji žrtve ga dešifruju, ne uspevaju da pronađu osnovnu poruku, odbacuju promenu stanja, ali i dalje potvrđuju incoming ciphertext i šalju device receipts nazad attacker-u.
4. Ponavljajte postupak neprekidno da biste izgradili RTT serije, a da se nikada ne pojavite na listi chat-ova žrtve.<sup>[[1]](#references)</sup>

Ako najpre morate da otkrijete koji su brojevi registrovani ili želite da unapred popunite device inventory-je u velikom obimu, povežite ovo sa [contact-discovery / registration oracles](../pentesting-web/registration-vulnerabilities.md), umesto ručnog pogađanja nasumičnih E.164 opsega.

Objavljeni radovi o contact-discovery-ju pokazali su zašto je ovo operativno važno: uz precizne tabele telefonskih prefiksa i umerene resurse, istraživači su mogli da upitaju približno `10%` američkih mobilnih brojeva na WhatsApp-u i `100%` na Signal-u pre nego što pređu na ciljano probing.<sup>[[11]](#references)</sup> U praksi, prethodno filtriranje aktivnih account-a održava budžet za silent probe usmerenim na brojeve koji će zaista dešifrovati pakete.

Novije WhatsApp verzije takođe izlažu `Settings -> Privacy -> Advanced -> Block unknown account messages`.<sup>[[10]](#references)</sup> Tretirajte ovo kao limiter throughput-a, a ne kao fix: uglavnom otežava dugotrajni flooding koji vrši samo stranger i nije relevantno kada ste već poznat contact.

## Recikliranje izmena i brisanja kao covert trigger-a

* **Ponovljena brisanja:** Nakon što je poruka jednom obrisana za sve, dodatni delete paketi koji referenciraju isti `message_id` nemaju UI efekat, ali ih svaki uređaj i dalje dešifruje i potvrđuje.
* **Operacije izvan window-a:** WhatsApp nameće prozore od ~60 h za brisanje i ~20 min za izmenu u UI-ju; Signal nameće ~48 h. Crafted protocol poruke izvan ovih prozora se na uređaju žrtve tiho ignorišu, ali se receipts ipak prenose, pa attacker-i mogu neograničeno da probe-uju dugo nakon završetka konverzacije.
* **Nevažeći payload-i:** Malformed edit body-ji ili brisanja koja referenciraju već očišćene poruke izazivaju isto ponašanje—dešifrovanje plus receipt, bez ikakvih artefakata vidljivih korisniku.<sup>[[1]](#references)</sup>

## Multi-device amplification & fingerprinting

* Svaki pridruženi uređaj (telefon, desktop aplikacija, browser companion) nezavisno dešifruje probe i vraća sopstveni ack. Prebrojavanje potvrda po probe-u otkriva tačan broj uređaja.
* Ako je uređaj offline, njegova potvrda se stavlja u queue i emituje pri ponovnom povezivanju. Praznine zato leak-uju online/offline cikluse, pa čak i rasporede putovanja (npr. desktop receipts prestaju tokom putovanja).
* RTT distribucije se razlikuju po platformi zbog OS power management-a i push wakeup-a. Grupisanje RTT-ova (npr. k-means na median/variance features) omogućava označavanje uređaja kao što su “Android handset", “iOS handset", “Electron desktop" itd.
* Pošto sender mora da preuzme key inventory primaoca pre šifrovanja, attacker takođe može da prati kada se uparuju novi uređaji; nagli porast broja uređaja ili novi RTT cluster predstavlja snažan indikator.<sup>[[1]](#references)</sup>

## Sampling cadence, queueing i stacked receipts

* **WhatsApp burst tolerance:** Objavljena merenja navode da je WhatsApp prihvatao burst-ove silent reaction-a brzinom od jednog probe-a na svakih `50 ms` bez očiglednog server-side queueing-a. To je korisno za kratke calibration burst-ove, brzo prebrojavanje uređaja ili brzo pokretanje drain attack-a.
* **Signal long-run queueing:** Signal je tolerisao kratke burst-ove, ali je počinjao da stavlja u queue sustained saobraćaj sa više probe-ova u sekundi. Za dugotrajni monitoring održavajte cadence oko `1 Hz` (ili niže), tako da svaki receipt i dalje odražava trenutno stanje uređaja umesto pražnjenja backlog-a.
* **Reconnect artefacts:** Kada se uređaj vrati online, neki klijenti grupišu ili brzo flush-uju više odloženih receipts-a. Tretirajte te burst-ove potvrda kao marker state transition-a, a ne kao nezavisne RTT samples, inače će vaš clustering / `active` naspram `idle` classifier overfit-ovati reconnect noise.<sup>[[1]](#references)</sup>

## Zaključivanje ponašanja iz RTT tragova

1. Uzimajte samples frekvencijom ≥1 Hz da biste obuhvatili efekte OS scheduling-a. Kod WhatsApp-a na iOS-u, RTT-ovi kraći od 1 s snažno koreliraju sa uključenim ekranom/foreground režimom, dok RTT-ovi duži od 1 s koreliraju sa isključenim ekranom/background throttling-om.
2. Napravite jednostavne classifiers (thresholding ili two-cluster k-means) koji svaki RTT označavaju kao "active" ili "idle". Grupisanje oznaka u streaks omogućava izvođenje vremena odlaska na spavanje, putovanja na posao, radnog vremena ili perioda kada je desktop companion aktivan.
3. Korelišite istovremene probe-ove usmerene ka svakom uređaju da biste videli kada korisnici prelaze sa mobilnog na desktop, kada companions odlaze offline i da li je aplikacija rate limited push-om ili persistent socket-om.
4. U realnim mrežama izbegavajte jedan hardcoded `1 s` threshold. Bootstrap-ujte svaki uređaj kratkim warm-up window-om i održavajte rolling baseline (na primer, `threshold = 0.9 * median RTT`) kako Wi-Fi/cellular drift ne bi urušio vaš classifier.<sup>[[1]](#references)</sup>

## Zaključivanje lokacije iz delivery RTT-a

Isti timing primitive može se ponovo iskoristiti za zaključivanje gde se primalac nalazi, a ne samo da li je aktivan. Rad `Hope of Delivery` pokazao je da training na RTT distribucijama za poznate lokacije primaoca omogućava attacker-u da kasnije klasifikuje lokaciju žrtve samo na osnovu delivery confirmations:<sup>[[2]](#references)</sup>

* Napravite baseline za istu metu dok se nalazi na nekoliko poznatih mesta (kod kuće, u kancelariji, na kampusu, u zemlji A naspram zemlje B itd.).
* Za svaku lokaciju prikupite veliki broj normalnih message RTT-ova i izdvojite jednostavne features kao što su median, variance ili percentile buckets.
* Tokom stvarnog attack-a uporedite novu probe seriju sa trained cluster-ima. Rad navodi da se često mogu razdvojiti čak i lokacije u istom gradu, sa tačnošću od `>80%` u scenariju sa 3 lokacije.
* Ovo najbolje funkcioniše kada attacker kontroliše sender environment i probe-uje pod sličnim network conditions, jer izmerena putanja obuhvata access network primaoca, wake-up latency i messenger infrastructure.<sup>[[2]](#references)</sup>

Za razliku od prethodno opisanih silent reaction/edit/delete napada, location inference ne zahteva nevažeće message ID-jeve niti stealthy state-changing pakete. Dovoljne su obične poruke sa normalnim delivery confirmations, pa je kompromis manja stealth karakteristika, ali šira primenljivost kroz različite messengere.

## Stealthy resource exhaustion

Pošto svaki silent probe mora biti dešifrovan i potvrđen, neprekidno slanje reaction toggle-a, nevažećih izmena ili delete-for-everyone paketa stvara application-layer DoS:<sup>[[1]](#references)</sup>

* Prisiljava radio/modem da svake sekunde emituje/prima podatke → primetno pražnjenje baterije, naročito na idle handset-ima.
* Generiše unmetered upstream/downstream saobraćaj koji troši mobile data planove, stapajući se sa TLS/WebSocket šumom.
* Zauzima crypto threads i uvodi jitter u latency-sensitive funkcije (VoIP, video pozive), iako korisnik nikada ne vidi obaveštenja.
* Na WhatsApp-u, invalid reactions prihvataju znatno više podataka nego što bi normalan emoji sugerisao: objavljena merenja pronašla su server-side prihvatanje do približno `1 MB` po reakciji.
* Oversized reactions prestaju da proizvode pouzdane delivery receipts kada body preraste približno `30 bytes`, ali se i dalje prosleđuju i obrađuju pre odbacivanja. Reaction body-je održavajte malim kada su vam potrebni ACK-ovi; povećajte ih samo kada je cilj čisto drain-ovanje ili covert one-way transport.
* Javna merenja dostigla su približno `3.7 MB/s` (`~13.3 GB/h`) saobraćaja žrtve u ovom režimu.

## References

- [1] [Careless Whisper: Exploiting Silent Delivery Receipts to Monitor Users on Mobile Instant Messengers](https://arxiv.org/html/2411.11194v4)
- [2] [Hope of Delivery: Extracting User Locations From Mobile Instant Messengers](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [3] [whatsmeow](https://github.com/tulir/whatsmeow)
- [4] [Cobalt](https://github.com/Auties00/Cobalt)
- [5] [signal-cli](https://github.com/AsamK/signal-cli)
- [6] [signal-cli manpage](https://github.com/AsamK/signal-cli/blob/master/man/signal-cli.1.adoc)
- [7] [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [8] [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)
- [9] [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python)
- [10] [How to block high volumes of unknown messages | WhatsApp Help Center](https://faq.whatsapp.com/3379690015658337)
- [11] [All the Numbers are US: Large-scale Abuse of Contact Discovery in Mobile Messengers](https://www.ndss-symposium.org/ndss-paper/all-the-numbers-are-us-large-scale-abuse-of-contact-discovery-in-mobile-messengers/)

{{#include ../banners/hacktricks-training.md}}
