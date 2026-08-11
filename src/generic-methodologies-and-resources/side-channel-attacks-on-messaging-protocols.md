# Side-Channel napadi putem potvrda isporuke u E2EE Messenger aplikacijama

{{#include ../banners/hacktricks-training.md}}

Potvrde isporuke su obavezne u modernim end-to-end encrypted (E2EE) Messenger aplikacijama, jer klijenti moraju da znaju kada je ciphertext dešifrovan kako bi mogli da odbace ratcheting state i ephemeral keys. Server prosleđuje opaque blobs, pa acknowledgements uređaja (dvostruke kvačice) emituje primalac nakon uspešnog dešifrovanja. Merenje round-trip time (RTT) između akcije koju je pokrenuo attacker i odgovarajuće potvrde isporuke otkriva timing channel visoke rezolucije koji leakuje stanje uređaja i online prisustvo i može se zloupotrebiti za covert DoS. Multi-device "client-fanout" deployment-i povećavaju leakage jer svaki registrovani uređaj dešifruje probe i vraća sopstvenu potvrdu.<sup>[[1]](#references)</sup>

## Izvori potvrda isporuke nasuprot signalima vidljivim korisniku

Izaberite tipove poruka koji uvek emituju potvrdu isporuke, ali ne prikazuju UI artefakte na uređaju victim-a. Tabela u nastavku prikazuje empirijski potvrđeno ponašanje:<sup>[[1]](#references)</sup>

| Messenger | Akcija | Potvrda isporuke | Obaveštenje victim-a | Napomene |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Text message | ● | ● | Uvek noisy → korisno samo za bootstrap state-a. |
| | Reaction | ● | ◐ (samo kada se reaguje na poruku victim-a) | Self-reactions i uklanjanja ostaju nevidljivi. |
| | Edit | ● | Platform-dependent silent push | Edit window ≈20 min; ack se i dalje šalje nakon isteka. |
| | Delete for everyone | ● | ○ | UI dozvoljava ~60 h, ali se kasniji packet-i i dalje ack-uju. |
| **Signal** | Text message | ● | ● | Ista ograničenja kao kod WhatsApp-a. |
| | Reaction | ● | ◐ | Self-reactions su nevidljive victim-u. |
| | Edit/Delete | ● | ○ | Server nameće ~48 h window, dozvoljava do 10 edit-a, ali se kasni packet-i i dalje ack-uju. |
| **Threema** | Text message | ● | ● | Multi-device potvrde se agregiraju, pa je vidljiv samo jedan RTT po probe-u. |

Legenda: ● = uvek, ◐ = uslovno, ○ = nikada. Platform-dependent UI ponašanje je navedeno u tekstu. Isključite read receipts ako je potrebno, ali delivery receipts ne mogu da se isključe u WhatsApp-u ili Signal-u.<sup>[[1]](#references)</sup>

## Ciljevi i modeli attacker-a

* **G1 – Fingerprinting uređaja:** Prebrojte koliko potvrda stiže po probe-u, grupišite RTT-ove da biste zaključili OS/client (Android nasuprot iOS-u nasuprot desktop-u) i pratite prelaze online/offline stanja.
* **G2 – Behavioural monitoring:** Posmatrajte high-frequency RTT seriju (≈1 Hz je stabilan) kao time-series i zaključujte da li je ekran uključen/isključen, da li je aplikacija u foreground/background-u, vreme putovanja nasuprot radnom vremenu itd.
* **G3 – Resource exhaustion:** Održavajte radio/CPU svakog uređaja victim-a aktivnim slanjem neprekidnih silent probe-ova, čime se prazni baterija, troši data i smanjuje kvalitet video-poziva.<sup>[[1]](#references)</sup>

Dva threat actor-a dovoljna su za opis abuse surface-a:<sup>[[1]](#references)</sup>

1. **Creepy companion:** već deli chat sa victim-om i zloupotrebljava self-reactions, uklanjanja reakcija ili ponovljene edit/delete akcije povezane sa postojećim message ID-jevima.
2. **Spooky stranger:** registruje burner account i šalje reakcije koje referenciraju message ID-jeve koji nikada nisu postojali u lokalnoj konverzaciji; WhatsApp i Signal ih i dalje dešifruju i acknowledge-uju iako UI odbacuje promenu state-a, pa prethodna konverzacija nije potrebna.

## Tooling za raw protocol access

Oslonite se na klijente koji izlažu dovoljno underlying E2EE protocol-a za kreiranje podržanih packet-a izvan UI ograničenja i logovanje preciznih timestamp-ova; arbitrary message ID-jeve treba proveriti za svaku implementaciju:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, WhatsApp Web multidevice API) dokumentuje slanje i prijem delivery receipt-a; [Cobalt](https://github.com/Auties00/Cobalt) (unofficial Java/Kotlin Web i mobile API) dokumentuje message operacije kao što su reacting, editing i deleting. Koristite njihove dokumentovane API-je umesto pretpostavke da je svaki internal frame izložen.<sup>[[3]](#references)[[4]](#references)</sup>
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) izlaže CLI, JSON-RPC i D-Bus interfejse, dok je [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) Java biblioteka za komunikaciju sa Signal-om.<sup>[[5]](#references)[[7]](#references)</sup> Trenutna `signal-cli` sintaksa koristi `sendReaction RECIPIENT --target-author --target-timestamp`; održavajte `receive` ili `daemon` aktivnim kako bi se protocol updates i dalje obrađivali.<sup>[[6]](#references)</sup> Primer self-reaction toggle-a:
```bash
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --emoji "👍"
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --remove
```
* **Threema:** Merenja u Careless Whisper radu pokazala su da su delivery receipt-i sinhronizovani između uređaja, pa se izlaže samo jedna potvrda po poruci čak i u multi-device setup-u.<sup>[[1]](#references)</sup>
* **Turnkey PoC-ovi:** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker) sadrži WhatsApp/Signal backende, podrazumevano koristi silent delete probe-ove i označava `active` nasuprot `standby` stanju pomoću rolling-median threshold-a (`RTT < 0.9 * median`).<sup>[[8]](#references)</sup> [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python) je jednostavniji WhatsApp-first CLI sa opcijama `--delay`, `--concurrent`, CSV/Prometheus exporter-ima i output-om prilagođenim za Grafana-u.<sup>[[9]](#references)</sup> Oba alata tretirajte kao reconnaissance helpers, a ne kao protocol references; važan zaključak je koliko je malo koda potrebno kada postoji raw client access.

Kada custom tooling nije dostupan, official client-i ili browser developer tools i dalje mogu da pokrenu silent akcije i izlože timing encrypted traffic-a; raw API-ji uklanjaju UI delays i dozvoljavaju invalid operations.<sup>[[1]](#references)</sup>

## Creepy companion: silent sampling loop

1. Izaberite bilo koju istorijsku poruku koju ste vi poslali u chatu, tako da victim nikada ne vidi promenu "reaction" balloons.
2. Naizmenično šaljite vidljivi emoji i prazan reaction payload (kodiran kao `""` u WhatsApp protobuf-ovima ili `--remove` u signal-cli). Svaki transmission daje device ack uprkos tome što za victim-a nema UI delta-e.
3. Zabeležite vreme slanja i svaki dolazak delivery receipt-a. 1 Hz loop poput sledećeg daje RTT trace-ove po uređaju neograničeno:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. Pošto WhatsApp/Signal prihvataju neograničene reaction updates, attacker nikada ne mora da objavi novi chat content niti da brine o edit window-ovima.<sup>[[1]](#references)</sup>

## Spooky stranger: probing arbitrary phone numbers

1. Registrujte svež WhatsApp/Signal account i preuzmite public identity keys za ciljni broj (to se automatski obavlja tokom session setup-a).
2. Kreirajte reaction packet koji referencira nasumični `message_id` koji nijedna strana nikada nije videla; rad navodi da WhatsApp i Signal prihvataju takve reakcije i i dalje generišu delivery receipt-e.<sup>[[1]](#references)</sup>
3. Pošaljite packet iako thread ne postoji. Uređaji victim-a ga dešifruju, ne uspevaju da pronađu osnovnu poruku, odbacuju state change, ali i dalje acknowledge-uju incoming ciphertext i šalju device receipt-e attacker-u.
4. Ponavljajte kontinuirano kako biste izgradili RTT serije bez prethodne konverzacije ili vidljivog obaveštenja.<sup>[[1]](#references)</sup>

Ako prvo treba da otkrijete koji su brojevi registrovani ili želite da unapred prikupite device inventories at scale, povežite ovo sa [contact-discovery / registration oracles](../pentesting-web/registration-vulnerabilities.md), umesto ručnog pogađanja nasumičnih E.164 opsega.

Objavljeni rad o contact-discovery-ju pokazao je zašto je ovo operativno važno: sa preciznim phone-prefix tabelama i umerenim resursima, istraživači su mogli da upitaju približno `10%` US mobilnih brojeva na WhatsApp-u i `100%` na Signal-u pre nego što pređu na targeted probing.<sup>[[11]](#references)</sup> U praksi, predfiltriranje aktivnih account-a održava budžet za silent probe usmerenim na brojeve koji će zaista dešifrovati packet-e.

Noviji WhatsApp build-ovi takođe izlažu `Settings -> Privacy -> Advanced -> Block unknown account messages`.<sup>[[10]](#references)</sup> Tretirajte ovo kao throughput limiter: tracker documentation navodi da WhatsApp blokira high-volume poruke sa unknown account-a, ali ne otkriva threshold, pa to ne sprečava u potpunosti probe reactions.<sup>[[8]](#references)</sup>

## Recycling edits i deletes kao covert triggers

* **Repeated deletes:** Nakon što je poruka jednom obrisana opcijom delete-for-everyone, naredni delete packet-i koji referenciraju isti `message_id` nemaju UI effect, ali ih svaki uređaj i dalje dešifruje i acknowledge-uje.
* **Out-of-window operations:** WhatsApp nameće ~60 h delete / ~20 min edit window u UI-ju; Signal nameće ~48 h. Crafted protocol messages izvan ovih window-ova se na uređaju victim-a tiho ignorišu, ali se receipt-i ipak šalju, pa attacker može neograničeno da probe-uje dugo nakon završetka konverzacije.
* **Invalid payloads:** Rad navodi da invalid messages i dalje mogu biti acknowledge-ovani; konkretno ponašanje za malformed bodies ili purged ID-jeve zavisi od implementacije, pa ga testirajte pre oslanjanja na njega.<sup>[[1]](#references)</sup>

## Multi-device amplification & fingerprinting

* Na WhatsApp-u i Signal-u svaki povezani uređaj (telefon, desktop app, browser companion) nezavisno dešifruje probe i vraća sopstveni ack. Brojanje receipt-a po probe-u otkriva tačan broj uređaja.<sup>[[1]](#references)</sup>
* Ako je uređaj offline, njegov receipt se stavlja u queue i emituje pri ponovnom povezivanju. Gaps zato leak-uju online/offline cycles, pa čak i commuting schedules (npr. desktop receipt-i prestaju tokom putovanja).
* RTT distributions se razlikuju po platformi i okruženju jer OS, model, client i network conditions utiču na timing. Grupisanje RTT-ova (npr. k-means na median/variance features) omogućava označavanje uređaja kao „Android handset“, „iOS handset“, „Electron desktop“ itd.
* Pošto sender mora da preuzme key inventory primaoca pre encrypting-a, attacker takođe može da prati kada se uparuju novi uređaji; nagli porast broja uređaja ili novi RTT cluster snažan je indikator.<sup>[[1]](#references)</sup>

## Sampling cadence, queueing i stacked receipts

* **WhatsApp burst tolerance:** Objavljena merenja navode da je WhatsApp prihvatao silent-reaction burst-ove brzinom od jednog probe-a na svakih `50 ms` bez očiglednog server-side queueing-a. To je korisno za kratke calibration burst-ove, brzo prebrojavanje uređaja ili brzo pokretanje drain attack-a.
* **Signal long-run queueing:** Signal je tolerisao kratke burst-ove, ali je počinjao da queue-uje sustained traffic sa više probe-ova u sekundi. Za dugotrajni monitoring održavajte cadence oko `1 Hz` (ili niže), tako da svaki receipt i dalje odražava trenutno stanje uređaja umesto pražnjenja backlog-a.
* **Reconnect artefacts:** Kada se uređaj vrati online, neki klijenti batch-uju ili brzo flush-uju više odloženih receipt-a. Tretirajte te receipt burst-ove kao state-transition marker, a ne kao nezavisne RTT samples, inače će vaš clustering / `active` nasuprot `idle` classifier overfit-ovati reconnect noise.<sup>[[1]](#references)</sup>

## Zaključivanje ponašanja iz RTT trace-ova

1. Uzimajte samples frekvencijom ≥1 Hz kako biste obuhvatili efekte OS scheduling-a. Kod WhatsApp-a na iOS-u, RTT-ovi <1 s snažno koreliraju sa uključenim ekranom/foreground-om, a >1 s sa screen-off/background throttling-om.
2. Napravite jednostavne classifiers (thresholding ili two-cluster k-means) koji svaki RTT označavaju kao "active" ili "idle". Grupisanje oznaka u streaks omogućava zaključivanje vremena spavanja, putovanja, radnog vremena ili aktivnosti desktop companion-a.
3. Korelišite simultane probe-ove ka svakom uređaju da biste videli kada korisnici prelaze sa mobile-a na desktop, kada companions odlaze offline i da li je aplikacija rate limited push-om nasuprot persistent socket-om.
4. U realnim networks izbegavajte jedan hardcoded `1 s` threshold. Bootstrap-ujte svaki uređaj kratkim warm-up window-om i održavajte rolling baseline (na primer, device-activity-tracker PoC koristi `threshold = 0.9 * median RTT`), tako da Wi-Fi/cellular drift ne uruši vaš classifier.<sup>[[1]](#references)[[8]](#references)</sup>

## Zaključivanje lokacije iz delivery RTT-a

Isti timing primitive može se ponovo upotrebiti za zaključivanje gde se recipient nalazi, a ne samo da li je active. `Hope of Delivery` rad pokazao je da training na RTT distributions za poznate lokacije recipient-a omogućava attacker-u da kasnije klasifikuje lokaciju victim-a samo na osnovu delivery confirmations:<sup>[[2]](#references)</sup>

* Napravite baseline za isti target dok se nalazi na nekoliko poznatih mesta (kuća, kancelarija, kampus, država A nasuprot državi B itd.).
* Za svaku lokaciju prikupite mnogo normalnih message RTT-ova i izdvojite jednostavne features kao što su median, variance ili percentile buckets.
* Tokom realnog attack-a uporedite novu probe seriju sa trained cluster-ima. Rad navodi da se često mogu razlikovati čak i lokacije u istom gradu, sa tačnošću `>80%` u postavci sa 3 lokacije.
* Ovo najbolje funkcioniše kada attacker kontroliše sender environment i probe-uje pod sličnim network conditions, jer izmerena putanja uključuje access network recipient-a, wake-up latency i Messenger infrastructure.<sup>[[2]](#references)</sup>

Za razliku od prethodno opisanih silent reaction/edit/delete attack-a, location inference ne zahteva invalid message ID-jeve ili stealthy state-changing packet-e. Obične poruke sa normalnim delivery confirmations dovoljne su, pa je tradeoff manja stealthiness, ali šira primenljivost kroz različite Messenger aplikacije.

## Stealthy resource exhaustion

Pošto svaki silent probe mora biti dešifrovan i acknowledge-ovan, kontinuirano slanje reaction toggle-ova, invalid edit-a ili delete-for-everyone packet-a stvara application-layer DoS:<sup>[[1]](#references)</sup>

* Prisiljava radio/modem da šalje/prima svake sekunde → primetno trošenje baterije, naročito na idle handset-ima.
* Generiše upstream/downstream traffic koji troši mobile data planove i može da se takmiči sa latency-sensitive funkcijama kao što su video-pozivi.<sup>[[1]](#references)</sup>
* Veliki invalid payload-i povećavaju processing work, ali rad navodi da je sama cryptography zanemarljiv deo troška baterije.<sup>[[1]](#references)</sup>
* Na WhatsApp-u invalid reactions prihvataju mnogo više data nego što bi normalan emoji sugerisao: objavljena merenja pokazala su server-side acceptance do približno `1 MB` po reakciji.
* Oversized reactions prestaju da proizvode pouzdane delivery receipt-e kada body naraste iznad približno `30 bytes`, ali se i dalje prosleđuju i obrađuju pre discard-a. Reaction bodies neka budu mali kada su vam potrebni ACK-ovi; povećajte ih samo kada je cilj pure drain ili covert one-way transport.
* Javna merenja dostigla su približno `3.7 MB/s` (`~13.3 GB/h`) victim traffic-a u ovom modu.

## References

- [1] [Careless Whisper: Exploatacija silent delivery receipt-a za monitoring korisnika na mobilnim instant Messenger aplikacijama](https://arxiv.org/html/2411.11194v4)
- [2] [Hope of Delivery: Izdvajanje lokacija korisnika iz mobilnih instant Messenger aplikacija](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [3] [whatsmeow](https://github.com/tulir/whatsmeow)
- [4] [Cobalt](https://github.com/Auties00/Cobalt)
- [5] [signal-cli](https://github.com/AsamK/signal-cli)
- [6] [signal-cli manpage](https://github.com/AsamK/signal-cli/blob/master/man/signal-cli.1.adoc)
- [7] [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [8] [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)
- [9] [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python)
- [10] [Kako blokirati velike količine nepoznatih poruka | WhatsApp Help Center](https://faq.whatsapp.com/3379690015658337)
- [11] [Svi brojevi su iz SAD: Abuse contact-discovery-ja velikih razmera u mobilnim Messenger aplikacijama](https://www.ndss-symposium.org/ndss-paper/all-the-numbers-are-us-large-scale-abuse-of-contact-discovery-in-mobile-messengers/)
{{#include ../banners/hacktricks-training.md}}
