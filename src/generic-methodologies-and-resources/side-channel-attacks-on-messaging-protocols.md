# Napadi bočnog kanala preko Delivery Receipt-a u E2EE messengerima

{{#include ../banners/hacktricks-training.md}}

Delivery receipt-ovi su obavezni u modernim end-to-end encrypted (E2EE) messengerima jer klijenti moraju da znaju kada je ciphertext dekriptovan kako bi mogli da odbace ratcheting state i ephemeral keys. Server prosleđuje opaque blob-ove, pa device acknowledgements (dupli čekmarkovi) emituje primalac nakon uspešne dekripcije. Merenje round-trip time (RTT) između akcije koju pokrene attacker i odgovarajućeg delivery receipt-a otkriva tajming kanal visoke rezolucije koji leak-uje stanje uređaja, online prisutnost, i može da se zloupotrebi za covert DoS. Multi-device "client-fanout" deployments pojačavaju leak jer svaki registrovani uređaj dekriptuje probe i vraća sopstveni receipt.

## Izvori delivery receipt-a naspram signala vidljivih korisniku

Birajte tipove poruka koji uvek emituju delivery receipt, ali ne prikazuju UI artefakte na žrtvi. Tabela ispod sumira empirijski potvrđeno ponašanje:

| Messenger | Akcija | Delivery receipt | Obaveštenje žrtvi | Napomene |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Text message | ● | ● | Uvek bučno → korisno samo za bootstrap state. |
| | Reaction | ● | ◐ (samo ako se reaguje na poruku žrtve) | Self-reactions i uklanjanja ostaju tihi. |
| | Edit | ● | Platform-dependent silent push | Prozor za edit ≈20 min; i dalje ack-ovan posle isteka. |
| | Delete for everyone | ● | ○ | UI dozvoljava ~60 h, ali kasniji paketi se i dalje ack-uju. |
| **Signal** | Text message | ● | ● | Ista ograničenja kao WhatsApp. |
| | Reaction | ● | ◐ | Self-reactions nevidljive žrtvi. |
| | Edit/Delete | ● | ○ | Server nameće prozor ~48 h, dozvoljava do 10 edita, ali kasni paketi se i dalje ack-uju. |
| **Threema** | Text message | ● | ● | Multi-device receipt-ovi se agregiraju, pa je po jednom probe-u vidljiv samo jedan RTT. |

Legenda: ● = uvek, ◐ = uslovno, ○ = nikad. Ponašanje UI-ja zavisno od platforme je navedeno inline. Po potrebi isključite read receipt-ove, ali delivery receipt-ovi ne mogu da se isključe u WhatsApp-u ili Signal-u.

## Ciljevi attacker-a i modeli

* **G1 – Device fingerprinting:** Prebrojite koliko receipt-ova stiže po probe-u, grupišite RTT-ove da biste zaključili OS/client (Android vs iOS vs desktop), i pratite online/offline prelaze.
* **G2 – Behavioural monitoring:** Tretirajte visoko-frekventni RTT niz (≈1 Hz je stabilno) kao vremensku seriju i izvedite screen on/off, app foreground/background, putovanje naspram radnog vremena, itd.
* **G3 – Resource exhaustion:** Držite radios/CPU svakog uređaja žrtve budnim slanjem beskonačnih tihih probe-ova, praznite bateriju/podatke i pogoršavajte VoIP/RTC kvalitet.

Dva threat actor-a su dovoljna da opišu površinu zloupotrebe:

1. **Creepy companion:** već deli chat sa žrtvom i zloupotrebljava self-reactions, uklanjanja reaction-a ili ponovljene edit/delete operacije vezane za postojeće message ID-jeve.
2. **Spooky stranger:** registruje burner nalog i šalje reaction-e koji referenciraju message ID-jeve koji nikada nisu postojali u lokalnoj konverzaciji; WhatsApp i Signal ih i dalje dekriptuju i potvrđuju iako UI odbacuje promenu stanja, pa prethodni razgovor nije potreban.

## Alati za sirov pristup protokolu

Oslonite se na klijente koji izlažu osnovni E2EE protokol kako biste mogli da pravite pakete van UI ograničenja, navedete proizvoljne `message_id` vrednosti i beležite precizne timestamp-ove:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, WhatsApp Web protocol) ili [Cobalt](https://github.com/Auties00/Cobalt) (mobile-oriented) omogućavaju slanje sirovih `ReactionMessage`, `ProtocolMessage` (edit/delete) i `Receipt` frame-ova uz održavanje double-ratchet state-a u sinhronizaciji.
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) u kombinaciji sa [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) izlaže svaki tip poruke preko CLI/API. Trenutna `signal-cli` sintaksa koristi `sendReaction RECIPIENT --target-author --target-timestamp`; držite `receive` ili `daemon` pokrenut da bi se delivery receipt-ovi zaista prikupljali. Primer self-reaction toggle:
```bash
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --emoji "👍"
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --remove
```
* **Threema:** Izvor Android klijenta dokumentuje kako se delivery receipt-ovi konsoliduju pre nego što napuste uređaj, što objašnjava zašto je side channel tamo praktično bez širine pojasa.
* **Turnkey PoCs:** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker) dolazi sa WhatsApp/Signal backend-ovima, podrazumevano koristi silent delete probe-ove i označava `active` naspram `standby` pomoću rolling-median praga (`RTT < 0.9 * median`). [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python) je lakši WhatsApp-first CLI sa `--delay`, `--concurrent`, CSV/Prometheus exporter-ima i izlazom pogodnim za Grafana-u. Tretirajte oba kao pomoćna sredstva za reconnaissance, a ne kao referentne izvore protokola; važan zaključak je koliko je malo koda potrebno kada postoji sirov pristup klijentu.

Kada custom tooling nije dostupan, i dalje možete da pokrećete tihe akcije iz WhatsApp Web ili Signal Desktop i da sniff-ujete encrypted websocket/WebRTC kanal, ali sirovi API-ji uklanjaju UI kašnjenja i omogućavaju nevalidne operacije.

## Creepy companion: petlja za tiho uzorkovanje

1. Izaberite bilo koju istorijsku poruku koju ste vi napisali u chatu, tako da žrtva nikada ne vidi kako se "reaction" balončići menjaju.
2. Naizmenično šaljite vidljivi emoji i prazan reaction payload (enkodovan kao `""` u WhatsApp protobufs ili `--remove` u signal-cli). Svaki prenos daje device ack uprkos tome što nema UI promene za žrtvu.
3. Zabeležite send time i vreme dolaska svakog delivery receipt-a. Petlja od 1 Hz kao što je sledeća daje per-device RTT trace-ove beskonačno:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. Pošto WhatsApp/Signal prihvataju neograničen broj reaction update-ova, attacker nikada ne mora da objavljuje novi chat sadržaj niti da brine o edit window-ima.

## Spooky stranger: sondiranje proizvoljnih brojeva telefona

1. Registrujte svež WhatsApp/Signal nalog i preuzmite javne identity keys za ciljni broj (što se automatski radi tokom setup-a sesije).
2. Napravite reaction/edit/delete paket koji referencira nasumični `message_id` koji nijedna strana nikada nije videla (WhatsApp prihvata proizvoljne `key.id` GUID-ove; Signal koristi milisekundne timestamp-ove).
3. Pošaljite paket iako thread ne postoji. Uređaji žrtve ga dekriptuju, ne uspeju da uparе osnovnu poruku, odbace promenu stanja, ali i dalje potvrde dolazni ciphertext, šaljući device receipt-ove nazad attacker-u.
4. Ponavljajte kontinuirano da biste izgradili RTT serije bez ikada pojavljivanja na listi chatova žrtve.

Ako prvo treba da otkrijete koji brojevi su registrovani ili želite da pre-seed-ujete device inventory na velikoj skali, povežite ovo sa [contact-discovery / registration oracles](../pentesting-web/registration-vulnerabilities.md) umesto da ručno pogađate nasumične E.164 opsege.

Objavljeni radovi o contact-discovery-ju su pokazali zašto je ovo operativno važno: uz tačne tabele telefonskih prefiksa i skromne resurse, istraživači su mogli da upitaju približno `10%` US mobilnih brojeva na WhatsApp-u i `100%` na Signal-u pre nego što pređu na ciljano sondiranje. U praksi, prethodno filtriranje aktivnih naloga drži budžet za tihe probe fokusiranim na brojeve koji će zaista dekriptovati pakete.

Novije WhatsApp verzije takođe izlažu `Settings -> Privacy -> Advanced -> Block unknown account messages`. Tretirajte to kao ograničenje propusnosti, a ne kao fix: uglavnom šteti trajnom flood-u od strane nepoznatih naloga i nebitno je kada ste već poznat kontakt.

## Recikliranje edit-a i delete-a kao covert trigger-a

* **Repeated deletes:** Nakon što je poruka jednom obrisana-for-everyone, dalji delete paketi koji referenciraju isti `message_id` nemaju UI efekat, ali svaki uređaj i dalje dekriptuje i potvrđuje ih.
* **Out-of-window operacije:** WhatsApp u UI-ju nameće prozor od ~60 h za delete / ~20 min za edit; Signal nameće ~48 h. Izrađene protocol poruke van ovih prozora žrtvin uređaj tiho ignoriše, ali receipt-ovi se i dalje prenose, pa attacker može da sondira i dugo nakon završetka konverzacije.
* **Invalid payloads:** Loše formirani edit body-jevi ili delete-ovi koji referenciraju već očišćene poruke izazivaju isto ponašanje — dekripcija plus receipt, nula korisnički vidljivih artefakata.

## Multi-device pojačanje i fingerprinting

* Svaki povezani uređaj (telefon, desktop app, browser companion) dekriptuje probe nezavisno i vraća sopstveni ack. Brojanje receipt-ova po probe-u otkriva tačan broj uređaja.
* Ako je uređaj offline, njegov receipt se queue-uje i emituje pri reconnect-u. Rupe zato leak-uju online/offline cikluse, pa čak i rasporede putovanja (npr. desktop receipt-ovi prestaju tokom putovanja).
* RTT distribucije se razlikuju po platformi zbog OS power management-a i push wakeup-ova. Grupisanje RTT-ova (npr. k-means nad median/variance feature-ima) može da označi „Android handset", „iOS handset", „Electron desktop", itd.
* Pošto sender mora da preuzme inventory ključeva primaoca pre enkripcije, attacker može takođe da prati kada se novi uređaji uparuju; naglo povećanje broja uređaja ili nova RTT klaster grupa je jak indikator.

## Cadence uzorkovanja, queueing i stacked receipt-ovi

* **WhatsApp burst tolerance:** Objavljena merenja su prijavila da je WhatsApp prihvatao silent-reaction burst-ove brzinom i do jedne probe svakih `50 ms` bez očiglednog server-side queueing-a. To je korisno za kratke kalibracione burst-ove, brzo brojanje uređaja ili brzo pokretanje drain napada.
* **Signal long-run queueing:** Signal je tolerisao kratke burst-ove, ali je počeo da queue-uje održavan multi-probe-per-second saobraćaj. Za dugotrajno praćenje držite cadence oko `1 Hz` (ili niže) tako da svaki receipt i dalje odražava trenutno stanje uređaja umesto pražnjenja backlog-a.
* **Reconnect artefacts:** Kada se uređaj vrati online, neki klijenti batch-uju ili brzo ispuštaju više odloženih receipt-ova. Tretirajte te burst-ove receipt-ova kao marker prelaza stanja, a ne kao nezavisne RTT uzorke, ili će vaš clustering / `active` vs `idle` klasifikator overfit-ovati reconnect noise.

## Zaključivanje ponašanja iz RTT trace-ova

1. Uzorkujte na ≥1 Hz da biste uhvatili OS scheduling efekte. Sa WhatsApp-om na iOS-u, RTT-ovi kraći od 1 s snažno koreliraju sa screen-on/foreground, a duži od 1 s sa screen-off/background throttling-om.
2. Napravite jednostavne klasifikatore (thresholding ili two-cluster k-means) koji svaki RTT označavaju kao "active" ili "idle". Agregirajte oznake u streak-ove da biste izveli vreme odlaska na spavanje, putovanja, radno vreme ili kada je desktop companion aktivan.
3. Korelišite istovremene probe prema svakom uređaju da biste videli kada korisnici prelaze sa mobilnog na desktop, kada companions idu offline i da li app rate limiting potiče od push ili persistent socket-a.
4. U stvarnim mrežama izbegavajte jedan hardcoded `1 s` threshold. Pokrenite bootstrap za svaki uređaj kratkim warm-up prozorom i održavajte rolling baseline (na primer, `threshold = 0.9 * median RTT`) tako da Wi-Fi/cellular drift ne sruši vaš klasifikator.

## Zaključivanje lokacije iz delivery RTT

Isti tajming primitiv može da se preusmeri da zaključi gde se primalac nalazi, a ne samo da li je aktivan. Rad `Hope of Delivery` je pokazao da treniranje na RTT distribucijama za poznate lokacije primaoca omogućava attacker-u da kasnije klasifikuje lokaciju žrtve samo iz delivery potvrda:

* Napravite baseline za isti target dok je na nekoliko poznatih mesta (dom, kancelarija, kampus, zemlja A naspram zemlje B, itd.).
* Za svaku lokaciju prikupite mnogo normalnih message RTT-ova i izdvojite jednostavne feature-e kao što su medijana, varijansa ili percentile buckets.
* Tokom stvarnog napada, uporedite novi probe niz sa treniranim klasterima. Rad navodi da se čak i lokacije u istom gradu često mogu razdvojiti, sa tačnošću `>80%` u setting-u sa 3 lokacije.
* Ovo najbolje radi kada attacker kontroliše sender okruženje i probe-uje pod sličnim mrežnim uslovima, jer mereni put uključuje recipient access network, wake-up latency i messenger infrastrukturu.

Za razliku od tihih reaction/edit/delete napada iznad, zaključivanje lokacije ne zahteva nevažeće message ID-jeve niti stealthy pakete koji menjaju stanje. Obične poruke sa normalnim delivery potvrđivanjem su dovoljne, pa je tradeoff niža stealth karakteristika ali šira primenljivost preko messengera.

## Stealthy resource exhaustion

Pošto svaki tihi probe mora da se dekriptuje i potvrdi, kontinuirano slanje reaction toggle-ova, nevalidnih edit-a ili delete-for-everyone paketa pravi application-layer DoS:

* Primorava radio/modem da šalje/prima svake sekunde → primetan pad baterije, posebno na idle handset-ovima.
* Generiše neograničen upstream/downstream saobraćaj koji troši mobile data planove dok se stapa sa TLS/WebSocket noise-om.
* Zauzima crypto thread-ove i uvodi jitter u latency-sensitive funkcije (VoIP, video calls) iako korisnik nikada ne vidi obaveštenja.
* Na WhatsApp-u, nevažeći reaction-i prihvataju mnogo više podataka nego što sugeriše normalan emoji: objavljena merenja su pokazala server-side prihvatanje do približno `1 MB` po reaction-u.
* Preveliki reaction-i prestaju da daju pouzdane delivery receipt-ove jednom kada body poraste iznad približno `30 bytes`, ali se i dalje prosleđuju i obrađuju pre odbacivanja. Držite reaction body-jeve male kada su vam potrebni ACK-ovi; uvećavajte ih samo kada je cilj čisto drain ili covert one-way transport.
* Javna merenja su dostigla oko `3.7 MB/s` (`~13.3 GB/h`) saobraćaja žrtve u ovom modu.

## Reference

- [Careless Whisper: Exploiting Silent Delivery Receipts to Monitor Users on Mobile Instant Messengers](https://arxiv.org/html/2411.11194v4)
- [Hope of Delivery: Extracting User Locations From Mobile Instant Messengers](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [whatsmeow](https://github.com/tulir/whatsmeow)
- [Cobalt](https://github.com/Auties00/Cobalt)
- [signal-cli](https://github.com/AsamK/signal-cli)
- [signal-cli manpage](https://github.com/AsamK/signal-cli/blob/master/man/signal-cli.1.adoc)
- [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)
- [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python)
- [How to block high volumes of unknown messages | WhatsApp Help Center](https://faq.whatsapp.com/3379690015658337)
- [All the Numbers are US: Large-scale Abuse of Contact Discovery in Mobile Messengers](https://www.ndss-symposium.org/ndss-paper/all-the-numbers-are-us-large-scale-abuse-of-contact-discovery-in-mobile-messengers/)

{{#include ../banners/hacktricks-training.md}}
