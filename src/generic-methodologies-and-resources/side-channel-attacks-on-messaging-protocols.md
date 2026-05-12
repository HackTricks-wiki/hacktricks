# Napadi bočnim kanalom preko delivery receipts u E2EE messengerima

{{#include ../banners/hacktricks-training.md}}

Delivery receipts su obavezni u savremenim end-to-end encrypted (E2EE) messengerima jer klijenti moraju da znaju kada je ciphertext dekriptovan, kako bi mogli da odbace ratcheting state i ephemeral keys. Server prosleđuje opaque blobs, pa device acknowledgements (double checkmarks) emituje primalac nakon uspešne dekripcije. Merenje round-trip time (RTT) između akcije koju pokrene napadač i odgovarajućeg delivery receipt-a otkriva timing channel visoke rezolucije koji leak-uje stanje uređaja, online prisustvo i može se zloupotrebiti za covert DoS. Multi-device "client-fanout" deployment-i pojačavaju leak jer svaki registrovani uređaj dekriptuje probe i vraća sopstveni receipt.

## Izvori delivery receipt-a naspram signala vidljivih korisniku

Birajte tipove poruka koji uvek emituju delivery receipt, ali ne prikazuju UI artefakte na žrtvi. Sledeća tabela sumira empirijski potvrđeno ponašanje:

| Messenger | Akcija | Delivery receipt | Obaveštenje žrtvi | Napomene |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Tekstualna poruka | ● | ● | Uvek bučno → korisno samo za bootstrap stanja. |
| | Reakcija | ● | ◐ (samo ako se reaguje na poruku žrtve) | Self-reactions i removals ostaju nevidljivi. |
| | Edit | ● | Silent push zavisan od platforme | Edit window ≈20 min; i dalje ack’d nakon isteka. |
| | Delete for everyone | ● | ○ | UI dozvoljava ~60 h, ali kasniji paketi se i dalje ack’d. |
| **Signal** | Tekstualna poruka | ● | ● | Ista ograničenja kao WhatsApp. |
| | Reakcija | ● | ◐ | Self-reactions nevidljive žrtvi. |
| | Edit/Delete | ● | ○ | Server nameće ~48 h window, dozvoljava do 10 edits, ali kasni paketi se i dalje ack’d. |
| **Threema** | Tekstualna poruka | ● | ● | Multi-device receipts su agregirani, pa je po probe-u vidljiv samo jedan RTT. |

Legenda: ● = uvek, ◐ = uslovno, ○ = nikad. Ponašanje UI-ja zavisno od platforme je navedeno direktno u tekstu. Po potrebi isključite read receipts, ali delivery receipts ne mogu da se isključe u WhatsApp-u ili Signal-u.

## Ciljevi i modeli napadača

* **G1 – Device fingerprinting:** Brojite koliko receipt-a stiže po probe-u, grupišite RTT-ove da biste zaključili OS/klijent (Android vs iOS vs desktop), i pratite online/offline prelaze.
* **G2 – Praćenje ponašanja:** Tretirajte visokofrekventnu RTT seriju (≈1 Hz je stabilno) kao time-series i zaključujte screen on/off, app foreground/background, commuting naspram radnog vremena itd.
* **G3 – Iscrpljivanje resursa:** Držite radio/CPU svakog uređaja žrtve budnim slanjem beskonačnih silent probe-ova, praznite bateriju/podatke i degradirajte VoIP/RTC kvalitet.

Dovoljna su dva threat actor-a da opišu površinu zloupotrebe:

1. **Creepy companion:** već deli chat sa žrtvom i zloupotrebljava self-reactions, uklanjanje reakcija ili ponovljene edite/deletes vezane za postojeće message ID-jeve.
2. **Spooky stranger:** registruje burner nalog i šalje reakcije koje referenciraju message ID-jeve koji nikada nisu postojali u lokalnom razgovoru; WhatsApp i Signal ih i dalje dekriptuju i potvrđuju iako UI odbacuje promenu stanja, pa prethodni razgovor nije potreban.

## Alati za raw protocol access

Oslonite se na klijente koji izlažu osnovni E2EE protocol, tako da možete da pravite pakete van UI ograničenja, zadajete proizvoljne `message_id`-eve i beležite precizne timestamps:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, WhatsApp Web protocol) ili [Cobalt](https://github.com/Auties00/Cobalt) (mobile-oriented) omogućavaju slanje raw `ReactionMessage`, `ProtocolMessage` (edit/delete) i `Receipt` frame-ova uz održavanje double-ratchet state-a u sinhronizaciji.
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) u kombinaciji sa [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) izlaže svaki tip poruke preko CLI/API. Trenutna `signal-cli` sintaksa koristi `sendReaction RECIPIENT --target-author --target-timestamp`; ostavite `receive` ili `daemon` da radi kako bi delivery receipts zaista bili prikupljeni. Primer self-reaction toggle:
```bash
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --emoji "👍"
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --remove
```
* **Threema:** Izvor Android klijenta dokumentuje kako se delivery receipts konsoliduju pre nego što napuste uređaj, što objašnjava zašto je side channel tamo zanemarljivog bandwidth-a.
* **Turnkey PoCs:** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker) dolazi sa WhatsApp/Signal backend-ovima, podrazumevano koristi silent delete probe-ove i označava `active` naspram `standby` pomoću rolling-median praga (`RTT < 0.9 * median`). [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python) je lakši WhatsApp-first CLI sa `--delay`, `--concurrent`, CSV/Prometheus exporter-ima i izlazom pogodnim za Grafana-u. Tretirajte oba kao pomoć za izviđanje, a ne kao protocol reference; ključna poruka je koliko je malo koda potrebno kada postoji raw client access.

Kada custom tooling nije dostupan, i dalje možete da pokrećete silent akcije iz WhatsApp Web ili Signal Desktop i sniff-ujete encrypted websocket/WebRTC kanal, ali raw API-ja uklanjaju UI kašnjenja i omogućavaju nevažeće operacije.

## Creepy companion: silent sampling loop

1. Izaberite bilo koju istorijsku poruku koju ste vi napisali u chatu, tako da žrtva nikada ne vidi da se "reaction" balončići menjaju.
2. Naizmenično šaljite vidljivi emoji i prazan reaction payload (enkodovan kao `""` u WhatsApp protobufs ili `--remove` u signal-cli). Svaki prenos daje device ack iako na UI-ju nema promene za žrtvu.
3. Zabeležite vreme slanja i svaki dolazak delivery receipt-a. 1 Hz loop poput sledećeg daje per-device RTT trace-ove neograničeno:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. Pošto WhatsApp/Signal prihvataju neograničene reaction update-ove, napadač nikada ne mora da objavljuje novi chat sadržaj niti da brine o edit window-ima.

## Spooky stranger: probing proizvoljnih brojeva telefona

1. Registrujte svež WhatsApp/Signal nalog i preuzmite javne identity keys za ciljani broj (to se radi automatski tokom setup-a sesije).
2. Napravite reaction/edit/delete paket koji referencira nasumični `message_id` koji nikada nije viđen ni od jedne strane (WhatsApp prihvata proizvoljne `key.id` GUID-ove; Signal koristi millisecond timestamps).
3. Pošaljite paket iako thread ne postoji. Uređaji žrtve ga dekriptuju, ne uspeju da pronađu osnovnu poruku, odbace promenu stanja, ali i dalje potvrde dolazni ciphertext, šaljući device receipts nazad napadaču.
4. Ponavljajte neprekidno da biste izgradili RTT serije bez ikakvog pojavljivanja u chat listi žrtve.

Ako prvo treba da otkrijete koji brojevi su registrovani ili želite da unapred popunite inventar uređaja u velikom obimu, povežite ovo sa [contact-discovery / registration oracles](../pentesting-web/registration-vulnerabilities.md) umesto da nasumično pogađate E.164 opsege ručno.

Nove WhatsApp verzije takođe izlažu `Settings -> Privacy -> Advanced -> Block unknown account messages`. Tretirajte to kao limiter propusnosti, ne kao rešenje: uglavnom otežava trajno flood-ovanje samo od strane stranaca i nije bitno jednom kada ste već poznat kontakt.

## Recycle-ovanje edita i delete-ova kao covert trigger-a

* **Repeated deletes:** Nakon što je poruka jednom deleted-for-everyone, dalji delete paketi koji referenciraju isti `message_id` nemaju UI efekat, ali svaki uređaj i dalje dekriptuje i potvrđuje ih.
* **Out-of-window operacije:** WhatsApp u UI-ju nameće ~60 h delete / ~20 min edit window; Signal nameće ~48 h. Napravљene protocol poruke van tih window-a žrtvin uređaj tiho ignoriše, ali receipts se i dalje prenose, pa napadači mogu da probe-uju beskonačno dugo nakon što je razgovor završen.
* **Invalid payloads:** Neispravna edit tela ili delete-ovi koji referenciraju već očišćene poruke izazivaju isto ponašanje—dekripcija plus receipt, nula korisniku vidljivih artefakata.

## Multi-device amplifikacija i fingerprinting

* Svaki povezani uređaj (telefon, desktop app, browser companion) nezavisno dekriptuje probe i vraća svoj ack. Brojanje receipt-a po probe-u otkriva tačan broj uređaja.
* Ako je uređaj offline, njegov receipt se redom čeka i emituje po ponovnom povezivanju. Praznine zato leak-uju online/offline cikluse i čak rasporede kretanja na posao (npr. desktop receipts prestaju tokom putovanja).
* RTT distribucije se razlikuju po platformi zbog OS power management-a i push wakeups. Grupisanje RTT-ova (npr. k-means nad median/variance feature-ima) omogućava označavanje „Android handset", „iOS handset", „Electron desktop", itd.
* Pošto pošiljalac mora da preuzme inventar ključeva primaoca pre šifrovanja, napadač može i da prati kada se dodaju novi uređaji; nagli porast broja uređaja ili nova RTT klaster grupa je jak indikator.

## Zaključivanje ponašanja iz RTT trace-ova

1. Skupljajte uzorke na ≥1 Hz da biste uhvatili OS scheduling efekte. Sa WhatsApp-om na iOS-u, RTT-ovi <1 s snažno koreliraju sa screen-on/foreground, a >1 s sa screen-off/background throttling-om.
2. Napravite jednostavne klasifikatore (thresholding ili two-cluster k-means) koji svaki RTT označavaju kao "active" ili "idle". Agregirajte oznake u streaks da biste izvukli bedtime, commute, radno vreme ili trenutke kada je desktop companion aktivan.
3. Korelišite istovremene probe-ove ka svakom uređaju da biste videli kada korisnici prelaze sa mobilnog na desktop, kada companions odlaze offline i da li je app rate limited preko push-a ili persistent socket-a.
4. U realnim mrežama, izbegavajte jedan hardcoded `1 s` threshold. Bootstrappujte svaki uređaj kratkim warm-up prozorom i održavajte rolling baseline (na primer, `threshold = 0.9 * median RTT`) tako da Wi-Fi/cellular drift ne sruši klasifikator.

## Zaključivanje lokacije iz delivery RTT

Isti timing primitive može da se prenameni za zaključivanje gde se primalac nalazi, a ne samo da li je aktivan. Rad `Hope of Delivery` je pokazao da treniranje na RTT distribucijama za poznate lokacije primaoca omogućava napadaču da kasnije klasifikuje lokaciju žrtve samo na osnovu delivery potvrda:

* Napravite baseline za istu metu dok je na više poznatih mesta (kuća, kancelarija, kampus, zemlja A naspram zemlje B, itd.).
* Za svaku lokaciju prikupite mnogo normalnih message RTT-ova i izvucite jednostavne feature-e kao što su median, variance ili percentile bucket-i.
* Tokom pravog napada, uporedite novu probe seriju sa treniranim klasterima. Rad navodi da se čak i lokacije u istom gradu često mogu razdvojiti, sa `>80%` tačnosti u setting-u sa 3 lokacije.
* Ovo radi najbolje kada napadač kontroliše sender okruženje i probe-uje pod sličnim mrežnim uslovima, jer izmerena putanja uključuje recipient access network, wake-up latency i messenger infrastrukturu.

Za razliku od tihog napada reakcijama/edit/delete-ovima iznad, zaključivanje lokacije ne zahteva nevažeće message ID-jeve niti stealthy state-changing pakete. Obične poruke sa normalnim delivery potvrđivanjem su dovoljne, pa je kompromis manji stealth ali šira primenljivost preko messengera.

## Stealthy resource exhaustion

Pošto svaki silent probe mora da bude dekriptovan i potvrđen, kontinuirano slanje reaction toggle-ova, invalid edita ili delete-for-everyone paketa stvara application-layer DoS:

* Prisiljava radio/modem da šalje/prima svake sekunde → primetan battery drain, naročito na idle handset-ima.
* Generiše neobračunat upstream/downstream traffic koji troši mobile data planove dok se stapa sa TLS/WebSocket noise-om.
* Zauzima crypto thread-ove i uvodi jitter u latency-sensitive funkcije (VoIP, video calls) iako korisnik nikada ne vidi notifikacije.
* Na WhatsApp-u, invalid reactions prihvataju daleko više podataka nego što normalni emoji sugeriše: objavljena merenja su našla server-side acceptance do približno `1 MB` po reaction-u.
* Oversized reactions prestaju da daju pouzdane delivery receipts kada body poraste iznad približno `30 bytes`, ali se i dalje prosleđuju i obrađuju pre odbacivanja. Držite reaction body-jeve malim kada su vam potrebni ACK-ovi; povećavajte ih samo kada je cilj čisto iscrpljivanje ili covert one-way transport.
* Javna merenja su dostigla oko `3.7 MB/s` (`~13.3 GB/h`) saobraćaja žrtve u ovom modu.

## Reference

- [Careless Whisper: Exploiting Silent Delivery Receipts to Monitor Users on Mobile Instant Messengers](https://arxiv.org/html/2411.11194v4)
- [Hope of Delivery: Extracting User Locations From Mobile Instant Messengers](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [whatsmeow](https://github.com/tulir/whatsmeow)
- [Cobalt](https://github.com/Auties00/Cobalt)
- [signal-cli](https://github.com/AsamK/signal-cli)
- [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)
- [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python)
- [How to block high volumes of unknown messages | WhatsApp Help Center](https://faq.whatsapp.com/3379690015658337)

{{#include ../banners/hacktricks-training.md}}
