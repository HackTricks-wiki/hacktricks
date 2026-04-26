# Napadi bočnim kanalom delivery receipt-a u E2EE messengerima

{{#include ../banners/hacktricks-training.md}}

Delivery receipt-i su obavezni u modernim end-to-end encrypted (E2EE) messengerima jer klijenti moraju da znaju kada je ciphertext dešifrovan kako bi mogli da odbace ratcheting state i ephemeral keys. Server prosleđuje opaque blobs, pa device acknowledgements (double checkmarks) šalje primalac nakon uspešnog dešifrovanja. Merenje round-trip time (RTT) između akcije koju pokrene napadač i odgovarajućeg delivery receipt-a otkriva vremenski kanal visoke rezolucije koji leak-uje stanje uređaja, online prisustvo i može da se zloupotrebi za covert DoS. Multi-device "client-fanout" deployments pojačavaju leak jer svaki registrovani uređaj dešifruje probe i vraća sopstveni receipt.

## Izvori delivery receipt-a naspram signalâ vidljivih korisniku

Birajte tipove poruka koji uvek šalju delivery receipt, ali ne prikazuju UI artefakte na žrtvi. Tabela ispod sumira empirijski potvrđeno ponašanje:

| Messenger | Akcija | Delivery receipt | Obaveštenje žrtvi | Napomene |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Tekstualna poruka | ● | ● | Uvek bučno → korisno samo za bootstrap stanja. |
| | Reakcija | ● | ◐ (samo ako se reaguje na poruku žrtve) | Samoreakcije i uklanjanja ostaju tiha. |
| | Edit | ● | silent push zavisan od platforme | Prozor za edit ≈20 min; i dalje šalje ack nakon isteka. |
| | Delete for everyone | ● | ○ | UI dozvoljava ~60 h, ali kasniji paketi se i dalje ack-uju. |
| **Signal** | Tekstualna poruka | ● | ● | Ista ograničenja kao WhatsApp. |
| | Reakcija | ● | ◐ | Samoreakcije nevidljive žrtvi. |
| | Edit/Delete | ● | ○ | Server nameće prozor od ~48 h, dozvoljava do 10 izmena, ali se kasni paketi i dalje ack-uju. |
| **Threema** | Tekstualna poruka | ● | ● | Multi-device receipt-i se agregiraju, pa je vidljiv samo jedan RTT po probe-u. |

Legenda: ● = uvek, ◐ = uslovno, ○ = nikad. Ponašanje UI-ja zavisno od platforme navedeno je direktno u tekstu. Ako treba, isključite read receipts, ali delivery receipts se ne mogu isključiti u WhatsApp ili Signal.

## Ciljevi napadača i modeli

* **G1 – Device fingerprinting:** Prebrojite koliko receipt-a stiže po probe-u, grupišite RTT-ove da biste zaključili OS/klijent (Android vs iOS vs desktop), i pratite online/offline prelaze.
* **G2 – Praćenje ponašanja:** Tretirajte niz RTT vrednosti visoke frekvencije (≈1 Hz je stabilno) kao time-series i zaključite screen on/off, app foreground/background, commuting naspram working hours, itd.
* **G3 – Iscrpljivanje resursa:** Držite radio/CPU svakog žrtvinog uređaja budnim slanjem beskonačnih tihih probe-ova, praznite bateriju/podatke i pogoršavajte VoIP/RTC kvalitet.

Dovoljna su dva threat actor-a da opišu površinu zloupotrebe:

1. **Creepy companion:** već deli chat sa žrtvom i zloupotrebljava samoreakcije, uklanjanja reakcija ili ponovljene edit/delete operacije vezane za postojeće message ID-jeve.
2. **Spooky stranger:** registruje burner nalog i šalje reakcije koje referenciraju message ID-jeve koji nikada nisu postojali u lokalnom razgovoru; WhatsApp i Signal ih i dalje dešifruju i potvrđuju iako UI odbacuje promenu stanja, pa prethodni razgovor nije potreban.

## Alati za raw protocol pristup

Oslonite se na klijente koji izlažu osnovni E2EE protokol kako biste mogli da pravite pakete van UI ograničenja, zadajete proizvoljne `message_id`-eve i beležite precizne vremenske oznake:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, WhatsApp Web protocol) ili [Cobalt](https://github.com/Auties00/Cobalt) (mobile-oriented) omogućavaju emitovanje raw `ReactionMessage`, `ProtocolMessage` (edit/delete) i `Receipt` frame-ova uz održavanje double-ratchet stanja sinhronizovanim.
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) u kombinaciji sa [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) izlaže svaki tip poruke kroz CLI/API. Primer toggla za samoreakciju:
```bash
signal-cli -u +12025550100 sendReaction --target +12025550123 \
--message-timestamp 1712345678901 --emoji "👍"
signal-cli -u +12025550100 sendReaction --target +12025550123 \
--message-timestamp 1712345678901 --remove  # encodes empty emoji
```
* **Threema:** Izvorni kod Android klijenta dokumentuje kako se delivery receipts konsoliduju pre nego što napuste uređaj, što objašnjava zašto side channel tamo ima zanemarljiv bandwidth.
* **Turnkey PoCs:** javni projekti poput `device-activity-tracker` i `careless-whisper-python` već automatizuju silent delete/reaction probe-ove i RTT klasifikaciju. Posmatrajte ih kao gotove pomoćne alate za reconnaissance, a ne kao reference za protokol; zanimljivo je to što potvrđuju da je napad operativno jednostavan kada postoji raw pristup klijentu.

Kada custom tooling nije dostupan, i dalje možete da okidate tihe akcije iz WhatsApp Web ili Signal Desktop i da sniff-ujete šifrovani websocket/WebRTC kanal, ali raw API-jevi uklanjaju UI kašnjenja i omogućavaju nevažeće operacije.

## Creepy companion: petlja tihog uzorkovanja

1. Izaberite bilo koju istorijsku poruku koju ste vi poslali u chatu, tako da žrtva nikada ne vidi da se "reaction" balončići menjaju.
2. Naizmenično šaljite vidljiv emoji i prazni reaction payload (kodiran kao `""` u WhatsApp protobufs ili `--remove` u signal-cli). Svaki prenos daje device ack iako nema UI promene za žrtvu.
3. Zabeležite vreme slanja i dolazak svakog delivery receipt-a. Petlja od 1 Hz poput sledeće daje per-device RTT tragove neograničeno:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. Pošto WhatsApp/Signal prihvataju neograničen broj update-a reakcija, napadač nikada ne mora da objavljuje novi sadržaj u chatu niti da brine o edit window-ima.

## Spooky stranger: probing proizvoljnih telefonskih brojeva

1. Registrujte svež WhatsApp/Signal nalog i preuzmite javne identity keys za ciljajući broj (što se radi automatski tokom session setup-a).
2. Napravite reaction/edit/delete paket koji referencira nasumičan `message_id` koji nijedna strana nikada nije videla (WhatsApp prihvata proizvoljne `key.id` GUID-ove; Signal koristi millisecond timestamps).
3. Pošaljite paket iako thread ne postoji. Žrtvini uređaji ga dešifruju, ne uspevaju da pronađu osnovnu poruku, odbacuju promenu stanja, ali i dalje potvrđuju dolazni ciphertext i šalju device receipts nazad napadaču.
4. Ponavljajte kontinuirano da biste izgradili RTT serije bez ikada pojavljivanja na listi chatova žrtve.

## Recikliranje edit i delete operacija kao covert triggera

* **Ponovljeni delete:** Nakon što je poruka jednom deleted-for-everyone, dalji delete paketi koji referenciraju isti `message_id` nemaju UI efekat, ali svaki uređaj ih i dalje dešifruje i potvrđuje.
* **Operacije van window-a:** WhatsApp u UI nameće ~60 h delete / ~20 min edit window-e; Signal nameće ~48 h. Izrađene protocol poruke van ovih granica žrtvin uređaj tiho ignoriše, a receipt-i se i dalje prenose, pa napadači mogu da probe-uju dugo nakon završetka razgovora.
* **Nevažeći payload-i:** Malformed edit body-jevi ili delete-ovi koji referenciraju već očišćene poruke izazivaju isto ponašanje—dešifrovanje plus receipt, bez korisniku vidljivih artefakata.

## Multi-device pojačanje i fingerprinting

* Svaki pridruženi uređaj (telefon, desktop app, browser companion) dešifruje probe nezavisno i vraća sopstveni ack. Prebrojavanjem receipt-a po probe-u otkriva se tačan broj uređaja.
* Ako je uređaj offline, njegov receipt se stavlja u red i šalje po ponovnom povezivanju. Rupe zato leak-uju online/offline cikluse, pa čak i commuting rasporede (npr. desktop receipt-i prestaju tokom putovanja).
* RTT raspodele se razlikuju po platformi zbog OS power management-a i push wakeup-ova. Grupisite RTT-ove (npr. k-means nad median/variance karakteristikama) da biste označili „Android handset", „iOS handset", „Electron desktop", itd.
* Pošto pošiljalac mora da preuzme inventar ključeva primaoca pre šifrovanja, napadač može i da prati kada se novi uređaji uparuju; naglo povećanje broja uređaja ili nova RTT grupa je jak indikator.

## Zaključivanje ponašanja iz RTT tragova

1. Uzorkujte na ≥1 Hz da biste uhvatili efekte OS scheduling-a. Sa WhatsApp na iOS, RTT <1 s snažno korelira sa screen-on/foreground, a >1 s sa screen-off/background throttling-om.
2. Napravite jednostavne klasifikatore (thresholding ili two-cluster k-means) koji svaki RTT označavaju kao "active" ili "idle". Agregirajte oznake u streaks da biste izvukli bedtimes, commutes, work hours, ili kada je desktop companion aktivan.
3. Korelišite istovremene probe prema svakom uređaju da biste videli kada korisnici prelaze sa mobilnog na desktop, kada companions odlaze offline i da li je app rate limited preko push ili persistent socket-a.

## Zaključivanje lokacije iz delivery RTT-a

Isti vremenski primitiv može da se preusmeri tako da zaključi gde se primalac nalazi, a ne samo da li je aktivan. Rad `Hope of Delivery` je pokazao da treniranje na RTT raspodelama za poznate lokacije primaoca omogućava napadaču da kasnije klasifikuje lokaciju žrtve samo iz delivery potvrda:

* Napravite baseline za isti cilj dok je na nekoliko poznatih mesta (kuća, kancelarija, kampus, država A naspram države B, itd.).
* Za svaku lokaciju prikupite mnogo normalnih RTT-ova poruka i izdvojite jednostavne karakteristike kao što su median, variance ili percentile buckets.
* Tokom stvarnog napada, uporedite novu seriju probe-ova sa obučenim cluster-ima. Rad izveštava da se čak i lokacije u istom gradu često mogu razdvojiti, sa `>80%` preciznosti u scenu sa 3 lokacije.
* Ovo najbolje radi kada napadač kontroliše sender environment i probe-uje pod sličnim mrežnim uslovima, jer mereni path uključuje recipient access network, wake-up latency i messenger infrastrukturu.

Za razliku od tihih napada reakcijama/edit/delete iznad, zaključivanje lokacije ne zahteva nevažeće message ID-jeve ni stealthy state-changing pakete. Obične poruke sa normalnim delivery potvrđivanjem su dovoljne, pa je kompromis manji stealth ali šira primenljivost kroz messengere.

## Stealthy resource exhaustion

Pošto svaki tihi probe mora da se dešifruje i potvrdi, kontinuirano slanje reaction toggles, nevažećih edit-ova ili delete-for-everyone paketa stvara application-layer DoS:

* Prisiljava radio/modem da šalje/prima svake sekunde → primetan pad baterije, posebno na idle handset-ovima.
* Generiše neometan upstream/downstream traffic koji troši mobilne data planove dok se stapa sa TLS/WebSocket šumom.
* Zauzima crypto thread-ove i uvodi jitter u latency-sensitive funkcije (VoIP, video pozivi) iako korisnik nikada ne vidi obaveštenja.

## Reference

- [Careless Whisper: Exploiting Silent Delivery Receipts to Monitor Users on Mobile Instant Messengers](https://arxiv.org/html/2411.11194v4)
- [Hope of Delivery: Extracting User Locations From Mobile Instant Messengers](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [whatsmeow](https://github.com/tulir/whatsmeow)
- [Cobalt](https://github.com/Auties00/Cobalt)
- [signal-cli](https://github.com/AsamK/signal-cli)
- [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)

{{#include ../banners/hacktricks-training.md}}
