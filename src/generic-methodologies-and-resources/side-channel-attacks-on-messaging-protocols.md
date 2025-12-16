# Delivery Receipt Side-Channel Attacks in E2EE Messengers

{{#include ../banners/hacktricks-training.md}}

Delivery receipts su obavezne u modernim end-to-end encrypted (E2EE) messengerima zato što klijenti moraju da znaju kada je ciphertext dekriptovan kako bi odbacili ratcheting state i ephemeral keys. Server prosleđuje opaque blobs, pa device acknowledgements (double checkmarks) šalje primalac nakon uspešne dekripcije. Merenje round-trip time (RTT) između napadačem pokrenute akcije i odgovarajuće delivery receipt otkriva high-resolution timing channel koji leak-uje stanje uređaja, online presence, i može se zloupotrebiti za covert DoS. Multi-device "client-fanout" deploy-ovi pojačavaju curenje jer svaki registrovani uređaj dekriptuje probe i vraća sopstveni receipt.

## Delivery receipt sources vs. user-visible signals

Izaberite tipove poruka koji uvek emituju delivery receipt, ali ne ostavljaju UI artefakte na žrtvi. Tabela ispod sumira empirijski potvrđeno ponašanje:

| Messenger | Action | Delivery receipt | Victim notification | Notes |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Text message | ● | ● | Uvek bučno → korisno samo za bootstrap state. |
| | Reaction | ● | ◐ (samo ako se reaguje na victim poruku) | Self-reactions i uklanjanja ostaju silent. |
| | Edit | ● | Platform-dependent silent push | Edit window ≈20 min; i dalje se ackuje nakon isteka. |
| | Delete for everyone | ● | ○ | UI dozvoljava ~60 h, ali kasniji paketi i dalje bivaju ack-ovani. |
| **Signal** | Text message | ● | ● | Iste ograničenja kao WhatsApp. |
| | Reaction | ● | ◐ | Self-reactions nevidljive žrtvi. |
| | Edit/Delete | ● | ○ | Server nameće ~48 h prozor, dozvoljava do 10 izmena, ali kasni paketi i dalje bivaju ack-ovani. |
| **Threema** | Text message | ● | ● | Multi-device receipts se agregiraju, pa postaje vidljiv samo jedan RTT po probe. |

Legend: ● = uvek, ◐ = uslovno, ○ = nikad. Platform-dependent UI ponašanje je navedeno inline. Isključite read receipts po potrebi, ali delivery receipts se ne mogu isključiti u WhatsApp-u ili Signal-u.

## Attacker goals and models

* **G1 – Device fingerprinting:** Brojati koliko receipts stigne po probe, klasterisati RTT-ove da bi se inferiralo OS/client (Android vs iOS vs desktop) i pratiti online/offline tranzicije.
* **G2 – Behavioural monitoring:** Tretirati high-frequency RTT seriju (≈1 Hz je stabilno) kao time-series i izvoditi informacije o screen on/off, app foreground/background, commuting vs working hours itd.
* **G3 – Resource exhaustion:** Držati radio/CPU svakog žrtvinog uređaja budnim slanjem beskonačnih silent probe-ova, prazniti bateriju/data i degradirati kvalitet VoIP/RTC sesija.

Dva threat actora su dovoljna da opišu surface zloupotrebe:

1. **Creepy companion:** već deli chat sa žrtvom i zloupotrebljava self-reactions, uklanjanje reakcija ili ponovljene edit/delete operacije vezane za postojeće message ID-e.
2. **Spooky stranger:** registruje burner account i šalje reakcije koje referenciraju message ID-e koji nikada nisu postojali u lokalnoj konverzaciji; WhatsApp i Signal ih i dalje dekriptuju i priznaju iako UI odbacuje promenu stanja, tako da prethodni razgovor nije potreban.

## Tooling for raw protocol access

Oslonite se na klijente koji izlažu underlying E2EE protocol kako biste mogli da craft-ujete pakete izvan UI ograničenja, specificirate arbitrarne `message_id`-eve i logujete precizne timestamp-ove:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, WhatsApp Web protocol) ili [Cobalt](https://github.com/Auties00/Cobalt) (mobile-oriented) vam omogućavaju da emitujete raw `ReactionMessage`, `ProtocolMessage` (edit/delete) i `Receipt` frame-ove dok držite double-ratchet state u sync-u.
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) u kombinaciji sa [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) izlaže svaki tip poruke preko CLI/API. Primer toggle-a self-reaction:
```bash
signal-cli -u +12025550100 sendReaction --target +12025550123 \
--message-timestamp 1712345678901 --emoji "👍"
signal-cli -u +12025550100 sendReaction --target +12025550123 \
--message-timestamp 1712345678901 --remove  # encodes empty emoji
```
* **Threema:** Izvor Android klijenta dokumentuje kako se delivery receipts konsoliduju pre nego što napuste uređaj, objašnjavajući zašto side channel tamo ima zanemarljivu propusnost.

Kada custom tooling nije dostupan, i dalje možete pokretati silent akcije iz WhatsApp Web-a ili Signal Desktop-a i sniff-ovati enkriptovani websocket/WebRTC kanal, ali raw API-jevi uklanjaju UI kašnjenja i dozvoljavaju invalidne operacije.

## Creepy companion: silent sampling loop

1. Izaberite bilo koju istorijsku poruku koju ste vi poslali u chatu tako da žrtva nikada ne vidi promenu "reaction" balona.
2. Naizmenično šaljite vidljivi emoji i empty reaction payload (kodirano kao `""` u WhatsApp protobuf-ima ili `--remove` u signal-cli). Svaka transmisija generiše device ack uprkos tome što nema UI delta za žrtvu.
3. Timestamp-ujte vreme slanja i svaki dolazak delivery receipt-a. 1 Hz loop kao sledeći daje po-uređaj RTT tragove u nedogled:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. Pošto WhatsApp/Signal prihvataju neograničene reaction update-e, napadaču nikada ne treba da postavlja novi chat sadržaj ili da brine o edit windows.

## Spooky stranger: probing arbitrary phone numbers

1. Registrujte nov račun na WhatsApp/Signal i preuzmite public identity keys za target broj (obavlja se automatski tokom setup-a sesije).
2. Craft-ujte reaction/edit/delete paket koji referencira nasumičan `message_id` nikad viđen od strane bilo koje strane (WhatsApp prihvata arbitrarne `key.id` GUID-ove; Signal koristi millisecond timestamps).
3. Pošaljite paket iako thread ne postoji. Žrtvini uređaji ga dekriptuju, ne uspevaju da nađu baznu poruku, odbacuju promenu stanja, ali i dalje potvrđuju dolazeći ciphertext slanjem device receipts nazad napadaču.
4. Ponavljajte kontinuirano da biste izgradili RTT seriju bez ikakvog pojavljivanja u žrtvinoj listi razgovora.

## Recycling edits and deletes as covert triggers

* **Repeated deletes:** Nakon što je poruka jednom obrisana-for-everyone, dalji delete paketi koji referenciraju isti `message_id` nemaju UI efekat, ali svaki uređaj i dalje dekriptuje i potvrđuje ih.
* **Out-of-window operations:** WhatsApp nameće ~60 h delete / ~20 min edit prozore u UI; Signal nameće ~48 h. Sastavljene protocol poruke izvan ovih prozora su tihi na uređaju žrtve, ali receipts se i dalje šalju, pa napadači mogu probati beskonačno dugo nakon što je konverzacija završena.
* **Invalid payloads:** Neispravna edit tela ili delete-i koji referenciraju već purgovane poruke izazivaju isto ponašanje — dekripciju plus receipt, nula korisnički vidljivih artefakata.

## Multi-device amplification & fingerprinting

* Svaki povezan uređaj (telefon, desktop app, browser companion) dekriptuje probe nezavisno i vraća sopstveni ack. Brojanjem receipts po probe otkriva se tačan broj uređaja.
* Ako je uređaj offline, njegov receipt se stavlja u red i emitira po ponovnom konektovanju. Gaps stoga leak-uju online/offline cikluse pa čak i rasporede putovanja (npr. desktop receipts prestanu tokom putovanja).
* RTT distribucije se razlikuju po platformi zbog OS power management-a i push wakeups. Klasterujte RTT-ove (npr. k-means na median/variance karakteristikama) da biste označili “Android handset”, “iOS handset”, “Electron desktop” itd.
* Pošto pošiljalac mora da preuzme inventory ključeva primaoca pre enkripcije, napadač takođe može pratiti kada su novi uređaji upareni; nagli porast u broju uređaja ili novi RTT klaster je snažan indikator.

## Behaviour inference from RTT traces

1. Sample-ujte na ≥1 Hz da biste uhvatili OS scheduling efekte. Sa WhatsApp-om na iOS-u, <1 s RTT-ovi snažno koreliraju sa screen-on/foreground, >1 s sa screen-off/background throttling-om.
2. Napravite jednostavne klasifikatore (thresholding ili two-cluster k-means) koji označavaju svaki RTT kao "active" ili "idle". Agregirajte oznake u streak-ove da izvedete bedtimes, commutes, radno vreme ili kada je desktop companion aktivan.
3. Korelirajte simultane probe prema svakom uređaju da vidite kada korisnici prelaze sa mobilnog na desktop, kada companion-i odlaze offline i da li je app rate-limited od strane push vs persistent socket.

## Stealthy resource exhaustion

Pošto svaka silent probe mora biti dekriptovana i potvrđena, kontinuirano slanje reaction toggle-a, invalidnih edit-ova ili delete-for-everyone paketa stvara application-layer DoS:

* Prisiljava radio/modem da šalje/prima svake sekunde → primetno pražnjenje baterije, posebno na idle handset-ima.
* Generiše upstream/downstream saobraćaj koji opterećuje mobilne podatkovne planove dok se stapaju u TLS/WebSocket šum.
* Zauzima crypto thread-ove i uvodi jitter u latency-sensitive funkcije (VoIP, video pozivi) iako korisnik nikada ne vidi notifikacije.

## References

- [Careless Whisper: Exploiting Silent Delivery Receipts to Monitor Users on Mobile Instant Messengers](https://arxiv.org/html/2411.11194v4)
- [whatsmeow](https://github.com/tulir/whatsmeow)
- [Cobalt](https://github.com/Auties00/Cobalt)
- [signal-cli](https://github.com/AsamK/signal-cli)
- [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)

{{#include ../banners/hacktricks-training.md}}
