# Delivery Receipt Side-Channel Attacks in E2EE Messengers

{{#include ../banners/hacktricks-training.md}}

Delivery receipts są obowiązkowe we współczesnych end-to-end encrypted (E2EE) messengerach, ponieważ klienci muszą wiedzieć, kiedy ciphertext został odszyfrowany, aby mogli odrzucić ratcheting state i ephemeral keys. Server forwarduje opaque blobs, więc device acknowledgements (double checkmarks) są wysyłane przez odbiorcę po pomyślnym odszyfrowaniu. Pomiar round-trip time (RTT) między akcją wywołaną przez atakującego a odpowiadającym delivery receipt ujawnia high-resolution timing channel, który leaks device state, online presence i może być nadużyty do covert DoS. Multi-device "client-fanout" deployments amplify the leakage, ponieważ każde zarejestrowane urządzenie odszyfrowuje probe i zwraca własny receipt.

## Delivery receipt sources vs. user-visible signals

Wybierz typy wiadomości, które zawsze emitują delivery receipt, ale nie powodują widocznych artefaktów UI dla ofiary. Poniższa tabela podsumowuje empirically confirmed zachowanie:

| Messenger | Action | Delivery receipt | Victim notification | Notes |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Text message | ● | ● | Always noisy → tylko użyteczne do bootstrapowania stanu. |
| | Reaction | ● | ◐ (only if reacting to victim message) | Self-reactions i removals pozostają silent. |
| | Edit | ● | Platform-dependent silent push | Edit window ≈20 min; nadal ack’owane po wygaśnięciu. |
| | Delete for everyone | ● | ○ | UI pozwala ~60 h, ale późniejsze pakiety nadal są ack’owane. |
| **Signal** | Text message | ● | ● | Te same ograniczenia co WhatsApp. |
| | Reaction | ● | ◐ | Self-reactions niewidoczne dla ofiary. |
| | Edit/Delete | ● | ○ | Server narzuca ~48 h okno, pozwala do 10 edycji, ale późne pakiety nadal są ack’owane. |
| **Threema** | Text message | ● | ● | Multi-device receipts są agregowane, więc tylko jedno RTT na probe staje się widoczne. |

Legend: ● = always, ◐ = conditional, ○ = never. Platform-dependent UI behaviour jest notowane inline. Wyłącz read receipts jeśli potrzeba, ale delivery receipts nie można wyłączyć w WhatsApp ani Signal.

## Attacker goals and models

* **G1 – Device fingerprinting:** Zliczaj, ile receipts przychodzi na probe, klastruj RTT, aby infer OS/client (Android vs iOS vs desktop) i obserwuj online/offline transitions.
* **G2 – Behavioural monitoring:** Traktuj wysokoczęstotliwościową serię RTT (≈1 Hz jest stabilne) jako time-series i wnioskować screen on/off, app foreground/background, commuting vs working hours itp.
* **G3 – Resource exhaustion:** Utrzymuj radios/CPUs każdego urządzenia ofiary aktywne, wysyłając never-ending silent probes, drenować battery/data oraz pogarszać jakość VoIP/RTC.

Dwie role zagrożeń wystarczą do opisania powierzchni nadużyć:

1. **Creepy companion:** już dzieli chat z ofiarą i nadużywa self-reactions, reaction removals lub powtarzanych edits/deletes powiązanych z istniejącymi message ID.
2. **Spooky stranger:** rejestruje burner account i wysyła reactions referujące message ID, które nigdy nie istniały w lokalnej konwersacji; WhatsApp i Signal nadal odszyfrowują i acknowledge’ują je, mimo że UI odrzuca zmianę stanu, więc nie jest wymagana wcześniejsza konwersacja.

## Tooling for raw protocol access

Polegaj na klientach, które expose underlying E2EE protocol, aby móc craftować pakiety poza ograniczeniami UI, określać dowolne `message_id` i logować precyzyjne timestamps:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, WhatsApp Web protocol) lub [Cobalt](https://github.com/Auties00/Cobalt) (zorientowany na mobile) pozwalają emitować surowe `ReactionMessage`, `ProtocolMessage` (edit/delete) i `Receipt` frames, jednocześnie utrzymując double-ratchet state w sync.
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) w połączeniu z [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) expose’uje każdy typ wiadomości przez CLI/API. Przykład toggle self-reaction:
```bash
signal-cli -u +12025550100 sendReaction --target +12025550123 \
--message-timestamp 1712345678901 --emoji "👍"
signal-cli -u +12025550100 sendReaction --target +12025550123 \
--message-timestamp 1712345678901 --remove  # encodes empty emoji
```
* **Threema:** Kod źródłowy klienta Android dokumentuje, jak delivery receipts są konsolidowane zanim opuszczą urządzenie, wyjaśniając, dlaczego side channel ma tam znikomy bandwidth.

Gdy custom tooling jest niedostępne, nadal możesz wywoływać silent actions z WhatsApp Web lub Signal Desktop i sniffować encrypted websocket/WebRTC channel, ale raw APIs usuwają opóźnienia UI i pozwalają na invalid operations.

## Creepy companion: silent sampling loop

1. Wybierz dowolną historyczną wiadomość, którą napisałeś w czacie, tak aby ofiara nigdy nie widziała zmiany "reaction" balloons.
2. Przełączaj się między widocznym emoji a pustym reaction payload (zakodowanym jako `""` w WhatsApp protobufs lub `--remove` w signal-cli). Każda transmisja daje device ack mimo braku delta w UI dla ofiary.
3. Timestampuj czas wysłania i każdy arrival delivery receipt. Pętla 1 Hz jak poniżej daje per-device RTT traces w nieskończoność:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. Ponieważ WhatsApp/Signal akceptują nieograniczone reaction updates, atakujący nigdy nie musi publikować nowej treści w czacie ani martwić się o edit windows.

## Spooky stranger: probing arbitrary phone numbers

1. Zarejestruj świeże konto WhatsApp/Signal i pobierz public identity keys dla target number (zrobione automatycznie podczas session setup).
2. Craftuj reaction/edit/delete packet, który referuje losowe `message_id` nigdy nie widziane przez żadną ze stron (WhatsApp akceptuje arbitralne `key.id` GUIDy; Signal używa millisecond timestamps).
3. Wyślij pakiet mimo braku istniejącego wątku. Urządzenia ofiary odszyfrowują go, nie mogą dopasować bazowej wiadomości, odrzucają zmianę stanu, ale nadal acknowledge’ują przychodzący ciphertext, wysyłając device receipts z powrotem do atakującego.
4. Powtarzaj ciągle, aby zbudować serię RTT bez pojawienia się w chat list ofiary.

## Recycling edits and deletes as covert triggers

* **Repeated deletes:** Po usunięciu wiadomości dla wszystkich (delete-for-everyone) raz, dalsze delete packets referujące to samo `message_id` nie mają efektu w UI, ale każde urządzenie nadal odszyfrowuje i acknowledge’uje je.
* **Out-of-window operations:** WhatsApp narzuca ~60 h okno dla delete / ~20 min dla edit w UI; Signal narzuca ~48 h. Crafted protocol messages poza tymi oknami są silent ignored na urządzeniu ofiary, a mimo to receipts są transmitowane, więc atakujący może probe’ować w nieskończoność długo po zakończeniu konwersacji.
* **Invalid payloads:** Malformed edit bodies lub deletes referujące już oczyszczone wiadomości wywołują to samo zachowanie — odszyfrowanie plus receipt, zero widocznych artefaktów dla użytkownika.

## Multi-device amplification & fingerprinting

* Każde powiązane urządzenie (telefon, desktop app, browser companion) odszyfrowuje probe niezależnie i zwraca własny ack. Zliczanie receipts na probe ujawnia dokładną liczbę urządzeń.
* Jeśli urządzenie jest offline, jego receipt jest kolejkowane i wysyłane po ponownym połączeniu. Luki więc leak online/offline cycles, a nawet harmonogramy commuting (np. receipts z desktopu przestają przychodzić podczas podróży).
* RTT distributions różnią się w zależności od platformy ze względu na OS power management i push wakeups. Klastruj RTT (np. k-means na median/variance features), aby oznaczyć “Android handset”, “iOS handset”, “Electron desktop” itd.
* Ponieważ sender musi pobrać recipient’s key inventory przed encryptowaniem, atakujący może także obserwować, kiedy nowe devices są parowane; nagły wzrost liczby urządzeń lub nowy RTT cluster jest silnym wskaźnikiem.

## Behaviour inference from RTT traces

1. Sampleuj z ≥1 Hz, aby uchwycić efekty planowania OS. W WhatsApp na iOS <1 s RTT silnie koreluje ze screen-on/foreground, >1 s z screen-off/background throttling.
2. Zbuduj proste klasyfikatory (thresholding lub two-cluster k-means), które etykietują każde RTT jako "active" lub "idle". Agreguj etykiety w streaks, aby wyprowadzić bedtimes, commutes, work hours lub kiedy desktop companion jest aktywny.
3. Koreluj simultaneous probes do każdego urządzenia, aby zobaczyć, kiedy użytkownicy przełączają się z mobile na desktop, kiedy companions są offline, oraz czy app jest rate limited przez push vs persistent socket.

## Stealthy resource exhaustion

Ponieważ każdy silent probe musi być odszyfrowany i acknowledge’owany, ciągłe wysyłanie reaction toggles, invalid edits lub delete-for-everyone packets tworzy application-layer DoS:

* Zmusza radio/modem do transmit/receive co sekundę → zauważalny drain na battery, szczególnie na idle handsets.
* Generuje nieodliczany upstream/downstream traffic, który konsumuje mobile data plans, jednocześnie mieszając się z TLS/WebSocket noise.
* Zajmuje crypto threads i wprowadza jitter w latency-sensitive funkcjach (VoIP, video calls), mimo że użytkownik nigdy nie widzi powiadomień.

## References

- [Careless Whisper: Exploiting Silent Delivery Receipts to Monitor Users on Mobile Instant Messengers](https://arxiv.org/html/2411.11194v4)
- [whatsmeow](https://github.com/tulir/whatsmeow)
- [Cobalt](https://github.com/Auties00/Cobalt)
- [signal-cli](https://github.com/AsamK/signal-cli)
- [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)

{{#include ../banners/hacktricks-training.md}}
