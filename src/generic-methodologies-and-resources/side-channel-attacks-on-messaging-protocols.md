# Ataki bocznego kanału na potwierdzenia dostarczenia w E2EE Messengerach

{{#include ../banners/hacktricks-training.md}}

Potwierdzenia dostarczenia są obowiązkowe w nowoczesnych messengerach z end-to-end encrypted (E2EE), ponieważ klienci muszą wiedzieć, kiedy ciphertext został odszyfrowany, aby mogli odrzucić stan ratcheting i efemeryczne klucze. Serwer przekazuje nieprzejrzyste bloby, więc potwierdzenia urządzenia (podwójne haczyki) są emitowane przez odbiorcę po udanym odszyfrowaniu. Pomiar czasu round-trip time (RTT) między działaniem wywołanym przez atakującego a odpowiadającym mu potwierdzeniem dostarczenia ujawnia kanał czasowy o wysokiej rozdzielczości, który leakuje stan urządzenia, obecność online i może być nadużywany do ukrytego DoS. Wdrożenia multi-device "client-fanout" wzmacniają leak, ponieważ każde zarejestrowane urządzenie odszyfrowuje sondę i zwraca własne potwierdzenie.

## Źródła potwierdzeń dostarczenia vs. sygnały widoczne dla użytkownika

Wybieraj typy wiadomości, które zawsze emitują potwierdzenie dostarczenia, ale nie pokazują artefaktów UI na ofierze. Poniższa tabela podsumowuje empirycznie potwierdzone zachowanie:

| Messenger | Action | Delivery receipt | Victim notification | Notes |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Text message | ● | ● | Zawsze hałaśliwe → użyteczne tylko do bootstrap stanu. |
| | Reaction | ● | ◐ (only if reacting to victim message) | Self-reactions i removals pozostają ciche. |
| | Edit | ● | Silent push zależny od platformy | Okno edycji ≈20 min; po wygaśnięciu nadal ack’d. |
| | Delete for everyone | ● | ○ | UI pozwala na ~60 h, ale późniejsze pakiety nadal są ack’d. |
| **Signal** | Text message | ● | ● | Te same ograniczenia co w WhatsApp. |
| | Reaction | ● | ◐ | Self-reactions niewidoczne dla ofiary. |
| | Edit/Delete | ● | ○ | Serwer egzekwuje okno ~48 h, pozwala na do 10 edycji, ale spóźnione pakiety nadal są ack’d. |
| **Threema** | Text message | ● | ● | Potwierdzenia multi-device są agregowane, więc widoczne jest tylko jedno RTT na sondę. |

Legenda: ● = zawsze, ◐ = warunkowo, ○ = nigdy. Zachowanie UI zależne od platformy jest opisane inline. W razie potrzeby wyłącz read receipts, ale delivery receipts nie da się wyłączyć w WhatsApp ani Signal.

## Cele atakującego i modele

* **G1 – Device fingerprinting:** Policz, ile potwierdzeń przychodzi na jedną sondę, klastruj RTT, aby wywnioskować OS/client (Android vs iOS vs desktop) i obserwuj przejścia online/offline.
* **G2 – Behavioural monitoring:** Traktuj wysokoczęstotliwościowy szereg RTT (≈1 Hz jest stabilne) jako szereg czasowy i wnioskuj o screen on/off, app foreground/background, dojazdach vs godzinach pracy itd.
* **G3 – Resource exhaustion:** Utrzymuj radio/CPU każdego urządzenia ofiary w stanie aktywnym, wysyłając niekończące się ciche sondy, rozładowując baterię/dane i pogarszając jakość VoIP/RTC.

Do opisania powierzchni nadużyć wystarczą dwa typy atakujących:

1. **Creepy companion:** już współdzieli czat z ofiarą i nadużywa self-reactions, reakcji removals albo powtarzanych edycji/usunięć powiązanych z istniejącymi message IDs.
2. **Spooky stranger:** rejestruje konto burner i wysyła reakcje odwołujące się do message IDs, które nigdy nie istniały w lokalnej konwersacji; WhatsApp i Signal nadal je odszyfrowują i potwierdzają, mimo że UI odrzuca zmianę stanu, więc wcześniejsza konwersacja nie jest wymagana.

## Narzędzia do surowego dostępu do protokołu

Polegaj na klientach, które ujawniają podstawowy protokół E2EE, aby móc tworzyć pakiety poza ograniczeniami UI, podawać arbitralne `message_id`s i logować precyzyjne znaczniki czasu:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, protokół WhatsApp Web) lub [Cobalt](https://github.com/Auties00/Cobalt) (zorientowany na mobile) pozwalają emitować surowe ramki `ReactionMessage`, `ProtocolMessage` (edit/delete) i `Receipt`, utrzymując stan double-ratchet w synchronizacji.
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) połączony z [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) udostępnia każdy typ wiadomości przez CLI/API. Aktualna składnia `signal-cli` używa `sendReaction RECIPIENT --target-author --target-timestamp`; trzymaj uruchomione `receive` albo `daemon`, aby delivery receipts były faktycznie zbierane. Przykład przełączania self-reaction:
```bash
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --emoji "👍"
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --remove
```
* **Threema:** Źródła klienta Android dokumentują, jak delivery receipts są konsolidowane przed opuszczeniem urządzenia, wyjaśniając, dlaczego side channel ma tam znikomą przepustowość.
* **Turnkey PoCs:** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker) dostarcza backendy WhatsApp/Signal, domyślnie używa cichych sond delete i oznacza `active` vs `standby` za pomocą progu rolling-median (`RTT < 0.9 * median`). [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python) to lżejszy CLI dla WhatsApp-first z `--delay`, `--concurrent`, eksportami CSV/Prometheus i wyjściem przyjaznym dla Grafana. Traktuj oba jako helpers do reconnaissance, a nie jako referencje protokołu; ważny wniosek to to, jak mało kodu potrzeba, gdy istnieje surowy dostęp do klienta.

Gdy własne narzędzia nie są dostępne, nadal możesz wywoływać ciche akcje z WhatsApp Web lub Signal Desktop i sniffować zaszyfrowany kanał websocket/WebRTC, ale surowe API usuwają opóźnienia UI i pozwalają na nieprawidłowe operacje.

## Creepy companion: silent sampling loop

1. Wybierz dowolną historyczną wiadomość, którą napisałeś w czacie, tak aby ofiara nigdy nie widziała, jak baloniki "reaction" się zmieniają.
2. Naprzemiennie wysyłaj widoczne emoji i pusty payload reakcji (kodowany jako `""` w protobufach WhatsApp albo `--remove` w signal-cli). Każda transmisja daje ack urządzenia mimo braku zmian UI dla ofiary.
3. Zapisz czas wysłania i każde nadejście delivery receipt. Pętla 1 Hz, taka jak poniżej, daje ślady RTT per device w nieskończoność:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. Ponieważ WhatsApp/Signal akceptują nieograniczone aktualizacje reakcji, atakujący nigdy nie musi publikować nowej treści czatu ani martwić się oknami edycji.

## Spooky stranger: sondowanie arbitralnych numerów telefonu

1. Zarejestruj świeże konto WhatsApp/Signal i pobierz publiczne identity keys dla numeru celu (robi się to automatycznie podczas konfiguracji sesji).
2. Zbuduj pakiet reaction/edit/delete, który odwołuje się do losowego `message_id`, nigdy niewidzianego przez żadną ze stron (WhatsApp akceptuje arbitralne GUID `key.id`; Signal używa znaczników czasu w milisekundach).
3. Wyślij pakiet, mimo że żaden wątek nie istnieje. Urządzenia ofiary odszyfrowują go, nie mogą dopasować wiadomości bazowej, odrzucają zmianę stanu, ale nadal potwierdzają przychodzący ciphertext, odsyłając delivery receipts do atakującego.
4. Powtarzaj to ciągle, aby budować szeregi RTT bez kiedykolwiek pojawiania się na liście czatów ofiary.

Jeśli najpierw musisz ustalić, które numery są zarejestrowane, albo chcesz masowo pre-seedować inventories urządzeń, połącz to z [contact-discovery / registration oracles](../pentesting-web/registration-vulnerabilities.md) zamiast zgadywać losowe zakresy E.164 ręcznie.

Opublikowane badania nad contact-discovery pokazały, dlaczego ma to znaczenie operacyjne: przy dokładnych tabelach prefiksów telefonicznych i umiarkowanych zasobach badacze byli w stanie zapytać około `10%` amerykańskich numerów mobilnych w WhatsApp i `100%` w Signal, zanim przeszli do ukierunkowanego sondowania. W praktyce wcześniejsze filtrowanie aktywnych kont pozwala skupić budżet cichych sond na numerach, które rzeczywiście będą odszyfrowywać pakiety.

Najnowsze buildy WhatsApp udostępniają też `Settings -> Privacy -> Advanced -> Block unknown account messages`. Traktuj to jako limiter przepustowości, a nie naprawę: głównie utrudnia utrzymane floodowanie od nieznajomych i nie ma znaczenia, gdy jesteś już znanym kontaktem.

## Recykling edycji i usunięć jako ukrytych triggerów

* **Repeated deletes:** Po tym, jak wiadomość została raz usunięta-for-everyone, kolejne pakiety delete odwołujące się do tego samego `message_id` nie mają efektu UI, ale każde urządzenie nadal je odszyfrowuje i potwierdza.
* **Out-of-window operations:** WhatsApp egzekwuje w UI okna ~60 h dla delete / ~20 min dla edit; Signal egzekwuje ~48 h. Spreparowane wiadomości protokołu poza tymi oknami są po cichu ignorowane na urządzeniu ofiary, ale receipts są transmitowane, więc atakujący mogą sondować bez końca długo po zakończeniu rozmowy.
* **Invalid payloads:** Uszkodzone body edit lub delete odwołujące się do już wyczyszczonych wiadomości wywołują to samo zachowanie — odszyfrowanie plus receipt, zero artefaktów widocznych dla użytkownika.

## Multi-device amplification & fingerprinting

* Każde powiązane urządzenie (telefon, aplikacja desktopowa, companion browser) odszyfrowuje sondę niezależnie i zwraca własny ack. Zliczanie receipts na jedną sondę ujawnia dokładną liczbę urządzeń.
* Jeśli urządzenie jest offline, jego receipt jest kolejkowane i emitowane po ponownym połączeniu. Luki leakują więc cykle online/offline, a nawet harmonogramy dojazdów (np. receipts desktopowe zatrzymują się podczas podróży).
* Rozkłady RTT różnią się między platformami z powodu zarządzania energią OS i wakeupów push. Klastruj RTT (np. k-means na cechach median/variance), aby etykietować „Android handset", „iOS handset", „Electron desktop" itd.
* Ponieważ nadawca musi pobrać inventory kluczy odbiorcy przed szyfrowaniem, atakujący może też obserwować, kiedy parowane są nowe urządzenia; nagły wzrost liczby urządzeń lub nowy klaster RTT jest silnym wskaźnikiem.

## Sampling cadence, queueing, and stacked receipts

* **WhatsApp burst tolerance:** Opublikowane pomiary raportowały, że WhatsApp akceptował bursty silent-reaction nawet z szybkością jednej sondy co `50 ms` bez oczywistego queueing po stronie serwera. Jest to przydatne do krótkich burstów kalibracyjnych, szybkiego liczenia urządzeń lub szybkiego uruchamiania ataku drain.
* **Signal long-run queueing:** Signal tolerował krótkie bursty, ale zaczął kolejkować utrzymujący się ruch wielosondowy na sekundę. Do długotrwałego monitoringu trzymaj cadence około `1 Hz` (lub niżej), aby każde potwierdzenie nadal odzwierciedlało aktualny stan urządzenia, a nie spłacanie backlogu.
* **Reconnect artefacts:** Gdy urządzenie wraca online, niektórzy klienci batchują lub szybko flushują kilka opóźnionych receipts. Traktuj takie bursty receiptów jako marker zmiany stanu, a nie jako niezależne próbki RTT, bo inaczej clustering / klasyfikator `active` vs `idle` będzie overfitować szum ponownego połączenia.

## Wnioskowanie o zachowaniu na podstawie śladów RTT

1. Próbkuj z częstotliwością ≥1 Hz, aby uchwycić efekty planowania OS. W WhatsApp na iOS RTT < 1 s silnie koreluje ze screen-on/foreground, a > 1 s ze screen-off/background throttling.
2. Buduj proste klasyfikatory (thresholding albo dwuklasowy k-means), które etykietują każdy RTT jako "active" lub "idle". Agreguj etykiety w streaks, aby wyprowadzić godziny snu, dojazdy, godziny pracy lub momenty aktywności companiona desktopowego.
3. Koreluj równoczesne sondy do każdego urządzenia, aby zobaczyć, kiedy użytkownicy przełączają się z mobile na desktop, kiedy companions idą offline i czy aplikacja jest rate limited przez push czy persistent socket.
4. W rzeczywistych sieciach unikaj jednego twardo zakodowanego progu `1 s`. Bootstrappuj każde urządzenie krótkim oknem rozgrzewki i utrzymuj rolling baseline (na przykład `threshold = 0.9 * median RTT`), aby drift Wi-Fi/cellular nie rozwalił klasyfikatora.

## Inference lokalizacji z delivery RTT

Ten sam prymityw czasowy można wykorzystać nie tylko do stwierdzenia, czy odbiorca jest aktywny, ale też gdzie się znajduje. Badanie `Hope of Delivery` pokazało, że trenowanie na rozkładach RTT dla znanych lokalizacji odbiorcy pozwala atakującemu później klasyfikować lokalizację ofiary wyłącznie na podstawie potwierdzeń dostarczenia:

* Zbuduj baseline dla tego samego celu, gdy znajduje się w kilku znanych miejscach (dom, biuro, kampus, kraj A vs kraj B itd.).
* Dla każdej lokalizacji zbierz wiele zwykłych RTT wiadomości i wyodrębnij proste cechy, takie jak mediana, wariancja lub koszyki percentyli.
* Podczas właściwego ataku porównaj nowy szereg sond z wytrenowanymi klastrami. Praca raportuje, że nawet lokalizacje w tym samym mieście często można rozdzielić, z dokładnością `>80%` w scenariuszu 3 lokalizacji.
* Działa to najlepiej, gdy atakujący kontroluje środowisko nadawcy i sonduje w podobnych warunkach sieciowych, ponieważ mierzona ścieżka obejmuje sieć dostępowa odbiorcy, latency wybudzania i infrastrukturę messengera.

W przeciwieństwie do cichych ataków reaction/edit/delete powyżej, inference lokalizacji nie wymaga invalid message IDs ani stealthy pakietów zmieniających stan. Wystarczą zwykłe wiadomości z normalnymi potwierdzeniami dostarczenia, więc kompromis to mniejszy stealth, ale szersza stosowalność między messengerami.

## Stealthy resource exhaustion

Ponieważ każda cicha sonda musi zostać odszyfrowana i potwierdzona, ciągłe wysyłanie toggli reakcji, invalid edits lub pakietów delete-for-everyone tworzy application-layer DoS:

* Wymusza transmisję/odbiór na radio/modemie co sekundę → zauważalny drain baterii, szczególnie na bezczynnych handsetach.
* Generuje nieprzeliczony upstream/downstream traffic, który zużywa pakiety danych mobilnych, mieszając się z szumem TLS/WebSocket.
* Zajmuje wątki crypto i wprowadza jitter w funkcjach wrażliwych na opóźnienia (VoIP, wideorozmowy), mimo że użytkownik nigdy nie widzi powiadomień.
* W WhatsApp invalid reactions akceptują znacznie więcej danych, niż sugeruje zwykłe emoji: opublikowane pomiary wykazały akceptację po stronie serwera do około `1 MB` na reaction.
* Oversized reactions przestają dawać wiarygodne delivery receipts, gdy body rośnie powyżej około `30 bytes`, ale nadal są przekazywane i przetwarzane przed odrzuceniem. Trzymaj body reakcji małe, gdy potrzebujesz ACK; powiększaj je tylko wtedy, gdy celem jest czysty drain albo ukryty transport jednokierunkowy.
* Publiczne pomiary osiągnęły około `3.7 MB/s` (`~13.3 GB/h`) ruchu ofiary w tym trybie.

## References

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
