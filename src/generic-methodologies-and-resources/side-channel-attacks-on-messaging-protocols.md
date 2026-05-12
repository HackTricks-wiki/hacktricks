# Ataki bocznego kanału na potwierdzenia dostarczenia w komunikatorach E2EE

{{#include ../banners/hacktricks-training.md}}

Potwierdzenia dostarczenia są obowiązkowe w nowoczesnych komunikatorach z szyfrowaniem end-to-end (E2EE), ponieważ klienty muszą wiedzieć, kiedy ciphertext został odszyfrowany, aby mogły odrzucić stan ratcheting i klucze efemeryczne. Serwer przekazuje nieprzezroczyste bloby, więc potwierdzenia urządzenia (podwójne znaczniki) są emitowane przez odbiorcę po udanym odszyfrowaniu. Pomiar czasu round-trip time (RTT) między akcją wywołaną przez atakującego a odpowiadającym jej potwierdzeniem dostarczenia ujawnia kanał czasowy o wysokiej rozdzielczości, który leakuje stan urządzenia, obecność online i może być nadużyty do ukrytego DoS. Wdrożenia multi-device z modelem "client-fanout" wzmacniają leak, ponieważ każde zarejestrowane urządzenie odszyfrowuje próbkę i zwraca własne potwierdzenie.

## Źródła potwierdzeń dostarczenia vs. sygnały widoczne dla użytkownika

Wybieraj typy wiadomości, które zawsze emitują potwierdzenie dostarczenia, ale nie pokazują artefaktów UI na ofierze. Poniższa tabela podsumowuje empirycznie potwierdzone zachowanie:

| Messenger | Akcja | Potwierdzenie dostarczenia | Powiadomienie ofiary | Uwagi |
|-----------|--------|---------------------------|----------------------|-------|
| **WhatsApp** | Wiadomość tekstowa | ● | ● | Zawsze hałaśliwe → przydatne tylko do bootstrapu stanu. |
| | Reakcja | ● | ◐ (tylko jeśli reagujesz na wiadomość ofiary) | Samoreakcje i ich usunięcia pozostają ciche. |
| | Edycja | ● | Cichy push zależny od platformy | Okno edycji ≈20 min; po wygaśnięciu nadal ack’d. |
| | Delete for everyone | ● | ○ | UI pozwala na ~60 h, ale późniejsze pakiety nadal ack’d. |
| **Signal** | Wiadomość tekstowa | ● | ● | Takie same ograniczenia jak w WhatsApp. |
| | Reakcja | ● | ◐ | Samoreakcje niewidoczne dla ofiary. |
| | Edit/Delete | ● | ○ | Serwer wymusza okno ~48 h, pozwala na do 10 edycji, ale późniejsze pakiety nadal ack’d. |
| **Threema** | Wiadomość tekstowa | ● | ● | Potwierdzenia multi-device są agregowane, więc widoczne jest tylko jedno RTT na próbkę. |

Legenda: ● = zawsze, ◐ = warunkowo, ○ = nigdy. Zachowanie UI zależne od platformy jest opisane w tekście. Wyłącz read receipts, jeśli potrzeba, ale delivery receipts nie można wyłączyć w WhatsApp ani Signal.

## Cele atakującego i modele

* **G1 – Device fingerprinting:** Zliczaj, ile potwierdzeń przychodzi na próbkę, grupuj RTT, aby wywnioskować OS/client (Android vs iOS vs desktop) oraz obserwuj przejścia online/offline.
* **G2 – Monitorowanie zachowania:** Traktuj wysokoczęstotliwościową serię RTT (≈1 Hz jest stabilne) jako szereg czasowy i wnioskuj o screen on/off, app foreground/background, godzinach dojazdów vs pracy itd.
* **G3 – Wyczerpanie zasobów:** Utrzymuj radia/CPU każdego urządzenia ofiary aktywne, wysyłając bez końca ciche próbki, rozładowując baterię/dane i pogarszając jakość VoIP/RTC.

Wystarczą dwie role zagrożenia, aby opisać powierzchnię nadużycia:

1. **Creepy companion:** już ma wspólny chat z ofiarą i nadużywa samoreakcji, usuwania reakcji albo powtarzanych edycji/usunięć powiązanych z istniejącymi `message_id`.
2. **Spooky stranger:** rejestruje konto burnera i wysyła reakcje odwołujące się do `message_id`, które nigdy nie istniały w lokalnej konwersacji; WhatsApp i Signal mimo to odszyfrowują je i potwierdzają, choć UI odrzuca zmianę stanu, więc nie jest wymagana wcześniejsza rozmowa.

## Narzędzia do bezpośredniego dostępu do protokołu

Polegaj na klientach, które ujawniają podstawowy protokół E2EE, aby można było tworzyć pakiety poza ograniczeniami UI, podawać dowolne `message_id` i logować precyzyjne znaczniki czasu:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, protokół WhatsApp Web) albo [Cobalt](https://github.com/Auties00/Cobalt) (zorientowany na mobile) pozwalają wysyłać surowe ramki `ReactionMessage`, `ProtocolMessage` (edit/delete) i `Receipt`, utrzymując stan double-ratchet w synchronizacji.
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) połączony z [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) udostępnia każdy typ wiadomości przez CLI/API. Aktualna składnia `signal-cli` używa `sendReaction RECIPIENT --target-author --target-timestamp`; zostaw `receive` lub `daemon` uruchomione, żeby potwierdzenia dostarczenia były faktycznie zbierane. Przykład przełączania samoreakcji:
```bash
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --emoji "👍"
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --remove
```
* **Threema:** Kod źródłowy klienta Android dokumentuje, jak potwierdzenia dostarczenia są konsolidowane przed opuszczeniem urządzenia, wyjaśniając, dlaczego ten boczny kanał ma tam znikomy bandwidth.
* **Turnkey PoCs:** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker) zawiera backendy WhatsApp/Signal, domyślnie używa cichych probe delete i oznacza `active` vs `standby` za pomocą progu rolling-median (`RTT < 0.9 * median`). [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python) to lżejszy CLI zorientowany najpierw na WhatsApp, z `--delay`, `--concurrent`, exporterami CSV/Prometheus i wyjściem przyjaznym dla Grafana. Traktuj oba jako pomocników do reconnaissance, a nie jako referencje protokołu; kluczowy wniosek to to, jak mało kodu jest potrzebne, gdy istnieje surowy dostęp do klienta.

Gdy własne narzędzia nie są dostępne, nadal można wywoływać ciche akcje z WhatsApp Web lub Signal Desktop i sniffować szyfrowany kanał websocket/WebRTC, ale surowe API usuwają opóźnienia UI i pozwalają na nieprawidłowe operacje.

## Creepy companion: pętla cichego próbkowania

1. Wybierz dowolną historyczną wiadomość, którą sam wysłałeś na chacie, aby ofiara nigdy nie widziała zmian w dymkach "reaction".
2. Naprzemiennie wysyłaj widoczną emoji i pusty payload reakcji (kodowany jako `""` w protobufach WhatsApp albo `--remove` w signal-cli). Każda transmisja daje potwierdzenie urządzenia mimo braku zmiany UI dla ofiary.
3. Oznaczaj czas wysłania i każde nadejście potwierdzenia dostarczenia. Pętla 1 Hz, taka jak poniżej, daje ślady RTT per urządzenie w nieskończoność:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. Ponieważ WhatsApp/Signal akceptują nieograniczone aktualizacje reakcji, atakujący nigdy nie musi publikować nowej treści na czacie ani martwić się o okna edycji.

## Spooky stranger: sondowanie dowolnych numerów telefonu

1. Zarejestruj świeże konto WhatsApp/Signal i pobierz publiczne klucze tożsamości dla numeru celu (robione automatycznie podczas konfiguracji sesji).
2. Zbuduj pakiet reaction/edit/delete, który odnosi się do losowego `message_id` nigdy niewidzianego przez żadną ze stron (WhatsApp akceptuje dowolne GUID `key.id`; Signal używa milisekundowych timestampów).
3. Wyślij pakiet, mimo że nie istnieje żaden thread. Urządzenia ofiary odszyfrowują go, nie znajdują wiadomości bazowej, odrzucają zmianę stanu, ale nadal potwierdzają przychodzący ciphertext, wysyłając potwierdzenia urządzenia z powrotem do atakującego.
4. Powtarzaj ciągle, aby budować serie RTT bez kiedykolwiek pojawiania się na liście czatów ofiary.

Jeśli najpierw musisz ustalić, które numery są zarejestrowane, albo chcesz pre-seedować inventory urządzeń na dużą skalę, połącz to z [contact-discovery / registration oracles](../pentesting-web/registration-vulnerabilities.md) zamiast zgadywać losowe zakresy E.164 ręcznie.

Najnowsze buildy WhatsApp ujawniają też `Settings -> Privacy -> Advanced -> Block unknown account messages`. Traktuj to jako limiter throughput, a nie fix: głównie utrudnia sustained stranger-only flooding i jest nieistotne, gdy jesteś już znanym kontaktem.

## Recykling edycji i usunięć jako ukrytych triggerów

* **Repeated deletes:** Po jednokrotnym `delete-for-everyone`, dalsze pakiety delete odnoszące się do tego samego `message_id` nie mają efektu w UI, ale każde urządzenie nadal je odszyfrowuje i potwierdza.
* **Operacje poza oknem:** WhatsApp wymusza okna ~60 h delete / ~20 min edit w UI; Signal wymusza ~48 h. Spreparowane wiadomości protokołu poza tymi oknami są po cichu ignorowane na urządzeniu ofiary, ale potwierdzenia są transmitowane, więc atakujący może sondować przez bardzo długi czas po zakończeniu rozmowy.
* **Nieprawidłowe payloady:** Źle sformatowane body edycji albo delete odnoszące się do już usuniętych wiadomości wywołują takie samo zachowanie — odszyfrowanie plus potwierdzenie, zero widocznych dla użytkownika artefaktów.

## Wzmocnienie multi-device i fingerprinting

* Każde powiązane urządzenie (telefon, aplikacja desktop, companion browser) odszyfrowuje próbkę niezależnie i zwraca własne ack. Zliczanie potwierdzeń na próbkę ujawnia dokładną liczbę urządzeń.
* Jeśli urządzenie jest offline, jego potwierdzenie jest kolejkujone i emitowane po ponownym połączeniu. Luki leakują więc cykle online/offline, a nawet harmonogramy dojazdów (np. potwierdzenia desktop zanikają podczas podróży).
* Rozkłady RTT różnią się między platformami z powodu zarządzania energią w OS i wakeupów push. Grupuj RTT (np. k-means na cechach median/variance), aby oznaczać „Android handset", „iOS handset", „Electron desktop" itd.
* Ponieważ nadawca musi pobrać inventory kluczy odbiorcy przed szyfrowaniem, atakujący może też obserwować, kiedy nowe urządzenia są parowane; nagły wzrost liczby urządzeń lub nowy klaster RTT to silny wskaźnik.

## Wnioskowanie o zachowaniu na podstawie śladów RTT

1. Próbkuj z częstotliwością ≥1 Hz, aby uchwycić efekty planowania zadań przez OS. W WhatsApp na iOS RTT <1 s silnie koreluje z screen-on/foreground, a >1 s z throttlingiem screen-off/background.
2. Buduj proste klasyfikatory (thresholding lub dwuklastrowy k-means), które oznaczają każdy RTT jako "active" albo "idle". Agreguj etykiety w streaks, aby wywnioskować godziny snu, dojazdy, godziny pracy albo to, kiedy aktywny jest companion desktop.
3. Koreluj jednoczesne próbki do każdego urządzenia, aby zobaczyć, kiedy użytkownicy przełączają się z mobile na desktop, kiedy companions przechodzą offline i czy aplikacja jest rate limited przez push czy przez persistent socket.
4. W rzeczywistych sieciach unikaj jednej zakodowanej na sztywno wartości `1 s`. Zainicjalizuj każde urządzenie krótkim oknem rozgrzewki i utrzymuj rolling baseline (na przykład `threshold = 0.9 * median RTT`), żeby drift Wi-Fi/cellular nie zniszczył klasyfikatora.

## Wnioskowanie o lokalizacji z delivery RTT

Ten sam prymityw czasowy można wykorzystać ponownie do ustalenia, gdzie znajduje się odbiorca, a nie tylko czy jest aktywny. Praca `Hope of Delivery` pokazała, że trenowanie na rozkładach RTT dla znanych lokalizacji odbiorcy pozwala atakującemu później klasyfikować lokalizację ofiary wyłącznie na podstawie potwierdzeń dostarczenia:

* Zbuduj baseline dla tego samego celu, gdy znajduje się w kilku znanych miejscach (dom, biuro, kampus, kraj A vs kraj B itd.).
* Dla każdej lokalizacji zbierz wiele normalnych RTT wiadomości i wyodrębnij proste cechy, takie jak mediana, variance lub bucket’y percentyli.
* Podczas właściwego ataku porównaj nową serię próbek z wytrenowanymi klastrami. W pracy raportuje się, że nawet lokalizacje w tym samym mieście często da się rozdzielić, z dokładnością `>80%` w scenariuszu 3-lokalizacyjnym.
* Działa to najlepiej, gdy atakujący kontroluje środowisko nadawcy i sonduje przy podobnych warunkach sieciowych, ponieważ mierzona ścieżka obejmuje sieć dostępową odbiorcy, opóźnienie wake-up i infrastrukturę komunikatora.

W przeciwieństwie do cichych ataków reaction/edit/delete powyżej, wnioskowanie o lokalizacji nie wymaga nieprawidłowych `message_id` ani stealthy pakietów zmieniających stan. Wystarczą zwykłe wiadomości z normalnymi potwierdzeniami dostarczenia, więc tradeoff to mniejsza stealth, ale szersza użyteczność across messengers.

## Stealthy resource exhaustion

Ponieważ każda cicha próbka musi zostać odszyfrowana i potwierdzona, ciągłe wysyłanie przełączeń reakcji, nieprawidłowych edycji lub pakietów delete-for-everyone tworzy application-layer DoS:

* Wymusza na radiu/modemie transmisję i odbiór co sekundę → zauważalny drain baterii, szczególnie na bezczynnych handsetach.
* Generuje niebiletowany ruch upstream/downstream, który zużywa plany danych mobile, jednocześnie zlewając się z szumem TLS/WebSocket.
* Zajmuje wątki crypto i wprowadza jitter w funkcjach wrażliwych na opóźnienia (VoIP, video calls), mimo że użytkownik nigdy nie widzi powiadomień.
* W WhatsApp nieprawidłowe reakcje akceptują znacznie więcej danych, niż sugeruje zwykła emoji: opublikowane pomiary wykazały akceptację po stronie serwera do około `1 MB` na reakcję.
* Zbyt duże reakcje przestają generować wiarygodne potwierdzenia dostarczenia, gdy body rośnie powyżej około `30 bytes`, ale nadal są przekazywane dalej i przetwarzane przed odrzuceniem. Trzymaj body reakcji małe, gdy potrzebujesz ACK; powiększaj je tylko wtedy, gdy celem jest czysty drain albo ukryty one-way transport.
* Publiczne pomiary osiągnęły około `3.7 MB/s` (`~13.3 GB/h`) ruchu ofiary w tym trybie.

## References

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
