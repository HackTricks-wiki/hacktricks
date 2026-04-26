# Ataki bocznego kanału na potwierdzenia dostarczenia w messengerach E2EE

{{#include ../banners/hacktricks-training.md}}

Potwierdzenia dostarczenia są obowiązkowe w nowoczesnych messengerach z szyfrowaniem end-to-end (E2EE), ponieważ klienty muszą wiedzieć, kiedy ciphertext został odszyfrowany, aby mogły odrzucić stan ratchetingu i klucze efemeryczne. Serwer przekazuje nieprzejrzyste blob-y, więc potwierdzenia urządzenia (podwójne ptaszki) są wysyłane przez odbiorcę po udanym odszyfrowaniu. Pomiar czasu round-trip time (RTT) między akcją wywołaną przez atakującego a odpowiadającym jej potwierdzeniem dostarczenia ujawnia kanał czasowy o wysokiej rozdzielczości, który leakuje stan urządzenia, obecność online i może być nadużywany do ukrytego DoS. Wdrożenia multi-device typu "client-fanout" wzmacniają leak, ponieważ każde zarejestrowane urządzenie odszyfrowuje probe i odsyła własne potwierdzenie.

## Źródła potwierdzeń dostarczenia vs. sygnały widoczne dla użytkownika

Wybieraj typy wiadomości, które zawsze emitują potwierdzenie dostarczenia, ale nie pokazują artefaktów UI na urządzeniu ofiary. Poniższa tabela podsumowuje empirycznie potwierdzone zachowanie:

| Messenger | Action | Delivery receipt | Victim notification | Notes |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Text message | ● | ● | Zawsze hałaśliwe → przydatne tylko do bootstrapowania stanu. |
| | Reaction | ● | ◐ (tylko jeśli reaguje na wiadomość ofiary) | Reakcje na siebie i ich usunięcia pozostają ciche. |
| | Edit | ● | ciche powiadomienie zależne od platformy | Okno edycji ≈20 min; po wygaśnięciu nadal ack’d. |
| | Delete for everyone | ● | ○ | UI pozwala na ~60 h, ale późniejsze pakiety nadal są ack’d. |
| **Signal** | Text message | ● | ● | Takie same ograniczenia jak w WhatsApp. |
| | Reaction | ● | ◐ | Reakcje na siebie niewidoczne dla ofiary. |
| | Edit/Delete | ● | ○ | Serwer wymusza okno ~48 h, pozwala na maks. 10 edycji, ale spóźnione pakiety nadal są ack’d. |
| **Threema** | Text message | ● | ● | Potwierdzenia multi-device są agregowane, więc widoczny jest tylko jeden RTT na probe. |

Legenda: ● = zawsze, ◐ = warunkowo, ○ = nigdy. Zachowanie UI zależne od platformy jest zaznaczone inline. W razie potrzeby wyłącz read receipts, ale delivery receipts nie da się wyłączyć w WhatsApp ani Signal.

## Cele atakującego i modele

* **G1 – Fingerprinting urządzenia:** Policz, ile potwierdzeń przychodzi na jedną probe, grupuj RTT, aby wywnioskować OS/client (Android vs iOS vs desktop), i obserwuj przejścia online/offline.
* **G2 – Monitoring behawioralny:** Traktuj wysokoczęstotliwościowy szereg RTT (≈1 Hz jest stabilne) jako time-series i wywnioskuj screen on/off, app foreground/background, godziny dojazdów vs pracy itd.
* **G3 – Wyczerpanie zasobów:** Trzymaj radia/CPU każdego urządzenia ofiary aktywne, wysyłając nieskończone ciche probe, rozładowując baterię/dane i pogarszając jakość VoIP/RTC.

Do opisania powierzchni nadużyć wystarczą dwa typy zagrożeń:

1. **Creepy companion:** już dzieli chat z ofiarą i nadużywa self-reactions, usuwania reakcji lub powtarzanych edycji/usunięć powiązanych z istniejącymi message IDs.
2. **Spooky stranger:** rejestruje jednorazowe konto i wysyła reakcje odnoszące się do message IDs, które nigdy nie istniały w lokalnej rozmowie; WhatsApp i Signal mimo to nadal je odszyfrowują i potwierdzają, choć UI odrzuca zmianę stanu, więc wcześniejsza rozmowa nie jest wymagana.

## Narzędzia do surowego dostępu do protokołu

Korzystaj z klientów, które ujawniają bazowy protokół E2EE, aby można było tworzyć pakiety poza ograniczeniami UI, podawać dowolne `message_id`s i logować precyzyjne znaczniki czasu:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, protokół WhatsApp Web) lub [Cobalt](https://github.com/Auties00/Cobalt) (zorientowany na mobile) pozwalają wysyłać surowe ramki `ReactionMessage`, `ProtocolMessage` (edit/delete) i `Receipt`, utrzymując stan double-ratchet w synchronizacji.
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) w połączeniu z [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) udostępnia każdy typ wiadomości przez CLI/API. Przykład przełączania self-reaction:
```bash
signal-cli -u +12025550100 sendReaction --target +12025550123 \
--message-timestamp 1712345678901 --emoji "👍"
signal-cli -u +12025550100 sendReaction --target +12025550123 \
--message-timestamp 1712345678901 --remove  # encodes empty emoji
```
* **Threema:** Kod źródłowy klienta Android dokumentuje, jak delivery receipts są konsolidowane przed opuszczeniem urządzenia, co wyjaśnia, dlaczego w tym przypadku boczny kanał ma znikomą przepustowość.
* **Turnkey PoCs:** publiczne projekty takie jak `device-activity-tracker` i `careless-whisper-python` już automatyzują ciche probe delete/reaction i klasyfikację RTT. Traktuj je jako gotowe pomocniki rozpoznawcze, a nie referencje protokołu; interesujące jest to, że potwierdzają, iż atak jest operacyjnie prosty, gdy istnieje surowy dostęp do klienta.

Gdy niestandardowe narzędzia są niedostępne, nadal można wywołać ciche akcje z WhatsApp Web lub Signal Desktop i sniffować szyfrowany kanał websocket/WebRTC, ale surowe API usuwają opóźnienia UI i pozwalają na nieprawidłowe operacje.

## Creepy companion: cicha pętla próbkowania

1. Wybierz dowolną historyczną wiadomość, którą sam napisałeś w chacie, aby ofiara nigdy nie widziała zmian w balonikach "reaction".
2. Przełączaj się między widocznym emoji a pustym payloadem reakcji (kodowanym jako `""` w protobufach WhatsApp albo `--remove` w signal-cli). Każda transmisja daje ack urządzenia mimo braku zmiany UI po stronie ofiary.
3. Zapisz czas wysłania i każdy moment przyjścia delivery receipt. Pętla 1 Hz, taka jak poniżej, daje ślady RTT per device bez ograniczeń:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. Ponieważ WhatsApp/Signal akceptują nieograniczoną liczbę aktualizacji reakcji, atakujący nigdy nie musi publikować nowej treści na czacie ani martwić się oknami edycji.

## Spooky stranger: sondowanie dowolnych numerów telefonu

1. Zarejestruj świeże konto WhatsApp/Signal i pobierz publiczne klucze tożsamości dla numeru celu (dzieje się to automatycznie podczas konfiguracji sesji).
2. Zbuduj pakiet reaction/edit/delete, który odnosi się do losowego `message_id` nigdy niewidzianego przez żadną ze stron (WhatsApp akceptuje dowolne GUID `key.id`; Signal używa timestampów w milisekundach).
3. Wyślij pakiet, mimo że nie istnieje żaden wątek. Urządzenia ofiary odszyfrują go, nie dopasują wiadomości bazowej, odrzucą zmianę stanu, ale nadal potwierdzą przychodzący ciphertext, odsyłając potwierdzenia urządzenia do atakującego.
4. Powtarzaj to ciągle, aby zbudować szereg RTT bez pojawiania się w liście czatów ofiary.

## Recykling edycji i usunięć jako ukrytych triggerów

* **Repeated deletes:** Po usunięciu wiadomości dla wszystkich raz, dalsze pakiety delete odnoszące się do tego samego `message_id` nie mają efektu w UI, ale każde urządzenie nadal je odszyfrowuje i potwierdza.
* **Operacje poza oknem:** WhatsApp wymusza w UI okna ~60 h dla delete / ~20 min dla edit; Signal wymusza ~48 h. Zbudowane wiadomości protokołu poza tymi oknami są po cichu ignorowane na urządzeniu ofiary, lecz receipt-y są nadal transmitowane, więc atakujący może sondować bez końca długo po zakończeniu rozmowy.
* **Invalid payloads:** Wadliwe body edycji lub delete odnoszące się do już usuniętych wiadomości wywołują takie samo zachowanie — odszyfrowanie plus receipt, zero artefaktów widocznych dla użytkownika.

## Wzmocnienie multi-device i fingerprinting

* Każde powiązane urządzenie (telefon, desktop app, browser companion) odszyfrowuje probe niezależnie i zwraca własny ack. Liczenie receiptów na jedną probe ujawnia dokładną liczbę urządzeń.
* Jeśli urządzenie jest offline, jego receipt jest kolejkowany i wysyłany po ponownym połączeniu. Luki ujawniają więc cykle online/offline, a nawet harmonogram dojazdów (np. receipt-y desktopa zatrzymują się podczas podróży).
* Rozkłady RTT różnią się między platformami z powodu zarządzania energią OS i wakeupów push. Grupuj RTT (np. k-means na cechach mediany/wariancji), aby etykietować „Android handset", „iOS handset", „Electron desktop" itd.
* Ponieważ nadawca musi pobrać inventory kluczy odbiorcy przed szyfrowaniem, atakujący może też obserwować, kiedy parowane są nowe urządzenia; nagły wzrost liczby urządzeń lub nowy klaster RTT jest silnym wskaźnikiem.

## Wnioskowanie behawioralne z trace RTT

1. Próbkuj z częstotliwością ≥1 Hz, aby uchwycić efekty planowania OS. W WhatsApp na iOS RTT <1 s silnie korelują z ekranem włączonym / foreground, a >1 s z ekranem wyłączonym / throttlingiem w tle.
2. Buduj proste klasyfikatory (thresholding lub dwuklastrowy k-means), które etykietują każdy RTT jako "active" lub "idle". Agreguj etykiety w streaks, aby wyprowadzić godziny snu, dojazdy, godziny pracy lub momenty aktywności desktopowego companion.
3. Koreluj jednoczesne probe do wszystkich urządzeń, aby zobaczyć, kiedy użytkownicy przełączają się z mobile na desktop, kiedy companions przechodzą offline i czy app jest rate limited przez push czy persistent socket.

## Wnioskowanie o lokalizacji z delivery RTT

Ten sam prymityw czasowy można wykorzystać ponownie do ustalenia, gdzie znajduje się odbiorca, a nie tylko czy jest aktywny. Praca `Hope of Delivery` pokazała, że trenowanie na rozkładach RTT dla znanych lokalizacji odbiorcy pozwala atakującemu później klasyfikować lokalizację ofiary wyłącznie na podstawie potwierdzeń dostarczenia:

* Zbuduj baseline dla tego samego celu, gdy przebywa w kilku znanych miejscach (dom, biuro, kampus, kraj A vs kraj B itd.).
* Dla każdej lokalizacji zbierz wiele zwykłych RTT wiadomości i wyciągnij proste cechy, takie jak mediana, wariancja lub koszyki percentyli.
* Podczas rzeczywistego ataku porównaj nowy szereg probe z wytrenowanymi klastrami. W pracy raportowano, że nawet lokalizacje w tym samym mieście można często rozdzielić, z dokładnością `>80%` w scenariuszu 3 lokalizacji.
* Działa to najlepiej, gdy atakujący kontroluje środowisko nadawcy i sonduje w podobnych warunkach sieciowych, ponieważ mierzona ścieżka obejmuje sieć dostępową odbiorcy, latency wybudzania i infrastrukturę messengera.

W przeciwieństwie do cichych ataków reaction/edit/delete opisanych powyżej, wnioskowanie o lokalizacji nie wymaga nieprawidłowych message IDs ani skrytych pakietów zmieniających stan. Wystarczą zwykłe wiadomości z normalnymi potwierdzeniami dostarczenia, więc kompromisem jest mniejsza stealth, ale szersza stosowalność między messengerami.

## Stealthy resource exhaustion

Ponieważ każda cicha probe musi zostać odszyfrowana i potwierdzona, ciągłe wysyłanie przełączników reakcji, nieprawidłowych edycji lub pakietów delete-for-everyone tworzy DoS na warstwie aplikacji:

* Wymusza na radiu/modemie nadawanie/odbiór co sekundę → zauważalny drain baterii, szczególnie na bezczynnych handsetach.
* Generuje nieopodatkowany upstream/downstream traffic, który zużywa plany danych mobilnych, a jednocześnie wtapia się w szum TLS/WebSocket.
* Zajmuje wątki crypto i wprowadza jitter w funkcjach wrażliwych na latency (VoIP, wideorozmowy), mimo że użytkownik nigdy nie widzi powiadomień.

## References

- [Careless Whisper: Exploiting Silent Delivery Receipts to Monitor Users on Mobile Instant Messengers](https://arxiv.org/html/2411.11194v4)
- [Hope of Delivery: Extracting User Locations From Mobile Instant Messengers](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [whatsmeow](https://github.com/tulir/whatsmeow)
- [Cobalt](https://github.com/Auties00/Cobalt)
- [signal-cli](https://github.com/AsamK/signal-cli)
- [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)

{{#include ../banners/hacktricks-training.md}}
