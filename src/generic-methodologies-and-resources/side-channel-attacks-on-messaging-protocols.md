# Ataki side-channel wykorzystujące potwierdzenia dostarczenia w komunikatorach E2EE

{{#include ../banners/hacktricks-training.md}}

Potwierdzenia dostarczenia są obowiązkowe we współczesnych komunikatorach z szyfrowaniem end-to-end (E2EE), ponieważ klienci muszą wiedzieć, kiedy ciphertext został odszyfrowany, aby móc odrzucić stan ratchetingu i klucze efemeryczne. Serwer przekazuje nieprzezroczyste bloby, więc potwierdzenia urządzeń (podwójne haczyki) są emitowane przez odbiorcę po pomyślnym odszyfrowaniu. Pomiar czasu round-trip (RTT) między akcją wywołaną przez atakującego a odpowiadającym jej potwierdzeniem dostarczenia ujawnia wysokorozdzielczy kanał czasowy, który leak stan urządzenia i obecność online, a także może być używany do covert DoS. Wdrożenia multi-device typu „client-fanout” wzmacniają leak, ponieważ każde zarejestrowane urządzenie odszyfrowuje probe i zwraca własne potwierdzenie.<sup>[[1]](#references)</sup>

## Źródła potwierdzeń dostarczenia a sygnały widoczne dla użytkownika

Wybierz typy wiadomości, które zawsze emitują potwierdzenie dostarczenia, ale nie powodują artefaktów UI po stronie ofiary. Poniższa tabela podsumowuje empirycznie potwierdzone zachowanie:<sup>[[1]](#references)</sup>

| Messenger | Akcja | Potwierdzenie dostarczenia | Powiadomienie ofiary | Uwagi |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Wiadomość tekstowa | ● | ● | Zawsze powoduje noise → przydatne tylko do bootstrapowania stanu. |
| | Reakcja | ● | ◐ (tylko przy reagowaniu na wiadomość ofiary) | Reakcje na własne wiadomości i ich usuwanie pozostają niewidoczne. |
| | Edycja | ● | Zależne od platformy silent push | Okno edycji ≈20 min; potwierdzenie nadal jest wysyłane po jego wygaśnięciu. |
| | Usuń dla wszystkich | ● | ○ | UI pozwala na ~60 h, ale późniejsze pakiety nadal otrzymują potwierdzenie. |
| **Signal** | Wiadomość tekstowa | ● | ● | Te same ograniczenia co w WhatsApp. |
| | Reakcja | ● | ◐ | Reakcje na własne wiadomości są niewidoczne dla ofiary. |
| | Edycja/Usunięcie | ● | ○ | Serwer wymusza okno ~48 h i pozwala na maksymalnie 10 edycji, ale późne pakiety nadal otrzymują potwierdzenie. |
| **Threema** | Wiadomość tekstowa | ● | ● | Potwierdzenia multi-device są agregowane, więc widoczne jest tylko jedno RTT na probe. |

Legenda: ● = zawsze, ◐ = warunkowo, ○ = nigdy. Zależne od platformy zachowanie UI odnotowano w tekście. W razie potrzeby wyłącz read receipts, ale delivery receipts nie można wyłączyć w WhatsApp ani Signal.<sup>[[1]](#references)</sup>

## Cele i modele atakującego

* **G1 – Fingerprinting urządzeń:** Zliczaj, ile potwierdzeń dociera dla każdego probe, grupuj RTT, aby wnioskować o systemie operacyjnym/kliencie (Android vs iOS vs desktop), oraz obserwuj przejścia online/offline.
* **G2 – Monitorowanie zachowania:** Traktuj serię RTT o wysokiej częstotliwości (≈1 Hz jest stabilne) jako szereg czasowy i wnioskuj o włączaniu/wyłączaniu ekranu, działaniu aplikacji na pierwszym/drugim planie, godzinach dojazdów i pracy itd.
* **G3 – Wyczerpywanie zasobów:** Utrzymuj radia/CPU wszystkich urządzeń ofiary w stanie aktywności, wysyłając nieskończone silent probes, co rozładowuje baterię, zużywa dane i pogarsza jakość VoIP/RTC.<sup>[[1]](#references)</sup>

Do opisania powierzchni nadużycia wystarczą dwa threat actors:<sup>[[1]](#references)</sup>

1. **Creepy companion:** już dzieli chat z ofiarą i nadużywa reakcji na własne wiadomości, usuwania reakcji albo wielokrotnych edycji/usunięć powiązanych z istniejącymi identyfikatorami wiadomości.
2. **Spooky stranger:** rejestruje burner account i wysyła reakcje odwołujące się do identyfikatorów wiadomości, które nigdy nie istniały w lokalnej rozmowie; WhatsApp i Signal nadal je odszyfrowują i potwierdzają, mimo że UI odrzuca zmianę stanu, więc wcześniejsza rozmowa nie jest wymagana.

## Narzędzia do dostępu do surowego protokołu

Korzystaj z klientów, które udostępniają bazowy protokół E2EE, dzięki czemu można tworzyć pakiety poza ograniczeniami UI, określać dowolne `message_id` i zapisywać precyzyjne znaczniki czasu:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, WhatsApp Web protocol) lub [Cobalt](https://github.com/Auties00/Cobalt) (zorientowany na urządzenia mobilne) pozwalają emitować surowe ramki `ReactionMessage`, `ProtocolMessage` (edit/delete) i `Receipt`, zachowując synchronizację stanu double-ratchet.<sup>[[3]](#references)[[4]](#references)</sup>
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) w połączeniu z [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) udostępnia każdy typ wiadomości przez CLI/API.<sup>[[5]](#references)[[7]](#references)</sup> Aktualna składnia `signal-cli` używa `sendReaction RECIPIENT --target-author --target-timestamp`; utrzymuj uruchomione `receive` lub `daemon`, aby delivery receipts były faktycznie zbierane.<sup>[[6]](#references)</sup> Przykład przełączania reakcji na własną wiadomość:
```bash
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --emoji "👍"
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --remove
```
* **Threema:** Kod źródłowy klienta Android dokumentuje sposób konsolidowania potwierdzeń dostarczenia przed ich opuszczeniem urządzenia, wyjaśniając, dlaczego side-channel ma tam pomijalną przepustowość.<sup>[[1]](#references)</sup>
* **Turnkey PoCs:** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker) zawiera backendy WhatsApp/Signal, domyślnie używa silent delete probes i oznacza stan `active` vs `standby` za pomocą progu opartego na medianie kroczącej (`RTT < 0.9 * median`). [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python) to lżejszy CLI skoncentrowany na WhatsApp, z opcjami `--delay`, `--concurrent`, eksporterami CSV/Prometheus i wyjściem przyjaznym dla Grafany.<sup>[[8]](#references)</sup> <sup>[[9]](#references)</sup> Traktuj oba narzędzia jako pomoce do reconnaissance, a nie jako referencje protokołu; najważniejszy wniosek jest taki, jak niewiele kodu potrzeba po uzyskaniu dostępu do surowego klienta.

Gdy custom tooling jest niedostępny, nadal można wywoływać silent actions z WhatsApp Web lub Signal Desktop i sniffować zaszyfrowany kanał websocket/WebRTC, ale raw APIs usuwają opóźnienia UI i pozwalają na nieprawidłowe operacje.

## Creepy companion: pętla cichego próbkowania

1. Wybierz dowolną historyczną wiadomość wysłaną przez siebie na chacie, aby ofiara nigdy nie zobaczyła zmian w „reaction” balloons.
2. Naprzemiennie wysyłaj widoczne emoji i pusty payload reakcji (kodowany jako `""` w protobufach WhatsApp lub jako `--remove` w signal-cli). Każda transmisja generuje ack urządzenia mimo braku zmiany UI widocznej dla ofiary.
3. Zapisuj czas wysłania i nadejście każdego delivery receipt. Pętla 1 Hz, taka jak poniższa, zapewnia nieograniczone ślady RTT dla poszczególnych urządzeń:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. Ponieważ WhatsApp/Signal akceptują nieograniczoną liczbę aktualizacji reakcji, atakujący nie musi publikować nowych treści na chacie ani martwić się o okna edycji.<sup>[[1]](#references)</sup>

## Spooky stranger: sondowanie dowolnych numerów telefonów

1. Zarejestruj nowe konto WhatsApp/Signal i pobierz publiczne klucze tożsamości dla numeru docelowego (odbywa się to automatycznie podczas konfiguracji sesji).
2. Utwórz pakiet reakcji/edycji/usunięcia odwołujący się do losowego `message_id`, którego żadna ze stron wcześniej nie widziała (WhatsApp akceptuje dowolne GUID-y `key.id`; Signal używa znaczników czasu w milisekundach).
3. Wyślij pakiet mimo braku wątku. Urządzenia ofiary odszyfrują go, nie znajdą wiadomości bazowej, odrzucą zmianę stanu, ale nadal potwierdzą przychodzący ciphertext, wysyłając device receipts z powrotem do atakującego.
4. Powtarzaj tę czynność, aby budować serie RTT bez pojawiania się w historii chatów ofiary.<sup>[[1]](#references)</sup>

Jeśli najpierw musisz ustalić, które numery są zarejestrowane, albo chcesz wstępnie utworzyć inventory urządzeń na dużą skalę, połącz to z [contact-discovery / registration oracles](../pentesting-web/registration-vulnerabilities.md), zamiast ręcznie zgadywać losowe zakresy E.164.

Opublikowane prace dotyczące contact-discovery pokazały, dlaczego ma to znaczenie operacyjne: przy użyciu dokładnych tabel prefiksów telefonicznych i umiarkowanych zasobów badacze mogli sprawdzić około `10%` amerykańskich numerów komórkowych w WhatsApp oraz `100%` w Signal, zanim przeszli do ukierunkowanego sondowania.<sup>[[11]](#references)</sup> W praktyce wcześniejsze odfiltrowanie aktywnych kont pozwala skoncentrować budżet silent probes na numerach, które rzeczywiście odszyfrują pakiety.

Nowsze wersje WhatsApp udostępniają także `Settings -> Privacy -> Advanced -> Block unknown account messages`.<sup>[[10]](#references)</sup> Traktuj to jako ogranicznik przepustowości, a nie rozwiązanie problemu: przede wszystkim utrudnia długotrwałe floodowanie wyłącznie przez strangers i nie ma znaczenia, gdy atakujący jest już znanym kontaktem.

## Ponowne wykorzystywanie edycji i usunięć jako covert triggers

* **Powtarzane usunięcia:** Po jednokrotnym usunięciu wiadomości dla wszystkich kolejne pakiety usunięcia odwołujące się do tego samego `message_id` nie wpływają na UI, ale każde urządzenie nadal je odszyfrowuje i potwierdza.
* **Operacje poza oknem czasowym:** WhatsApp wymusza w UI okno ~60 h na usunięcie i ~20 min na edycję; Signal wymusza ~48 h. Utworzone wiadomości protokołu wysłane poza tymi oknami są po cichu ignorowane na urządzeniu ofiary, ale potwierdzenia są przesyłane, więc atakujący może sondować przez nieograniczony czas po zakończeniu rozmowy.
* **Nieprawidłowe payloady:** Nieprawidłowo sformatowane treści edycji lub usunięcia odwołujące się do już usuniętych wiadomości wywołują takie samo zachowanie — odszyfrowanie i potwierdzenie, bez artefaktów widocznych dla użytkownika.<sup>[[1]](#references)</sup>

## Wzmacnianie i fingerprinting multi-device

* Każde powiązane urządzenie (telefon, aplikacja desktopowa, przeglądarkowy companion) niezależnie odszyfrowuje probe i zwraca własny ack. Zliczanie potwierdzeń dla każdego probe ujawnia dokładną liczbę urządzeń.
* Jeśli urządzenie jest offline, jego potwierdzenie zostaje zakolejkowane i wysłane po ponownym połączeniu. Luki ujawniają zatem cykle online/offline, a nawet harmonogramy dojazdów (np. potwierdzenia desktopu zanikają podczas podróży).
* Rozkłady RTT różnią się zależnie od platformy ze względu na zarządzanie energią przez system operacyjny i wybudzenia push. Grupuj RTT (np. za pomocą k-means na cechach mediany/wariancji), aby oznaczać urządzenia jako „Android handset”, „iOS handset”, „Electron desktop” itd.
* Ponieważ nadawca musi pobrać inventory kluczy odbiorcy przed szyfrowaniem, atakujący może także obserwować moment parowania nowych urządzeń; nagły wzrost liczby urządzeń lub pojawienie się nowego klastra RTT jest silnym wskaźnikiem.<sup>[[1]](#references)</sup>

## Częstotliwość próbkowania, kolejkowanie i skumulowane potwierdzenia

* **Tolerancja WhatsApp na bursty:** Opublikowane pomiary wykazały, że WhatsApp akceptował bursty silent reactions z szybkością nawet jednego probe co `50 ms`, bez widocznego kolejkowania po stronie serwera. Jest to przydatne przy krótkich burstach kalibracyjnych, szybkim zliczaniu urządzeń lub szybkim zwiększaniu intensywności drain attack.
* **Długotrwałe kolejkowanie w Signal:** Signal tolerował krótkie bursty, ale zaczynał kolejkować utrzymywany ruch z częstotliwością wielu probe na sekundę. Przy długotrwałym monitorowaniu utrzymuj częstotliwość około `1 Hz` (lub niższą), aby każde potwierdzenie nadal odzwierciedlało bieżący stan urządzenia, a nie opróżnianie backlogu.
* **Artefakty ponownego połączenia:** Gdy urządzenie wraca online, niektóre klienty grupują lub szybko wysyłają wiele opóźnionych potwierdzeń. Traktuj te bursty potwierdzeń jako znacznik zmiany stanu, a nie jako niezależne próbki RTT, w przeciwnym razie klasteryzacja / klasyfikator `active` vs `idle` będzie nadmiernie dopasowany do noise’u związanego z ponownym połączeniem.<sup>[[1]](#references)</sup>

## Wnioskowanie o zachowaniu na podstawie śladów RTT

1. Próbkuj z częstotliwością ≥1 Hz, aby uchwycić efekty harmonogramowania systemu operacyjnego. W WhatsApp na iOS RTT <1 s silnie koreluje z włączonym ekranem/działaniem aplikacji na pierwszym planie, a RTT >1 s z wygaszonym ekranem/ograniczeniem aktywności w tle.
2. Twórz proste klasyfikatory (progowanie lub k-means z dwoma klastrami), które oznaczają każde RTT jako „active” albo „idle”. Grupuj oznaczenia w serie, aby wyznaczyć godziny snu, dojazdy, godziny pracy lub czas aktywności desktop companion.
3. Koreluj równoczesne probe kierowane do każdego urządzenia, aby zobaczyć, kiedy użytkownicy przełączają się z urządzenia mobilnego na desktop, kiedy companiony przechodzą offline oraz czy aplikacja jest ograniczana przez push, czy przez persistent socket.
4. W rzeczywistych sieciach unikaj jednego, sztywnego progu `1 s`. Zainicjalizuj każde urządzenie krótkim oknem rozgrzewkowym i utrzymuj baseline kroczący (na przykład `threshold = 0.9 * median RTT`), aby zmienność Wi-Fi/sieci komórkowej nie zniszczyła klasyfikatora.<sup>[[1]](#references)</sup>

## Wnioskowanie o lokalizacji na podstawie RTT dostarczenia

Ten sam prymityw czasowy można wykorzystać do wnioskowania, gdzie znajduje się odbiorca, a nie tylko czy jest aktywny. Praca `Hope of Delivery` pokazała, że trening na rozkładach RTT dla znanych lokalizacji odbiorcy pozwala później atakującemu klasyfikować lokalizację ofiary wyłącznie na podstawie potwierdzeń dostarczenia:<sup>[[2]](#references)</sup>

* Utwórz baseline dla tego samego celu, gdy znajduje się on w kilku znanych miejscach (dom, biuro, kampus, kraj A vs kraj B itd.).
* Dla każdej lokalizacji zbierz wiele RTT zwykłych wiadomości i wyodrębnij proste cechy, takie jak mediana, wariancja lub przedziały percentylowe.
* Podczas właściwego ataku porównaj nową serię probe z wytrenowanymi klastrami. W artykule podano, że często można rozróżnić nawet lokalizacje w obrębie tego samego miasta, z dokładnością `>80%` w układzie 3 lokalizacji.
* Działa to najlepiej, gdy atakujący kontroluje środowisko nadawcy i wysyła probe w podobnych warunkach sieciowych, ponieważ mierzona ścieżka obejmuje sieć dostępową odbiorcy, opóźnienie wybudzania oraz infrastrukturę messengera.<sup>[[2]](#references)</sup>

W przeciwieństwie do opisanych wyżej ataków z użyciem silent reaction/edit/delete, wnioskowanie o lokalizacji nie wymaga nieprawidłowych identyfikatorów wiadomości ani stealthy state-changing packets. Wystarczą zwykłe wiadomości z normalnymi potwierdzeniami dostarczenia, więc kompromisem jest mniejsza stealth, ale szersza możliwość zastosowania w różnych messengerach.

## Stealthy resource exhaustion

Ponieważ każdy silent probe musi zostać odszyfrowany i potwierdzony, ciągłe wysyłanie przełączeń reakcji, nieprawidłowych edycji lub pakietów delete-for-everyone tworzy DoS na warstwie aplikacji:<sup>[[1]](#references)</sup>

* Zmusza radio/modem do nadawania/odbierania co sekundę → powoduje zauważalne zużycie baterii, szczególnie na bezczynnych telefonach.
* Generuje niemierzony ruch upstream/downstream, który zużywa pakiety danych komórkowych, wtapiając się w noise TLS/WebSocket.
* Obciąża wątki kryptograficzne i wprowadza jitter do funkcji wrażliwych na opóźnienia (VoIP, połączenia wideo), mimo że użytkownik nie widzi żadnych powiadomień.
* W WhatsApp nieprawidłowe reakcje akceptują znacznie więcej danych, niż sugerowałoby zwykłe emoji: opublikowane pomiary wykazały akceptację po stronie serwera na poziomie około `1 MB` na reakcję.
* Zbyt duże reakcje przestają generować wiarygodne potwierdzenia dostarczenia, gdy treść przekroczy około `30 bytes`, ale nadal są przekazywane i przetwarzane przed odrzuceniem. Utrzymuj małe treści reakcji, gdy potrzebujesz ACK; zwiększaj ich rozmiar tylko wtedy, gdy celem jest wyłącznie drain lub covert one-way transport.
* Publiczne pomiary osiągnęły około `3.7 MB/s` (`~13.3 GB/h`) ruchu ofiary w tym trybie.

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
