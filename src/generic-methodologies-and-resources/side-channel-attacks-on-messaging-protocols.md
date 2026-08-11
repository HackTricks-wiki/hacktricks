# Side-Channel Attacks związane z potwierdzeniami dostarczenia w komunikatorach E2EE

{{#include ../banners/hacktricks-training.md}}

Potwierdzenia dostarczenia są obowiązkowe we współczesnych komunikatorach z szyfrowaniem end-to-end (E2EE), ponieważ klienci muszą wiedzieć, kiedy ciphertext został odszyfrowany, aby móc odrzucić stan ratchetingu i klucze ephemeral. Serwer przekazuje nieprzejrzyste bloby, więc potwierdzenia urządzeń (podwójne znaczniki wyboru) są wysyłane przez odbiorcę po pomyślnym odszyfrowaniu. Pomiar czasu round-trip (RTT) między akcją wywołaną przez atakującego a odpowiadającym jej potwierdzeniem dostarczenia ujawnia wysokorozdzielczy kanał timingowy, który leak stan urządzenia i obecność online oraz może zostać wykorzystany do przeprowadzenia ukrytego DoS. Wdrożenia multi-device typu „client-fanout” wzmacniają leakage, ponieważ każde zarejestrowane urządzenie odszyfrowuje probe i zwraca własne potwierdzenie.<sup>[[1]](#references)</sup>

## Źródła potwierdzeń dostarczenia a sygnały widoczne dla użytkownika

Wybierz typy wiadomości, które zawsze generują potwierdzenie dostarczenia, ale nie powodują artefaktów UI widocznych dla ofiary. Poniższa tabela podsumowuje empirycznie potwierdzone zachowanie:<sup>[[1]](#references)</sup>

| Messenger | Akcja | Potwierdzenie dostarczenia | Powiadomienie ofiary | Uwagi |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Wiadomość tekstowa | ● | ● | Zawsze generuje szum → przydatne tylko do zainicjowania stanu. |
| | Reakcja | ● | ◐ (tylko przy reagowaniu na wiadomość ofiary) | Własne reakcje i ich usuwanie pozostają niewidoczne. |
| | Edycja | ● | Zależne od platformy silent push | Okno edycji ≈20 min; po jego upływie nadal wysyłane jest potwierdzenie. |
| | Usuń dla wszystkich | ● | ○ | UI pozwala na ~60 h, ale późniejsze pakiety nadal otrzymują potwierdzenie. |
| **Signal** | Wiadomość tekstowa | ● | ● | Te same ograniczenia co w WhatsApp. |
| | Reakcja | ● | ◐ | Własne reakcje są niewidoczne dla ofiary. |
| | Edycja/Usunięcie | ● | ○ | Serwer wymusza okno ~48 h i pozwala na maksymalnie 10 edycji, ale późne pakiety nadal otrzymują potwierdzenie. |
| **Threema** | Wiadomość tekstowa | ● | ● | Potwierdzenia multi-device są agregowane, więc widoczny jest tylko jeden RTT na probe. |

Legenda: ● = zawsze, ◐ = warunkowo, ○ = nigdy. Zachowanie UI zależne od platformy zaznaczono w tekście. W razie potrzeby wyłącz potwierdzenia odczytu, ale potwierdzeń dostarczenia nie można wyłączyć w WhatsApp ani Signal.<sup>[[1]](#references)</sup>

## Cele i modele atakującego

* **G1 – Fingerprinting urządzeń:** Zliczaj, ile potwierdzeń przychodzi dla każdego probe, grupuj RTT, aby wnioskować o systemie/client (Android vs iOS vs desktop), i obserwuj przejścia online/offline.
* **G2 – Monitorowanie zachowania:** Traktuj serię RTT o wysokiej częstotliwości (≈1 Hz jest stabilne) jako szereg czasowy i wnioskuj o włączaniu/wyłączaniu ekranu, działaniu aplikacji na pierwszym/na drugim planie, godzinach dojazdów i pracy itd.
* **G3 – Wyczerpywanie zasobów:** Utrzymuj radia/CPU każdego urządzenia ofiary w stanie aktywnym, wysyłając niekończące się silent probes, co rozładowuje baterię, zużywa dane i pogarsza jakość połączeń wideo.<sup>[[1]](#references)</sup>

Do opisania powierzchni nadużycia wystarczą dwaj threat actors:<sup>[[1]](#references)</sup>

1. **Creepy companion:** już dzieli czat z ofiarą i nadużywa własnych reakcji, usuwania reakcji lub wielokrotnych edycji/usunięć powiązanych z istniejącymi message ID.
2. **Spooky stranger:** rejestruje konto burner i wysyła reakcje odwołujące się do message ID, które nigdy nie istniały w lokalnej konwersacji; WhatsApp i Signal nadal je odszyfrowują i potwierdzają, mimo że UI odrzuca zmianę stanu, więc wcześniejsza konwersacja nie jest wymagana.

## Tooling do dostępu do surowego protokołu

Korzystaj z klientów, które udostępniają wystarczającą część bazowego protokołu E2EE, aby tworzyć obsługiwane pakiety poza ograniczeniami UI i rejestrować precyzyjne znaczniki czasu; użycie dowolnych message ID wymaga sprawdzenia każdej implementacji:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, WhatsApp Web multidevice API) dokumentuje wysyłanie i odbieranie potwierdzeń dostarczenia; [Cobalt](https://github.com/Auties00/Cobalt) (nieoficjalne Java/Kotlin Web i mobile API) dokumentuje operacje na wiadomościach, takie jak reagowanie, edycja i usuwanie. Korzystaj z udokumentowanych API, zamiast zakładać, że każda wewnętrzna ramka jest udostępniona.<sup>[[3]](#references)[[4]](#references)</sup>
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) udostępnia interfejsy CLI, JSON-RPC i D-Bus, natomiast [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) jest biblioteką Java do komunikacji z Signal.<sup>[[5]](#references)[[7]](#references)</sup> Bieżąca składnia `signal-cli` używa `sendReaction RECIPIENT --target-author --target-timestamp`; pozostaw `receive` lub `daemon` uruchomione, aby aktualizacje protokołu nadal były przetwarzane.<sup>[[6]](#references)</sup> Przykład przełączania własnej reakcji:
```bash
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --emoji "👍"
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --remove
```
* **Threema:** Pomiary opisane w artykule Careless Whisper wykazały, że potwierdzenia dostarczenia są synchronizowane między urządzeniami, więc nawet w konfiguracji multi-device ujawniane jest tylko jedno potwierdzenie na wiadomość.<sup>[[1]](#references)</sup>
* **Turnkey PoCs:** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker) zawiera backendy WhatsApp/Signal, domyślnie używa silent delete probes i oznacza stany `active` oraz `standby` za pomocą progu opartego na medianie kroczącej (`RTT < 0.9 * median`).<sup>[[8]](#references)</sup> [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python) to prostsze narzędzie CLI skoncentrowane na WhatsApp, obsługujące `--delay`, `--concurrent`, eksportery CSV/Prometheus i dane wyjściowe przyjazne dla Grafana.<sup>[[9]](#references)</sup> Traktuj oba narzędzia jako pomocniki do reconnaissance, a nie referencje protokołu; najważniejszy wniosek jest taki, jak niewiele kodu potrzeba po uzyskaniu dostępu do surowego klienta.

Gdy custom tooling jest niedostępny, oficjalne klienty lub browser developer tools nadal mogą wywoływać ciche akcje i ujawniać timing zaszyfrowanego ruchu; raw API usuwają opóźnienia UI i umożliwiają nieprawidłowe operacje.<sup>[[1]](#references)</sup>

## Creepy companion: cicha pętla próbkowania

1. Wybierz dowolną historyczną wiadomość wysłaną przez siebie na czacie, aby ofiara nigdy nie zobaczyła zmian „baloników” reakcji.
2. Naprzemiennie wysyłaj widoczne emoji i pusty payload reakcji (kodowany jako `""` w WhatsApp protobufs lub jako `--remove` w signal-cli). Każda transmisja generuje ack urządzenia mimo braku zmiany UI widocznej dla ofiary.
3. Rejestruj czas wysłania i nadejście każdego potwierdzenia dostarczenia. Pętla 1 Hz, taka jak poniższa, zapewnia nieograniczone ślady RTT dla poszczególnych urządzeń:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. Ponieważ WhatsApp/Signal akceptują nieograniczoną liczbę aktualizacji reakcji, atakujący nie musi publikować nowej treści na czacie ani martwić się oknami edycji.<sup>[[1]](#references)</sup>

## Spooky stranger: sondowanie dowolnych numerów telefonów

1. Zarejestruj nowe konto WhatsApp/Signal i pobierz publiczne klucze tożsamości dla numeru docelowego (odbywa się to automatycznie podczas konfiguracji sesji).
2. Utwórz pakiet reakcji odwołujący się do losowego `message_id`, którego żadna ze stron nigdy nie widziała; artykuł informuje, że zarówno WhatsApp, jak i Signal akceptują takie reakcje i nadal generują potwierdzenia dostarczenia.<sup>[[1]](#references)</sup>
3. Wyślij pakiet, mimo że nie istnieje żaden wątek. Urządzenia ofiary odszyfrują go, nie dopasują wiadomości bazowej, odrzucą zmianę stanu, ale nadal potwierdzą przychodzący ciphertext, wysyłając potwierdzenia urządzeń z powrotem do atakującego.
4. Powtarzaj tę czynność ciągle, aby budować serie RTT bez wcześniejszej konwersacji i widocznego powiadomienia.<sup>[[1]](#references)</sup>

Jeśli najpierw musisz wykryć, które numery są zarejestrowane, lub chcesz przygotować inwentarze urządzeń na dużą skalę, połącz to z [contact-discovery / registration oracles](../pentesting-web/registration-vulnerabilities.md), zamiast ręcznie zgadywać losowe zakresy E.164.

Opublikowane badania contact-discovery pokazały, dlaczego ma to znaczenie operacyjne: dzięki dokładnym tabelom prefiksów telefonicznych i umiarkowanym zasobom badacze mogli odpytać około `10%` amerykańskich numerów komórkowych w WhatsApp i `100%` w Signal, zanim przeszli do ukierunkowanego sondowania.<sup>[[11]](#references)</sup> W praktyce wcześniejsze odfiltrowanie aktywnych kont pozwala skupić budżet silent probes na numerach, które rzeczywiście odszyfrują pakiety.

Nowsze wersje WhatsApp udostępniają również `Settings -> Privacy -> Advanced -> Block unknown account messages`.<sup>[[10]](#references)</sup> Traktuj to jako ogranicznik przepustowości: dokumentacja trackera wskazuje, że WhatsApp blokuje dużą liczbę wiadomości z nieznanych kont, ale nie ujawnia progu, więc nie zapobiega całkowicie reakcjom probe.<sup>[[8]](#references)</sup>

## Recykling edycji i usunięć jako ukrytych triggerów

* **Powtarzane usunięcia:** Po jednokrotnym usunięciu wiadomości dla wszystkich kolejne pakiety usunięcia odwołujące się do tego samego `message_id` nie mają wpływu na UI, ale każde urządzenie nadal je odszyfrowuje i potwierdza.
* **Operacje poza oknem czasowym:** WhatsApp wymusza w UI okna ~60 h dla usunięcia i ~20 min dla edycji; Signal wymusza ~48 h. Utworzone wiadomości protokołu wysłane poza tymi oknami są po cichu ignorowane na urządzeniu ofiary, ale potwierdzenia są przesyłane, dzięki czemu atakujący może sondować długo po zakończeniu konwersacji.
* **Nieprawidłowe payloady:** Artykuł informuje, że nieprawidłowe wiadomości nadal mogą otrzymywać potwierdzenia; dokładne zachowanie dla zniekształconych treści lub usuniętych ID zależy od implementacji, więc przed poleganiem na nim należy wykonać testy.<sup>[[1]](#references)</sup>

## Wzmocnienie multi-device i fingerprinting

* W WhatsApp i Signal każde powiązane urządzenie (telefon, aplikacja desktopowa, browser companion) niezależnie odszyfrowuje probe i zwraca własny ack. Zliczanie potwierdzeń dla każdego probe ujawnia dokładną liczbę urządzeń.<sup>[[1]](#references)</sup>
* Jeśli urządzenie jest offline, jego potwierdzenie jest kolejkowane i wysyłane po ponownym połączeniu. Przerwy ujawniają zatem cykle online/offline, a nawet harmonogramy dojazdów (np. potwierdzenia desktopu ustają podczas podróży).
* Rozkłady RTT różnią się zależnie od platformy i środowiska, ponieważ system, model, klient i warunki sieciowe wpływają na czas. Grupuj RTT (np. metodą k-means na cechach mediany/wariancji), aby oznaczać je jako „Android handset”, „iOS handset”, „Electron desktop” itd.
* Ponieważ nadawca musi pobrać inwentarz kluczy odbiorcy przed szyfrowaniem, atakujący może także obserwować moment parowania nowych urządzeń; nagły wzrost liczby urządzeń lub pojawienie się nowego klastra RTT jest silnym wskaźnikiem.<sup>[[1]](#references)</sup>

## Częstotliwość próbkowania, kolejkowanie i skumulowane potwierdzenia

* **Tolerancja WhatsApp na bursty:** Opublikowane pomiary wykazały, że WhatsApp akceptował bursty silent reactions z szybkością do jednego probe co `50 ms` bez widocznego kolejkowania po stronie serwera. Jest to przydatne przy krótkich burstach kalibracyjnych, szybkim zliczaniu urządzeń lub szybkim zwiększaniu intensywności drain attack.
* **Długotrwałe kolejkowanie w Signal:** Signal tolerował krótkie bursty, ale zaczynał kolejkować utrzymywany ruch obejmujący wiele probe na sekundę. Przy długotrwałym monitorowaniu utrzymuj częstotliwość około `1 Hz` (lub niższą), aby każde potwierdzenie nadal odzwierciedlało bieżący stan urządzenia, a nie opróżnianie backlogu.
* **Artefakty ponownego połączenia:** Gdy urządzenie wraca online, niektóre klienty grupują lub szybko opróżniają wiele opóźnionych potwierdzeń. Traktuj takie bursty potwierdzeń jako znacznik zmiany stanu, a nie niezależne próbki RTT; w przeciwnym razie klastrowanie / klasyfikator `active` vs `idle` będzie nadmiernie dopasowany do szumu ponownego połączenia.<sup>[[1]](#references)</sup>

## Wnioskowanie o zachowaniu na podstawie śladów RTT

1. Próbkuj z częstotliwością ≥1 Hz, aby uchwycić efekty planowania zadań systemu. W WhatsApp na iOS RTT <1 s silnie koreluje z włączonym ekranem/działaniem aplikacji na pierwszym planie, a >1 s z wyłączonym ekranem/dławieniem aplikacji w tle.
2. Twórz proste klasyfikatory (progowanie lub k-means z dwoma klastrami), które oznaczają każdy RTT jako „active” lub „idle”. Grupuj oznaczenia w serie, aby wyznaczać pory snu, dojazdy, godziny pracy lub okresy aktywności desktop companion.
3. Koreluj jednoczesne probe kierowane do każdego urządzenia, aby sprawdzić, kiedy użytkownicy przełączają się z urządzenia mobilnego na desktop, kiedy companions przechodzą offline oraz czy aplikacja jest ograniczana przez push czy persistent socket.
4. W rzeczywistych sieciach unikaj pojedynczego, hardcoded progu `1 s`. Skalibruj każde urządzenie za pomocą krótkiego okna rozgrzewkowego i utrzymuj baseline kroczący (na przykład PoC device-activity-tracker używa `threshold = 0.9 * median RTT`), aby zmienność Wi-Fi/sieci komórkowej nie zniszczyła klasyfikatora.<sup>[[1]](#references)[[8]](#references)</sup>

## Wnioskowanie o lokalizacji na podstawie RTT dostarczenia

Ten sam mechanizm timingowy można wykorzystać do wnioskowania, gdzie znajduje się odbiorca, a nie tylko czy jest aktywny. Badania `Hope of Delivery` wykazały, że trenowanie na rozkładach RTT dla znanych lokalizacji odbiorcy pozwala atakującemu później klasyfikować lokalizację ofiary wyłącznie na podstawie potwierdzeń dostarczenia:<sup>[[2]](#references)</sup>

* Zbuduj baseline dla tego samego celu, gdy znajduje się on w kilku znanych miejscach (dom, biuro, kampus, kraj A vs kraj B itd.).
* Dla każdej lokalizacji zbierz wiele normalnych RTT wiadomości i wyodrębnij proste cechy, takie jak mediana, wariancja lub przedziały percentylowe.
* Podczas właściwego ataku porównaj nową serię probe z wytrenowanymi klastrami. Artykuł informuje, że często można rozróżnić nawet lokalizacje w tym samym mieście, z dokładnością `>80%` w konfiguracji obejmującej 3 lokalizacje.
* Działa to najlepiej, gdy atakujący kontroluje środowisko nadawcy i wykonuje probe w podobnych warunkach sieciowych, ponieważ mierzona ścieżka obejmuje sieć dostępową odbiorcy, opóźnienie wybudzania i infrastrukturę messengera.<sup>[[2]](#references)</sup>

W przeciwieństwie do opisanych powyżej ataków z użyciem silent reaction/edit/delete, wnioskowanie o lokalizacji nie wymaga nieprawidłowych message ID ani ukrytych pakietów zmieniających stan. Wystarczą zwykłe wiadomości z normalnymi potwierdzeniami dostarczenia, więc kompromisem jest mniejsza dyskrecja, ale szersze zastosowanie w różnych messengerach.

## Ukryte wyczerpywanie zasobów

Ponieważ każde silent probe musi zostać odszyfrowane i potwierdzone, ciągłe wysyłanie przełączników reakcji, nieprawidłowych edycji lub pakietów delete-for-everyone tworzy DoS na poziomie aplikacji:<sup>[[1]](#references)</sup>

* Zmusza radio/modem do nadawania/odbierania co sekundę → powoduje zauważalne rozładowywanie baterii, szczególnie na bezczynnych urządzeniach.
* Generuje ruch przychodzący/wychodzący, który zużywa pakiety danych i może konkurować z funkcjami wrażliwymi na opóźnienia, takimi jak połączenia wideo.<sup>[[1]](#references)</sup>
* Duże nieprawidłowe payloady zwiększają obciążenie obliczeniowe, ale artykuł informuje, że sama kryptografia stanowi pomijalną część kosztu energetycznego baterii.<sup>[[1]](#references)</sup>
* W WhatsApp nieprawidłowe reakcje akceptują znacznie więcej danych, niż sugerowałoby zwykłe emoji: opublikowane pomiary wykazały akceptację po stronie serwera do około `1 MB` na reakcję.
* Zbyt duże reakcje przestają generować wiarygodne potwierdzenia dostarczenia, gdy treść przekroczy około `30 bytes`, ale nadal są przekazywane i przetwarzane przed odrzuceniem. Gdy potrzebujesz ACK, utrzymuj treść reakcji małą; zwiększaj ją tylko wtedy, gdy celem jest wyłącznie drain lub ukryty transport jednokierunkowy.
* Publiczne pomiary osiągnęły około `3.7 MB/s` (`~13.3 GB/h`) ruchu ofiary w tym trybie.

## References

- [1] [Careless Whisper: Wykorzystanie cichych potwierdzeń dostarczenia do monitorowania użytkowników w mobilnych komunikatorach internetowych](https://arxiv.org/html/2411.11194v4)
- [2] [Hope of Delivery: Wydobywanie lokalizacji użytkowników z mobilnych komunikatorów internetowych](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [3] [whatsmeow](https://github.com/tulir/whatsmeow)
- [4] [Cobalt](https://github.com/Auties00/Cobalt)
- [5] [signal-cli](https://github.com/AsamK/signal-cli)
- [6] [strona podręcznika signal-cli](https://github.com/AsamK/signal-cli/blob/master/man/signal-cli.1.adoc)
- [7] [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [8] [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)
- [9] [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python)
- [10] [Jak blokować duże ilości wiadomości od nieznanych nadawców | Centrum pomocy WhatsApp](https://faq.whatsapp.com/3379690015658337)
- [11] [Wszystkie numery pochodzą z USA: Nadużycia contact discovery na dużą skalę w mobilnych komunikatorach](https://www.ndss-symposium.org/ndss-paper/all-the-numbers-are-us-large-scale-abuse-of-contact-discovery-in-mobile-messengers/)
{{#include ../banners/hacktricks-training.md}}
