# Ataki side-channel z wykorzystaniem potwierdzeń dostarczenia w komunikatorach E2EE

Potwierdzenia dostarczenia są obowiązkowe we współczesnych komunikatorach end-to-end encrypted (E2EE), ponieważ klienci muszą wiedzieć, kiedy ciphertext został odszyfrowany, aby mogli odrzucić stan ratchetowania i klucze ephemeral. Serwer przekazuje niejawne bloby, więc potwierdzenia urządzeń (podwójne znaczniki wyboru) są emitowane przez odbiorcę po pomyślnym odszyfrowaniu. Pomiar czasu round-trip (RTT) między akcją wyzwoloną przez atakującego a odpowiadającym jej potwierdzeniem dostarczenia ujawnia kanał czasowy o wysokiej rozdzielczości, który powoduje leak stanu urządzenia i obecności online oraz może zostać wykorzystany do covert DoS. Wdrożenia multi-device typu "client-fanout" zwiększają leak, ponieważ każde zarejestrowane urządzenie odszyfrowuje probe i zwraca własne potwierdzenie.<sup>[[1]](#references)</sup>

## Źródła potwierdzeń dostarczenia a sygnały widoczne dla użytkownika

Wybierz typy wiadomości, które zawsze emitują potwierdzenie dostarczenia, ale nie powodują artefaktów UI po stronie ofiary. Poniższa tabela podsumowuje empirycznie potwierdzone zachowanie:<sup>[[1]](#references)</sup>

| Messenger | Akcja | Potwierdzenie dostarczenia | Powiadomienie ofiary | Uwagi |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Wiadomość tekstowa | ● | ● | Zawsze powoduje szum → przydatne tylko do bootstrapowania stanu. |
| | Reakcja | ● | ◐ (tylko przy reakcji na wiadomość ofiary) | Reakcje własne i ich usuwanie pozostają niewidoczne. |
| | Edycja | ● | Zależne od platformy silent push | Okno edycji ≈20 min; potwierdzenie jest nadal wysyłane po jego wygaśnięciu. |
| | Usuń dla wszystkich | ● | ○ | UI pozwala na ~60 h, ale późniejsze pakiety nadal otrzymują potwierdzenie. |
| **Signal** | Wiadomość tekstowa | ● | ● | Te same ograniczenia co w WhatsApp. |
| | Reakcja | ● | ◐ | Reakcje własne są niewidoczne dla ofiary. |
| | Edycja/Usunięcie | ● | ○ | Serwer wymusza okno ~48 h, zezwala na maksymalnie 10 edycji, ale późne pakiety nadal otrzymują potwierdzenia. |
| **Threema** | Wiadomość tekstowa | ● | ● | Potwierdzenia multi-device są agregowane, więc widoczny jest tylko jeden RTT na probe. |

Legenda: ● = zawsze, ◐ = warunkowo, ○ = nigdy. Zachowanie UI zależne od platformy zaznaczono w tekście. W razie potrzeby wyłącz read receipts, ale delivery receipts nie można wyłączyć w WhatsApp ani Signal.<sup>[[1]](#references)</sup>

## Cele i modele atakującego

* **G1 – Fingerprinting urządzeń:** Policz, ile potwierdzeń dociera dla każdego probe, grupuj RTT, aby wnioskować o systemie/client (Android vs iOS vs desktop), i obserwuj przejścia online/offline.
* **G2 – Monitorowanie zachowania:** Traktuj serię RTT o wysokiej częstotliwości (≈1 Hz jest stabilne) jako szereg czasowy i wnioskuj o włączeniu/wyłączeniu ekranu, działaniu aplikacji na foreground/background, godzinach dojazdów i pracy itd.
* **G3 – Wyczerpywanie zasobów:** Utrzymuj radia/CPU wszystkich urządzeń ofiary w stanie aktywności, wysyłając niekończące się silent probes, rozładowując baterię, zużywając dane i pogarszając jakość video call.<sup>[[1]](#references)</sup>

Do opisania powierzchni nadużycia wystarczą dwaj threat actors:<sup>[[1]](#references)</sup>

1. **Creepy companion:** już współdzieli chat z ofiarą i nadużywa reakcji własnych, usuwania reakcji lub powtarzających się edycji/usunięć powiązanych z istniejącymi message IDs.
2. **Spooky stranger:** rejestruje burner account i wysyła reakcje odwołujące się do message IDs, które nigdy nie istniały w lokalnej rozmowie; WhatsApp i Signal nadal je odszyfrowują i potwierdzają, mimo że UI odrzuca zmianę stanu, więc wcześniejsza rozmowa nie jest wymagana.

## Tooling do dostępu do surowego protokołu

Korzystaj z klientów, które udostępniają wystarczającą część bazowego protokołu E2EE, aby tworzyć obsługiwane pakiety poza ograniczeniami UI i logować precyzyjne znaczniki czasu; użycie arbitralnych message IDs wymaga sprawdzenia każdej implementacji:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, WhatsApp Web multidevice API) dokumentuje wysyłanie i odbieranie delivery receipts; [Cobalt](https://github.com/Auties00/Cobalt) (nieoficjalne Java/Kotlin Web i mobile API) dokumentuje operacje na wiadomościach, takie jak reagowanie, edycja i usuwanie. Używaj udokumentowanych API zamiast zakładać, że każda wewnętrzna ramka jest udostępniona.<sup>[[3]](#references)[[4]](#references)</sup>
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) udostępnia interfejsy CLI, JSON-RPC i D-Bus, natomiast [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) jest biblioteką Java służącą do komunikacji z Signal.<sup>[[5]](#references)[[7]](#references)</sup> Aktualna składnia `signal-cli` używa `sendReaction RECIPIENT --target-author --target-timestamp`; pozostaw `receive` lub `daemon` uruchomione, aby aktualizacje protokołu nadal były przetwarzane.<sup>[[6]](#references)</sup> Przykład przełączania reakcji własnej:
```bash
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --emoji "👍"
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --remove
```
* **Threema:** Pomiary opisane w pracy Careless Whisper wykazały, że delivery receipts są synchronizowane między urządzeniami, więc nawet w konfiguracji multi-device ujawniane jest tylko jedno potwierdzenie na wiadomość.<sup>[[1]](#references)</sup>
* **Turnkey PoCs:** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker) zawiera backendy WhatsApp/Signal, domyślnie używa silent delete probes i oznacza stany `active` oraz `standby` za pomocą progu opartego na medianie kroczącej (`RTT < 0.9 * median`).<sup>[[8]](#references)</sup> [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python) jest prostszym CLI skoncentrowanym na WhatsApp, z opcjami `--delay`, `--concurrent`, exporterami CSV/Prometheus i outputem przyjaznym dla Grafana.<sup>[[9]](#references)</sup> Traktuj oba narzędzia jako pomoce do reconnaissance, a nie referencje protokołu; najważniejsze jest to, jak niewiele kodu potrzeba po uzyskaniu dostępu do surowego klienta.

Gdy custom tooling jest niedostępny, official clients lub browser developer tools nadal mogą wyzwalać silent actions i ujawniać timing zaszyfrowanego ruchu; raw APIs usuwają opóźnienia UI i umożliwiają nieprawidłowe operacje.<sup>[[1]](#references)</sup>

## Creepy companion: silent sampling loop

1. Wybierz dowolną historyczną wiadomość wysłaną przez siebie na czacie, aby ofiara nigdy nie zobaczyła zmian "reaction" balloons.
2. Naprzemiennie wysyłaj widoczne emoji i pusty reaction payload (kodowany jako `""` w protobufach WhatsApp lub jako `--remove` w signal-cli). Każda transmisja powoduje ack urządzenia mimo braku zmiany UI po stronie ofiary.
3. Zapisuj czas wysłania i nadejście każdego delivery receipt. Pętla 1 Hz, taka jak poniższa, zapewnia nieograniczone ślady RTT dla poszczególnych urządzeń:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. Ponieważ WhatsApp/Signal akceptują nieograniczoną liczbę aktualizacji reakcji, atakujący nie musi publikować nowej treści na czacie ani martwić się o okna edycji.<sup>[[1]](#references)</sup>

## Spooky stranger: probing arbitralnych numerów telefonów

1. Zarejestruj nowe konto WhatsApp/Signal i pobierz publiczne klucze tożsamości dla numeru docelowego (odbywa się to automatycznie podczas konfiguracji sesji).
2. Utwórz reaction packet odwołujący się do losowego `message_id`, którego żadna ze stron nigdy nie widziała; praca donosi, że zarówno WhatsApp, jak i Signal akceptują takie reakcje i nadal generują delivery receipts.<sup>[[1]](#references)</sup>
3. Wyślij pakiet, mimo że nie istnieje żaden wątek. Urządzenia ofiary odszyfrują go, nie znajdą wiadomości bazowej, odrzucą zmianę stanu, ale nadal potwierdzą przychodzący ciphertext, wysyłając device receipts do atakującego.
4. Powtarzaj operację nieprzerwanie, aby zbudować serie RTT bez wcześniejszej rozmowy i widocznego powiadomienia.<sup>[[1]](#references)</sup>

Jeśli najpierw musisz ustalić, które numery są zarejestrowane, albo chcesz przygotować inwentarze urządzeń na dużą skalę, połącz to z [contact-discovery / registration oracles](../pentesting-web/registration-vulnerabilities.md), zamiast ręcznie zgadywać losowe zakresy E.164.

Opublikowane prace dotyczące contact-discovery pokazały, dlaczego ma to znaczenie operacyjne: przy użyciu dokładnych tabel prefiksów telefonicznych i umiarkowanych zasobów badacze byli w stanie odpytać około `10%` numerów komórkowych w USA w WhatsApp i `100%` w Signal, zanim przeszli do targetowanego probing.<sup>[[11]](#references)</sup> W praktyce wcześniejsze filtrowanie aktywnych kont pozwala skoncentrować budżet silent probes na numerach, które rzeczywiście odszyfrują pakiety.

Nowsze buildy WhatsApp udostępniają również `Settings -> Privacy -> Advanced -> Block unknown account messages`.<sup>[[10]](#references)</sup> Traktuj to jako ograniczenie przepustowości: dokumentacja trackera mówi, że WhatsApp blokuje wiadomości o dużej częstotliwości pochodzące od nieznanych kont, ale nie ujawnia progu, więc funkcja ta nie zapobiega całkowicie reaction probes.<sup>[[8]](#references)</sup>

## Recykling edycji i usunięć jako covert triggers

* **Repeated deletes:** Po jednorazowym usunięciu wiadomości dla wszystkich kolejne delete packets odwołujące się do tego samego `message_id` nie powodują efektu w UI, ale każde urządzenie nadal je odszyfrowuje i potwierdza.
* **Out-of-window operations:** WhatsApp wymusza w UI okno ~60 h dla usuwania i ~20 min dla edycji; Signal wymusza ~48 h. Utworzone wiadomości protokołu spoza tych okien są po stronie urządzenia ofiary cicho ignorowane, ale receipts są przesyłane, dzięki czemu atakujący może sondować system długo po zakończeniu rozmowy.
* **Invalid payloads:** Praca donosi, że invalid messages nadal mogą otrzymywać potwierdzenia; dokładne zachowanie dla malformed bodies lub purged IDs zależy od implementacji, więc należy je przetestować przed poleganiem na tej właściwości.<sup>[[1]](#references)</sup>

## Wzmocnienie multi-device i fingerprinting

* W WhatsApp i Signal każde powiązane urządzenie (telefon, aplikacja desktopowa, browser companion) niezależnie odszyfrowuje probe i zwraca własny ack. Zliczanie receipts dla każdego probe ujawnia dokładną liczbę urządzeń.<sup>[[1]](#references)</sup>
* Jeśli urządzenie jest offline, jego receipt jest kolejkowany i emitowany po ponownym połączeniu. Luki ujawniają więc cykle online/offline, a nawet harmonogramy dojazdów (np. receipts z desktopa przestają się pojawiać podczas podróży).
* Rozkłady RTT różnią się w zależności od platformy i środowiska, ponieważ system operacyjny, model, client i warunki sieciowe wpływają na timing. Grupuj RTT (np. za pomocą k-means na cechach mediany/wariancji), aby oznaczać je jako „Android handset”, „iOS handset”, „Electron desktop” itd.
* Ponieważ sender musi pobrać inwentarz kluczy odbiorcy przed zaszyfrowaniem wiadomości, atakujący może także obserwować, kiedy parowane są nowe urządzenia; nagły wzrost liczby urządzeń lub nowy klaster RTT jest silnym wskaźnikiem.<sup>[[1]](#references)</sup>

## Sampling cadence, kolejkowanie i stacked receipts

* **WhatsApp burst tolerance:** Opublikowane pomiary wykazały, że WhatsApp akceptował bursty silent reactions z częstotliwością nawet jednego probe co `50 ms`, bez widocznego kolejkowania po stronie serwera. Jest to przydatne w krótkich burstach kalibracyjnych, szybkim zliczaniu urządzeń lub szybkim zwiększaniu intensywności drain attack.
* **Signal long-run queueing:** Signal tolerował krótkie bursty, ale zaczął kolejkować utrzymywany ruch obejmujący wiele probe na sekundę. W przypadku długotrwałego monitorowania utrzymuj cadence na poziomie około `1 Hz` (lub niższym), aby każde potwierdzenie nadal odzwierciedlało bieżący stan urządzenia, a nie opróżnianie backlogu.
* **Reconnect artefacts:** Gdy urządzenie wraca online, niektóre klienci grupują lub szybko opróżniają wiele opóźnionych receipts. Traktuj takie burste receipts jako marker zmiany stanu, a nie niezależne próbki RTT, w przeciwnym razie clustering / klasyfikator `active` vs `idle` będzie nadmiernie dopasowany do szumu związanego z reconnect.<sup>[[1]](#references)</sup>

## Wnioskowanie o zachowaniu na podstawie śladów RTT

1. Próbkuj z częstotliwością ≥1 Hz, aby uchwycić efekty harmonogramowania systemu operacyjnego. W WhatsApp na iOS RTT <1 s silnie koreluje z włączonym ekranem/foreground, a >1 s z wyłączonym ekranem/throttlingiem background.
2. Zbuduj proste klasyfikatory (progowanie lub two-cluster k-means), które oznaczą każdy RTT jako „active” lub „idle”. Agreguj oznaczenia w serie, aby wyznaczyć godziny snu, dojazdy, godziny pracy lub czas aktywności desktop companion.
3. Koreluj jednoczesne probe kierowane do każdego urządzenia, aby sprawdzić, kiedy użytkownicy przełączają się z urządzeń mobilnych na desktop, kiedy companions przechodzą offline oraz czy aplikacja jest rate limited przez push czy persistent socket.
4. W rzeczywistych sieciach unikaj jednego sztywnego progu `1 s`. Zainicjalizuj każde urządzenie za pomocą krótkiego okna rozgrzewkowego i utrzymuj baseline kroczący (na przykład PoC device-activity-tracker używa `threshold = 0.9 * median RTT`), aby zmienność Wi-Fi/cellular nie zniszczyła klasyfikatora.<sup>[[1]](#references)[[8]](#references)</sup>

## Wnioskowanie o lokalizacji na podstawie RTT dostarczenia

Ten sam mechanizm czasowy można wykorzystać do wnioskowania o lokalizacji odbiorcy, a nie tylko o jego aktywności. Praca `Hope of Delivery` wykazała, że trenowanie na rozkładach RTT dla znanych lokalizacji odbiorcy pozwala atakującemu później klasyfikować lokalizację ofiary wyłącznie na podstawie delivery confirmations:<sup>[[2]](#references)</sup>

* Zbuduj baseline dla tego samego celu, gdy znajduje się on w kilku znanych miejscach (dom, biuro, kampus, kraj A vs kraj B itd.).
* Dla każdej lokalizacji zbierz wiele normalnych RTT wiadomości i wyodrębnij proste cechy, takie jak mediana, wariancja lub przedziały percentylowe.
* Podczas właściwego ataku porównaj nową serię probe z wytrenowanymi klastrami. Praca informuje, że często można rozróżnić nawet lokalizacje w obrębie tego samego miasta, z dokładnością `>80%` w konfiguracji obejmującej 3 lokalizacje.
* Metoda działa najlepiej, gdy atakujący kontroluje środowisko nadawcy i wykonuje probe w podobnych warunkach sieciowych, ponieważ mierzona ścieżka obejmuje sieć dostępową odbiorcy, opóźnienie wybudzenia i infrastrukturę komunikatora.<sup>[[2]](#references)</sup>

W przeciwieństwie do opisanych wyżej ataków z użyciem silent reaction/edit/delete, wnioskowanie o lokalizacji nie wymaga invalid message IDs ani stealthy state-changing packets. Wystarczą zwykłe wiadomości z normalnymi potwierdzeniami dostarczenia, więc kompromisem jest mniejsza stealth, ale szersze zastosowanie w różnych komunikatorach.

## Stealthy resource exhaustion

Ponieważ każdy silent probe musi zostać odszyfrowany i potwierdzony, ciągłe wysyłanie reaction toggles, invalid edits lub delete-for-everyone packets tworzy DoS na poziomie aplikacji:<sup>[[1]](#references)</sup>

* Zmusza radio/modem do transmisji/odbioru co sekundę → powoduje zauważalne zużycie baterii, szczególnie na bezczynnych urządzeniach.
* Generuje ruch upstream/downstream, który zużywa pakiety danych komórkowych i może konkurować z funkcjami wrażliwymi na opóźnienia, takimi jak video calls.<sup>[[1]](#references)</sup>
* Duże invalid payloads zwiększają obciążenie obliczeniowe, ale praca informuje, że sama kryptografia stanowi pomijalną część kosztu baterii.<sup>[[1]](#references)</sup>
* W WhatsApp invalid reactions akceptują znacznie więcej danych, niż sugerowałoby zwykłe emoji: opublikowane pomiary wykazały akceptację po stronie serwera na poziomie około `1 MB` na reakcję.
* Oversized reactions przestają generować wiarygodne delivery receipts, gdy body przekroczy około `30 bytes`, ale nadal są przekazywane i przetwarzane przed odrzuceniem. Utrzymuj bodies reakcji małe, gdy potrzebujesz ACKs; zwiększaj ich rozmiar tylko wtedy, gdy celem jest czysty drain lub covert one-way transport.
* Publiczne pomiary osiągnęły około `3.7 MB/s` (`~13.3 GB/h`) ruchu ofiary w tym trybie.

## References

- [1] [Careless Whisper: Wykorzystanie cichych potwierdzeń dostarczenia do monitorowania użytkowników mobilnych komunikatorów internetowych](https://arxiv.org/html/2411.11194v4)
- [2] [Hope of Delivery: Wydobywanie lokalizacji użytkowników z mobilnych komunikatorów internetowych](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [3] [whatsmeow](https://github.com/tulir/whatsmeow)
- [4] [Cobalt](https://github.com/Auties00/Cobalt)
- [5] [signal-cli](https://github.com/AsamK/signal-cli)
- [6] [Podręcznik signal-cli](https://github.com/AsamK/signal-cli/blob/master/man/signal-cli.1.adoc)
- [7] [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [8] [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)
- [9] [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python)
- [10] [Jak blokować duże ilości wiadomości od nieznanych nadawców | Centrum pomocy WhatsApp](https://faq.whatsapp.com/3379690015658337)
- [11] [Wszystkie numery są amerykańskie: nadużywanie funkcji contact discovery na dużą skalę w mobilnych komunikatorach internetowych](https://www.ndss-symposium.org/ndss-paper/all-the-numbers-are-us-large-scale-abuse-of-contact-discovery-in-mobile-messengers/)
{{#include ../banners/hacktricks-training.md}}
