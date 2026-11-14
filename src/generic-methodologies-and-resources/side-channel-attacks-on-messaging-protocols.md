# Ataki side-channel z wykorzystaniem potwierdzeń dostarczenia w komunikatorach E2EE

{{#include ../banners/hacktricks-training.md}}

Potwierdzenia dostarczenia są niezbędne we współczesnych komunikatorach szyfrujących end-to-end (E2EE), ponieważ klienci muszą wiedzieć, kiedy tekst zaszyfrowany został odszyfrowany, aby móc usunąć stan ratchetingu i klucze efemeryczne. Serwer przekazuje nieczytelne bloby, więc urządzenie odbiorcy wysyła potwierdzenie (dwa znaczniki wyboru) po pomyślnym odszyfrowaniu. Pomiar czasu round-trip (RTT) między działaniem wywołanym przez atakującego a odpowiadającym mu potwierdzeniem dostarczenia ujawnia kanał czasowy o wysokiej rozdzielczości, który zdradza stan urządzenia i obecność użytkownika online oraz może zostać wykorzystany do ukrytego DoS. Wdrożenia wielourządzeniowe typu „client-fanout” wzmacniają wyciek, ponieważ każde zarejestrowane urządzenie odszyfrowuje sondę i odsyła własne potwierdzenie.<sup>[[1]](#references)</sup>

## Źródła potwierdzeń dostarczenia a sygnały widoczne dla użytkownika

Wybieraj typy wiadomości, które zawsze generują potwierdzenie dostarczenia, ale nie pozostawiają u ofiary śladów w interfejsie. Poniższa tabela podsumowuje zachowanie potwierdzone empirycznie:<sup>[[1]](#references)</sup>

| Messenger | Działanie | Potwierdzenie dostarczenia | Powiadomienie ofiary | Uwagi |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Wiadomość tekstowa | ● | ● | Zawsze widoczna → przydatna tylko do wstępnego rozpoznania stanu. |
| | Reakcja | ● | ◐ (tylko w reakcji na wiadomość ofiary) | Własne reakcje i ich usuwanie są niewidoczne. |
| | Edycja | ● | Cichy push zależny od platformy | Okno edycji ≈20 min; potwierdzenie jest wysyłane także po jego upływie. |
| | Usuń u wszystkich | ● | ○ | Interfejs pozwala na to przez ~60 godz., ale późniejsze pakiety nadal otrzymują potwierdzenie. |
| **Signal** | Wiadomość tekstowa | ● | ● | Te same ograniczenia co w WhatsApp. |
| | Reakcja | ● | ◐ | Własne reakcje są niewidoczne dla ofiary. |
| | Edycja/Usunięcie | ● | ○ | Serwer egzekwuje okno ~48 godz. i pozwala na maks. 10 edycji, ale późne pakiety nadal otrzymują potwierdzenie. |
| **Threema** | Wiadomość tekstowa | ● | ● | Potwierdzenia z wielu urządzeń są agregowane, więc widoczny jest tylko jeden RTT na sondę. |

Legenda: ● = zawsze, ◐ = warunkowo, ○ = nigdy. Zależne od platformy zachowanie interfejsu opisano w uwagach. W razie potrzeby wyłącz potwierdzenia odczytu, ale w WhatsApp ani Signal nie można wyłączyć potwierdzeń dostarczenia.<sup>[[1]](#references)</sup>

## Cele i modele atakującego

* **G1 – Fingerprinting urządzeń:** Zliczaj potwierdzenia otrzymane dla każdej sondy, grupuj RTT, aby wnioskować o systemie operacyjnym/kliencie (Android vs iOS vs komputer), i obserwuj przejścia między stanem online a offline.
* **G2 – Monitorowanie zachowania:** Traktuj serię RTT o wysokiej częstotliwości (≈1 Hz jest stabilne) jako szereg czasowy i wnioskuj o włączonym/wyłączonym ekranie, działaniu aplikacji na pierwszym lub drugim planie, godzinach dojazdów do pracy i pracy itp.
* **G3 – Wyczerpywanie zasobów:** Utrzymuj aktywność modułów radiowych/CPU na wszystkich urządzeniach ofiary, wysyłając niekończące się ciche sondy, co wyczerpuje baterię i transfer danych oraz pogarsza jakość połączeń wideo.<sup>[[1]](#references)</sup>

Do opisania powierzchni nadużyć wystarczą dwa typy sprawców:<sup>[[1]](#references)</sup>

1. **Creepy companion:** już prowadzi czat z ofiarą i nadużywa własnych reakcji, ich usuwania lub powtarzanych edycji/usunięć powiązanych z istniejącymi identyfikatorami wiadomości.
2. **Spooky stranger:** rejestruje konto tymczasowe i wysyła reakcje odwołujące się do identyfikatorów wiadomości, które nigdy nie istniały w lokalnej konwersacji; WhatsApp i Signal nadal je odszyfrowują i potwierdzają, mimo że interfejs odrzuca zmianę stanu, więc wcześniejsza konwersacja nie jest wymagana.

## Narzędzia do dostępu do surowego protokołu

Korzystaj z klientów udostępniających wystarczającą część bazowego protokołu E2EE, by tworzyć obsługiwane pakiety z pominięciem ograniczeń interfejsu i rejestrować dokładne znaczniki czasu; możliwość użycia dowolnych identyfikatorów wiadomości należy sprawdzić w każdej implementacji:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, wielourządzeniowe API WhatsApp Web) opisuje wysyłanie i odbieranie potwierdzeń dostarczenia; [Cobalt](https://github.com/Auties00/Cobalt) (nieoficjalne API Web i mobilne w Javie/Kotlinie) opisuje operacje na wiadomościach, takie jak reagowanie, edytowanie i usuwanie. Korzystaj z udokumentowanych API, zamiast zakładać, że udostępniona jest każda wewnętrzna ramka.<sup>[[3]](#references)[[4]](#references)</sup>
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) udostępnia interfejsy CLI, JSON-RPC i D-Bus, a [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) to biblioteka Java do komunikacji z Signal.<sup>[[5]](#references)[[7]](#references)</sup> Aktualna składnia `signal-cli` to `sendReaction RECIPIENT --target-author --target-timestamp`; pozostaw uruchomione `receive` lub `daemon`, aby nadal przetwarzać aktualizacje protokołu.<sup>[[6]](#references)</sup> Przykład przełączania własnej reakcji:
  ```bash
  signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
      --target-timestamp 1712345678901 --emoji "👍"
  signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
      --target-timestamp 1712345678901 --remove
  ```
* **Threema:** Pomiary opisane w artykule Careless Whisper wykazały, że potwierdzenia dostarczenia są synchronizowane między urządzeniami, więc nawet przy konfiguracji wielourządzeniowej ujawniane jest tylko jedno potwierdzenie na wiadomość.<sup>[[1]](#references)</sup>
* **Gotowe PoC:** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker) zawiera backendy WhatsApp/Signal, domyślnie używa silent delete probes i oznacza stan jako `active` lub `standby` na podstawie progu opartego na medianie kroczącej (`RTT < 0.9 * median`).<sup>[[8]](#references)</sup> [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python) to prostsze CLI nastawione na WhatsApp, oferujące `--delay`, `--concurrent`, eksport do CSV/Prometheus oraz dane wyjściowe przyjazne dla Grafany.<sup>[[9]](#references)</sup> Traktuj oba narzędzia jako pomoc przy rekonesansie, a nie jako dokumentację protokołu; najważniejsze jest to, jak niewiele kodu potrzeba, gdy ma się dostęp do surowego klienta.

Gdy niestandardowe narzędzia są niedostępne, oficjalne klienty lub narzędzia deweloperskie przeglądarki nadal mogą wyzwalać ciche akcje i ujawniać timing zaszyfrowanego ruchu; surowe API eliminują opóźnienia interfejsu i pozwalają wykonywać nieprawidłowe operacje.<sup>[[1]](#references)</sup>

## Creepy companion: cicha pętla próbkowania

1. Wybierz dowolną starszą wiadomość, którą wysłałeś na czacie, aby ofiara nie widziała zmian „dymków” reakcji.
2. Na przemian wysyłaj widoczne emoji i pusty payload reakcji (kodowany jako `""` w protobufach WhatsApp lub jako `--remove` w signal-cli). Każda transmisja wywołuje device ack, mimo że interfejs ofiary się nie zmienia.
3. Zapisuj znacznik czasu wysłania oraz czas nadejścia każdego potwierdzenia dostarczenia. Pętla 1 Hz, taka jak poniższa, pozwala bez końca zbierać ślady RTT dla poszczególnych urządzeń:
   ```python
   while True:
       send_reaction(msg_id, "👍")
       log_receipts()
       send_reaction(msg_id, "")  # removal
       log_receipts()
       time.sleep(0.5)
   ```
4. Ponieważ WhatsApp/Signal akceptują nieograniczoną liczbę aktualizacji reakcji, atakujący nigdy nie musi publikować nowej treści na czacie ani martwić się o okno edycji.<sup>[[1]](#references)</sup>

## Upiorny nieznajomy: sondowanie dowolnych numerów telefonów

1. Zarejestruj nowe konto WhatsApp/Signal i pobierz publiczne klucze tożsamości dla numeru docelowego (odbywa się to automatycznie podczas konfiguracji sesji).
2. Przygotuj pakiet reakcji odwołujący się do losowego `message_id`, którego żadna ze stron wcześniej nie widziała; w artykule opisano, że WhatsApp i Signal akceptują takie reakcje i nadal generują potwierdzenia dostarczenia.<sup>[[1]](#references)</sup>
3. Wyślij pakiet, mimo że nie istnieje żaden wątek. Urządzenia ofiary odszyfrują go, nie znajdą wiadomości bazowej i odrzucą zmianę stanu, ale nadal potwierdzą odebranie szyfrogramu, wysyłając potwierdzenia urządzeń do atakującego.
4. Powtarzaj operację, aby budować serie RTT bez wcześniejszej rozmowy ani widocznego powiadomienia.<sup>[[1]](#references)</sup>

Jeśli najpierw musisz sprawdzić, które numery są zarejestrowane, lub masowo wstępnie zebrać informacje o urządzeniach, połącz tę metodę z [contact-discovery / registration oracles](../pentesting-web/registration-vulnerabilities.md), zamiast ręcznie zgadywać losowe zakresy E.164.

Opublikowane badania nad contact-discovery pokazały, dlaczego ma to znaczenie w praktyce: korzystając z dokładnych tabel prefiksów telefonicznych i umiarkowanych zasobów, badacze mogli sprawdzić około `10%` amerykańskich numerów komórkowych w WhatsApp i `100%` w Signal, zanim przeszli do ukierunkowanego sondowania.<sup>[[11]](#references)</sup> W praktyce wcześniejsze filtrowanie aktywnych kont pozwala skupić budżet cichych sond na numerach, które rzeczywiście odszyfrują pakiety.

Nowsze wersje WhatsApp udostępniają też opcję `Settings -> Privacy -> Advanced -> Block unknown account messages`.<sup>[[10]](#references)</sup> Traktuj ją jako ograniczenie przepustowości: dokumentacja trackera informuje, że WhatsApp blokuje wiadomości o dużej częstotliwości wysyłane z nieznanych kont, ale nie ujawnia progu, więc opcja ta nie zapobiega całkowicie sondowaniu za pomocą reakcji.<sup>[[8]](#references)</sup>

## Ponowne wykorzystywanie edycji i usunięć jako ukrytych wyzwalaczy

* **Wielokrotne usuwanie:** Po jednorazowym usunięciu wiadomości dla wszystkich kolejne pakiety usunięcia odwołujące się do tego samego `message_id` nie mają wpływu na interfejs, ale każde urządzenie nadal je odszyfrowuje i potwierdza.
* **Operacje poza dozwolonym oknem:** WhatsApp wymusza w interfejsie okna około 60 h na usunięcie i 20 min na edycję; Signal — około 48 h. Przygotowane wiadomości protokołu wysłane po upływie tych okien są po cichu ignorowane na urządzeniu ofiary, ale potwierdzenia są przesyłane, dzięki czemu atakujący może sondować bez końca, nawet długo po zakończeniu rozmowy.
* **Nieprawidłowe ładunki:** W artykule opisano, że nieprawidłowe wiadomości również mogą być potwierdzane; dokładne zachowanie w przypadku błędnych treści lub usuniętych identyfikatorów zależy od implementacji, więc przed poleganiem na nim należy je przetestować.<sup>[[1]](#references)</sup>

## Wzmacnianie sygnału i fingerprinting wielu urządzeń

* W WhatsApp i Signal każde powiązane urządzenie (telefon, aplikacja desktopowa, przeglądarka towarzysząca) niezależnie odszyfrowuje sondę i zwraca własne potwierdzenie. Zliczanie potwierdzeń dla każdej sondy ujawnia dokładną liczbę urządzeń.<sup>[[1]](#references)</sup>
* Jeśli urządzenie jest offline, jego potwierdzenie zostaje zakolejkowane i wysłane po ponownym połączeniu. Przerwy ujawniają więc cykle online/offline, a nawet harmonogram dnia (np. potwierdzenia z komputera ustają podczas podróży).
* Rozkłady RTT różnią się w zależności od platformy i środowiska, ponieważ na czas wpływają system operacyjny, model, klient i warunki sieciowe. Grupuj RTT (np. za pomocą k-means na cechach mediany i wariancji), aby rozpoznawać „telefon z Androidem”, „telefon z iOS”, „komputer z Electron” itp.
* Ponieważ przed szyfrowaniem nadawca musi pobrać spis kluczy odbiorcy, atakujący może też obserwować, kiedy parowane są nowe urządzenia; nagły wzrost ich liczby lub pojawienie się nowego skupienia RTT jest mocnym wskaźnikiem.<sup>[[1]](#references)</sup>

**Fingerprinting na podstawie zakolejkowanych potwierdzeń:** Wyślij kilka sond z różnymi identyfikatorami wiadomości, gdy urządzenie docelowe jest offline. Gdy ponownie się połączy, skoreluj identyfikatory w zwróconych potwierdzeniach dostarczenia i sprawdź, czy są osobne, czy zgrupowane w jednym potwierdzeniu oraz czy zgrupowane identyfikatory zachowują kolejność wysyłania, czy ją odwracają. W testowanych klientach WhatsApp na Androida/iOS zwracał osobne potwierdzenia dostarczenia, podczas gdy wersje Web, Windows i macOS grupowały je; macOS odwracał kolejność zgrupowanych identyfikatorów. Signal Desktop grupował potwierdzenia, w przeciwieństwie do klientów mobilnych. Pozwala to sklasyfikować klienta ponownie łączącego się z siecią, nawet gdy rozkłady RTT się pokrywają. Nie myl potwierdzeń dostarczenia z potwierdzeniami odczytu — zasady ich grupowania są inne.<sup>[[1]](#references)</sup>

Informacje o osobnej sondzie WhatsApp, która odczytuje **uzupełnianie prekey po stronie serwera** bez dostarczania wiadomości, znajdziesz w artykule [Prekey Bundle Depletion and Refill Side Channel](whatsapp-prekey-bundle-side-channel.md).

## Częstotliwość próbkowania, kolejkowanie i grupowanie potwierdzeń

* **Tolerancja WhatsApp na serie sond:** Opublikowane pomiary wykazały, że WhatsApp akceptował serie cichych reakcji z częstotliwością jednej sondy co `50 ms`, bez widocznego kolejkowania po stronie serwera. Przydaje się to do krótkich serii kalibracyjnych, szybkiego zliczania urządzeń lub szybkiego rozpoczęcia ataku drenującego.
* **Długotrwałe kolejkowanie w Signal:** Signal tolerował krótkie serie, ale przy długotrwałym ruchu przekraczającym jedną sondę na sekundę zaczynał kolejkować pakiety. Przy długotrwałym monitorowaniu utrzymuj częstotliwość około `1 Hz` (lub niższą), aby każde potwierdzenie nadal odzwierciedlało bieżący stan urządzenia, a nie opróżnianie kolejki.
* **Artefakty ponownego połączenia:** Gdy urządzenie wraca do sieci, niektórzy klienci grupują wiele opóźnionych potwierdzeń lub szybko je wysyłają. Traktuj takie serie potwierdzeń jako znacznik zmiany stanu, a nie niezależne próbki RTT. W przeciwnym razie klasteryzacja / klasyfikator `active` vs `idle` nadmiernie dopasuje się do szumu związanego z ponownym połączeniem.<sup>[[1]](#references)</sup>

## Wnioskowanie o zachowaniu na podstawie śladów RTT

1. Próbkuj z częstotliwością ≥1 Hz, aby uchwycić efekty planowania zadań systemu operacyjnego. W WhatsApp na iOS RTT <1 s silnie koreluje z włączonym ekranem i działaniem aplikacji na pierwszym planie, a RTT >1 s — z wyłączonym ekranem i ograniczeniami pracy w tle.
2. Zbuduj proste klasyfikatory (progowe lub k-means z dwoma skupieniami), które oznaczają każde RTT jako „active” lub „idle”. Łącz etykiety w serie, aby wyznaczyć pory snu, dojazdy, godziny pracy lub czas aktywności aplikacji towarzyszącej na komputerze.
3. Wysyłaj równoczesne sondy do każdego urządzenia, aby sprawdzić, kiedy użytkownicy przełączają się z telefonu na komputer, kiedy urządzenia towarzyszące przechodzą offline oraz czy aplikacja jest ograniczana przez push czy przez trwałe połączenie gniazdowe.
4. W rzeczywistych sieciach unikaj jednego, sztywno zakodowanego progu `1 s`. Skalibruj każde urządzenie za pomocą krótkiego okresu rozgrzewki i utrzymuj przesuwający się punkt odniesienia (na przykład PoC device-activity-tracker używa `threshold = 0.9 * median RTT`), aby zmienność Wi-Fi/sieci komórkowej nie rozregulowała klasyfikatora.<sup>[[1]](#references)[[8]](#references)</sup>

## Wnioskowanie o lokalizacji na podstawie RTT dostarczenia

Ten sam mechanizm pomiaru czasu można wykorzystać do ustalenia, gdzie znajduje się odbiorca, a nie tylko tego, czy jest aktywny. Badanie `Hope of Delivery` wykazało, że trenowanie na rozkładach RTT dla znanych lokalizacji odbiorcy pozwala później atakującemu sklasyfikować lokalizację ofiary wyłącznie na podstawie potwierdzeń dostarczenia:<sup>[[2]](#references)</sup>

* Zbuduj punkt odniesienia dla tego samego celu w kilku znanych miejscach (dom, biuro, kampus, kraj A i kraj B itp.).
* Dla każdej lokalizacji zbierz wiele próbek RTT zwykłych wiadomości i wyodrębnij proste cechy, takie jak mediana, wariancja lub przedziały percentylowe.
* Podczas właściwego ataku porównaj nową serię sond z wytrenowanymi skupieniami. W artykule podano, że często można rozróżnić nawet lokalizacje w obrębie tego samego miasta, uzyskując `>80%` dokładności w przypadku trzech lokalizacji.
* Metoda działa najlepiej, gdy atakujący kontroluje środowisko nadawcy i wysyła sondy w podobnych warunkach sieciowych, ponieważ mierzona trasa obejmuje sieć dostępową odbiorcy, opóźnienie wybudzania i infrastrukturę komunikatora.<sup>[[2]](#references)</sup>

W przeciwieństwie do opisanych wyżej ataków z cichymi reakcjami, edycją i usuwaniem, wnioskowanie o lokalizacji nie wymaga nieprawidłowych identyfikatorów wiadomości ani ukrytych pakietów zmieniających stan. Wystarczą zwykłe wiadomości z normalnymi potwierdzeniami dostarczenia, więc kompromisem jest mniejsza dyskrecja, ale szersze zastosowanie w różnych komunikatorach.

## Dyskretne wyczerpywanie zasobów

Ponieważ każda cicha sonda musi zostać odszyfrowana i potwierdzona, ciągłe wysyłanie przełączanych reakcji, nieprawidłowych edycji lub pakietów usunięcia dla wszystkich powoduje DoS na poziomie aplikacji:<sup>[[1]](#references)</sup>

* Wymusza nadawanie/odbieranie przez radio/modem co sekundę → zauważalne zużycie baterii, szczególnie na nieużywanych telefonach.
* Generuje ruch przychodzący i wychodzący, zużywając pakiet danych i mogąc zakłócać funkcje wrażliwe na opóźnienia, takie jak połączenia wideo.<sup>[[1]](#references)</sup>
* Duże nieprawidłowe ładunki zwiększają obciążenie przetwarzania, ale według artykułu sama kryptografia ma znikomy udział w zużyciu baterii.<sup>[[1]](#references)</sup>
* W WhatsApp nieprawidłowe reakcje akceptują znacznie więcej danych, niż sugerowałaby zwykła emotikona: opublikowane pomiary wykazały akceptację po stronie serwera do około `1 MB` na reakcję.
* Zbyt duże reakcje przestają generować wiarygodne potwierdzenia dostarczenia, gdy treść przekracza około `30 bytes`, ale przed odrzuceniem nadal są przekazywane dalej i przetwarzane. Gdy potrzebujesz ACK, treść reakcji powinna być mała; zwiększaj ją tylko wtedy, gdy celem jest czyste wyczerpywanie zasobów lub ukryty transport jednokierunkowy.
* Publiczne pomiary osiągnęły około `3.7 MB/s` (`~13.3 GB/h`) ruchu u ofiary w tym trybie.



## References

- [1] [Nieostrożny szept: wykorzystywanie cichych potwierdzeń dostarczenia do monitorowania użytkowników mobilnych komunikatorów internetowych](https://arxiv.org/html/2411.11194v4)
- [2] [Nadzieja na dostarczenie: ustalanie lokalizacji użytkowników na podstawie mobilnych komunikatorów internetowych](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [3] [whatsmeow](https://github.com/tulir/whatsmeow)
- [4] [Cobalt](https://github.com/Auties00/Cobalt)
- [5] [signal-cli](https://github.com/AsamK/signal-cli)
- [6] [strona man signal-cli](https://github.com/AsamK/signal-cli/blob/master/man/signal-cli.1.adoc)
- [7] [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [8] [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)
- [9] [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python)
- [10] [Jak blokować dużą liczbę wiadomości od nieznanych nadawców | Centrum pomocy WhatsApp](https://faq.whatsapp.com/3379690015658337)
- [11] [Wszystkie numery należą do USA: nadużywanie contact-discovery na dużą skalę w mobilnych komunikatorach](https://www.ndss-symposium.org/ndss-paper/all-the-numbers-are-us-large-scale-abuse-of-contact-discovery-in-mobile-messengers/)
{{#include ../banners/hacktricks-training.md}}
