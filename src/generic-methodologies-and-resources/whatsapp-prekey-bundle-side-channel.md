# Wyczerpywanie i uzupełnianie pakietu Prekey WhatsApp jako kanał boczny

{{#include ../banners/hacktricks-training.md}}

WhatsApp przechowuje dla każdego urządzenia klucz tożsamości, podpisany klucz prekey oraz zapas jednorazowych kluczy prekey. Pobranie pakietu urządzenia zużywa jeden jednorazowy klucz prekey przechowywany na serwerze, nawet jeśli żądający nie wysyła żadnej wiadomości. Daje to atakującemu, który ma konto WhatsApp i numer telefonu celu, możliwość sondowania **po stronie serwera**, odrębną od [pomiaru czasu potwierdzeń dostarczenia po stronie klienta](side-channel-attacks-on-messaging-protocols.md). Brak jednorazowego klucza prekey osłabia też poufność przekazywania w *początkowych* wiadomościach nowo ustanowionej sesji; sam w sobie nie ujawnia tekstu jawnego.<sup>[[1]](#references)[[2]](#references)</sup>

## Sprawdzanie pakietów urządzeń celu

[Artefakt Prekey Pogo](https://github.com/sbaresearch/prekey-pogo) paruje się jako sesja towarzysząca WhatsApp i obsługuje **ręczne** zapytania o urządzenia i klucze prekey. Sparuj go z kontem testowym, a następnie użyj interaktywnych poleceń `target`, `devices`, `prekey` (urządzenie główne) i `combine` (wszystkie urządzenia). Udostępniony artefakt celowo nie zawiera funkcji automatycznego wyczerpywania ani przeciążania serwera.<sup>[[1]](#references)[[3]](#references)</sup>

```bash
git clone https://github.com/sbaresearch/prekey-pogo
cd prekey-pogo
./setup.sh
go run .
```

Dla każdej odpowiedzi zapisuj JID urządzenia, znacznik czasu bundle `t`, ID signed-prekey `skey.id` oraz informację, czy występuje jednorazowy `key.id`. ID urządzenia `0` oznacza telefon; niezerowe ID oznaczają urządzenia towarzyszące. W implementacjach testowanych w artykule początkowe ID signed-prekey pozwala też odróżnić niektóre klienty: Android zaczyna od `0`, iOS i macOS używają losowej wartości, a WhatsApp Web i Windows Desktop zaczynają od `1`. Traktuj to jako fingerprint implementacji, a nie niezmienną regułę protokołu.<sup>[[1]](#references)</sup>

## Zamień uzupełnianie puli w oracle stanu online

Najpierw przeprowadź kalibrację na urządzeniu, które kontrolujesz: wielokrotnie pobieraj jego bundle, aż serwer przestanie zwracać jednorazowy `key`, i zanotuj ostatni znacznik czasu oraz ID kluczy. W przypadku urządzenia docelowego powtórz opróżnianie puli, a następnie po określonym czasie ponownie odpytaj serwer: nowy jednorazowy klucz i nowszy znacznik czasu bundle wskazują, że urządzenie przesłało nową partię kluczy. W opisanych testach WhatsApp serwer inicjował uzupełnienie, gdy pozostawało mniej niż 11 kluczy, a klienty przesyłały 812 nowych kluczy. Stosuj tę procedurę osobno dla każdego JID urządzenia, aby odróżnić telefon od urządzeń towarzyszących. Opóźnione uzupełnienie jedynie **sugeruje**, że urządzenie jest offline: taki sam wynik mogą dać harmonogram zadań w tle, utrata połączenia sieciowego i opóźnienie uzupełniania charakterystyczne dla danego klienta. W przeciwieństwie do pomiaru RTT potwierdzenia, ta sonda nie wymaga dostarczenia szyfrogramu ani potwierdzenia po stronie ofiary.<sup>[[1]](#references)[[2]](#references)</sup>

Każde zapytanie zużywa jednorazowy klucz, więc do ciągłego działania oracle potrzebny jest własny klient, który potrafi wielokrotnie pobierać prekey; publicznie dostępny artefakt pokazuje jedynie ręczne zapytania. Utrzymywanie pustej rezerwy może sprawić, że inni użytkownicy będą nawiązywać nowe sesje bez jednorazowego prekey. Ogranicza to forward secrecy dla pierwszych wiadomości do czasu kolejnego kroku ratchetu, ale wykorzystanie nagranego szyfrogramu wymaga dodatkowo dostępu do szyfrogramu E2EE oraz późniejszego przejęcia odpowiednich kluczy prywatnych długo- i średnioterminowych. Istniejące, nawiązane sesje nie są automatycznie obniżane do słabszego poziomu zabezpieczeń.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## References

- [1] [Prekey Pogo: Badanie problemów bezpieczeństwa i prywatności w mechanizmie handshake WhatsApp](https://www.usenix.org/system/files/woot25-gegenhuber.pdf)
- [2] [Protokół uzgadniania kluczy X3DH](https://signal.org/docs/specifications/x3dh/)
- [3] [Artefakty Prekey Pogo](https://github.com/sbaresearch/prekey-pogo)
{{#include ../banners/hacktricks-training.md}}
