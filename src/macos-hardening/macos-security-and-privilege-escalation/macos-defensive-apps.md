# macOS Defensive Apps

{{#include ../../banners/hacktricks-training.md}}

## Firewalls

- [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html): Będzie monitorować każde połączenie nawiązane przez każdy proces. W zależności od trybu (ciche zezwolenie na połączenia, ciche odrzucenie połączenia i powiadomienie) **pokaże ci powiadomienie** za każdym razem, gdy nawiązywane jest nowe połączenie. Posiada również bardzo ładny interfejs graficzny do przeglądania tych informacji.
- [**LuLu**](https://objective-see.org/products/lulu.html): Zapora sieciowa Objective-See. To podstawowa zapora, która powiadomi cię o podejrzanych połączeniach (ma interfejs graficzny, ale nie jest tak elegancki jak ten w Little Snitch).

## Wykrywanie persistencji

- [**KnockKnock**](https://objective-see.org/products/knockknock.html): Aplikacja Objective-See, która przeszuka kilka lokalizacji, gdzie **złośliwe oprogramowanie może się utrzymywać** (to narzędzie jednorazowe, a nie usługa monitorująca).
- [**BlockBlock**](https://objective-see.org/products/blockblock.html): Podobnie jak KnockKnock, monitorując procesy, które generują persistencję.

## Wykrywanie keyloggerów

- [**ReiKey**](https://objective-see.org/products/reikey.html): Aplikacja Objective-See do znajdowania **keyloggerów**, które instalują "event taps" na klawiaturze.

{{#include ../../banners/hacktricks-training.md}}
