# Inne triki webowe

{{#include ../banners/hacktricks-training.md}}

## Host header

Back-endy czasami ufają polu HTTP `Host` podczas konstruowania absolutnych linków. Jeśli wiadomość e-mail dotycząca resetowania hasła używa hosta podanego przez atakującego, żądanie resetu dla ofiary może wysłać link zawierający token przez domenę kontrolowaną przez atakującego. Przy każdym przeskoku proxy sprawdź również pola forwarded-host, obsługę zduplikowanych nagłówków Host oraz cele żądań w formacie absolutnym.<sup>[[1]](#references)</sup>

> [!WARNING]
> Kliknięcie przez użytkownika może nie być konieczne: **skanery bezpieczeństwa poczty, usługi podglądu lub inne pośredniki mogą automatycznie zażądać linku kontrolowanego przez atakującego**, ujawniając token resetowania.

## Wartości logiczne sesji

Niektóre aplikacje zapisują ukończenie weryfikacji jako wartość logiczną w sesji, a następnie pozwalają innemu endpointowi polegać na tej fladze. Po legalnym przejściu kontroli dla jednego zasobu sprawdź, czy ta sama flaga nie autoryzuje nieprawidłowo innego użytkownika, obiektu lub workflow. Jest to błąd autoryzacji/ponownego użycia stanu drugiego rzędu, a nie tylko IDOR.<sup>[[2]](#references)</sup>

## Funkcjonalność rejestracji

Spróbuj zarejestrować się jako już istniejący użytkownik. Spróbuj także użyć równoważnych znaków (kropek, wielu spacji i Unicode).

## Pomylenie stanu zmiany adresu e-mail

Zarejestruj adres e-mail i zmień go przed potwierdzeniem. Sprawdź, czy potwierdzenie nowego adresu jest wysyłane na stary adres albo czy potwierdzenie starego tokenu aktywuje nowy adres. Tokeny potwierdzające muszą być powiązane z dokładnym kontem, oczekującym adresem, przeznaczeniem i bieżącym stanem.

## Ujawnione Atlassian service desks


{{#ref}}
https://yourcompanyname.atlassian.net/servicedesk/customer/user/login
{{#endref}}

## TRACE method

Metoda HTTP `TRACE` żąda zwrócenia otrzymanego żądania w pętli zwrotnej na potrzeby diagnostyki. RFC 9110 wymaga od odbiorców pominięcia poufnych pól, takich jak dane uwierzytelniające i cookies, w odzwierciedlanej treści, ale niebezpieczne implementacje lub nagłówki dodane przez pośredników nadal mogą ujawniać wewnętrzne przekształcenia żądania. Przeglądarki uniemożliwiają skryptom generowanie żądań TRACE, dlatego historyczny cross-site tracing attack również zależy od odrębnego sposobu wstrzyknięcia chronionych pól.<sup>[[3]](#references)</sup>![Obraz przedstawiający odpowiedź TRACE](https://miro.medium.com/max/60/1*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Obraz do posta](https://miro.medium.com/max/1330/1*wDFRADTOd9Tj63xucenvAA.png)

## References

- [1] [Jak udało mi się przejąć dowolne konto użytkownika za pomocą Host Header Injection](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2)
- [2] [Mniej znany wektor ataku: ataki IDOR drugiego rzędu](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a)
- [3] [RFC 9110, sekcja 9.3.8 — TRACE](https://www.rfc-editor.org/rfc/rfc9110.html#name-trace)
{{#include ../banners/hacktricks-training.md}}
