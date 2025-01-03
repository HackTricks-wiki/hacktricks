# Inne sztuczki internetowe

{{#include ../banners/hacktricks-training.md}}

### Nagłówek hosta

Kilka razy backend ufa **nagłówkowi Host**, aby wykonać pewne działania. Na przykład, może użyć jego wartości jako **domeny do wysłania resetu hasła**. Gdy otrzymasz e-mail z linkiem do zresetowania hasła, używaną domeną jest ta, którą wpisałeś w nagłówku Host. Następnie możesz zażądać resetu hasła innych użytkowników i zmienić domenę na kontrolowaną przez siebie, aby ukraść ich kody resetu hasła. [WriteUp](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2).

> [!WARNING]
> Zauważ, że możliwe jest, że nie musisz nawet czekać, aż użytkownik kliknie link do resetu hasła, aby uzyskać token, ponieważ być może nawet **filtry spamowe lub inne urządzenia/boty pośredniczące klikną w niego, aby go przeanalizować**.

### Booleany sesji

Czasami, gdy poprawnie zakończysz weryfikację, backend **po prostu doda boolean o wartości "True" do atrybutu bezpieczeństwa twojej sesji**. Następnie inny punkt końcowy będzie wiedział, czy pomyślnie przeszedłeś tę kontrolę.\
Jednak jeśli **przejdziesz kontrolę** i twoja sesja otrzyma tę wartość "True" w atrybucie bezpieczeństwa, możesz spróbować **uzyskać dostęp do innych zasobów**, które **zależą od tego samego atrybutu**, ale do których **nie powinieneś mieć uprawnień** do dostępu. [WriteUp](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a).

### Funkcjonalność rejestracji

Spróbuj zarejestrować się jako już istniejący użytkownik. Spróbuj także użyć równoważnych znaków (kropki, dużo spacji i Unicode).

### Przejęcie e-maili

Zarejestruj e-mail, przed potwierdzeniem zmień e-mail, a następnie, jeśli nowy e-mail potwierdzający zostanie wysłany na pierwszy zarejestrowany e-mail, możesz przejąć dowolny e-mail. Lub jeśli możesz włączyć drugi e-mail potwierdzający pierwszy, możesz również przejąć dowolne konto.

### Dostęp do wewnętrznego serwisu wsparcia firm korzystających z Atlassian

{% embed url="https://yourcompanyname.atlassian.net/servicedesk/customer/user/login" %}

### Metoda TRACE

Programiści mogą zapomnieć wyłączyć różne opcje debugowania w środowisku produkcyjnym. Na przykład, metoda HTTP `TRACE` jest zaprojektowana do celów diagnostycznych. Jeśli jest włączona, serwer WWW odpowie na żądania, które używają metody `TRACE`, echo w odpowiedzi dokładnego żądania, które zostało odebrane. To zachowanie jest często nieszkodliwe, ale czasami prowadzi do ujawnienia informacji, takich jak nazwy wewnętrznych nagłówków uwierzytelniających, które mogą być dołączane do żądań przez odwrotne proxy.![Image for post](https://miro.medium.com/max/60/1*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Image for post](https://miro.medium.com/max/1330/1*wDFRADTOd9Tj63xucenvAA.png)

{{#include ../banners/hacktricks-training.md}}
