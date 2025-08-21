# Inne sztuczki internetowe

{{#include ../banners/hacktricks-training.md}}

### Nagłówek hosta

Kilka razy zaplecze ufa **nagłówkowi Host**, aby wykonać pewne działania. Na przykład, może użyć jego wartości jako **domeny do wysłania resetu hasła**. Gdy otrzymasz e-mail z linkiem do zresetowania hasła, używana domena to ta, którą wpisałeś w nagłówku Host. Następnie możesz zażądać resetu hasła innych użytkowników i zmienić domenę na kontrolowaną przez siebie, aby ukraść ich kody resetowania hasła. [WriteUp](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2).

> [!WARNING]
> Zauważ, że możliwe jest, że nie musisz nawet czekać, aż użytkownik kliknie link do resetowania hasła, aby uzyskać token, ponieważ nawet **filtry spamowe lub inne urządzenia/boty pośredniczące mogą kliknąć w niego, aby go przeanalizować**.

### Booleany sesji

Czasami, gdy poprawnie zakończysz weryfikację, zaplecze **po prostu doda boolean z wartością "True" do atrybutu zabezpieczeń twojej sesji**. Następnie inny punkt końcowy będzie wiedział, czy pomyślnie przeszedłeś tę kontrolę.\
Jednak jeśli **przejdziesz kontrolę** i twoja sesja otrzyma wartość "True" w atrybucie zabezpieczeń, możesz spróbować **uzyskać dostęp do innych zasobów**, które **zależą od tego samego atrybutu**, ale do których **nie powinieneś mieć uprawnień** do dostępu. [WriteUp](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a).

### Funkcjonalność rejestracji

Spróbuj zarejestrować się jako już istniejący użytkownik. Spróbuj także użyć równoważnych znaków (kropki, dużo spacji i Unicode).

### Przejęcie e-maili

Zarejestruj e-mail, przed potwierdzeniem zmień e-mail, a następnie, jeśli nowy e-mail potwierdzający zostanie wysłany na pierwszy zarejestrowany e-mail, możesz przejąć dowolny e-mail. Lub jeśli możesz włączyć drugi e-mail potwierdzający pierwszy, możesz również przejąć dowolne konto.

### Dostęp do wewnętrznego serwisu wsparcia firm korzystających z atlassian

{{#ref}}
https://yourcompanyname.atlassian.net/servicedesk/customer/user/login
{{#endref}}

### Metoda TRACE

Programiści mogą zapomnieć wyłączyć różne opcje debugowania w środowisku produkcyjnym. Na przykład, metoda HTTP `TRACE` jest zaprojektowana do celów diagnostycznych. Jeśli jest włączona, serwer webowy odpowiada na żądania, które używają metody `TRACE`, echoując w odpowiedzi dokładne żądanie, które zostało odebrane. To zachowanie jest często nieszkodliwe, ale czasami prowadzi do ujawnienia informacji, takich jak nazwy wewnętrznych nagłówków uwierzytelniających, które mogą być dołączane do żądań przez odwrotne proxy.![Image for post](https://miro.medium.com/max/60/1*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Image for post](https://miro.medium.com/max/1330/1*wDFRADTOd9Tj63xucenvAA.png)

{{#include ../banners/hacktricks-training.md}}
