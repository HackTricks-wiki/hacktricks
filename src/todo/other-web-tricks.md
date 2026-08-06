# Inne triki Web

{{#include ../banners/hacktricks-training.md}}

### Host header

W wielu przypadkach back-end ufa **nagłówkowi Host** podczas wykonywania określonych działań. Na przykład może używać jego wartości jako **domeny, do której wysyłane jest żądanie resetu hasła**. Gdy otrzymasz wiadomość e-mail z linkiem do resetu hasła, użyta domena będzie tą, którą umieścisz w nagłówku Host. Następnie możesz zażądać resetu hasła innych użytkowników i zmienić domenę na kontrolowaną przez siebie, aby wykraść ich kody resetowania hasła. [WriteUp](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2).<sup>[[1]](#references)</sup>

> [!WARNING]
> Pamiętaj, że możliwe jest, iż nie musisz nawet czekać, aż użytkownik kliknie link resetowania hasła, aby uzyskać token, ponieważ **filtry antyspamowe lub inne urządzenia pośredniczące/boty mogą go kliknąć w celu przeanalizowania go**.

### Session booleans

Czasami po poprawnym przejściu weryfikacji back-end **po prostu dodaje wartość logiczną „True” do atrybutu bezpieczeństwa w Twojej sesji**. Następnie inny endpoint sprawdza, czy pomyślnie przeszedłeś tę kontrolę.\
Jeśli jednak **przejdziesz kontrolę**, a Twoja sesja otrzyma wartość „True” w atrybucie bezpieczeństwa, możesz spróbować **uzyskać dostęp do innych zasobów**, które **zależą od tego samego atrybutu**, ale do których **nie powinieneś mieć uprawnień**. [WriteUp](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a).<sup>[[2]](#references)</sup>

### Register functionality

Spróbuj zarejestrować się jako już istniejący użytkownik. Spróbuj także użyć równoważnych znaków (kropek, wielu spacji i znaków Unicode).

### Takeover emails

Zarejestruj adres e-mail, a przed jego potwierdzeniem zmień adres e-mail. Następnie, jeśli nowa wiadomość potwierdzająca zostanie wysłana na pierwszy zarejestrowany adres e-mail, możesz przejąć dowolny adres e-mail. Jeśli natomiast możesz włączyć drugi adres e-mail, potwierdzając pierwszy, możesz również przejąć dowolne konto.

### Access Internal servicedesk of companies using atlassian


{{#ref}}
https://yourcompanyname.atlassian.net/servicedesk/customer/user/login
{{#endref}}

### TRACE method

Deweloperzy mogą zapomnieć o wyłączeniu różnych opcji debugowania w środowisku produkcyjnym. Na przykład metoda HTTP `TRACE` jest przeznaczona do celów diagnostycznych. Jeśli jest włączona, serwer Web odpowie na żądania używające metody `TRACE`, umieszczając w odpowiedzi dokładnie to żądanie, które zostało odebrane. Takie zachowanie jest zazwyczaj nieszkodliwe, ale czasami prowadzi do ujawnienia informacji, takich jak nazwy wewnętrznych nagłówków uwierzytelniania, które mogą być dołączane do żądań przez reverse proxy.![Obraz dla wpisu](https://miro.medium.com/max/60/1*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Obraz dla wpisu](https://miro.medium.com/max/1330/1*wDFRADTOd9Tj63xucenvAA.png)

## Referencje

- [1] [How I was able to take over any user's account with Host Header Injection](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2)
- [2] [A less known attack vector: Second Order IDOR attacks](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a)

{{#include ../banners/hacktricks-training.md}}
