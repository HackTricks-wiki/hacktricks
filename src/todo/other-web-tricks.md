# Inne triki webowe

{{#include ../banners/hacktricks-training.md}}

### Host header

W wielu przypadkach backend ufa **nagłówkowi Host** podczas wykonywania określonych działań. Na przykład może używać jego wartości jako **domeny, na którą wysyłane jest żądanie resetu hasła**. Gdy otrzymasz wiadomość e-mail z linkiem do resetu hasła, użyta domena będzie tą, którą umieścisz w nagłówku Host. Następnie możesz zażądać resetu hasła innych użytkowników i zmienić domenę na kontrolowaną przez siebie, aby wykraść ich kody resetowania hasła. [WriteUp](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2).<sup>[[1]](#references)</sup>

> [!WARNING]
> Pamiętaj, że być może nie musisz nawet czekać, aż użytkownik kliknie link resetowania hasła, aby uzyskać token, ponieważ **filtry antyspamowe lub inne pośredniczące urządzenia/boty mogą go kliknąć, aby go przeanalizować**.

### Booleany sesji

Czasami po pomyślnym przejściu weryfikacji backend **po prostu dodaje boolean o wartości "True" do atrybutu bezpieczeństwa Twojej sesji**. Następnie inny endpoint sprawdza, czy pomyślnie przeszedłeś tę kontrolę.\
Jeśli jednak **przejdziesz kontrolę** i Twoja sesja otrzyma wartość "True" w atrybucie bezpieczeństwa, możesz spróbować **uzyskać dostęp do innych zasobów**, które **zależą od tego samego atrybutu**, ale do których **nie powinieneś mieć uprawnień**. [WriteUp](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a).<sup>[[2]](#references)</sup>

### Funkcja rejestracji

Spróbuj zarejestrować się jako już istniejący użytkownik. Spróbuj także użyć równoważnych znaków (kropek, wielu spacji i Unicode).

### Przejęcie adresów e-mail

Zarejestruj adres e-mail, a następnie przed jego potwierdzeniem zmień adres e-mail. Jeśli nowa wiadomość potwierdzająca zostanie wysłana na pierwszy zarejestrowany adres e-mail, możesz przejąć dowolny adres e-mail. Jeśli natomiast możesz włączyć drugi adres e-mail, potwierdzając pierwszy, również możesz przejąć dowolne konto.

### Dostęp do wewnętrznego servicedesk firm z wykorzystaniem atlassian


{{#ref}}
https://yourcompanyname.atlassian.net/servicedesk/customer/user/login
{{#endref}}

### Metoda TRACE

Deweloperzy mogą zapomnieć o wyłączeniu różnych opcji debugowania w środowisku produkcyjnym. Na przykład metoda HTTP `TRACE` jest przeznaczona do celów diagnostycznych. Jeśli jest włączona, serwer web odpowie na żądania wykorzystujące metodę `TRACE`, odsyłając w odpowiedzi dokładne żądanie, które otrzymał. Takie zachowanie jest zwykle nieszkodliwe, ale czasami prowadzi do ujawnienia informacji, takich jak nazwy wewnętrznych nagłówków uwierzytelniania, które mogą być dołączane do żądań przez reverse proxies.![Obraz dla posta](https://miro.medium.com/max/60/1*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Obraz dla posta](https://miro.medium.com/max/1330/1*wDFRADTOd9Tj63xucenvAA.png)

## References

- [1] [How I was able to take over any user's account with Host Header injection](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2)
- [2] [A less known attack vector: Second order IDOR attacks](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a)

{{#include ../banners/hacktricks-training.md}}
