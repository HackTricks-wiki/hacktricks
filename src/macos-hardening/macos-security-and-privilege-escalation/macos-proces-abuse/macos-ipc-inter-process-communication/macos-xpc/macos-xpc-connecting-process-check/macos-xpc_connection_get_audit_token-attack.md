# macOS xpc_connection_get_audit_token Attack

{{#include ../../../../../../banners/hacktricks-training.md}}

**Aby uzyskać więcej informacji, sprawdź oryginalny post:** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/). To jest podsumowanie:

## Mach Messages Basic Info

Jeśli nie wiesz, czym są Mach Messages, zacznij od sprawdzenia tej strony:

{{#ref}}
../../
{{#endref}}

Na razie pamiętaj, że ([definicja stąd](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):\
Mach messages są wysyłane przez _mach port_, który jest **kanałem komunikacyjnym z jednym odbiorcą i wieloma nadawcami** wbudowanym w jądro mach. **Wiele procesów może wysyłać wiadomości** do mach portu, ale w danym momencie **tylko jeden proces może z niego odczytać**. Podobnie jak deskryptory plików i gniazda, mach porty są przydzielane i zarządzane przez jądro, a procesy widzą tylko liczbę całkowitą, którą mogą użyć, aby wskazać jądru, który z ich mach portów chcą użyć.

## XPC Connection

Jeśli nie wiesz, jak nawiązywane jest połączenie XPC, sprawdź:

{{#ref}}
../
{{#endref}}

## Vuln Summary

Co jest interesujące do wiedzenia, to że **abstrakcja XPC to połączenie jeden do jednego**, ale opiera się na technologii, która **może mieć wielu nadawców, więc:**

- Mach ports są jednym odbiorcą, **wieloma nadawcami**.
- Token audytu połączenia XPC to token audytu **skopiowany z najnowszej odebranej wiadomości**.
- Uzyskanie **tokenu audytu** połączenia XPC jest kluczowe dla wielu **sprawdzania bezpieczeństwa**.

Chociaż poprzednia sytuacja brzmi obiecująco, istnieją pewne scenariusze, w których nie spowoduje to problemów ([stąd](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):

- Tokeny audytu są często używane do sprawdzenia autoryzacji, aby zdecydować, czy zaakceptować połączenie. Ponieważ dzieje się to za pomocą wiadomości do portu usługi, **połączenie nie zostało jeszcze nawiązane**. Więcej wiadomości na tym porcie będzie po prostu traktowane jako dodatkowe żądania połączenia. Tak więc wszelkie **sprawdzenia przed zaakceptowaniem połączenia nie są podatne** (to również oznacza, że w `-listener:shouldAcceptNewConnection:` token audytu jest bezpieczny). Dlatego **szukamy połączeń XPC, które weryfikują konkretne działania**.
- Obsługa zdarzeń XPC jest realizowana synchronicznie. Oznacza to, że obsługa zdarzenia dla jednej wiadomości musi być zakończona przed wywołaniem jej dla następnej, nawet w równoległych kolejkach dyspozycyjnych. Tak więc wewnątrz **obsługi zdarzeń XPC token audytu nie może być nadpisany** przez inne normalne (nie-odpowiedzi!) wiadomości.

Dwie różne metody, które mogą być wykorzystywane:

1. Variant1:
- **Eksploit** **łączy** się z usługą **A** i usługą **B**
- Usługa **B** może wywołać **funkcjonalność z uprawnieniami** w usłudze A, której użytkownik nie może
- Usługa **A** wywołuje **`xpc_connection_get_audit_token`** podczas _**nie**_ będąc w **obsłudze zdarzeń** dla połączenia w **`dispatch_async`**.
- Tak więc **inna** wiadomość mogłaby **nadpisać token audytu**, ponieważ jest wysyłana asynchronicznie poza obsługą zdarzeń.
- Eksploit przekazuje **usłudze B prawo do WYSYŁANIA do usługi A**.
- Tak więc svc **B** będzie faktycznie **wysyłać** **wiadomości** do usługi **A**.
- **Eksploit** próbuje **wywołać** **uprzywilejowane działanie.** W RC svc **A** **sprawdza** autoryzację tego **działania**, podczas gdy **svc B nadpisał token audytu** (dając exploitowi dostęp do wywołania uprzywilejowanego działania).
2. Variant 2:
- Usługa **B** może wywołać **funkcjonalność z uprawnieniami** w usłudze A, której użytkownik nie może
- Eksploit łączy się z **usługą A**, która **wysyła** exploitowi **wiadomość oczekującą na odpowiedź** w określonym **porcie odpowiedzi**.
- Eksploit wysyła **usłudze** B wiadomość przekazując **ten port odpowiedzi**.
- Gdy usługa **B odpowiada**, **wysyła wiadomość do usługi A**, **podczas gdy** **eksploit** wysyła inną **wiadomość do usługi A**, próbując **osiągnąć funkcjonalność z uprawnieniami** i oczekując, że odpowiedź od usługi B nadpisze token audytu w idealnym momencie (Race Condition).

## Variant 1: calling xpc_connection_get_audit_token outside of an event handler <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

Scenariusz:

- Dwie usługi mach **`A`** i **`B`**, z którymi możemy się połączyć (na podstawie profilu sandbox i kontroli autoryzacji przed zaakceptowaniem połączenia).
- _**A**_ musi mieć **sprawdzenie autoryzacji** dla konkretnego działania, które **`B`** może przekazać (ale nasza aplikacja nie może).
- Na przykład, jeśli B ma jakieś **uprawnienia** lub działa jako **root**, może to pozwolić mu poprosić A o wykonanie uprzywilejowanego działania.
- Dla tego sprawdzenia autoryzacji, **`A`** uzyskuje token audytu asynchronicznie, na przykład wywołując `xpc_connection_get_audit_token` z **`dispatch_async`**.

> [!CAUTION]
> W tym przypadku atakujący mógłby wywołać **Race Condition**, tworząc **eksploit**, który **prosi A o wykonanie akcji** kilka razy, podczas gdy **B wysyła wiadomości do `A`**. Gdy RC jest **udane**, **token audytu** **B** zostanie skopiowany w pamięci **podczas** gdy żądanie naszego **eksploit** jest **obsługiwane** przez A, dając mu **dostęp do uprzywilejowanej akcji, którą tylko B mógłby zażądać**.

To zdarzyło się z **`A`** jako `smd` i **`B`** jako `diagnosticd`. Funkcja [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) z smb może być używana do instalacji nowego uprzywilejowanego narzędzia pomocniczego (jako **root**). Jeśli **proces działający jako root skontaktuje się** z **smd**, żadne inne kontrole nie będą przeprowadzane.

Dlatego usługa **B** to **`diagnosticd`**, ponieważ działa jako **root** i może być używana do **monitorowania** procesu, więc po rozpoczęciu monitorowania, będzie **wysyłać wiele wiadomości na sekundę.**

Aby przeprowadzić atak:

1. Nawiąż **połączenie** z usługą o nazwie `smd` za pomocą standardowego protokołu XPC.
2. Utwórz drugie **połączenie** z `diagnosticd`. W przeciwieństwie do normalnej procedury, zamiast tworzyć i wysyłać dwa nowe mach porty, prawo do wysyłania portu klienta jest zastępowane duplikatem **prawa do wysyłania** związanego z połączeniem `smd`.
3. W rezultacie wiadomości XPC mogą być wysyłane do `diagnosticd`, ale odpowiedzi z `diagnosticd` są przekierowywane do `smd`. Dla `smd` wydaje się, że wiadomości zarówno od użytkownika, jak i `diagnosticd` pochodzą z tego samego połączenia.

![Image depicting the exploit process](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)

4. Następny krok polega na poleceniu `diagnosticd`, aby rozpoczął monitorowanie wybranego procesu (potencjalnie własnego użytkownika). Równocześnie wysyłany jest potok rutynowych wiadomości 1004 do `smd`. Celem jest zainstalowanie narzędzia z podwyższonymi uprawnieniami.
5. Ta akcja wywołuje warunek wyścigu w funkcji `handle_bless`. Czas jest kluczowy: wywołanie funkcji `xpc_connection_get_pid` musi zwrócić PID procesu użytkownika (ponieważ uprzywilejowane narzędzie znajduje się w pakiecie aplikacji użytkownika). Jednak funkcja `xpc_connection_get_audit_token`, szczególnie w podprogramie `connection_is_authorized`, musi odnosić się do tokenu audytu należącego do `diagnosticd`.

## Variant 2: reply forwarding

W środowisku XPC (Cross-Process Communication), chociaż obsługa zdarzeń nie wykonuje się równolegle, obsługa wiadomości odpowiedzi ma unikalne zachowanie. Konkretnie, istnieją dwa różne sposoby wysyłania wiadomości, które oczekują odpowiedzi:

1. **`xpc_connection_send_message_with_reply`**: Tutaj wiadomość XPC jest odbierana i przetwarzana w wyznaczonej kolejce.
2. **`xpc_connection_send_message_with_reply_sync`**: Z kolei w tej metodzie wiadomość XPC jest odbierana i przetwarzana w bieżącej kolejce dyspozycyjnej.

To rozróżnienie jest kluczowe, ponieważ pozwala na możliwość **parsing odpowiedzi równolegle z wykonaniem obsługi zdarzeń XPC**. Należy zauważyć, że podczas gdy `_xpc_connection_set_creds` implementuje blokady, aby chronić przed częściowym nadpisaniem tokenu audytu, nie rozszerza tej ochrony na cały obiekt połączenia. W rezultacie tworzy to lukę, w której token audytu może być zastąpiony w czasie między analizą pakietu a wykonaniem jego obsługi zdarzeń.

Aby wykorzystać tę lukę, wymagane jest następujące ustawienie:

- Dwie usługi mach, określane jako **`A`** i **`B`**, które mogą nawiązać połączenie.
- Usługa **`A`** powinna zawierać sprawdzenie autoryzacji dla konkretnego działania, które tylko **`B`** może wykonać (aplikacja użytkownika nie może).
- Usługa **`A`** powinna wysłać wiadomość, która oczekuje odpowiedzi.
- Użytkownik może wysłać wiadomość do **`B`**, na którą odpowie.

Proces eksploatacji obejmuje następujące kroki:

1. Czekaj na wysłanie wiadomości przez usługę **`A`**, która oczekuje odpowiedzi.
2. Zamiast odpowiadać bezpośrednio na **`A`**, port odpowiedzi jest przejmowany i używany do wysłania wiadomości do usługi **`B`**.
3. Następnie wysyłana jest wiadomość dotycząca zabronionej akcji, z oczekiwaniem, że zostanie przetworzona równolegle z odpowiedzią od **`B`**.

Poniżej znajduje się wizualna reprezentacja opisanego scenariusza ataku:

!\[https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png]\(../../../../../../images/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../images/image (33).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Discovery Problems

- **Trudności w lokalizowaniu instancji**: Wyszukiwanie instancji użycia `xpc_connection_get_audit_token` było trudne, zarówno statycznie, jak i dynamicznie.
- **Metodologia**: Frida została użyta do podłączenia funkcji `xpc_connection_get_audit_token`, filtrując wywołania, które nie pochodziły z obsługi zdarzeń. Jednak ta metoda była ograniczona do podłączonego procesu i wymagała aktywnego użycia.
- **Narzędzia analityczne**: Narzędzia takie jak IDA/Ghidra były używane do badania dostępnych usług mach, ale proces był czasochłonny, skomplikowany przez wywołania związane z pamięcią podręczną dyld.
- **Ograniczenia skryptowe**: Próby skryptowania analizy wywołań do `xpc_connection_get_audit_token` z bloków `dispatch_async` były utrudnione przez złożoności w analizie bloków i interakcjach z pamięcią podręczną dyld.

## The fix <a href="#the-fix" id="the-fix"></a>

- **Zgłoszone problemy**: Zgłoszenie zostało przesłane do Apple, szczegółowo opisujące ogólne i specyficzne problemy znalezione w `smd`.
- **Odpowiedź Apple**: Apple rozwiązało problem w `smd`, zastępując `xpc_connection_get_audit_token` funkcją `xpc_dictionary_get_audit_token`.
- **Charakter naprawy**: Funkcja `xpc_dictionary_get_audit_token` jest uważana za bezpieczną, ponieważ pobiera token audytu bezpośrednio z wiadomości mach związanej z odebraną wiadomością XPC. Jednak nie jest częścią publicznego API, podobnie jak `xpc_connection_get_audit_token`.
- **Brak szerszej naprawy**: Nie jest jasne, dlaczego Apple nie wdrożyło bardziej kompleksowej naprawy, takiej jak odrzucenie wiadomości, które nie są zgodne z zapisanym tokenem audytu połączenia. Możliwość legalnych zmian tokenu audytu w niektórych scenariuszach (np. użycie `setuid`) może być czynnikiem.
- **Aktualny status**: Problem nadal występuje w iOS 17 i macOS 14, stanowiąc wyzwanie dla tych, którzy starają się go zidentyfikować i zrozumieć.

{{#include ../../../../../../banners/hacktricks-training.md}}
