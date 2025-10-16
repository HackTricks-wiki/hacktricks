# macOS xpc_connection_get_audit_token Atak

{{#include ../../../../../../banners/hacktricks-training.md}}

**Po więcej informacji sprawdź oryginalny wpis:** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/). Poniżej streszczenie:

## Mach Messages — podstawowe informacje

Jeśli nie wiesz, czym są Mach Messages, zacznij od sprawdzenia tej strony:


{{#ref}}
../../
{{#endref}}

Na razie zapamiętaj, że ([definicja stąd](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):\
Mach messages są wysyłane przez _mach port_, który jest kanałem komunikacji **single receiver, multiple sender** wbudowanym w mach kernel. **Wiele procesów może wysyłać wiadomości** do mach portu, ale w danym momencie **tylko jeden proces może z niego czytać**. Podobnie jak deskryptory plików i gniazda, mach ports są przydzielane i zarządzane przez kernel, a procesy widzą jedynie liczbę całkowitą, której mogą użyć, aby wskazać kernelowi, którego z ich mach ports chcą użyć.

## XPC Connection

Jeśli nie wiesz, jak nawiązywane jest połączenie XPC, sprawdź:


{{#ref}}
../
{{#endref}}

## Podsumowanie podatności

Warto wiedzieć, że **abstrakcja XPC to połączenie one-to-one**, ale opiera się na technologii, która **może mieć wielu nadawców, więc:**

- Mach ports są single receiver, **multiple sender**.
- Audit token połączenia XPC jest skopiowany z **ostatnio otrzymanej wiadomości**.
- Uzyskanie **audit token** połączenia XPC jest krytyczne dla wielu **kontroli bezpieczeństwa**.

Mimo że powyższa sytuacja wygląda groźnie, istnieją scenariusze, w których to nie powoduje problemów ([stąd](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):

- Audit tokens są często wykorzystywane do sprawdzenia autoryzacji decydującego o zaakceptowaniu połączenia. Ponieważ odbywa się to przez wiadomość do service portu, **połączenie jeszcze nie zostało ustanowione**. Kolejne wiadomości na tym porcie będą po prostu traktowane jako dodatkowe żądania połączenia. Zatem jakiekolwiek **sprawdzenia przed zaakceptowaniem połączenia nie są podatne** (to także oznacza, że wewnątrz `-listener:shouldAcceptNewConnection:` audit token jest bezpieczny). W związku z tym **szukamy połączeń XPC, które weryfikują konkretne akcje**.
- Handlery zdarzeń XPC są obsługiwane synchronicznie. Oznacza to, że handler zdarzenia dla jednej wiadomości musi zakończyć wykonanie, zanim wywoła się handler dla następnej, nawet na współbieżnych kolejkach dispatch. Zatem wewnątrz **XPC event handler** audit token nie może zostać nadpisany przez inne normalne (nie-reply!) wiadomości.

Dwa różne sposoby, w które to może być wykorzystane:

1. Variant1:
- **Exploit** **connects** to service **A** and service **B**
- Service **B** can call a **privileged functionality** in service A that the user cannot
- Service **A** calls **`xpc_connection_get_audit_token`** while _**not**_ inside the **event handler** for a connection in a **`dispatch_async`**.
- So a **different** message could **overwrite the Audit Token** because it's being dispatched asynchronously outside of the event handler.
- The exploit passes to **service B the SEND right to service A**.
- So svc **B** will be actually **sending** the **messages** to service **A**.
- The **exploit** tries to **call** the **privileged action.** In a RC svc **A** **checks** the authorization of this **action** while **svc B overwrote the Audit token** (giving the exploit access to call the privileged action).
2. Variant 2:
- Service **B** can call a **privileged functionality** in service A that the user cannot
- Exploit connects with **service A** which **sends** the exploit a **message expecting a response** in a specific **replay** **port**.
- Exploit sends **service** B a message passing **that reply port**.
- When service **B** replies, it s**ends the message to service A**, **while** the **exploit** sends a different **message to service A** trying to **reach a privileged functionality** and expecting that the reply from service B will overwrite the Audit token in the perfect moment (Race Condition).

## Variant 1: calling xpc_connection_get_audit_token outside of an event handler <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

Scenariusz:

- Dwa mach services **`A`** i **`B`**, do których obieca możemy się podłączyć (na podstawie profilu sandbox i sprawdzeń autoryzacji przed zaakceptowaniem połączenia).
- _**A**_ musi mieć sprawdzenie autoryzacji dla konkretnej akcji, którą **`B`** może przekazać (ale nasza aplikacja nie).
- Na przykład, jeśli B ma pewne **entitlements** lub działa jako **root**, może poprosić A o wykonanie uprzywilejowanej akcji.
- Dla tego sprawdzenia autoryzacji, **`A`** pozyskuje audit token asynchronicznie, na przykład wywołując `xpc_connection_get_audit_token` z poziomu **`dispatch_async`**.

> [!CAUTION]
> W takim przypadku atakujący może wywołać **Race Condition**, tworząc **exploit**, który **prosi A o wykonanie akcji** wielokrotnie, jednocześnie zmuszając **B** do wysyłania wiadomości do `A`. Gdy RC powiedzie się, **audit token** należący do **B** zostanie skopiowany do pamięci **w trakcie** obsługi żądania naszego **exploita** przez A, dając mu dostęp do uprzywilejowanej akcji, do której dostęp miało tylko B.

To miało miejsce z **`A`** jako `smd` i **`B`** jako `diagnosticd`. Funkcja [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) z smb może być użyta do zainstalowania nowego uprzywilejowanego helpera (jako **root**). Jeśli proces działający jako root kontaktuje `smd`, nie będą wykonywane żadne dodatkowe sprawdzenia.

Dlatego service **B** to **`diagnosticd`**, ponieważ działa jako **root** i może być użyte do monitorowania procesu — po rozpoczęciu monitorowania będzie on wysyłać wiele wiadomości na sekundę.

Aby przeprowadzić atak:

1. Nawiąż **połączenie** z service o nazwie `smd` używając standardowego protokołu XPC.
2. Utwórz drugorzędne **połączenie** z `diagnosticd`. W przeciwieństwie do normalnej procedury, zamiast tworzyć i wysyłać dwa nowe mach ports, prawa wysyłki klienta są zastępowane duplikatem **send right** powiązanego z połączeniem `smd`.
3. W rezultacie wiadomości XPC mogą być wysyłane do `diagnosticd`, ale odpowiedzi z `diagnosticd` są przekierowywane do `smd`. Dla `smd` wygląda to tak, jakby wiadomości zarówno od użytkownika, jak i od `diagnosticd` pochodziły z tego samego połączenia.

![Ilustracja procesu exploitacji](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)

4. Następnie instruuje się `diagnosticd`, aby rozpoczął monitorowanie wybranego procesu (potencjalnie własnego procesu użytkownika). Równocześnie wysyłana jest zalewowa ilość rutynowych wiadomości 1004 do `smd`. Celem jest zainstalowanie narzędzia z podwyższonymi uprawnieniami.
5. To powoduje race condition w funkcji `handle_bless`. Czas jest krytyczny: wywołanie `xpc_connection_get_pid` musi zwrócić PID procesu użytkownika (ponieważ uprzywilejowane narzędzie znajduje się w bundle aplikacji użytkownika). Jednak `xpc_connection_get_audit_token`, konkretnie w podprogramie `connection_is_authorized`, musi odwoływać się do audit token należącego do `diagnosticd`.

## Variant 2: reply forwarding

W środowisku XPC, chociaż handlery zdarzeń nie wykonują się współbieżnie, przetwarzanie wiadomości reply ma specyficzne zachowanie. Konkretnie, istnieją dwa odrębne sposoby wysyłania wiadomości oczekujących na odpowiedź:

1. **`xpc_connection_send_message_with_reply`**: Tutaj wiadomość XPC jest odbierana i przetwarzana na wskazanej kolejce.
2. **`xpc_connection_send_message_with_reply_sync`**: Natomiast w tej metodzie wiadomość XPC jest odbierana i przetwarzana na aktualnej kolejce dispatch.

To rozróżnienie jest kluczowe, ponieważ pozwala na możliwość, że **pakiety reply są parsowane współbieżnie z wykonywaniem handlera zdarzenia XPC**. Warto zauważyć, że chociaż `_xpc_connection_set_creds` implementuje blokowanie chroniące przed częściowym nadpisaniem audit token, nie rozszerza tej ochrony na cały obiekt połączenia. W konsekwencji powstaje luka, w której audit token może zostać zastąpiony w przedziale czasu pomiędzy parsowaniem pakietu a wykonaniem jego handlera zdarzenia.

Aby wykorzystać tę lukę, wymagane jest następujące ustawienie:

- Dwa mach services, oznaczone jako **`A`** i **`B`**, które oba mogą nawiązać połączenie.
- Service **`A`** powinien zawierać sprawdzenie autoryzacji dla konkretnej akcji, którą tylko **`B`** może wykonać (aplikacja użytkownika nie).
- Service **`A`** powinien wysłać wiadomość oczekującą na reply.
- Użytkownik może wysłać wiadomość do **`B`**, na którą B odpowie.

Proces eksploatacji obejmuje kroki:

1. Czekaj, aż service **`A`** wyśle wiadomość oczekującą na reply.
2. Zamiast odpowiadać bezpośrednio **`A`**, port reply zostaje przechwycony i użyty do wysłania wiadomości do service **`B`**.
3. Następnie wysyłana jest wiadomość dotycząca zabronionej akcji, z oczekiwaniem, że zostanie przetworzona współbieżnie z reply od **`B`**.

Poniżej wizualna reprezentacja opisanego scenariusza ataku:

!\[https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png]\(../../../../../../images/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../images/image (33).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Problemy z odkrywaniem

- **Trudności w odnalezieniu wystąpień**: Wyszukiwanie użyć `xpc_connection_get_audit_token` było trudne, zarówno statycznie, jak i dynamicznie.
- **Metodologia**: Użyto Frida do hookowania funkcji `xpc_connection_get_audit_token`, filtrując wywołania niezależne od event handlerów. Jednak ta metoda była ograniczona do procesu, w którym zaaplikowano hook, i wymagała aktywnego użycia.
- **Narzędzia analityczne**: Narzędzia takie jak IDA/Ghidra były używane do badania osiągalnych mach services, ale proces był czasochłonny, utrudniony wywołaniami z dyld shared cache.
- **Ograniczenia skryptowe**: Próby zautomatyzowania analizy pod kątem wywołań `xpc_connection_get_audit_token` z bloków `dispatch_async` były utrudnione złożonością parsowania bloków i interakcjami z dyld shared cache.

## Poprawka <a href="#the-fix" id="the-fix"></a>

- **Zgłoszone problemy**: Zgłoszono Apple ogólne i szczegółowe problemy znalezione w `smd`.
- **Odpowiedź Apple**: Apple zaadresowało problem w `smd` zastępując `xpc_connection_get_audit_token` funkcją `xpc_dictionary_get_audit_token`.
- **Charakter poprawki**: Funkcja `xpc_dictionary_get_audit_token` jest uważana za bezpieczną, ponieważ pobiera audit token bezpośrednio z mach message związanego z otrzymaną wiadomością XPC. Jednak nie jest częścią publicznego API, podobnie jak `xpc_connection_get_audit_token`.
- **Brak szerszego rozwiązania**: Nie jest jasne, dlaczego Apple nie wdrożyło bardziej ogólnego rozwiązania, takiego jak odrzucanie wiadomości, które nie zgadzają się z zapisanym audit token połączenia. Możliwe, że zmiana audit token w pewnych scenariuszach (np. użycie `setuid`) może być uzasadniona.
- **Aktualny stan**: Luka utrzymuje się w iOS 17 i macOS 14, co utrudnia jej identyfikację i zrozumienie.

## Znajdowanie podatnych ścieżek kodu w praktyce (2024–2025)

Podczas audytu usług XPC pod kątem tej klasy błędów, skup się na autoryzacji wykonywanej poza handlerem wiadomości lub równocześnie z przetwarzaniem reply.

Wskazówki do statycznego triage:
- Szukaj wywołań `xpc_connection_get_audit_token` osiągalnych z bloków umieszczonych za pomocą `dispatch_async`/`dispatch_after` lub innych worker queues, które działają poza handlerem wiadomości.
- Szukaj helperów autoryzacyjnych, które mieszają stan per-connection i per-message (np. pobieranie PID przez `xpc_connection_get_pid`, ale audit token przez `xpc_connection_get_audit_token`).
- W kodzie NSXPC upewnij się, że sprawdzenia są wykonywane w `-listener:shouldAcceptNewConnection:`, lub dla sprawdzeń per-message, że implementacja używa per-message audit token (np. słownika wiadomości przez `xpc_dictionary_get_audit_token` w kodzie niższego poziomu).

Wskazówki do dynamicznego triage:
- Hookuj `xpc_connection_get_audit_token` i oznaczaj wywołania, których stos użytkownika nie zawiera ścieżki dostarczania zdarzeń (np. `_xpc_connection_mach_event`). Przykład hooka Frida:
```javascript
Interceptor.attach(Module.getExportByName(null, 'xpc_connection_get_audit_token'), {
onEnter(args) {
const bt = Thread.backtrace(this.context, Backtracer.ACCURATE)
.map(DebugSymbol.fromAddress).join('\n');
if (!bt.includes('_xpc_connection_mach_event')) {
console.log('[!] xpc_connection_get_audit_token outside handler\n' + bt);
}
}
});
```
Notatki:
- Na macOS instrumentowanie protected/Apple binaries może wymagać wyłączenia SIP lub środowiska deweloperskiego; preferuj testowanie własnych builds lub userland services.
- Dla reply-forwarding races (Variant 2) monitoruj jednoczesne parsowanie reply packets, fuzzując timingi `xpc_connection_send_message_with_reply` względem normalnych requestów i sprawdzając, czy efektywny audit token używany podczas autoryzacji może być zmanipulowany.

## Primitwy eksploatacji, których prawdopodobnie będziesz potrzebować

- Multi-sender setup (Variant 1): utwórz połączenia do A i B; zdubluj send right portu klienta A i użyj go jako portu klienta B, tak aby odpowiedzi B były dostarczane do A.
```c
// Duplicate a SEND right you already hold
mach_port_t dup;
mach_port_insert_right(mach_task_self(), a_client, a_client, MACH_MSG_TYPE_MAKE_SEND);
dup = a_client; // use `dup` when crafting B’s connect packet instead of a fresh client port
```
- Reply hijack (Variant 2): przechwyć prawo send-once z oczekującego żądania A (reply port), a następnie wyślij spreparowaną wiadomość do B używając tego reply port, tak aby odpowiedź B trafiła do A podczas parsowania twojego uprzywilejowanego żądania.

These require low-level mach message crafting for the XPC bootstrap and message formats; review the mach/XPC primer pages in this section for the exact packet layouts and flags.

## Przydatne narzędzia

- XPC sniffing/dynamic inspection: gxpc (open-source XPC sniffer) może pomóc w enumeracji połączeń i obserwacji ruchu, aby zweryfikować konfiguracje z wieloma nadawcami i synchronizację. Example: `gxpc -p <PID> --whitelist <service-name>`.
- Classic dyld interposing for libxpc: interpose on `xpc_connection_send_message*` and `xpc_connection_get_audit_token` aby logować miejsca wywołań i stosy podczas testów black-box.



## Źródła

- Sector 7 – Don’t Talk All at Once! Podnoszenie uprawnień na macOS przez Audit Token Spoofing: <https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/>
- Apple – O zawartości zabezpieczeń macOS Ventura 13.4 (CVE‑2023‑32405): <https://support.apple.com/en-us/106333>


{{#include ../../../../../../banners/hacktricks-training.md}}
