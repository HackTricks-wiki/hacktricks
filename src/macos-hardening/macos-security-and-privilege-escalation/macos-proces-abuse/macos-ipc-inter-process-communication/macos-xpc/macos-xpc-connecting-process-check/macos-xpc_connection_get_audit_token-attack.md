# macOS xpc_connection_get_audit_token Attack

{{#include ../../../../../../banners/hacktricks-training.md}}

**Więcej informacji znajdziesz w oryginalnym poście:** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/). Poniżej znajduje się podsumowanie:<sup>[[1]](#references)</sup>

## Podstawowe informacje o Mach Messages

Jeśli nie wiesz, czym są Mach Messages, zacznij od tej strony:


{{#ref}}
../../
{{#endref}}

Na razie zapamiętaj, że ([definicja stąd](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):<sup>[[1]](#references)</sup>\
Mach messages są wysyłane przez _mach port_, czyli kanał komunikacyjny **single receiver, multiple sender**, wbudowany w jądro mach. **Wiele procesów może wysyłać wiadomości** do mach portu, ale w dowolnym momencie **tylko jeden proces może je z niego odczytywać**. Podobnie jak deskryptory plików i sockety, mach ports są przydzielane i zarządzane przez jądro, a procesy widzą jedynie liczbę całkowitą, której mogą użyć do wskazania jądru, z którego ze swoich mach ports chcą skorzystać.

## XPC Connection

Jeśli nie wiesz, jak ustanawiane jest XPC connection, sprawdź:


{{#ref}}
../
{{#endref}}

## Podsumowanie podatności

Warto wiedzieć, że **abstrakcja XPC to połączenie one-to-one**, ale opiera się na technologii, która **może obsługiwać wielu nadawców, dlatego:**

- Mach ports mają jednego odbiorcę i **wielu nadawców**.
- Audit token XPC connection to audit token **skopiowany z ostatnio odebranej wiadomości**.
- Uzyskanie **audit token** XPC connection ma kluczowe znaczenie dla wielu **security checks**.<sup>[[1]](#references)</sup>

Chociaż powyższa sytuacja brzmi obiecująco, istnieją scenariusze, w których nie spowoduje ona problemów ([stąd](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):<sup>[[1]](#references)</sup>

- Audit tokens są często używane podczas authorization check, aby zdecydować, czy zaakceptować connection. Dzieje się to za pomocą wiadomości wysyłanej do service port, więc **connection nie zostało jeszcze ustanowione**. Kolejne wiadomości na tym porcie będą po prostu obsługiwane jako dodatkowe żądania connection. Oznacza to, że **checks wykonywane przed zaakceptowaniem connection nie są podatne** (oznacza to również, że w ramach `-listener:shouldAcceptNewConnection:` audit token jest bezpieczny). Dlatego **szukamy XPC connections, które weryfikują konkretne actions**.
- XPC event handlers są obsługiwane synchronicznie. Oznacza to, że event handler dla jednej wiadomości musi zostać zakończony przed wywołaniem go dla następnej, nawet w przypadku współbieżnych dispatch queues. Dlatego wewnątrz **XPC event handler audit token nie może zostać nadpisany** przez inne zwykłe wiadomości (inne niż reply!).<sup>[[1]](#references)</sup>

Istnieją dwa sposoby, w jakie może to być exploitable:

1. Variant1:
- **Exploit** **łączy się** z service **A** i service **B**
- Service **B** może wywołać w service A **privileged functionality**, której użytkownik nie może wywołać
- Service **A** wywołuje **`xpc_connection_get_audit_token`**, gdy _**nie**_ znajduje się wewnątrz **event handler** dla connection w **`dispatch_async`**.
- W związku z tym **inna** wiadomość może **nadpisać Audit Token**, ponieważ jest dispatchowana asynchronicznie poza event handler.
- Exploit przekazuje **service B** prawo **SEND** do service A.
- W rezultacie svc **B** będzie faktycznie **wysyłać** **messages** do service **A**.
- **Exploit** próbuje wywołać **privileged action**. W RC svc **A** **sprawdza** authorization tej **action**, gdy **svc B nadpisał Audit token** (zapewniając exploitowi dostęp do wywołania privileged action).
2. Variant 2:
- Service **B** może wywołać w service A **privileged functionality**, której użytkownik nie może wywołać
- Exploit łączy się z **service A**, który **wysyła** exploitowi **message oczekującą odpowiedzi** na określonym **replay** **port**.
- Exploit wysyła do **service B** message przekazującą **ten reply port**.
- Gdy service **B** odpowiada, **wysyła message do service A**, **podczas gdy** **exploit** wysyła inną **message do service A**, próbując **uzyskać dostęp do privileged functionality** i oczekując, że reply od service B nadpisze Audit token w odpowiednim momencie (Race Condition).

## Variant 1: wywoływanie xpc_connection_get_audit_token poza event handler <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

Scenario:

- Dwa mach services **`A`** i **`B`**, z którymi możemy nawiązać connection (na podstawie sandbox profile oraz authorization checks wykonywanych przed zaakceptowaniem connection).
- _**A**_ musi mieć **authorization check** dla określonej action, którą **B** może przejść (ale nasza aplikacja nie).
- Przykładowo, jeśli B ma określone **entitlements** lub działa jako **root**, może pozwolić mu to poprosić A o wykonanie privileged action.
- Na potrzeby tego authorization check **A** pobiera audit token asynchronicznie, na przykład wywołując `xpc_connection_get_audit_token` z poziomu `dispatch_async`.

> [!CAUTION]
> W tym przypadku attacker może wywołać **Race Condition**, tworząc **exploit**, który wielokrotnie prosi **A o wykonanie action**, jednocześnie powodując, że **B wysyła messages do `A`**. Gdy **RC** zakończy się powodzeniem, **audit token** należący do **B** zostanie skopiowany do pamięci **w trakcie obsługi żądania naszego exploitu** przez A, zapewniając mu **dostęp do privileged action**, o którą może poprosić tylko B.

Stało się tak, gdy **`A`** było `smd`, a **`B`** było `diagnosticd`. Funkcja [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) z smb może zostać użyta do zainstalowania nowego privileged helper tool (jako **root**). Jeśli **process działający jako root skontaktuje się z** **smd**, nie zostaną wykonane żadne dodatkowe checks.

Dlatego service **B** to **`diagnosticd`**, ponieważ działa jako **root** i może być używany do **monitorowania** procesu, więc po rozpoczęciu monitorowania będzie **wysyłać wiele messages na sekundę.**

Aby wykonać attack:

1. Zainicjuj **connection** z service o nazwie `smd`, używając standardowego protokołu XPC.
2. Utwórz dodatkowe **connection** z `diagnosticd`. W przeciwieństwie do standardowej procedury, zamiast tworzyć i wysyłać dwa nowe mach ports, prawo send klienta zostaje zastąpione duplikatem **send right** powiązanego z connection `smd`.
3. W rezultacie messages XPC mogą być dispatchowane do `diagnosticd`, ale odpowiedzi z `diagnosticd` są przekierowywane do `smd`. Dla `smd` wygląda to tak, jakby messages zarówno od użytkownika, jak i od `diagnosticd` pochodziły z tego samego connection.

![Obraz przedstawiający proces exploitu](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)

4. Następny krok polega na nakazaniu `diagnosticd` rozpoczęcia monitorowania wybranego procesu (potencjalnie własnego procesu użytkownika). Jednocześnie do `smd` wysyłany jest flood standardowych messages 1004. Celem jest zainstalowanie toola z podwyższonymi privileges.
5. Ta action wywołuje race condition wewnątrz funkcji `handle_bless`. Kluczowe jest odpowiednie wyczucie czasu: wywołanie funkcji `xpc_connection_get_pid` musi zwrócić PID procesu użytkownika (ponieważ privileged tool znajduje się w bundle aplikacji użytkownika). Jednak funkcja `xpc_connection_get_audit_token`, konkretnie w podprocedurze `connection_is_authorized`, musi odwoływać się do audit token należącego do `diagnosticd`.<sup>[[1]](#references)</sup>

## Variant 2: reply forwarding

W środowisku XPC (Cross-Process Communication), mimo że event handlers nie są wykonywane współbieżnie, obsługa reply messages ma unikalne zachowanie. W szczególności istnieją dwie różne metody wysyłania messages oczekujących na reply:

1. **`xpc_connection_send_message_with_reply`**: W tym przypadku XPC message jest odbierana i przetwarzana na wyznaczonej queue.
2. **`xpc_connection_send_message_with_reply_sync`**: W tej metodzie XPC message jest natomiast odbierana i przetwarzana na bieżącej dispatch queue.

To rozróżnienie ma kluczowe znaczenie, ponieważ umożliwia **równoczesne parsowanie reply packets i wykonywanie XPC event handler**. Warto zauważyć, że chociaż `_xpc_connection_set_creds` implementuje locking chroniący przed częściowym nadpisaniem audit token, ochrona ta nie obejmuje całego connection object. W efekcie powstaje podatność, w której audit token może zostać zastąpiony w czasie pomiędzy parsowaniem packetu a wykonaniem jego event handler.

Aby wykorzystać tę podatność, wymagane jest następujące setup:

- Dwa mach services, określane jako **`A`** i **`B`**, z którymi można nawiązać connection.
- Service **`A`** powinien zawierać authorization check dla określonej action, którą może wykonać wyłącznie **`B`** (aplikacja użytkownika nie może).
- Service **`A`** powinien wysłać message oczekującą na reply.
- Użytkownik może wysłać message do **`B`**, na którą service odpowie.

Proces exploitu obejmuje następujące kroki:

1. Zaczekaj, aż service **`A`** wyśle message oczekującą na reply.
2. Zamiast odpowiadać bezpośrednio do **`A`**, przejmij reply port i użyj go do wysłania message do service **`B`**.
3. Następnie dispatchowana jest message dotycząca zabronionej action, z założeniem, że zostanie przetworzona współbieżnie z reply od **`B`**.<sup>[[1]](#references)</sup>

Poniżej przedstawiono wizualizację opisanego attack:

!\[https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png]\(../../../../../../images/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../images/image (33).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Problemy z wykrywaniem

- **Trudności w lokalizowaniu instances**: Wyszukiwanie instances użycia `xpc_connection_get_audit_token` było trudne zarówno statycznie, jak i dynamicznie.
- **Methodology**: Frida została użyta do hookowania funkcji `xpc_connection_get_audit_token` i filtrowania wywołań, które nie pochodziły z event handlers. Metoda ta była jednak ograniczona do hookowanego procesu i wymagała aktywnego użycia.
- **Narzędzia analityczne**: Narzędzia takie jak IDA/Ghidra były używane do badania osiągalnych mach services, ale proces był czasochłonny i komplikowały go wywołania obejmujące dyld shared cache.
- **Ograniczenia skryptów**: Próby oskryptowania analizy wywołań `xpc_connection_get_audit_token` z bloków `dispatch_async` były utrudnione przez złożoność parsowania blocks oraz interakcje z dyld shared cache.<sup>[[1]](#references)</sup>

## The fix <a href="#the-fix" id="the-fix"></a>

- **Zgłoszone problemy**: Do Apple przesłano report szczegółowo opisujący ogólne i konkretne problemy znalezione w `smd`.
- **Odpowiedź Apple**: Apple naprawiło problem w `smd`, zastępując `xpc_connection_get_audit_token` przez `xpc_dictionary_get_audit_token`.<sup>[[1]](#references)[[2]](#references)</sup>
- **Charakterystyka fix**: Funkcja `xpc_dictionary_get_audit_token` jest uznawana za bezpieczną, ponieważ pobiera audit token bezpośrednio z mach message powiązanej z odebraną XPC message. Nie jest jednak częścią public API, podobnie jak `xpc_connection_get_audit_token`.
- **Brak szerszego fix**: Nie jest jasne, dlaczego Apple nie wdrożyło bardziej kompleksowego fix, takiego jak odrzucanie messages, które nie odpowiadają zapisanemu audit token connection. Możliwym czynnikiem mogą być uzasadnione zmiany audit token w określonych scenariuszach (np. użycie `setuid`).
- **Obecny status**: Problem nadal występuje w iOS 17 i macOS 14, co stanowi wyzwanie dla osób próbujących go zidentyfikować i zrozumieć.<sup>[[1]](#references)</sup>

## Znajdowanie podatnych code paths w praktyce (2024–2025)

Podczas audytowania XPC services pod kątem tej klasy błędów skup się na authorization wykonywanym poza message event handler albo współbieżnie z obsługą replies.

Wskazówki dotyczące static triage:
- Szukaj wywołań `xpc_connection_get_audit_token`, do których można dotrzeć z blocks umieszczanych w kolejce przez `dispatch_async`/`dispatch_after` lub inne worker queues działające poza message handler.
- Szukaj authorization helpers, które łączą stan per-connection i per-message (np. pobierają PID przez `xpc_connection_get_pid`, ale audit token przez `xpc_connection_get_audit_token`).
- W kodzie NSXPC sprawdź, czy checks są wykonywane w `-listener:shouldAcceptNewConnection:` lub, w przypadku checks per-message, czy implementacja używa audit token per-message (np. dictionary message przez `xpc_dictionary_get_audit_token` w kodzie niższego poziomu).

Wskazówki dotyczące dynamic triage:
- Hookuj `xpc_connection_get_audit_token` i oznaczaj wywołania, których user stack nie zawiera ścieżki dostarczania event (np. `_xpc_connection_mach_event`). Przykładowy hook Frida:
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
Uwagi:
- W systemie macOS instrumentowanie chronionych/binarnych plików Apple może wymagać wyłączonego SIP lub środowiska deweloperskiego; preferuj testowanie własnych buildów lub usług userland.
- W przypadku race conditions związanych z przekazywaniem odpowiedzi (Variant 2) monitoruj równoczesne parsowanie pakietów odpowiedzi, fuzzując czasy wywołań `xpc_connection_send_message_with_reply` względem normalnych żądań i sprawdzając, czy token audytu używany podczas autoryzacji może zostać zmanipulowany.

## Primitives eksploatacji, których prawdopodobnie będziesz potrzebować

- Konfiguracja wielu nadawców (Variant 1): utwórz połączenia z A i B; zduplikuj send right portu klienta A i użyj go jako portu klienta B, aby odpowiedzi B były dostarczane do A.
```c
// Duplicate a SEND right you already hold
mach_port_t dup;
mach_port_insert_right(mach_task_self(), a_client, a_client, MACH_MSG_TYPE_MAKE_SEND);
dup = a_client; // use `dup` when crafting B’s connect packet instead of a fresh client port
```
- Reply hijack (Variant 2): przechwyć send-once right z oczekującego requestu A (reply port), a następnie wyślij spreparowaną message do B za pomocą tego reply port, aby odpowiedź B trafiła do A, podczas gdy Twój uprzywilejowany request jest parsowany.

Wymaga to niskopoziomowego tworzenia komunikatów mach dla bootstrap XPC i formatów messages; przejrzyj strony wprowadzające do mach/XPC w tej sekcji, aby poznać dokładne układy pakietów i flags.

## Przydatne narzędzia

- Sniffing/dynamic inspection XPC: gxpc (open-source XPC sniffer) może pomóc wyliczyć connections i obserwować traffic w celu walidacji konfiguracji multi-sender oraz timing. Przykład: `gxpc -p <PID> --whitelist <service-name>`.
- Klasyczne dyld interposing dla libxpc: zastosuj interpose na `xpc_connection_send_message*` i `xpc_connection_get_audit_token`, aby logować call sites i stacks podczas black-box testing.



## Referencje

- [1] [Sector 7 – Nie mówcie wszyscy naraz! Podnoszenie uprawnień w macOS przez spoofing Audit Token](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [2] [Apple – Informacje o zawartości zabezpieczeń macOS Ventura 13.4 (CVE‑2023‑32405)](https://support.apple.com/en-us/106333)


{{#include ../../../../../../banners/hacktricks-training.md}}
