# Atak macOS xpc_connection_get_audit_token

{{#include ../../../../../../banners/hacktricks-training.md}}

**Więcej informacji znajdziesz w oryginalnym poście:** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/). To jest podsumowanie:

## Podstawowe informacje o Mach Messages

Jeśli nie wiesz, czym są Mach Messages, zacznij od tej strony:


{{#ref}}
../../
{{#endref}}

Na razie zapamiętaj, że ([definicja z tego miejsca](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):\
Mach messages są wysyłane przez _mach port_, czyli kanał komunikacyjny **single receiver, multiple sender** wbudowany w mach kernel. **Wiele procesów może wysyłać messages** do mach port, ale w dowolnym momencie **tylko jeden proces może z niego odczytywać**. Podobnie jak file descriptors i sockets, mach ports są przydzielane i zarządzane przez kernel, a procesy widzą wyłącznie liczbę całkowitą, której mogą użyć do wskazania kernelowi, którego ze swoich mach ports chcą użyć.

## XPC Connection

Jeśli nie wiesz, jak ustanawiane jest połączenie XPC, sprawdź:


{{#ref}}
../
{{#endref}}

## Podsumowanie podatności

Warto wiedzieć, że **abstrakcja XPC jest połączeniem one-to-one**, ale bazuje na technologii, która **może mieć wielu nadawców, więc:**

- Mach ports mają single receiver, **multiple sender**.
- Audit token połączenia XPC to audit token **skopiowany z ostatnio odebranego message**.
- Uzyskanie **audit token** połączenia XPC ma kluczowe znaczenie dla wielu **security checks**.<sup>[1]</sup>

Chociaż powyższa sytuacja brzmi obiecująco, istnieją scenariusze, w których nie spowoduje ona problemów ([z tego miejsca](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):

- Audit tokens są często używane do authorization check, aby zdecydować, czy zaakceptować połączenie. Ponieważ odbywa się to za pomocą message wysłanego do service port, **połączenie nie zostało jeszcze ustanowione**. Kolejne messages na tym porcie zostaną po prostu obsłużone jako dodatkowe żądania połączenia. Dlatego **checks wykonywane przed zaakceptowaniem połączenia nie są podatne** (oznacza to również, że w ramach `-listener:shouldAcceptNewConnection:` audit token jest bezpieczny). Szukamy więc połączeń XPC, które weryfikują konkretne działania.
- XPC event handlers są obsługiwane synchronicznie. Oznacza to, że event handler dla jednego message musi zostać zakończony przed wywołaniem go dla następnego, nawet na współbieżnych dispatch queues. Dlatego wewnątrz **XPC event handler audit token nie może zostać nadpisany** przez inne zwykłe messages (inne niż reply!).<sup>[1]</sup>

Istnieją dwie metody, które mogą być podatne na exploit:

1. Variant1:
- **Exploit** **łączy się** z service **A** i service **B**
- Service **B** może wywołać **privileged functionality** w service A, której użytkownik nie może wywołać
- Service **A** wywołuje **`xpc_connection_get_audit_token`**, będąc _**poza**_ **event handlerem** połączenia w **`dispatch_async`**.
- W ten sposób **inny** message może **nadpisać Audit Token**, ponieważ jest obsługiwany asynchronicznie poza event handlerem.
- Exploit przekazuje do **service B** prawo **SEND** do service A.
- W ten sposób svc **B** będzie faktycznie **wysyłać** **messages** do service **A**.
- **Exploit** próbuje **wywołać privileged action.** W RC svc **A** **sprawdza** authorization dla tego **action**, gdy **svc B nadpisał Audit token** (zapewniając exploitowi dostęp do wywołania privileged action).
2. Variant 2:
- Service **B** może wywołać **privileged functionality** w service A, której użytkownik nie może wywołać
- Exploit łączy się z **service A**, który **wysyła** exploitowi **message oczekujący odpowiedzi** przez konkretny **reply** **port**.
- Exploit wysyła do **service** B message przekazujący **ten reply port**.
- Gdy service **B** odpowie, **wysyła message do service A**, **podczas gdy** **exploit** wysyła inny **message do service A**, próbując **dotrzeć do privileged functionality** i oczekując, że reply od service B nadpisze Audit token w odpowiednim momencie (Race Condition).

## Variant 1: wywoływanie xpc_connection_get_audit_token poza event handlerem <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

Scenariusz:

- Dwa mach services **`A`** i **`B`**, z którymi możemy się połączyć (na podstawie sandbox profile i authorization checks wykonywanych przed zaakceptowaniem połączenia).
- _**A**_ musi mieć **authorization check** dla konkretnego action, który **B** może przejść (ale nasza aplikacja nie).
- Na przykład, jeśli B ma określone **entitlements** lub działa jako **root**, może zezwolić mu to na żądanie od A wykonania privileged action.
- Na potrzeby tego authorization check **A** pobiera audit token asynchronicznie, na przykład wywołując `xpc_connection_get_audit_token` z poziomu `dispatch_async`.

> [!CAUTION]
> W tym przypadku atakujący może wywołać **Race Condition**, tworząc **exploit**, który wielokrotnie prosi A o wykonanie action, jednocześnie powodując, że **B wysyła messages do `A`**. Gdy RC zakończy się **powodzeniem**, **audit token** procesu **B** zostanie skopiowany do pamięci **w czasie obsługi żądania przez nasz exploit** przez A, zapewniając mu **dostęp do privileged action, o którą może poprosić wyłącznie B**.

Taka sytuacja wystąpiła, gdy **`A`** było `smd`, a **`B`** było `diagnosticd`. Funkcja [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) z smb może zostać użyta do zainstalowania nowego privileged helper tool (jako **root**). Jeśli **proces działający jako root skontaktuje się z** **smd**, nie zostaną wykonane żadne inne checks.

Dlatego service **B** to **`diagnosticd`**, ponieważ działa jako **root** i może służyć do **monitorowania** procesu, więc po rozpoczęciu monitorowania będzie **wysyłać wiele messages na sekundę.**

Aby wykonać atak:

1. Zainicjuj **połączenie** z service o nazwie `smd`, używając standardowego protokołu XPC.
2. Utwórz dodatkowe **połączenie** z `diagnosticd`. W przeciwieństwie do normalnej procedury, zamiast tworzyć i wysyłać dwa nowe mach ports, prawo send client port zostaje zastąpione duplikatem **send right** powiązanego z połączeniem `smd`.
3. W rezultacie messages XPC mogą być wysyłane do `diagnosticd`, ale odpowiedzi z `diagnosticd` są przekierowywane do `smd`. Dla `smd` wygląda to tak, jakby messages zarówno od użytkownika, jak i od `diagnosticd` pochodziły z tego samego połączenia.

![Image depicting the exploit process](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)

4. Następnym krokiem jest polecenie `diagnosticd` rozpoczęcia monitorowania wybranego procesu (potencjalnie własnego procesu użytkownika). Jednocześnie do `smd` wysyłany jest flood standardowych messages 1004. Celem jest zainstalowanie tool z podwyższonymi privileges.
5. Działanie to wywołuje race condition wewnątrz funkcji `handle_bless`. Kluczowe znaczenie ma timing: wywołanie funkcji `xpc_connection_get_pid` musi zwrócić PID procesu użytkownika (ponieważ privileged tool znajduje się w app bundle użytkownika). Jednak funkcja `xpc_connection_get_audit_token`, konkretnie w subroutine `connection_is_authorized`, musi odwoływać się do audit token należącego do `diagnosticd`.<sup>[1]</sup>

## Variant 2: reply forwarding

W środowisku XPC (Cross-Process Communication), chociaż event handlers nie wykonują się współbieżnie, obsługa reply messages ma unikalne zachowanie. W szczególności istnieją dwie różne metody wysyłania messages oczekujących na reply:

1. **`xpc_connection_send_message_with_reply`**: W tym przypadku XPC message jest odbierany i przetwarzany w wyznaczonej queue.
2. **`xpc_connection_send_message_with_reply_sync`**: W tej metodzie XPC message jest odbierany i przetwarzany w bieżącej dispatch queue.

To rozróżnienie ma kluczowe znaczenie, ponieważ umożliwia **równoczesne parsowanie reply packets i wykonywanie XPC event handler**. Warto zauważyć, że chociaż `_xpc_connection_set_creds` implementuje locking w celu ochrony przed częściowym nadpisaniem audit token, ochrona ta nie obejmuje całego connection object. W rezultacie powstaje podatność, w której audit token może zostać zastąpiony w czasie między parsowaniem packet a wykonaniem jego event handlera.

Aby wykorzystać tę podatność, wymagana jest następująca konfiguracja:

- Dwa mach services, określane jako **`A`** i **`B`**, z którymi można ustanowić połączenie.
- Service **`A`** powinien zawierać authorization check dla konkretnego action, który może wykonać wyłącznie **`B`** (aplikacja użytkownika nie może go wykonać).
- Service **`A`** powinien wysłać message oczekujący na reply.
- Użytkownik może wysłać message do **`B`**, na który B odpowie.

Proces exploita obejmuje następujące kroki:

1. Poczekaj, aż service **`A`** wyśle message oczekujący na reply.
2. Zamiast odpowiadać bezpośrednio do **`A`**, przejmij reply port i użyj go do wysłania message do service **`B`**.
3. Następnie wysłany zostaje message dotyczący zabronionego action, z oczekiwaniem, że zostanie on przetworzony równocześnie z reply od **`B`**.<sup>[1]</sup>

Poniżej znajduje się wizualizacja opisanego scenariusza ataku:

!\[https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png]\(../../../../../../images/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../images/image (33).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Problemy z wykrywaniem

- **Trudności w lokalizowaniu instancji**: Wyszukiwanie instancji użycia `xpc_connection_get_audit_token` było trudne zarówno statycznie, jak i dynamicznie.
- **Metodologia**: Użyto Frida do hookowania funkcji `xpc_connection_get_audit_token`, filtrując wywołania niepochodzące z event handlers. Metoda ta była jednak ograniczona do hookowanego procesu i wymagała aktywnego użycia.
- **Narzędzia analityczne**: Narzędzia takie jak IDA/Ghidra służyły do badania osiągalnych mach services, ale proces był czasochłonny i komplikowały go wywołania związane z dyld shared cache.
- **Ograniczenia skryptów**: Próby oskryptowania analizy wywołań `xpc_connection_get_audit_token` z bloków `dispatch_async` były utrudnione przez złożoność parsowania blocks i interakcje z dyld shared cache.<sup>[1]</sup>

## Poprawka <a href="#the-fix" id="the-fix"></a>

- **Zgłoszone problemy**: Do Apple przesłano raport opisujący ogólne i szczegółowe problemy znalezione w `smd`.
- **Odpowiedź Apple**: Apple rozwiązało problem w `smd`, zastępując `xpc_connection_get_audit_token` funkcją `xpc_dictionary_get_audit_token`.<sup>[1][2]</sup>
- **Charakter poprawki**: Funkcja `xpc_dictionary_get_audit_token` jest uznawana za bezpieczną, ponieważ pobiera audit token bezpośrednio z mach message powiązanego z odebranym XPC message. Nie jest jednak częścią public API, podobnie jak `xpc_connection_get_audit_token`.
- **Brak szerszej poprawki**: Nie jest jasne, dlaczego Apple nie wdrożyło bardziej kompleksowej poprawki, takiej jak odrzucanie messages, które nie odpowiadają zapisanemu audit token połączenia. Możliwe, że znaczenie ma możliwość legalnych zmian audit token w określonych scenariuszach (np. przy użyciu `setuid`).
- **Obecny status**: Problem nadal występuje w iOS 17 i macOS 14, co stanowi wyzwanie dla osób próbujących go zidentyfikować i zrozumieć.<sup>[1]</sup>

## Praktyczne wyszukiwanie podatnych ścieżek kodu (2024–2025)

Podczas audytowania usług XPC pod kątem tej klasy błędów skup się na authorization wykonywanej poza event handlerem message albo równocześnie z przetwarzaniem reply.

Wskazówki dotyczące static triage:
- Szukaj wywołań `xpc_connection_get_audit_token` osiągalnych z bloków kolejkowanych przez `dispatch_async`/`dispatch_after` lub inne worker queues działające poza message handlerem.
- Szukaj authorization helpers, które mieszają stan per-connection i per-message (np. pobierają PID z `xpc_connection_get_pid`, ale audit token z `xpc_connection_get_audit_token`).
- W kodzie NSXPC sprawdź, czy checks są wykonywane w `-listener:shouldAcceptNewConnection:` lub, w przypadku checks per-message, czy implementacja używa audit token per-message (np. dictionary message przez `xpc_dictionary_get_audit_token` w kodzie niskopoziomowym).

Wskazówki dotyczące dynamic triage:
- Hookuj `xpc_connection_get_audit_token` i oznaczaj wywołania, których user stack nie zawiera ścieżki event delivery (np. `_xpc_connection_mach_event`). Przykładowy Frida hook:
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
- W macOS instrumentowanie chronionych/binarnych plików Apple może wymagać wyłączenia SIP lub środowiska deweloperskiego; preferuj testowanie własnych buildów lub usług userland.
- W przypadku reply-forwarding races (Variant 2) monitoruj równoczesne parsowanie pakietów odpowiedzi, fuzzując czasy `xpc_connection_send_message_with_reply` względem normalnych żądań i sprawdzając, czy audit token faktycznie używany podczas autoryzacji może zostać zmanipulowany.

## Primitives eksploatacji, których prawdopodobnie będziesz potrzebować

- Multi-sender setup (Variant 1): utwórz connections do A i B; zduplikuj send right portu klienta A i użyj go jako portu klienta B, aby odpowiedzi B były dostarczane do A.
```c
// Duplicate a SEND right you already hold
mach_port_t dup;
mach_port_insert_right(mach_task_self(), a_client, a_client, MACH_MSG_TYPE_MAKE_SEND);
dup = a_client; // use `dup` when crafting B’s connect packet instead of a fresh client port
```
- Reply hijack (Variant 2): przechwyć prawo send-once z oczekującego żądania A (reply port), a następnie wyślij spreparowaną wiadomość do B przy użyciu tego reply port, aby odpowiedź B trafiła do A podczas parsowania Twojego uprzywilejowanego żądania.

Wymaga to niskopoziomowego tworzenia komunikatów mach dla bootstrap XPC i formatów komunikatów; przejrzyj strony z primerem mach/XPC w tej sekcji, aby poznać dokładne układy pakietów i flagi.

## Przydatne narzędzia

- Sniffing/dynamic inspection XPC: gxpc (open-source XPC sniffer) może pomóc wyliczyć połączenia i obserwować ruch w celu zweryfikowania konfiguracji multi-sender oraz synchronizacji czasowej. Przykład: `gxpc -p <PID> --whitelist <service-name>`.
- Klasyczny dyld interposing dla libxpc: zastosuj interpose na `xpc_connection_send_message*` i `xpc_connection_get_audit_token`, aby rejestrować miejsca wywołań i stosy podczas testów black-box.



## References

- [1] [Sector 7 – Don’t Talk All at Once! Elevating Privileges on macOS by Audit Token Spoofing](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [2] [Apple – About the security content of macOS Ventura 13.4 (CVE‑2023‑32405)](https://support.apple.com/en-us/106333)


{{#include ../../../../../../banners/hacktricks-training.md}}
