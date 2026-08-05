# Attack wykorzystujący xpc_connection_get_audit_token w macOS

{{#include ../../../../../../banners/hacktricks-training.md}}

**Więcej informacji znajdziesz w oryginalnym poście:** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/). Poniżej znajduje się podsumowanie:

## Podstawowe informacje o Mach Messages

Jeśli nie wiesz, czym są Mach Messages, zacznij od tej strony:


{{#ref}}
../../
{{#endref}}

Na razie zapamiętaj, że ([definicja z tego miejsca](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):\
Mach messages są wysyłane przez _mach port_, czyli kanał komunikacyjny **single receiver, multiple sender** wbudowany w jądro mach. **Wiele procesów może wysyłać messages** do mach portu, ale w danym momencie **tylko jeden proces może z niego odczytywać**. Podobnie jak file descriptors i sockets, mach ports są przydzielane i zarządzane przez kernel, a procesy widzą jedynie liczbę całkowitą, której mogą użyć do wskazania kernelowi, którego ze swoich mach ports chcą użyć.

## XPC Connection

Jeśli nie wiesz, jak ustanawiane jest połączenie XPC, sprawdź:


{{#ref}}
../
{{#endref}}

## Podsumowanie podatności

Warto wiedzieć, że **abstrakcja XPC jest połączeniem one-to-one**, ale opiera się na technologii, która **może mieć wielu senderów, dlatego:**

- Mach ports mają jednego receivera i **wielu senderów**.
- Audit token połączenia XPC jest tokenem audytowym **skopiowanym z ostatnio odebranego message**.
- Uzyskanie **audit token** połączenia XPC ma kluczowe znaczenie dla wielu **security checks**.<sup>[[1]](#references)</sup>

Chociaż powyższa sytuacja brzmi obiecująco, istnieją scenariusze, w których nie spowoduje ona problemów ([z tego miejsca](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):

- Audit tokens są często używane do authorization check, aby zdecydować, czy zaakceptować połączenie. Ponieważ odbywa się to za pomocą message wysłanego do service portu, **połączenie nie zostało jeszcze ustanowione**. Kolejne messages na tym porcie zostaną po prostu obsłużone jako dodatkowe żądania połączenia. Dlatego **checks wykonywane przed zaakceptowaniem połączenia nie są podatne** (oznacza to również, że wewnątrz `-listener:shouldAcceptNewConnection:` audit token jest bezpieczny). Szukamy więc połączeń XPC, które weryfikują określone działania.
- XPC event handlers są obsługiwane synchronicznie. Oznacza to, że event handler dla jednego message musi zostać zakończony przed wywołaniem go dla następnego, nawet w przypadku współbieżnych dispatch queues. Dlatego wewnątrz **XPC event handler audit token nie może zostać nadpisany** przez inne zwykłe messages (niebędące reply!).<sup>[[1]](#references)</sup>

Istnieją dwa różne sposoby, na które może to być exploitable:

1. Variant1:
- **Exploit** łączy się z service **A** i service **B**
- Service **B** może wywołać w service A **privileged functionality**, której użytkownik nie może wywołać
- Service **A** wywołuje **`xpc_connection_get_audit_token`**, gdy _**nie**_ znajduje się wewnątrz **event handlera** dla połączenia w **`dispatch_async`**.
- W związku z tym inny message może **nadpisać Audit Token**, ponieważ jest dispatchowany asynchronicznie poza event handlerem.
- Exploit przekazuje **service B prawo SEND do service A**.
- W rezultacie svc **B** będzie faktycznie **wysyłać** **messages** do service **A**.
- **Exploit** próbuje wywołać **privileged action**. W RC svc **A** **sprawdza** authorization tej **action**, gdy **svc B nadpisał Audit token** (dając exploitowi dostęp do wywołania privileged action).
2. Variant 2:
- Service **B** może wywołać w service A **privileged functionality**, której użytkownik nie może wywołać
- Exploit łączy się z **service A**, który **wysyła** exploitowi **message oczekujący odpowiedzi** na określonym **replay** **porcie**.
- Exploit wysyła do **service** B message przekazujący **ten reply port**.
- Gdy service **B** odpowiada, **wysyła message do service A**, podczas gdy **exploit** wysyła inny **message do service A**, próbując **uzyskać dostęp do privileged functionality** i oczekując, że reply od service B nadpisze Audit token w odpowiednim momencie (Race Condition).

## Variant 1: wywołanie xpc_connection_get_audit_token poza event handlerem <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

Scenariusz:

- Dwa mach services, **`A`** i **`B`**, z którymi możemy się połączyć (na podstawie sandbox profile i authorization checks wykonywanych przed zaakceptowaniem połączenia).
- _**A**_ musi mieć **authorization check** dla określonej action, którą **B** może przejść, ale nasza aplikacja nie.
- Na przykład, jeśli B ma określone **entitlements** lub działa jako **root**, może pozwolić mu to poprosić A o wykonanie privileged action.
- Na potrzeby tego authorization check **A** pobiera audit token asynchronicznie, na przykład wywołując `xpc_connection_get_audit_token` z poziomu `dispatch_async`.

> [!CAUTION]
> W tym przypadku attacker może wywołać **Race Condition**, tworząc **exploit**, który wielokrotnie prosi **A o wykonanie action**, jednocześnie powodując, że **B wysyła messages do `A`**. Gdy RC zakończy się **sukcesem**, **audit token** procesu **B** zostanie skopiowany do pamięci **w trakcie obsługi żądania naszego exploita** przez A, dając mu **dostęp do privileged action**, o którą mógł poprosić wyłącznie B.

Miało to miejsce, gdy **`A`** było `smd`, a **`B`** było `diagnosticd`. Funkcja [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) z smb może służyć do instalowania nowego privileged helper tool (jako **root**). Jeśli **proces działający jako root skontaktuje się z** **smd**, nie będą wykonywane żadne dodatkowe checks.

Dlatego service **B** to **`diagnosticd`**, ponieważ działa jako **root** i może służyć do **monitorowania** procesu, więc po rozpoczęciu monitorowania będzie **wysyłać wiele messages na sekundę.**

Aby wykonać attack:

1. Zainicjuj **connection** do service o nazwie `smd`, korzystając ze standardowego protokołu XPC.
2. Utwórz drugie **connection** do `diagnosticd`. W przeciwieństwie do normalnej procedury, zamiast tworzyć i wysyłać dwa nowe mach ports, client port send right zostaje zastąpione duplikatem **send right** powiązanego z connection do `smd`.
3. W rezultacie messages XPC mogą być dispatchowane do `diagnosticd`, ale responses z `diagnosticd` są przekierowywane do `smd`. Dla `smd` wygląda to tak, jakby messages zarówno od użytkownika, jak i od `diagnosticd` pochodziły z tego samego connection.

![Image depicting the exploit process](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)

4. Następny krok polega na nakazaniu `diagnosticd` rozpoczęcia monitorowania wybranego procesu (potencjalnie własnego procesu użytkownika). Jednocześnie do `smd` wysyłany jest flood rutynowych messages 1004. Celem jest zainstalowanie toola z podwyższonymi privileges.
5. Ta action wywołuje race condition wewnątrz funkcji `handle_bless`. Kluczowe jest właściwe zgranie w czasie: wywołanie funkcji `xpc_connection_get_pid` musi zwrócić PID procesu użytkownika (ponieważ privileged tool znajduje się w bundle aplikacji użytkownika). Jednak funkcja `xpc_connection_get_audit_token`, konkretnie w subroutine `connection_is_authorized`, musi odwoływać się do audit token należącego do `diagnosticd`.<sup>[[1]](#references)</sup>

## Variant 2: reply forwarding

W środowisku XPC (Cross-Process Communication), chociaż event handlers nie wykonują się współbieżnie, obsługa reply messages ma unikalne zachowanie. W szczególności istnieją dwie różne metody wysyłania messages oczekujących na reply:

1. **`xpc_connection_send_message_with_reply`**: W tym przypadku XPC message jest odbierany i przetwarzany w wyznaczonej kolejce.
2. **`xpc_connection_send_message_with_reply_sync`**: W tej metodzie XPC message jest natomiast odbierany i przetwarzany w bieżącej dispatch queue.

To rozróżnienie ma kluczowe znaczenie, ponieważ umożliwia **równoczesne parsowanie reply packets i wykonywanie XPC event handlera**. Warto zauważyć, że chociaż `_xpc_connection_set_creds` stosuje locking w celu ochrony przed częściowym nadpisaniem audit token, ochrona ta nie obejmuje całego connection object. W rezultacie powstaje podatność, w której audit token może zostać zastąpiony w czasie pomiędzy parsowaniem pakietu a wykonaniem jego event handlera.

Do wykorzystania tej podatności wymagana jest następująca konfiguracja:

- Dwa mach services, określane jako **`A`** i **`B`**, z którymi można ustanowić connection.
- Service **`A`** powinien zawierać authorization check dla określonej action, którą może wykonać wyłącznie **`B`** (aplikacja użytkownika nie może).
- Service **`A`** powinien wysłać message oczekujący na reply.
- Użytkownik może wysłać message do **`B`**, na który B odpowie.

Proces wykorzystania podatności obejmuje następujące kroki:

1. Zaczekaj, aż service **`A`** wyśle message oczekujący na reply.
2. Zamiast odpowiadać bezpośrednio do **`A`**, przejmij reply port i użyj go do wysłania message do service **`B`**.
3. Następnie dispatchowany jest message dotyczący zabronionej action, z oczekiwaniem, że będzie przetwarzany współbieżnie z reply od **`B`**.<sup>[[1]](#references)</sup>

Poniżej znajduje się wizualna reprezentacja opisanego scenariusza attack:

!\[https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png]\(../../../../../../images/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../images/image (33).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Problemy z wykrywaniem

- **Trudności w lokalizowaniu przypadków**: Wyszukiwanie przypadków użycia `xpc_connection_get_audit_token` było trudne zarówno statycznie, jak i dynamicznie.
- **Metodologia**: Do hookowania funkcji `xpc_connection_get_audit_token` użyto Frida, filtrując wywołania, które nie pochodziły z event handlers. Metoda ta była jednak ograniczona do hookowanego procesu i wymagała aktywnego użycia.
- **Narzędzia analityczne**: Narzędzia takie jak IDA/Ghidra służyły do badania osiągalnych mach services, ale proces był czasochłonny i komplikowały go wywołania związane z dyld shared cache.
- **Ograniczenia skryptów**: Próby zautomatyzowania analizy wywołań `xpc_connection_get_audit_token` z bloków `dispatch_async` były utrudnione przez złożoność parsowania blocks oraz interakcje z dyld shared cache.<sup>[[1]](#references)</sup>

## Poprawka <a href="#the-fix" id="the-fix"></a>

- **Zgłoszone problemy**: Do Apple przesłano report opisujący ogólne i konkretne problemy znalezione w `smd`.
- **Odpowiedź Apple**: Apple rozwiązało problem w `smd`, zastępując `xpc_connection_get_audit_token` funkcją `xpc_dictionary_get_audit_token`.<sup>[[1]](#references)[[2]](#references)</sup>
- **Charakter poprawki**: Funkcja `xpc_dictionary_get_audit_token` jest uznawana za bezpieczną, ponieważ pobiera audit token bezpośrednio z mach message powiązanego z odebranym XPC message. Nie jest ona jednak częścią public API, podobnie jak `xpc_connection_get_audit_token`.
- **Brak szerszej poprawki**: Nie jest jasne, dlaczego Apple nie wdrożyło bardziej kompleksowej poprawki, takiej jak odrzucanie messages, które nie odpowiadają zapisanemu audit token połączenia. Możliwe, że znaczenie miała możliwość legalnych zmian audit token w określonych scenariuszach (np. użycie `setuid`).
- **Obecny status**: Problem nadal występuje w iOS 17 i macOS 14, co stanowi wyzwanie dla osób próbujących go zidentyfikować i zrozumieć.<sup>[[1]](#references)</sup>

## Praktyczne znajdowanie podatnych ścieżek kodu (2024–2025)

Podczas audytowania usług XPC pod kątem tej klasy błędów skup się na authorization wykonywanej poza event handlerem message albo współbieżnie z przetwarzaniem reply.

Wskazówki do wstępnej analizy statycznej:
- Szukaj wywołań `xpc_connection_get_audit_token` osiągalnych z blocks umieszczanych w kolejce przez `dispatch_async`/`dispatch_after` lub inne worker queues działające poza message handlerem.
- Szukaj authorization helpers, które łączą stan per-connection ze stanem per-message (np. pobierają PID z `xpc_connection_get_pid`, ale audit token z `xpc_connection_get_audit_token`).
- W kodzie NSXPC sprawdź, czy checks są wykonywane w `-listener:shouldAcceptNewConnection:` albo, w przypadku checks per-message, czy implementacja używa audit token per-message (np. dictionary message przez `xpc_dictionary_get_audit_token` w kodzie niższego poziomu).

Wskazówki do wstępnej analizy dynamicznej:
- Hookuj `xpc_connection_get_audit_token` i oznaczaj wywołania, których user stack nie zawiera ścieżki dostarczania eventów (np. `_xpc_connection_mach_event`). Przykładowy hook Frida:
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
- W przypadku wyścigów związanych z przekazywaniem odpowiedzi (Variant 2) monitoruj równoczesne parsowanie pakietów odpowiedzi, fuzzując czasy wywołań `xpc_connection_send_message_with_reply` względem normalnych żądań i sprawdzając, czy można wpłynąć na efektywny audit token używany podczas autoryzacji.

## Primitives eksploatacji, których prawdopodobnie będziesz potrzebować

- Konfiguracja multi-sender (Variant 1): utwórz połączenia z A i B; zduplikuj send right portu klienta A i użyj go jako portu klienta B, aby odpowiedzi B były dostarczane do A.
```c
// Duplicate a SEND right you already hold
mach_port_t dup;
mach_port_insert_right(mach_task_self(), a_client, a_client, MACH_MSG_TYPE_MAKE_SEND);
dup = a_client; // use `dup` when crafting B’s connect packet instead of a fresh client port
```
- Reply hijack (Variant 2): przechwyć send-once right z oczekującego żądania A (reply port), a następnie wyślij spreparowaną wiadomość do B przy użyciu tego reply port, aby odpowiedź B trafiła do A, gdy Twoje uprzywilejowane żądanie jest parsowane.

Wymaga to niskopoziomowego tworzenia komunikatów mach dla bootstrap XPC i formatów wiadomości; przejrzyj strony z primerem mach/XPC w tej sekcji, aby poznać dokładne układy pakietów i flagi.

## Przydatne narzędzia

- Sniffing/dynamic inspection XPC: gxpc (open-source XPC sniffer) może pomóc wyliczyć połączenia i obserwować ruch w celu zweryfikowania konfiguracji multi-sender oraz synchronizacji. Przykład: `gxpc -p <PID> --whitelist <service-name>`.
- Klasyczne dyld interposing dla libxpc: zastosuj interpose na `xpc_connection_send_message*` i `xpc_connection_get_audit_token`, aby logować miejsca wywołań i stosy podczas black-box testing.



## Referencje

- [1] [Sector 7 – Nie mówcie wszyscy naraz! Podnoszenie uprawnień w macOS przez spoofing Audit Token](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [2] [Apple – Informacje o zawartości zabezpieczeń macOS Ventura 13.4 (CVE‑2023‑32405)](https://support.apple.com/en-us/106333)


{{#include ../../../../../../banners/hacktricks-training.md}}
