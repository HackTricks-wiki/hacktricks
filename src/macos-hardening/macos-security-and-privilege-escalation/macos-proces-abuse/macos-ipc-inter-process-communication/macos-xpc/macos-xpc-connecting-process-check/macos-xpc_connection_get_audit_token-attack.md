# macOS xpc_connection_get_audit_token Attack

{{#include ../../../../../../banners/hacktricks-training.md}}

**За додатне информације погледајте оригиналну објаву:** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/). Ово је сажетак:

## Основне информације о Mach Messages

Ако не знате шта су Mach Messages, почните са овом страницом:


{{#ref}}
../../
{{#endref}}

За сада запамтите следеће ([дефиниција одавде](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):\
Mach messages се шаљу преко _mach port-а_, који је комуникациони канал са **једним receiver-ом и више sender-а**, уграђен у mach kernel. **Више процеса може слати messages** на mach port, али у сваком тренутку **само један процес може читати са њега**. Као и file descriptors и sockets, mach ports се додељују и њима управља kernel, а процеси виде само цео број који могу да користе како би kernel-у назначили који од својих mach ports желе да користе.

## XPC Connection

Ако не знате како се успоставља XPC connection, погледајте:


{{#ref}}
../
{{#endref}}

## Сажетак рањивости

Важно је да знате да је **XPC апстракција one-to-one connection**, али је заснована на технологији која **може имати више sender-а, па:**

- Mach ports имају један receiver и **више sender-а**.
- Audit token XPC connection-а је audit token **копиран из последњег примљеног message-а**.
- Добијање **audit token-а** XPC connection-а критично је за многе **security checks**.<sup>[1]</sup>

Иако претходна ситуација делује обећавајуће, постоје сценарији у којима ово неће изазвати проблеме ([одатле](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):

- Audit tokens се често користе за authorization check како би се одлучило да ли connection треба прихватити. Пошто се ово дешава коришћењем message-а ка service port-у, **connection још није успостављен**. Додатни messages на овом port-у само ће бити обрађени као додатни захтеви за connection. Због тога **провере пре прихватања connection-а нису рањиве** (то такође значи да је audit token унутар `-listener:shouldAcceptNewConnection:` безбедан). Зато тражимо XPC connections који проверавају конкретне actions.
- XPC event handlers се обрађују синхроно. То значи да event handler за један message мора бити завршен пре него што се позове за следећи, чак и на concurrent dispatch queues. Зато унутар **XPC event handler-а audit token не може бити преписан** другим уобичајеним (не-reply!) messages.<sup>[1]</sup>

Постоје два начина на која би ово могло бити искоришћено:

1. Variant1:
- **Exploit** се **повезује** на service **A** и service **B**.
- Service **B** може да позове **privileged functionality** у service-у A коју корисник не може да позове.
- Service **A** позива **`xpc_connection_get_audit_token`** док _**није**_ унутар **event handler-а** за connection у **`dispatch_async`**.
- Зато би други message могао да **препише Audit Token**, јер се обрађује асинхроно, изван event handler-а.
- Exploit прослеђује **service-у B SEND right ка service-у A**.
- Тако ће svc **B** заправо **слати** **messages** service-у **A**.
- **Exploit** покушава да позове **privileged action**. У RC-у svc **A** проверава authorization овог **action-а** док је **svc B преписао Audit token** (чиме exploit добија приступ позивању privileged action-а).

2. Variant 2:
- Service **B** може да позове **privileged functionality** у service-у A коју корисник не може да позове.
- Exploit се повезује са **service-ом A**, који exploit-у **шаље** **message који очекује response** на одређени **replay** **port**.
- Exploit шаље service-у B message који прослеђује **тај reply port**.
- Када service **B** одговори, он **шаље message service-у A**, док **exploit** шаље други **message service-у A** и покушава да **достигне privileged functionality**, очекујући да ће response service-а B преписати Audit token у правом тренутку (Race Condition).

## Variant 1: calling xpc_connection_get_audit_token outside of an event handler <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

Сценарио:

- Два mach services-а, **`A`** и **`B`**, на која можемо да се повежемо (на основу sandbox profile-а и authorization checks пре прихватања connection-а).
- _**A**_ мора имати **authorization check** за одређени action који **B** може да прође (али наша апликација не може).
- На пример, ако B има одређене **entitlements** или ради као **root**, могао би да затражи од A да изврши privileged action.
- За овај authorization check, **A** асинхроно прибавља audit token, на пример позивањем `xpc_connection_get_audit_token` из `dispatch_async`.

> [!CAUTION]
> У овом случају attacker може да изазове **Race Condition**, правећи **exploit** који више пута тражи од A да изврши action, док **B шаље messages service-у `A`**. Када је RC **успешан**, **audit token** service-а **B** биће копиран у memory док A обрађује захтев нашег **exploit-а**, чиме exploit добија **access** privileged action-у који је могао да затражи само B.

Ово се догодило са **`A`** као `smd` и **`B`** као `diagnosticd`. Функција [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) из smb-а може се користити за инсталирање новог privileged helper tool-а (као **root**). Ако **process running as root contact** контактира **`smd`**, неће бити извршене додатне провере.

Зато је service **B** **`diagnosticd`**, јер ради као **root** и може се користити за **monitor** процеса; када monitoring започне, он ће **слати више messages-а у секунди.**

За извођење attack-а:

1. Иницирајте **connection** ка service-у под називом `smd` користећи стандардни XPC protocol.
2. Успоставите секундарни **connection** ка `diagnosticd`. За разлику од уобичајене процедуре, уместо креирања и слања два нова mach ports-а, client port send right се замењује дупликатом **send right-а** повезаног са `smd` connection-ом.
3. Као резултат, XPC messages могу бити прослеђени service-у `diagnosticd`, али се responses од `diagnosticd` преусмеравају ка `smd`. За `smd` изгледа као да messages и од корисника и од `diagnosticd` потичу са истог connection-а.

![Слика која приказује процес exploit-а](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)

4. Следећи корак је налагање service-у `diagnosticd` да започне monitoring изабраног процеса (потенцијално самог корисниковог процеса). Истовремено се `smd`-у шаље flood уобичајених 1004 messages-а. Циљ је инсталирање tool-а са elevated privileges.
5. Ова action покреће race condition унутар функције `handle_bless`. Време је критично: позив функције `xpc_connection_get_pid` мора вратити PID корисниковог процеса (јер се privileged tool налази у bundle-у корисникове апликације). Међутим, функција `xpc_connection_get_audit_token`, конкретно унутар subroutine-а `connection_is_authorized`, мора да покаже на audit token који припада service-у `diagnosticd`.<sup>[1]</sup>

## Variant 2: reply forwarding

У XPC (Cross-Process Communication) окружењу, иако се event handlers не извршавају concurrent, обрада reply messages-а има јединствено понашање. Конкретно, постоје два различита начина слања messages-а који очекују reply:

1. **`xpc_connection_send_message_with_reply`**: Овде се XPC message прима и обрађује на одређеном queue-у.
2. **`xpc_connection_send_message_with_reply_sync`**: Насупрот томе, овим методом се XPC message прима и обрађује на тренутном dispatch queue-у.

Ова разлика је критична јер омогућава да се reply packets парсирају concurrent са извршавањем XPC event handler-а. Значајно је да, иако `_xpc_connection_set_creds` имплементира locking ради заштите од делимичног преписивања audit token-а, та заштита се не односи на цео connection object. Последично, настаје рањивост у којој audit token може бити замењен током интервала између парсирања packet-а и извршавања његовог event handler-а.

За exploit ове рањивости потребно је следеће:

- Два mach services-а, названа **`A`** и **`B`**, од којих оба могу да успоставе connection.
- Service **`A`** треба да има authorization check за одређени action који само **`B`** може да изврши (корисникова апликација не може).
- Service **`A`** треба да пошаље message који очекује reply.
- Корисник може послати message service-у **`B`**, на који ће он одговорити.

Процес exploitation-а обухвата следеће кораке:

1. Сачекајте да service **`A`** пошаље message који очекује reply.
2. Уместо директног одговора service-у **`A`**, reply port се преузима и користи за слање message-а service-у **`B`**.
3. Након тога се шаље message који укључује forbidden action, уз очекивање да ће бити обрађен concurrent са reply-ом service-а **`B`**.<sup>[1]</sup>

Испод је визуелни приказ описаног attack сценарија:

!\[https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png]\(../../../../../../images/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../images/image (33).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Проблеми при откривању

- **Потешкоће при проналажењу instances-а**: Било је тешко статички и динамички претражити instances коришћења `xpc_connection_get_audit_token`.
- **Methodology**: Frida је коришћена за hook-овање функције `xpc_connection_get_audit_token`, уз филтрирање позива који не потичу из event handlers-а. Међутим, овај метод је био ограничен на hook-овани process и захтевао је активну употребу.
- **Analysis Tooling**: Tools као што су IDA/Ghidra коришћени су за испитивање доступних mach services-а, али је процес био дуготрајан и додатно закомпликован позивима који укључују dyld shared cache.
- **Scripting Limitations**: Покушаји да се analysis скриптује за позиве `xpc_connection_get_audit_token` из `dispatch_async` blocks-а били су отежани сложеношћу парсирања blocks-а и интеракцијама са dyld shared cache-ом.<sup>[1]</sup>

## Исправка <a href="#the-fix" id="the-fix"></a>

- **Reported Issues**: Apple-у је поднет report са детаљима о општим и специфичним проблемима пронађеним унутар `smd`.
- **Apple's Response**: Apple је решио проблем у `smd` тако што је `xpc_connection_get_audit_token` заменио функцијом `xpc_dictionary_get_audit_token`.<sup>[1][2]</sup>
- **Nature of the Fix**: Функција `xpc_dictionary_get_audit_token` сматра се безбедном јер преузима audit token директно из mach message-а повезаног са примљеним XPC message-ом. Међутим, она није део public API-ја, слично као `xpc_connection_get_audit_token`.
- **Absence of a Broader Fix**: Није јасно зашто Apple није имплементирао свеобухватнију исправку, као што је одбацивање messages-а који се не подударају са сачуваним audit token-ом connection-а. Могућност легитимних промена audit token-а у одређеним сценаријима (нпр. коришћење `setuid`) можда је један од фактора.
- **Current Status**: Проблем и даље постоји у iOS 17 и macOS 14, што представља изазов за оне који покушавају да га идентификују и разумеју.<sup>[1]</sup>

## Практично проналажење рањивих code paths (2024–2025)

При auditing-у XPC services-а за ову bug class, усредсредите се на authorization који се извршава изван event handler-а за message или concurrent са обрадом reply-а.

Смернице за static triage:

- Потражите позиве `xpc_connection_get_audit_token` до којих се може доћи из blocks-а стављених у queue преко `dispatch_async`/`dispatch_after` или других worker queues-а који се извршавају изван message handler-а.
- Потражите authorization helpers који мешају state по connection-у и по message-у (нпр. преузимање PID-а преко `xpc_connection_get_pid`, али audit token-а преко `xpc_connection_get_audit_token`).
- У NSXPC code-у проверите да ли се checks извршавају у `-listener:shouldAcceptNewConnection:` или, за checks по message-у, да ли implementation користи audit token по message-у (нпр. dictionary message-а преко `xpc_dictionary_get_audit_token` у lower-level code-у).

Смернице за dynamic triage:

- Hook-ујте `xpc_connection_get_audit_token` и означите invocations чији user stack не садржи event-delivery path (нпр. `_xpc_connection_mach_event`). Пример Frida hook-а:
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
Napomene:
- Na macOS-u, instrumentacija zaštićenih/Apple binarnih datoteka može zahtevati onemogućen SIP ili razvojno okruženje; prednost dajte testiranju sopstvenih buildova ili userland servisa.
- Za reply-forwarding race uslove (Varijanta 2), pratite konkurentno parsiranje reply paketa fuzzovanjem vremenskih intervala između `xpc_connection_send_message_with_reply` i normalnih zahteva i proverite da li se može uticati na efektivni audit token koji se koristi tokom autorizacije.

## Exploitation primitives koje će vam verovatno biti potrebne

- Multi-sender podešavanje (Varijanta 1): kreirajte konekcije ka A i B; duplicirajte send right klijentskog porta A i upotrebite ga kao klijentski port B-a, tako da se B-ovi reply-i isporučuju A-u.
```c
// Duplicate a SEND right you already hold
mach_port_t dup;
mach_port_insert_right(mach_task_self(), a_client, a_client, MACH_MSG_TYPE_MAKE_SEND);
dup = a_client; // use `dup` when crafting B’s connect packet instead of a fresh client port
```
- Reply hijack (Variant 2): preuzmite send-once right iz A-ovog zahteva na čekanju (reply port), zatim pošaljite konstruisanu poruku procesu B koristeći taj reply port, tako da B-ov odgovor stigne u A dok se vaš privileged request obrađuje.

Ovo zahteva niskonivousko konstruisanje mach poruka za XPC bootstrap i formate poruka; pregledajte mach/XPC primer stranice u ovom odeljku za tačne rasporede paketa i flags.

## Korisni alati

- XPC sniffing/dynamic inspection: gxpc (open-source XPC sniffer) može pomoći pri nabrajanju konekcija i posmatranju saobraćaja radi provere multi-sender postavki i vremenskog usklađivanja. Primer: `gxpc -p <PID> --whitelist <service-name>`.
- Classic dyld interposing za libxpc: postavite interpose na `xpc_connection_send_message*` i `xpc_connection_get_audit_token` da biste beležili mesta poziva i stackove tokom black-box testiranja.



## References

- [1] [Sector 7 – Don’t Talk All at Once! Elevating Privileges on macOS by Audit Token Spoofing](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [2] [Apple – About the security content of macOS Ventura 13.4 (CVE‑2023‑32405)](https://support.apple.com/en-us/106333)


{{#include ../../../../../../banners/hacktricks-training.md}}
