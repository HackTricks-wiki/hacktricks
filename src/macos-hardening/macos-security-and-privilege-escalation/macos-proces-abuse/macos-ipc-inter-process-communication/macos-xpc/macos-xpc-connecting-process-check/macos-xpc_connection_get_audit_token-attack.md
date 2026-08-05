# Attack macOS xpc_connection_get_audit_token

{{#include ../../../../../../banners/hacktricks-training.md}}

**Для получения дополнительной информации ознакомьтесь с оригинальной публикацией:** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/). Краткое изложение:

## Основная информация о Mach Messages

Если вы не знаете, что такое Mach Messages, начните с этой страницы:


{{#ref}}
../../
{{#endref}}

Пока запомните следующее ([определение отсюда](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):\
Mach messages отправляются через _mach port_, являющийся встроенным в ядро mach каналом связи **с одним получателем и несколькими отправителями**. **Несколько процессов могут отправлять сообщения** на mach port, но в любой момент времени **только один процесс может считывать их**. Как и file descriptors и sockets, mach ports выделяются и управляются ядром, а процессы видят только целое число, которое они могут использовать, чтобы указать ядру, какой из их mach ports они хотят использовать.

## XPC Connection

Если вы не знаете, как устанавливается XPC connection, ознакомьтесь с разделом:


{{#ref}}
../
{{#endref}}

## Краткое описание уязвимости

Важно понимать, что **абстракция XPC представляет собой соединение один-к-одному**, но построена поверх технологии, которая **может иметь несколько отправителей, поэтому:**

- Mach ports имеют одного получателя и **нескольких отправителей**.
- Audit token XPC connection — это audit token, **скопированный из последнего полученного сообщения**.
- Получение **audit token** XPC connection критично для многих **security checks**.<sup>[1]</sup>

Хотя описанная ситуация выглядит многообещающей, существуют сценарии, в которых она не приводит к проблемам ([отсюда](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):

- Audit tokens часто используются для authorization check, чтобы решить, принимать ли connection. Поскольку это выполняется с помощью сообщения на service port, **connection ещё не установлено**. Дополнительные сообщения на этом port будут просто обрабатываться как дополнительные запросы на установление connection. Поэтому **checks до принятия connection не уязвимы** (это также означает, что внутри `-listener:shouldAcceptNewConnection:` audit token безопасен). Следовательно, нас интересуют XPC connections, которые проверяют конкретные действия.
- XPC event handlers обрабатываются синхронно. Это означает, что event handler одного сообщения должен завершиться до его вызова для следующего сообщения, даже при использовании concurrent dispatch queues. Поэтому внутри **XPC event handler audit token не может быть перезаписан** другими обычными сообщениями (не reply-сообщениями).<sup>[1]</sup>

Существует два способа эксплуатации этой особенности:

1. Variant1:
- **Exploit** подключается к service **A** и service **B**.
- Service **B** может вызвать в service A **privileged functionality**, недоступную пользователю.
- Service **A** вызывает **`xpc_connection_get_audit_token`**, находясь _**не**_ внутри **event handler** для connection в **`dispatch_async`**.
- Поэтому **другое** сообщение может **перезаписать Audit Token**, поскольку оно обрабатывается асинхронно вне event handler.
- Exploit передаёт **service B SEND right для service A**.
- Поэтому svc **B** фактически будет **отправлять** **messages** service **A**.
- **Exploit** пытается **вызвать privileged action**. В RC svc **A** **проверяет** authorization этого **action**, пока **svc B перезаписал Audit token** (предоставляя exploit доступ к вызову privileged action).

2. Variant 2:
- Service **B** может вызвать в service A **privileged functionality**, недоступную пользователю.
- Exploit подключается к **service A**, который **отправляет** exploit сообщение, ожидающее ответ, через специальный **replay** **port**.
- Exploit отправляет service **B** сообщение, передавая **этот reply port**.
- Когда service **B** отвечает, он **отправляет сообщение service A**, пока **exploit** отправляет другое **сообщение service A**, пытаясь **достичь privileged functionality** и рассчитывая, что reply от service B перезапишет Audit token в нужный момент (Race Condition).

## Variant 1: вызов xpc_connection_get_audit_token вне event handler <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

Сценарий:

- Два mach services — **`A`** и **`B`**, к которым мы можем подключиться (на основании sandbox profile и authorization checks до принятия connection).
- _**A**_ должен иметь **authorization check** для определённого action, который **`B`** может пройти, но наше приложение — нет.
- Например, если B имеет определённые **entitlements** или работает от имени **root**, он может разрешить запрос A на выполнение privileged action.
- Для этого authorization check **`A`** получает audit token асинхронно, например вызывая `xpc_connection_get_audit_token` из `dispatch_async`.

> [!CAUTION]
> В этом случае attacker может инициировать **Race Condition**, создав **exploit**, который несколько раз просит A выполнить action, одновременно заставляя **B отправлять messages в `A`**. При **успешном** RC **audit token** **B** будет скопирован в память, пока запрос нашего **exploit** обрабатывается A, предоставляя ему **access к privileged action**, который может запросить только B.

Это произошло с **`A`**, представленным как `smd`, и **`B`**, представленным как `diagnosticd`. Функция [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) из smb может использоваться для установки нового privileged helper toot (от имени **root**). Если **process running as root contact** **`smd`**, дополнительные checks выполняться не будут.

Поэтому service **B** — это **`diagnosticd`**, поскольку он работает от имени **root** и может использоваться для **monitor** процесса; после начала мониторинга он будет **отправлять несколько сообщений в секунду**.

Для выполнения attack:

1. Инициируйте **connection** к service с именем `smd`, используя стандартный XPC protocol.
2. Создайте secondary **connection** к `diagnosticd`. В отличие от обычной процедуры, вместо создания и отправки двух новых mach ports client port send right заменяется дубликатом **send right**, связанным с connection `smd`.
3. В результате XPC messages могут быть отправлены в `diagnosticd`, но ответы от `diagnosticd` перенаправляются в `smd`. Для `smd` будет выглядеть так, будто messages от пользователя и `diagnosticd` исходят из одного и того же connection.

![Изображение, показывающее процесс exploit](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)

4. Следующий шаг — поручить `diagnosticd` начать monitor выбранного процесса (потенциально самого процесса пользователя). Одновременно в `smd` отправляется поток обычных сообщений 1004. Цель — установить tool с повышенными privileges.
5. Это action вызывает race condition внутри функции `handle_bless`. Время имеет критическое значение: вызов функции `xpc_connection_get_pid` должен вернуть PID процесса пользователя (поскольку privileged tool находится в app bundle пользователя). Однако функция `xpc_connection_get_audit_token`, а именно внутри subroutine `connection_is_authorized`, должна обратиться к audit token, принадлежащему `diagnosticd`.<sup>[1]</sup>

## Variant 2: reply forwarding

В среде XPC (Cross-Process Communication), хотя event handlers не выполняются concurrently, обработка reply messages имеет особое поведение. В частности, существуют два разных метода отправки messages, ожидающих reply:

1. **`xpc_connection_send_message_with_reply`**: здесь XPC message получает и обрабатывается в designated queue.
2. **`xpc_connection_send_message_with_reply_sync`**: напротив, в этом методе XPC message получает и обрабатывается в текущей dispatch queue.

Это различие важно, поскольку допускает возможность **reply packets обрабатываться concurrently с выполнением XPC event handler**. В частности, хотя `_xpc_connection_set_creds` реализует locking для защиты от частичной перезаписи audit token, эта защита не распространяется на весь connection object. В результате возникает уязвимость, при которой audit token может быть заменён в промежутке между parsing packet и выполнением его event handler.

Для эксплуатации этой уязвимости требуется следующая конфигурация:

- Два mach services, обозначенные как **`A`** и **`B`**, к каждому из которых можно установить connection.
- Service **`A`** должен содержать authorization check для конкретного action, который может выполнить только **`B`** (приложение пользователя не может).
- Service **`A`** должен отправлять message, ожидая reply.
- Пользователь может отправить message в **`B`**, на который тот ответит.

Процесс эксплуатации включает следующие шаги:

1. Дождаться, пока service **`A`** отправит message, ожидая reply.
2. Вместо прямого ответа **`A`** перехватить reply port и использовать его для отправки message service **`B`**.
3. Затем отправляется message, связанное с запрещённым action, в расчёте на то, что оно будет обработано concurrently с reply от **`B`**.<sup>[1]</sup>

Ниже представлено визуальное описание указанного сценария attack:

!\[https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png]\(../../../../../../images/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../images/image (33).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Проблемы обнаружения

- **Сложности с поиском экземпляров**: поиск экземпляров использования `xpc_connection_get_audit_token` был сложным как статически, так и динамически.
- **Методология**: Frida использовалась для hook функции `xpc_connection_get_audit_token` с фильтрацией вызовов, исходящих не из event handlers. Однако этот метод был ограничен hooked process и требовал его активного использования.
- **Инструменты анализа**: такие tools, как IDA/Ghidra, использовались для изучения доступных mach services, но процесс занимал много времени и осложнялся вызовами, связанными с dyld shared cache.
- **Ограничения scripting**: попытки автоматизировать анализ вызовов `xpc_connection_get_audit_token` из блоков `dispatch_async` были затруднены сложностями parsing blocks и взаимодействия с dyld shared cache.<sup>[1]</sup>

## Исправление <a href="#the-fix" id="the-fix"></a>

- **Сообщение о проблемах**: Apple был отправлен report с описанием общих и конкретных проблем, обнаруженных в `smd`.
- **Ответ Apple**: Apple устранила проблему в `smd`, заменив `xpc_connection_get_audit_token` на `xpc_dictionary_get_audit_token`.<sup>[1][2]</sup>
- **Характер исправления**: функция `xpc_dictionary_get_audit_token` считается безопасной, поскольку получает audit token непосредственно из mach message, связанного с полученным XPC message. Однако она не входит в public API, как и `xpc_connection_get_audit_token`.
- **Отсутствие более широкого исправления**: остаётся непонятным, почему Apple не реализовала более comprehensive fix, например отбрасывание messages, которые не соответствуют сохранённому audit token connection. Возможной причиной могут быть легитимные изменения audit token в определённых сценариях (например, при использовании `setuid`).
- **Текущий статус**: проблема сохраняется в iOS 17 и macOS 14, создавая сложности для тех, кто пытается её обнаружить и понять.<sup>[1]</sup>

## Практический поиск уязвимых code paths (2024–2025)

При аудите XPC services этого класса ошибок сосредоточьтесь на authorization, выполняемой вне event handler сообщения или concurrently с обработкой reply.

Подсказки для static triage:

- Ищите вызовы `xpc_connection_get_audit_token`, доступные из blocks, поставленных в очередь через `dispatch_async`/`dispatch_after`, или другие worker queues, работающие вне message handler.
- Ищите authorization helpers, смешивающие состояние per-connection и per-message (например, получение PID через `xpc_connection_get_pid`, но audit token через `xpc_connection_get_audit_token`).
- В NSXPC проверьте, что checks выполняются в `-listener:shouldAcceptNewConnection:` или, для per-message checks, что реализация использует per-message audit token (например, dictionary сообщения через `xpc_dictionary_get_audit_token` в lower-level code).

Подсказки для dynamic triage:

- Hook `xpc_connection_get_audit_token` и отмечайте вызовы, user stack которых не содержит event-delivery path (например, `_xpc_connection_mach_event`). Пример Frida hook:
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
Нотатки:
- У macOS для інструментування захищених/Apple binaries може знадобитися вимкнений SIP або середовище розробки; надавайте перевагу тестуванню власних збірок або userland services.
- Для reply-forwarding races (Variant 2) відстежуйте паралельний розбір reply packets, змінюючи таймінги `xpc_connection_send_message_with_reply` порівняно зі звичайними запитами та перевіряючи, чи можна вплинути на effective audit token, який використовується під час авторизації.

## Exploitation primitives, які, імовірно, вам знадобляться

- Multi-sender setup (Variant 1): створіть connections до A і B; дублюйте send right клієнтського порту A та використовуйте його як клієнтський порт B, щоб replies від B доставлялися до A.
```c
// Duplicate a SEND right you already hold
mach_port_t dup;
mach_port_insert_right(mach_task_self(), a_client, a_client, MACH_MSG_TYPE_MAKE_SEND);
dup = a_client; // use `dup` when crafting B’s connect packet instead of a fresh client port
```
- Reply hijack (Variant 2): перехопіть send-once right із pending request від A (reply port), а потім надішліть crafted message до B, використовуючи цей reply port, щоб reply від B надійшов до A, поки ваш privileged request обробляється.

Це потребує low-level створення mach messages для XPC bootstrap і форматів повідомлень; перегляньте сторінки mach/XPC primer у цьому розділі, щоб ознайомитися з точними packet layouts і flags.

## Корисні інструменти

- XPC sniffing/dynamic inspection: gxpc (open-source XPC sniffer) може допомогти перелічити connections і спостерігати traffic, щоб перевірити multi-sender setups і timing. Приклад: `gxpc -p <PID> --whitelist <service-name>`.
- Класичний dyld interposing для libxpc: виконайте interpose на `xpc_connection_send_message*` і `xpc_connection_get_audit_token`, щоб під час black-box testing логувати call sites і stacks.



## References

- [1] [Sector 7 – Don’t Talk All at Once! Elevating Privileges on macOS by Audit Token Spoofing](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [2] [Apple – About the security content of macOS Ventura 13.4 (CVE‑2023‑32405)](https://support.apple.com/en-us/106333)


{{#include ../../../../../../banners/hacktricks-training.md}}
