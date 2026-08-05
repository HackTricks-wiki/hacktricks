# macOS xpc_connection_get_audit_token Attack

{{#include ../../../../../../banners/hacktricks-training.md}}

**Для отримання додаткової інформації перегляньте оригінальний пост:** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/). Це короткий виклад:

## Базова інформація про Mach Messages

Якщо ви не знаєте, що таке Mach Messages, почніть із цієї сторінки:


{{#ref}}
../../
{{#endref}}

Поки що запам’ятайте, що ([визначення звідси](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):\
Mach messages надсилаються через _mach port_, що є каналом **комунікації з одним отримувачем і кількома відправниками**, вбудованим у mach kernel. **Кілька процесів можуть надсилати messages** до mach port, але в будь-який момент **лише один процес може читати з нього**. Як і file descriptors та sockets, mach ports виділяються та керуються kernel, а процеси бачать лише ціле число, яке вони можуть використовувати, щоб вказати kernel, який зі своїх mach ports вони хочуть використати.

## XPC Connection

Якщо ви не знаєте, як встановлюється XPC connection, перегляньте:


{{#ref}}
../
{{#endref}}

## Короткий опис вразливості

Важливо знати, що **абстракція XPC є з’єднанням один-до-одного**, але вона базується на технології, яка **може мати кількох відправників, тому:**

- Mach ports мають одного отримувача та **кількох відправників**.
- Audit token XPC connection — це audit token, **скопійований з останнього отриманого message**.
- Отримання **audit token** XPC connection є критично важливим для багатьох **перевірок безпеки**.<sup>[[1]](#references)</sup>

Хоча попередня ситуація здається перспективною, існують сценарії, у яких вона не спричинить проблем ([звідси](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):

- Audit tokens часто використовуються для authorization check, щоб вирішити, чи приймати connection. Оскільки це відбувається за допомогою message до service port, **connection ще не встановлено**. Наступні messages на цьому port просто оброблятимуться як додаткові connection requests. Тому **перевірки до прийняття connection не є вразливими** (це також означає, що в межах `-listener:shouldAcceptNewConnection:` audit token є безпечним). Отже, нас цікавлять XPC connections, які перевіряють конкретні дії.
- XPC event handlers обробляються синхронно. Це означає, що event handler для одного message має завершити роботу до його виклику для наступного message, навіть у concurrent dispatch queues. Тому всередині **XPC event handler audit token не може бути перезаписаний** іншими звичайними (не reply!) messages.<sup>[[1]](#references)</sup>

Існує два різні методи, за допомогою яких це може бути exploitable:

1. Variant1:
- **Exploit** **підключається** до service **A** і service **B**
- Service **B** може викликати **privileged functionality** у service A, яку користувач не може викликати
- Service **A** викликає **`xpc_connection_get_audit_token`**, перебуваючи _**не**_ всередині **event handler** для connection у **`dispatch_async`**.
- Отже, **інший** message може **перезаписати Audit Token**, оскільки він dispatch-иться асинхронно поза event handler.
- Exploit передає service **B** право **SEND** до service A.
- Тому svc **B** фактично **надсилатиме** **messages** до service **A**.
- **Exploit** намагається **викликати privileged action**. У RC svc **A** **перевіряє** authorization для цієї **дії**, поки **svc B перезаписав Audit token** (надаючи exploit доступ до виклику privileged action).
2. Variant 2:
- Service **B** може викликати **privileged functionality** у service A, яку користувач не може викликати
- Exploit підключається до **service A**, який **надсилає** exploit **message, що очікує відповідь**, через спеціальний **replay** **port**.
- Exploit надсилає service B message, передаючи **цей reply port**.
- Коли service **B** відповідає, він **надсилає message до service A**, **поки** **exploit** надсилає інший **message до service A**, намагаючись **досягти privileged functionality**, очікуючи, що reply від service B перезапише Audit token у потрібний момент (Race Condition).

## Variant 1: calling xpc_connection_get_audit_token outside of an event handler <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

Сценарій:

- Два mach services — **`A`** і **`B`**, до яких ми можемо підключитися (залежно від sandbox profile та authorization checks перед прийняттям connection).
- _**A**_ має виконувати **authorization check** для конкретної дії, яку **B** може пройти (але наш app не може).
- Наприклад, якщо B має певні **entitlements** або працює як **root**, він може дозволити йому попросити A виконати privileged action.
- Для цього authorization check **A** асинхронно отримує audit token, наприклад викликаючи `xpc_connection_get_audit_token` з `dispatch_async`.

> [!CAUTION]
> У цьому випадку attacker може ініціювати **Race Condition**, створивши **exploit**, який кілька разів просить A виконати action, одночасно змушуючи **B надсилати messages до `A`**. Коли RC **успішний**, **audit token** від **B** буде скопійований у memory **під час обробки** request від нашого **exploit** процесом A, надаючи йому **доступ до privileged action**, який може запросити лише B.

Це сталося з **`A`** як `smd` і **`B`** як `diagnosticd`. Функцію [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) з smb можна використовувати для встановлення нового privileged helper tool (як **root**). Якщо **process running as root contact** **smd**, інші checks виконуватися не будуть.

Тому service **B** — це **`diagnosticd`**, оскільки він працює як **root** і може використовуватися для **моніторингу** process, тож після початку моніторингу він **надсилатиме кілька messages на секунду.**

Для виконання атаки:

1. Ініціюйте **connection** до service з назвою `smd`, використовуючи стандартний XPC protocol.
2. Створіть secondary **connection** до `diagnosticd`. На відміну від звичайної процедури, замість створення й надсилання двох нових mach ports client port send right замінюється дублікатом **send right**, пов’язаного з connection до `smd`.
3. У результаті XPC messages можуть dispatch-итися до `diagnosticd`, але responses від `diagnosticd` перенаправляються до `smd`. Для `smd` виглядає так, ніби messages і від user, і від `diagnosticd` походять з одного connection.

![Image depicting the exploit process](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)

4. Наступний крок полягає в тому, щоб наказати `diagnosticd` почати моніторинг вибраного process (потенційно власного process користувача). Одночасно до `smd` надсилається flood звичайних messages 1004. Мета — встановити tool з elevated privileges.
5. Ця дія спричиняє race condition у функції `handle_bless`. Час має критичне значення: виклик функції `xpc_connection_get_pid` повинен повернути PID process користувача (оскільки privileged tool розташований у app bundle користувача). Однак функція `xpc_connection_get_audit_token`, зокрема в subroutine `connection_is_authorized`, повинна посилатися на audit token, що належить `diagnosticd`.<sup>[[1]](#references)</sup>

## Variant 2: reply forwarding

У середовищі XPC (Cross-Process Communication), хоча event handlers не виконуються concurrently, обробка reply messages має унікальну поведінку. Зокрема, існує два різні методи надсилання messages, які очікують reply:

1. **`xpc_connection_send_message_with_reply`**: тут XPC message отримується та обробляється у визначеній queue.
2. **`xpc_connection_send_message_with_reply_sync`**: натомість у цьому методі XPC message отримується та обробляється у поточній dispatch queue.

Ця відмінність є важливою, оскільки допускає можливість **паралельного parsing reply packets із виконанням XPC event handler**. Зокрема, хоча `_xpc_connection_set_creds` реалізує locking для захисту від часткового перезапису audit token, цей захист не поширюється на весь connection object. У результаті виникає вразливість, за якої audit token може бути замінений у проміжку між parsing packet і виконанням його event handler.

Для exploitation цієї вразливості потрібна така конфігурація:

- Два mach services, позначені як **`A`** і **`B`**, до яких можна встановити connection.
- Service **`A`** має містити authorization check для конкретної дії, яку може виконати лише **`B`** (app користувача не може).
- Service **`A`** має надсилати message, що очікує reply.
- User може надіслати message до **`B`**, на який той відповість.

Процес exploitation складається з таких кроків:

1. Дочекайтеся, поки service **`A`** надішле message, що очікує reply.
2. Замість прямої відповіді **`A`** reply port перехоплюється та використовується для надсилання message до service **`B`**.
3. Після цього dispatch-иться message, пов’язаний із забороненою дією, з очікуванням, що він оброблятиметься concurrently з reply від **`B`**.<sup>[[1]](#references)</sup>

Нижче наведено візуальне представлення описаного сценарію атаки:

!\[https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png]\(../../../../../../images/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../images/image (33).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Проблеми під час Discovery

- **Складність пошуку instances**: пошук instances використання `xpc_connection_get_audit_token` був складним як статично, так і динамічно.
- **Methodology**: Frida використовувався для hook функції `xpc_connection_get_audit_token` із фільтрацією викликів, які не походять з event handlers. Однак цей метод був обмежений process, у якому встановлено hook, і вимагав активного використання.
- **Analysis Tooling**: такі tools, як IDA/Ghidra, використовувалися для перевірки доступних mach services, але процес був тривалим і ускладнювався викликами, пов’язаними з dyld shared cache.
- **Scripting Limitations**: спроби написати script для аналізу викликів `xpc_connection_get_audit_token` з `dispatch_async` blocks ускладнювалися parsing blocks та взаємодією з dyld shared cache.<sup>[[1]](#references)</sup>

## The fix <a href="#the-fix" id="the-fix"></a>

- **Reported Issues**: Apple було надіслано report з описом загальних і конкретних проблем, виявлених у `smd`.
- **Apple's Response**: Apple усунула проблему в `smd`, замінивши `xpc_connection_get_audit_token` на `xpc_dictionary_get_audit_token`.<sup>[[1]](#references)[[2]](#references)</sup>
- **Nature of the Fix**: Функція `xpc_dictionary_get_audit_token` вважається безпечною, оскільки отримує audit token безпосередньо з mach message, пов’язаного з отриманим XPC message. Однак вона не є частиною public API, так само як і `xpc_connection_get_audit_token`.
- **Absence of a Broader Fix**: Залишається незрозумілим, чому Apple не реалізувала comprehensive fix, наприклад відкидання messages, які не відповідають збереженому audit token connection. Причиною може бути можливість легітимної зміни audit token у певних сценаріях (наприклад, використання `setuid`).
- **Current Status**: Проблема зберігається в iOS 17 і macOS 14, створюючи труднощі для тих, хто намагається її виявити та зрозуміти.<sup>[[1]](#references)</sup>

## Finding vulnerable code paths in practice (2024–2025)

Під час аудиту XPC services для цього класу вразливостей зосередьтеся на authorization, що виконується поза event handler message або concurrently з обробкою reply.

Підказки для static triage:
- Шукайте виклики `xpc_connection_get_audit_token`, доступні з blocks, поставлених у queue через `dispatch_async`/`dispatch_after`, або інші worker queues, які виконуються поза message handler.
- Шукайте authorization helpers, які змішують state connection і state message (наприклад, отримують PID через `xpc_connection_get_pid`, а audit token — через `xpc_connection_get_audit_token`).
- У NSXPC code перевірте, що checks виконуються в `-listener:shouldAcceptNewConnection:` або, для per-message checks, що implementation використовує per-message audit token (наприклад, dictionary message через `xpc_dictionary_get_audit_token` у lower-level code).

Підказки для dynamic triage:
- Встановіть hook на `xpc_connection_get_audit_token` і позначайте виклики, чий user stack не містить event-delivery path (наприклад, `_xpc_connection_mach_event`). Приклад Frida hook:
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
Примітки:
- У macOS для інструментування захищених бінарних файлів або бінарних файлів Apple може знадобитися вимкнений SIP або середовище розробки; надавайте перевагу тестуванню власних збірок або userland-сервісів.
- Для перегонів під час переспрямування відповідей (Variant 2) відстежуйте паралельний аналіз пакетів відповідей, змінюючи таймінги `xpc_connection_send_message_with_reply` порівняно зі звичайними запитами, і перевіряйте, чи можна вплинути на effective audit token, який використовується під час авторизації.

## Примітиви експлуатації, які вам, імовірно, знадобляться

- Multi-sender setup (Variant 1): створіть підключення до A і B; дублюйте send right клієнтського порту A та використайте його як клієнтський порт B, щоб відповіді B доставлялися до A.
```c
// Duplicate a SEND right you already hold
mach_port_t dup;
mach_port_insert_right(mach_task_self(), a_client, a_client, MACH_MSG_TYPE_MAKE_SEND);
dup = a_client; // use `dup` when crafting B’s connect packet instead of a fresh client port
```
- Reply hijack (Variant 2): захопити send-once right із pending request від A (reply port), а потім надіслати crafted message до B, використовуючи цей reply port, щоб відповідь B потрапила до A, поки ваш privileged request обробляється.

Це вимагає низькорівневого створення mach messages для bootstrap XPC і форматів повідомлень; перегляньте сторінки з primer про mach/XPC у цьому розділі, щоб дізнатися точні packet layouts і flags.

## Корисні інструменти

- XPC sniffing/dynamic inspection: gxpc (open-source XPC sniffer) може допомогти перелічити connections і спостерігати за traffic, щоб перевірити multi-sender setups і timing. Приклад: `gxpc -p <PID> --whitelist <service-name>`.
- Класичний dyld interposing для libxpc: interpose на `xpc_connection_send_message*` і `xpc_connection_get_audit_token`, щоб під час black-box testing записувати call sites і stacks.



## References

- [1] [Sector 7 – Don’t Talk All at Once! Elevating Privileges on macOS by Audit Token Spoofing](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [2] [Apple – About the security content of macOS Ventura 13.4 (CVE‑2023‑32405)](https://support.apple.com/en-us/106333)


{{#include ../../../../../../banners/hacktricks-training.md}}
