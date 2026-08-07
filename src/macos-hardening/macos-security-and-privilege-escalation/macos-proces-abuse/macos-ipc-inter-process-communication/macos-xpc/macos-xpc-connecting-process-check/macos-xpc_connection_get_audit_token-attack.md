# macOS xpc_connection_get_audit_token Attack

{{#include ../../../../../../banners/hacktricks-training.md}}

**Для отримання додаткової інформації перегляньте оригінальний допис:** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/). Це короткий виклад:<sup>[[1]](#references)</sup>

## Основна інформація про Mach Messages

Якщо ви не знаєте, що таке Mach Messages, почніть із цієї сторінки:


{{#ref}}
../../
{{#endref}}

Наразі запам’ятайте, що ([визначення звідси](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):<sup>[[1]](#references)</sup>\
Mach messages надсилаються через _mach port_, який є вбудованим у ядро mach каналом комунікації **з одним отримувачем і кількома відправниками**. **Кілька процесів можуть надсилати messages** до mach port, але в будь-який момент **лише один процес може читати з нього**. Як і file descriptors та sockets, mach ports виділяються та керуються ядром, а процеси бачать лише ціле число, яке вони можуть використовувати, щоб вказати ядру, який із їхніх mach ports потрібно використати.

## XPC Connection

Якщо ви не знаєте, як встановлюється XPC connection, перегляньте:


{{#ref}}
../
{{#endref}}

## Короткий опис вразливості

Вам важливо знати, що **абстракція XPC являє собою з’єднання один-до-одного**, але базується на технології, яка **може мати кілька відправників, тому:**

- Mach ports мають одного отримувача та **кількох відправників**.
- Audit token XPC connection — це audit token, **скопійований з останнього отриманого message**.
- Отримання **audit token** XPC connection є критично важливим для багатьох **перевірок безпеки**.<sup>[[1]](#references)</sup>

Хоча попередня ситуація виглядає багатообіцяльною, існують сценарії, у яких це не спричинить проблем ([звідси](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):<sup>[[1]](#references)</sup>

- Audit tokens часто використовуються для перевірки авторизації, щоб вирішити, чи приймати connection. Оскільки це відбувається за допомогою message до service port, **connection ще не встановлено**. Подальші messages на цьому port просто оброблятимуться як додаткові запити на встановлення connection. Отже, **перевірки до прийняття connection не є вразливими** (це також означає, що в межах `-listener:shouldAcceptNewConnection:` audit token є безпечним). Тому ми **шукаємо XPC connections, які перевіряють конкретні дії**.
- XPC event handlers обробляються синхронно. Це означає, що event handler для одного message має завершитися до його виклику для наступного message, навіть у concurrent dispatch queues. Тому всередині **XPC event handler audit token не може бути перезаписаний** іншими звичайними (не reply!) messages.<sup>[[1]](#references)</sup>

Існує два різні методи, за допомогою яких це може бути експлуатовано:

1. Variant1:
- **Exploit** **підключається** до service **A** і service **B**
- Service **B** може викликати **привілейовану функціональність** у service A, яку користувач не може викликати
- Service **A** викликає **`xpc_connection_get_audit_token`**, перебуваючи _**не**_ всередині **event handler** для connection у **`dispatch_async`**.
- Отже, **інший** message може **перезаписати Audit Token**, оскільки він диспетчеризується асинхронно поза event handler.
- Exploit передає **service B SEND right до service A**.
- Тому svc **B** фактично **надсилатиме** **messages** до service **A**.
- **Exploit** намагається **викликати привілейовану дію.** У разі RC svc **A** **перевіряє** авторизацію цієї **дії**, поки **svc B перезаписує Audit token** (надаючи exploit доступ до виклику привілейованої дії).
2. Variant 2:
- Service **B** може викликати **привілейовану функціональність** у service A, яку користувач не може викликати
- Exploit підключається до **service A**, який **надсилає** exploit **message, що очікує відповідь**, через певний **replay** **port**.
- Exploit надсилає **service** B message, передаючи **цей reply port**.
- Коли service **B** відповідає, він **надсилає message до service A**, **поки** **exploit** надсилає інший **message до service A**, намагаючись **досягти привілейованої функціональності** та очікуючи, що відповідь від service B перезапише Audit token у потрібний момент (Race Condition).

## Variant 1: виклик xpc_connection_get_audit_token поза event handler <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

Сценарій:

- Два mach services — **`A`** і **`B`**, до яких ми можемо підключитися (залежно від sandbox profile та перевірок авторизації перед прийняттям connection).
- _**A**_ має виконувати **перевірку авторизації** для певної дії, яку може пройти **`B`** (але не наш app).
- Наприклад, якщо B має певні **entitlements** або працює від імені **root**, він може дозволяти запитувати A про виконання привілейованої дії.
- Для цієї перевірки авторизації **`A`** отримує audit token асинхронно, наприклад викликаючи `xpc_connection_get_audit_token` з `dispatch_async`.

> [!CAUTION]
> У цьому випадку attacker може створити **Race Condition**, створивши **exploit**, який кілька разів просить **A** виконати дію, одночасно змушуючи **B надсилати messages до `A`**. Коли RC є **успішною**, **audit token** **B** буде скопійовано в пам’ять **під час обробки запиту нашого exploit** процесом A, надаючи йому **доступ до привілейованої дії, яку міг запитувати лише B**.

Це сталося з **`A`** як `smd` і **`B`** як `diagnosticd`. Функцію [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) із smb можна використати для встановлення нового привілейованого helper tool (як **root**). Якщо **процес, що працює від імені root, контактує з** **smd**, додаткові перевірки не виконуються.

Тому service **B** — це **`diagnosticd`**, оскільки він працює від імені **root** і може використовуватися для **моніторингу** процесу; після початку моніторингу він **надсилатиме кілька messages на секунду.**

Щоб виконати attack:

1. Ініціюйте **connection** до service з іменем `smd`, використовуючи стандартний XPC protocol.
2. Створіть вторинне **connection** до `diagnosticd`. На відміну від звичайної процедури, замість створення та надсилання двох нових mach ports право client port send замінюється дублікатом **send right**, пов’язаним із connection до `smd`.
3. У результаті XPC messages можуть диспетчеризуватися до `diagnosticd`, але відповіді від `diagnosticd` перенаправляються до `smd`. Для `smd` це виглядає так, ніби messages і від користувача, і від `diagnosticd` надходять з одного connection.

![Зображення, що демонструє процес exploit](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)

4. Наступний крок полягає в тому, щоб доручити `diagnosticd` розпочати моніторинг вибраного процесу (можливо, власного процесу користувача). Одночасно до `smd` надсилається flood зі звичайних messages 1004. Мета — встановити tool із підвищеними privileges.
5. Ця дія запускає race condition у функції `handle_bless`. Критично важливо, щоб виклик функції `xpc_connection_get_pid` повернув PID процесу користувача (оскільки privileged tool розташований у app bundle користувача). Водночас функція `xpc_connection_get_audit_token`, зокрема в підпрограмі `connection_is_authorized`, має посилатися на audit token, що належить `diagnosticd`.<sup>[[1]](#references)</sup>

## Variant 2: перенаправлення reply

У середовищі XPC (Cross-Process Communication), хоча event handlers не виконуються одночасно, обробка reply messages має унікальну поведінку. Зокрема, існує два різні методи надсилання messages, які очікують reply:

1. **`xpc_connection_send_message_with_reply`**: тут XPC message отримується та обробляється у визначеній queue.
2. **`xpc_connection_send_message_with_reply_sync`**: натомість у цьому методі XPC message отримується та обробляється в поточній dispatch queue.

Ця відмінність є критично важливою, оскільки створює можливість **одночасного аналізу reply packets та виконання XPC event handler**. Зокрема, хоча `_xpc_connection_set_creds` використовує locking для захисту від часткового перезапису audit token, цей захист не поширюється на весь connection object. У результаті виникає вразливість, за якої audit token може бути замінений у проміжку між аналізом packet і виконанням його event handler.

Для експлуатації цієї вразливості потрібне таке налаштування:

- Два mach services, позначені як **`A`** і **`B`**, до обох з яких можна встановити connection.
- Service **`A`** має містити перевірку авторизації для певної дії, яку може виконати лише **`B`** (app користувача не може).
- Service **`A`** має надсилати message, що очікує reply.
- Користувач може надсилати message до **`B`**, який відповідатиме на нього.

Процес exploitation складається з таких кроків:

1. Дочекайтеся, поки service **`A`** надішле message, що очікує reply.
2. Замість прямої відповіді **`A`** reply port перехоплюється та використовується для надсилання message до service **`B`**.
3. Після цього диспетчеризується message, пов’язаний із забороненою дією, з очікуванням, що його буде оброблено одночасно з reply від **`B`**.<sup>[[1]](#references)</sup>

Нижче наведено візуальне представлення описаного сценарію attack:

!\[https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png]\(../../../../../../images/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../images/image (33).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Проблеми під час виявлення

- **Складнощі з пошуком екземплярів**: пошук екземплярів використання `xpc_connection_get_audit_token` був складним як статично, так і динамічно.
- **Методологія**: Frida використовувалася для hook функції `xpc_connection_get_audit_token` із фільтрацією викликів, які не походять з event handlers. Однак цей метод був обмежений процесом, у якому встановлено hook, і вимагав активного використання.
- **Інструменти аналізу**: такі tools, як IDA/Ghidra, використовувалися для дослідження доступних mach services, але процес був тривалим і ускладнювався викликами, пов’язаними зі shared cache dyld.
- **Обмеження scripting**: спроби автоматизувати аналіз викликів `xpc_connection_get_audit_token` із блоків `dispatch_async` ускладнювалися труднощами аналізу блоків та взаємодією зі shared cache dyld.<sup>[[1]](#references)</sup>

## Виправлення <a href="#the-fix" id="the-fix"></a>

- **Повідомлені проблеми**: Apple було надіслано report із описом загальних і конкретних проблем, виявлених у `smd`.
- **Відповідь Apple**: Apple виправила проблему в `smd`, замінивши `xpc_connection_get_audit_token` на `xpc_dictionary_get_audit_token`.<sup>[[1]](#references)[[2]](#references)</sup>
- **Суть виправлення**: функція `xpc_dictionary_get_audit_token` вважається безпечною, оскільки отримує audit token безпосередньо з mach message, пов’язаного з отриманим XPC message. Однак вона не є частиною public API, так само як і `xpc_connection_get_audit_token`.
- **Відсутність комплекснішого виправлення**: залишається незрозумілим, чому Apple не реалізувала комплексніше виправлення, наприклад відкидання messages, які не відповідають збереженому audit token connection. Причиною може бути можливість легітимних змін audit token у певних сценаріях (наприклад, під час використання `setuid`).
- **Поточний стан**: проблема зберігається в iOS 17 і macOS 14, що створює труднощі для тих, хто намагається її виявити та зрозуміти.<sup>[[1]](#references)</sup>

## Пошук вразливих code paths на практиці (2024–2025)

Під час аудиту XPC services на наявність цього класу помилок зосередьтеся на авторизації, яка виконується поза event handler message або одночасно з обробкою reply.

Підказки для статичного triage:
- Шукайте виклики `xpc_connection_get_audit_token`, доступні з блоків, поставлених у queue через `dispatch_async`/`dispatch_after`, або в інші worker queues, які виконуються поза message handler.
- Шукайте authorization helpers, які змішують стан connection і message (наприклад, отримують PID через `xpc_connection_get_pid`, але audit token — через `xpc_connection_get_audit_token`).
- У коді NSXPC перевірте, що перевірки виконуються в `-listener:shouldAcceptNewConnection:` або, для перевірок на рівні message, що реалізація використовує audit token конкретного message (наприклад, dictionary message через `xpc_dictionary_get_audit_token` у коді нижчого рівня).

Підказки для dynamic triage:
- Встановіть hook на `xpc_connection_get_audit_token` і позначайте виклики, user stack яких не містить шляху доставки event (наприклад, `_xpc_connection_mach_event`). Приклад Frida hook:
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
- У macOS інструментування захищених/Apple binaries може вимагати вимкнення SIP або development environment; для тестування краще використовувати власні збірки чи userland services.
- Для reply-forwarding races (Variant 2) відстежуйте одночасний парсинг reply packets, змінюючи таймінги `xpc_connection_send_message_with_reply` порівняно зі звичайними запитами та перевіряючи, чи можна вплинути на effective audit token, який використовується під час авторизації.

## Exploitation primitives, які вам, імовірно, знадобляться

- Multi-sender setup (Variant 1): створіть connections до A і B; дублюйте send right клієнтського порту A та використовуйте його як клієнтський порт B, щоб replies від B доставлялися до A.
```c
// Duplicate a SEND right you already hold
mach_port_t dup;
mach_port_insert_right(mach_task_self(), a_client, a_client, MACH_MSG_TYPE_MAKE_SEND);
dup = a_client; // use `dup` when crafting B’s connect packet instead of a fresh client port
```
- Reply hijack (Variant 2): захопити send-once right із pending request процесу A (reply port), а потім надіслати crafted message процесу B, використовуючи цей reply port, щоб reply процесу B надійшов до A, поки обробляється ваш privileged request.

Це вимагає low-level створення mach messages для bootstrap XPC і форматів messages; перегляньте сторінки з primer про mach/XPC у цьому розділі, щоб дізнатися точні packet layouts і flags.

## Корисні інструменти

- XPC sniffing/dynamic inspection: gxpc (open-source XPC sniffer) може допомогти перерахувати connections і спостерігати за traffic, щоб перевірити multi-sender setups і timing. Приклад: `gxpc -p <PID> --whitelist <service-name>`.
- Classic dyld interposing для libxpc: виконайте interpose для `xpc_connection_send_message*` і `xpc_connection_get_audit_token`, щоб під час black-box testing журналювати call sites і stacks.



## References

- [1] [Sector 7 – Не говоріть усі одночасно! Підвищення привілеїв у macOS за допомогою підроблення Audit Token](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [2] [Apple – Про вміст security updates macOS Ventura 13.4 (CVE‑2023‑32405)](https://support.apple.com/en-us/106333)


{{#include ../../../../../../banners/hacktricks-training.md}}
