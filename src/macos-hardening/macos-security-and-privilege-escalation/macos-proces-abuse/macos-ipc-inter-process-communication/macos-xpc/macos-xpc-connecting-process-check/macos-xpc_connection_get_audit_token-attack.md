# macOS xpc_connection_get_audit_token Атака

{{#include ../../../../../../banners/hacktricks-training.md}}

**Для додаткової інформації дивіться оригінальний пост:** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/). Це короткий виклад:

## Основна інформація про Mach Messages

Якщо ви не знаєте, що таке Mach Messages, почніть з цієї сторінки:


{{#ref}}
../../
{{#endref}}

Наразі пам’ятайте, що ([definition from here](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):\
Mach messages відправляються через _mach port_, який є каналом звʼязку **single receiver, multiple sender**, вбудованим в mach kernel. **Кілька процесів можуть відправляти повідомлення** до mach port, але в будь-який момент **тільки один процес може читати з нього**. Подібно до файлових дескрипторів і сокетів, mach ports виділяються і керуються ядром, а процеси бачать лише ціле число, яке вони можуть використовувати, щоб вказати ядру, яким із їх mach ports вони хочуть користуватися.

## З'єднання XPC

Якщо ви не знаєте, як встановлюється з'єднання XPC, перегляньте:


{{#ref}}
../
{{#endref}}

## Коротко про вразливість

Важливо знати, що **абстракція XPC — це one-to-one з'єднання**, але воно побудоване поверх технології, яка **може мати кількох відправників, отже:**

- Mach ports — одиночний приймач, **multiple sender**.
- Audit token з'єднання XPC — це audit token, **скопійований з найщойно отриманого повідомлення**.
- Отримання **audit token** XPC-з'єднання критично для багатьох **перевірок безпеки**.

Хоча попередня ситуація звучить загрозливо, існують сценарії, де це не викликає проблем ([from here](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):

- Audit tokens часто використовуються для перевірки авторизації, щоб вирішити, чи приймати з'єднання. Оскільки це відбувається за допомогою повідомлення до service port, **з'єднання ще не встановлено**. Більше повідомлень на цьому порті просто оброблятимуться як додаткові запити на з'єднання. Тому будь-які **перевірки перед прийняттям з'єднання не вразливі** (це також означає, що всередині `-listener:shouldAcceptNewConnection:` audit token безпечний). Ми отже **шукаємо XPC-з'єднання, які перевіряють конкретні дії**.
- XPC event handlers обробляються синхронно. Це означає, що обробник події для одного повідомлення має завершити роботу перед тим, як викликатися для наступного, навіть на concurrent dispatch queues. Тому всередині **XPC event handler** audit token не може бути перезаписаний іншими звичайними (не-reply!) повідомленнями.

Існують два різних методи, які можуть бути експлуатовані:

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

Сценарій:

- Два mach сервіси **`A`** і **`B`**, до яких ми обидва можемо підключитися (виходячи з sandbox profile та перевірок авторизації перед прийняттям з'єднання).
- _**A**_ повинен мати **перевірку авторизації** для конкретної дії, яку **`B`** може виконати (але наш додаток — ні).
- Наприклад, якщо B має певні **entitlements** або працює як **root**, він може дозволити A виконати привілейовану дію.
- Для цієї перевірки авторизації **`A`** отримує audit token асинхронно, наприклад викликаючи `xpc_connection_get_audit_token` зсередини **`dispatch_async`**.

> [!CAUTION]
> У цьому випадку атакуючий може спричинити **Race Condition**, зробивши **exploit**, який **просить A виконати дію** кілька разів, одночасно змушуючи **B надсилати повідомлення до `A`**. Коли RC **успішний**, **audit token** від **B** буде скопійований в памʼять **поки** запит нашого **exploit** обробляється A, даючи йому **доступ до привілейованої дії, яку тільки B міг запитати**.

Це сталося з **`A`** як `smd` та **`B`** як `diagnosticd`. Функцію [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) з smb можна використати для встановлення нового привілейованого helper tool (як **root**). Якщо процес, що запускається як root, контактує з **smd**, інші перевірки не проводяться.

Отже, сервіс **B** — це **`diagnosticd`**, бо він працює як **root** і може використовуватись для моніторингу процесу, тож після запуску моніторингу він буде **надсилати кілька повідомлень на секунду.**

Щоб виконати атаку:

1. Ініціюйте **з'єднання** з сервісом `smd`, використовуючи стандартний XPC protocol.
2. Встановіть друге **з'єднання** до `diagnosticd`. На відміну від звичайної процедури, замість створення й відправлення двох нових mach port-ів, client port send right замінюється дублікатом **send right**, пов'язаного із з'єднанням `smd`.
3. В результаті XPC повідомлення можуть бути відправлені до `diagnosticd`, але відповіді від `diagnosticd` перенаправляються до `smd`. Для `smd` виглядає, ніби повідомлення від користувача й `diagnosticd` походять з одного й того ж з'єднання.

![Image depicting the exploit process](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)

4. Далі інструктуйте `diagnosticd` розпочати моніторинг обраного процесу (можливо, власного користувача). Одночасно надсилається потік рутинних повідомлень 1004 до `smd`. Мета — встановити інструмент з підвищеними привілеями.
5. Це викликає race condition у функції `handle_bless`. Ключовим є таймінг: виклик `xpc_connection_get_pid` має повернути PID процесу користувача (оскільки привілейований інструмент знаходиться в бандлі додатку користувача). Однак `xpc_connection_get_audit_token`, зокрема у підрутині `connection_is_authorized`, має посилатися на audit token, що належить `diagnosticd`.

## Variant 2: reply forwarding

В XPC (Cross-Process Communication) середовищі, хоча event handlers не виконуються паралельно, обробка reply-повідомлень має особливу поведінку. Конкретно, існують два різні методи відправки повідомлень з очікуванням відповіді:

1. **`xpc_connection_send_message_with_reply`**: тут XPC повідомлення приймається та обробляється на призначеній черзі.
2. **`xpc_connection_send_message_with_reply_sync`**: навпаки, у цьому методі XPC повідомлення приймається та обробляється на поточній dispatch queue.

Ця відмінність критична, бо вона дозволяє можливість **парсингу reply-пакетів одночасно з виконанням XPC event handler**. Зауважте, що хоча `_xpc_connection_set_creds` впроваджує блокування, щоб запобігти частковому перезапису audit token, воно не поширюється на весь об'єкт з'єднання. Це створює вразливість, коли audit token може бути замінений у проміжку між парсингом пакета й виконанням його event handler.

Щоб експлуатувати цю вразливість, потрібна така конфігурація:

- Два mach сервіси, назвемо їх **`A`** і **`B`**, до яких обидва можна підключитися.
- Сервіс **`A`** повинен мати перевірку авторизації для конкретної дії, яку може виконати лише **`B`** (а не користувацький додаток).
- Сервіс **`A`** повинен відправити повідомлення з очікуванням відповіді.
- Користувач може надіслати повідомлення до **`B`**, на яке той відповість.

Процес експлуатації:

1. Чекайте, поки сервіс **`A`** надішле повідомлення, що очікує відповіді.
2. Замість прямої відповіді `A`, reply port перехоплюється й використовується для відправки повідомлення до сервісу **`B`**.
3. Після цього надсилається повідомлення, що стосується забороненої дії, з очікуванням, що воно буде оброблене одночасно з відповіддю від **`B`**.

Нижче наведено візуальне представлення описаного сценарію атаки:

!\[https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png]\(../../../../../../images/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../images/image (33).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Проблеми з виявленням

- **Складно знайти випадки**: Пошук місць використання `xpc_connection_get_audit_token` був складним як статично, так і динамічно.
- **Методологія**: Frida використовувався для хукання `xpc_connection_get_audit_token`, фільтруючи виклики, що не походять з event handlers. Однак цей метод обмежувався захопленим процесом і вимагав активного використання.
- **Аналітичні інструменти**: IDA/Ghidra застосовувалися для вивчення досяжних mach сервісів, але процес був трудомістким, ускладнений викликами, що стосуються dyld shared cache.
- **Обмеження скриптів**: Спроби автоматизувати аналіз викликів `xpc_connection_get_audit_token` з `dispatch_async` блоків були ускладнені складнощами парсингу блоків і взаємодії з dyld shared cache.

## Виправлення <a href="#the-fix" id="the-fix"></a>

- **Звітування**: Рапорт був поданий до Apple з описом загальних і специфічних проблем, знайдених у `smd`.
- **Відповідь Apple**: Apple виправила проблему в `smd`, замінивши `xpc_connection_get_audit_token` на `xpc_dictionary_get_audit_token`.
- **Сутність виправлення**: Функцію `xpc_dictionary_get_audit_token` вважають безпечною, оскільки вона отримує audit token безпосередньо з mach message, повʼязаного з отриманим XPC повідомленням. Однак вона не є частиною публічного API, подібно до `xpc_connection_get_audit_token`.
- **Відсутність загального фіксу**: Невідомо, чому Apple не впровадила більш загальне рішення, наприклад відкидати повідомлення, що не відповідають збереженому audit token з'єднання. Можливо, є сценарії, де зміна audit token є легітимною (наприклад при використанні `setuid`).
- **Поточний стан**: Проблема зберігається в iOS 17 та macOS 14, що ускладнює її ідентифікацію та розуміння.

## Пошук вразливих шляхів коду на практиці (2024–2025)

При аудиті XPC сервісів на цю класу багів, зосередьтеся на авторизації, що виконується поза обробником повідомлення або одночасно з обробкою reply.

Підказки для статичного триажу:
- Шукайте виклики `xpc_connection_get_audit_token`, досяжні з блоків, поставлених у чергу через `dispatch_async`/`dispatch_after` або інших worker queues, що працюють поза message handler.
- Шукайте helper-и авторизації, які змішують стан на рівні з'єднання й на рівні повідомлення (наприклад, отримують PID з `xpc_connection_get_pid`, але audit token з `xpc_connection_get_audit_token`).
- В NSXPC коді перевірте, що перевірки виконуються в `-listener:shouldAcceptNewConnection:`, або для перевірок на рівні повідомлення переконайтесь, що реалізація використовує audit token конкретного повідомлення (наприклад, словник повідомлення через `xpc_dictionary_get_audit_token` у низькорівневому коді).

Поради для динамічного триажу:
- Hook-айте `xpc_connection_get_audit_token` і позначайте виклики, стек користувача яких не містить шлях доставки подій (наприклад, `_xpc_connection_mach_event`). Приклад Frida hook:
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
- На macOS інструментування захищених/Apple бінарних файлів може вимагати вимкненого SIP або середовища розробки; віддавайте перевагу тестуванню власних збірок або userland services.
- Для reply-forwarding races (Variant 2) контролюйте одночасний розбір reply packets, роблячи fuzzing timings `xpc_connection_send_message_with_reply` проти звичайних запитів, та перевіряйте, чи можна вплинути на effective audit token, що використовується під час авторизації.

## Exploitation primitives, які вам, ймовірно, знадобляться

- Multi-sender setup (Variant 1): створіть з’єднання до A і B; дублюйте send right клієнтського порту A і використайте його як client port для B, щоб replies від B доставлялися до A.
```c
// Duplicate a SEND right you already hold
mach_port_t dup;
mach_port_insert_right(mach_task_self(), a_client, a_client, MACH_MSG_TYPE_MAKE_SEND);
dup = a_client; // use `dup` when crafting B’s connect packet instead of a fresh client port
```
- Reply hijack (Variant 2): захопіть send-once right з A’s pending request (reply port), потім надішліть спеціально сформоване повідомлення до B, використовуючи цей reply port, щоб відповідь B потрапила на A, поки ваш привілейований запит обробляється.

Це вимагає низькорівневого mach message crafting для XPC bootstrap і форматів повідомлень; перегляньте mach/XPC primer сторінки в цьому розділі для точних макетів пакетів і flags.

## Корисні інструменти

- XPC sniffing/dynamic inspection: gxpc (open-source XPC sniffer) може допомогти перебрати підключення та спостерігати трафік для підтвердження налаштувань з кількома відправниками і таймінгу. Приклад: `gxpc -p <PID> --whitelist <service-name>`.
- Classic dyld interposing for libxpc: перехоплюйте (interpose) виклики `xpc_connection_send_message*` та `xpc_connection_get_audit_token` для логування call sites та стеків під час black-box testing.

## Посилання

- Sector 7 – Don’t Talk All at Once! Elevating Privileges on macOS by Audit Token Spoofing: <https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/>
- Apple – About the security content of macOS Ventura 13.4 (CVE‑2023‑32405): <https://support.apple.com/en-us/106333>


{{#include ../../../../../../banners/hacktricks-training.md}}
