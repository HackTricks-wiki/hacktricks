# macOS Thread Injection via Task port

{{#include ../../../../banners/hacktricks-training.md}}

## Code

- [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
- [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)

## 1. Thread Hijacking

Спочатку функція `task_threads()` викликається для task port, щоб отримати список thread із віддаленого task. Для hijacking обирається thread. Цей підхід відрізняється від звичайних методів code injection, оскільки створення нового remote thread заборонене через mitigation, яка блокує `thread_create_running()`.<sup>[1]</sup>

Щоб керувати thread, викликається `thread_suspend()`, що зупиняє його виконання.<sup>[1]</sup>

Єдині операції, дозволені над remote thread, полягають у його **зупиненні** та **запуску**, а також в **отриманні**/**зміні** значень його регістрів. Remote function calls ініціюються встановленням регістрів `x0`–`x7` у значення **аргументів**, налаштуванням `pc` на потрібну функцію та відновленням виконання thread. Щоб thread не аварійно завершився після повернення, потрібно виявити момент повернення.<sup>[1]</sup>

Один зі способів полягає в реєстрації **exception handler** для remote thread за допомогою `thread_set_exception_ports()` і встановленні регістра `lr` у недійсну адресу перед викликом функції. Після виконання функції це спричиняє exception, надсилаючи повідомлення на exception port і даючи змогу перевірити стан thread, щоб отримати return value. Альтернативний спосіб, запозичений з exploit *triple_fetch* Ian Beer, полягає у встановленні `lr` у нескінченний цикл; після цього регістри thread безперервно перевіряються, доки `pc` не вкаже на цю інструкцію.<sup>[1]</sup>

## 2. Mach ports for communication

Наступний етап передбачає створення Mach ports для забезпечення communication із remote thread. Ці ports використовуються для передавання довільних send/receive rights між tasks.<sup>[1]</sup>

Для двонапрямленої communication створюються два Mach receive rights: один у local task, а інший у remote task. Потім send right для кожного port передається до відповідного counterpart task, що дає змогу обмінюватися повідомленнями.<sup>[1]</sup>

Якщо зосередитися на local port, receive right належить local task. Port створюється за допомогою `mach_port_allocate()`. Проблема полягає в передаванні send right до цього port у remote task.<sup>[1]</sup>

Один зі способів полягає у використанні `thread_set_special_port()` для розміщення send right до local port у `THREAD_KERNEL_PORT` remote thread. Потім remote thread змушується викликати `mach_thread_self()`, щоб отримати send right.<sup>[1]</sup>

Для remote port процес фактично виконується у зворотному порядку. Remote thread вказується створити Mach port за допомогою `mach_reply_port()` (оскільки `mach_port_allocate()` непридатна через механізм повернення значення). Після створення port у remote thread викликається `mach_port_insert_right()` для створення send right. Потім це right зберігається в kernel за допомогою `thread_set_special_port()`. У local task для remote thread використовується `thread_get_special_port()`, щоб отримати send right до щойно виділеного Mach port у remote task.<sup>[1]</sup>

Після виконання цих кроків Mach ports створено, що закладає основу для двонапрямленої communication.<sup>[1]</sup>

## 3. Basic Memory Read/Write Primitives

У цьому розділі розглядається використання execute primitive для створення базових memory read/write primitives. Ці початкові кроки є важливими для отримання більшого контролю над remote process, хоча primitives на цьому етапі не матимуть широкого застосування. Невдовзі їх буде оновлено до більш просунутих версій.<sup>[1]</sup>

### Memory reading and writing using the execute primitive

Мета полягає у виконанні memory reading і writing за допомогою конкретних функцій. Для **reading memory**:
```c
uint64_t read_func(uint64_t *address) {
return *address;
}
```
Для **запису в пам’ять**:
```c
void write_func(uint64_t *address, uint64_t value) {
*address = value;
}
```
Ці функції відповідають наведеному нижче асемблерному коду:
```
_read_func:
ldr x0, [x0]
ret
_write_func:
str x1, [x0]
ret
```
### Визначення відповідних функцій

Сканування поширених бібліотек виявило відповідних кандидатів для цих операцій:<sup>[1]</sup>

1. **Читання пам’яті — `property_getName()`** (libobjc):
```c
const char *property_getName(objc_property_t prop) {
return prop->name;
}
```
2. **Запис у пам’ять — `_xpc_int64_set_value()`** (libxpc):
```c
__xpc_int64_set_value:
str x1, [x0, #0x18]
ret
```
Щоб виконати 64-бітовий запис за довільною адресою:
```c
_xpc_int64_set_value(address - 0x18, value);
```
За наявності цих примітивів створення спільної пам’яті стає наступним кроком, що означає значний прогрес у контролі над віддаленим процесом.<sup>[1]</sup>

## 4. Налаштування спільної пам’яті

Мета полягає у встановленні спільної пам’яті між локальними та віддаленими task, що спрощує передавання даних і забезпечує виклик функцій із кількома аргументами. Підхід використовує `libxpc` та тип об’єкта `OS_xpc_shmem`, побудований на Mach memory entries.<sup>[1]</sup>

### Огляд процесу

1. **Виділення пам’яті**
* Виділити пам’ять для спільного використання за допомогою `mach_vm_allocate()`.
* Використати `xpc_shmem_create()` для створення об’єкта `OS_xpc_shmem` для виділеної області.
2. **Створення спільної пам’яті у віддаленому процесі**
* Виділити пам’ять для об’єкта `OS_xpc_shmem` у віддаленому процесі (`remote_malloc`).
* Скопіювати локальний шаблон об’єкта; виправлення вбудованого Mach send right за зміщенням `0x18` все ще необхідне.
3. **Виправлення Mach memory entry**
* Вставити send right за допомогою `thread_set_special_port()` і перезаписати поле `0x18` іменем віддаленого entry.
4. **Завершення**
* Перевірити віддалений об’єкт і замапити його віддаленим викликом `xpc_shmem_remote()`.

## 5. Отримання повного контролю

Після отримання довільного виконання та back-channel через спільну пам’ять ви фактично контролюєте цільовий процес:<sup>[1]</sup>

* **Довільне читання/запис пам’яті** — використовувати `memcpy()` між локальними та спільними областями.
* **Виклики функцій із > 8 аргументами** — розміщувати додаткові аргументи у стеку відповідно до calling convention arm64.
* **Передавання Mach port** — передавати rights у Mach-повідомленнях через встановлені ports.
* **Передавання file descriptor** — використовувати fileports (див. *triple_fetch*).

Усе це загорнуто в бібліотеку [`threadexec`](https://github.com/bazad/threadexec) для зручного повторного використання.

---

## 6. Нюанси Apple Silicon (arm64e)

На пристроях Apple Silicon (arm64e) **Pointer Authentication Codes (PAC)** захищають усі адреси повернення та багато вказівників на функції. Техніки thread-hijacking, які *повторно використовують наявний код*, продовжують працювати, оскільки початкові значення в `lr`/`pc` уже містять дійсні PAC-підписи. Проблеми виникають, коли ви намагаєтеся перейти до пам’яті, контрольованої attacker:

1. Виділити виконувану пам’ять усередині цільового процесу (віддалені `mach_vm_allocate` + `mprotect(PROT_EXEC)`).
2. Скопіювати payload.
3. Усередині *віддаленого* процесу підписати вказівник:
```c
uint64_t ptr = (uint64_t)payload;
ptr = ptrauth_sign_unauthenticated((void*)ptr, ptrauth_key_asia, 0);
```
4. Установіть `pc = ptr` у стані захопленого thread.

Альтернативно, дотримуйтеся сумісності з PAC, об’єднуючи наявні gadgets/functions (традиційний ROP).

## 7. Виявлення та посилення захисту за допомогою EndpointSecurity

Framework **EndpointSecurity (ES)** надає kernel events, які дають змогу захисникам спостерігати за спробами thread injection або блокувати їх:

* `ES_EVENT_TYPE_AUTH_GET_TASK` – спрацьовує, коли process запитує port іншого task (наприклад, через `task_for_pid()`).
* `ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE` – генерується щоразу, коли thread створюється в *іншому* task.<sup>[3]</sup>
* `ES_EVENT_TYPE_NOTIFY_THREAD_SET_STATE` (додано в macOS 14 Sonoma) – вказує на маніпуляцію registers наявного thread.

Мінімальний Swift client, який виводить події remote thread:
```swift
import EndpointSecurity

let client = try! ESClient(subscriptions: [.notifyRemoteThreadCreate]) {
(_, msg) in
if let evt = msg.remoteThreadCreate {
print("[ALERT] remote thread in pid \(evt.target.pid) by pid \(evt.thread.pid)")
}
}
RunLoop.main.run()
```
Виконання запитів за допомогою **osquery** ≥ 5.8:
```sql
SELECT target_pid, source_pid, target_path
FROM es_process_events
WHERE event_type = 'REMOTE_THREAD_CREATE';
```
### Міркування щодо Hardened Runtime

Розповсюдження вашого застосунку **без** entitlement `com.apple.security.get-task-allow` не дозволяє зловмисникам без прав root отримувати його task-port. System Integrity Protection (SIP) все ще блокує доступ до багатьох Apple binaries, але стороннє програмне забезпечення має явно відмовитися від цього захисту.

## 8. Нещодавні публічні інструменти (2023-2025)

| Tool | Year | Remarks |
|------|------|---------|
| [`task_vaccine`](https://github.com/rodionovd/task_vaccine) | 2023 | Компактний PoC, що демонструє захоплення потоків із підтримкою PAC у Ventura/Sonoma |
| `remote_thread_es` | 2024 | EndpointSecurity helper, який кілька EDR-вендорів використовують для виявлення подій `REMOTE_THREAD_CREATE` |

> Ознайомлення з вихідним кодом цих проєктів допоможе зрозуміти зміни API, запроваджені в macOS 13/14, і зберігати сумісність між Intel ↔ Apple Silicon.

## References

- [1] [Обхід обмежень для platform binaries за допомогою task_threads() - bazad.github.io](https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/)
- [2] [rodionovd/task_vaccine - GitHub](https://github.com/rodionovd/task_vaccine)
- [3] [ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE - Документація Apple для розробників](https://developer.apple.com/documentation/endpointsecurity/es_event_type_notify_remote_thread_create)

{{#include ../../../../banners/hacktricks-training.md}}
