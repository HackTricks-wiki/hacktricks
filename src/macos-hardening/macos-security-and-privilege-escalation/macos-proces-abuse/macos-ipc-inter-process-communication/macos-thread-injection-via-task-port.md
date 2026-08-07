# macOS Thread Injection через Task port

{{#include ../../../../banners/hacktricks-training.md}}

## Code

- [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
- [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)

## 1. Thread Hijacking

Спочатку функція `task_threads()` викликається для task port, щоб отримати список thread від remote task. Для hijacking обирається thread. Цей підхід відрізняється від звичайних методів code injection, оскільки створення нового remote thread заборонене через mitigation, яка блокує `thread_create_running()`.<sup>[[1]](#references)</sup>

Щоб отримати контроль над thread, викликається `thread_suspend()`, що зупиняє його виконання.<sup>[[1]](#references)</sup>

Єдині дозволені операції над remote thread полягають у його **зупиненні** та **запуску**, а також в **отриманні**/**зміні** значень його регістрів. Remote function calls ініціюються встановленням у регістри `x0`–`x7` **аргументів**, налаштуванням `pc` на потрібну function і відновленням виконання thread. Щоб thread не завершився аварійно після повернення, необхідно виявити момент повернення.<sup>[[1]](#references)</sup>

Один зі способів полягає в реєстрації **exception handler** для remote thread за допомогою `thread_set_exception_ports()` і встановленні регістра `lr` на недійсну адресу перед викликом function. Це спричиняє exception після виконання function, надсилаючи повідомлення до exception port і дозволяючи перевірити стан thread для отримання return value. Альтернативний спосіб, запозичений з exploit *triple_fetch* Ian Beer, полягає у встановленні `lr` у нескінченний цикл; після цього регістри thread безперервно перевіряються, доки `pc` не вкаже на цю інструкцію.<sup>[[1]](#references)</sup>

## 2. Mach ports для communication

Наступний етап передбачає створення Mach ports для забезпечення communication з remote thread. Ці ports використовуються для передачі довільних send/receive rights між tasks.<sup>[[1]](#references)</sup>

Для двонапрямленої communication створюються два Mach receive rights: один у local task, а інший у remote task. Потім send right для кожного port передається відповідному counterpart task, що забезпечує обмін повідомленнями.<sup>[[1]](#references)</sup>

Розглянемо local port: receive right належить local task. Port створюється за допомогою `mach_port_allocate()`. Проблема полягає в передачі send right до цього port у remote task.<sup>[[1]](#references)</sup>

Одна зі стратегій передбачає використання `thread_set_special_port()` для розміщення send right до local port у `THREAD_KERNEL_PORT` remote thread. Потім remote thread отримує вказівку викликати `mach_thread_self()` для отримання send right.<sup>[[1]](#references)</sup>

Для remote port процес фактично виконується у зворотному порядку. Remote thread отримує вказівку створити Mach port за допомогою `mach_reply_port()` (оскільки `mach_port_allocate()` непридатна через механізм повернення результату). Після створення port у remote thread викликається `mach_port_insert_right()` для встановлення send right. Потім це право зберігається в kernel за допомогою `thread_set_special_port()`. У local task для remote thread використовується `thread_get_special_port()`, щоб отримати send right до щойно виділеного Mach port у remote task.<sup>[[1]](#references)</sup>

Після виконання цих кроків Mach ports створено, що створює основу для двонапрямленої communication.<sup>[[1]](#references)</sup>

## 3. Basic Memory Read/Write Primitives

У цьому розділі розглядається використання execute primitive для створення базових memory read/write primitives. Ці початкові кроки є важливими для отримання більшого контролю над remote process, хоча primitives на цьому етапі ще не матимуть широкого застосування. Незабаром їх буде вдосконалено до більш розширених версій.<sup>[[1]](#references)</sup>

### Memory reading and writing using the execute primitive

Мета полягає у виконанні memory reading and writing за допомогою конкретних functions. Для **читання memory**:
```c
uint64_t read_func(uint64_t *address) {
return *address;
}
```
Для **запису в пам'ять**:
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

Сканування поширених бібліотек виявило відповідних кандидатів для цих операцій:<sup>[[1]](#references)</sup>

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
Щоб виконати 64-бітний запис за довільною адресою:
```c
_xpc_int64_set_value(address - 0x18, value);
```
Після встановлення цих примітивів створення спільної пам’яті стає наступним кроком, що знаменує значний прогрес у контролі над віддаленим процесом.<sup>[[1]](#references)</sup>

## 4. Налаштування спільної пам’яті

Мета полягає у встановленні спільної пам’яті між локальними та віддаленими задачами, що спрощує передавання даних і забезпечує виклик функцій із кількома аргументами. Підхід використовує `libxpc` і тип об’єкта `OS_xpc_shmem`, побудований на Mach memory entries.<sup>[[1]](#references)</sup>

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
* Перевірити віддалений об’єкт і відобразити його за допомогою віддаленого виклику `xpc_shmem_remote()`.

## 5. Отримання повного контролю

Після отримання довільного виконання та back-channel через спільну пам’ять ви фактично контролюєте цільовий процес:<sup>[[1]](#references)</sup>

* **Довільне читання/запис пам’яті** — використовувати `memcpy()` між локальними та спільними областями.
* **Виклики функцій із > 8 аргументами** — розмістити додаткові аргументи у стеку відповідно до arm64 calling convention.
* **Передавання Mach port** — передавати rights у Mach-повідомленнях через встановлені порти.
* **Передавання файлових дескрипторів** — використовувати fileports (див. *triple_fetch*).

Усе це обгорнуто в бібліотеку [`threadexec`](https://github.com/bazad/threadexec) для зручного повторного використання.

---

## 6. Особливості Apple Silicon (arm64e)

На пристроях Apple Silicon (arm64e) **Pointer Authentication Codes (PAC)** захищають усі адреси повернення та багато вказівників на функції. Техніки Thread-hijacking, які *повторно використовують наявний code*, продовжують працювати, оскільки початкові значення в `lr`/`pc` уже містять дійсні PAC-підписи. Проблеми виникають, коли ви намагаєтеся перейти до memory, контрольованої attacker:

1. Виділити executable memory усередині цілі (`mach_vm_allocate` + `mprotect(PROT_EXEC)` на віддаленій стороні).
2. Скопіювати payload.
3. Усередині *віддаленого* процесу підписати вказівник:
```c
uint64_t ptr = (uint64_t)payload;
ptr = ptrauth_sign_unauthenticated((void*)ptr, ptrauth_key_asia, 0);
```
4. Встановіть `pc = ptr` у стані перехопленого потоку.

Альтернативно, дотримуйтеся вимог PAC, об’єднуючи наявні gadgets/functions (традиційний ROP).

## 7. Виявлення та посилення захисту за допомогою EndpointSecurity

Фреймворк **EndpointSecurity (ES)** надає події ядра, які дають змогу захисникам відстежувати або блокувати спроби ін’єкції потоків:

* `ES_EVENT_TYPE_AUTH_GET_TASK` – генерується, коли процес запитує порт іншого task (наприклад, через `task_for_pid()`).
* `ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE` – генерується щоразу, коли потік створюється в *іншому* task.<sup>[[3]](#references)</sup>
* `ES_EVENT_TYPE_NOTIFY_THREAD_SET_STATE` (додано в macOS 14 Sonoma) – вказує на маніпуляцію регістрами наявного потоку.

Мінімальний Swift-клієнт, який виводить події віддалених потоків:
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
Запит за допомогою **osquery** ≥ 5.8:
```sql
SELECT target_pid, source_pid, target_path
FROM es_process_events
WHERE event_type = 'REMOTE_THREAD_CREATE';
```
### Міркування щодо Hardened Runtime

Розповсюдження вашого застосунку **без** entitlement `com.apple.security.get-task-allow` не дає non-root attackers отримати його task-port. System Integrity Protection (SIP) і надалі блокує доступ до багатьох Apple binaries, але third-party software має явно opt-out.

## 8. Recent Public Tooling (2023-2025)

| Tool | Year | Remarks |
|------|------|---------|
| [`task_vaccine`](https://github.com/rodionovd/task_vaccine) | 2023 | Компактний PoC, що демонструє PAC-aware thread hijacking на Ventura/Sonoma<sup>[[2]](#references)</sup> |
| `remote_thread_es` | 2024 | EndpointSecurity helper, який використовується кількома EDR vendors для виявлення подій `REMOTE_THREAD_CREATE` |

> Ознайомлення з вихідним кодом цих проєктів допомагає зрозуміти зміни API, запроваджені в macOS 13/14, і зберігати сумісність між Intel ↔ Apple Silicon.

## References

- [1] [Bypassing platform binary restrictions with task_threads() - bazad.github.io](https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/)
- [2] [rodionovd/task_vaccine - GitHub](https://github.com/rodionovd/task_vaccine)
- [3] [ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE - Apple Developer Documentation](https://developer.apple.com/documentation/endpointsecurity/es_event_type_notify_remote_thread_create)

{{#include ../../../../banners/hacktricks-training.md}}
