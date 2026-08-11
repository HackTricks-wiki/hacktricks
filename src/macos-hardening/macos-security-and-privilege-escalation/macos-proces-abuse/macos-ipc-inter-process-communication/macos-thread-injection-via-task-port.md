# Ін'єкція потоку в macOS через Task port

{{#include ../../../../banners/hacktricks-training.md}}

## Code

- [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
- [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)

## 1. Перехоплення потоку

Спочатку для отримання списку потоків віддаленого task викликається функція `task_threads()` через task port. Для перехоплення обирається один потік. Цей підхід відрізняється від звичайних методів code injection, оскільки створення нового віддаленого потоку заборонене mitigation, яка блокує `thread_create_running()`.<sup>[[1]](#references)</sup>

Щоб отримати контроль над потоком, викликається `thread_suspend()`, що зупиняє його виконання.<sup>[[1]](#references)</sup>

Єдині дозволені операції над віддаленим потоком — його **зупинка** та **запуск**, а також **отримання**/**зміна** значень його регістрів. Віддалені виклики функцій ініціюються встановленням у регістри `x0`–`x7` **аргументів**, налаштуванням `pc` на потрібну функцію та відновленням виконання потоку. Щоб потік не завершився аварійно після повернення, необхідно виявити момент повернення.<sup>[[1]](#references)</sup>

Один зі способів полягає в реєстрації **обробника винятків** для віддаленого потоку за допомогою `thread_set_exception_ports()` та встановленні регістра `lr` на недійсну адресу перед викликом функції. Після виконання функції це спричиняє виняток, унаслідок чого повідомлення надсилається до exception port, що дає змогу перевірити стан потоку та отримати значення, яке повертається. Інший підхід, запозичений з exploit *triple_fetch* Ian Beer, полягає у встановленні `lr` на нескінченний цикл; після цього регістри потоку безперервно контролюються, доки `pc` не вкаже на цю інструкцію.<sup>[[1]](#references)</sup>

## 2. Mach ports для комунікації

Наступний етап полягає у створенні Mach ports для забезпечення комунікації з віддаленим потоком. Ці ports використовуються для передачі довільних прав на надсилання/отримання між tasks.<sup>[[1]](#references)</sup>

Для двонапрямленої комунікації створюються два Mach receive rights: один у локальному, а інший у віддаленому task. Потім для кожного port відповідний send right передається до іншого task, що дає змогу обмінюватися повідомленнями.<sup>[[1]](#references)</sup>

Якщо розглянути локальний port, receive right належить локальному task. Port створюється за допомогою `mach_port_allocate()`. Проблема полягає в передачі send right до цього port у віддалений task.<sup>[[1]](#references)</sup>

Один зі способів полягає у використанні `thread_set_special_port()` для розміщення send right локального port у `THREAD_KERNEL_PORT` віддаленого потоку. Потім віддаленому потоку дається вказівка викликати `mach_thread_self()` для отримання send right.<sup>[[1]](#references)</sup>

Для віддаленого port процес фактично виконується у зворотному порядку. Віддаленому потоку дається вказівка створити Mach port за допомогою `mach_reply_port()` (оскільки `mach_port_allocate()` непридатна через механізм повернення значення). Після створення port у віддаленому потоці викликається `mach_port_insert_right()` для створення send right. Потім це право зберігається в kernel за допомогою `thread_set_special_port()`. У локальному task для віддаленого потоку викликається `thread_get_special_port()`, щоб отримати send right до щойно виділеного Mach port у віддаленому task.<sup>[[1]](#references)</sup>

Після завершення цих кроків Mach ports створено, що створює основу для двонапрямленої комунікації.<sup>[[1]](#references)</sup>

## 3. Базові примітиви читання/запису пам'яті

У цьому розділі розглядається використання execute primitive для створення базових примітивів читання/запису пам'яті. Ці початкові кроки необхідні для отримання більшого контролю над віддаленим процесом, хоча на цьому етапі примітиви матимуть небагато застосувань. Незабаром їх буде вдосконалено до більш розширених версій.<sup>[[1]](#references)</sup>

### Читання та запис пам'яті за допомогою execute primitive

Мета полягає у виконанні читання та запису пам'яті за допомогою певних функцій. Для **читання пам'яті**:
```c
uint64_t read_func(uint64_t *address) {
return *address;
}
```
Надайте текст для перекладу.
```c
void write_func(uint64_t *address, uint64_t value) {
*address = value;
}
```
Цим функціям відповідає наведений нижче асемблерний код:
```
_read_func:
ldr x0, [x0]
ret
_write_func:
str x1, [x0]
ret
```
### Визначення відповідних функцій

Сканування поширених бібліотек виявило відповідні кандидати для цих операцій:<sup>[[1]](#references)</sup>

1. **Читання пам’яті — `property_getName()`** (libobjc):
```c
const char *property_getName(objc_property_t prop) {
return prop->name;
}
```
2. **Запис пам’яті — `_xpc_int64_set_value()`** (libxpc):
```c
__xpc_int64_set_value:
str x1, [x0, #0x18]
ret
```
Щоб виконати 64-бітовий запис за довільною адресою:
```c
_xpc_int64_set_value(address - 0x18, value);
```
Після встановлення цих примітивів створення спільної пам’яті стає наступним етапом, що є значним прогресом у контролі над віддаленим процесом.<sup>[[1]](#references)</sup>

## 4. Налаштування спільної пам’яті

Мета полягає у встановленні спільної пам’яті між локальними та віддаленими задачами, що спрощує передавання даних і полегшує виклик функцій із кількома аргументами. Підхід використовує `libxpc` і тип об’єкта `OS_xpc_shmem`, побудований на Mach memory entries.<sup>[[1]](#references)</sup>

### Огляд процесу

1. **Виділення пам’яті**
* Виділіть пам’ять для спільного використання за допомогою `mach_vm_allocate()`.
* Використайте `xpc_shmem_create()`, щоб створити об’єкт `OS_xpc_shmem` для виділеної області.
2. **Створення спільної пам’яті у віддаленому процесі**
* Виділіть пам’ять для об’єкта `OS_xpc_shmem` у віддаленому процесі (`remote_malloc`).
* Скопіюйте локальний шаблон об’єкта; виправлення вбудованого Mach send right за зміщенням `0x18` все ще необхідне.
3. **Виправлення Mach memory entry**
* Вставте send right за допомогою `thread_set_special_port()` і перезапишіть поле `0x18` ім’ям віддаленого entry.
4. **Завершення**
* Перевірте віддалений об’єкт і замапте його за допомогою віддаленого виклику `xpc_shmem_remote()`.

## 5. Отримання повного контролю

Після отримання довільного виконання та back-channel через спільну пам’ять ви фактично контролюєте цільовий процес:<sup>[[1]](#references)</sup>

* **Довільне читання/запис пам’яті** — використовуйте `memcpy()` між локальними та спільними областями.
* **Виклики функцій із > 8 аргументами** — розміщуйте додаткові аргументи у стеку відповідно до arm64 calling convention.
* **Передавання Mach port** — передавайте права у Mach-повідомленнях через встановлені порти.
* **Передавання file descriptor** — використовуйте fileports (див. *triple_fetch*).

Усе це обгорнуто в бібліотеку [`threadexec`](https://github.com/bazad/threadexec) для простого повторного використання.

---

## 6. Особливості Apple Silicon (arm64e)

На пристроях Apple Silicon (arm64e) **Pointer Authentication Codes (PAC)** захищають усі адреси повернення та багато покажчиків на функції. Техніки thread-hijacking, які *повторно використовують наявний код*, продовжують працювати, оскільки початкові значення в `lr`/`pc` уже містять дійсні PAC-підписи. Проблеми виникають, коли ви намагаєтеся перейти до пам’яті, контрольованої attacker:

1. Виділіть виконувану пам’ять усередині цілі (`mach_vm_allocate` + `mprotect(PROT_EXEC)` у віддаленому процесі).
2. Скопіюйте payload.
3. Усередині *віддаленого* процесу підпишіть покажчик:
```c
uint64_t ptr = (uint64_t)payload;
ptr = ptrauth_sign_unauthenticated((void*)ptr, ptrauth_key_asia, 0);
```
4. Установіть `pc = ptr` у стані перехопленого thread.

Альтернативно, залишайтеся сумісними з PAC, об’єднуючи наявні gadgets/functions (традиційний ROP).

## 7. Виявлення та посилення захисту за допомогою EndpointSecurity

Framework **EndpointSecurity (ES)** надає події kernel, які дають змогу захисникам спостерігати за спробами thread injection або блокувати їх:

* `ES_EVENT_TYPE_AUTH_GET_TASK` – спрацьовує, коли process запитує port іншого task (наприклад, через `task_for_pid()`).
* `ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE` – генерується щоразу, коли thread створюється в *іншому* task.<sup>[[3]](#references)</sup>
* `ES_EVENT_TYPE_NOTIFY_THREAD_SET_STATE` (додано в macOS 14 Sonoma) – вказує на маніпуляцію register наявного thread.

Мінімальний Swift client, який виводить події remote-thread:
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
### Міркування щодо hardened runtime

Розповсюдження вашого застосунку **без** entitlement `com.apple.security.get-task-allow` не дозволяє attackers без root отримувати його task-port. System Integrity Protection (SIP) усе ще блокує доступ до багатьох бінарних файлів Apple, але стороннє програмне забезпечення має явно відмовитися від цього захисту.

## 8. Нещодавні публічні інструменти (2023-2025)

| Інструмент | Рік | Примітки |
|------|------|---------|
| [`task_vaccine`](https://github.com/rodionovd/task_vaccine) | 2023 | Компактний PoC, що демонструє PAC-aware перехоплення потоків у Ventura/Sonoma<sup>[[2]](#references)</sup> |
| `remote_thread_es` | 2024 | EndpointSecurity helper, який кілька EDR vendors використовують для виявлення подій `REMOTE_THREAD_CREATE` |

> Ознайомлення з вихідним кодом цих проєктів допомагає зрозуміти зміни API, запроваджені в macOS 13/14, і зберігати сумісність між Intel ↔ Apple Silicon.

## References

- [1] [Обхід обмежень platform binary за допомогою task_threads() - bazad.github.io](https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/)
- [2] [rodionovd/task_vaccine - GitHub](https://github.com/rodionovd/task_vaccine)
- [3] [ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE - Документація Apple для розробників](https://developer.apple.com/documentation/endpointsecurity/es_event_type_notify_remote_thread_create)
{{#include ../../../../banners/hacktricks-training.md}}
