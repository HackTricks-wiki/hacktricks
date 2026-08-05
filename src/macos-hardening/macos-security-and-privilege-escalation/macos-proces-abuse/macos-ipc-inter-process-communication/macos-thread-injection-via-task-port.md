# macOS Thread Injection via Task port

{{#include ../../../../banners/hacktricks-training.md}}

## Code

- [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
- [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)

## 1. Перехоплення потоку

Спочатку функція `task_threads()` викликається через task port для отримання списку потоків віддаленого task. Для перехоплення обирається один потік. Цей підхід відрізняється від звичайних методів code injection, оскільки створення нового remote thread заборонене через mitigation, що блокує `thread_create_running()`.<sup>[[1]](#references)</sup>

Для керування потоком викликається `thread_suspend()`, що зупиняє його виконання.<sup>[[1]](#references)</sup>

Єдині дозволені операції над віддаленим потоком - **зупиняти** та **запускати** його, а також **отримувати**/**змінювати** значення його регістрів. Виклики віддалених функцій ініціюються встановленням у регістри `x0`-`x7` **аргументів**, налаштуванням `pc` на потрібну функцію та відновленням виконання потоку. Щоб потік не завершився аварійно після повернення, потрібно виявити момент повернення.<sup>[[1]](#references)</sup>

Один зі способів полягає в реєстрації **обробника винятків** для віддаленого потоку за допомогою `thread_set_exception_ports()` і встановленні регістра `lr` у недійсну адресу перед викликом функції. Після виконання функції це спричиняє виняток, унаслідок чого повідомлення надсилається до exception port. Це дає змогу перевірити стан потоку та отримати значення, яке повертає функція. В іншому варіанті, запозиченому з exploit *triple_fetch* Ian Beer, `lr` встановлюється на нескінченний цикл; після цього регістри потоку постійно перевіряються, доки `pc` не вкаже на цю інструкцію.<sup>[[1]](#references)</sup>

## 2. Mach ports для комунікації

Наступний етап передбачає створення Mach ports для забезпечення комунікації з віддаленим потоком. Ці ports використовуються для передачі довільних send/receive rights між task.<sup>[[1]](#references)</sup>

Для двонапрямленої комунікації створюються два Mach receive rights: один у локальному, а інший у віддаленому task. Потім send right для кожного port передається відповідному task, що дає змогу обмінюватися повідомленнями.<sup>[[1]](#references)</sup>

Розглянемо локальний port: receive right належить локальному task. Port створюється за допомогою `mach_port_allocate()`. Складність полягає в передачі send right до цього port у віддалений task.<sup>[[1]](#references)</sup>

Один зі способів полягає у використанні `thread_set_special_port()` для розміщення send right локального port у `THREAD_KERNEL_PORT` віддаленого потоку. Потім віддаленому потоку дається вказівка викликати `mach_thread_self()` для отримання send right.<sup>[[1]](#references)</sup>

Для віддаленого port процес фактично виконується у зворотному порядку. Віддаленому потоку дається вказівка створити Mach port за допомогою `mach_reply_port()` (оскільки `mach_port_allocate()` непридатна через механізм повернення результату). Після створення port у віддаленому потоці викликається `mach_port_insert_right()` для створення send right. Потім це право зберігається в kernel за допомогою `thread_set_special_port()`. Повернувшись до локального task, на віддаленому потоці використовується `thread_get_special_port()` для отримання send right до щойно виділеного Mach port у віддаленому task.<sup>[[1]](#references)</sup>

Виконання цих кроків призводить до створення Mach ports і закладає основу для двонапрямленої комунікації.<sup>[[1]](#references)</sup>

## 3. Базові примітиви читання/запису пам'яті

У цьому розділі розглядається використання execute primitive для створення базових примітивів читання/запису пам'яті. Ці початкові кроки важливі для отримання більшого контролю над віддаленим процесом, хоча на цьому етапі примітиви не мають широкого застосування. Незабаром їх буде вдосконалено до більш потужних версій.<sup>[[1]](#references)</sup>

### Читання та запис пам'яті за допомогою execute primitive

Мета полягає у виконанні читання та запису пам'яті за допомогою певних функцій. Для **читання пам'яті**:
```c
uint64_t read_func(uint64_t *address) {
return *address;
}
```
Для **запису пам'яті**:
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

Сканування поширених бібліотек виявило відповідні кандидати для цих операцій:<sup>[[1]](#references)</sup>

1. **Читання пам’яті — `property_getName()`** (libobjc):
```c
const char *property_getName(objc_property_t prop) {
return prop->name;
}
```
2. **Запис у пам'ять — `_xpc_int64_set_value()`** (libxpc):
```c
__xpc_int64_set_value:
str x1, [x0, #0x18]
ret
```
Щоб виконати 64-бітний запис за довільною адресою:
```c
_xpc_int64_set_value(address - 0x18, value);
```
Після встановлення цих примітивів створення shared memory стає наступним етапом і знаменує значний прогрес у контролі над віддаленим процесом.<sup>[[1]](#references)</sup>

## 4. Налаштування Shared Memory

Мета полягає у встановленні shared memory між локальними та віддаленими tasks, що спрощує передавання даних і забезпечує виклик функцій із кількома аргументами. Цей підхід використовує `libxpc` і його тип об’єкта `OS_xpc_shmem`, побудований на Mach memory entries.<sup>[[1]](#references)</sup>

### Огляд процесу

1. **Виділення пам’яті**
* Виділити пам’ять для спільного використання за допомогою `mach_vm_allocate()`.
* Використати `xpc_shmem_create()` для створення об’єкта `OS_xpc_shmem` для виділеної області.
2. **Створення shared memory у віддаленому процесі**
* Виділити пам’ять для об’єкта `OS_xpc_shmem` у віддаленому процесі (`remote_malloc`).
* Скопіювати локальний шаблон об’єкта; виправлення вбудованого Mach send right за зміщенням `0x18` все ще необхідне.
3. **Виправлення Mach memory entry**
* Вставити send right за допомогою `thread_set_special_port()` і перезаписати поле `0x18` ім’ям віддаленого entry.
4. **Завершення**
* Перевірити віддалений об’єкт і замапити його віддаленим викликом `xpc_shmem_remote()`.

## 5. Отримання повного контролю

Після отримання довільного виконання та back-channel через shared memory ви фактично контролюєте цільовий процес:<sup>[[1]](#references)</sup>

* **Довільне читання/запис пам’яті** — використовувати `memcpy()` між локальними та спільними областями.
* **Виклики функцій із > 8 аргументами** — розмістити додаткові аргументи у стеку відповідно до arm64 calling convention.
* **Передавання Mach port** — передавати rights у Mach messages через встановлені ports.
* **Передавання file descriptor** — використовувати fileports (див. *triple_fetch*).

Усе це обгорнуто в бібліотеку [`threadexec`](https://github.com/bazad/threadexec) для зручного повторного використання.

---

## 6. Особливості Apple Silicon (arm64e)

На пристроях Apple Silicon (arm64e) **Pointer Authentication Codes (PAC)** захищають усі адреси повернення та багато вказівників на функції. Техніки thread-hijacking, які *повторно використовують наявний code*, продовжують працювати, оскільки вихідні значення в `lr`/`pc` вже містять дійсні PAC-підписи. Проблеми виникають, коли ви намагаєтеся перейти до memory, контрольованої attacker:

1. Виділити executable memory усередині цільового процесу (віддалені `mach_vm_allocate` + `mprotect(PROT_EXEC)`).
2. Скопіювати payload.
3. Усередині *віддаленого* процесу підписати pointer:
```c
uint64_t ptr = (uint64_t)payload;
ptr = ptrauth_sign_unauthenticated((void*)ptr, ptrauth_key_asia, 0);
```
4. Установіть `pc = ptr` у стані захопленого thread.

Альтернативно, дотримуйтеся PAC-сумісності, об’єднуючи наявні gadgets/functions (традиційний ROP).

## 7. Виявлення та hardening за допомогою EndpointSecurity

Framework **EndpointSecurity (ES)** надає kernel events, які дають змогу захисникам спостерігати за спробами thread injection або блокувати їх:

* `ES_EVENT_TYPE_AUTH_GET_TASK` – виникає, коли процес запитує port іншого task (наприклад, через `task_for_pid()`).
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
### Міркування щодо Hardened Runtime

Розповсюдження вашого застосунку **без** entitlement `com.apple.security.get-task-allow` не дає non-root attackers змоги отримати його task-port. System Integrity Protection (SIP) як і раніше блокує доступ до багатьох Apple binaries, але стороннє програмне забезпечення має явно відмовитися від цього захисту.

## 8. Нові публічні інструменти (2023-2025)

| Tool | Year | Remarks |
|------|------|---------|
| [`task_vaccine`](https://github.com/rodionovd/task_vaccine) | 2023 | Компактний PoC, що демонструє PAC-aware thread hijacking у Ventura/Sonoma |
| `remote_thread_es` | 2024 | EndpointSecurity helper, який кілька EDR vendors використовують для виявлення подій `REMOTE_THREAD_CREATE` |

> Ознайомлення з вихідним кодом цих проєктів допомагає зрозуміти зміни API, запроваджені в macOS 13/14, і зберігати сумісність між Intel та Apple Silicon.

## Посилання

- [1] [Обхід обмежень platform binary за допомогою task_threads() - bazad.github.io](https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/)
- [2] [rodionovd/task_vaccine - GitHub](https://github.com/rodionovd/task_vaccine)
- [3] [ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE - Документація Apple для розробників](https://developer.apple.com/documentation/endpointsecurity/es_event_type_notify_remote_thread_create)

{{#include ../../../../banners/hacktricks-training.md}}
