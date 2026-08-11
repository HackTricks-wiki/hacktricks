# macOS MIG - Mach Interface Generator

{{#include ../../../../banners/hacktricks-training.md}}

## Basic Information

MIG було створено, щоб **спростити процес створення коду Mach IPC**. По суті, він **генерує необхідний код** для взаємодії сервера й клієнта на основі заданого визначення. Навіть якщо згенерований код виглядає неохайно, розробнику буде достатньо імпортувати його, і його код стане набагато простішим.<sup>[[1]](#references)</sup>

Визначення задається мовою Interface Definition Language (IDL) із використанням розширення `.defs`.

Ці визначення мають 5 секцій:

- **Subsystem declaration**: Ключове слово subsystem використовується для зазначення **назви** та **ідентифікатора**. Також можна позначити його як **`KernelServer`**, якщо сервер має працювати в ядрі.<sup>[[4]](#references)</sup>
- **Inclusions and imports**: MIG використовує C-prepocessor, тому підтримує імпорти. Крім того, можна використовувати `uimport` і `simport` для згенерованого коду користувача або сервера.
- **Type declarations**: Можна визначати типи даних, хоча зазвичай імпортуються `mach_types.defs` і `std_types.defs`. Для власних типів можна використовувати такий синтаксис:
- \[i`n/out]tran`: Функція, яку потрібно перекласти з вхідного повідомлення або у вихідне повідомлення
- `c[user/server]type`: Відображення на інший тип C.
- `destructor`: Викликати цю функцію, коли тип звільняється.
- **Operations**: Це визначення методів RPC. Існує 5 різних типів:
- `routine`: Очікує reply
- `simpleroutine`: Не очікує reply
- `procedure`: Очікує reply
- `simpleprocedure`: Не очікує reply
- `function`: Очікує reply

### Example

Створіть файл визначення, у цьому випадку — з дуже простою функцією:
```cpp:myipc.defs
subsystem myipc 500; // Arbitrary name and id

userprefix USERPREF;        // Prefix for created functions in the client
serverprefix SERVERPREF;    // Prefix for created functions in the server

#include <mach/mach_types.defs>
#include <mach/std_types.defs>

simpleroutine Subtract(
server_port :  mach_port_t;
n1          :  uint32_t;
n2          :  uint32_t);
```
Зверніть увагу, що перший **аргумент — це порт для прив’язування**, а MIG **автоматично оброблятиме порт відповіді** (якщо в коді клієнта не викликається `mig_get_reply_port()`). Крім того, **ідентифікатори операцій** будуть **послідовними**, починаючи з указаного ID підсистеми (тому, якщо операцію вилучено, її видаляють і використовують `skip`, щоб зберегти її ID).

Тепер використайте MIG для генерування коду сервера та клієнта, які зможуть взаємодіяти між собою для виклику функції Subtract:
```bash
mig -header myipcUser.h -sheader myipcServer.h myipc.defs
```
У поточному каталозі буде створено кілька нових файлів.

> [!TIP]
> Складніший приклад можна знайти у вашій системі за допомогою: `mdfind mach_port.defs`\
> Скомпілювати його можна з тієї самої папки, де знаходиться файл, за допомогою: `mig -DLIBSYSCALL_INTERFACE mach_ports.defs`<sup>[[2]](#references)</sup>

У файлах **`myipcServer.c`** і **`myipcServer.h`** можна знайти оголошення та визначення struct **`SERVERPREFmyipc_subsystem`**, який фактично визначає функцію для виклику на основі отриманого message ID (ми вказали початковий номер 500):

{{#tabs}}
{{#tab name="myipcServer.c"}}
```c
/* Description of this subsystem, for use in direct RPC */
const struct SERVERPREFmyipc_subsystem SERVERPREFmyipc_subsystem = {
myipc_server_routine,
500, // start ID
501, // end ID
(mach_msg_size_t)sizeof(union __ReplyUnion__SERVERPREFmyipc_subsystem),
(vm_address_t)0,
{
{ (mig_impl_routine_t) 0,
// Function to call
(mig_stub_routine_t) _XSubtract, 3, 0, (routine_arg_descriptor_t)0, (mach_msg_size_t)sizeof(__Reply__Subtract_t)},
}
};
```
{{#endtab}}

{{#tab name="myipcServer.h"}}
```c
/* Description of this subsystem, for use in direct RPC */
extern const struct SERVERPREFmyipc_subsystem {
mig_server_routine_t	server;	/* Server routine */
mach_msg_id_t	start;	/* Min routine number */
mach_msg_id_t	end;	/* Max routine number + 1 */
unsigned int	maxsize;	/* Max msg size */
vm_address_t	reserved;	/* Reserved */
struct routine_descriptor	/* Array of routine descriptors */
routine[1];
} SERVERPREFmyipc_subsystem;
```
{{#endtab}}
{{#endtabs}}

На основі попередньої структури функція **`myipc_server_routine`** отримує **ідентифікатор повідомлення** та повертає відповідну функцію для виклику:
```c
mig_external mig_routine_t myipc_server_routine
(mach_msg_header_t *InHeadP)
{
int msgh_id;

msgh_id = InHeadP->msgh_id - 500;

if ((msgh_id > 0) || (msgh_id < 0))
return 0;

return SERVERPREFmyipc_subsystem.routine[msgh_id].stub_routine;
}
```
У цьому прикладі ми визначили лише 1 function у definitions, але якби ми визначили більше functions, вони знаходилися б у масиві **`SERVERPREFmyipc_subsystem`**, і першій було б призначено ID **500**, другій — ID **501**...

Якщо очікувалося, що function надсилатиме **reply**, також існувала б function `mig_internal kern_return_t __MIG_check__Reply__<name>`.

Фактично цей зв’язок можна ідентифікувати у struct **`subsystem_to_name_map_myipc`** з **`myipcServer.h`** (**`subsystem*to_name_map*\***`** в інших файлах):
```c
#ifndef subsystem_to_name_map_myipc
#define subsystem_to_name_map_myipc \
{ "Subtract", 500 }
#endif
```
Нарешті, ще однією важливою функцією для роботи **server** буде **`myipc_server`** — саме вона фактично **викликатиме функцію**, пов’язану з отриманим id:<sup>[[3]](#references)</sup>

<pre class="language-c"><code class="lang-c">mig_external boolean_t myipc_server
(mach_msg_header_t *InHeadP, mach_msg_header_t *OutHeadP)
{
/*
* typedef struct {
* 	mach_msg_header_t Head;
* 	NDR_record_t NDR;
* 	kern_return_t RetCode;
* } mig_reply_error_t;
*/

mig_routine_t routine;

OutHeadP->msgh_bits = MACH_MSGH_BITS(MACH_MSGH_BITS_REPLY(InHeadP->msgh_bits), 0);
OutHeadP->msgh_remote_port = InHeadP->msgh_reply_port;
/* Minimal size: routine() will update it if different */
OutHeadP->msgh_size = (mach_msg_size_t)sizeof(mig_reply_error_t);
OutHeadP->msgh_local_port = MACH_PORT_NULL;
OutHeadP->msgh_id = InHeadP->msgh_id + 100;
OutHeadP->msgh_reserved = 0;

if ((InHeadP->msgh_id > 500) || (InHeadP->msgh_id < 500) ||
<strong>	    ((routine = SERVERPREFmyipc_subsystem.routine[InHeadP->msgh_id - 500].stub_routine) == 0)) {
</strong>		((mig_reply_error_t *)OutHeadP)->NDR = NDR_record;
((mig_reply_error_t *)OutHeadP)->RetCode = MIG_BAD_ID;
return FALSE;
}
<strong>	(*routine) (InHeadP, OutHeadP);
</strong>	return TRUE;
}
</code></pre>

Перевірте наведені вище виділені рядки, які отримують доступ до функції для виклику за ID.

Нижче наведено код для створення простого **server** і **client**, де client може викликати функції Subtract із server:

{{#tabs}}
{{#tab name="myipc_server.c"}}
```c
// gcc myipc_server.c myipcServer.c -o myipc_server

#include <stdio.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>
#include "myipcServer.h"

kern_return_t SERVERPREFSubtract(mach_port_t server_port, uint32_t n1, uint32_t n2)
{
printf("Received: %d - %d = %d\n", n1, n2, n1 - n2);
return KERN_SUCCESS;
}

int main() {

mach_port_t port;
kern_return_t kr;

// Register the mach service
kr = bootstrap_check_in(bootstrap_port, "xyz.hacktricks.mig", &port);
if (kr != KERN_SUCCESS) {
printf("bootstrap_check_in() failed with code 0x%x\n", kr);
return 1;
}

// myipc_server is the function that handles incoming messages (check previous exlpanation)
mach_msg_server(myipc_server, sizeof(union __RequestUnion__SERVERPREFmyipc_subsystem), port, MACH_MSG_TIMEOUT_NONE);
}
```
{{#endtab}}

{{#tab name="myipc_client.c"}}
```c
// gcc myipc_client.c myipcUser.c -o myipc_client

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <mach/mach.h>
#include <servers/bootstrap.h>
#include "myipcUser.h"

int main() {

// Lookup the receiver port using the bootstrap server.
mach_port_t port;
kern_return_t kr = bootstrap_look_up(bootstrap_port, "xyz.hacktricks.mig", &port);
if (kr != KERN_SUCCESS) {
printf("bootstrap_look_up() failed with code 0x%x\n", kr);
return 1;
}
printf("Port right name %d\n", port);
USERPREFSubtract(port, 40, 2);
}
```
{{#endtab}}
{{#endtabs}}

### The NDR_record

NDR_record експортується `libsystem_kernel.dylib` і є структурою, яка дозволяє MIG **перетворювати дані так, щоб вони не залежали від системи**, у якій використовується MIG, оскільки MIG задумувався для використання між різними системами (а не лише на одному комп’ютері).

Це цікаво, оскільки якщо `_NDR_record` знайдено у бінарному файлі як dependency (`jtool2 -S <binary> | grep NDR` або `nm`), це означає, що бінарний файл є MIG client або Server.

Крім того, **MIG servers** мають dispatch table у `__DATA.__const` (або в `__CONST.__constdata` у ядрі macOS і `__DATA_CONST.__const` в інших ядрах \*OS). Її можна вивантажити за допомогою **`jtool2`**.

А **MIG clients** використовують `__NDR_record`, щоб надсилати його через `__mach_msg` на servers.

## Binary Analysis

### jtool

Оскільки багато бінарних файлів тепер використовують MIG для відкриття mach ports, важливо знати, як **визначити, що було використано MIG**, а також **функції, які MIG виконує** для кожного message ID.

[**jtool2**](../../macos-apps-inspecting-debugging-and-fuzzing/index.html#jtool2) може проаналізувати інформацію MIG у Mach-O binary, вказавши message ID та визначивши функцію для виконання:
```bash
jtool2 -d __DATA.__const myipc_server | grep MIG
```
Крім того, MIG-функції є обгортками навколо фактичної функції, яка викликається. Тому, отримавши дизасемблювання та виконавши пошук `BL`, ви можете знайти фактичну функцію, яка викликається:
```bash
jtool2 -d __DATA.__const myipc_server | grep BL
```
### Асемблер

Раніше згадувалося, що функцією, яка відповідатиме за **виклик правильної функції залежно від отриманого ID повідомлення**, була `myipc_server`. Однак зазвичай у вас не буде символів бінарного файлу (назв функцій), тому корисно **перевірити, як вона виглядає після декомпіляції**, оскільки вона завжди буде дуже схожою (код цієї функції не залежить від відкритих функцій):

{{#tabs}}
{{#tab name="myipc_server decompiled 1"}}

<pre class="language-c"><code class="lang-c">int _myipc_server(int arg0, int arg1) {
var_10 = arg0;
var_18 = arg1;
// Initial instructions to find the proper function ponters
*(int32_t *)var_18 = *(int32_t *)var_10 & 0x1f;
*(int32_t *)(var_18 + 0x8) = *(int32_t *)(var_10 + 0x8);
*(int32_t *)(var_18 + 0x4) = 0x24;
*(int32_t *)(var_18 + 0xc) = 0x0;
*(int32_t *)(var_18 + 0x14) = *(int32_t *)(var_10 + 0x14) + 0x64;
*(int32_t *)(var_18 + 0x10) = 0x0;
if (*(int32_t *)(var_10 + 0x14) <= 0x1f4 && *(int32_t *)(var_10 + 0x14) >= 0x1f4) {
rax = *(int32_t *)(var_10 + 0x14);
// Call to sign_extend_64 that can help to identifyf this function
// This stores in rax the pointer to the call that needs to be called
// Check the used of the address 0x100004040 (functions addresses array)
// 0x1f4 = 500 (the starting ID)
<strong>            rax = *(sign_extend_64(rax - 0x1f4) * 0x28 + 0x100004040);
</strong>            var_20 = rax;
// If - else, the if returns false, while the else call the correct function and returns true
<strong>            if (rax == 0x0) {
</strong>                    *(var_18 + 0x18) = **_NDR_record;
*(int32_t *)(var_18 + 0x20) = 0xfffffffffffffed1;
var_4 = 0x0;
}
else {
// Calculated address that calls the proper function with 2 arguments
<strong>                    (var_20)(var_10, var_18);
</strong>                    var_4 = 0x1;
}
}
else {
*(var_18 + 0x18) = **_NDR_record;
*(int32_t *)(var_18 + 0x20) = 0xfffffffffffffed1;
var_4 = 0x0;
}
rax = var_4;
return rax;
}
</code></pre>

{{#endtab}}

{{#tab name="myipc_server decompiled 2"}}
Це та сама функція, декомпільована в іншій безкоштовній версії Hopper:

<pre class="language-c"><code class="lang-c">int _myipc_server(int arg0, int arg1) {
r31 = r31 - 0x40;
saved_fp = r29;
stack[-8] = r30;
var_10 = arg0;
var_18 = arg1;
// Initial instructions to find the proper function ponters
*(int32_t *)var_18 = *(int32_t *)var_10 & 0x1f | 0x0;
*(int32_t *)(var_18 + 0x8) = *(int32_t *)(var_10 + 0x8);
*(int32_t *)(var_18 + 0x4) = 0x24;
*(int32_t *)(var_18 + 0xc) = 0x0;
*(int32_t *)(var_18 + 0x14) = *(int32_t *)(var_10 + 0x14) + 0x64;
*(int32_t *)(var_18 + 0x10) = 0x0;
r8 = *(int32_t *)(var_10 + 0x14);
r8 = r8 - 0x1f4;
if (r8 > 0x0) {
if (CPU_FLAGS & G) {
r8 = 0x1;
}
}
if ((r8 & 0x1) == 0x0) {
r8 = *(int32_t *)(var_10 + 0x14);
r8 = r8 - 0x1f4;
if (r8 < 0x0) {
if (CPU_FLAGS & L) {
r8 = 0x1;
}
}
if ((r8 & 0x1) == 0x0) {
r8 = *(int32_t *)(var_10 + 0x14);
// 0x1f4 = 500 (the starting ID)
<strong>                    r8 = r8 - 0x1f4;
</strong>                    asm { smaddl     x8, w8, w9, x10 };
r8 = *(r8 + 0x8);
var_20 = r8;
r8 = r8 - 0x0;
if (r8 != 0x0) {
if (CPU_FLAGS & NE) {
r8 = 0x1;
}
}
// Same if else as in the previous version
// Check the used of the address 0x100004040 (functions addresses array)
<strong>                    if ((r8 & 0x1) == 0x0) {
</strong><strong>                            *(var_18 + 0x18) = **0x100004000;
</strong>                            *(int32_t *)(var_18 + 0x20) = 0xfffffed1;
var_4 = 0x0;
}
else {
// Call to the calculated address where the function should be
<strong>                            (var_20)(var_10, var_18);
</strong>                            var_4 = 0x1;
}
}
else {
*(var_18 + 0x18) = **0x100004000;
*(int32_t *)(var_18 + 0x20) = 0xfffffed1;
var_4 = 0x0;
}
}
else {
*(var_18 + 0x18) = **0x100004000;
*(int32_t *)(var_18 + 0x20) = 0xfffffed1;
var_4 = 0x0;
}
r0 = var_4;
return r0;
}

</code></pre>

{{#endtab}}
{{#endtabs}}

Якщо перейти до функції **`0x100004000`**, ви знайдете масив структур **`routine_descriptor`**. Першим елементом структури є **адреса**, за якою реалізовано **функцію**, а **структура займає 0x28 байт**, тому кожні 0x28 байт (починаючи з байта 0) можна отримати 8 байт, і це буде **адреса функції**, яку буде викликано:

<figure><img src="../../../../images/image (35).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../../images/image (36).png" alt=""><figcaption></figcaption></figure>

Ці дані можна отримати [**за допомогою цього Hopper script**](https://github.com/knightsc/hopper/blob/master/scripts/MIG%20Detect.py).

### Налагодження

Код, згенерований MIG, також викликає `kernel_debug` для створення журналів операцій під час входу та виходу. Їх можна переглянути за допомогою **`trace`** або **`kdv`**: `kdv all | grep MIG`

## References

- [1] [bootstrap_cmds — `migcom.tproj` (сам компілятор MIG)](https://github.com/apple-oss-distributions/bootstrap_cmds/tree/main/migcom.tproj)
- [2] [XNU — `osfmk/mach/mach_port.defs` (приклад визначення підсистеми MIG)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/mach_port.defs)
- [3] [XNU — `osfmk/mach/message.h` (структура заголовка Mach-повідомлення)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/message.h)
- [4] [XNU — `osfmk/mach/task.defs` (визначення підсистеми MIG)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/task.defs)
{{#include ../../../../banners/hacktricks-training.md}}
