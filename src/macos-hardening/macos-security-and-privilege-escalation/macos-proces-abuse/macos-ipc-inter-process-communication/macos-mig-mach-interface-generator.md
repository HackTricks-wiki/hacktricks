# macOS MIG - Mach Interface Generator

{{#include ../../../../banners/hacktricks-training.md}}

## Основна інформація

MIG був створений для **спрощення процесу створення коду Mach IPC**. Він в основному **генерує необхідний код** для зв'язку сервера та клієнта відповідно до заданого визначення. Навіть якщо згенерований код виглядає неохайно, розробнику просто потрібно буде імпортувати його, і його код стане набагато простішим, ніж раніше.

Визначення вказується в Мові Визначення Інтерфейсу (IDL) з використанням розширення `.defs`.

Ці визначення мають 5 секцій:

- **Оголошення підсистеми**: Ключове слово subsystem використовується для вказівки **імені** та **ідентифікатора**. Також можливо позначити його як **`KernelServer`**, якщо сервер повинен працювати в ядрі.
- **Включення та імпорти**: MIG використовує C-препроцесор, тому він може використовувати імпорти. Більше того, можливо використовувати `uimport` та `simport` для коду, згенерованого користувачем або сервером.
- **Оголошення типів**: Можливо визначити типи даних, хоча зазвичай він імпортує `mach_types.defs` та `std_types.defs`. Для користувацьких типів можна використовувати деякий синтаксис:
- \[i`n/out]tran`: Функція, яка повинна бути переведена з вхідного або на вихідне повідомлення
- `c[user/server]type`: Відображення на інший тип C.
- `destructor`: Викликати цю функцію, коли тип звільняється.
- **Операції**: Це визначення методів RPC. Є 5 різних типів:
- `routine`: Очікує відповідь
- `simpleroutine`: Не очікує відповіді
- `procedure`: Очікує відповідь
- `simpleprocedure`: Не очікує відповіді
- `function`: Очікує відповідь

### Приклад

Створіть файл визначення, в цьому випадку з дуже простою функцією:
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
Зверніть увагу, що перший **аргумент - це порт для прив'язки**, а MIG **автоматично оброблятиме порт відповіді** (якщо не викликати `mig_get_reply_port()` у коді клієнта). Крім того, **ID операцій** буде **послідовним**, починаючи з вказаного ID підсистеми (тому, якщо операція застаріла, вона видаляється, а `skip` використовується для продовження використання її ID).

Тепер використовуйте MIG для генерації коду сервера та клієнта, які зможуть спілкуватися один з одним для виклику функції Subtract:
```bash
mig -header myipcUser.h -sheader myipcServer.h myipc.defs
```
У поточному каталозі буде створено кілька нових файлів.

> [!TIP]
> Ви можете знайти більш складний приклад у вашій системі за допомогою: `mdfind mach_port.defs`\
> І ви можете скомпілювати його з тієї ж папки, що й файл, за допомогою: `mig -DLIBSYSCALL_INTERFACE mach_ports.defs`

У файлах **`myipcServer.c`** та **`myipcServer.h`** ви можете знайти оголошення та визначення структури **`SERVERPREFmyipc_subsystem`**, яка в основному визначає функцію для виклику на основі отриманого ідентифікатора повідомлення (ми вказали початковий номер 500):

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

На основі попередньої структури функція **`myipc_server_routine`** отримає **ідентифікатор повідомлення** та поверне відповідну функцію для виклику:
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
У цьому прикладі ми визначили лише 1 функцію в визначеннях, але якби ми визначили більше функцій, вони були б всередині масиву **`SERVERPREFmyipc_subsystem`**, а перша була б призначена ID **500**, друга - ID **501**...

Якщо функція повинна була надіслати **reply**, функція `mig_internal kern_return_t __MIG_check__Reply__<name>` також існувала б.

Насправді, цю залежність можна ідентифікувати в структурі **`subsystem_to_name_map_myipc`** з **`myipcServer.h`** (**`subsystem*to_name_map*\***`\*\* в інших файлах):
```c
#ifndef subsystem_to_name_map_myipc
#define subsystem_to_name_map_myipc \
{ "Subtract", 500 }
#endif
```
Нарешті, ще одна важлива функція для роботи сервера буде **`myipc_server`**, яка фактично **викликатиме функцію**, пов'язану з отриманим ідентифікатором:

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
/* Мінімальний розмір: routine() оновить його, якщо він відрізняється */
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

Перевірте раніше виділені рядки, що отримують доступ до функції для виклику за ідентифікатором.

Наступний код створює простий **сервер** та **клієнт**, де клієнт може викликати функції Subtract з сервера:

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

### NDR_record

NDR_record експортується з `libsystem_kernel.dylib`, і це структура, яка дозволяє MIG **перетворювати дані так, щоб вони були незалежними від системи**, оскільки MIG задумувався для використання між різними системами (а не лише на одній машині).

Це цікаво, оскільки якщо `_NDR_record` знайдено в бінарному файлі як залежність (`jtool2 -S <binary> | grep NDR` або `nm`), це означає, що бінарний файл є клієнтом або сервером MIG.

Більше того, **MIG сервери** мають таблицю розподілу в `__DATA.__const` (або в `__CONST.__constdata` в ядрі macOS і `__DATA_CONST.__const` в інших ядрах \*OS). Це можна вивантажити за допомогою **`jtool2`**.

А **MIG клієнти** використовуватимуть `__NDR_record`, щоб надсилати з `__mach_msg` до серверів.

## Аналіз бінарних файлів

### jtool

Оскільки багато бінарних файлів зараз використовують MIG для відкриття mach портів, цікаво знати, як **виявити, що використовувався MIG** і **функції, які виконує MIG** з кожним ідентифікатором повідомлення.

[**jtool2**](../../macos-apps-inspecting-debugging-and-fuzzing/index.html#jtool2) може аналізувати інформацію MIG з Mach-O бінарного файлу, вказуючи ідентифікатор повідомлення та ідентифікуючи функцію для виконання:
```bash
jtool2 -d __DATA.__const myipc_server | grep MIG
```
Більше того, функції MIG є просто обгортками для фактичних функцій, які викликаються, що означає, що отримавши їх дизасемблювання та здійснивши пошук за BL, ви можете знайти фактичну функцію, яка викликається:
```bash
jtool2 -d __DATA.__const myipc_server | grep BL
```
### Assembly

Було раніше згадано, що функція, яка буде **викликати правильну функцію в залежності від отриманого ідентифікатора повідомлення**, називається `myipc_server`. Однак зазвичай у вас не буде символів бінарного файлу (немає імен функцій), тому цікаво **перевірити, як вона виглядає в декомпільованому вигляді**, оскільки код цієї функції завжди буде дуже схожим (код цієї функції незалежний від експонованих функцій):

{{#tabs}}
{{#tab name="myipc_server decompiled 1"}}

<pre class="language-c"><code class="lang-c">int _myipc_server(int arg0, int arg1) {
var_10 = arg0;
var_18 = arg1;
// Початкові інструкції для знаходження правильних вказівників функцій
*(int32_t *)var_18 = *(int32_t *)var_10 & 0x1f;
*(int32_t *)(var_18 + 0x8) = *(int32_t *)(var_10 + 0x8);
*(int32_t *)(var_18 + 0x4) = 0x24;
*(int32_t *)(var_18 + 0xc) = 0x0;
*(int32_t *)(var_18 + 0x14) = *(int32_t *)(var_10 + 0x14) + 0x64;
*(int32_t *)(var_18 + 0x10) = 0x0;
if (*(int32_t *)(var_10 + 0x14) <= 0x1f4 && *(int32_t *)(var_10 + 0x14) >= 0x1f4) {
rax = *(int32_t *)(var_10 + 0x14);
// Виклик sign_extend_64, який може допомогти ідентифікувати цю функцію
// Це зберігає в rax вказівник на виклик, який потрібно виконати
// Перевірте використання адреси 0x100004040 (масив адрес функцій)
// 0x1f4 = 500 (початковий ID)
<strong>            rax = *(sign_extend_64(rax - 0x1f4) * 0x28 + 0x100004040);
</strong>            var_20 = rax;
// Якщо - інакше, if повертає false, тоді як else викликає правильну функцію і повертає true
<strong>            if (rax == 0x0) {
</strong>                    *(var_18 + 0x18) = **_NDR_record;
*(int32_t *)(var_18 + 0x20) = 0xfffffffffffffed1;
var_4 = 0x0;
}
else {
// Обчислена адреса, яка викликає правильну функцію з 2 аргументами
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
Це та ж функція, декомпільована в іншій безкоштовній версії Hopper:

<pre class="language-c"><code class="lang-c">int _myipc_server(int arg0, int arg1) {
r31 = r31 - 0x40;
saved_fp = r29;
stack[-8] = r30;
var_10 = arg0;
var_18 = arg1;
// Початкові інструкції для знаходження правильних вказівників функцій
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
// 0x1f4 = 500 (початковий ID)
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
// Те ж if-else, що і в попередній версії
// Перевірте використання адреси 0x100004040 (масив адрес функцій)
<strong>                    if ((r8 & 0x1) == 0x0) {
</strong><strong>                            *(var_18 + 0x18) = **0x100004000;
</strong>                            *(int32_t *)(var_18 + 0x20) = 0xfffffed1;
var_4 = 0x0;
}
else {
// Виклик обчисленої адреси, де повинна бути функція
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

Насправді, якщо ви перейдете до функції **`0x100004000`**, ви знайдете масив структур **`routine_descriptor`**. Перший елемент структури - це **адреса**, де реалізована **функція**, а **структура займає 0x28 байт**, тому кожні 0x28 байт (починаючи з байта 0) ви можете отримати 8 байт, і це буде **адреса функції**, яка буде викликана:

<figure><img src="../../../../images/image (35).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../../images/image (36).png" alt=""><figcaption></figcaption></figure>

Ці дані можна витягти [**використовуючи цей скрипт Hopper**](https://github.com/knightsc/hopper/blob/master/scripts/MIG%20Detect.py).

### Debug

Код, згенерований MIG, також викликає `kernel_debug`, щоб генерувати журнали про операції при вході та виході. Можна перевірити їх, використовуючи **`trace`** або **`kdv`**: `kdv all | grep MIG`

## References

- [\*OS Internals, Volume I, User Mode, Jonathan Levin](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

{{#include ../../../../banners/hacktricks-training.md}}
