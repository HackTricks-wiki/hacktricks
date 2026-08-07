# macOS MIG - Mach Interface Generator

{{#include ../../../../banners/hacktricks-training.md}}

## Podstawowe informacje

MIG został utworzony, aby **uprościć proces tworzenia kodu Mach IPC**. Zasadniczo **generuje kod wymagany**, aby server i client mogły się komunikować na podstawie określonej definicji. Nawet jeśli wygenerowany kod jest nieczytelny, developer musi go jedynie zaimportować, a jego kod będzie znacznie prostszy niż wcześniej.<sup>[[1]](#references)</sup>

Definicja jest określana w Interface Definition Language (IDL) przy użyciu rozszerzenia `.defs`.

Definicje te mają 5 sekcji:

- **Deklaracja subsystemu**: Słowo kluczowe subsystem służy do wskazania **nazwy** i **id**. Możliwe jest również oznaczenie go jako **`KernelServer`**, jeśli server powinien działać w kernelu.<sup>[[4]](#references)</sup>
- **Dołączenia i importy**: MIG używa preprocesora C, dzięki czemu może korzystać z importów. Możliwe jest również użycie `uimport` i `simport` dla kodu generowanego po stronie user lub server.
- **Deklaracje typów**: Możliwe jest definiowanie typów danych, chociaż zwykle importowane są `mach_types.defs` i `std_types.defs`. W przypadku niestandardowych typów można użyć następującej składni:
- \[i`n/out]tran`: Funkcja, która musi przetłumaczyć wiadomość przychodzącą lub wychodzącą
- `c[user/server]type`: Mapowanie na inny typ C.
- `destructor`: Wywołanie tej funkcji po zwolnieniu typu.
- **Operacje**: Są to definicje metod RPC. Istnieje 5 różnych typów:
- `routine`: Oczekuje odpowiedzi
- `simpleroutine`: Nie oczekuje odpowiedzi
- `procedure`: Oczekuje odpowiedzi
- `simpleprocedure`: Nie oczekuje odpowiedzi
- `function`: Oczekuje odpowiedzi

### Przykład

Utwórz plik definicji, w tym przypadku z bardzo prostą funkcją:
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
Pamiętaj, że pierwszy **argument to port, z którym należy się powiązać**, a MIG **automatycznie obsłuży port odpowiedzi** (chyba że w kodzie klienta zostanie wywołane `mig_get_reply_port()`). Ponadto **identyfikatory operacji** będą przydzielane **sekwencyjnie**, począwszy od wskazanego identyfikatora subsystemu (jeśli więc operacja zostanie wycofana, jest usuwana, a do zachowania jej identyfikatora używane jest `skip`).

Teraz użyj MIG, aby wygenerować kod serwera i klienta, które będą mogły komunikować się ze sobą w celu wywołania funkcji Subtract:
```bash
mig -header myipcUser.h -sheader myipcServer.h myipc.defs
```
W bieżącym katalogu zostanie utworzonych kilka nowych plików.

> [!TIP]
> Bardziej złożony przykład można znaleźć w systemie za pomocą: `mdfind mach_port.defs`\
> Można go skompilować z tego samego folderu co plik za pomocą: `mig -DLIBSYSCALL_INTERFACE mach_ports.defs`<sup>[[2]](#references)</sup>

W plikach **`myipcServer.c`** i **`myipcServer.h`** można znaleźć deklarację i definicję struktury **`SERVERPREFmyipc_subsystem`**, która zasadniczo definiuje funkcję wywoływaną na podstawie odebranego identyfikatora wiadomości (wskazaliśmy numer początkowy 500):

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

Na podstawie poprzedniej struktury funkcja **`myipc_server_routine`** pobierze **identyfikator komunikatu** i zwróci właściwą funkcję do wywołania:
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
W tym przykładzie zdefiniowaliśmy w definicjach tylko 1 funkcję, ale gdybyśmy zdefiniowali więcej funkcji, znajdowałyby się one w tablicy **`SERVERPREFmyipc_subsystem`**, a pierwszej zostałby przypisany identyfikator **500**, drugiej identyfikator **501**...

Jeśli funkcja miała wysyłać **odpowiedź**, istniałaby również funkcja `mig_internal kern_return_t __MIG_check__Reply__<name>`.

W rzeczywistości można zidentyfikować tę relację w strukturze **`subsystem_to_name_map_myipc`** z pliku **`myipcServer.h`** (**`subsystem*to_name_map*\***`** w innych plikach):
```c
#ifndef subsystem_to_name_map_myipc
#define subsystem_to_name_map_myipc \
{ "Subtract", 500 }
#endif
```
Na koniec kolejną ważną funkcją potrzebną do działania **serwera** będzie **`myipc_server`**, która faktycznie **wywoła funkcję** powiązaną z otrzymanym identyfikatorem:<sup>[[3]](#references)</sup>

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

Sprawdź wcześniej wyróżnione wiersze uzyskujące dostęp do funkcji, która ma zostać wywołana, na podstawie identyfikatora.

Poniżej znajduje się kod tworzący prosty **serwer** i **klienta**, w którym klient może wywoływać funkcje Subtract z serwera:

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

NDR_record jest eksportowany przez `libsystem_kernel.dylib` i jest strukturą, która pozwala MIG **przekształcać dane tak, aby były niezależne od systemu**, ponieważ MIG został zaprojektowany do używania między różnymi systemami (a nie tylko na tej samej maszynie).

Jest to interesujące, ponieważ jeśli `_NDR_record` zostanie znaleziony w pliku binarnym jako zależność (`jtool2 -S <binary> | grep NDR` lub `nm`), oznacza to, że plik binarny jest klientem lub serwerem MIG.

Ponadto **serwery MIG** mają tabelę dispatch w `__DATA.__const` (lub w `__CONST.__constdata` w jądrze macOS i `__DATA_CONST.__const` w innych jądrach \*OS). Można ją zrzucić za pomocą **`jtool2`**.

**Klienci MIG** będą używać `__NDR_record` do wysyłania danych za pomocą `__mach_msg` do serwerów.

## Binary Analysis

### jtool

Ponieważ wiele plików binarnych używa obecnie MIG do udostępniania portów Mach, warto wiedzieć, jak **zidentyfikować użycie MIG** oraz **funkcje wykonywane przez MIG** dla każdego message ID.

[**jtool2**](../../macos-apps-inspecting-debugging-and-fuzzing/index.html#jtool2) może analizować informacje MIG z pliku binarnego Mach-O, wskazując message ID i identyfikując funkcję do wykonania:
```bash
jtool2 -d __DATA.__const myipc_server | grep MIG
```
Ponadto funkcje MIG są jedynie wrapperami dla wywoływanej właściwej funkcji, co oznacza, że uzyskanie ich disassembly i wyszukanie instrukcji BL może pozwolić na znalezienie faktycznie wywoływanej funkcji:
```bash
jtool2 -d __DATA.__const myipc_server | grep BL
```
### Assembly

Ранее упоминалось, что функцией, которая отвечает за **вызов правильной функции в зависимости от полученного ID сообщения**, была `myipc_server`. Однако обычно у вас не будет символов binary (имён функций), поэтому полезно **проверить, как она выглядит в decompiled виде**, поскольку она всегда будет очень похожей (код этой функции не зависит от exposed функций):

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
// 0x1f4 = 500 (the strating ID)
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
Это та же функция, decompiled в другой free версии Hopper:

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
// 0x1f4 = 500 (the strating ID)
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

На самом деле, если перейти к функции **`0x100004000`**, вы найдёте массив структур **`routine_descriptor`**. Первый элемент структуры — это **адрес**, по которому реализована **функция**, а **структура занимает 0x28 байт**, поэтому каждые 0x28 байт (начиная с byte 0) можно получить 8 байт, которые будут **адресом вызываемой функции**:

<figure><img src="../../../../images/image (35).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../../images/image (36).png" alt=""><figcaption></figcaption></figure>

Эти данные можно извлечь [**с помощью этого Hopper script**](https://github.com/knightsc/hopper/blob/master/scripts/MIG%20Detect.py).

### Debug

Код, сгенерированный MIG, также вызывает `kernel_debug` для создания логов об операциях при входе и выходе. Их можно просматривать с помощью **`trace`** или **`kdv`**: `kdv all | grep MIG`

## References

- [1] [bootstrap_cmds — `migcom.tproj` (сам MIG compiler)](https://github.com/apple-oss-distributions/bootstrap_cmds/tree/main/migcom.tproj)
- [2] [XNU — `osfmk/mach/mach_port.defs` (пример определения MIG subsystem)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/mach_port.defs)
- [3] [XNU — `osfmk/mach/message.h` (структура заголовка Mach message)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/message.h)
- [4] [XNU — `osfmk/mach/task.defs` (определение task subsystem для MIG)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/task.defs)

{{#include ../../../../banners/hacktricks-training.md}}
