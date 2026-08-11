# macOS MIG - Mach Interface Generator

{{#include ../../../../banners/hacktricks-training.md}}

## Temel Bilgiler

MIG, **Mach IPC** kodu oluşturma sürecini **basitleştirmek** için oluşturulmuştur. Temel olarak, sunucunun ve istemcinin belirli bir tanımla iletişim kurması için gereken kodu **oluşturur**. Oluşturulan kod çirkin olsa bile geliştiricinin yalnızca bunu içe aktarması gerekir ve kendi kodu öncekinden çok daha basit olur.<sup>[[1]](#references)</sup>

Tanım, `.defs` uzantısı kullanılarak Interface Definition Language (IDL) ile belirtilir.

Bu tanımlar 5 bölümden oluşur:

- **Subsystem bildirimi**: `subsystem` anahtar sözcüğü **adı** ve **id** değerini belirtmek için kullanılır. Sunucunun kernel içinde çalışması gerekiyorsa bunu **`KernelServer`** olarak işaretlemek de mümkündür.<sup>[[4]](#references)</sup>
- **Inclusions and imports**: MIG, C-prepocessor kullanır; bu nedenle import'ları kullanabilir. Ayrıca user veya server tarafından oluşturulan kod için `uimport` ve `simport` kullanmak mümkündür.
- **Type declarations**: Veri türlerini tanımlamak mümkündür; ancak genellikle `mach_types.defs` ve `std_types.defs` import edilir. Özel türler için bazı syntax'lar kullanılabilir:
- \[i`n/out]tran`: Gelen bir mesajdan çevrilmesi veya giden bir mesaja çevrilmesi gereken function
- `c[user/server]type`: Başka bir C türüne mapping.
- `destructor`: Tür serbest bırakıldığında bu function'ı çağırır.
- **Operations**: Bunlar RPC method'larının tanımlarıdır. 5 farklı tür vardır:
- `routine`: Yanıt bekler
- `simpleroutine`: Yanıt beklemez
- `procedure`: Yanıt bekler
- `simpleprocedure`: Yanıt beklemez
- `function`: Yanıt bekler

### Örnek

Bu durumda çok basit bir function içeren bir definition file oluşturun:
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
İlk **argümanın bağlanılacak port olduğunu** ve MIG'in **reply port'u otomatik olarak yöneteceğini** (istemci kodunda `mig_get_reply_port()` çağrılmadığı sürece) unutmayın. Ayrıca, **işlemlerin ID'leri**, belirtilen subsystem ID'den başlayarak **ardışık olacaktır** (bu nedenle bir işlem kullanımdan kaldırılırsa silinir ve ID'sini kullanmaya devam etmek için `skip` kullanılır).

Şimdi, Subtract function'ı çağırmak üzere birbirleriyle iletişim kurabilecek server ve client kodunu oluşturmak için MIG'i kullanın:
```bash
mig -header myipcUser.h -sheader myipcServer.h myipc.defs
```
Geçerli dizinde birkaç yeni dosya oluşturulacaktır.

> [!TIP]
> Sisteminizde daha karmaşık bir örneği şu komutla bulabilirsiniz: `mdfind mach_port.defs`\
> Ve dosyayla aynı klasörden şu komutla derleyebilirsiniz: `mig -DLIBSYSCALL_INTERFACE mach_ports.defs`<sup>[[2]](#references)</sup>

**`myipcServer.c`** ve **`myipcServer.h`** dosyalarında, alınan message ID'ye göre çağrılacak function'ı temel olarak tanımlayan **`SERVERPREFmyipc_subsystem`** struct'ının declaration ve definition'ını bulabilirsiniz (500 olarak bir başlangıç numarası belirttik):

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

Önceki struct'a dayanarak **`myipc_server_routine`** işlevi **message ID** değerini alacak ve çağrılacak uygun işlevi döndürecektir:
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
Bu örnekte definitions içinde yalnızca 1 function tanımladık; ancak daha fazla function tanımlamış olsaydık, bunlar **`SERVERPREFmyipc_subsystem`** array'inin içinde yer alacak ve ilki **500** ID'sine, ikincisi **501** ID'sine atanacaktı...

Function'ın bir **reply** göndermesi bekleniyorsa `mig_internal kern_return_t __MIG_check__Reply__<name>` function'ı da mevcut olacaktı.

Aslında bu ilişkiyi **`myipcServer.h`** içindeki **`subsystem_to_name_map_myipc`** struct'ında (diğer dosyalarda **`subsystem*to_name_map*\***`) tespit etmek mümkündür:
```c
#ifndef subsystem_to_name_map_myipc
#define subsystem_to_name_map_myipc \
{ "Subtract", 500 }
#endif
```
Son olarak, sunucunun çalışmasını sağlayacak bir diğer önemli function, alınan id ile ilişkili **function'ı çağıracak** olan **`myipc_server`** olacaktır:<sup>[[3]](#references)</sup>

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

ID ile çağrılacak function'a erişen, daha önce vurgulanan satırları inceleyin.

Aşağıda, client'ın server'dan Subtract function'larını çağırabileceği basit bir **server** ve **client** oluşturma kodu yer almaktadır:

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

NDR_record, `libsystem_kernel.dylib` tarafından export edilir ve MIG'in **verileri sistemden bağımsız olacak şekilde dönüştürmesini** sağlayan bir struct'tır; çünkü MIG, yalnızca aynı makine içinde değil, farklı sistemler arasında kullanılmak üzere tasarlanmıştır.

Bu ilginçtir; çünkü `_NDR_record` bir binary içinde dependency olarak (`jtool2 -S <binary> | grep NDR` veya `nm`) bulunuyorsa, bu binary'nin bir MIG istemcisi veya sunucusu olduğu anlamına gelir.

Ayrıca **MIG sunucuları**, dispatch table'ı `__DATA.__const` içinde (macOS kernel'da `__CONST.__constdata` ve diğer \*OS kernel'larında `__DATA_CONST.__const` içinde) bulundurur. Bu tablo **`jtool2`** ile dump edilebilir.

**MIG istemcileri** ise `__mach_msg` ile sunuculara göndermek üzere `__NDR_record` kullanır.

## Binary Analysis

### jtool

Günümüzde birçok binary, mach port'ları expose etmek için MIG kullandığından, **MIG'in kullanıldığını** ve her message ID ile MIG'in **hangi function'ları çalıştırdığını** belirlemek önemlidir.

[**jtool2**](../../macos-apps-inspecting-debugging-and-fuzzing/index.html#jtool2), bir Mach-O binary içindeki MIG bilgilerini parse ederek message ID'yi gösterir ve çalıştırılacak function'ı belirler:
```bash
jtool2 -d __DATA.__const myipc_server | grep MIG
```
Ayrıca, MIG fonksiyonları çağrılan gerçek fonksiyonun wrapper'larıdır. Bu nedenle, disassembly'yi elde edip `BL` araması yaparak çağrılan gerçek fonksiyonu bulabilirsiniz:
```bash
jtool2 -d __DATA.__const myipc_server | grep BL
```
### Assembly

Daha önce, **alınan message ID'ye bağlı olarak doğru function'ı çağırmaktan sorumlu olacak function'ın** `myipc_server` olduğu belirtilmişti. Ancak genellikle binary'nin symbol'larına sahip olmayacağınızdan (function isimleri bulunmaz), **decompile edildiğinde nasıl göründüğünü** kontrol etmek ilgi çekicidir; çünkü bu görünüm her zaman birbirine çok benzer (bu function'ın code'u, expose edilen function'lardan bağımsızdır):

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
Bu, farklı bir Hopper free version'ında decompile edilmiş aynı function'dır:

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

Aslında **`0x100004000`** function'ına giderseniz, **`routine_descriptor`** struct'larının array'ini bulacaksınız. Struct'ın ilk elementi, **function'ın** implement edildiği **adrestir** ve **struct 0x28 byte** uzunluğundadır; dolayısıyla byte 0'dan başlayarak her 0x28 byte'ta 8 byte alabilir ve bu değer, çağrılacak **function'ın adresi** olur:

<figure><img src="../../../../images/image (35).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../../images/image (36).png" alt=""><figcaption></figcaption></figure>

Bu data [**bu Hopper script'i kullanılarak**](https://github.com/knightsc/hopper/blob/master/scripts/MIG%20Detect.py) extract edilebilir.

### Debug

MIG tarafından generate edilen code, entry ve exit işlemleri hakkında log'lar oluşturmak için `kernel_debug`'ı da çağırır. Bunları **`trace`** veya **`kdv`** kullanarak incelemek mümkündür: `kdv all | grep MIG`

## References

- [1] [bootstrap_cmds — `migcom.tproj` (MIG compiler'ın kendisi)](https://github.com/apple-oss-distributions/bootstrap_cmds/tree/main/migcom.tproj)
- [2] [XNU — `osfmk/mach/mach_port.defs` (örnek MIG subsystem definition'ı)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/mach_port.defs)
- [3] [XNU — `osfmk/mach/message.h` (Mach message header layout'u)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/message.h)
- [4] [XNU — `osfmk/mach/task.defs` (task subsystem MIG definition'ı)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/task.defs)
{{#include ../../../../banners/hacktricks-training.md}}
