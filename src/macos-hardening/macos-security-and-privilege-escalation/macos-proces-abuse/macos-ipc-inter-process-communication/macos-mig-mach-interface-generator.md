# macOS MIG - Mach Interface Generator

{{#include ../../../../banners/hacktricks-training.md}}

## Temel Bilgiler

MIG, **Mach IPC** kodu oluşturma sürecini **basitleştirmek** için yaratılmıştır. Temelde, belirli bir tanım ile sunucu ve istemcinin iletişim kurması için **gerekli kodu üretir**. Üretilen kod çirkin olsa da, bir geliştirici sadece onu içe aktarmalı ve kodu öncekinden çok daha basit olacaktır.

Tanım, `.defs` uzantısını kullanarak Arayüz Tanım Dili (IDL) ile belirtilir.

Bu tanımlar 5 bölümden oluşur:

- **Alt sistem bildirimi**: Alt sistem anahtar kelimesi, **isim** ve **kimlik** belirtmek için kullanılır. Sunucunun çekirdek içinde çalışması gerekiyorsa **`KernelServer`** olarak işaretlemek de mümkündür.
- **Dahil etme ve içe aktarma**: MIG, C ön işleyicisini kullandığı için içe aktarmaları kullanabilir. Ayrıca, kullanıcı veya sunucu tarafından üretilen kodlar için `uimport` ve `simport` kullanmak mümkündür.
- **Tür bildirimleri**: Veri türlerini tanımlamak mümkündür, ancak genellikle `mach_types.defs` ve `std_types.defs` dosyalarını içe aktarır. Özel türler için bazı sözdizimleri kullanılabilir:
- \[i`n/out]tran`: Gelen veya giden bir mesajdan çevrilmesi gereken fonksiyon
- `c[user/server]type`: Başka bir C türüne eşleme.
- `destructor`: Tür serbest bırakıldığında bu fonksiyonu çağır.
- **İşlemler**: Bunlar RPC yöntemlerinin tanımlarıdır. 5 farklı tür vardır:
- `routine`: Yanıt bekler
- `simpleroutine`: Yanıt beklemez
- `procedure`: Yanıt bekler
- `simpleprocedure`: Yanıt beklemez
- `function`: Yanıt bekler

### Örnek

Bu durumda çok basit bir fonksiyon ile bir tanım dosyası oluşturun:
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
Not edin ki ilk **argüman bağlanacak porttur** ve MIG **yanıt portunu otomatik olarak yönetecektir** (müşteri kodunda `mig_get_reply_port()` çağrılmadığı sürece). Ayrıca, **işlemlerin ID'si** belirtilen alt sistem ID'sinden **sıralı** olarak başlayacaktır (yani bir işlem geçersiz kılındığında silinir ve ID'sini hala kullanmak için `skip` kullanılır).

Şimdi MIG'i kullanarak birbirleriyle iletişim kurabilecek sunucu ve istemci kodunu oluşturun ve Çıkarma fonksiyonunu çağırın:
```bash
mig -header myipcUser.h -sheader myipcServer.h myipc.defs
```
Mevcut dizinde birkaç yeni dosya oluşturulacaktır.

> [!TIP]
> Daha karmaşık bir örneği sisteminizde bulabilirsiniz: `mdfind mach_port.defs`\
> Ve dosyanın bulunduğu klasörden derleyebilirsiniz: `mig -DLIBSYSCALL_INTERFACE mach_ports.defs`

Dosyalarda **`myipcServer.c`** ve **`myipcServer.h`** **`SERVERPREFmyipc_subsystem`** yapısının beyanını ve tanımını bulabilirsiniz; bu yapı, alınan mesaj ID'sine dayalı olarak çağrılacak fonksiyonu tanımlar (başlangıç numarası olarak 500 belirttik):

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

Önceki yapıya dayanarak, **`myipc_server_routine`** fonksiyonu **mesaj ID'sini** alacak ve çağrılacak uygun fonksiyonu döndürecektir:
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
Bu örnekte tanımlamalarda yalnızca 1 fonksiyon tanımlamışız, ancak daha fazla fonksiyon tanımlasaydık, bunlar **`SERVERPREFmyipc_subsystem`** dizisi içinde yer alırdı ve ilki ID **500**'e, ikincisi ID **501**'e atanırdı...

Fonksiyonun bir **reply** göndermesi bekleniyorsa, `mig_internal kern_return_t __MIG_check__Reply__<name>` fonksiyonu da mevcut olurdu.

Aslında, bu ilişkiyi **`myipcServer.h`** içindeki **`subsystem_to_name_map_myipc`** yapısında tanımlamak mümkündür (**`subsystem*to_name_map*\***`** diğer dosyalarda):
```c
#ifndef subsystem_to_name_map_myipc
#define subsystem_to_name_map_myipc \
{ "Subtract", 500 }
#endif
```
Son olarak, sunucunun çalışmasını sağlamak için önemli bir başka işlev **`myipc_server`** olacaktır; bu, alınan id ile ilgili **işlevi çağıracak** olanıdır:

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
/* Minimal boyut: routine() farklıysa güncelleyecektir */
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

ID ile çağrılacak işlevi erişen daha önce vurgulanan satırları kontrol edin.

Aşağıda, istemcinin sunucudan Çıkarma işlevlerini çağırabileceği basit bir **sunucu** ve **istemci** oluşturmak için kod bulunmaktadır:

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

NDR_record, `libsystem_kernel.dylib` tarafından dışa aktarılır ve MIG'in **verileri sistemden bağımsız hale getirmesine** olanak tanıyan bir yapıdır; çünkü MIG'in farklı sistemler arasında (sadece aynı makinede değil) kullanılmak üzere tasarlandığı düşünülmektedir.

Bu ilginçtir çünkü eğer bir ikili dosyada `_NDR_record` bir bağımlılık olarak bulunursa (`jtool2 -S <binary> | grep NDR` veya `nm`), bu, ikili dosyanın bir MIG istemcisi veya sunucusu olduğu anlamına gelir.

Ayrıca **MIG sunucuları**, `__DATA.__const` içinde (veya macOS çekirdeğinde `__CONST.__constdata` ve diğer \*OS çekirdeklerinde `__DATA_CONST.__const`) dağıtım tablosuna sahiptir. Bu, **`jtool2`** ile dökülebilir.

Ve **MIG istemcileri**, sunuculara `__mach_msg` ile göndermek için `__NDR_record` kullanacaktır.

## İkili Analiz

### jtool

Birçok ikili dosya artık mach portlarını açmak için MIG kullanıyorsa, **MIG'in nasıl kullanıldığını** ve her mesaj kimliği ile **MIG'in hangi işlevleri yürüttüğünü** bilmek ilginçtir.

[**jtool2**](../../macos-apps-inspecting-debugging-and-fuzzing/index.html#jtool2), bir Mach-O ikili dosyasından MIG bilgilerini ayrıştırabilir, mesaj kimliğini belirtebilir ve yürütülecek işlevi tanımlayabilir:
```bash
jtool2 -d __DATA.__const myipc_server | grep MIG
```
Ayrıca, MIG fonksiyonları çağrılan gerçek fonksiyonların sadece sarmalayıcılarıdır, bu da demektir ki, onun ayrıştırmasını alıp BL için grep yaparsanız, çağrılan gerçek fonksiyonu bulabilirsiniz:
```bash
jtool2 -d __DATA.__const myipc_server | grep BL
```
### Assembly

Daha önce, **gelen mesaj ID'sine bağlı olarak doğru fonksiyonu çağıracak olan** fonksiyonun `myipc_server` olduğu belirtilmişti. Ancak genellikle ikili dosyanın sembollerine (fonksiyon isimlerine) sahip olmayacaksınız, bu nedenle **dekompile edilmiş halinin nasıl göründüğünü kontrol etmek ilginçtir** çünkü bu fonksiyonun kodu, sergilenen fonksiyonlardan bağımsız olarak her zaman çok benzer olacaktır:

{{#tabs}}
{{#tab name="myipc_server decompiled 1"}}

<pre class="language-c"><code class="lang-c">int _myipc_server(int arg0, int arg1) {
var_10 = arg0;
var_18 = arg1;
// Uygun fonksiyon işaretçilerini bulmak için başlangıç talimatları
*(int32_t *)var_18 = *(int32_t *)var_10 & 0x1f;
*(int32_t *)(var_18 + 0x8) = *(int32_t *)(var_10 + 0x8);
*(int32_t *)(var_18 + 0x4) = 0x24;
*(int32_t *)(var_18 + 0xc) = 0x0;
*(int32_t *)(var_18 + 0x14) = *(int32_t *)(var_10 + 0x14) + 0x64;
*(int32_t *)(var_18 + 0x10) = 0x0;
if (*(int32_t *)(var_10 + 0x14) <= 0x1f4 && *(int32_t *)(var_10 + 0x14) >= 0x1f4) {
rax = *(int32_t *)(var_10 + 0x14);
// Bu fonksiyonu tanımlamaya yardımcı olabilecek sign_extend_64 çağrısı
// Bu, rax'ta çağrılması gereken çağrının işaretçisini saklar
// 0x100004040 adresinin kullanıldığını kontrol et (fonksiyon adresleri dizisi)
// 0x1f4 = 500 (başlangıç ID'si)
<strong>            rax = *(sign_extend_64(rax - 0x1f4) * 0x28 + 0x100004040);
</strong>            var_20 = rax;
// Eğer - else, if false dönerken, else doğru fonksiyonu çağırır ve true döner
<strong>            if (rax == 0x0) {
</strong>                    *(var_18 + 0x18) = **_NDR_record;
*(int32_t *)(var_18 + 0x20) = 0xfffffffffffffed1;
var_4 = 0x0;
}
else {
// İki argümanla uygun fonksiyonu çağıran hesaplanan adres
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
Bu, farklı bir Hopper ücretsiz versiyonunda dekompile edilmiş aynı fonksiyondur:

<pre class="language-c"><code class="lang-c">int _myipc_server(int arg0, int arg1) {
r31 = r31 - 0x40;
saved_fp = r29;
stack[-8] = r30;
var_10 = arg0;
var_18 = arg1;
// Uygun fonksiyon işaretçilerini bulmak için başlangıç talimatları
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
// 0x1f4 = 500 (başlangıç ID'si)
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
// Önceki versiyondakiyle aynı if else
// 0x100004040 adresinin kullanıldığını kontrol et (fonksiyon adresleri dizisi)
<strong>                    if ((r8 & 0x1) == 0x0) {
</strong><strong>                            *(var_18 + 0x18) = **0x100004000;
</strong>                            *(int32_t *)(var_18 + 0x20) = 0xfffffed1;
var_4 = 0x0;
}
else {
// Fonksiyonun çağrılması gereken hesaplanan adrese çağrı
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

Aslında **`0x100004000`** fonksiyonuna giderseniz, **`routine_descriptor`** yapıların dizisini bulacaksınız. Yapının ilk elemanı, **fonksiyonun** uygulandığı **adres** ve **yapı 0x28 bayt** alır, bu nedenle her 0x28 bayt (0. bayttan başlayarak) 8 bayt alabilir ve bu, çağrılacak **fonksiyonun adresi** olacaktır:

<figure><img src="../../../../images/image (35).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../../images/image (36).png" alt=""><figcaption></figcaption></figure>

Bu veriler [**bu Hopper scriptini kullanarak**](https://github.com/knightsc/hopper/blob/master/scripts/MIG%20Detect.py) çıkarılabilir.

### Debug

MIG tarafından üretilen kod ayrıca giriş ve çıkış işlemleri hakkında günlükler oluşturmak için `kernel_debug` çağrısını da yapar. Bunları **`trace`** veya **`kdv`** kullanarak kontrol etmek mümkündür: `kdv all | grep MIG`

## References

- [\*OS Internals, Volume I, User Mode, Jonathan Levin](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

{{#include ../../../../banners/hacktricks-training.md}}
