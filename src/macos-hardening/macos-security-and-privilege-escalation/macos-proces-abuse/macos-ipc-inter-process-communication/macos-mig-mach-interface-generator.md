# macOS MIG - Mach Interface Generator

{{#include ../../../../banners/hacktricks-training.md}}

## Basic Information

MIG iliumbwa ili **kurahisisha mchakato wa uundaji wa Mach IPC**. Kimsingi **inazalisha msimbo unaohitajika** kwa server na mteja kuwasiliana na ufafanuzi uliopewa. Hata kama msimbo uliozalishwa ni mbaya, mendelezi atahitaji tu kuingiza na msimbo wake utakuwa rahisi zaidi kuliko kabla.

Ufafanuzi umeainishwa katika Lugha ya Ufafanuzi wa Interface (IDL) kwa kutumia kiambishi cha `.defs`.

Mafafanuzi haya yana sehemu 5:

- **Tangazo la subsystem**: Neno muhimu subsystem linatumika kuashiria **jina** na **id**. Pia inawezekana kuashiria kama **`KernelServer`** ikiwa server inapaswa kukimbia katika kernel.
- **Injizaji na uagizaji**: MIG inatumia C-preprocessor, hivyo inaweza kutumia uagizaji. Aidha, inawezekana kutumia `uimport` na `simport` kwa msimbo ulioandikwa na mtumiaji au server.
- **Matangazo ya aina**: Inawezekana kufafanua aina za data ingawa kawaida itauagiza `mach_types.defs` na `std_types.defs`. Kwa zile za kawaida baadhi ya sintaks inaweza kutumika:
- \[i`n/out]tran`: Kazi inayohitaji kutafsiriwa kutoka ujumbe unaoingia au kwenda ujumbe unaotoka
- `c[user/server]type`: Ramani kwa aina nyingine ya C.
- `destructor`: Piga simu kwa kazi hii wakati aina inachukuliwa.
- **Operesheni**: Hizi ni ufafanuzi wa mbinu za RPC. Kuna aina 5 tofauti:
- `routine`: Inatarajia jibu
- `simpleroutine`: Haitarajia jibu
- `procedure`: Inatarajia jibu
- `simpleprocedure`: Haitarajia jibu
- `function`: Inatarajia jibu

### Example

Create a definition file, in this case with a very simple function:
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
Kumbuka kwamba **hoja ya kwanza ni bandari ya kuunganisha** na MIG itashughulikia **bandari ya majibu kiotomatiki** (isipokuwa unaita `mig_get_reply_port()` katika msimbo wa mteja). Zaidi ya hayo, **ID ya operesheni** itakuwa **mfuatano** ikianza na ID ya mfumo iliyoonyeshwa (hivyo ikiwa operesheni imeondolewa inafutwa na `skip` inatumika ili bado kutumia ID yake).

Sasa tumia MIG kuunda msimbo wa seva na mteja ambao utaweza kuwasiliana kati yao ili kuita kazi ya Subtract:
```bash
mig -header myipcUser.h -sheader myipcServer.h myipc.defs
```
Kadhaa ya faili mpya zitaundwa katika saraka ya sasa.

> [!TIP]
> Unaweza kupata mfano mgumu zaidi katika mfumo wako kwa kutumia: `mdfind mach_port.defs`\
> Na unaweza kuikamilisha kutoka kwenye folda ile ile kama faili kwa kutumia: `mig -DLIBSYSCALL_INTERFACE mach_ports.defs`

Katika faili **`myipcServer.c`** na **`myipcServer.h`** unaweza kupata tangazo na ufafanuzi wa muundo **`SERVERPREFmyipc_subsystem`**, ambao kimsingi unafafanua kazi ya kuita kulingana na kitambulisho cha ujumbe kilichopokelewa (tulionyesha nambari ya kuanzia 500):

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

Kulingana na muundo wa awali, kazi **`myipc_server_routine`** itapata **kitambulisho cha ujumbe** na kurudisha kazi sahihi ya kuita:
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
Katika mfano huu tumefafanua tu kazi 1 katika maelezo, lakini kama tungeweza kufafanua kazi zaidi, zingekuwa ndani ya array ya **`SERVERPREFmyipc_subsystem`** na ya kwanza ingekuwa imepewa ID **500**, ya pili ingekuwa na ID **501**...

Ikiwa kazi ilitarajiwa kutuma **reply** kazi `mig_internal kern_return_t __MIG_check__Reply__<name>` pia ingekuwepo.

Kwa kweli inawezekana kubaini uhusiano huu katika struct **`subsystem_to_name_map_myipc`** kutoka **`myipcServer.h`** (**`subsystem*to_name_map*\***`** katika faili zingine):
```c
#ifndef subsystem_to_name_map_myipc
#define subsystem_to_name_map_myipc \
{ "Subtract", 500 }
#endif
```
Hatimaye, kazi nyingine muhimu ili kufanya seva ifanye kazi itakuwa **`myipc_server`**, ambayo ndiyo itakayofanya **kuita kazi** inayohusiana na kitambulisho kilichopokelewa:

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
/* Ukubwa wa chini: routine() itasasisha ikiwa tofauti */
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

Angalia mistari iliyosisitizwa hapo awali inayoingia kwenye kazi ya kuita kwa ID.

Ifuatayo ni msimbo wa kuunda **seva** na **mteja** ambapo mteja anaweza kuita kazi ya Kupunguza kutoka kwa seva:

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

NDR_record inasafirishwa na `libsystem_kernel.dylib`, na ni struct inayoruhusu MIG **kubadilisha data ili iweze kutumika bila kujali mfumo** inatumika kama MIG ilidhaniwa kutumika kati ya mifumo tofauti (na sio tu kwenye mashine moja).

Hii ni ya kuvutia kwa sababu ikiwa `_NDR_record` inapatikana katika binary kama utegemezi (`jtool2 -S <binary> | grep NDR` au `nm`), inamaanisha kwamba binary ni mteja au Server wa MIG.

Zaidi ya hayo, **MIG servers** zina meza ya dispatch katika `__DATA.__const` (au katika `__CONST.__constdata` katika kernel ya macOS na `__DATA_CONST.__const` katika kernel nyingine za \*OS). Hii inaweza kutolewa kwa **`jtool2`**.

Na **MIG clients** zitatumia `__NDR_record` kutuma na `__mach_msg` kwa servers.

## Uchambuzi wa Binary

### jtool

Kama binaries nyingi sasa zinatumia MIG kufichua mach ports, ni ya kuvutia kujua jinsi ya **kutambua kwamba MIG ilitumika** na **kazi ambazo MIG inatekeleza** na kila kitambulisho cha ujumbe.

[**jtool2**](../../macos-apps-inspecting-debugging-and-fuzzing/index.html#jtool2) inaweza kuchambua taarifa za MIG kutoka kwa binary ya Mach-O ikionyesha kitambulisho cha ujumbe na kutambua kazi ya kutekeleza:
```bash
jtool2 -d __DATA.__const myipc_server | grep MIG
```
Zaidi ya hayo, kazi za MIG ni vifungashio vya kazi halisi inayoitwa, ambayo inamaanisha kwamba kupata usambazaji wake na kutafuta BL unaweza kukuwezesha kupata kazi halisi inayoitwa:
```bash
jtool2 -d __DATA.__const myipc_server | grep BL
```
### Assembly

Ilielezwa awali kwamba kazi ambayo itashughulikia **kuita kazi sahihi kulingana na kitambulisho cha ujumbe kilichopokelewa** ilikuwa `myipc_server`. Hata hivyo, kwa kawaida hutakuwa na alama za binary (hakuna majina ya kazi), hivyo ni muhimu **kuangalia inavyoonekana baada ya kutafsiriwa** kwani itakuwa karibu sawa kila wakati (kanuni ya kazi hii haitegemei kazi zilizowekwa):

{{#tabs}}
{{#tab name="myipc_server decompiled 1"}}

<pre class="language-c"><code class="lang-c">int _myipc_server(int arg0, int arg1) {
var_10 = arg0;
var_18 = arg1;
// Maagizo ya awali ya kutafuta viashiria sahihi vya kazi
*(int32_t *)var_18 = *(int32_t *)var_10 & 0x1f;
*(int32_t *)(var_18 + 0x8) = *(int32_t *)(var_10 + 0x8);
*(int32_t *)(var_18 + 0x4) = 0x24;
*(int32_t *)(var_18 + 0xc) = 0x0;
*(int32_t *)(var_18 + 0x14) = *(int32_t *)(var_10 + 0x14) + 0x64;
*(int32_t *)(var_18 + 0x10) = 0x0;
if (*(int32_t *)(var_10 + 0x14) <= 0x1f4 && *(int32_t *)(var_10 + 0x14) >= 0x1f4) {
rax = *(int32_t *)(var_10 + 0x14);
// Kuitisha sign_extend_64 ambayo inaweza kusaidia kutambua kazi hii
// Hii inahifadhi katika rax kiashiria cha simu ambacho kinahitaji kuitwa
// Angalia matumizi ya anwani 0x100004040 (array ya anwani za kazi)
// 0x1f4 = 500 (kitambulisho cha kuanzia)
<strong>            rax = *(sign_extend_64(rax - 0x1f4) * 0x28 + 0x100004040);
</strong>            var_20 = rax;
// Ikiwa - vinginevyo, ikiwa inarudi uongo, wakati vinginevyo inaita kazi sahihi na inarudi kweli
<strong>            if (rax == 0x0) {
</strong>                    *(var_18 + 0x18) = **_NDR_record;
*(int32_t *)(var_18 + 0x20) = 0xfffffffffffffed1;
var_4 = 0x0;
}
else {
// Anwani iliyohesabiwa inayoiita kazi sahihi na hoja 2
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
Hii ni kazi ile ile iliyotafsiriwa katika toleo tofauti la Hopper bure:

<pre class="language-c"><code class="lang-c">int _myipc_server(int arg0, int arg1) {
r31 = r31 - 0x40;
saved_fp = r29;
stack[-8] = r30;
var_10 = arg0;
var_18 = arg1;
// Maagizo ya awali ya kutafuta viashiria sahihi vya kazi
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
// 0x1f4 = 500 (kitambulisho cha kuanzia)
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
// Hali sawa kama katika toleo la awali
// Angalia matumizi ya anwani 0x100004040 (array ya anwani za kazi)
<strong>                    if ((r8 & 0x1) == 0x0) {
</strong><strong>                            *(var_18 + 0x18) = **0x100004000;
</strong>                            *(int32_t *)(var_18 + 0x20) = 0xfffffed1;
var_4 = 0x0;
}
else {
// Kuitisha anwani iliyohesabiwa ambapo kazi inapaswa kuwa
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

Kwa kweli ikiwa utaenda kwenye kazi **`0x100004000`** utapata array ya **`routine_descriptor`** structs. Kigezo cha kwanza cha struct ni **anwani** ambapo **kazi** imewekwa, na **struct inachukua 0x28 bytes**, hivyo kila byte 0x28 (kuanzia byte 0) unaweza kupata byte 8 na hiyo itakuwa **anwani ya kazi** ambayo itaitwa:

<figure><img src="../../../../images/image (35).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../../images/image (36).png" alt=""><figcaption></figcaption></figure>

Data hii inaweza kutolewa [**kwa kutumia script hii ya Hopper**](https://github.com/knightsc/hopper/blob/master/scripts/MIG%20Detect.py).

### Debug

Kanuni iliyozalishwa na MIG pia inaita `kernel_debug` ili kuzalisha log kuhusu operesheni za kuingia na kutoka. Inawezekana kuangalia hizo kwa kutumia **`trace`** au **`kdv`**: `kdv all | grep MIG`

## References

- [\*OS Internals, Volume I, User Mode, Jonathan Levin](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

{{#include ../../../../banners/hacktricks-training.md}}
