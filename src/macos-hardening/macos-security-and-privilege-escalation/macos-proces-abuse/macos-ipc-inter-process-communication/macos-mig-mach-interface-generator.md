# macOS MIG - Mach Interface Generator

{{#include ../../../../banners/hacktricks-training.md}}

## Taarifa za Msingi

MIG iliundwa ili **kurahisisha mchakato wa kuunda** code ya Mach IPC. Kimsingi **hutengeneza code inayohitajika** ili server na client ziwasiliane kwa kutumia definition fulani. Hata kama code iliyotengenezwa si nzuri, developer atahitaji tu kui-import, na code yake itakuwa rahisi zaidi kuliko hapo awali.

Definition hubainishwa katika Interface Definition Language (IDL) kwa kutumia extension ya `.defs`.

Definitions hizi zina sehemu 5:

- **Subsystem declaration**: Keyword subsystem hutumiwa kuonyesha **jina** na **id**. Pia inawezekana kuiweka kama **`KernelServer`** ikiwa server inapaswa kuendeshwa kwenye kernel.
- **Inclusions and imports**: MIG hutumia C-prepocessor, hivyo inaweza kutumia imports. Zaidi ya hayo, inawezekana kutumia `uimport` na `simport` kwa code inayotengenezwa ya user au server.
- **Type declarations**: Inawezekana kufafanua data types, ingawa kwa kawaida ita-import `mach_types.defs` na `std_types.defs`. Kwa custom types, syntax fulani inaweza kutumika:
- \[i`n/out]tran`: Function inayohitaji kutafsiriwa kutoka kwenye message inayoingia au kwenda kwenye message inayotoka
- `c[user/server]type`: Mapping kwenda kwenye C type nyingine.
- `destructor`: Ita-call function hii wakati type inaachiliwa.
- **Operations**: Hizi ni definitions za RPC methods. Kuna aina 5 tofauti:
- `routine`: Inatarajia reply
- `simpleroutine`: Haitarajii reply
- `procedure`: Inatarajia reply
- `simpleprocedure`: Haitarajii reply
- `function`: Inatarajia reply

### Mfano

Unda definition file, katika hali hii ikiwa na function rahisi sana:
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
Kumbuka kwamba **argument ya kwanza ni port ya kufungia bind** na MIG **itashughulikia port ya reply kiotomatiki** (isipokuwa unapoiita `mig_get_reply_port()` kwenye code ya client). Zaidi ya hayo, **ID za operations** zitakuwa **za kufuatana**, zikianza na subsystem ID iliyoonyeshwa (hivyo, ikiwa operation imepitwa na wakati, inafutwa na `skip` hutumika ili kuendelea kutumia ID yake).

Sasa tumia MIG kutengeneza code ya server na client itakayoweza kuwasiliana ili kuita function ya Subtract:
```bash
mig -header myipcUser.h -sheader myipcServer.h myipc.defs
```
Faili kadhaa mpya zitaundwa katika directory ya sasa.

> [!TIP]
> Unaweza kupata mfano changamano zaidi kwenye mfumo wako kwa kutumia: `mdfind mach_port.defs`\
> Na unaweza kuicompile kutoka folder ileile iliyo na faili hiyo kwa kutumia: `mig -DLIBSYSCALL_INTERFACE mach_ports.defs`

Katika faili **`myipcServer.c`** na **`myipcServer.h`** unaweza kupata declaration na definition ya struct **`SERVERPREFmyipc_subsystem`**, ambayo kimsingi hufafanua function ya kuita kulingana na message ID iliyopokelewa (tulionyesha nambari ya kuanzia kuwa 500):

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

Kwa kuzingatia struct iliyotangulia, function **`myipc_server_routine`** itapata **message ID** na kurudisha function sahihi ya kuita:
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
Katika mfano huu tumefafanua function 1 katika definitions, lakini kama tungefafanua functions zaidi, zingekuwa ndani ya array ya **`SERVERPREFmyipc_subsystem`**, na ya kwanza ingepewa ID **500**, ya pili ID **501**...

Ikiwa function ilitarajiwa kutuma **reply**, function `mig_internal kern_return_t __MIG_check__Reply__<name>` pia ingekuwepo.

Kwa kweli, inawezekana kutambua uhusiano huu katika struct **`subsystem_to_name_map_myipc`** kutoka **`myipcServer.h`** (**`subsystem*to_name_map*\*`** katika files nyingine):
```c
#ifndef subsystem_to_name_map_myipc
#define subsystem_to_name_map_myipc \
{ "Subtract", 500 }
#endif
```
Hatimaye, function nyingine muhimu ya kufanya server ifanye kazi itakuwa **`myipc_server`**, ambayo ndiyo itakayo **ita function** inayohusiana na id iliyopokelewa:

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

Kagua mistari iliyoangaziwa hapo awali inayofikia function itakayoitwa kwa kutumia ID.

Ifuatayo ni code ya kuunda **server** na **client** rahisi, ambapo client inaweza kuita functions za Subtract kutoka kwa server:

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

NDR_record inatumwa na `libsystem_kernel.dylib`, na ni struct inayowezesha MIG **kubadilisha data ili isiathiriwe na mfumo** unaotumika, kwa kuwa MIG ilibuniwa kutumiwa kati ya mifumo tofauti (na si ndani ya machine moja pekee).

Hili ni muhimu kwa sababu ikiwa `_NDR_record` inapatikana kwenye binary kama dependency (`jtool2 -S <binary> | grep NDR` au `nm`), inamaanisha kuwa binary hiyo ni MIG client au Server.

Zaidi ya hayo, **MIG servers** huwa na dispatch table katika `__DATA.__const` (au katika `__CONST.__constdata` kwenye macOS kernel na `__DATA_CONST.__const` kwenye *OS kernels nyingine). Hii inaweza kudumpiwa kwa kutumia **`jtool2`**.

Na **MIG clients** zitatumia `__NDR_record` kuituma pamoja na `__mach_msg` kwa servers.

## Binary Analysis

### jtool

Kwa kuwa binaries nyingi sasa hutumia MIG kufichua mach ports, ni muhimu kujua jinsi ya **kutambua kuwa MIG imetumika** na **functions ambazo MIG hutekeleza** kwa kila message ID.

[**jtool2**](../../macos-apps-inspecting-debugging-and-fuzzing/index.html#jtool2) inaweza kuchanganua taarifa za MIG kutoka kwenye Mach-O binary, ikionyesha message ID na kubainisha function ya kutekeleza:
```bash
jtool2 -d __DATA.__const myipc_server | grep MIG
```
Zaidi ya hayo, MIG functions ni wrappers tu za actual function inayoteuliwa, hivyo kupata disassembly yake na kufanya grep ya BL kunaweza kukusaidia kupata actual function inayoteuliwa:
```bash
jtool2 -d __DATA.__const myipc_server | grep BL
```
### Assembly

Iliwekwa wazi hapo awali kwamba function itakayoshughulikia **calling the correct function depending on the received message ID** ni `myipc_server`. Hata hivyo, kwa kawaida hutakuwa na symbols za binary (majina ya functions), kwa hiyo ni muhimu **kuangalia jinsi inavyoonekana ikiwa decompiled**, kwa kuwa daima itafanana sana (code ya function hii haitegemei functions zilizowekwa wazi):

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
Hii ni function ileile iliyo-decompiled katika toleo tofauti la Hopper free:

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

Kwa kweli ukienda kwenye function **`0x100004000`** utapata array ya structs za **`routine_descriptor`**. Kipengele cha kwanza cha struct ni **address** ambako **function** imetekelezwa, na **struct ina ukubwa wa 0x28 bytes**, kwa hiyo kila baada ya 0x28 bytes (kuanzia byte 0) unaweza kupata bytes 8, ambazo zitakuwa **address ya function** itakayoitwa:

<figure><img src="../../../../images/image (35).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../../images/image (36).png" alt=""><figcaption></figcaption></figure>

Data hii inaweza kutolewa [**kwa kutumia Hopper script hii**](https://github.com/knightsc/hopper/blob/master/scripts/MIG%20Detect.py).

### Debug

Code inayozalishwa na MIG pia huita `kernel_debug` ili kutengeneza logs kuhusu operations wakati wa kuingia na kutoka. Inawezekana kuzikagua kwa kutumia **`trace`** au **`kdv`**: `kdv all | grep MIG`

## Marejeo

- [1] [bootstrap_cmds — `migcom.tproj` (the MIG compiler itself)](https://github.com/apple-oss-distributions/bootstrap_cmds/tree/main/migcom.tproj)
- [2] [XNU — `osfmk/mach/mach_port.defs` (example MIG subsystem definition)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/mach_port.defs)
- [3] [XNU — `osfmk/mach/task.defs` (task subsystem MIG definition)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/task.defs)
- [4] [XNU — `osfmk/mach/message.h` (Mach message header layout)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/message.h)

{{#include ../../../../banners/hacktricks-training.md}}
