# macOS MIG - Mach Interface Generator

{{#include ../../../../banners/hacktricks-training.md}}

## मूलभूत जानकारी

MIG को **Mach IPC** code creation की प्रक्रिया को **सरल बनाने** के लिए बनाया गया था। यह मूल रूप से दिए गए definition के साथ server और client को communicate कराने के लिए आवश्यक code **generate** करता है। भले ही generated code देखने में खराब हो, developer को केवल इसे import करना होगा और उसका code पहले की तुलना में बहुत सरल होगा।<sup>[[1]](#references)</sup>

Definition को `.defs` extension का उपयोग करके Interface Definition Language (IDL) में specify किया जाता है।

इन definitions के 5 sections होते हैं:

- **Subsystem declaration**: `subsystem` keyword का उपयोग **name** और **id** बताने के लिए किया जाता है। इसे **`KernelServer`** के रूप में mark करना भी संभव है, यदि server को kernel में run करना हो।<sup>[[4]](#references)</sup>
- **Inclusions and imports**: MIG C-prepocessor का उपयोग करता है, इसलिए यह imports का उपयोग कर सकता है। इसके अलावा, user या server generated code के लिए `uimport` और `simport` का उपयोग करना संभव है।
- **Type declarations**: Data types define करना संभव है, हालांकि आमतौर पर यह `mach_types.defs` और `std_types.defs` को import करेगा। Custom types के लिए कुछ syntax का उपयोग किया जा सकता है:
- \[i`n/out]tran`: Incoming message से या outgoing message में translate किए जाने वाले Function
- `c[user/server]type`: किसी अन्य C type से Mapping।
- `destructor`: Type release होने पर इस function को Call करें।
- **Operations**: ये RPC methods की definitions हैं। इनके 5 अलग-अलग types होते हैं:
- `routine`: Reply की अपेक्षा करता है
- `simpleroutine`: Reply की अपेक्षा नहीं करता
- `procedure`: Reply की अपेक्षा करता है
- `simpleprocedure`: Reply की अपेक्षा नहीं करता
- `function`: Reply की अपेक्षा करता है

### उदाहरण

एक definition file बनाएँ, इस मामले में एक बहुत ही सरल function के साथ:
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
ध्यान दें कि पहला **argument bind किया जाने वाला port है** और MIG **reply port को automatically handle करेगा** (जब तक client code में `mig_get_reply_port()` को call न किया जाए)। इसके अलावा, **operations की ID** दिए गए subsystem ID से शुरू होकर **sequential** होंगी (इसलिए यदि कोई operation deprecated है, तो उसे delete कर दिया जाता है और उसकी ID का उपयोग जारी रखने के लिए `skip` का उपयोग किया जाता है)।

अब MIG का उपयोग करके server और client code generate करें, जो Subtract function को call करने के लिए आपस में communicate कर सकें:
```bash
mig -header myipcUser.h -sheader myipcServer.h myipc.defs
```
वर्तमान directory में कई नई files बनाई जाएंगी।

> [!TIP]
> आप अपने system में अधिक complex example इस command से पा सकते हैं: `mdfind mach_port.defs`\
> और आप इसे उसी folder से compile कर सकते हैं जिसमें file मौजूद है: `mig -DLIBSYSCALL_INTERFACE mach_ports.defs`<sup>[[2]](#references)</sup>

Files **`myipcServer.c`** और **`myipcServer.h`** में आपको struct **`SERVERPREFmyipc_subsystem`** की declaration और definition मिल सकती है, जो मूल रूप से प्राप्त message ID के आधार पर call किए जाने वाले function को define करता है (हमने 500 को starting number के रूप में दर्शाया था):

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

पिछली struct के आधार पर function **`myipc_server_routine`** को **message ID** मिलेगा और यह call करने के लिए उचित function return करेगा:
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
इस उदाहरण में हमने definitions में केवल 1 function define किया है, लेकिन यदि हमने अधिक functions define किए होते, तो वे **`SERVERPREFmyipc_subsystem`** के array के अंदर होते और पहले को ID **500**, दूसरे को ID **501**... assign किया जाता।

यदि function से **reply** भेजने की अपेक्षा होती, तो function `mig_internal kern_return_t __MIG_check__Reply__<name>` भी मौजूद होता।

वास्तव में **`myipcServer.h`** के struct **`subsystem_to_name_map_myipc`** (**`subsystem*to_name_map*\***`** अन्य files में) में इस relation की पहचान करना संभव है:
```c
#ifndef subsystem_to_name_map_myipc
#define subsystem_to_name_map_myipc \
{ "Subtract", 500 }
#endif
```
अंततः, server को काम करने के लिए एक और महत्वपूर्ण function **`myipc_server`** होगा, जो प्राप्त id से संबंधित **function को call** करेगा:<sup>[[3]](#references)</sup>

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

पहले highlight की गई lines को check करें, जो ID के आधार पर call किए जाने वाले function तक access करती हैं।

नीचे एक simple **server** और **client** बनाने का code दिया गया है, जिसमें client server से Subtract functions को call कर सकता है:

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

NDR_record को `libsystem_kernel.dylib` export करता है, और यह एक struct है जो MIG को **data को इस तरह transform करने की अनुमति देता है कि वह system से independent रहे**; क्योंकि MIG को अलग-अलग systems के बीच उपयोग करने के लिए बनाया गया था (न कि केवल एक ही machine में)।

यह महत्वपूर्ण है क्योंकि यदि `_NDR_record` किसी binary में dependency के रूप में (`jtool2 -S <binary> | grep NDR` या `nm`) पाया जाता है, तो इसका अर्थ है कि binary एक MIG client या Server है।

इसके अलावा **MIG servers** की dispatch table `__DATA.__const` (या macOS kernel में `__CONST.__constdata` और अन्य \*OS kernels में `__DATA_CONST.__const`) में होती है। इसे **`jtool2`** से dump किया जा सकता है।

और **MIG clients**, `__mach_msg` के साथ servers को भेजने के लिए `__NDR_record` का उपयोग करेंगे।

## Binary Analysis

### jtool

कई binaries अब mach ports expose करने के लिए MIG का उपयोग करती हैं, इसलिए यह जानना उपयोगी है कि **MIG का उपयोग किया गया था या नहीं** और प्रत्येक message ID के साथ MIG द्वारा execute किए जाने वाले **functions** कौन-से हैं।

[**jtool2**](../../macos-apps-inspecting-debugging-and-fuzzing/index.html#jtool2) Mach-O binary से MIG information parse कर सकता है, जिसमें message ID और execute किए जाने वाले function की पहचान शामिल होती है:
```bash
jtool2 -d __DATA.__const myipc_server | grep MIG
```
इसके अलावा, MIG functions उस वास्तविक function के चारों ओर wrappers होते हैं जिसे call किया जाता है। इसलिए, disassembly प्राप्त करके और `BL` को खोजकर, आप call किए जा रहे वास्तविक function को ढूंढ सकते हैं:
```bash
jtool2 -d __DATA.__const myipc_server | grep BL
```
### Assembly

पहले यह बताया गया था कि प्राप्त message ID के आधार पर **सही function को call करने का काम करने वाला function** `myipc_server` था। हालांकि, आमतौर पर आपके पास binary के symbols (कोई function names नहीं) नहीं होंगे, इसलिए यह देखना उपयोगी है कि decompiled रूप में यह कैसा दिखता है, क्योंकि यह हमेशा बहुत समान होगा (इस function का code exposed functions से independent होता है):

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
यह वही function है, जिसे Hopper के एक अलग free version में decompile किया गया है:

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

वास्तव में, यदि आप **`0x100004000`** function पर जाएं, तो आपको **`routine_descriptor`** structs का array मिलेगा। Struct का पहला element वह **address** है जहां **function** implemented है, और **struct का आकार `0x28` bytes** है। इसलिए byte 0 से शुरू करके प्रत्येक 0x28 bytes पर आप 8 bytes प्राप्त कर सकते हैं, जो call किए जाने वाले **function का address** होगा:

<figure><img src="../../../../images/image (35).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../../images/image (36).png" alt=""><figcaption></figcaption></figure>

यह data [**इस Hopper script का उपयोग करके**](https://github.com/knightsc/hopper/blob/master/scripts/MIG%20Detect.py) extract किया जा सकता है।

### Debug

MIG द्वारा generated code entry और exit पर operations के बारे में logs generate करने के लिए `kernel_debug` को भी call करता है। इन्हें **`trace`** या **`kdv`** का उपयोग करके inspect किया जा सकता है: `kdv all | grep MIG`

## References

- [1] [bootstrap_cmds — `migcom.tproj` (MIG compiler स्वयं)](https://github.com/apple-oss-distributions/bootstrap_cmds/tree/main/migcom.tproj)
- [2] [XNU — `osfmk/mach/mach_port.defs` (उदाहरण MIG subsystem definition)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/mach_port.defs)
- [3] [XNU — `osfmk/mach/message.h` (Mach message header layout)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/message.h)
- [4] [XNU — `osfmk/mach/task.defs` (task subsystem MIG definition)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/task.defs)
{{#include ../../../../banners/hacktricks-training.md}}
