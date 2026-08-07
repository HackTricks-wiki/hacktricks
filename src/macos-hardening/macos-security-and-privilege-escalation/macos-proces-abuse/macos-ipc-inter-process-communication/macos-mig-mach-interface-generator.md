# macOS MIG - Mach Interface Generator

{{#include ../../../../banners/hacktricks-training.md}}

## Basiese Inligting

MIG is geskep om die **proses van Mach IPC**-kode-skepping te **vereenvoudig**. Dit **genereer basies die nodige kode** sodat server en client met 'n gegewe definisie kan kommunikeer. Selfs al is die gegenereerde kode lelik, hoef 'n ontwikkelaar dit net in te voer, en sy kode sal baie eenvoudiger wees as voorheen.<sup>[[1]](#references)</sup>

Die definisie word in Interface Definition Language (IDL) gespesifiseer deur die `.defs`-uitbreiding te gebruik.

Hierdie definisies het 5 afdelings:

- **Subsystem declaration**: Die sleutelwoord subsystem word gebruik om die **naam** en die **id** aan te dui. Dit is ook moontlik om dit as **`KernelServer`** te merk indien die server in die kernel moet loop.<sup>[[4]](#references)</sup>
- **Inclusions and imports**: MIG gebruik die C-prepocessor, dus kan dit imports gebruik. Boonop is dit moontlik om `uimport` en `simport` vir user- of server-gegenereerde kode te gebruik.
- **Type declarations**: Dit is moontlik om datatipes te definieer, hoewel dit gewoonlik `mach_types.defs` en `std_types.defs` sal import. Vir pasgemaakte tipes kan die volgende sintaksis gebruik word:
- \[i`n/out]tran`: Funksie wat vanaf 'n inkomende of na 'n uitgaande boodskap vertaal moet word
- `c[user/server]type`: Mapping na 'n ander C-tipe.
- `destructor`: Roep hierdie funksie aan wanneer die tipe vrygestel word.
- **Operations**: Dit is die definisies van die RPC-metodes. Daar is 5 verskillende tipes:
- `routine`: Verwag 'n antwoord
- `simpleroutine`: Verwag nie 'n antwoord nie
- `procedure`: Verwag 'n antwoord
- `simpleprocedure`: Verwag nie 'n antwoord nie
- `function`: Verwag 'n antwoord

### Voorbeeld

Skep 'n definisielêer, in hierdie geval met 'n baie eenvoudige funksie:
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
Let daarop dat die eerste **argument die port is waaraan gebind moet word** en MIG die **reply port outomaties sal hanteer** (tensy `mig_get_reply_port()` in die client code geroep word). Boonop sal die **ID's van die operations** **opeenvolgend wees**, vanaf die aangeduide subsystem ID (dus, as 'n operation deprecated is, word dit verwyder en `skip` gebruik om steeds sy ID te gebruik).

Gebruik nou MIG om die server- en client code te genereer wat met mekaar sal kan kommunikeer om die Subtract-funksie te roep:
```bash
mig -header myipcUser.h -sheader myipcServer.h myipc.defs
```
Verskeie nuwe lêers sal in die huidige gids geskep word.

> [!TIP]
> Jy kan ’n meer komplekse voorbeeld in jou stelsel vind met: `mdfind mach_port.defs`\
> En jy kan dit vanuit dieselfde gids as die lêer compile met: `mig -DLIBSYSCALL_INTERFACE mach_ports.defs`<sup>[[2]](#references)</sup>

In die lêers **`myipcServer.c`** en **`myipcServer.h`** kan jy die verklaring en definisie van die struktuur **`SERVERPREFmyipc_subsystem`** vind, wat basies die funksie definieer wat op grond van die ontvangde boodskap-ID geroep moet word (ons het ’n begintal van 500 aangedui):

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

Based on the previous struct the function **`myipc_server_routine`** will get the **message ID** and return the proper function to call:
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
In hierdie voorbeeld het ons slegs 1 funksie in die definisies gedefinieer, maar indien ons meer funksies gedefinieer het, sou hulle binne die array **`SERVERPREFmyipc_subsystem`** gewees het, en die eerste een sou aan die ID **500** toegeken gewees het, die tweede een aan die ID **501**...

Indien daar van die funksie verwag is om ’n **reply** te stuur, sou die funksie `mig_internal kern_return_t __MIG_check__Reply__<name>` ook bestaan het.

Dit is eintlik moontlik om hierdie verhouding in die struct **`subsystem_to_name_map_myipc`** vanaf **`myipcServer.h`** (**`subsystem*to_name_map*\***`** in ander lêers) te identifiseer:
```c
#ifndef subsystem_to_name_map_myipc
#define subsystem_to_name_map_myipc \
{ "Subtract", 500 }
#endif
```
Uiteindelik sal nog ’n belangrike funksie om die server te laat werk **`myipc_server`** wees, wat die funksie wat met die ontvangde id verband hou, werklik sal **aanroep**:<sup>[[3]](#references)</sup>

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

Kontroleer die lyne wat hierbo uitgelig is en wat toegang verkry tot die funksie wat volgens die ID aangeroep moet word.

Die volgende is die kode om ’n eenvoudige **server** en **client** te skep waar die client die Subtract-funksies vanaf die server kan aanroep:

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

Die NDR_record word deur `libsystem_kernel.dylib` uitgevoer, en dit is 'n struct wat MIG toelaat om **data te transformeer sodat dit sisteem-onafhanklik is** aangesien MIG ontwerp is om tussen verskillende sisteme gebruik te word (en nie slegs op dieselfde masjien nie).

Dit is interessant, want as `_NDR_record` in 'n binary as 'n dependency gevind word (`jtool2 -S <binary> | grep NDR` of `nm`), beteken dit dat die binary 'n MIG client of Server is.

Verder het **MIG servers** die dispatch table in `__DATA.__const` (of in `__CONST.__constdata` in die macOS-kernel en `__DATA_CONST.__const` in ander \*OS-kernels). Dit kan met **`jtool2`** gedump word.

En **MIG clients** sal die `__NDR_record` gebruik om dit met `__mach_msg` na die servers te stuur.

## Binary Analysis

### jtool

Aangesien baie binaries nou MIG gebruik om mach ports bloot te stel, is dit interessant om te weet hoe om **te identifiseer dat MIG gebruik is** en die **funksies wat MIG met elke message ID uitvoer**.

[**jtool2**](../../macos-apps-inspecting-debugging-and-fuzzing/index.html#jtool2) kan MIG-inligting uit 'n Mach-O-binary parseer, wat die message ID aandui en die funksie identifiseer wat uitgevoer moet word:
```bash
jtool2 -d __DATA.__const myipc_server | grep MIG
```
Boonop is MIG-funksies bloot wrappers van die werklike funksie wat aangeroep word, wat beteken dat jy moontlik die werklike funksie wat aangeroep word kan vind deur die disassembly daarvan te verkry en vir BL te grep:
```bash
jtool2 -d __DATA.__const myipc_server | grep BL
```
### Samestelling

Daar is voorheen genoem dat die funksie wat sal sorg dat **die korrekte funksie geroep word, afhangend van die ontvangde message ID**, `myipc_server` is. Jy sal egter gewoonlik nie die simbole van die binary hê nie (geen funksiename nie), daarom is dit interessant om te **kyk hoe dit gedecompileer lyk**, aangesien dit altyd baie soortgelyk sal wees (die kode van hierdie funksie is onafhanklik van die blootgestelde funksies):

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
Dit is dieselfde funksie wat in ’n ander Hopper free-weergawe gedecompileer is:

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

As jy eintlik na die funksie **`0x100004000`** gaan, sal jy die array van **`routine_descriptor`**-structs vind. Die eerste element van die struct is die **adres** waar die **funksie** geïmplementeer is, en die **struct neem 0x28 bytes** in beslag. Dus kan jy vir elke 0x28 bytes (begin by byte 0) 8 bytes kry, wat die **adres van die funksie** sal wees wat geroep gaan word:

<figure><img src="../../../../images/image (35).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../../images/image (36).png" alt=""><figcaption></figcaption></figure>

Hierdie data kan [**met hierdie Hopper-script**](https://github.com/knightsc/hopper/blob/master/scripts/MIG%20Detect.py) onttrek word.

### Ontfouting

Die kode wat deur MIG gegenereer word, roep ook `kernel_debug` aan om logs oor operasies by entry en exit te genereer. Dit is moontlik om dit met **`trace`** of **`kdv`** na te gaan: `kdv all | grep MIG`

## Verwysings

- [1] [bootstrap_cmds — `migcom.tproj` (die MIG compiler self)](https://github.com/apple-oss-distributions/bootstrap_cmds/tree/main/migcom.tproj)
- [2] [XNU — `osfmk/mach/mach_port.defs` (voorbeeld van ’n MIG subsystem-definisie)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/mach_port.defs)
- [3] [XNU — `osfmk/mach/message.h` (uitleg van die Mach message-header)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/message.h)
- [4] [XNU — `osfmk/mach/task.defs` (MIG-definisie van die task-subsystem)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/task.defs)

{{#include ../../../../banners/hacktricks-training.md}}
