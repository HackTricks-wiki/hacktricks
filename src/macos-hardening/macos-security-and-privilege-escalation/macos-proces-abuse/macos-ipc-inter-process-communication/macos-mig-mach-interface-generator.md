# macOS MIG - Mach Interface Generator

{{#include ../../../../banners/hacktricks-training.md}}

## Basiese Inligting

MIG is geskep om die proses van die skep van **Mach IPC**-code te **vereenvoudig**. Dit **genereer basies die nodige code** vir die server en client om met ’n gegewe definisie te kommunikeer. Selfs al is die gegenereerde code lelik, hoef ’n ontwikkelaar dit net in te voer, en sy code sal baie eenvoudiger as voorheen wees.

Die definisie word in Interface Definition Language (IDL) gespesifiseer met die `.defs`-uitbreiding.

Hierdie definisies het 5 afdelings:

- **Subsystem-deklarasie**: Die sleutelwoord subsystem word gebruik om die **naam** en die **id** aan te dui. Dit is ook moontlik om dit as **`KernelServer`** te merk indien die server in die kernel moet loop.
- **Insluitings en imports**: MIG gebruik die C-preprocessor, dus kan dit imports gebruik. Dit is ook moontlik om `uimport` en `simport` vir user- of server-gegenereerde code te gebruik.
- **Tipe-deklarasies**: Dit is moontlik om datatipes te definieer, alhoewel dit gewoonlik `mach_types.defs` en `std_types.defs` sal import. Vir pasgemaakte tipes kan sommige sintaksis gebruik word:
- \[i`n/out]tran`: Funksie wat vanaf ’n inkomende of na ’n uitgaande boodskap vertaal moet word
- `c[user/server]type`: Kartering na ’n ander C-tipe.
- `destructor`: Roep hierdie funksie aan wanneer die tipe vrygestel word.
- **Operasies**: Dit is die definisies van die RPC-metodes. Daar is 5 verskillende tipes:
- `routine`: Verwag ’n antwoord
- `simpleroutine`: Verwag nie ’n antwoord nie
- `procedure`: Verwag ’n antwoord
- `simpleprocedure`: Verwag nie ’n antwoord nie
- `function`: Verwag ’n antwoord

### Voorbeeld

Skep ’n definisielêer, in hierdie geval met ’n baie eenvoudige funksie:
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
Let daarop dat die eerste **argument die port is waaraan gebind moet word** en MIG die **reply port outomaties sal hanteer** (tensy `mig_get_reply_port()` in die client-kode geroep word). Verder sal die **ID van die operasies** **opeenvolgend** wees, beginnende by die aangeduide subsystem-ID (dus, indien ’n operasie deprecated is, word dit uitgevee en `skip` gebruik om steeds sy ID te gebruik).

Gebruik nou MIG om die server- en client-kode te genereer wat met mekaar sal kan kommunikeer om die Subtract-funksie aan te roep:
```bash
mig -header myipcUser.h -sheader myipcServer.h myipc.defs
```
Verskeie nuwe lêers sal in die huidige gids geskep word.

> [!TIP]
> Jy kan ’n meer komplekse voorbeeld op jou stelsel vind met: `mdfind mach_port.defs`\
> En jy kan dit vanuit dieselfde gids as die lêer saamstel met: `mig -DLIBSYSCALL_INTERFACE mach_ports.defs`

In die lêers **`myipcServer.c`** en **`myipcServer.h`** kan jy die verklaring en definisie van die struct **`SERVERPREFmyipc_subsystem`** vind, wat basies die funksie definieer wat op grond van die ontvangde boodskap-ID geroep moet word (ons het ’n beginnommer van 500 aangedui):

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

Gebaseer op die vorige struktuur, sal die funksie **`myipc_server_routine`** die **boodskap-ID** kry en die korrekte funksie terugstuur om aan te roep:
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
In hierdie voorbeeld het ons slegs 1 funksie in die definitions gedefinieer, maar as ons meer funksies gedefinieer het, sou hulle binne die array van **`SERVERPREFmyipc_subsystem`** gewees het, en die eerste een sou aan die ID **500** toegeken gewees het, die tweede een aan die ID **501**...

As daar van die funksie verwag is om ’n **reply** te stuur, sou die funksie `mig_internal kern_return_t __MIG_check__Reply__<name>` ook bestaan het.

Dit is eintlik moontlik om hierdie verhouding in die struct **`subsystem_to_name_map_myipc`** vanaf **`myipcServer.h`** (**`subsystem*to_name_map*\***`** in ander lêers) te identifiseer:
```c
#ifndef subsystem_to_name_map_myipc
#define subsystem_to_name_map_myipc \
{ "Subtract", 500 }
#endif
```
Laastens sal nog ’n belangrike funksie om die server te laat werk **`myipc_server`** wees, wat die een is wat werklik die **funksie sal aanroep** wat met die ontvangde id verband hou:

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

Gaan die lyne wat voorheen uitgelig is na wat toegang verkry tot die funksie wat volgens die ID aangeroep moet word.

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

### Die NDR_record

Die NDR_record word deur `libsystem_kernel.dylib` uitgevoer, en dit is 'n struct wat MIG toelaat om **data te transformeer sodat dit van die stelsel onafhanklik is**, aangesien MIG ontwerp is om tussen verskillende stelsels gebruik te word (en nie slegs op dieselfde masjien nie).

Dit is interessant omdat, indien `_NDR_record` in 'n binary as 'n dependency gevind word (`jtool2 -S <binary> | grep NDR` of `nm`), dit beteken dat die binary 'n MIG client of Server is.

Verder het **MIG servers** die dispatch table in `__DATA.__const` (of in `__CONST.__constdata` in die macOS-kernel en `__DATA_CONST.__const` in ander \*OS-kernels). Dit kan met **`jtool2`** gedump word.

En **MIG clients** sal die `__NDR_record` gebruik om dit met `__mach_msg` na die servers te stuur.

## Binary Analysis

### jtool

Aangesien baie binaries nou MIG gebruik om mach ports bloot te stel, is dit interessant om te weet hoe om **te identifiseer dat MIG gebruik is** en die **funksies wat MIG met elke message ID uitvoer**.

[**jtool2**](../../macos-apps-inspecting-debugging-and-fuzzing/index.html#jtool2) kan MIG-inligting uit 'n Mach-O binary ontleed, wat die message ID aandui en die funksie identifiseer wat uitgevoer moet word:
```bash
jtool2 -d __DATA.__const myipc_server | grep MIG
```
Boonop is MIG-funksies bloot wrappers vir die werklike funksie wat geroep word, wat beteken dat jy, deur die disassembly daarvan te verkry en vir BL te grep, moontlik die werklike funksie wat geroep word, kan vind:
```bash
jtool2 -d __DATA.__const myipc_server | grep BL
```
### Assembly

Daar is voorheen genoem dat die funksie wat sal sorg dat die **korrekte funksie geroep word, afhangend van die ontvangde boodskap-ID**, `myipc_server` is. Jy sal egter gewoonlik nie die simbole van die binary hê nie (geen funksiename nie), daarom is dit interessant om **te kyk hoe dit gedekompileer lyk**, aangesien dit altyd baie soortgelyk sal wees (die kode van hierdie funksie is onafhanklik van die blootgestelde funksies):

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
Dit is dieselfde funksie, gedekompileer in ’n ander gratis weergawe van Hopper:

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

As jy eintlik na die funksie **`0x100004000`** gaan, sal jy die array van **`routine_descriptor`**-strukture vind. Die eerste element van die struktuur is die **adres** waar die **funksie** geïmplementeer is, en die **struktuur neem 0x28 bytes** in beslag. Dus kan jy vir elke 0x28 bytes (begin by byte 0) 8 bytes kry, en dit sal die **adres van die funksie** wees wat geroep sal word:

<figure><img src="../../../../images/image (35).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../../images/image (36).png" alt=""><figcaption></figcaption></figure>

Hierdie data kan [**met hierdie Hopper-script**](https://github.com/knightsc/hopper/blob/master/scripts/MIG%20Detect.py) onttrek word.

### Ontfouting

Die kode wat deur MIG gegenereer word, roep ook `kernel_debug` aan om logs oor bewerkings by die intrede en uitgang te genereer. Dit is moontlik om dit met **`trace`** of **`kdv`** na te gaan: `kdv all | grep MIG`

## Verwysings

- [1] [bootstrap_cmds — `migcom.tproj` (die MIG compiler self)](https://github.com/apple-oss-distributions/bootstrap_cmds/tree/main/migcom.tproj)
- [2] [XNU — `osfmk/mach/mach_port.defs` (voorbeeld van ’n MIG-substelseldefinisie)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/mach_port.defs)
- [3] [XNU — `osfmk/mach/task.defs` (MIG-definisie van die task-substelsel)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/task.defs)
- [4] [XNU — `osfmk/mach/message.h` (uitleg van die Mach-boodskapkop)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/message.h)

{{#include ../../../../banners/hacktricks-training.md}}
