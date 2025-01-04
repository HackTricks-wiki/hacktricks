# macOS MIG - Mach Interface Generator

{{#include ../../../../banners/hacktricks-training.md}}

## Basiese Inligting

MIG is geskep om die **proses van Mach IPC** kode skepping te **vereenvoudig**. Dit genereer basies die **nodige kode** vir bediener en kliënt om met 'n gegewe definisie te kommunikeer. Alhoewel die gegenereerde kode lelik is, sal 'n ontwikkelaar net dit moet invoer en sy kode sal baie eenvoudiger wees as voorheen.

Die definisie word gespesifiseer in Interface Definition Language (IDL) met die `.defs` uitbreiding.

Hierdie definisies het 5 afdelings:

- **Substelseld verklaring**: Die sleutelwoord subsystem word gebruik om die **naam** en die **id** aan te dui. Dit is ook moontlik om dit as **`KernelServer`** te merk as die bediener in die kernel moet loop.
- **Insluitings en invoere**: MIG gebruik die C-prepocessor, so dit is in staat om invoere te gebruik. Boonop is dit moontlik om `uimport` en `simport` te gebruik vir gebruiker of bediener gegenereerde kode.
- **Tipe verklarings**: Dit is moontlik om datatipes te definieer alhoewel dit gewoonlik `mach_types.defs` en `std_types.defs` sal invoer. Vir persoonlike tipes kan 'n sekere sintaksis gebruik word:
- \[i`n/out]tran`: Funksie wat vertaal moet word van 'n inkomende of na 'n uitgaande boodskap
- `c[user/server]type`: Kaart na 'n ander C tipe.
- `destructor`: Roep hierdie funksie aan wanneer die tipe vrygestel word.
- **Operasies**: Dit is die definisies van die RPC metodes. Daar is 5 verskillende tipes:
- `routine`: Verwag antwoord
- `simpleroutine`: Verwag nie antwoord nie
- `procedure`: Verwag antwoord
- `simpleprocedure`: Verwag nie antwoord nie
- `function`: Verwag antwoord

### Voorbeeld

Skep 'n definisie lêer, in hierdie geval met 'n baie eenvoudige funksie:
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
Let wel dat die eerste **argument die poort is om te bind** en MIG sal **automaties die antwoordpoort hanteer** (tenzij `mig_get_reply_port()` in die kliëntkode aangeroep word). Boonop sal die **ID van die operasies** **sekwensieel** wees wat begin by die aangeduide subsysteem-ID (so as 'n operasie verouderd is, word dit verwyder en `skip` word gebruik om steeds sy ID te gebruik).

Gebruik nou MIG om die bediener- en kliëntkode te genereer wat in staat sal wees om met mekaar te kommunikeer om die Subtract-funksie aan te roep:
```bash
mig -header myipcUser.h -sheader myipcServer.h myipc.defs
```
Verskeie nuwe lêers sal in die huidige gids geskep word.

> [!TIP]
> Jy kan 'n meer komplekse voorbeeld in jou stelsel vind met: `mdfind mach_port.defs`\
> En jy kan dit saamstel vanaf dieselfde gids as die lêer met: `mig -DLIBSYSCALL_INTERFACE mach_ports.defs`

In die lêers **`myipcServer.c`** en **`myipcServer.h`** kan jy die verklaring en definisie van die struktuur **`SERVERPREFmyipc_subsystem`** vind, wat basies die funksie definieer om te bel op grond van die ontvangde boodskap-ID (ons het 'n begingetal van 500 aangedui):

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

Gebaseer op die vorige struktuur sal die funksie **`myipc_server_routine`** die **boodskap-ID** verkry en die toepaslike funksie teruggee om aan te roep:
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
In hierdie voorbeeld het ons slegs 1 funksie in die definisies gedefinieer, maar as ons meer funksies gedefinieer het, sou hulle binne die array van **`SERVERPREFmyipc_subsystem`** gewees het en die eerste een sou aan die ID **500** toegeken gewees het, die tweede een aan die ID **501**...

As die funksie verwag is om 'n **antwoord** te stuur, sou die funksie `mig_internal kern_return_t __MIG_check__Reply__<name>` ook bestaan het.

Werklik is dit moontlik om hierdie verhouding in die struktuur **`subsystem_to_name_map_myipc`** van **`myipcServer.h`** (**`subsystem*to_name_map*\***`\*\* in ander lêers) te identifiseer:
```c
#ifndef subsystem_to_name_map_myipc
#define subsystem_to_name_map_myipc \
{ "Subtract", 500 }
#endif
```
Uiteindelik, 'n ander belangrike funksie om die bediener te laat werk sal wees **`myipc_server`**, wat die een is wat werklik die **funksie** sal aanroep wat verband hou met die ontvangde id:

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
/* Minimale grootte: routine() sal dit opdateer as dit verskil */
OutHeadP->msgh_size = (mach_msg_size_t)sizeof(mig_reply_error_t);
OutHeadP->msgh_local_port = MACH_PORT_NULL;
OutHeadP->msgh_id = InHeadP->msgh_id + 100;
OutHeadP->msgh_reserved = 0;

if ((InHeadP->msgh_id > 500) || (InHeadP->msgh_id &#x3C; 500) ||
<strong>	    ((routine = SERVERPREFmyipc_subsystem.routine[InHeadP->msgh_id - 500].stub_routine) == 0)) {
</strong>		((mig_reply_error_t *)OutHeadP)->NDR = NDR_record;
((mig_reply_error_t *)OutHeadP)->RetCode = MIG_BAD_ID;
return FALSE;
}
<strong>	(*routine) (InHeadP, OutHeadP);
</strong>	return TRUE;
}
</code></pre>

Kontroleer die voorheen beklemtoonde lyne wat toegang tot die funksie om aan te roep deur ID.

Die volgende is die kode om 'n eenvoudige **bediener** en **klient** te skep waar die klient die funksies Subtract van die bediener kan aanroep:

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

Die NDR_record word uitgevoer deur `libsystem_kernel.dylib`, en dit is 'n struktuur wat MIG toelaat om **data te transformeer sodat dit onpartydig is teenoor die stelsel** waarvoor dit gebruik word, aangesien MIG bedoel was om tussen verskillende stelsels gebruik te word (en nie net op dieselfde masjien nie).

Dit is interessant omdat as `_NDR_record` in 'n binêre as 'n afhanklikheid gevind word (`jtool2 -S <binary> | grep NDR` of `nm`), dit beteken dat die binêre 'n MIG-kliënt of -bediener is.

Boonop het **MIG-bedieners** die afleweringstabel in `__DATA.__const` (of in `__CONST.__constdata` in die macOS-kern en `__DATA_CONST.__const` in ander \*OS-kerns). Dit kan gedump word met **`jtool2`**.

En **MIG-kliënte** sal die `__NDR_record` gebruik om met `__mach_msg` na die bedieners te stuur.

## Binêre Analise

### jtool

Aangesien baie binêre nou MIG gebruik om mach-poorte bloot te stel, is dit interessant om te weet hoe om **te identifiseer dat MIG gebruik is** en die **funksies wat MIG met elke boodskap-ID uitvoer**.

[**jtool2**](../../macos-apps-inspecting-debugging-and-fuzzing/index.html#jtool2) kan MIG-inligting uit 'n Mach-O binêre ontleed wat die boodskap-ID aandui en die funksie identifiseer wat uitgevoer moet word:
```bash
jtool2 -d __DATA.__const myipc_server | grep MIG
```
Boonop, MIG-funksies is net omhulsel van die werklike funksie wat aangeroep word, wat beteken dat jy deur die ontbinding daarvan te kry en vir BL te soek, dalk die werklike funksie wat aangeroep word, kan vind:
```bash
jtool2 -d __DATA.__const myipc_server | grep BL
```
### Assembly

Daar is voorheen genoem dat die funksie wat **die korrekte funksie sal aanroep afhangende van die ontvangde boodskap ID** `myipc_server` was. Dit is egter gewoonlik dat jy nie die simbole van die binêre (geen funksie name) sal hê nie, so dit is interessant om **te kyk hoe dit dekompilleer lyk** aangesien dit altyd baie soortgelyk sal wees (die kode van hierdie funksie is onafhanklik van die funksies wat blootgestel word):

{{#tabs}}
{{#tab name="myipc_server decompiled 1"}}

<pre class="language-c"><code class="lang-c">int _myipc_server(int arg0, int arg1) {
var_10 = arg0;
var_18 = arg1;
// Begininstruksies om die regte funksie aanwysers te vind
*(int32_t *)var_18 = *(int32_t *)var_10 &#x26; 0x1f;
*(int32_t *)(var_18 + 0x8) = *(int32_t *)(var_10 + 0x8);
*(int32_t *)(var_18 + 0x4) = 0x24;
*(int32_t *)(var_18 + 0xc) = 0x0;
*(int32_t *)(var_18 + 0x14) = *(int32_t *)(var_10 + 0x14) + 0x64;
*(int32_t *)(var_18 + 0x10) = 0x0;
if (*(int32_t *)(var_10 + 0x14) &#x3C;= 0x1f4 &#x26;&#x26; *(int32_t *)(var_10 + 0x14) >= 0x1f4) {
rax = *(int32_t *)(var_10 + 0x14);
// Aanroep na sign_extend_64 wat kan help om hierdie funksie te identifiseer
// Dit stoor in rax die aanwyser na die oproep wat gemaak moet word
// Kontroleer die gebruik van die adres 0x100004040 (funksies adresse array)
// 0x1f4 = 500 (die begin ID)
<strong>            rax = *(sign_extend_64(rax - 0x1f4) * 0x28 + 0x100004040);
</strong>            var_20 = rax;
// As - anders, die as keer vals terug, terwyl die anders die korrekte funksie aanroep en waarborg waar
<strong>            if (rax == 0x0) {
</strong>                    *(var_18 + 0x18) = **_NDR_record;
*(int32_t *)(var_18 + 0x20) = 0xfffffffffffffed1;
var_4 = 0x0;
}
else {
// Gerekende adres wat die regte funksie met 2 argumente aanroep
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
Dit is dieselfde funksie dekompilleer in 'n ander Hopper gratis weergawe:

<pre class="language-c"><code class="lang-c">int _myipc_server(int arg0, int arg1) {
r31 = r31 - 0x40;
saved_fp = r29;
stack[-8] = r30;
var_10 = arg0;
var_18 = arg1;
// Begininstruksies om die regte funksie aanwysers te vind
*(int32_t *)var_18 = *(int32_t *)var_10 &#x26; 0x1f | 0x0;
*(int32_t *)(var_18 + 0x8) = *(int32_t *)(var_10 + 0x8);
*(int32_t *)(var_18 + 0x4) = 0x24;
*(int32_t *)(var_18 + 0xc) = 0x0;
*(int32_t *)(var_18 + 0x14) = *(int32_t *)(var_10 + 0x14) + 0x64;
*(int32_t *)(var_18 + 0x10) = 0x0;
r8 = *(int32_t *)(var_10 + 0x14);
r8 = r8 - 0x1f4;
if (r8 > 0x0) {
if (CPU_FLAGS &#x26; G) {
r8 = 0x1;
}
}
if ((r8 &#x26; 0x1) == 0x0) {
r8 = *(int32_t *)(var_10 + 0x14);
r8 = r8 - 0x1f4;
if (r8 &#x3C; 0x0) {
if (CPU_FLAGS &#x26; L) {
r8 = 0x1;
}
}
if ((r8 &#x26; 0x1) == 0x0) {
r8 = *(int32_t *)(var_10 + 0x14);
// 0x1f4 = 500 (die begin ID)
<strong>                    r8 = r8 - 0x1f4;
</strong>                    asm { smaddl     x8, w8, w9, x10 };
r8 = *(r8 + 0x8);
var_20 = r8;
r8 = r8 - 0x0;
if (r8 != 0x0) {
if (CPU_FLAGS &#x26; NE) {
r8 = 0x1;
}
}
// Dieselfde as - anders soos in die vorige weergawe
// Kontroleer die gebruik van die adres 0x100004040 (funksies adresse array)
<strong>                    if ((r8 &#x26; 0x1) == 0x0) {
</strong><strong>                            *(var_18 + 0x18) = **0x100004000;
</strong>                            *(int32_t *)(var_18 + 0x20) = 0xfffffed1;
var_4 = 0x0;
}
else {
// Aanroep na die berekende adres waar die funksie moet wees
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

As jy eintlik na die funksie **`0x100004000`** gaan, sal jy die array van **`routine_descriptor`** strukture vind. Die eerste element van die struktuur is die **adres** waar die **funksie** geïmplementeer is, en die **struktuur neem 0x28 bytes**, so elke 0x28 bytes (begin vanaf byte 0) kan jy 8 bytes kry en dit sal die **adres van die funksie** wees wat aangeroep gaan word:

<figure><img src="../../../../images/image (35).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../../images/image (36).png" alt=""><figcaption></figcaption></figure>

Hierdie data kan [**met hierdie Hopper skrip**](https://github.com/knightsc/hopper/blob/master/scripts/MIG%20Detect.py) onttrek word.

### Debug

Die kode wat deur MIG gegenereer word, roep ook `kernel_debug` aan om logs oor operasies op in- en uitgang te genereer. Dit is moontlik om hulle te kontroleer met **`trace`** of **`kdv`**: `kdv all | grep MIG`

## References

- [\*OS Internals, Volume I, User Mode, Jonathan Levin](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

{{#include ../../../../banners/hacktricks-training.md}}
