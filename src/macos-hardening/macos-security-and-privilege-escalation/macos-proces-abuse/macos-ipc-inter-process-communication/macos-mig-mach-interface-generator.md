# macOS MIG - Mach Interface Generator

{{#include ../../../../banners/hacktricks-training.md}}

## Основне информације

MIG је креиран да **поједностави процес креирања Mach IPC** кода. Он у основи **генерише потребан код** како би server и client комуницирали на основу дате дефиниције. Иако је генерисани код неугледан, developer ће морати само да га увезе, па ће његов код бити много једноставнији него раније.<sup>[[1]](#references)</sup>

Дефиниција се задаје у Interface Definition Language (IDL) формату, уз екстензију `.defs`.

Ове дефиниције имају 5 секција:

- **Декларација subsystem-а**: Кључна реч subsystem се користи за навођење **назива** и **id-а**. Такође је могуће означити га као **`KernelServer`** ако server треба да се извршава у kernel-у.<sup>[[4]](#references)</sup>
- **Укључивања и imports**: MIG користи C-prepocessor, па може да користи imports. Поред тога, могуће је користити `uimport` и `simport` за кориснички или server генерисани код.
- **Декларације типова**: Могуће је дефинисати типове података, иако ће се обично увозити `mach_types.defs` и `std_types.defs`. За прилагођене типове може се користити следећа синтакса:
- \[i`n/out]tran`: Функција коју треба превести из долазне или у одлазну поруку
- `c[user/server]type`: Мапирање на други C тип.
- `destructor`: Позивање ове функције када се тип ослободи.
- **Операције**: Ово су дефиниције RPC метода. Постоји 5 различитих типова:
- `routine`: Очекује одговор
- `simpleroutine`: Не очекује одговор
- `procedure`: Очекује одговор
- `simpleprocedure`: Не очекује одговор
- `function`: Очекује одговор

### Пример

Креирајте датотеку са дефиницијом, у овом случају са веома једноставном функцијом:
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
Imajte na umu da je prvi **argument port koji treba povezati** i da će MIG **automatski obraditi port za odgovor** (osim ako se u client kodu pozove `mig_get_reply_port()`). Pored toga, **ID-ovi operacija** biće **sekvencijalni**, počevši od navedenog ID-a subsystem-a (ako je neka operacija zastarela, ona se briše, a koristi se `skip` kako bi se njen ID i dalje koristio).

Sada upotrebite MIG da generišete server i client kod koji će moći međusobno da komuniciraju radi pozivanja funkcije Subtract:
```bash
mig -header myipcUser.h -sheader myipcServer.h myipc.defs
```
U trenutnom direktorijumu biće kreirano nekoliko novih fajlova.

> [!TIP]
> Složeniji primer možete pronaći na svom sistemu pomoću: `mdfind mach_port.defs`\
> Možete ga kompajlirati iz istog foldera u kojem se nalazi fajl pomoću: `mig -DLIBSYSCALL_INTERFACE mach_ports.defs`<sup>[[2]](#references)</sup>

U fajlovima **`myipcServer.c`** i **`myipcServer.h`** možete pronaći deklaraciju i definiciju strukture **`SERVERPREFmyipc_subsystem`**, koja u osnovi definiše funkciju koju treba pozvati na osnovu primljenog ID-a poruke (naveli smo početni broj 500):

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

Na osnovu prethodne strukture, funkcija **`myipc_server_routine`** će dobiti **ID poruke** i vratiti odgovarajuću funkciju koju treba pozvati:
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
U ovom primeru definisali smo samo 1 funkciju u definicijama, ali da smo definisali više funkcija, one bi se nalazile unutar niza **`SERVERPREFmyipc_subsystem`**, pri čemu bi prvoj bio dodeljen ID **500**, drugoj ID **501**...

Ako se očekivalo da funkcija pošalje **reply**, postojala bi i funkcija `mig_internal kern_return_t __MIG_check__Reply__<name>`.

Zapravo, ovu vezu je moguće identifikovati u strukturi **`subsystem_to_name_map_myipc`** iz **`myipcServer.h`** (**`subsystem*to_name_map*\***`** u drugim datotekama):
```c
#ifndef subsystem_to_name_map_myipc
#define subsystem_to_name_map_myipc \
{ "Subtract", 500 }
#endif
```
Konačno, još jedna važna funkcija koja omogućava rad servera biće **`myipc_server`**, odnosno funkcija koja će zapravo **pozvati funkciju** povezanu sa primljenim id-jem:<sup>[[3]](#references)</sup>

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

Proverite prethodno istaknute linije koje pristupaju funkciji koju treba pozvati.

U nastavku je kod za kreiranje jednostavnog **servera** i **klijenta**, pri čemu klijent može da poziva funkcije Subtract sa servera:

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

NDR_record se eksportuje iz `libsystem_kernel.dylib` i predstavlja struct koji omogućava MIG-u da **transformiše podatke tako da budu nezavisni od sistema** u kojem se koristi, pošto je MIG osmišljen za komunikaciju između različitih sistema (a ne samo unutar iste mašine).

Ovo je zanimljivo zato što, ako se `_NDR_record` pronađe u binarnom fajlu kao dependency (`jtool2 -S <binary> | grep NDR` ili `nm`), to znači da je binarni fajl MIG client ili Server.

Pored toga, **MIG servers** imaju dispatch table u `__DATA.__const` (ili u `__CONST.__constdata` u macOS kernelu i `__DATA_CONST.__const` u drugim \*OS kernelima). Ovo se može izdumpovati pomoću **`jtool2`**.

A **MIG clients** će koristiti `__NDR_record` za slanje pomoću `__mach_msg` serverima.

## Binary Analysis

### jtool

Pošto mnogi binarni fajlovi sada koriste MIG za izlaganje mach portova, zanimljivo je znati kako **identifikovati da je MIG korišćen** i **funkcije koje MIG izvršava** za svaki message ID.

[**jtool2**](../../macos-apps-inspecting-debugging-and-fuzzing/index.html#jtool2) može parsirati MIG informacije iz Mach-O binarnog fajla, navodeći message ID i identifikujući funkciju koju treba izvršiti:
```bash
jtool2 -d __DATA.__const myipc_server | grep MIG
```
Štaviše, MIG functions su omotači oko stvarne funkcije koja se poziva. Zato, pribavljanjem disassembly-ja i pretragom za `BL`, možda ćete moći da pronađete stvarnu funkciju koja se poziva:
```bash
jtool2 -d __DATA.__const myipc_server | grep BL
```
### Assembly

Prethodno je pomenuto da je funkcija koja će se pobrinuti za **pozivanje odgovarajuće funkcije u zavisnosti od primljenog message ID-ja** bila `myipc_server`. Međutim, obično nećete imati simbole binarnog fajla (nazive funkcija), pa je korisno **proveriti kako izgleda nakon dekompilacije**, jer će uvek biti veoma slična (kod ove funkcije je nezavisan od izloženih funkcija):

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
Ovo je ista funkcija dekompilirana u drugoj besplatnoj verziji Hopper-a:

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

Ako zapravo odete do funkcije **`0x100004000`**, pronaći ćete niz struktura **`routine_descriptor`**. Prvi element strukture je **adresa** na kojoj je implementirana **funkcija**, a **struktura zauzima 0x28 bajtova**, tako da na svakih 0x28 bajtova (počevši od bajta 0) možete uzeti 8 bajtova i to će biti **adresa funkcije** koja će biti pozvana:

<figure><img src="../../../../images/image (35).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../../images/image (36).png" alt=""><figcaption></figcaption></figure>

Ovi podaci mogu da se izvuku [**korišćenjem ove Hopper skripte**](https://github.com/knightsc/hopper/blob/master/scripts/MIG%20Detect.py).

### Debug

Kod koji generiše MIG takođe poziva `kernel_debug` kako bi generisao logove o operacijama pri ulasku i izlasku. Moguće ih je pregledati pomoću **`trace`** ili **`kdv`**: `kdv all | grep MIG`

## References

- [1] [bootstrap_cmds — `migcom.tproj` (sam MIG compiler)](https://github.com/apple-oss-distributions/bootstrap_cmds/tree/main/migcom.tproj)
- [2] [XNU — `osfmk/mach/mach_port.defs` (primer definicije MIG subsystem-a)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/mach_port.defs)
- [3] [XNU — `osfmk/mach/message.h` (raspored Mach message header-a)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/message.h)
- [4] [XNU — `osfmk/mach/task.defs` (MIG definicija task subsystem-a)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/task.defs)
{{#include ../../../../banners/hacktricks-training.md}}
