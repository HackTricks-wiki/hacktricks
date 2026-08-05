# macOS MIG - Mach Interface Generator

{{#include ../../../../banners/hacktricks-training.md}}

## Informazioni di base

MIG è stato creato per **semplificare il processo di creazione del codice Mach IPC**. In pratica **genera il codice necessario** affinché server e client comunichino sulla base di una determinata definizione. Anche se il codice generato è poco leggibile, uno sviluppatore dovrà solo importarlo e il suo codice sarà molto più semplice di prima.

La definizione viene specificata in Interface Definition Language (IDL) usando l'estensione `.defs`.

Queste definizioni hanno 5 sezioni:

- **Dichiarazione del subsystem**: la keyword subsystem viene usata per indicare il **nome** e l'**id**. È anche possibile contrassegnarlo come **`KernelServer`** se il server deve essere eseguito nel kernel.
- **Inclusioni e import**: MIG usa il preprocessore C, quindi è in grado di usare gli import. Inoltre, è possibile usare `uimport` e `simport` per il codice generato dal client o dal server.
- **Dichiarazioni dei tipi**: è possibile definire tipi di dati, anche se di solito vengono importati `mach_types.defs` e `std_types.defs`. Per quelli personalizzati è possibile usare la seguente sintassi:
- \[i`n/out]tran`: Funzione che deve essere tradotta da un messaggio in entrata o verso un messaggio in uscita
- `c[user/server]type`: Mapping verso un altro tipo C.
- `destructor`: Chiama questa funzione quando il tipo viene rilasciato.
- **Operazioni**: queste sono le definizioni dei metodi RPC. Esistono 5 tipi diversi:
- `routine`: Si aspetta una risposta
- `simpleroutine`: Non si aspetta una risposta
- `procedure`: Si aspetta una risposta
- `simpleprocedure`: Non si aspetta una risposta
- `function`: Si aspetta una risposta

### Esempio

Crea un file di definizione, in questo caso con una funzione molto semplice:
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
Nota che il primo **argomento è la porta a cui effettuare il bind** e MIG gestirà **automaticamente la reply port** (a meno che non venga chiamato `mig_get_reply_port()` nel codice client). Inoltre, gli **ID delle operazioni** saranno **sequenziali**, iniziando dall'ID del subsystem indicato (quindi, se un'operazione è deprecata, viene eliminata e si usa `skip` per continuare a utilizzare il relativo ID).

Ora usa MIG per generare il codice server e client che saranno in grado di comunicare tra loro per chiamare la funzione Subtract:
```bash
mig -header myipcUser.h -sheader myipcServer.h myipc.defs
```
Nella directory corrente verranno creati diversi nuovi file.

> [!TIP]
> Puoi trovare un esempio più complesso nel sistema usando: `mdfind mach_port.defs`\
> E puoi compilarlo dalla stessa cartella del file con: `mig -DLIBSYSCALL_INTERFACE mach_ports.defs`

Nei file **`myipcServer.c`** e **`myipcServer.h`** puoi trovare la dichiarazione e la definizione della struct **`SERVERPREFmyipc_subsystem`**, che definisce fondamentalmente la funzione da chiamare in base all'ID del messaggio ricevuto (abbiamo indicato un numero iniziale pari a 500):

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

In base alla struct precedente, la funzione **`myipc_server_routine`** riceverà il **message ID** e restituirà la funzione appropriata da chiamare:
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
In questo esempio abbiamo definito solo 1 funzione nelle definitions, ma se ne avessimo definite altre, sarebbero state contenute nell'array di **`SERVERPREFmyipc_subsystem`** e alla prima sarebbe stato assegnato l'ID **500**, alla seconda l'ID **501**...

Se ci si aspettava che la funzione inviasse una **reply**, sarebbe esistita anche la funzione `mig_internal kern_return_t __MIG_check__Reply__<name>`.

In realtà, è possibile identificare questa relazione nella struct **`subsystem_to_name_map_myipc`** da **`myipcServer.h`** (**`subsystem*to_name_map*\***`** in altri file):
```c
#ifndef subsystem_to_name_map_myipc
#define subsystem_to_name_map_myipc \
{ "Subtract", 500 }
#endif
```
Infine, un'altra funzione importante per far funzionare il server sarà **`myipc_server`**, ovvero quella che effettivamente **chiamerà la funzione** associata all'id ricevuto:

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

Controlla le righe precedentemente evidenziate che accedono alla funzione da chiamare tramite l'ID.

Di seguito è riportato il codice per creare un semplice **server** e **client**, in cui il client può chiamare le funzioni Subtract dal server:

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

Il NDR_record è esportato da `libsystem_kernel.dylib` ed è una struct che consente a MIG di **trasformare i dati in modo che siano indipendenti dal sistema** su cui viene utilizzato, poiché MIG è stato progettato per essere usato tra sistemi diversi (e non solo all'interno della stessa macchina).

Questo è interessante perché, se `_NDR_record` viene trovato in un binary come dependency (`jtool2 -S <binary> | grep NDR` o `nm`), significa che il binary è un client o un server MIG.

Inoltre, i **server MIG** hanno la dispatch table in `__DATA.__const` (o in `__CONST.__constdata` nel kernel di macOS e in `__DATA_CONST.__const` negli altri kernel \*OS). Questa può essere estratta con **`jtool2`**.

I **client MIG**, invece, utilizzeranno `__NDR_record` per inviarlo ai server tramite `__mach_msg`.

## Binary Analysis

### jtool

Poiché molti binary ora utilizzano MIG per esporre mach ports, è interessante sapere come **identificare se MIG è stato utilizzato** e le **funzioni eseguite da MIG** per ogni message ID.

[**jtool2**](../../macos-apps-inspecting-debugging-and-fuzzing/index.html#jtool2) può analizzare le informazioni MIG da un binary Mach-O, indicando il message ID e identificando la funzione da eseguire:
```bash
jtool2 -d __DATA.__const myipc_server | grep MIG
```
Inoltre, le funzioni MIG sono semplici wrapper della funzione effettiva che viene chiamata, il che significa che ottenendo la sua disassembly e cercando BL, potresti riuscire a trovare la funzione effettiva chiamata:
```bash
jtool2 -d __DATA.__const myipc_server | grep BL
```
### Assembly

In precedenza è stato menzionato che la funzione incaricata di **chiamare la funzione corretta in base al message ID ricevuto** era `myipc_server`. Tuttavia, di solito non si dispone dei simboli del binary (nessun nome delle funzioni), quindi è utile **verificare come appare dopo la decompilazione**, poiché sarà sempre molto simile (il codice di questa funzione è indipendente dalle funzioni esposte):

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
Questa è la stessa funzione decompilata in una versione gratuita diversa di Hopper:

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

In realtà, se si raggiunge la funzione **`0x100004000`**, si troverà l'array di struct **`routine_descriptor`**. Il primo elemento della struct è l'**indirizzo** in cui è implementata la **funzione**, e la **struct occupa 0x28 byte**; quindi, ogni 0x28 byte (a partire dal byte 0), è possibile ottenere 8 byte che rappresenteranno l'**indirizzo della funzione** da chiamare:

<figure><img src="../../../../images/image (35).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../../images/image (36).png" alt=""><figcaption></figcaption></figure>

Questi dati possono essere estratti [**using this Hopper script**](https://github.com/knightsc/hopper/blob/master/scripts/MIG%20Detect.py).

### Debug

Il codice generato da MIG chiama anche `kernel_debug` per generare log sulle operazioni in entrata e in uscita. È possibile consultarli usando **`trace`** o **`kdv`**: `kdv all | grep MIG`

## Riferimenti

- [1] [bootstrap_cmds — `migcom.tproj` (the MIG compiler itself)](https://github.com/apple-oss-distributions/bootstrap_cmds/tree/main/migcom.tproj)
- [2] [XNU — `osfmk/mach/mach_port.defs` (example MIG subsystem definition)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/mach_port.defs)
- [3] [XNU — `osfmk/mach/task.defs` (task subsystem MIG definition)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/task.defs)
- [4] [XNU — `osfmk/mach/message.h` (Mach message header layout)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/message.h)

{{#include ../../../../banners/hacktricks-training.md}}
