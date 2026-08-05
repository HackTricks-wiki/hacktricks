# macOS MIG - Mach Interface Generator

{{#include ../../../../banners/hacktricks-training.md}}

## Βασικές πληροφορίες

Το MIG δημιουργήθηκε για να **απλοποιήσει τη διαδικασία δημιουργίας κώδικα Mach IPC**. Βασικά, **παράγει τον απαιτούμενο κώδικα** ώστε ο server και ο client να επικοινωνούν με βάση έναν συγκεκριμένο ορισμό. Ακόμα κι αν ο παραγόμενος κώδικας είναι δύσχρηστος, ένας developer θα χρειάζεται απλώς να τον κάνει import και ο κώδικάς του θα είναι πολύ απλούστερος από πριν.

Ο ορισμός καθορίζεται σε Interface Definition Language (IDL) με χρήση της επέκτασης `.defs`.

Αυτοί οι ορισμοί έχουν 5 ενότητες:

- **Δήλωση subsystem**: Η λέξη-κλειδί subsystem χρησιμοποιείται για να υποδείξει το **όνομα** και το **id**. Είναι επίσης δυνατό να σημειωθεί ως **`KernelServer`** αν ο server πρέπει να εκτελείται στον kernel.
- **Inclusions και imports**: Το MIG χρησιμοποιεί τον C-preprocessor, επομένως μπορεί να χρησιμοποιεί imports. Επιπλέον, είναι δυνατή η χρήση των `uimport` και `simport` για κώδικα που παράγεται για τον user ή τον server.
- **Δηλώσεις τύπων**: Είναι δυνατός ο ορισμός data types, αν και συνήθως γίνεται import των `mach_types.defs` και `std_types.defs`. Για custom τύπους μπορεί να χρησιμοποιηθεί η ακόλουθη σύνταξη:
- \[i`n/out]tran`: Συνάρτηση που χρειάζεται μετάφραση από ένα incoming ή προς ένα outgoing message
- `c[user/server]type`: Mapping σε έναν άλλο C type.
- `destructor`: Κλήση αυτής της συνάρτησης όταν ο τύπος απελευθερώνεται.
- **Operations**: Αυτοί είναι οι ορισμοί των RPC methods. Υπάρχουν 5 διαφορετικοί τύποι:
- `routine`: Αναμένει reply
- `simpleroutine`: Δεν αναμένει reply
- `procedure`: Αναμένει reply
- `simpleprocedure`: Δεν αναμένει reply
- `function`: Αναμένει reply

### Παράδειγμα

Δημιουργήστε ένα definition file, σε αυτή την περίπτωση με μια πολύ απλή συνάρτηση:
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
Σημειώστε ότι το πρώτο **όρισμα είναι η θύρα στην οποία θα γίνει σύνδεση** και το MIG θα **διαχειριστεί αυτόματα τη θύρα απάντησης** (εκτός αν καλέσετε τη `mig_get_reply_port()` στον κώδικα του client). Επιπλέον, τα **ID των operations** θα είναι **διαδοχικά**, ξεκινώντας από το υποδεικνυόμενο ID του subsystem (επομένως, αν ένα operation έχει καταργηθεί, διαγράφεται και χρησιμοποιείται το `skip` ώστε να συνεχίσει να χρησιμοποιείται το ID του).

Τώρα χρησιμοποιήστε το MIG για να δημιουργήσετε τον κώδικα του server και του client, οι οποίοι θα μπορούν να επικοινωνούν μεταξύ τους για να καλέσουν τη συνάρτηση Subtract:
```bash
mig -header myipcUser.h -sheader myipcServer.h myipc.defs
```
Αρκετά νέα αρχεία θα δημιουργηθούν στον τρέχοντα κατάλογο.

> [!TIP]
> Μπορείτε να βρείτε ένα πιο σύνθετο παράδειγμα στο σύστημά σας με: `mdfind mach_port.defs`\
> Και μπορείτε να το κάνετε compile από τον ίδιο φάκελο όπου βρίσκεται το αρχείο με: `mig -DLIBSYSCALL_INTERFACE mach_ports.defs`

Στα αρχεία **`myipcServer.c`** και **`myipcServer.h`** μπορείτε να βρείτε τη δήλωση και τον ορισμό του struct **`SERVERPREFmyipc_subsystem`**, το οποίο βασικά ορίζει τη function που θα κληθεί με βάση το message ID που λήφθηκε (υποδείξαμε έναν αρχικό αριθμό 500):

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

Με βάση το προηγούμενο struct, η συνάρτηση **`myipc_server_routine`** θα λάβει το **message ID** και θα επιστρέψει την κατάλληλη συνάρτηση προς κλήση:
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
Σε αυτό το παράδειγμα έχουμε ορίσει μόνο 1 function στους ορισμούς, αλλά αν είχαμε ορίσει περισσότερες functions, θα βρίσκονταν μέσα στο array του **`SERVERPREFmyipc_subsystem`** και η πρώτη θα είχε αντιστοιχιστεί στο ID **500**, η δεύτερη στο ID **501**...

Αν η function αναμενόταν να στείλει ένα **reply**, θα υπήρχε επίσης η function `mig_internal kern_return_t __MIG_check__Reply__<name>`.

Στην πραγματικότητα, είναι δυνατό να εντοπιστεί αυτή η σχέση στο struct **`subsystem_to_name_map_myipc`** από το **`myipcServer.h`** (**`subsystem*to_name_map*\***`** σε άλλα αρχεία):
```c
#ifndef subsystem_to_name_map_myipc
#define subsystem_to_name_map_myipc \
{ "Subtract", 500 }
#endif
```
Τέλος, μια ακόμη σημαντική συνάρτηση για να λειτουργήσει ο **server** θα είναι η **`myipc_server`**, η οποία θα **καλεί τη συνάρτηση** που σχετίζεται με το ληφθέν id:

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

Ελέγξτε τις προηγουμένως επισημασμένες γραμμές που προσπελαύνουν τη συνάρτηση προς κλήση βάσει του ID.

Ακολουθεί ο κώδικας για τη δημιουργία ενός απλού **server** και **client**, όπου ο client μπορεί να καλεί τις συναρτήσεις Subtract από τον server:

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

Το NDR_record εξάγεται από το `libsystem_kernel.dylib` και είναι ένα struct που επιτρέπει στο MIG να **μετασχηματίζει τα δεδομένα ώστε να είναι ανεξάρτητα από το σύστημα** στο οποίο χρησιμοποιείται, καθώς το MIG σχεδιάστηκε για χρήση μεταξύ διαφορετικών συστημάτων (και όχι μόνο στο ίδιο μηχάνημα).

Αυτό είναι ενδιαφέρον, επειδή αν το `_NDR_record` εντοπιστεί σε ένα binary ως dependency (`jtool2 -S <binary> | grep NDR` ή `nm`), σημαίνει ότι το binary είναι MIG client ή Server.

Επιπλέον, οι **MIG servers** έχουν τον dispatch table στο `__DATA.__const` (ή στο `__CONST.__constdata` στον kernel του macOS και στο `__DATA_CONST.__const` στους υπόλοιπους \*OS kernels). Αυτό μπορεί να γίνει dump με το **`jtool2`**.

Και οι **MIG clients** θα χρησιμοποιήσουν το `__NDR_record` για να το στείλουν με το `__mach_msg` στους servers.

## Binary Analysis

### jtool

Καθώς πολλά binaries χρησιμοποιούν πλέον MIG για να εκθέτουν mach ports, είναι ενδιαφέρον να γνωρίζουμε πώς να **εντοπίζουμε ότι χρησιμοποιήθηκε το MIG** και τις **functions που εκτελεί το MIG** με κάθε message ID.

Το [**jtool2**](../../macos-apps-inspecting-debugging-and-fuzzing/index.html#jtool2) μπορεί να αναλύσει πληροφορίες MIG από ένα Mach-O binary, υποδεικνύοντας το message ID και προσδιορίζοντας τη function που πρέπει να εκτελεστεί:
```bash
jtool2 -d __DATA.__const myipc_server | grep MIG
```
Επιπλέον, οι MIG functions είναι απλώς wrappers της actual function που καλείται, πράγμα που σημαίνει ότι, λαμβάνοντας το disassembly της και κάνοντας grep για BL, ενδέχεται να μπορέσετε να βρείτε την actual function που καλείται:
```bash
jtool2 -d __DATA.__const myipc_server | grep BL
```
### Assembly

Αναφέρθηκε προηγουμένως ότι η function που θα αναλάβει να **καλέσει τη σωστή function ανάλογα με το message ID που λήφθηκε** ήταν η `myipc_server`. Ωστόσο, συνήθως δεν θα έχετε τα symbols του binary (ονόματα functions), επομένως έχει ενδιαφέρον να **ελέγξετε πώς εμφανίζεται μετά από decompilation**, καθώς θα είναι πάντα πολύ παρόμοια (ο κώδικας αυτής της function είναι ανεξάρτητος από τις exposed functions):

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
Αυτή είναι η ίδια function μετά από decompilation σε διαφορετική free έκδοση του Hopper:

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

Στην πραγματικότητα, αν μεταβείτε στη function **`0x100004000`**, θα βρείτε τον πίνακα από structs **`routine_descriptor`**. Το πρώτο στοιχείο του struct είναι η **διεύθυνση** στην οποία υλοποιείται η **function**, ενώ το **struct καταλαμβάνει 0x28 bytes**. Επομένως, ανά 0x28 bytes (ξεκινώντας από το byte 0), μπορείτε να λάβετε 8 bytes, τα οποία θα είναι η **διεύθυνση της function** που θα κληθεί:

<figure><img src="../../../../images/image (35).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../../images/image (36).png" alt=""><figcaption></figcaption></figure>

Αυτά τα δεδομένα μπορούν να εξαχθούν [**χρησιμοποιώντας αυτό το Hopper script**](https://github.com/knightsc/hopper/blob/master/scripts/MIG%20Detect.py).

### Αποσφαλμάτωση

Ο κώδικας που δημιουργείται από το MIG καλεί επίσης το `kernel_debug` για να δημιουργεί logs σχετικά με τις operations κατά την είσοδο και την έξοδο. Μπορείτε να τα ελέγξετε χρησιμοποιώντας τα **`trace`** ή **`kdv`**: `kdv all | grep MIG`

## References

- [1] [bootstrap_cmds — `migcom.tproj` (the MIG compiler itself)](https://github.com/apple-oss-distributions/bootstrap_cmds/tree/main/migcom.tproj)
- [2] [XNU — `osfmk/mach/mach_port.defs` (example MIG subsystem definition)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/mach_port.defs)
- [3] [XNU — `osfmk/mach/task.defs` (task subsystem MIG definition)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/task.defs)
- [4] [XNU — `osfmk/mach/message.h` (Mach message header layout)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/message.h)

{{#include ../../../../banners/hacktricks-training.md}}
