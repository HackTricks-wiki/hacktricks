# macOS MIG - Mach Interface Generator

{{#include ../../../../banners/hacktricks-training.md}}

## Basic Information

MIG δημιουργήθηκε για να **απλοποιήσει τη διαδικασία δημιουργίας κώδικα Mach IPC**. Βασικά **παράγει τον απαραίτητο κώδικα** για να επικοινωνούν ο server και ο client με μια δεδομένη ορισμό. Ακόμα και αν ο παραγόμενος κώδικας είναι άσχημος, ένας προγραμματιστής θα χρειαστεί απλώς να τον εισάγει και ο κώδικάς του θα είναι πολύ πιο απλός από πριν.

Ο ορισμός καθορίζεται στη Γλώσσα Ορισμού Διεπαφής (IDL) χρησιμοποιώντας την επέκταση `.defs`.

Αυτοί οι ορισμοί έχουν 5 ενότητες:

- **Δήλωση υποσυστήματος**: Η λέξη-κλειδί subsystem χρησιμοποιείται για να υποδείξει το **όνομα** και το **id**. Είναι επίσης δυνατό να το επισημάνετε ως **`KernelServer`** αν ο server πρέπει να εκτελείται στον πυρήνα.
- **Εισαγωγές και imports**: Το MIG χρησιμοποιεί τον C-preprocessor, οπότε μπορεί να χρησιμοποιεί imports. Επιπλέον, είναι δυνατό να χρησιμοποιηθούν `uimport` και `simport` για κώδικα που έχει παραχθεί από χρήστη ή server.
- **Δηλώσεις τύπων**: Είναι δυνατό να οριστούν τύποι δεδομένων αν και συνήθως θα εισάγει `mach_types.defs` και `std_types.defs`. Για προσαρμοσμένους τύπους μπορεί να χρησιμοποιηθεί κάποια σύνταξη:
- \[i`n/out]tran`: Συνάρτηση που πρέπει να μεταφραστεί από ένα εισερχόμενο ή σε ένα εξερχόμενο μήνυμα
- `c[user/server]type`: Χαρτογράφηση σε άλλο τύπο C.
- `destructor`: Καλέστε αυτή τη συνάρτηση όταν ο τύπος απελευθερωθεί.
- **Λειτουργίες**: Αυτές είναι οι ορισμοί των μεθόδων RPC. Υπάρχουν 5 διαφορετικοί τύποι:
- `routine`: Αναμένει απάντηση
- `simpleroutine`: Δεν αναμένει απάντηση
- `procedure`: Αναμένει απάντηση
- `simpleprocedure`: Δεν αναμένει απάντηση
- `function`: Αναμένει απάντηση

### Example

Δημιουργήστε ένα αρχείο ορισμού, σε αυτή την περίπτωση με μια πολύ απλή συνάρτηση:
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
Σημειώστε ότι το πρώτο **επιχείρημα είναι η θύρα για δέσμευση** και το MIG θα **χειριστεί αυτόματα τη θύρα απάντησης** (εκτός αν καλέσετε το `mig_get_reply_port()` στον κωδικό του πελάτη). Επιπλέον, το **ID των λειτουργιών** θα είναι **διαδοχικό** ξεκινώντας από το υποσύστημα ID που υποδεικνύεται (έτσι αν μια λειτουργία είναι απαρχαιωμένη, διαγράφεται και χρησιμοποιείται το `skip` για να χρησιμοποιηθεί ακόμα το ID της).

Τώρα χρησιμοποιήστε το MIG για να δημιουργήσετε τον κωδικό του διακομιστή και του πελάτη που θα είναι σε θέση να επικοινωνούν μεταξύ τους για να καλέσουν τη λειτουργία Subtract:
```bash
mig -header myipcUser.h -sheader myipcServer.h myipc.defs
```
Πολλά νέα αρχεία θα δημιουργηθούν στον τρέχοντα φάκελο.

> [!TIP]
> Μπορείτε να βρείτε ένα πιο σύνθετο παράδειγμα στο σύστημά σας με: `mdfind mach_port.defs`\
> Και μπορείτε να το μεταγλωττίσετε από τον ίδιο φάκελο με το αρχείο με: `mig -DLIBSYSCALL_INTERFACE mach_ports.defs`

Στα αρχεία **`myipcServer.c`** και **`myipcServer.h`** μπορείτε να βρείτε την δήλωση και τον ορισμό της δομής **`SERVERPREFmyipc_subsystem`**, η οποία βασικά ορίζει τη λειτουργία που θα καλέσετε με βάση το αναγνωριστικό μηνύματος που ελήφθη (υποδείξαμε έναν αρχικό αριθμό 500):

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

Βασισμένη στη προηγούμενη δομή, η συνάρτηση **`myipc_server_routine`** θα λάβει το **ID μηνύματος** και θα επιστρέψει τη σωστή συνάρτηση για κλήση:
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
Σε αυτό το παράδειγμα έχουμε ορίσει μόνο 1 συνάρτηση στις ορισμοί, αλλά αν είχαμε ορίσει περισσότερες συναρτήσεις, θα ήταν μέσα στον πίνακα του **`SERVERPREFmyipc_subsystem`** και η πρώτη θα είχε ανατεθεί στο ID **500**, η δεύτερη στο ID **501**...

Αν η συνάρτηση αναμενόταν να στείλει μια **απάντηση**, η συνάρτηση `mig_internal kern_return_t __MIG_check__Reply__<name>` θα υπήρχε επίσης.

Στην πραγματικότητα, είναι δυνατόν να προσδιοριστεί αυτή η σχέση στη δομή **`subsystem_to_name_map_myipc`** από **`myipcServer.h`** (**`subsystem*to_name_map*\***`\*\* σε άλλα αρχεία):
```c
#ifndef subsystem_to_name_map_myipc
#define subsystem_to_name_map_myipc \
{ "Subtract", 500 }
#endif
```
Τέλος, μια άλλη σημαντική λειτουργία για να λειτουργήσει ο διακομιστής θα είναι **`myipc_server`**, η οποία είναι αυτή που θα **καλέσει τη συνάρτηση** που σχετίζεται με το ληφθέν id:

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
/* Ελάχιστο μέγεθος: η routine() θα το ενημερώσει αν είναι διαφορετικό */
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

Ελέγξτε τις προηγουμένως επισημασμένες γραμμές που αποκτούν πρόσβαση στη συνάρτηση για να καλέσουν με ID.

Ακολουθεί ο κώδικας για τη δημιουργία ενός απλού **διακομιστή** και **πελάτη** όπου ο πελάτης μπορεί να καλέσει τις συναρτήσεις Αφαίρεση από τον διακομιστή:

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

### Το NDR_record

Το NDR_record εξάγεται από το `libsystem_kernel.dylib`, και είναι μια δομή που επιτρέπει στο MIG να **μετασχηματίζει δεδομένα ώστε να είναι ανεξάρτητα από το σύστημα** στο οποίο χρησιμοποιείται, καθώς το MIG σχεδιάστηκε για να χρησιμοποιείται μεταξύ διαφορετικών συστημάτων (και όχι μόνο στην ίδια μηχανή).

Αυτό είναι ενδιαφέρον γιατί αν το `_NDR_record` βρεθεί σε ένα δυαδικό αρχείο ως εξάρτηση (`jtool2 -S <binary> | grep NDR` ή `nm`), σημαίνει ότι το δυαδικό αρχείο είναι πελάτης ή διακομιστής MIG.

Επιπλέον, οι **διακομιστές MIG** έχουν τον πίνακα διανομής στο `__DATA.__const` (ή στο `__CONST.__constdata` στον πυρήνα macOS και `__DATA_CONST.__const` σε άλλους πυρήνες \*OS). Αυτό μπορεί να αποθηκευτεί με **`jtool2`**.

Και οι **πελάτες MIG** θα χρησιμοποιήσουν το `__NDR_record` για να στείλουν με `__mach_msg` στους διακομιστές.

## Ανάλυση Δυαδικών

### jtool

Καθώς πολλά δυαδικά αρχεία χρησιμοποιούν τώρα το MIG για να εκθέσουν mach ports, είναι ενδιαφέρον να γνωρίζουμε πώς να **αναγνωρίσουμε ότι χρησιμοποιήθηκε το MIG** και τις **λειτουργίες που εκτελεί το MIG** με κάθε ID μηνύματος.

[**jtool2**](../../macos-apps-inspecting-debugging-and-fuzzing/#jtool2) μπορεί να αναλύσει πληροφορίες MIG από ένα δυαδικό Mach-O υποδεικνύοντας το ID μηνύματος και αναγνωρίζοντας τη λειτουργία που πρέπει να εκτελεστεί:
```bash
jtool2 -d __DATA.__const myipc_server | grep MIG
```
Επιπλέον, οι λειτουργίες MIG είναι απλώς περιτυλίγματα της πραγματικής λειτουργίας που καλείται, πράγμα που σημαίνει ότι αν αποκτήσετε την αποσυναρμολόγησή της και κάνετε grep για BL, μπορεί να είστε σε θέση να βρείτε την πραγματική λειτουργία που καλείται:
```bash
jtool2 -d __DATA.__const myipc_server | grep BL
```
### Assembly

Αναφέρθηκε προηγουμένως ότι η συνάρτηση που θα φροντίσει για **την κλήση της σωστής συνάρτησης ανάλογα με το αναγνωριστικό μηνύματος που έχει ληφθεί** ήταν η `myipc_server`. Ωστόσο, συνήθως δεν θα έχετε τα σύμβολα του δυαδικού (χωρίς ονόματα συναρτήσεων), οπότε είναι ενδιαφέρον να **ελέγξετε πώς φαίνεται αποσυμπιεσμένο** καθώς θα είναι πάντα πολύ παρόμοιο (ο κώδικας αυτής της συνάρτησης είναι ανεξάρτητος από τις εκτεθειμένες συναρτήσεις):

{{#tabs}}
{{#tab name="myipc_server decompiled 1"}}

<pre class="language-c"><code class="lang-c">int _myipc_server(int arg0, int arg1) {
var_10 = arg0;
var_18 = arg1;
// Αρχικές οδηγίες για να βρείτε τους σωστούς δείκτες συναρτήσεων
*(int32_t *)var_18 = *(int32_t *)var_10 &#x26; 0x1f;
*(int32_t *)(var_18 + 0x8) = *(int32_t *)(var_10 + 0x8);
*(int32_t *)(var_18 + 0x4) = 0x24;
*(int32_t *)(var_18 + 0xc) = 0x0;
*(int32_t *)(var_18 + 0x14) = *(int32_t *)(var_10 + 0x14) + 0x64;
*(int32_t *)(var_18 + 0x10) = 0x0;
if (*(int32_t *)(var_10 + 0x14) &#x3C;= 0x1f4 &#x26;&#x26; *(int32_t *)(var_10 + 0x14) >= 0x1f4) {
rax = *(int32_t *)(var_10 + 0x14);
// Κλήση στη sign_extend_64 που μπορεί να βοηθήσει στην αναγνώριση αυτής της συνάρτησης
// Αυτό αποθηκεύει στο rax τον δείκτη στην κλήση που πρέπει να γίνει
// Ελέγξτε τη χρήση της διεύθυνσης 0x100004040 (πίνακας διευθύνσεων συναρτήσεων)
// 0x1f4 = 500 (το αρχικό ID)
<strong>            rax = *(sign_extend_64(rax - 0x1f4) * 0x28 + 0x100004040);
</strong>            var_20 = rax;
// Αν - αλλιώς, το if επιστρέφει false, ενώ το else καλεί τη σωστή συνάρτηση και επιστρέφει true
<strong>            if (rax == 0x0) {
</strong>                    *(var_18 + 0x18) = **_NDR_record;
*(int32_t *)(var_18 + 0x20) = 0xfffffffffffffed1;
var_4 = 0x0;
}
else {
// Υπολογισμένη διεύθυνση που καλεί τη σωστή συνάρτηση με 2 παραμέτρους
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
Αυτή είναι η ίδια συνάρτηση αποσυμπιεσμένη σε μια διαφορετική δωρεάν έκδοση του Hopper:

<pre class="language-c"><code class="lang-c">int _myipc_server(int arg0, int arg1) {
r31 = r31 - 0x40;
saved_fp = r29;
stack[-8] = r30;
var_10 = arg0;
var_18 = arg1;
// Αρχικές οδηγίες για να βρείτε τους σωστούς δείκτες συναρτήσεων
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
// 0x1f4 = 500 (το αρχικό ID)
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
// Ίδιο if else όπως στην προηγούμενη έκδοση
// Ελέγξτε τη χρήση της διεύθυνσης 0x100004040 (πίνακας διευθύνσεων συναρτήσεων)
<strong>                    if ((r8 &#x26; 0x1) == 0x0) {
</strong><strong>                            *(var_18 + 0x18) = **0x100004000;
</strong>                            *(int32_t *)(var_18 + 0x20) = 0xfffffed1;
var_4 = 0x0;
}
else {
// Κλήση στη υπολογισμένη διεύθυνση όπου θα πρέπει να είναι η συνάρτηση
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

Στην πραγματικότητα, αν πάτε στη συνάρτηση **`0x100004000`** θα βρείτε τον πίνακα των **`routine_descriptor`** δομών. Το πρώτο στοιχείο της δομής είναι η **διεύθυνση** όπου είναι υλοποιημένη η **συνάρτηση**, και η **δομή καταλαμβάνει 0x28 bytes**, οπότε κάθε 0x28 bytes (ξεκινώντας από το byte 0) μπορείτε να πάρετε 8 bytes και αυτό θα είναι η **διεύθυνση της συνάρτησης** που θα κληθεί:

<figure><img src="../../../../images/image (35).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../../images/image (36).png" alt=""><figcaption></figcaption></figure>

Αυτά τα δεδομένα μπορούν να εξαχθούν [**χρησιμοποιώντας αυτό το σενάριο Hopper**](https://github.com/knightsc/hopper/blob/master/scripts/MIG%20Detect.py).

### Debug

Ο κώδικας που παράγεται από το MIG καλεί επίσης το `kernel_debug` για να δημιουργήσει αρχεία καταγραφής σχετικά με τις λειτουργίες κατά την είσοδο και έξοδο. Είναι δυνατή η εξέταση τους χρησιμοποιώντας **`trace`** ή **`kdv`**: `kdv all | grep MIG`

## References

- [\*OS Internals, Volume I, User Mode, Jonathan Levin](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

{{#include ../../../../banners/hacktricks-training.md}}
