# macOS MIG - Mach Interface Generator

{{#include ../../../../banners/hacktricks-training.md}}

## Osnovne informacije

MIG je kreiran da ** pojednostavi proces kreiranja Mach IPC** koda. U suštini, **generiše potrebni kod** za komunikaciju servera i klijenta prema datoj definiciji. Čak i ako je generisani kod ružan, programer će samo trebati da ga uveze i njegov kod će biti mnogo jednostavniji nego pre.

Definicija se specificira u jeziku za definiciju interfejsa (IDL) koristeći ekstenziju `.defs`.

Ove definicije imaju 5 sekcija:

- **Deklaracija podsistema**: Ključna reč subsystem se koristi da označi **ime** i **id**. Takođe je moguće označiti ga kao **`KernelServer`** ako server treba da radi u kernelu.
- **Uključivanja i uvozi**: MIG koristi C-preprocesor, tako da može da koristi uvoze. Štaviše, moguće je koristiti `uimport` i `simport` za kod generisan od strane korisnika ili servera.
- **Deklaracije tipova**: Moguće je definisati tipove podataka, iako obično uvozi `mach_types.defs` i `std_types.defs`. Za prilagođene tipove može se koristiti neka sintaksa:
- \[i`n/out]tran`: Funkcija koja treba da se prevede iz dolazne ili u odlaznu poruku
- `c[user/server]type`: Mapiranje na drugi C tip.
- `destructor`: Pozovite ovu funkciju kada se tip oslobodi.
- **Operacije**: Ovo su definicije RPC metoda. Postoji 5 različitih tipova:
- `routine`: Očekuje odgovor
- `simpleroutine`: Ne očekuje odgovor
- `procedure`: Očekuje odgovor
- `simpleprocedure`: Ne očekuje odgovor
- `function`: Očekuje odgovor

### Primer

Kreirajte datoteku definicije, u ovom slučaju sa vrlo jednostavnom funkcijom:
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
Napomena da je prvi **argument port koji se vezuje** i MIG će **automatski obraditi port za odgovor** (osim ako se poziva `mig_get_reply_port()` u klijentskom kodu). Štaviše, **ID operacija** će biti **sekvencijalni** počinjući od naznačenog ID-a podsistema (tako da ako je neka operacija zastarela, ona se briše i `skip` se koristi da bi se i dalje koristio njen ID).

Sada koristite MIG da generišete server i klijentski kod koji će moći da komuniciraju jedni s drugima kako bi pozvali funkciju Subtract:
```bash
mig -header myipcUser.h -sheader myipcServer.h myipc.defs
```
Nekoliko novih fajlova biće kreirano u trenutnom direktorijumu.

> [!TIP]
> Možete pronaći složeniji primer na vašem sistemu sa: `mdfind mach_port.defs`\
> I možete ga kompajlirati iz iste fascikle kao i fajl sa: `mig -DLIBSYSCALL_INTERFACE mach_ports.defs`

U fajlovima **`myipcServer.c`** i **`myipcServer.h`** možete pronaći deklaraciju i definiciju strukture **`SERVERPREFmyipc_subsystem`**, koja u osnovi definiše funkciju koja se poziva na osnovu primljenog ID-a poruke (naveli smo početni broj 500):

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

Na osnovu prethodne strukture, funkcija **`myipc_server_routine`** će dobiti **ID poruke** i vratiti odgovarajuću funkciju za pozivanje:
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
U ovom primeru smo definisali samo 1 funkciju u definicijama, ali da smo definisali više funkcija, one bi bile unutar niza **`SERVERPREFmyipc_subsystem`** i prva bi bila dodeljena ID-u **500**, druga ID-u **501**...

Ako se očekivalo da funkcija pošalje **odgovor**, funkcija `mig_internal kern_return_t __MIG_check__Reply__<name>` bi takođe postojala.

Zapravo, moguće je identifikovati ovu vezu u strukturi **`subsystem_to_name_map_myipc`** iz **`myipcServer.h`** (**`subsystem*to_name_map*\***`\*\* u drugim datotekama):
```c
#ifndef subsystem_to_name_map_myipc
#define subsystem_to_name_map_myipc \
{ "Subtract", 500 }
#endif
```
Na kraju, još jedna važna funkcija za rad servera biće **`myipc_server`**, koja će zapravo **pozvati funkciju** vezanu za primljeni id:

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
/* Minimalna veličina: routine() će je ažurirati ako je drugačija */
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

Proverite prethodno istaknute linije koje pristupaju funkciji koja se poziva po ID-u.

Sledeći je kod za kreiranje jednostavnog **servera** i **klijenta** gde klijent može pozvati funkcije Oduzimanje sa servera:

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

NDR_record se izvozi iz `libsystem_kernel.dylib`, i to je struktura koja omogućava MIG-u da **transformiše podatke tako da budu agnostični prema sistemu** na kojem se koristi, jer je MIG zamišljen da se koristi između različitih sistema (a ne samo na istoj mašini).

To je zanimljivo jer ako se `_NDR_record` pronađe u binarnom fajlu kao zavisnost (`jtool2 -S <binary> | grep NDR` ili `nm`), to znači da je binarni fajl MIG klijent ili server.

Štaviše, **MIG serveri** imaju tabelu raspodele u `__DATA.__const` (ili u `__CONST.__constdata` u macOS kernelu i `__DATA_CONST.__const` u drugim \*OS kernelima). Ovo se može izdumpovati pomoću **`jtool2`**.

A **MIG klijenti** će koristiti `__NDR_record` da pošalju sa `__mach_msg` serverima.

## Analiza binarnih fajlova

### jtool

Kako mnogi binarni fajlovi sada koriste MIG za izlaganje mach portova, zanimljivo je znati kako **identifikovati da je MIG korišćen** i **funkcije koje MIG izvršava** sa svakim ID-om poruke.

[**jtool2**](../../macos-apps-inspecting-debugging-and-fuzzing/index.html#jtool2) može da analizira MIG informacije iz Mach-O binarnog fajla, ukazujući na ID poruke i identifikujući funkciju koja treba da se izvrši:
```bash
jtool2 -d __DATA.__const myipc_server | grep MIG
```
Pored toga, MIG funkcije su samo omotači stvarne funkcije koja se poziva, što znači da dobijanjem njenog disasembly-a i pretraživanjem za BL možda možete pronaći stvarnu funkciju koja se poziva:
```bash
jtool2 -d __DATA.__const myipc_server | grep BL
```
### Assembly

Prethodno je pomenuto da će funkcija koja se bavi **pozivanjem ispravne funkcije u zavisnosti od primljenog ID-a poruke** biti `myipc_server`. Međutim, obično nećete imati simbole binarnog fajla (nema imena funkcija), pa je zanimljivo **proveriti kako izgleda dekompilirana** jer će uvek biti vrlo slična (kod ove funkcije je nezavistan od izloženih funkcija):

{{#tabs}}
{{#tab name="myipc_server decompiled 1"}}

<pre class="language-c"><code class="lang-c">int _myipc_server(int arg0, int arg1) {
var_10 = arg0;
var_18 = arg1;
// Početne instrukcije za pronalaženje ispravnih pokazivača funkcija
*(int32_t *)var_18 = *(int32_t *)var_10 &#x26; 0x1f;
*(int32_t *)(var_18 + 0x8) = *(int32_t *)(var_10 + 0x8);
*(int32_t *)(var_18 + 0x4) = 0x24;
*(int32_t *)(var_18 + 0xc) = 0x0;
*(int32_t *)(var_18 + 0x14) = *(int32_t *)(var_10 + 0x14) + 0x64;
*(int32_t *)(var_18 + 0x10) = 0x0;
if (*(int32_t *)(var_10 + 0x14) &#x3C;= 0x1f4 &#x26;&#x26; *(int32_t *)(var_10 + 0x14) >= 0x1f4) {
rax = *(int32_t *)(var_10 + 0x14);
// Poziv sign_extend_64 koji može pomoći u identifikaciji ove funkcije
// Ovo čuva u rax pokazivač na poziv koji treba da se pozove
// Proverite korišćenje adrese 0x100004040 (niz adresa funkcija)
// 0x1f4 = 500 (početni ID)
<strong>            rax = *(sign_extend_64(rax - 0x1f4) * 0x28 + 0x100004040);
</strong>            var_20 = rax;
// Ako - else, if vraća false, dok else poziva ispravnu funkciju i vraća true
<strong>            if (rax == 0x0) {
</strong>                    *(var_18 + 0x18) = **_NDR_record;
*(int32_t *)(var_18 + 0x20) = 0xfffffffffffffed1;
var_4 = 0x0;
}
else {
// Izračunata adresa koja poziva ispravnu funkciju sa 2 argumenta
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
Ovo je ista funkcija dekompilirana u drugoj verziji Hopper-a:

<pre class="language-c"><code class="lang-c">int _myipc_server(int arg0, int arg1) {
r31 = r31 - 0x40;
saved_fp = r29;
stack[-8] = r30;
var_10 = arg0;
var_18 = arg1;
// Početne instrukcije za pronalaženje ispravnih pokazivača funkcija
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
// 0x1f4 = 500 (početni ID)
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
// Ista if else kao u prethodnoj verziji
// Proverite korišćenje adrese 0x100004040 (niz adresa funkcija)
<strong>                    if ((r8 &#x26; 0x1) == 0x0) {
</strong><strong>                            *(var_18 + 0x18) = **0x100004000;
</strong>                            *(int32_t *)(var_18 + 0x20) = 0xfffffed1;
var_4 = 0x0;
}
else {
// Poziv na izračunatu adresu gde bi funkcija trebala biti
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

U stvari, ako odete na funkciju **`0x100004000`** pronaći ćete niz **`routine_descriptor`** struktura. Prvi element strukture je **adresa** gde je **funkcija** implementirana, a **struktura zauzima 0x28 bajtova**, tako da svaka 0x28 bajtova (počevši od bajta 0) možete dobiti 8 bajtova i to će biti **adresa funkcije** koja će biti pozvana:

<figure><img src="../../../../images/image (35).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../../images/image (36).png" alt=""><figcaption></figcaption></figure>

Ovi podaci se mogu izvući [**koristeći ovaj Hopper skript**](https://github.com/knightsc/hopper/blob/master/scripts/MIG%20Detect.py).

### Debug

Kod koji generiše MIG takođe poziva `kernel_debug` da generiše logove o operacijama na ulazu i izlazu. Moguće je proveriti ih koristeći **`trace`** ili **`kdv`**: `kdv all | grep MIG`

## References

- [\*OS Internals, Volume I, User Mode, Jonathan Levin](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

{{#include ../../../../banners/hacktricks-training.md}}
