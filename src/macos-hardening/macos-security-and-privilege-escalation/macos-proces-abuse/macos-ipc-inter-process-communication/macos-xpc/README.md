# macOS XPC

{{#include ../../../../../banners/hacktricks-training.md}}

## Βασικές πληροφορίες

Το XPC είναι ένα framework για **επικοινωνία μεταξύ διεργασιών** σε macOS και iOS. Παρέχει μηχανισμούς για **ασφαλείς, ασύγχρονες κλήσεις μεταξύ διεργασιών**. Το XPC υποστηρίζει **εφαρμογές με διαχωρισμό προνομίων**, στις οποίες κάθε **στοιχείο** εκτελείται με **μόνο τα δικαιώματα που χρειάζεται**, περιορίζοντας έτσι την πιθανή ζημιά από μια διεργασία που έχει παραβιαστεί.<sup>[[1]](#references)</sup>

Το XPC χρησιμοποιεί μια μορφή Επικοινωνίας μεταξύ Διεργασιών (IPC), δηλαδή ένα σύνολο μεθόδων που επιτρέπουν σε διαφορετικά προγράμματα που εκτελούνται στο ίδιο σύστημα να ανταλλάσσουν δεδομένα.

Τα κύρια οφέλη του XPC περιλαμβάνουν:

1. **Ασφάλεια**: Με τον διαχωρισμό των εργασιών σε διαφορετικές διεργασίες, σε κάθε διεργασία μπορούν να εκχωρηθούν μόνο τα δικαιώματα που χρειάζεται. Αυτό σημαίνει ότι ακόμη και αν μια διεργασία παραβιαστεί, έχει περιορισμένη δυνατότητα να προκαλέσει ζημιά.
2. **Σταθερότητα**: Το XPC συμβάλλει στον περιορισμό των καταρρεύσεων στο στοιχείο όπου συμβαίνουν. Αν μια διεργασία καταρρεύσει, μπορεί να επανεκκινηθεί χωρίς να επηρεαστεί το υπόλοιπο σύστημα.
3. **Απόδοση**: Το XPC διευκολύνει την ταυτόχρονη εκτέλεση, καθώς διαφορετικές εργασίες μπορούν να εκτελούνται παράλληλα σε διαφορετικές διεργασίες.

Το κύριο **μειονέκτημα** είναι ότι ο **διαχωρισμός μιας εφαρμογής σε πολλές διεργασίες** και η επικοινωνία τους μέσω XPC προσθέτουν επιβάρυνση. Σε σύγχρονα συστήματα, αυτή η επιβάρυνση είναι συνήθως μικρή σε σύγκριση με τα οφέλη στην ασφάλεια και τη σταθερότητα.<sup>[[1]](#references)</sup>

## XPC Services ειδικά για εφαρμογές

Τα στοιχεία XPC μιας εφαρμογής βρίσκονται **μέσα στην ίδια την εφαρμογή**. Για παράδειγμα, στο Safari βρίσκονται στο **`/Applications/Safari.app/Contents/XPCServices`**. Έχουν την επέκταση **`.xpc`** (όπως το **`com.apple.Safari.SandboxBroker.xpc`**) και είναι **επίσης bundles**, με το κύριο binary και ένα `Info.plist` στο εσωτερικό τους. Για παράδειγμα: `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker` και `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`.<sup>[[2]](#references)</sup>

Ένα **στοιχείο XPC μπορεί να έχει διαφορετικά entitlements και προνόμια** από άλλα στοιχεία XPC ή από το κύριο binary της εφαρμογής. Εξαίρεση αποτελεί μια υπηρεσία XPC που έχει ρυθμιστεί με την παράμετρο **`JoinExistingSession`** ορισμένη σε `true` στο αρχείο **Info.plist**. Σε αυτήν την περίπτωση, η υπηρεσία XPC συμμετέχει στην **ίδια συνεδρία ασφαλείας με την εφαρμογή** που την κάλεσε.<sup>[[4]](#references)</sup>

Οι υπηρεσίες XPC **εκκινούνται** από το **launchd** όταν χρειάζεται και μπορούν να **τερματιστούν** όταν **ολοκληρώσουν** τις εργασίες τους, ώστε να απελευθερωθούν πόροι του συστήματος. **Τα στοιχεία XPC που αφορούν συγκεκριμένες εφαρμογές μπορούν να χρησιμοποιηθούν μόνο από την εφαρμογή στην οποία ανήκουν**, μειώνοντας έτσι την έκθεση σε πιθανές ευπάθειες.<sup>[[2]](#references)</sup>

## XPC Services σε επίπεδο συστήματος

Σε αντίθεση με τις υπηρεσίες που αφορούν συγκεκριμένες εφαρμογές, οι υπηρεσίες XPC σε επίπεδο συστήματος δεν περιορίζονται στην εφαρμογή στην οποία ανήκουν. Μπορεί να είναι προσβάσιμες από clients πολλών χρηστών, ανάλογα με το domain του launchd και τους ελέγχους εξουσιοδότησης της ίδιας της υπηρεσίας. Αυτές οι υπηρεσίες Mach, τις οποίες διαχειρίζεται το launchd, πρέπει να **ορίζονται σε** αρχεία plist που βρίσκονται σε καταλόγους όπως οι **`/System/Library/LaunchDaemons`**, **`/Library/LaunchDaemons`**, **`/System/Library/LaunchAgents`** ή **`/Library/LaunchAgents`**.<sup>[[2]](#references)[[3]](#references)</sup>

Αυτά τα αρχεία plist περιέχουν ένα κλειδί **`MachServices`** με το όνομα της υπηρεσίας και ένα κλειδί **`Program`** με τη διαδρομή προς το binary:

```xml
cat /Library/LaunchDaemons/com.jamf.management.daemon.plist

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Program</key>
	<string>/Library/Application Support/JAMF/Jamf.app/Contents/MacOS/JamfDaemon.app/Contents/MacOS/JamfDaemon</string>
	<key>AbandonProcessGroup</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>Label</key>
	<string>com.jamf.management.daemon</string>
	<key>MachServices</key>
	<dict>
		<key>com.jamf.management.daemon.aad</key>
		<true/>
		<key>com.jamf.management.daemon.agent</key>
		<true/>
		<key>com.jamf.management.daemon.binary</key>
		<true/>
		<key>com.jamf.management.daemon.selfservice</key>
		<true/>
		<key>com.jamf.management.daemon.service</key>
		<true/>
	</dict>
	<key>RunAtLoad</key>
	<true/>
</dict>
</plist>
```

Οι υπηρεσίες στο **`LaunchDaemons`** εκτελούνται συνήθως ως root. Επομένως, αν μια μη προνομιούχα διεργασία μπορεί να καλέσει μια ευάλωτη μέθοδο που εκθέτει κάποια από αυτές τις υπηρεσίες, ενδέχεται να μπορέσει να κλιμακώσει τα προνόμιά της.

## Αντικείμενα XPC

- **`xpc_object_t`**

Τα payload αιτημάτων και απαντήσεων XPC είναι συνήθως αντικείμενα dictionary, τα οποία απλοποιούν τη σειριοποίηση και την αποσειριοποίηση. Το `libxpc.dylib` ορίζει επίσης τους τύπους δεδομένων που χρειάζονται για την επαλήθευση ότι τα δεδομένα που λαμβάνονται έχουν τον αναμενόμενο τύπο. Στο C API κάθε αντικείμενο είναι ένα `xpc_object_t` (και ο τύπος του μπορεί να ελεγχθεί με τη χρήση της `xpc_get_type(object)`).<sup>[[2]](#references)</sup>\
Επιπλέον, η συνάρτηση `xpc_copy_description(object)` μπορεί να χρησιμοποιηθεί για τη λήψη μιας συμβολοσειράς που αναπαριστά το αντικείμενο και μπορεί να φανεί χρήσιμη για debugging.\
Αυτά τα αντικείμενα διαθέτουν επίσης μεθόδους όπως `xpc_<object>_copy`, `xpc_<object>_equal`, `xpc_<object>_hash`, `xpc_<object>_serialize`, `xpc_<object>_deserialize`...

Τα αντικείμενα `xpc_object_t` δημιουργούνται με την κλήση μιας συνάρτησης `xpc_<objectType>_create`, η οποία καλεί εσωτερικά τη `_xpc_base_create(Class, Size)`, δηλώνοντας την κλάση του αντικειμένου (μία από τις `XPC_TYPE_*`) και το μέγεθός του. Προστίθενται επιπλέον 40 bytes για metadata, επομένως τα δεδομένα του αντικειμένου ξεκινούν από το offset των 40 bytes.\
Επομένως, το `xpc_<objectType>_t` είναι ένα είδος υποκλάσης του `xpc_object_t`, το οποίο με τη σειρά του αποτελεί υποκλάση του `os_object_t*`.

> [!WARNING]
> Σημειώστε ότι ο developer πρέπει να χρησιμοποιεί τα `xpc_dictionary_[get/set]_<objectType>` για να λαμβάνει ή να ορίζει τον τύπο και την πραγματική τιμή ενός key.

- **`xpc_pipe`**

Ένα **`xpc_pipe`** είναι ένας αγωγός FIFO που μπορούν να χρησιμοποιούν οι διεργασίες για να επικοινωνούν (η επικοινωνία γίνεται με μηνύματα Mach).\
Μπορείτε να δημιουργήσετε έναν XPC server καλώντας τις `xpc_pipe_create()` ή `xpc_pipe_create_from_port()`, ώστε να δημιουργηθεί με χρήση συγκεκριμένης θύρας Mach. Έπειτα, για τη λήψη μηνυμάτων μπορείτε να καλέσετε τις `xpc_pipe_receive` και `xpc_pipe_try_receive`.

Σημειώστε ότι το αντικείμενο **`xpc_pipe`** είναι ένα **`xpc_object_t`** με πληροφορίες στη struct του σχετικά με τις δύο θύρες Mach που χρησιμοποιούνται και το όνομα (αν υπάρχει). Για παράδειγμα, στο plist του daemon `secinitd`, `/System/Library/LaunchDaemons/com.apple.secinitd.plist`, ρυθμίζεται ο αγωγός με όνομα `com.apple.secinitd`.

Παράδειγμα **`xpc_pipe`** είναι ο **bootstrap pipe** που δημιουργεί το **`launchd`**, ο οποίος επιτρέπει την κοινή χρήση θυρών Mach.

- **`NSXPC*`**

Πρόκειται για αντικείμενα Objective-C υψηλού επιπέδου που αφαιρούν τις λεπτομέρειες των συνδέσεων XPC.\
Επιπλέον, είναι ευκολότερο να γίνει debugging αυτών των αντικειμένων με το DTrace απ’ ό,τι των προηγούμενων.

- **`GCD Queues`**

Το XPC χρησιμοποιεί το GCD για τη μεταφορά μηνυμάτων, ενώ παράλληλα δημιουργεί ορισμένες ουρές dispatch, όπως οι `xpc.transactionq`, `xpc.io`, `xpc-events.add-listenerq`, `xpc.service-instance`...

## Υπηρεσίες XPC

Πρόκειται για **bundles με επέκταση `.xpc`**, τα οποία βρίσκονται μέσα στον φάκελο **`XPCServices`** άλλων projects. Στο `Info.plist` έχουν ορισμένο το `CFBundlePackageType` σε **`XPC!`**.\
Αυτό το αρχείο έχει και άλλα configuration keys, όπως το `ServiceType`, που μπορεί να είναι Application, User ή System· το `_SandboxProfile`, που μπορεί να ορίζει ένα sandbox· και το `_AllowedClients`, που μπορεί να υποδεικνύει τα entitlements ή την ταυτότητα που απαιτούνται για την επικοινωνία με την υπηρεσία. Αυτές και άλλες επιλογές ρυθμίζουν την υπηρεσία κατά την εκκίνησή της.<sup>[[2]](#references)</sup>

### Εκκίνηση μιας υπηρεσίας

Η εφαρμογή επιχειρεί να **συνδεθεί** με μια υπηρεσία XPC χρησιμοποιώντας τη `xpc_connection_create_mach_service`· έπειτα, το launchd εντοπίζει τον daemon και εκκινεί το **`xpcproxy`**. Το **`xpcproxy`** επιβάλλει τους ρυθμισμένους περιορισμούς και εκκινεί την υπηρεσία με τους file descriptors και τις θύρες Mach που της έχουν δοθεί.<sup>[[3]](#references)</sup>

Για να επιταχυνθεί η αναζήτηση της υπηρεσίας XPC, χρησιμοποιείται cache.

Μπορείτε να παρακολουθήσετε τις ενέργειες του `xpcproxy` με τη χρήση του:

```bash
supraudit S -C -o /tmp/output /dev/auditpipe
```

Η βιβλιοθήκη XPC χρησιμοποιεί το `kdebug` για να καταγράφει ενέργειες καλώντας τις `xpc_ktrace_pid0` και `xpc_ktrace_pid1`. Οι κωδικοί που χρησιμοποιεί δεν είναι τεκμηριωμένοι, επομένως πρέπει να προστεθούν στο `/usr/share/misc/trace.codes`. Έχουν το πρόθεμα `0x29`· για παράδειγμα, το `0x29000004` είναι το `XPC_serializer_pack`.\
Το βοηθητικό πρόγραμμα `xpcproxy` χρησιμοποιεί το πρόθεμα `0x22`· για παράδειγμα: `0x2200001c: xpcproxy:will_do_preexec`.

## Έλεγχος βοηθητικών προγραμμάτων XPC τύπου Application

Ένα `XPCService.ServiceType` με τιμή `Application` αποτελεί χρήσιμο σημείο εκκίνησης για τον έλεγχο βοηθητικών προγραμμάτων που παρέχονται από frameworks: απαριθμήστε τα bundles, διατηρήστε τις υπηρεσίες που εκτελούνται και εξετάστε το αναγνωριστικό και τα entitlements του βοηθητικού προγράμματος. Αναζητήστε τόσο στο `/System/Library/Frameworks` όσο και στο `/System/Library/PrivateFrameworks`· η ακριβής λίστα αλλάζει μεταξύ των εκδόσεων του macOS.<sup>[[7]](#references)</sup>

```bash
find /System/Library/Frameworks /System/Library/PrivateFrameworks \
  -type d -name '*.xpc' -print0 2>/dev/null |
while IFS= read -r -d '' bundle; do
    plist="$bundle/Contents/Info.plist"
    [ "$(plutil -extract XPCService.ServiceType raw -o - "$plist" 2>/dev/null)" = Application ] || continue

    exe=$(plutil -extract CFBundleExecutable raw -o - "$plist" 2>/dev/null) || continue
    bin="$bundle/Contents/MacOS/$exe"
    ps -axo comm= | awk -v b="$bin" '{sub(/^[[:space:]]+/, ""); if ($0==b) found=1} END {exit !found}' || continue

    printf '\n%s\n  id: %s\n' "$bundle" \
      "$(plutil -extract CFBundleIdentifier raw -o - "$plist" 2>/dev/null)"
    codesign -d --entitlements :- "$bundle" 2>&1
done
```

### Διαλογή του listener και ανάκτηση ενός ελάχιστου protocol

Εντοπίστε το `-[<delegate> listener:shouldAcceptNewConnection:]` στο helper. Μια διαδρομή που ορίζει τα `exportedInterface` και `exportedObject`, συνεχίζει τη σύνδεση και επιστρέφει `YES`/`1` χωρίς να ελέγχει το audit token, το code requirement ή το entitlement του peer εκθέτει το RPC interface σε κάθε client που μπορεί να εντοπίσει την υπηρεσία. Αυτό αποδεικνύει μόνο **προσβασιμότητα**: για να υπάρχει επίπτωση, απαιτείται επίσης μια exported μέθοδος που εκτελεί privileged λειτουργία χωρίς επαρκή εξουσιοδότηση ανά client ή μέθοδο, ή που επεξεργάζεται με μη ασφαλή τρόπο δεδομένα ελεγχόμενα από τον attacker.<sup>[[7]](#references)</sup>

Ανακτήστε μόνο τους selectors που χρειάζονται για τις δοκιμές. Τα metadata των Objective-C selectors αποκαλύπτουν τον αριθμό των ορισμάτων· οι χρήσεις των ορισμάτων στον decompiler συνήθως βοηθούν στον προσδιορισμό των τύπων (για παράδειγμα, οι τιμές που περνούν στα `-[EKEvent setStartDate:]` και `setEndDate:` είναι `NSDate *`), ενώ η έμμεση κλήση στο τέλος της μεθόδου αποκαλύπτει τις παραμέτρους του reply block. Ένα μερικό τοπικό protocol αρκεί για το `NSXPCInterface`· δεν χρειάζεται να ανακατασκευάσετε ολόκληρο το private protocol.<sup>[[7]](#references)</sup>

### Σύνδεση με το ανακατασκευασμένο interface

Για μια υπηρεσία application XPC, φορτώστε οποιοδήποτε framework ορίζει τις απαιτούμενες private classes, δημιουργήστε τη σύνδεση με το `initWithServiceName:`, ορίστε το ανακατασκευασμένο remote interface, εγκαταστήστε handlers για errors, interruptions και invalidations και μόνο τότε συνεχίστε τη σύνδεση. Διατηρήστε ενεργό το run loop για τις ασύγχρονες απαντήσεις. Εκτελέστε ξανά τον client μέσα σε sandboxed εφαρμογή όταν δοκιμάζετε όριο sandbox — η επιτυχία ενός standalone client δεν αποτελεί απόδειξη παράκαμψης του sandbox.<sup>[[7]](#references)</sup>

<details>
<summary>Ελάχιστος Objective-C client</summary>

```objectivec
@protocol RecoveredProtocol
- (void)createEventIntentWithStartDate:(NSDate *)start
                               endDate:(NSDate *)end
                             withReply:(void (^)(id object, id error))reply;
@end

[[NSBundle bundleWithPath:@"/System/Library/PrivateFrameworks/AppPredictionFoundation.framework"] load];
NSXPCConnection *c = [[NSXPCConnection alloc]
    initWithServiceName:@"com.apple.proactive.AppPredictionIntentsHelperService"];
c.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:@protocol(RecoveredProtocol)];
c.interruptionHandler = ^{ NSLog(@"interrupted"); };
c.invalidationHandler = ^{ NSLog(@"invalidated"); };
[c resume];
id proxy = [c remoteObjectProxyWithErrorHandler:^(NSError *e) { NSLog(@"%@", e); }];
[proxy createEventIntentWithStartDate:[NSDate date]
                              endDate:[NSDate dateWithTimeIntervalSinceNow:3600]
                            withReply:^(id obj, id err) { NSLog(@"%@ %@", obj, err); }];
[[NSRunLoop currentRunLoop] run];
```

Compile with `clang -fblocks -framework Foundation -o xpc_client xpc_client.m`.<sup>[[7]](#references)</sup>

</details>

### Χρησιμοποιήστε αποτυχίες secure coding ως oracle τύπων

Ένα σφάλμα `NSCocoaErrorDomain`, όπως ο κωδικός `4101`, μπορεί να αποκρύπτει τη χρήσιμη εξαίρεση σειριοποίησης. Αναζητήστε το όνομα της υπηρεσίας στο macOS unified log/Console: η εξαίρεση προσδιορίζει τόσο την απροσδόκητη κλάση όσο και τις κλάσεις που επιτρέπονται για αυτό το όρισμα του selector. Για μια απάντηση, επεκτείνετε τη λίστα επιτρεπόμενων κλάσεων στη **μεριά του client** με `setClasses:forSelector:argumentIndex:ofReply:`· με `ofReply:YES`, ο δείκτης `0` αναφέρεται στην πρώτη παράμετρο του block απάντησης και όχι στην πρώτη παράμετρο της μεθόδου.<sup>[[7]](#references)</sup>

Ρυθμίστε το interface πριν το αναθέσετε στη σύνδεση και καλέσετε το `[c resume]`:<sup>[[7]](#references)</sup>

```objectivec
NSXPCInterface *iface = [NSXPCInterface interfaceWithProtocol:@protocol(RecoveredProtocol)];
NSMutableSet *classes = [NSMutableSet setWithArray:@[
    NSDate.class, NSString.class, NSNumber.class,
    NSDictionary.class, NSArray.class, NSData.class
]];
Class intentClass = NSClassFromString(@"INIntent");
if (intentClass) [classes addObject:intentClass];
[iface setClasses:classes
      forSelector:@selector(createEventIntentWithStartDate:endDate:withReply:)
    argumentIndex:0
          ofReply:YES];
c.remoteObjectInterface = iface;
```

Η αντίστροφη περίπτωση είναι επίσης χρήσιμη: αν ο server απορρίψει μια είσοδο Foundation και καταγράψει μία μόνο επιτρεπόμενη private class, το log αποκαλύπτει τον αναμενόμενο τύπο wire και το framework του. Φορτώστε αυτό το framework, εξετάστε τις μεθόδους/ιδιότητες της class για να προσδιορίσετε με μεγαλύτερη ακρίβεια τους γενικούς τύπους `id` και κατασκευάστε δυναμικά το private object. Τα ορίσματα του `NSInvocation` ξεκινούν από τον δείκτη `2`, επειδή οι δείκτες `0` και `1` είναι τα κρυφά ορίσματα `self` και `_cmd`.<sup>[[7]](#references)</sup>

<details>
<summary>Κατασκευή private ορίσματος με NSInvocation</summary>

```objectivec
Class cls = NSClassFromString(@"LNStaticDeferredLocalizedString");
id allocated = [cls alloc];
SEL initializer = NSSelectorFromString(@"initWithKey:table:bundleURL:");
NSMethodSignature *signature = [allocated methodSignatureForSelector:initializer];
NSInvocation *invocation = [NSInvocation invocationWithMethodSignature:signature];
[invocation setTarget:allocated];
[invocation setSelector:initializer];

NSString *key = @"KEY";
NSString *table = @"Localizable";
NSURL *bundleURL = NSBundle.mainBundle.bundleURL;
[invocation setArgument:&key atIndex:2];
[invocation setArgument:&table atIndex:3];
[invocation setArgument:&bundleURL atIndex:4];
[invocation invoke];

__unsafe_unretained id privateObject = nil;
[invocation getReturnValue:&privateObject];
```

</details>

Για τη σχετική ροή εργασιών που αφορά τις υπηρεσίες Mach σε όλο το σύστημα, οι οποίες είναι καταχωρισμένες στο launchd, δείτε:

{{#ref}}
../../macos-xpc-mach-services-abuse.md
{{#endref}}

## Μηνύματα συμβάντων XPC

Οι εφαρμογές μπορούν να **εγγραφούν** σε διαφορετικά **μηνύματα** συμβάντων, ώστε να **ενεργοποιούνται κατ' απαίτηση** όταν συμβαίνουν τέτοια συμβάντα. Η **ρύθμιση** αυτών των υπηρεσιών γίνεται σε **αρχεία plist του launchd**, τα οποία βρίσκονται **στους ίδιους καταλόγους με τα προηγούμενα** και περιέχουν ένα επιπλέον κλειδί **`LaunchEvent`**.

### Έλεγχος της διεργασίας που συνδέεται μέσω XPC

Όταν μια διεργασία προσπαθεί να καλέσει μια μέθοδο μέσω σύνδεσης XPC, η **υπηρεσία XPC θα πρέπει να ελέγχει αν επιτρέπεται σε αυτή τη διεργασία να συνδεθεί**. Ακολουθούν συνήθεις μέθοδοι επαλήθευσης και τα πιθανά προβλήματά τους:


{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

## Εξουσιοδότηση XPC

Η Apple επιτρέπει επίσης στις εφαρμογές να **διαμορφώνουν δικαιώματα εξουσιοδότησης και τον τρόπο με τον οποίο τα αποκτούν οι καλούντες**, ώστε μια διεργασία με τα απαιτούμενα δικαιώματα να **επιτρέπεται να καλεί μια μέθοδο** που εκθέτει η υπηρεσία XPC:


{{#ref}}
macos-xpc-authorization.md
{{#endref}}

## XPC Sniffer

Για την υποκλοπή μηνυμάτων XPC, μπορείτε να χρησιμοποιήσετε το **xpcspy**, το οποίο χρησιμοποιεί το **Frida**.<sup>[[5]](#references)</sup>

```bash
# Install
pip3 install xpcspy
pip3 install xpcspy --no-deps # To not make xpcspy install Frida 15 and downgrade your Frida installation

# Start sniffing
xpcspy -U -r -W <bundle-id>
## Using filters (i: for input, o: for output)
xpcspy -U <prog-name> -t 'i:com.apple.*' -t 'o:com.apple.*' -r
```

Ένα άλλο πιθανό εργαλείο είναι το **XPoCe2**.<sup>[[6]](#references)</sup>

## Παράδειγμα κώδικα C για επικοινωνία XPC

{{#tabs}}
{{#tab name="xpc_server.c"}}

```c
// gcc xpc_server.c -o xpc_server

#include <xpc/xpc.h>

static void handle_event(xpc_object_t event) {
    if (xpc_get_type(event) == XPC_TYPE_DICTIONARY) {
        // Print received message
        const char* received_message = xpc_dictionary_get_string(event, "message");
        printf("Received message: %s\n", received_message);

        // Create a response dictionary
        xpc_object_t response = xpc_dictionary_create(NULL, NULL, 0);
        xpc_dictionary_set_string(response, "received", "received");

        // Send response
        xpc_connection_t remote = xpc_dictionary_get_remote_connection(event);
        xpc_connection_send_message(remote, response);

        // Clean up
        xpc_release(response);
    }
}

static void handle_connection(xpc_connection_t connection) {
    xpc_connection_set_event_handler(connection, ^(xpc_object_t event) {
        handle_event(event);
    });
    xpc_connection_resume(connection);
}

int main(int argc, const char *argv[]) {
    xpc_connection_t service = xpc_connection_create_mach_service("xyz.hacktricks.service",
                                                                   dispatch_get_main_queue(),
                                                                   XPC_CONNECTION_MACH_SERVICE_LISTENER);
    if (!service) {
        fprintf(stderr, "Failed to create service.\n");
        exit(EXIT_FAILURE);
    }

    xpc_connection_set_event_handler(service, ^(xpc_object_t event) {
        xpc_type_t type = xpc_get_type(event);
        if (type == XPC_TYPE_CONNECTION) {
            handle_connection(event);
        }
    });

    xpc_connection_resume(service);
    dispatch_main();

    return 0;
}
```

{{#endtab}}

{{#tab name="xpc_client.c"}}

```c
// gcc xpc_client.c -o xpc_client

#include <xpc/xpc.h>

int main(int argc, const char *argv[]) {
    xpc_connection_t connection = xpc_connection_create_mach_service("xyz.hacktricks.service", NULL, XPC_CONNECTION_MACH_SERVICE_PRIVILEGED);

    xpc_connection_set_event_handler(connection, ^(xpc_object_t event) {
        if (xpc_get_type(event) == XPC_TYPE_DICTIONARY) {
            // Print received message
            const char* received_message = xpc_dictionary_get_string(event, "received");
            printf("Received message: %s\n", received_message);
        }
    });

    xpc_connection_resume(connection);

    xpc_object_t message = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_string(message, "message", "Hello, Server!");

    xpc_connection_send_message(connection, message);

    dispatch_main();

    return 0;
}
```

{{#endtab}}

{{#tab name="xyz.hacktricks.service.plist"}}

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
<key>Label</key>
<string>xyz.hacktricks.service</string>
<key>MachServices</key>
    <dict>
        <key>xyz.hacktricks.service</key>
        <true/>
    </dict>
<key>Program</key>
    <string>/tmp/xpc_server</string>
    <key>ProgramArguments</key>
    <array>
        <string>/tmp/xpc_server</string>
    </array>
</dict>
</plist>
```

{{#endtab}}
{{#endtabs}}

```bash
# Compile the server & client
gcc xpc_server.c -o xpc_server
gcc xpc_client.c -o xpc_client

# Save the server in its configured location
cp xpc_server /tmp

# Load daemon
sudo cp xyz.hacktricks.service.plist /Library/LaunchDaemons
sudo launchctl load /Library/LaunchDaemons/xyz.hacktricks.service.plist

# Call client
./xpc_client

# Clean
sudo launchctl unload /Library/LaunchDaemons/xyz.hacktricks.service.plist
sudo rm /Library/LaunchDaemons/xyz.hacktricks.service.plist /tmp/xpc_server
```

## Παράδειγμα κώδικα Objective-C για επικοινωνία XPC

{{#tabs}}
{{#tab name="oc_xpc_server.m"}}

```objectivec
// gcc -framework Foundation oc_xpc_server.m -o oc_xpc_server
#include <Foundation/Foundation.h>

@protocol MyXPCProtocol
- (void)sayHello:(NSString *)some_string withReply:(void (^)(NSString *))reply;
@end

@interface MyXPCObject : NSObject <MyXPCProtocol>
@end


@implementation MyXPCObject
- (void)sayHello:(NSString *)some_string withReply:(void (^)(NSString *))reply {
    NSLog(@"Received message: %@", some_string);
    NSString *response = @"Received";
    reply(response);
}
@end

@interface MyDelegate : NSObject <NSXPCListenerDelegate>
@end


@implementation MyDelegate

- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
    newConnection.exportedInterface = [NSXPCInterface interfaceWithProtocol:@protocol(MyXPCProtocol)];

    MyXPCObject *my_object = [MyXPCObject new];

    newConnection.exportedObject = my_object;

    [newConnection resume];
    return YES;
}
@end

int main(void) {

    NSXPCListener *listener = [[NSXPCListener alloc] initWithMachServiceName:@"xyz.hacktricks.svcoc"];

    id <NSXPCListenerDelegate> delegate = [MyDelegate new];
    listener.delegate = delegate;
    [listener resume];

    sleep(10); // Fake something is done and then it ends
}
```

{{#endtab}}

{{#tab name="oc_xpc_client.m"}}

```objectivec
// gcc -framework Foundation oc_xpc_client.m -o oc_xpc_client
#include <Foundation/Foundation.h>

@protocol MyXPCProtocol
- (void)sayHello:(NSString *)some_string withReply:(void (^)(NSString *))reply;
@end

int main(void) {
    NSXPCConnection *connection = [[NSXPCConnection alloc] initWithMachServiceName:@"xyz.hacktricks.svcoc" options:NSXPCConnectionPrivileged];
    connection.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:@protocol(MyXPCProtocol)];
    [connection resume];

    [[connection remoteObjectProxy] sayHello:@"Hello, Server!" withReply:^(NSString *response) {
        NSLog(@"Received response: %@", response);
    }];

    [[NSRunLoop currentRunLoop] run];

    return 0;
}
```

{{#endtab}}

{{#tab name="xyz.hacktricks.svcoc.plist"}}

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
<key>Label</key>
<string>xyz.hacktricks.svcoc</string>
<key>MachServices</key>
    <dict>
        <key>xyz.hacktricks.svcoc</key>
        <true/>
    </dict>
<key>Program</key>
    <string>/tmp/oc_xpc_server</string>
    <key>ProgramArguments</key>
    <array>
        <string>/tmp/oc_xpc_server</string>
    </array>
</dict>
</plist>
```

{{#endtab}}
{{#endtabs}}

```bash
# Compile the server & client
gcc -framework Foundation oc_xpc_server.m -o oc_xpc_server
gcc -framework Foundation oc_xpc_client.m -o oc_xpc_client

# Save server on it's location
cp oc_xpc_server /tmp

# Load daemon
sudo cp xyz.hacktricks.svcoc.plist /Library/LaunchDaemons
sudo launchctl load /Library/LaunchDaemons/xyz.hacktricks.svcoc.plist

# Call client
./oc_xpc_client

# Clean
sudo launchctl unload /Library/LaunchDaemons/xyz.hacktricks.svcoc.plist
sudo rm /Library/LaunchDaemons/xyz.hacktricks.svcoc.plist /tmp/oc_xpc_server
```

## Client μέσα σε Dylib

```objectivec
// gcc -dynamiclib -framework Foundation oc_xpc_client.m -o oc_xpc_client.dylib
// gcc injection example:
// DYLD_INSERT_LIBRARIES=oc_xpc_client.dylib /path/to/vuln/bin

#import <Foundation/Foundation.h>

@protocol MyXPCProtocol
- (void)sayHello:(NSString *)some_string withReply:(void (^)(NSString *))reply;
@end

__attribute__((constructor))
static void customConstructor(int argc, const char **argv)
{
        NSString*  _serviceName = @"xyz.hacktricks.svcoc";

        NSXPCConnection* _agentConnection = [[NSXPCConnection alloc] initWithMachServiceName:_serviceName options:4096];

        [_agentConnection setRemoteObjectInterface:[NSXPCInterface interfaceWithProtocol:@protocol(MyXPCProtocol)]];

        [_agentConnection resume];

        [[_agentConnection remoteObjectProxyWithErrorHandler:^(NSError* error) {
            (void)error;
            NSLog(@"Connection Failure");
        }] sayHello:@"Hello, Server!" withReply:^(NSString *response) {
            NSLog(@"Received response: %@", response);
    }    ];
        NSLog(@"Done!");

    return;
}
```

## Remote XPC

Η λειτουργικότητα που παρέχεται από το `RemoteXPC.framework` (από το `libxpc`) επιτρέπει την επικοινωνία XPC μεταξύ διαφορετικών hosts.\
Οι υπηρεσίες που υποστηρίζουν remote XPC έχουν το κλειδί `UsesRemoteXPC` στο plist τους, όπως συμβαίνει με το `/System/Library/LaunchDaemons/com.apple.SubmitDiagInfo.plist`. Παρόλο που η υπηρεσία είναι καταχωρισμένη στο `launchd`, τη λειτουργικότητα παρέχουν το `UserEventAgent` και τα plugins `com.apple.remoted.plugin` και `com.apple.remoteservicediscovery.events.plugin`.

Επιπλέον, το `RemoteServiceDiscovery.framework` λαμβάνει πληροφορίες από το `com.apple.remoted.plugin`, εκθέτοντας συναρτήσεις όπως οι `get_device`, `get_unique_device` και `connect`.

Μόλις η `connect` επιστρέψει το socket file descriptor της υπηρεσίας, είναι δυνατή η χρήση της κλάσης `remote_xpc_connection_*`.

Μπορείτε να λάβετε πληροφορίες για remote services με το CLI `/usr/libexec/remotectl`, χρησιμοποιώντας εντολές όπως:

```bash
/usr/libexec/remotectl list # Get bridge devices
/usr/libexec/remotectl show ...# Get device properties and services
/usr/libexec/remotectl dumpstate # Like dump without indicating a service
/usr/libexec/remotectl [netcat|relay] ... # Expose a service in a port
...
```

Η επικοινωνία μεταξύ του bridgeOS και του host πραγματοποιείται μέσω μιας αποκλειστικής διεπαφής IPv6. Το `MultiverseSupport.framework` δημιουργεί sockets, των οποίων τα file descriptors χρησιμοποιούνται για την επικοινωνία.\
Μπορείτε να εντοπίσετε αυτές τις επικοινωνίες με τα `netstat`, `nettop` ή την εναλλακτική λύση ανοικτού κώδικα `netbottom`.

## References

- [1] [Apple Developer — XPC](https://developer.apple.com/documentation/xpc)
- [2] [Apple Developer Archive — Δημιουργία υπηρεσιών XPC](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingXPCServices.html)
- [3] [Apple Developer — `xpc_connection_create_mach_service`](https://developer.apple.com/documentation/xpc/xpc_connection_create_mach_service(_:_:_:))
- [4] [Apple Developer — `JoinExistingSession`](https://developer.apple.com/documentation/bundleresources/information_property_list/xpcservice/joinexistingsession)
- [5] [hot3eed/xpcspy](https://github.com/hot3eed/xpcspy)
- [6] [NewOSXBook — XPoCe2](https://newosxbook.com/tools/XPoCe2.html)
- [7] [Reverse Society - Επίθεση σε macOS XPC Helpers: Αντίστροφη μηχανική πρωτοκόλλου](https://blog.reversesociety.co/blog/2025/how-to-attack-macos-application-xpc-helpers)
{{#include ../../../../../banners/hacktricks-training.md}}
