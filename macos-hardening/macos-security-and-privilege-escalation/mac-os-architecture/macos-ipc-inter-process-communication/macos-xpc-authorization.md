## Autorização XPC

A Apple também propõe outra maneira de autenticar se o processo de conexão tem **permissões para chamar um método XPC exposto**.

Quando um aplicativo precisa **executar ações como um usuário privilegiado**, em vez de executar o aplicativo como um usuário privilegiado, ele geralmente instala como root um HelperTool como um serviço XPC que pode ser chamado do aplicativo para executar essas ações. No entanto, o aplicativo que chama o serviço deve ter autorização suficiente.

### ShuoldAcceptNewConnection sempre YES

Um exemplo pode ser encontrado em [EvenBetterAuthorizationSample](https://github.com/brenwell/EvenBetterAuthorizationSample). Em `App/AppDelegate.m`, ele tenta **conectar** ao **HelperTool**. E em `HelperTool/HelperTool.m`, a função **`shouldAcceptNewConnection`** **não verificará** nenhum dos requisitos indicados anteriormente. Ele sempre retornará YES:
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

{% content-ref url="macos-xpc-connecting-process-check.md" %}
[macos-xpc-connecting-process-check.md](macos-xpc-connecting-process-check.md)
{% endcontent-ref %}

### Direitos de aplicação

No entanto, há alguma **autorização ocorrendo quando um método do HelperTool é chamado**.

A função **`applicationDidFinishLaunching`** do arquivo `App/AppDelegate.m` criará uma referência de autorização vazia após o aplicativo ter iniciado. Isso deve sempre funcionar.\
Em seguida, ele tentará **adicionar alguns direitos** a essa referência de autorização chamando `setupAuthorizationRights`:
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
A função `setupAuthorizationRights` do arquivo `Common/Common.m` armazenará no banco de dados de autorização `/var/db/auth.db` os direitos da aplicação. Observe como ela adicionará apenas os direitos que ainda não estão no banco de dados:
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
A função `enumerateRightsUsingBlock` é a utilizada para obter as permissões de aplicativos, que são definidas em `commandInfo`:
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
Isso significa que, no final desse processo, as permissões declaradas dentro de `commandInfo` serão armazenadas em `/var/db/auth.db`. Observe como lá você pode encontrar para **cada método** que exigirá autenticação, o **nome da permissão** e o **`kCommandKeyAuthRightDefault`**. Este último **indica quem pode obter esse direito**.

Existem diferentes escopos para indicar quem pode acessar um direito. Alguns deles são definidos em [AuthorizationDB.h](https://github.com/aosm/Security/blob/master/Security/libsecurity\_authorization/lib/AuthorizationDB.h) (você pode encontrar [todos eles aqui](https://www.dssw.co.uk/reference/authorization-rights/)), mas, em resumo:

<table><thead><tr><th width="284.3333333333333">Nome</th><th width="165">Valor</th><th>Descrição</th></tr></thead><tbody><tr><td>kAuthorizationRuleClassAllow</td><td>allow</td><td>Qualquer pessoa</td></tr><tr><td>kAuthorizationRuleClassDeny</td><td>deny</td><td>Ninguém</td></tr><tr><td>kAuthorizationRuleIsAdmin</td><td>is-admin</td><td>O usuário atual precisa ser um administrador (dentro do grupo de administradores)</td></tr><tr><td>kAuthorizationRuleAuthenticateAsSessionUser</td><td>authenticate-session-owner</td><td>Pedir ao usuário para autenticar.</td></tr><tr><td>kAuthorizationRuleAuthenticateAsAdmin</td><td>authenticate-admin</td><td>Pedir ao usuário para autenticar. Ele precisa ser um administrador (dentro do grupo de administradores)</td></tr><tr><td>kAuthorizationRightRule</td><td>rule</td><td>Especificar regras</td></tr><tr><td>kAuthorizationComment</td><td>comment</td><td>Especificar alguns comentários extras sobre o direito</td></tr></tbody></table>

### Verificação de Direitos

Em `HelperTool/HelperTool.m`, a função **`readLicenseKeyAuthorization`** verifica se o chamador está autorizado a **executar tal método** chamando a função **`checkAuthorization`**. Esta função verificará se os **dados de autenticação** enviados pelo processo chamador têm um **formato correto** e, em seguida, verificará **o que é necessário para obter o direito** de chamar o método específico. Se tudo correr bem, o **`error` retornado será `nil`**:
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
Observe que para **verificar os requisitos para obter o direito** de chamar aquele método, a função `authorizationRightForCommand` apenas verificará o objeto previamente comentado **`commandInfo`**. Em seguida, ela chamará **`AuthorizationCopyRights`** para verificar **se tem os direitos** para chamar a função (observe que as flags permitem interação com o usuário).

Neste caso, para chamar a função `readLicenseKeyAuthorization`, o `kCommandKeyAuthRightDefault` é definido como `@kAuthorizationRuleClassAllow`. Então, **qualquer pessoa pode chamá-lo**.

### Informações do BD

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
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
