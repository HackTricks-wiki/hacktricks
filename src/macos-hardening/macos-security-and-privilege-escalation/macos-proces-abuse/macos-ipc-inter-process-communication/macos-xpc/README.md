# macOS XPC

{{#include ../../../../../banners/hacktricks-training.md}}

## Informações básicas

XPC é um framework para **comunicação entre processos** no macOS e iOS. Ele fornece mecanismos para fazer **chamadas assíncronas seguras entre processos**. O XPC oferece suporte a **aplicativos com privilégios separados**, nos quais cada **componente** é executado com **apenas as permissões necessárias**, limitando assim os possíveis danos causados por um processo comprometido.<sup>[[1]](#references)</sup>

O XPC usa uma forma de comunicação entre processos (IPC), que é um conjunto de métodos que permite a diferentes programas em execução no mesmo sistema trocar dados.

Os principais benefícios do XPC incluem:

1. **Segurança**: Ao separar o trabalho em diferentes processos, cada processo pode receber apenas as permissões necessárias. Isso significa que, mesmo que um processo seja comprometido, sua capacidade de causar danos é limitada.
2. **Estabilidade**: O XPC ajuda a isolar falhas no componente onde ocorrem. Se um processo falhar, ele pode ser reiniciado sem afetar o restante do sistema.
3. **Desempenho**: O XPC facilita a execução concorrente, pois diferentes tarefas podem ser executadas simultaneamente em processos distintos.

A principal **desvantagem** é que **separar um aplicativo em vários processos** e fazê-los se comunicar por meio do XPC adiciona overhead. Em sistemas modernos, esse overhead costuma ser pequeno em comparação com os benefícios de segurança e estabilidade.<sup>[[1]](#references)</sup>

## Serviços XPC específicos de aplicativos

Os componentes XPC de um aplicativo ficam **dentro do próprio aplicativo**. Por exemplo, no Safari, você pode encontrá-los em **`/Applications/Safari.app/Contents/XPCServices`**. Eles têm a extensão **`.xpc`** (como **`com.apple.Safari.SandboxBroker.xpc`**) e **também são bundles**, com o binário principal e um `Info.plist` dentro deles. Por exemplo: `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker` e `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`.<sup>[[2]](#references)</sup>

Um **componente XPC pode ter entitlements e privilégios diferentes** dos de outros componentes XPC ou do binário principal do aplicativo. Uma exceção é um serviço XPC configurado com **`JoinExistingSession`** definido como `true` no arquivo **Info.plist**. Nesse caso, o serviço XPC entra na **mesma sessão de segurança do aplicativo** que o chamou.<sup>[[4]](#references)</sup>

Os serviços XPC são **iniciados** pelo **launchd** quando necessário e podem ser **encerrados** depois que suas tarefas são **concluídas**, para liberar recursos do sistema. **Os componentes XPC específicos de um aplicativo só podem ser usados pelo aplicativo que os contém**, reduzindo assim a exposição a possíveis vulnerabilidades.<sup>[[2]](#references)</sup>

## Serviços XPC em todo o sistema

Ao contrário dos serviços específicos de aplicativos, os serviços XPC em todo o sistema não são restritos ao aplicativo que os contém. Eles podem ser acessíveis a clientes de vários usuários, dependendo do domínio do launchd e das próprias verificações de autorização do serviço. Esses serviços Mach gerenciados pelo launchd precisam ser **definidos em arquivos plist** localizados em diretórios como **`/System/Library/LaunchDaemons`**, **`/Library/LaunchDaemons`**, **`/System/Library/LaunchAgents`** ou **`/Library/LaunchAgents`**.<sup>[[2]](#references)[[3]](#references)</sup>

Esses arquivos plist têm uma chave **`MachServices`** contendo o nome do serviço e uma chave **`Program`** contendo o caminho para o binário:

```xml
cat /Library/LaunchDaemons/com.jamf.management.daemon.plist

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Program</key>
	<string>/Library/Application Support/JAMF/Jamf.app/Contents/MacOS/JamfDaemon.app/Contents/MacOS/JamfDaemon</string>
	<key>AbandonProcessGroup</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>Label</key>
	<string>com.jamf.management.daemon</string>
	<key>MachServices</key>
	<dict>
		<key>com.jamf.management.daemon.aad</key>
		<true/>
		<key>com.jamf.management.daemon.agent</key>
		<true/>
		<key>com.jamf.management.daemon.binary</key>
		<true/>
		<key>com.jamf.management.daemon.selfservice</key>
		<true/>
		<key>com.jamf.management.daemon.service</key>
		<true/>
	</dict>
	<key>RunAtLoad</key>
	<true/>
</dict>
</plist>
```

Services em **`LaunchDaemons`** geralmente são executados como root. Portanto, se um processo sem privilégios puder acessar um método vulnerável exposto por um desses serviços, talvez consiga escalar privilégios.

## Objetos XPC

- **`xpc_object_t`**

As cargas úteis de requisição e resposta do XPC geralmente são objetos de dicionário, que simplificam a serialização e a desserialização. `libxpc.dylib` também declara os tipos de dados necessários para verificar se os dados recebidos têm o tipo esperado. Na API C, todo objeto é um `xpc_object_t` (e seu tipo pode ser verificado usando `xpc_get_type(object)`).<sup>[[2]](#references)</sup>\
Além disso, a função `xpc_copy_description(object)` pode ser usada para obter uma representação em string do objeto, que pode ser útil para fins de depuração.\
Esses objetos também têm métodos que podem ser chamados, como `xpc_<object>_copy`, `xpc_<object>_equal`, `xpc_<object>_hash`, `xpc_<object>_serialize`, `xpc_<object>_deserialize`...

Os objetos `xpc_object_t` são criados chamando uma função `xpc_<objectType>_create`, que internamente chama `_xpc_base_create(Class, Size)`, indicando a classe do objeto (uma das `XPC_TYPE_*`) e seu tamanho. São adicionados 40 bytes extras para metadados, portanto os dados do objeto começam no deslocamento de 40 bytes.\
Portanto, `xpc_<objectType>_t` é uma espécie de subclasse de `xpc_object_t`, que, por sua vez, seria uma subclasse de `os_object_t*`.

> [!WARNING]
> Observe que cabe ao desenvolvedor usar `xpc_dictionary_[get/set]_<objectType>` para obter ou definir o tipo e o valor real de uma chave.

- **`xpc_pipe`**

Um **`xpc_pipe`** é um pipe FIFO que os processos podem usar para se comunicar (a comunicação usa mensagens Mach).\
É possível criar um servidor XPC chamando `xpc_pipe_create()` ou `xpc_pipe_create_from_port()` para criá-lo usando uma porta Mach específica. Depois, para receber mensagens, é possível chamar `xpc_pipe_receive` e `xpc_pipe_try_receive`.

Observe que o objeto **`xpc_pipe`** é um **`xpc_object_t`** cuja estrutura contém informações sobre as duas portas Mach usadas e o nome (se houver). Por exemplo, o daemon `secinitd` configura o pipe chamado `com.apple.secinitd` em seu plist `/System/Library/LaunchDaemons/com.apple.secinitd.plist`.

Um exemplo de **`xpc_pipe`** é o **pipe bootstrap** criado pelo **`launchd`**, que permite compartilhar portas Mach.

- **`NSXPC*`**

São objetos Objective-C de alto nível que abstraem conexões XPC.\
Além disso, esses objetos são mais fáceis de depurar com DTrace do que os anteriores.

- **`GCD Queues`**

O XPC usa GCD para passar mensagens e também gera determinadas filas de dispatch, como `xpc.transactionq`, `xpc.io`, `xpc-events.add-listenerq`, `xpc.service-instance`...

## Serviços XPC

São **bundles com a extensão `.xpc`** localizados dentro da pasta **`XPCServices`** de outros projetos; em seu `Info.plist`, eles têm `CFBundlePackageType` definido como **`XPC!`**.\
Esse arquivo contém outras chaves de configuração, como `ServiceType`, que pode ser Application, User ou System; `_SandboxProfile`, que pode definir um sandbox; e `_AllowedClients`, que pode indicar os entitlements ou a identidade necessários para entrar em contato com o serviço. Essas e outras opções configuram o serviço quando ele é iniciado.<sup>[[2]](#references)</sup>

### Iniciando um serviço

O app tenta **se conectar** a um serviço XPC usando `xpc_connection_create_mach_service`; em seguida, o launchd localiza o daemon e inicia **`xpcproxy`**. **`xpcproxy`** aplica as restrições configuradas e inicia o serviço com os descritores de arquivo e as portas Mach fornecidos.<sup>[[3]](#references)</sup>

Para acelerar a busca pelo serviço XPC, é usado um cache.

É possível rastrear as ações de `xpcproxy` usando:

```bash
supraudit S -C -o /tmp/output /dev/auditpipe
```

A biblioteca XPC usa `kdebug` para registrar ações chamando `xpc_ktrace_pid0` e `xpc_ktrace_pid1`. Os códigos que ela usa não são documentados, então precisam ser adicionados a `/usr/share/misc/trace.codes`. Eles têm o prefixo `0x29`; por exemplo, `0x29000004` é `XPC_serializer_pack`.\
O utilitário `xpcproxy` usa o prefixo `0x22`, por exemplo: `0x2200001c: xpcproxy:will_do_preexec`.

## Auditoria de helpers XPC do tipo Application

Um `XPCService.ServiceType` igual a `Application` é um bom ponto de partida para auditar helpers fornecidos pelo framework: enumere os bundles, mantenha os serviços em execução e inspecione o identificador e os entitlements do helper. Pesquise em `/System/Library/Frameworks` e `/System/Library/PrivateFrameworks`; o inventário exato muda entre as versões do macOS.<sup>[[7]](#references)</sup>

```bash
find /System/Library/Frameworks /System/Library/PrivateFrameworks \
  -type d -name '*.xpc' -print0 2>/dev/null |
while IFS= read -r -d '' bundle; do
    plist="$bundle/Contents/Info.plist"
    [ "$(plutil -extract XPCService.ServiceType raw -o - "$plist" 2>/dev/null)" = Application ] || continue

    exe=$(plutil -extract CFBundleExecutable raw -o - "$plist" 2>/dev/null) || continue
    bin="$bundle/Contents/MacOS/$exe"
    ps -axo comm= | awk -v b="$bin" '{sub(/^[[:space:]]+/, ""); if ($0==b) found=1} END {exit !found}' || continue

    printf '\n%s\n  id: %s\n' "$bundle" \
      "$(plutil -extract CFBundleIdentifier raw -o - "$plist" 2>/dev/null)"
    codesign -d --entitlements :- "$bundle" 2>&1
done
```

### Faça a triagem do listener e recupere um protocolo mínimo

Localize `-[<delegate> listener:shouldAcceptNewConnection:]` no helper. Um caminho que define `exportedInterface` e `exportedObject`, retoma a conexão e retorna `YES`/`1` sem verificar o audit token, o code requirement ou o entitlement do peer expõe a interface RPC a qualquer cliente que consiga localizar o serviço. Isso comprova apenas a **alcançabilidade**: o impacto ainda depende de um método exportado que execute uma operação privilegiada sem autorização adequada por cliente/método ou que processe de forma insegura dados controlados pelo atacante.<sup>[[7]](#references)</sup>

Recupere apenas os selectors necessários para os testes. Os metadados dos selectors Objective-C revelam o número de argumentos; o uso dos argumentos no decompilador geralmente ajuda a determinar os tipos (por exemplo, os valores passados a `-[EKEvent setStartDate:]` e `setEndDate:` são `NSDate *`), enquanto a invocação indireta no fim do método revela os parâmetros do reply block. Um protocolo local parcial é suficiente para `NSXPCInterface`; não é necessário reconstruir o protocolo privado completo.<sup>[[7]](#references)</sup>

### Conecte-se com a interface reconstruída

Para um serviço XPC de aplicação, carregue qualquer framework que defina as classes privadas necessárias, crie a conexão com `initWithServiceName:`, atribua a interface remota reconstruída, instale handlers de erro/interrupção/invalidação e só então retome a conexão. Mantenha o run loop ativo para receber respostas assíncronas. Execute novamente o cliente dentro de uma aplicação em sandbox ao testar uma fronteira de sandbox — o sucesso de um cliente independente não comprova um escape de sandbox.<sup>[[7]](#references)</sup>

<details>
<summary>Cliente Objective-C mínimo</summary>

```objectivec
@protocol RecoveredProtocol
- (void)createEventIntentWithStartDate:(NSDate *)start
                               endDate:(NSDate *)end
                             withReply:(void (^)(id object, id error))reply;
@end

[[NSBundle bundleWithPath:@"/System/Library/PrivateFrameworks/AppPredictionFoundation.framework"] load];
NSXPCConnection *c = [[NSXPCConnection alloc]
    initWithServiceName:@"com.apple.proactive.AppPredictionIntentsHelperService"];
c.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:@protocol(RecoveredProtocol)];
c.interruptionHandler = ^{ NSLog(@"interrupted"); };
c.invalidationHandler = ^{ NSLog(@"invalidated"); };
[c resume];
id proxy = [c remoteObjectProxyWithErrorHandler:^(NSError *e) { NSLog(@"%@", e); }];
[proxy createEventIntentWithStartDate:[NSDate date]
                              endDate:[NSDate dateWithTimeIntervalSinceNow:3600]
                            withReply:^(id obj, id err) { NSLog(@"%@ %@", obj, err); }];
[[NSRunLoop currentRunLoop] run];
```

Compile com `clang -fblocks -framework Foundation -o xpc_client xpc_client.m`.<sup>[[7]](#references)</sup>

</details>

### Use falhas de secure-coding como oráculos de tipo

Um erro `NSCocoaErrorDomain`, como o código `4101`, pode ocultar a exceção de serialização útil. Pesquise no log unificado do macOS/Console pelo nome do serviço: a exceção identifica tanto a classe inesperada quanto as classes permitidas para esse argumento do selector. Para uma resposta, amplie a allowlist da interface **do lado do cliente** com `setClasses:forSelector:argumentIndex:ofReply:`; com `ofReply:YES`, o índice `0` significa o primeiro parâmetro do bloco de resposta, não o primeiro parâmetro do método.<sup>[[7]](#references)</sup>

Configure a interface antes de atribuí-la à conexão e chamar `[c resume]`:<sup>[[7]](#references)</sup>

```objectivec
NSXPCInterface *iface = [NSXPCInterface interfaceWithProtocol:@protocol(RecoveredProtocol)];
NSMutableSet *classes = [NSMutableSet setWithArray:@[
    NSDate.class, NSString.class, NSNumber.class,
    NSDictionary.class, NSArray.class, NSData.class
]];
Class intentClass = NSClassFromString(@"INIntent");
if (intentClass) [classes addObject:intentClass];
[iface setClasses:classes
      forSelector:@selector(createEventIntentWithStartDate:endDate:withReply:)
    argumentIndex:0
          ofReply:YES];
c.remoteObjectInterface = iface;
```

O caso inverso também é útil: se o servidor rejeitar uma entrada Foundation e registrar uma única classe privada permitida, o log revela o tipo esperado no fio e seu framework. Carregue esse framework, inspecione os métodos/propriedades da classe para refinar os tipos genéricos `id` e construa o objeto privado dinamicamente. Os argumentos de `NSInvocation` começam no índice `2`, porque os índices `0` e `1` correspondem aos argumentos ocultos `self` e `_cmd`.<sup>[[7]](#references)</sup>

<details>
<summary>Construir um argumento privado com NSInvocation</summary>

```objectivec
Class cls = NSClassFromString(@"LNStaticDeferredLocalizedString");
id allocated = [cls alloc];
SEL initializer = NSSelectorFromString(@"initWithKey:table:bundleURL:");
NSMethodSignature *signature = [allocated methodSignatureForSelector:initializer];
NSInvocation *invocation = [NSInvocation invocationWithMethodSignature:signature];
[invocation setTarget:allocated];
[invocation setSelector:initializer];

NSString *key = @"KEY";
NSString *table = @"Localizable";
NSURL *bundleURL = NSBundle.mainBundle.bundleURL;
[invocation setArgument:&key atIndex:2];
[invocation setArgument:&table atIndex:3];
[invocation setArgument:&bundleURL atIndex:4];
[invocation invoke];

__unsafe_unretained id privateObject = nil;
[invocation getReturnValue:&privateObject];
```

</details>

Para ver o workflow relacionado a serviços Mach registrados pelo launchd e disponíveis em todo o sistema, consulte:

{{#ref}}
../../macos-xpc-mach-services-abuse.md
{{#endref}}

## Mensagens de eventos XPC

Os aplicativos podem **se inscrever** em diferentes **mensagens** de eventos, permitindo que sejam **iniciados sob demanda** quando esses eventos ocorrerem. A **configuração** desses serviços é feita em arquivos plist do **launchd**, localizados nos **mesmos diretórios que os anteriores** e contendo uma chave **`LaunchEvent`** adicional.

### Verificação do processo que se conecta ao XPC

Quando um processo tenta chamar um método por meio de uma conexão XPC, o **serviço XPC deve verificar se esse processo tem permissão para se conectar**. Estes são métodos comuns de verificação e suas armadilhas:


{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

## Autorização XPC

A Apple também permite que os aplicativos **configurem direitos de autorização e como os chamadores os obtêm**, para que um processo com os direitos necessários **tenha permissão para chamar um método** exposto pelo serviço XPC:


{{#ref}}
macos-xpc-authorization.md
{{#endref}}

## XPC Sniffer

Para sniffar mensagens XPC, você pode usar **xpcspy**, que usa **Frida**.<sup>[[5]](#references)</sup>

```bash
# Install
pip3 install xpcspy
pip3 install xpcspy --no-deps # To not make xpcspy install Frida 15 and downgrade your Frida installation

# Start sniffing
xpcspy -U -r -W <bundle-id>
## Using filters (i: for input, o: for output)
xpcspy -U <prog-name> -t 'i:com.apple.*' -t 'o:com.apple.*' -r
```

Outra ferramenta possível é **XPoCe2**.<sup>[[6]](#references)</sup>

## Exemplo de código C de comunicação XPC

{{#tabs}}
{{#tab name="xpc_server.c"}}

```c
// gcc xpc_server.c -o xpc_server

#include <xpc/xpc.h>

static void handle_event(xpc_object_t event) {
    if (xpc_get_type(event) == XPC_TYPE_DICTIONARY) {
        // Print received message
        const char* received_message = xpc_dictionary_get_string(event, "message");
        printf("Received message: %s\n", received_message);

        // Create a response dictionary
        xpc_object_t response = xpc_dictionary_create(NULL, NULL, 0);
        xpc_dictionary_set_string(response, "received", "received");

        // Send response
        xpc_connection_t remote = xpc_dictionary_get_remote_connection(event);
        xpc_connection_send_message(remote, response);

        // Clean up
        xpc_release(response);
    }
}

static void handle_connection(xpc_connection_t connection) {
    xpc_connection_set_event_handler(connection, ^(xpc_object_t event) {
        handle_event(event);
    });
    xpc_connection_resume(connection);
}

int main(int argc, const char *argv[]) {
    xpc_connection_t service = xpc_connection_create_mach_service("xyz.hacktricks.service",
                                                                   dispatch_get_main_queue(),
                                                                   XPC_CONNECTION_MACH_SERVICE_LISTENER);
    if (!service) {
        fprintf(stderr, "Failed to create service.\n");
        exit(EXIT_FAILURE);
    }

    xpc_connection_set_event_handler(service, ^(xpc_object_t event) {
        xpc_type_t type = xpc_get_type(event);
        if (type == XPC_TYPE_CONNECTION) {
            handle_connection(event);
        }
    });

    xpc_connection_resume(service);
    dispatch_main();

    return 0;
}
```

{{#endtab}}

{{#tab name="xpc_client.c"}}

```c
// gcc xpc_client.c -o xpc_client

#include <xpc/xpc.h>

int main(int argc, const char *argv[]) {
    xpc_connection_t connection = xpc_connection_create_mach_service("xyz.hacktricks.service", NULL, XPC_CONNECTION_MACH_SERVICE_PRIVILEGED);

    xpc_connection_set_event_handler(connection, ^(xpc_object_t event) {
        if (xpc_get_type(event) == XPC_TYPE_DICTIONARY) {
            // Print received message
            const char* received_message = xpc_dictionary_get_string(event, "received");
            printf("Received message: %s\n", received_message);
        }
    });

    xpc_connection_resume(connection);

    xpc_object_t message = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_string(message, "message", "Hello, Server!");

    xpc_connection_send_message(connection, message);

    dispatch_main();

    return 0;
}
```

{{#endtab}}

{{#tab name="xyz.hacktricks.service.plist"}}

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
<key>Label</key>
<string>xyz.hacktricks.service</string>
<key>MachServices</key>
    <dict>
        <key>xyz.hacktricks.service</key>
        <true/>
    </dict>
<key>Program</key>
    <string>/tmp/xpc_server</string>
    <key>ProgramArguments</key>
    <array>
        <string>/tmp/xpc_server</string>
    </array>
</dict>
</plist>
```

{{#endtab}}
{{#endtabs}}

```bash
# Compile the server & client
gcc xpc_server.c -o xpc_server
gcc xpc_client.c -o xpc_client

# Save the server in its configured location
cp xpc_server /tmp

# Load daemon
sudo cp xyz.hacktricks.service.plist /Library/LaunchDaemons
sudo launchctl load /Library/LaunchDaemons/xyz.hacktricks.service.plist

# Call client
./xpc_client

# Clean
sudo launchctl unload /Library/LaunchDaemons/xyz.hacktricks.service.plist
sudo rm /Library/LaunchDaemons/xyz.hacktricks.service.plist /tmp/xpc_server
```

## Exemplo de código Objective-C de comunicação XPC

{{#tabs}}
{{#tab name="oc_xpc_server.m"}}

```objectivec
// gcc -framework Foundation oc_xpc_server.m -o oc_xpc_server
#include <Foundation/Foundation.h>

@protocol MyXPCProtocol
- (void)sayHello:(NSString *)some_string withReply:(void (^)(NSString *))reply;
@end

@interface MyXPCObject : NSObject <MyXPCProtocol>
@end


@implementation MyXPCObject
- (void)sayHello:(NSString *)some_string withReply:(void (^)(NSString *))reply {
    NSLog(@"Received message: %@", some_string);
    NSString *response = @"Received";
    reply(response);
}
@end

@interface MyDelegate : NSObject <NSXPCListenerDelegate>
@end


@implementation MyDelegate

- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
    newConnection.exportedInterface = [NSXPCInterface interfaceWithProtocol:@protocol(MyXPCProtocol)];

    MyXPCObject *my_object = [MyXPCObject new];

    newConnection.exportedObject = my_object;

    [newConnection resume];
    return YES;
}
@end

int main(void) {

    NSXPCListener *listener = [[NSXPCListener alloc] initWithMachServiceName:@"xyz.hacktricks.svcoc"];

    id <NSXPCListenerDelegate> delegate = [MyDelegate new];
    listener.delegate = delegate;
    [listener resume];

    sleep(10); // Fake something is done and then it ends
}
```

{{#endtab}}

{{#tab name="oc_xpc_client.m"}}

```objectivec
// gcc -framework Foundation oc_xpc_client.m -o oc_xpc_client
#include <Foundation/Foundation.h>

@protocol MyXPCProtocol
- (void)sayHello:(NSString *)some_string withReply:(void (^)(NSString *))reply;
@end

int main(void) {
    NSXPCConnection *connection = [[NSXPCConnection alloc] initWithMachServiceName:@"xyz.hacktricks.svcoc" options:NSXPCConnectionPrivileged];
    connection.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:@protocol(MyXPCProtocol)];
    [connection resume];

    [[connection remoteObjectProxy] sayHello:@"Hello, Server!" withReply:^(NSString *response) {
        NSLog(@"Received response: %@", response);
    }];

    [[NSRunLoop currentRunLoop] run];

    return 0;
}
```

{{#endtab}}

{{#tab name="xyz.hacktricks.svcoc.plist"}}

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
<key>Label</key>
<string>xyz.hacktricks.svcoc</string>
<key>MachServices</key>
    <dict>
        <key>xyz.hacktricks.svcoc</key>
        <true/>
    </dict>
<key>Program</key>
    <string>/tmp/oc_xpc_server</string>
    <key>ProgramArguments</key>
    <array>
        <string>/tmp/oc_xpc_server</string>
    </array>
</dict>
</plist>
```

{{#endtab}}
{{#endtabs}}

```bash
# Compile the server & client
gcc -framework Foundation oc_xpc_server.m -o oc_xpc_server
gcc -framework Foundation oc_xpc_client.m -o oc_xpc_client

# Save server on it's location
cp oc_xpc_server /tmp

# Load daemon
sudo cp xyz.hacktricks.svcoc.plist /Library/LaunchDaemons
sudo launchctl load /Library/LaunchDaemons/xyz.hacktricks.svcoc.plist

# Call client
./oc_xpc_client

# Clean
sudo launchctl unload /Library/LaunchDaemons/xyz.hacktricks.svcoc.plist
sudo rm /Library/LaunchDaemons/xyz.hacktricks.svcoc.plist /tmp/oc_xpc_server
```

## Cliente dentro de uma Dylib

```objectivec
// gcc -dynamiclib -framework Foundation oc_xpc_client.m -o oc_xpc_client.dylib
// gcc injection example:
// DYLD_INSERT_LIBRARIES=oc_xpc_client.dylib /path/to/vuln/bin

#import <Foundation/Foundation.h>

@protocol MyXPCProtocol
- (void)sayHello:(NSString *)some_string withReply:(void (^)(NSString *))reply;
@end

__attribute__((constructor))
static void customConstructor(int argc, const char **argv)
{
        NSString*  _serviceName = @"xyz.hacktricks.svcoc";

        NSXPCConnection* _agentConnection = [[NSXPCConnection alloc] initWithMachServiceName:_serviceName options:4096];

        [_agentConnection setRemoteObjectInterface:[NSXPCInterface interfaceWithProtocol:@protocol(MyXPCProtocol)]];

        [_agentConnection resume];

        [[_agentConnection remoteObjectProxyWithErrorHandler:^(NSError* error) {
            (void)error;
            NSLog(@"Connection Failure");
        }] sayHello:@"Hello, Server!" withReply:^(NSString *response) {
            NSLog(@"Received response: %@", response);
    }    ];
        NSLog(@"Done!");

    return;
}
```

## Remote XPC

A funcionalidade fornecida por `RemoteXPC.framework` (de `libxpc`) permite a comunicação XPC entre hosts diferentes.\
Os serviços que oferecem suporte a Remote XPC têm a chave `UsesRemoteXPC` em seu plist, como é o caso de `/System/Library/LaunchDaemons/com.apple.SubmitDiagInfo.plist`. Embora o serviço esteja registrado no `launchd`, `UserEventAgent` e seus plugins `com.apple.remoted.plugin` e `com.apple.remoteservicediscovery.events.plugin` fornecem essa funcionalidade.

Além disso, `RemoteServiceDiscovery.framework` obtém informações de `com.apple.remoted.plugin`, expondo funções como `get_device`, `get_unique_device` e `connect`.

Depois que `connect` retorna o descritor de arquivo de socket do serviço, é possível usar a classe `remote_xpc_connection_*`.

É possível obter informações sobre serviços remotos com a CLI `/usr/libexec/remotectl`, usando comandos como:

```bash
/usr/libexec/remotectl list # Get bridge devices
/usr/libexec/remotectl show ...# Get device properties and services
/usr/libexec/remotectl dumpstate # Like dump without indicating a service
/usr/libexec/remotectl [netcat|relay] ... # Expose a service in a port
...
```

A comunicação entre bridgeOS e o host ocorre por meio de uma interface IPv6 dedicada. `MultiverseSupport.framework` estabelece sockets cujos descritores de arquivo são usados para a comunicação.\
É possível encontrar essas comunicações usando `netstat`, `nettop` ou a alternativa open source `netbottom`.

## References

- [1] [Apple Developer — XPC](https://developer.apple.com/documentation/xpc)
- [2] [Arquivo do Apple Developer — Criando serviços XPC](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingXPCServices.html)
- [3] [Apple Developer — `xpc_connection_create_mach_service`](https://developer.apple.com/documentation/xpc/xpc_connection_create_mach_service(_:_:_:))
- [4] [Apple Developer — `JoinExistingSession`](https://developer.apple.com/documentation/bundleresources/information_property_list/xpcservice/joinexistingsession)
- [5] [hot3eed/xpcspy](https://github.com/hot3eed/xpcspy)
- [6] [NewOSXBook — XPoCe2](https://newosxbook.com/tools/XPoCe2.html)
- [7] [Reverse Society — Atacando XPC Helpers do macOS: engenharia reversa de protocolos](https://blog.reversesociety.co/blog/2025/how-to-attack-macos-application-xpc-helpers)
{{#include ../../../../../banners/hacktricks-training.md}}
