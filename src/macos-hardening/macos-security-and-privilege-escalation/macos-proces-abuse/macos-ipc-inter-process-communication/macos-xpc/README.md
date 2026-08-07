# XPC do macOS

{{#include ../../../../../banners/hacktricks-training.md}}

## Informações básicas

XPC, que significa comunicação entre processos do XNU (o kernel usado pelo macOS), é um framework para **comunicação entre processos** no macOS e iOS. O XPC fornece um mecanismo para fazer **chamadas de métodos seguras e assíncronas entre diferentes processos** no sistema. Ele faz parte do paradigma de segurança da Apple, permitindo a **criação de aplicações com privilégios separados**, nas quais cada **componente** é executado com **apenas as permissões necessárias** para realizar seu trabalho, limitando assim os possíveis danos causados por um processo comprometido.

O XPC usa uma forma de Inter-Process Communication (IPC), que é um conjunto de métodos para que diferentes programas em execução no mesmo sistema enviem dados entre si.

Os principais benefícios do XPC incluem:

1. **Segurança**: ao separar o trabalho em diferentes processos, cada processo pode receber apenas as permissões necessárias. Isso significa que, mesmo que um processo seja comprometido, sua capacidade de causar danos é limitada.
2. **Estabilidade**: o XPC ajuda a isolar crashes no componente onde ocorrem. Se um processo sofrer um crash, ele poderá ser reiniciado sem afetar o restante do sistema.
3. **Desempenho**: o XPC permite concorrência de forma simples, pois diferentes tarefas podem ser executadas simultaneamente em diferentes processos.

A única **desvantagem** é que **separar uma aplicação em vários processos** e fazê-los se comunicar via XPC é **menos eficiente**. Porém, nos sistemas atuais, isso quase não é perceptível, e os benefícios são maiores.

## Serviços XPC específicos da aplicação

Os componentes XPC de uma aplicação ficam **dentro da própria aplicação**. Por exemplo, no Safari, você pode encontrá-los em **`/Applications/Safari.app/Contents/XPCServices`**. Eles têm a extensão **`.xpc`** (como **`com.apple.Safari.SandboxBroker.xpc`**) e também são **bundles** com o binário principal dentro deles: `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker` e um `Info.plist: /Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`

Como você pode estar imaginando, um **componente XPC terá entitlements e privilégios diferentes** dos outros componentes XPC ou do binário principal da aplicação. EXCETO se um serviço XPC estiver configurado com [**JoinExistingSession**](https://developer.apple.com/documentation/bundleresources/information_property_list/xpcservice/joinexistingsession) definido como “True” em seu arquivo **Info.plist**. Nesse caso, o serviço XPC será executado na **mesma sessão de segurança que a aplicação** que o chamou.

Os serviços XPC são **iniciados** pelo **launchd** quando necessário e **encerrados** assim que todas as tarefas são **concluídas**, para liberar recursos do sistema. **Os componentes XPC específicos da aplicação só podem ser utilizados pela própria aplicação**, reduzindo assim o risco associado a possíveis vulnerabilidades.

## Serviços XPC em todo o sistema

Os serviços XPC em todo o sistema são acessíveis a todos os usuários. Esses serviços, sejam do tipo launchd ou Mach, precisam ser **definidos em** arquivos **plist** localizados em diretórios específicos, como **`/System/Library/LaunchDaemons`**, **`/Library/LaunchDaemons`**, **`/System/Library/LaunchAgents`** ou **`/Library/LaunchAgents`**.

Esses arquivos plist terão uma chave chamada **`MachServices`** com o nome do serviço e uma chave chamada **`Program`** com o caminho para o binário:
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
Os que estão em **`LaunchDameons`** são executados pelo root. Portanto, se um processo sem privilégios puder se comunicar com um deles, poderá conseguir escalar privilégios.

## Objetos XPC

- **`xpc_object_t`**

Cada mensagem XPC é um objeto dicionário que simplifica a serialização e desserialização. Além disso, `libxpc.dylib` declara a maioria dos tipos de dados, portanto é possível garantir que os dados recebidos sejam do tipo esperado. Na API C, cada objeto é um `xpc_object_t` (e seu tipo pode ser verificado usando `xpc_get_type(object)`).\
Além disso, a função `xpc_copy_description(object)` pode ser usada para obter uma representação em string do objeto, o que pode ser útil para fins de debugging.\
Esses objetos também possuem alguns métodos que podem ser chamados, como `xpc_<object>_copy`, `xpc_<object>_equal`, `xpc_<object>_hash`, `xpc_<object>_serialize`, `xpc_<object>_deserialize`...

Os `xpc_object_t` são criados chamando a função `xpc_<objetType>_create`, que internamente chama `_xpc_base_create(Class, Size)`, onde são indicados o tipo da classe do objeto (um dos tipos `XPC_TYPE_*`) e seu tamanho (serão adicionados 40B extras ao tamanho para metadados). Isso significa que os dados do objeto começarão no offset 40B.\
Portanto, o `xpc_<objectType>_t` é uma espécie de subclasse do `xpc_object_t`, que seria uma subclasse de `os_object_t*`.

> [!WARNING]
> Observe que deve ser o developer quem usa `xpc_dictionary_[get/set]_<objectType>` para obter ou definir o tipo e o valor real de uma chave.

- **`xpc_pipe`**

Um **`xpc_pipe`** é um pipe FIFO que os processos podem usar para se comunicar (a comunicação usa mensagens Mach).\
É possível criar um servidor XPC chamando `xpc_pipe_create()` ou `xpc_pipe_create_from_port()` para criá-lo usando uma porta Mach específica. Então, para receber mensagens, é possível chamar `xpc_pipe_receive` e `xpc_pipe_try_receive`.

Observe que o objeto **`xpc_pipe`** é um **`xpc_object_t`** com informações, em sua struct, sobre as duas portas Mach usadas e o nome (se houver). O nome, por exemplo, é configurado pelo daemon `secinitd` em seu plist `/System/Library/LaunchDaemons/com.apple.secinitd.plist`, que configura o pipe chamado `com.apple.secinitd`.

Um exemplo de **`xpc_pipe`** é o **bootstrap pipe** criado pelo **`launchd`**, possibilitando o compartilhamento de portas Mach.

- **`NSXPC*`**

São objetos Objective-C de alto nível que permitem a abstração de conexões XPC.\
Além disso, é mais fácil fazer debugging desses objetos com DTrace do que dos anteriores.

- **`GCD Queues`**

O XPC usa GCD para passar mensagens; além disso, gera determinadas dispatch queues, como `xpc.transactionq`, `xpc.io`, `xpc-events.add-listenerq`, `xpc.service-instance`...

## Serviços XPC

São **bundles com a extensão `.xpc`** localizados dentro da pasta **`XPCServices`** de outros projetos e, no `Info.plist`, têm `CFBundlePackageType` definido como **`XPC!`**.\
Esse arquivo possui outras chaves de configuração, como `ServiceType`, que pode ser Application, User ou System, ou `_SandboxProfile`, que pode definir um sandbox, ou `_AllowedClients`, que pode indicar entitlements ou o ID necessário para entrar em contato com o serviço. Essas e outras opções de configuração serão úteis para configurar o serviço quando ele for iniciado.

### Iniciando um Serviço

O app tenta **se conectar** a um serviço XPC usando `xpc_connection_create_mach_service`; então, o launchd localiza o daemon e inicia o **`xpcproxy`**. O **`xpcproxy`** aplica as restrições configuradas e inicia o serviço com os FDs e as portas Mach fornecidos.

Para melhorar a velocidade da busca pelo serviço XPC, um cache é usado.

É possível rastrear as ações do `xpcproxy` usando:
```bash
supraudit S -C -o /tmp/output /dev/auditpipe
```
A biblioteca XPC usa `kdebug` para registrar ações chamando `xpc_ktrace_pid0` e `xpc_ktrace_pid1`. Os códigos que ela usa não são documentados, portanto é necessário adicioná-los a `/usr/share/misc/trace.codes`. Eles têm o prefixo `0x29` e, por exemplo, um deles é `0x29000004`: `XPC_serializer_pack`.\
O utilitário `xpcproxy` usa o prefixo `0x22`, por exemplo: `0x2200001c: xpcproxy:will_do_preexec`.

## Mensagens de eventos XPC

Os aplicativos podem **assinar** diferentes **mensagens** de eventos, permitindo que sejam **iniciados sob demanda** quando esses eventos ocorrerem. A **configuração** desses serviços é feita em **arquivos plist do launchd**, localizados nos **mesmos diretórios que os anteriores** e contendo uma chave **`LaunchEvent`** adicional.

### Verificação do processo de conexão XPC

Quando um processo tenta chamar um método por meio de uma conexão XPC, o **serviço XPC deve verificar se esse processo tem permissão para se conectar**. Estas são as formas mais comuns de fazer essa verificação e as armadilhas mais comuns:


{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

## Autorização XPC

A Apple também permite que os aplicativos **configurem alguns direitos e como obtê-los**; assim, se o processo chamador os tiver, ele será **autorizado a chamar um método** do serviço XPC:


{{#ref}}
macos-xpc-authorization.md
{{#endref}}

## Sniffer XPC

Para capturar as mensagens XPC, você pode usar o [**xpcspy**](https://github.com/hot3eed/xpcspy), que utiliza **Frida**.
```bash
# Install
pip3 install xpcspy
pip3 install xpcspy --no-deps # To not make xpcspy install Frida 15 and downgrade your Frida installation

# Start sniffing
xpcspy -U -r -W <bundle-id>
## Using filters (i: for input, o: for output)
xpcspy -U <prog-name> -t 'i:com.apple.*' -t 'o:com.apple.*' -r
```
Outra ferramenta possível de usar é o [**XPoCe2**](https://newosxbook.com/tools/XPoCe2.html).

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

# Save server on it's location
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
## Exemplo de Código Objective-C de Comunicação XPC

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
## Cliente dentro de um código Dylb
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

Esta funcionalidade fornecida pelo `RemoteXPC.framework` (de `libxpc`) permite comunicar via XPC entre diferentes hosts.\
Os serviços que suportam Remote XPC terão a chave `UsesRemoteXPC` em seu plist, como ocorre em `/System/Library/LaunchDaemons/com.apple.SubmitDiagInfo.plist`. No entanto, embora o serviço seja registrado com o `launchd`, é o `UserEventAgent`, com os plugins `com.apple.remoted.plugin` e `com.apple.remoteservicediscovery.events.plugin`, que fornece a funcionalidade.

Além disso, o `RemoteServiceDiscovery.framework` permite obter informações do `com.apple.remoted.plugin`, expondo funções como `get_device`, `get_unique_device`, `connect`...

Depois que `connect` é usado e o socket `fd` do serviço é obtido, é possível usar a classe `remote_xpc_connection_*`.

É possível obter informações sobre serviços remotos usando a ferramenta CLI `/usr/libexec/remotectl` com parâmetros como:
```bash
/usr/libexec/remotectl list # Get bridge devices
/usr/libexec/remotectl show ...# Get device properties and services
/usr/libexec/remotectl dumpstate # Like dump withuot indicateing a servie
/usr/libexec/remotectl [netcat|relay] ... # Expose a service in a port
...
```
A comunicação entre o BridgeOS e o host ocorre por meio de uma interface IPv6 dedicada. O `MultiverseSupport.framework` permite estabelecer sockets cujo `fd` será usado para a comunicação.\
É possível encontrar essas comunicações usando `netstat`, `nettop` ou a opção open source, `netbottom`.

{{#include ../../../../../banners/hacktricks-training.md}}
