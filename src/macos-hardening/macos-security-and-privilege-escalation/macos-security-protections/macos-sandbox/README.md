# macOS Sandbox

{{#include ../../../../banners/hacktricks-training.md}}

## Informações básicas

O MacOS Sandbox (inicialmente chamado Seatbelt) **limita os aplicativos** executados dentro do sandbox às **ações permitidas especificadas no perfil do Sandbox** com o qual o app está sendo executado. Isso ajuda a garantir que **o aplicativo acessará apenas os recursos esperados**.

Qualquer app com o **entitlement** **`com.apple.security.app-sandbox`** será executado dentro do sandbox. **Binários da Apple** geralmente são executados dentro de um Sandbox, e todos os aplicativos da **App Store têm esse entitlement**. Portanto, vários aplicativos serão executados dentro do sandbox.<sup>[[4]](#references)</sup>

Para controlar o que um processo pode ou não fazer, o **Sandbox possui hooks** em praticamente qualquer operação que um processo possa tentar (incluindo a maioria dos syscalls), usando **MACF**. No entanto, d**ependendo** dos **entitlements** do app, o Sandbox pode ser mais permissivo com o processo.

Alguns componentes importantes do Sandbox são:

- A **kernel extension** `/System/Library/Extensions/Sandbox.kext`
- O **private framework** `/System/Library/PrivateFrameworks/AppSandbox.framework`
- Um **daemon** executado em userland `/usr/libexec/sandboxd`
- Os **containers** `~/Library/Containers`

### Containers

Cada aplicativo em sandbox terá seu próprio container em `~/Library/Containers/{CFBundleIdentifier}` :
```bash
ls -l ~/Library/Containers
total 0
drwx------@ 4 username  staff  128 May 23 20:20 com.apple.AMPArtworkAgent
drwx------@ 4 username  staff  128 May 23 20:13 com.apple.AMPDeviceDiscoveryAgent
drwx------@ 4 username  staff  128 Mar 24 18:03 com.apple.AVConference.Diagnostic
drwx------@ 4 username  staff  128 Mar 25 14:14 com.apple.Accessibility-Settings.extension
drwx------@ 4 username  staff  128 Mar 25 14:10 com.apple.ActionKit.BundledIntentHandler
[...]
```
Dentro de cada pasta de bundle id, você pode encontrar o **plist** e o diretório **Data** do App com uma estrutura que imita a pasta Home:
```bash
cd /Users/username/Library/Containers/com.apple.Safari
ls -la
total 104
drwx------@   4 username  staff    128 Mar 24 18:08 .
drwx------  348 username  staff  11136 May 23 20:57 ..
-rw-r--r--    1 username  staff  50214 Mar 24 18:08 .com.apple.containermanagerd.metadata.plist
drwx------   13 username  staff    416 Mar 24 18:05 Data

ls -l Data
total 0
drwxr-xr-x@  8 username  staff   256 Mar 24 18:08 CloudKit
lrwxr-xr-x   1 username  staff    19 Mar 24 18:02 Desktop -> ../../../../Desktop
drwx------   2 username  staff    64 Mar 24 18:02 Documents
lrwxr-xr-x   1 username  staff    21 Mar 24 18:02 Downloads -> ../../../../Downloads
drwx------  35 username  staff  1120 Mar 24 18:08 Library
lrwxr-xr-x   1 username  staff    18 Mar 24 18:02 Movies -> ../../../../Movies
lrwxr-xr-x   1 username  staff    17 Mar 24 18:02 Music -> ../../../../Music
lrwxr-xr-x   1 username  staff    20 Mar 24 18:02 Pictures -> ../../../../Pictures
drwx------   2 username  staff    64 Mar 24 18:02 SystemData
drwx------   2 username  staff    64 Mar 24 18:02 tmp
```
> [!CAUTION]
> Observe que, mesmo que os symlinks estejam presentes para "escapar" do Sandbox e acessar outras pastas, o App ainda precisa **ter permissões** para acessá-las. Essas permissões estão dentro do **`.plist`**, em `RedirectablePaths`.

O **`SandboxProfileData`** é o CFData do perfil compilado do Sandbox convertido para B64.
```bash
# Get container config
## You need FDA to access the file, not even just root can read it
plutil -convert xml1 .com.apple.containermanagerd.metadata.plist -o -

# Binary sandbox profile
<key>SandboxProfileData</key>
<data>
AAAhAboBAAAAAAgAAABZAO4B5AHjBMkEQAUPBSsGPwsgASABHgEgASABHwEf...

# In this file you can find the entitlements:
<key>Entitlements</key>
<dict>
<key>com.apple.MobileAsset.PhishingImageClassifier2</key>
<true/>
<key>com.apple.accounts.appleaccount.fullaccess</key>
<true/>
<key>com.apple.appattest.spi</key>
<true/>
<key>keychain-access-groups</key>
<array>
<string>6N38VWS5BX.ru.keepcoder.Telegram</string>
<string>6N38VWS5BX.ru.keepcoder.TelegramShare</string>
</array>
[...]

# Some parameters
<key>Parameters</key>
<dict>
<key>_HOME</key>
<string>/Users/username</string>
<key>_UID</key>
<string>501</string>
<key>_USER</key>
<string>username</string>
[...]

# The paths it can access
<key>RedirectablePaths</key>
<array>
<string>/Users/username/Downloads</string>
<string>/Users/username/Documents</string>
<string>/Users/username/Library/Calendars</string>
<string>/Users/username/Desktop</string>
<key>RedirectedPaths</key>
<array/>
[...]
```
> [!WARNING]
> Tudo o que for criado/modificado por um aplicativo em Sandbox receberá o **atributo de quarentena**. Isso impedirá um espaço de Sandbox ao acionar o Gatekeeper caso o aplicativo em Sandbox tente executar algo com **`open`**.

## Perfis de Sandbox

Os perfis de Sandbox são arquivos de configuração que indicam o que será **permitido/proibido** nesse **Sandbox**. Ele usa a **Sandbox Profile Language (SBPL)**, que utiliza a linguagem de programação [**Scheme**](<https://en.wikipedia.org/wiki/Scheme_(programming_language)>).

Aqui você pode encontrar um exemplo:
```scheme
(version 1) ; First you get the version

(deny default) ; Then you should indicate the default action when no rule applies

(allow network*) ; You can use wildcards and allow everything

(allow file-read* ; You can specify where to apply the rule
(subpath "/Users/username/")
(literal "/tmp/afile")
(regex #"^/private/etc/.*")
)

(allow mach-lookup
(global-name "com.apple.analyticsd")
)
```
> [!TIP]
> Confira esta [**pesquisa**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/) **para verificar mais ações que podem ser permitidas ou negadas.**<sup>[[5]](#references)</sup>
>
> Observe que, na versão compilada de um profile, os nomes das operações são substituídos por suas entradas em um array conhecido pela dylib e pelo kext, tornando a versão compilada menor e mais difícil de ler.

Serviços importantes do **sistema** também são executados dentro de seu próprio **sandbox** personalizado, como o serviço `mdnsresponder`. Você pode visualizar esses **sandbox profiles** personalizados em:

- **`/usr/share/sandbox`**
- **`/System/Library/Sandbox/Profiles`**
- Outros sandbox profiles podem ser consultados em [https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles).
- No iOS, o platform profile está dentro do `.kext` do sandbox, em `_platform_profile_data`, dentro do binário.

Os aplicativos da **App Store** usam o **profile** **`/System/Library/Sandbox/Profiles/application.sb`**. Você pode verificar nesse profile como entitlements, como **`com.apple.security.network.server`**, permitem que um processo use a rede.

Em seguida, alguns serviços daemon da **Apple** usam profiles diferentes, localizados em `/System/Library/Sandbox/Profiles/*.sb` ou `/usr/share/sandbox/*.sb`. Esses sandboxes são aplicados na função principal que chama a API `sandbox_init_XXX`.<sup>[[3]](#references)</sup>

**SIP** é um Sandbox profile chamado platform_profile em `/System/Library/Sandbox/rootless.conf`.

### Exemplos de Sandbox Profiles

Para iniciar um aplicativo com um **sandbox profile** específico, você pode usar:
```bash
sandbox-exec -f example.sb /Path/To/The/Application
sandbox-exec -n no-internet ping 8.8.8.8
```
{{#tabs}}
{{#tab name="touch"}}
```scheme:touch.sb
(version 1)
(deny default)
(allow file* (literal "/tmp/hacktricks.txt"))
```

```bash
# This will fail because default is denied, so it cannot execute touch
sandbox-exec -f touch.sb touch /tmp/hacktricks.txt
# Check logs
log show --style syslog --predicate 'eventMessage contains[c] "sandbox"' --last 30s
[...]
2023-05-26 13:42:44.136082+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) process-exec* /usr/bin/touch
2023-05-26 13:42:44.136100+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /usr/bin/touch
2023-05-26 13:42:44.136321+0200  localhost kernel[0]: (Sandbox) Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /var
2023-05-26 13:42:52.701382+0200  localhost kernel[0]: (Sandbox) 5 duplicate reports for Sandbox: sandbox-exec(41398) deny(1) file-read-metadata /var
[...]
```

```scheme:touch2.sb
(version 1)
(deny default)
(allow file* (literal "/tmp/hacktricks.txt"))
(allow process* (literal "/usr/bin/touch"))
; This will also fail because:
; 2023-05-26 13:44:59.840002+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-metadata /usr/bin/touch
; 2023-05-26 13:44:59.840016+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /usr/bin/touch
; 2023-05-26 13:44:59.840028+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /usr/bin
; 2023-05-26 13:44:59.840034+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-metadata /usr/lib/dyld
; 2023-05-26 13:44:59.840050+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) sysctl-read kern.bootargs
; 2023-05-26 13:44:59.840061+0200  localhost kernel[0]: (Sandbox) Sandbox: touch(41575) deny(1) file-read-data /
```

```scheme:touch3.sb
(version 1)
(deny default)
(allow file* (literal "/private/tmp/hacktricks.txt"))
(allow process* (literal "/usr/bin/touch"))
(allow file-read-data (literal "/"))
; This one will work
```
{{#endtab}}
{{#endtabs}}

> [!TIP]
> Observe que o **software** **desenvolvido pela Apple** que é executado no **Windows** **não possui precauções de segurança adicionais**, como application sandboxing.

Exemplos de bypasses:

- [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)<sup>[[6]](#references)</sup>
- [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) (eles conseguem escrever arquivos fora do sandbox cujo nome começa com `~$`).<sup>[[7]](#references)</sup>

### Rastreamento do Sandbox

#### Via perfil

É possível rastrear todas as verificações que o sandbox realiza sempre que uma ação é verificada. Para isso, basta criar o seguinte perfil:
```scheme:trace.sb
(version 1)
(trace /tmp/trace.out)
```
E então basta executar algo usando esse perfil:
```bash
sandbox-exec -f /tmp/trace.sb /bin/ls
```
Em `/tmp/trace.out`, será possível ver cada verificação do sandbox executada todas as vezes em que foi chamada (portanto, haverá muitas duplicatas).

Também é possível rastrear o sandbox usando o parâmetro **`-t`**: `sandbox-exec -t /path/trace.out -p "(version 1)" /bin/ls`

#### Via API

A função `sandbox_set_trace_path`, exportada por `libsystem_sandbox.dylib`, permite especificar um nome de arquivo de trace onde as verificações do sandbox serão gravadas.\
Também é possível fazer algo semelhante chamando `sandbox_vtrace_enable()` e obtendo os erros dos logs a partir do buffer, chamando `sandbox_vtrace_report()`.

### Inspeção do Sandbox

`libsandbox.dylib` exporta uma função chamada sandbox_inspect_pid, que fornece uma lista do estado do sandbox de um processo (incluindo extensions). No entanto, apenas binários de plataforma podem usar essa função.

### Perfis de Sandbox do MacOS e iOS

O MacOS armazena os perfis de sandbox do sistema em dois locais: **/usr/share/sandbox/** e **/System/Library/Sandbox/Profiles**.

E, se um aplicativo de terceiros tiver o entitlement _**com.apple.security.app-sandbox**_, o sistema aplicará o perfil **/System/Library/Sandbox/Profiles/application.sb** a esse processo.

No iOS, o perfil padrão é chamado **container**, e não temos a representação textual SBPL. Na memória, esse sandbox é representado como uma árvore binária Allow/Deny para cada permissão do sandbox.

### SBPL personalizado em aplicativos da App Store

Seria possível que empresas fizessem seus aplicativos serem executados **com perfis de Sandbox personalizados** (em vez de usarem o padrão). Elas precisam usar o entitlement **`com.apple.security.temporary-exception.sbpl`**, que precisa ser autorizado pela Apple.

É possível verificar a definição desse entitlement em **`/System/Library/Sandbox/Profiles/application.sb:`**
```scheme
(sandbox-array-entitlement
"com.apple.security.temporary-exception.sbpl"
(lambda (string)
(let* ((port (open-input-string string)) (sbpl (read port)))
(with-transparent-redirection (eval sbpl)))))
```
Isso fará **eval da string após este entitlement** como um perfil de Sandbox.

### Compilando e descompilando um Sandbox Profile

A ferramenta **`sandbox-exec`** usa as funções `sandbox_compile_*` de `libsandbox.dylib`. As principais funções exportadas são: `sandbox_compile_file` (espera um caminho de arquivo, parâmetro `-f`), `sandbox_compile_string` (espera uma string, parâmetro `-p`), `sandbox_compile_name` (espera o nome de um container, parâmetro `-n`), `sandbox_compile_entitlements` (espera um plist de entitlements).

Esta versão reversa e [**open source da ferramenta sandbox-exec**](https://newosxbook.com/src.jl?tree=listings&file=/sandbox_exec.c) permite fazer com que o **`sandbox-exec`** grave o perfil de Sandbox compilado em um arquivo.

Além disso, para confinar um processo dentro de um container, ele pode chamar `sandbox_spawnattrs_set[container/profilename]` e passar um container ou um perfil preexistente.

## Debug e Bypass do Sandbox

No macOS, ao contrário do iOS, onde os processos são colocados em Sandbox desde o início pelo kernel, **os processos precisam optar pelo Sandbox por conta própria**. Isso significa que, no macOS, um processo não é restringido pelo Sandbox até decidir ativamente entrar nele, embora os apps da App Store estejam sempre em Sandbox.

Os processos são automaticamente colocados em Sandbox a partir do userland quando iniciam se tiverem o entitlement: `com.apple.security.app-sandbox`. Para uma explicação detalhada desse processo, consulte:


{{#ref}}
macos-sandbox-debug-and-bypass/
{{#endref}}

## **Sandbox Extensions**

As extensions permitem conceder privilégios adicionais a um objeto e são concedidas ao chamar uma das funções:

- `sandbox_issue_extension`
- `sandbox_extension_issue_file[_with_new_type]`
- `sandbox_extension_issue_mach`
- `sandbox_extension_issue_iokit_user_client_class`
- `sandbox_extension_issue_iokit_registry_rentry_class`
- `sandbox_extension_issue_generic`
- `sandbox_extension_issue_posix_ipc`

As extensions são armazenadas no segundo slot de label do MACF, acessível a partir das credenciais do processo. O seguinte **`sbtool`** pode acessar essas informações.

Observe que as extensions geralmente são concedidas por processos autorizados; por exemplo, `tccd` concederá o token de extension de `com.apple.tcc.kTCCServicePhotos` quando um processo tentar acessar as fotos e for autorizado em uma mensagem XPC. Em seguida, o processo precisará consumir o token de extension para que ele seja adicionado a ele.\
Observe que os tokens de extension são hexadecimais longos que codificam as permissões concedidas. No entanto, eles não têm o PID autorizado codificado, o que significa que qualquer processo com acesso ao token pode ser **consumido por vários processos**.

Observe que as extensions também estão muito relacionadas aos entitlements; portanto, ter determinados entitlements pode conceder automaticamente determinadas extensions.

### **Verificar Privilégios do PID**

[**De acordo com isto**](https://www.youtube.com/watch?v=mG715HcDgO8&t=3011s), as funções **`sandbox_check`** (é uma `__mac_syscall`) podem verificar **se uma operação é permitida ou não** pelo Sandbox em um determinado PID, audit token ou ID exclusivo.<sup>[[8]](#references)</sup>

A [**ferramenta sbtool**](http://newosxbook.com/src.jl?tree=listings&file=sbtool.c) (encontre-a [compilada aqui](https://newosxbook.com/articles/hitsb.html)) pode verificar se um PID pode executar determinadas ações:
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explanation of the sandbox profile and extensions
sbtool <pid> all
```
### \[un]suspend

Também é possível suspender e reativar o sandbox usando as funções `sandbox_suspend` e `sandbox_unsuspend` de `libsystem_sandbox.dylib`.

Observe que, para chamar a função de suspensão, alguns entitlements são verificados para autorizar o chamador a fazê-lo, como:

- com.apple.private.security.sandbox-manager
- com.apple.security.print
- com.apple.security.temporary-exception.audio-unit-host

## mac_syscall

Essa chamada de sistema (#381) espera primeiro um argumento string que indicará o módulo a ser executado e, em seguida, um código no segundo argumento que indicará a função a ser executada. O terceiro argumento dependerá da função executada.<sup>[[2]](#references)</sup>

A função `___sandbox_ms` encapsula a chamada de `mac_syscall`, indicando `"Sandbox"` no primeiro argumento, assim como `___sandbox_msp` é um wrapper de `mac_set_proc` (#387). Então, alguns dos códigos suportados por `___sandbox_ms` podem ser encontrados nesta tabela:

- **set_profile (#0)**: Aplica um profile compilado ou nomeado a um processo.
- **platform_policy (#1)**: Impõe verificações de policy específicas da plataforma (varia entre macOS e iOS).
- **check_sandbox (#2)**: Realiza uma verificação manual de uma operação específica do sandbox.
- **note (#3)**: Adiciona uma anotação a um Sandbox.
- **container (#4)**: Anexa uma anotação a um sandbox, normalmente para debugging ou identificação.
- **extension_issue (#5)**: Gera uma nova extension para um processo.
- **extension_consume (#6)**: Consome uma extension fornecida.
- **extension_release (#7)**: Libera a memória associada a uma extension consumida.
- **extension_update_file (#8)**: Modifica os parâmetros de uma file extension existente dentro do sandbox.
- **extension_twiddle (#9)**: Ajusta ou modifica uma file extension existente (por exemplo, TextEdit, rtf, rtfd).
- **suspend (#10)**: Suspende temporariamente todas as verificações do sandbox (requer os entitlements apropriados).
- **unsuspend (#11)**: Retoma todas as verificações do sandbox anteriormente suspensas.
- **passthrough_access (#12)**: Permite acesso direto de passthrough a um recurso, ignorando as verificações do sandbox.
- **set_container_path (#13)**: (somente iOS) Define um caminho de container para um app group ou signing ID.
- **container_map (#14)**: (somente iOS) Recupera um caminho de container de `containermanagerd`.
- **sandbox_user_state_item_buffer_send (#15)**: (iOS 10+) Define metadados do user mode no sandbox.
- **inspect (#16)**: Fornece informações de debugging sobre um processo em sandbox.
- **dump (#18)**: (macOS 11) Despeja o profile atual de um sandbox para análise.
- **vtrace (#19)**: Rastreia operações do sandbox para monitoramento ou debugging.
- **builtin_profile_deactivate (#20)**: (macOS < 11) Desativa profiles nomeados (por exemplo, `pe_i_can_has_debugger`).
- **check_bulk (#21)**: Realiza várias operações `sandbox_check` em uma única chamada.
- **reference_retain_by_audit_token (#28)**: Cria uma referência para um audit token para uso em verificações do sandbox.
- **reference_release (#29)**: Libera uma referência de audit token retida anteriormente.
- **rootless_allows_task_for_pid (#30)**: Verifica se `task_for_pid` é permitido (semelhante às verificações de `csr`).
- **rootless_whitelist_push (#31)**: (macOS) Aplica um arquivo de manifesto do System Integrity Protection (SIP).
- **rootless_whitelist_check (preflight) (#32)**: Verifica o arquivo de manifesto do SIP antes da execução.
- **rootless_protected_volume (#33)**: (macOS) Aplica proteções do SIP a um disco ou partição.
- **rootless_mkdir_protected (#34)**: Aplica proteção do SIP/DataVault a um processo de criação de diretório.

## Sandbox.kext

Observe que, no iOS, a extensão do kernel contém **todos os profiles hardcoded** dentro do segmento `__TEXT.__const` para evitar que sejam modificados. Estas são algumas funções interessantes da extensão do kernel:

- **`hook_policy_init`**: Intercepta `mpo_policy_init` e é chamada após `mac_policy_register`. Ela realiza a maior parte das inicializações do Sandbox. Também inicializa o SIP.
- **`hook_policy_initbsd`**: Configura a interface sysctl, registrando `security.mac.sandbox.sentinel`, `security.mac.sandbox.audio_active` e `security.mac.sandbox.debug_mode` (se inicializado com `PE_i_can_has_debugger`).
- **`hook_policy_syscall`**: É chamada por `mac_syscall` com `"Sandbox"` como primeiro argumento e um código indicando a operação como segundo argumento. Um switch é usado para localizar o código a ser executado de acordo com o código solicitado.

### MACF Hooks

**`Sandbox.kext`** usa mais de uma centena de hooks via MACF. A maioria dos hooks apenas verifica alguns casos triviais que permitem realizar a ação; caso contrário, eles chamam **`cred_sb_evalutate`** com as **credentials** do MACF, um número correspondente à **operação** a ser realizada e um **buffer** para a saída.<sup>[[1]](#references)</sup>

Um bom exemplo disso é a função **`_mpo_file_check_mmap`**, que intercepta `mmap` e começa verificando se a nova memória será gravável (e, caso não seja, permite a execução); em seguida, verifica se ela é usada para o dyld shared cache e, nesse caso, permite a execução; por fim, chama **`sb_evaluate_internal`** (ou um de seus wrappers) para realizar verificações adicionais de permissão.

Além disso, entre os centenas de hooks usados pelo Sandbox, há 3 particularmente interessantes:

- `mpo_proc_check_for`: Aplica o profile, se necessário e caso ele ainda não tenha sido aplicado anteriormente.
- `mpo_vnode_check_exec`: É chamada quando um processo carrega o binário associado; então, uma verificação do profile é realizada, assim como uma verificação que proíbe execuções SUID/SGID.
- `mpo_cred_label_update_execve`: É chamada quando o label é atribuído. Esta é a mais longa, pois é chamada quando o binário está totalmente carregado, mas ainda não foi executado. Ela realiza ações como criar o objeto sandbox, anexar a struct do sandbox às credenciais kauth, remover o acesso a mach ports...

Observe que **`_cred_sb_evalutate`** é um wrapper sobre **`sb_evaluate_internal`**, e essa função recebe as credentials fornecidas e realiza a avaliação usando a função **`eval`**, que normalmente avalia o **platform profile**, aplicado por padrão a todos os processos, e depois o **specific process profile**. Observe que o platform profile é um dos principais componentes do **SIP** no macOS.

## Sandboxd

O Sandbox também possui um daemon de usuário em execução que expõe o serviço XPC Mach `com.apple.sandboxd` e vincula a porta especial 14 (`HOST_SEATBELT_PORT`), usada pela extensão do kernel para se comunicar com ele. Ele expõe algumas funções usando MIG.

## References

- [1] [XNU — `security/mac_policy.h` (hooks MACF registrados pelo Sandbox kext)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_policy.h)
- [2] [XNU — `security/mac_base.c` (`__mac_syscall`, o entry point por trás de `__sandbox_ms`)](https://github.com/apple-oss-distributions/xnu/blob/main/security/mac_base.c)
- [3] [Página man de `sandbox_init(3)`](https://keith.github.io/xcode-man-pages/sandbox_init.3.html)
- [4] [Apple Developer — App Sandbox](https://developer.apple.com/documentation/security/app-sandbox)
- [5] [Guia do Apple Sandbox v1.0](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/)
- [6] [Escape do sandbox do Mac](https://lapcatsoftware.com/articles/sandbox-escape.html)
- [7] [Escape do Sandbox do Office365 para MacOS](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)
- [8] [HITBGSEC 2016 SG - The Apple Sandbox: Deeper Into The Quagmire - Jonathan Levin](https://www.youtube.com/watch?v=mG715HcDgO8&t=3011s)
{{#include ../../../../banners/hacktricks-training.md}}
