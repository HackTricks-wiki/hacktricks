# macOS Sandbox

{{#include ../../../../banners/hacktricks-training.md}}

## Informações Básicas

O macOS Sandbox (inicialmente chamado de Seatbelt) **limita as aplicações** que estão rodando dentro do sandbox às **ações permitidas especificadas no perfil do Sandbox** com o qual o aplicativo está rodando. Isso ajuda a garantir que **a aplicação acessará apenas os recursos esperados**.

Qualquer aplicativo com a **entitlement** **`com.apple.security.app-sandbox`** será executado dentro do sandbox. **Binários da Apple** geralmente são executados dentro de um Sandbox, e todos os aplicativos da **App Store têm essa entitlement**. Portanto, vários aplicativos serão executados dentro do sandbox.

Para controlar o que um processo pode ou não fazer, o **Sandbox tem hooks** em quase qualquer operação que um processo possa tentar (incluindo a maioria das syscalls) usando **MACF**. No entanto, **dependendo** das **entitlements** do aplicativo, o Sandbox pode ser mais permissivo com o processo.

Alguns componentes importantes do Sandbox são:

- A **extensão do kernel** `/System/Library/Extensions/Sandbox.kext`
- O **framework privado** `/System/Library/PrivateFrameworks/AppSandbox.framework`
- Um **daemon** rodando em userland `/usr/libexec/sandboxd`
- Os **containers** `~/Library/Containers`

### Containers

Cada aplicação sandboxed terá seu próprio container em `~/Library/Containers/{CFBundleIdentifier}` :
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
Dentro de cada pasta de id de pacote, você pode encontrar o **plist** e o **diretório de Dados** do App com uma estrutura que imita a pasta Home:
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
> Observe que, mesmo que os symlinks estejam lá para "escapar" do Sandbox e acessar outras pastas, o App ainda precisa **ter permissões** para acessá-las. Essas permissões estão dentro do **`.plist`** em `RedirectablePaths`.

Os **`SandboxProfileData`** são os dados do perfil de sandbox compilados CFData escapados para B64.
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
> Tudo criado/modificado por um aplicativo Sandboxed receberá o **atributo de quarentena**. Isso impedirá um espaço de sandbox ao acionar o Gatekeeper se o aplicativo sandbox tentar executar algo com **`open`**.

## Perfis de Sandbox

Os perfis de Sandbox são arquivos de configuração que indicam o que será **permitido/proibido** nesse **Sandbox**. Ele usa a **Linguagem de Perfil de Sandbox (SBPL)**, que utiliza a linguagem de programação [**Scheme**](<https://en.wikipedia.org/wiki/Scheme_(programming_language)>).

Aqui você pode encontrar um exemplo:
```scheme
(version 1) ; First you get the version

(deny default) ; Then you shuold indicate the default action when no rule applies

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
> Confira esta [**pesquisa**](https://reverse.put.as/2011/09/14/apple-sandbox-guide-v1-0/) **para verificar mais ações que podem ser permitidas ou negadas.**
>
> Note que na versão compilada de um perfil, o nome das operações é substituído por suas entradas em um array conhecido pela dylib e pelo kext, tornando a versão compilada mais curta e mais difícil de ler.

Serviços **sistêmicos** importantes também são executados dentro de seu próprio **sandbox** personalizado, como o serviço `mdnsresponder`. Você pode visualizar esses **perfis de sandbox** personalizados em:

- **`/usr/share/sandbox`**
- **`/System/Library/Sandbox/Profiles`**
- Outros perfis de sandbox podem ser verificados em [https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles).

Aplicativos da **App Store** usam o **perfil** **`/System/Library/Sandbox/Profiles/application.sb`**. Você pode verificar neste perfil como direitos como **`com.apple.security.network.server`** permitem que um processo use a rede.

Então, alguns **serviços de daemon da Apple** usam perfis diferentes localizados em `/System/Library/Sandbox/Profiles/*.sb` ou `/usr/share/sandbox/*.sb`. Esses sandboxes são aplicados na função principal chamando a API `sandbox_init_XXX`.

**SIP** é um perfil de Sandbox chamado platform_profile em `/System/Library/Sandbox/rootless.conf`.

### Exemplos de Perfil de Sandbox

Para iniciar um aplicativo com um **perfil de sandbox específico**, você pode usar:
```bash
sandbox-exec -f example.sb /Path/To/The/Application
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

> [!NOTE]
> Observe que o **software** **desenvolvido pela Apple** que roda em **Windows** **não possui precauções de segurança adicionais**, como o sandboxing de aplicativos.

Exemplos de bypass:

- [https://lapcatsoftware.com/articles/sandbox-escape.html](https://lapcatsoftware.com/articles/sandbox-escape.html)
- [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c) (eles conseguem escrever arquivos fora do sandbox cujo nome começa com `~$`).

### Rastreamento de Sandbox

#### Via perfil

É possível rastrear todas as verificações que o sandbox realiza toda vez que uma ação é verificada. Para isso, basta criar o seguinte perfil:
```scheme:trace.sb
(version 1)
(trace /tmp/trace.out)
```
E então, apenas execute algo usando esse perfil:
```bash
sandbox-exec -f /tmp/trace.sb /bin/ls
```
Em `/tmp/trace.out` você poderá ver cada verificação de sandbox realizada toda vez que foi chamada (ou seja, muitos duplicados).

Também é possível rastrear o sandbox usando o **`-t`** parâmetro: `sandbox-exec -t /path/trace.out -p "(version 1)" /bin/ls`

#### Via API

A função `sandbox_set_trace_path` exportada por `libsystem_sandbox.dylib` permite especificar um nome de arquivo de rastreamento onde as verificações de sandbox serão escritas.\
Também é possível fazer algo semelhante chamando `sandbox_vtrace_enable()` e, em seguida, obtendo os logs de erro do buffer chamando `sandbox_vtrace_report()`.

### Inspeção de Sandbox

`libsandbox.dylib` exporta uma função chamada sandbox_inspect_pid que fornece uma lista do estado do sandbox de um processo (incluindo extensões). No entanto, apenas binários da plataforma podem usar essa função.

### Perfis de Sandbox do MacOS e iOS

O MacOS armazena perfis de sandbox do sistema em dois locais: **/usr/share/sandbox/** e **/System/Library/Sandbox/Profiles**.

E se um aplicativo de terceiros tiver a _**com.apple.security.app-sandbox**_ concessão, o sistema aplica o perfil **/System/Library/Sandbox/Profiles/application.sb** a esse processo.

No iOS, o perfil padrão é chamado **container** e não temos a representação de texto SBPL. Na memória, esse sandbox é representado como uma árvore binária de Permitir/Negar para cada permissão do sandbox.

### SBPL Personalizado em aplicativos da App Store

Pode ser possível para empresas fazerem seus aplicativos rodarem **com perfis de Sandbox personalizados** (em vez do padrão). Elas precisam usar a concessão **`com.apple.security.temporary-exception.sbpl`** que precisa ser autorizada pela Apple.

É possível verificar a definição dessa concessão em **`/System/Library/Sandbox/Profiles/application.sb:`**
```scheme
(sandbox-array-entitlement
"com.apple.security.temporary-exception.sbpl"
(lambda (string)
(let* ((port (open-input-string string)) (sbpl (read port)))
(with-transparent-redirection (eval sbpl)))))
```
Isto irá **avaliar a string após esta concessão** como um perfil de Sandbox.

### Compilando e descompilando um Perfil de Sandbox

A ferramenta **`sandbox-exec`** utiliza as funções `sandbox_compile_*` da `libsandbox.dylib`. As principais funções exportadas são: `sandbox_compile_file` (espera um caminho de arquivo, parâmetro `-f`), `sandbox_compile_string` (espera uma string, parâmetro `-p`), `sandbox_compile_name` (espera um nome de um contêiner, parâmetro `-n`), `sandbox_compile_entitlements` (espera um plist de concessões).

Esta versão revertida e [**open source da ferramenta sandbox-exec**](https://newosxbook.com/src.jl?tree=listings&file=/sandbox_exec.c) permite que **`sandbox-exec`** escreva em um arquivo o perfil de sandbox compilado.

Além disso, para confinar um processo dentro de um contêiner, pode chamar `sandbox_spawnattrs_set[container/profilename]` e passar um contêiner ou perfil pré-existente.

## Depurar e Bypass Sandbox

No macOS, ao contrário do iOS, onde os processos são isolados desde o início pelo kernel, **os processos devem optar por entrar no sandbox**. Isso significa que no macOS, um processo não é restrito pelo sandbox até que decida ativamente entrar nele, embora os aplicativos da App Store estejam sempre isolados.

Os processos são automaticamente isolados do userland quando começam, se tiverem a concessão: `com.apple.security.app-sandbox`. Para uma explicação detalhada deste processo, verifique:

{{#ref}}
macos-sandbox-debug-and-bypass/
{{#endref}}

## **Extensões de Sandbox**

As extensões permitem conceder privilégios adicionais a um objeto e são concedidas chamando uma das funções:

- `sandbox_issue_extension`
- `sandbox_extension_issue_file[_with_new_type]`
- `sandbox_extension_issue_mach`
- `sandbox_extension_issue_iokit_user_client_class`
- `sandbox_extension_issue_iokit_registry_rentry_class`
- `sandbox_extension_issue_generic`
- `sandbox_extension_issue_posix_ipc`

As extensões são armazenadas no segundo slot de rótulo MACF acessível a partir das credenciais do processo. A seguinte **`sbtool`** pode acessar essas informações.

Note que as extensões são geralmente concedidas por processos permitidos, por exemplo, `tccd` concederá o token de extensão de `com.apple.tcc.kTCCServicePhotos` quando um processo tentar acessar as fotos e for permitido em uma mensagem XPC. Então, o processo precisará consumir o token de extensão para que ele seja adicionado a ele.\
Note que os tokens de extensão são longos hexadecimais que codificam as permissões concedidas. No entanto, eles não têm o PID permitido codificado, o que significa que qualquer processo com acesso ao token pode ser **consumido por múltiplos processos**.

Note que as extensões estão muito relacionadas às concessões também, então ter certas concessões pode automaticamente conceder certas extensões.

### **Verificar Privilégios de PID**

[**De acordo com isso**](https://www.youtube.com/watch?v=mG715HcDgO8&t=3011s), as funções **`sandbox_check`** (é um `__mac_syscall`), podem verificar **se uma operação é permitida ou não** pelo sandbox em um certo PID, token de auditoria ou ID único.

A [**ferramenta sbtool**](http://newosxbook.com/src.jl?tree=listings&file=sbtool.c) (encontre-a [compilada aqui](https://newosxbook.com/articles/hitsb.html)) pode verificar se um PID pode realizar certas ações:
```bash
sbtool <pid> mach #Check mac-ports (got from launchd with an api)
sbtool <pid> file /tmp #Check file access
sbtool <pid> inspect #Gives you an explanation of the sandbox profile and extensions
sbtool <pid> all
```
### \[un]suspend

Também é possível suspender e retomar a sandbox usando as funções `sandbox_suspend` e `sandbox_unsuspend` da `libsystem_sandbox.dylib`.

Observe que, para chamar a função de suspensão, algumas permissões são verificadas para autorizar o chamador a chamá-la, como:

- com.apple.private.security.sandbox-manager
- com.apple.security.print
- com.apple.security.temporary-exception.audio-unit-host

## mac_syscall

Esta chamada de sistema (#381) espera um primeiro argumento do tipo string que indicará o módulo a ser executado e, em seguida, um código no segundo argumento que indicará a função a ser executada. O terceiro argumento dependerá da função executada.

A chamada da função `___sandbox_ms` envolve `mac_syscall`, indicando no primeiro argumento `"Sandbox"`, assim como `___sandbox_msp` é um wrapper de `mac_set_proc` (#387). Então, alguns dos códigos suportados por `___sandbox_ms` podem ser encontrados nesta tabela:

- **set_profile (#0)**: Aplica um perfil compilado ou nomeado a um processo.
- **platform_policy (#1)**: Impõe verificações de política específicas da plataforma (varia entre macOS e iOS).
- **check_sandbox (#2)**: Realiza uma verificação manual de uma operação específica da sandbox.
- **note (#3)**: Adiciona uma anotação a uma Sandbox.
- **container (#4)**: Anexa uma anotação a uma sandbox, tipicamente para depuração ou identificação.
- **extension_issue (#5)**: Gera uma nova extensão para um processo.
- **extension_consume (#6)**: Consome uma extensão dada.
- **extension_release (#7)**: Libera a memória vinculada a uma extensão consumida.
- **extension_update_file (#8)**: Modifica parâmetros de uma extensão de arquivo existente dentro da sandbox.
- **extension_twiddle (#9)**: Ajusta ou modifica uma extensão de arquivo existente (por exemplo, TextEdit, rtf, rtfd).
- **suspend (#10)**: Suspende temporariamente todas as verificações da sandbox (requer permissões apropriadas).
- **unsuspend (#11)**: Retoma todas as verificações da sandbox que foram suspensas anteriormente.
- **passthrough_access (#12)**: Permite acesso direto a um recurso, ignorando as verificações da sandbox.
- **set_container_path (#13)**: (apenas iOS) Define um caminho de contêiner para um grupo de aplicativos ou ID de assinatura.
- **container_map (#14)**: (apenas iOS) Recupera um caminho de contêiner do `containermanagerd`.
- **sandbox_user_state_item_buffer_send (#15)**: (iOS 10+) Define metadados de modo de usuário na sandbox.
- **inspect (#16)**: Fornece informações de depuração sobre um processo em sandbox.
- **dump (#18)**: (macOS 11) Despeja o perfil atual de uma sandbox para análise.
- **vtrace (#19)**: Rastreia operações da sandbox para monitoramento ou depuração.
- **builtin_profile_deactivate (#20)**: (macOS < 11) Desativa perfis nomeados (por exemplo, `pe_i_can_has_debugger`).
- **check_bulk (#21)**: Realiza várias operações `sandbox_check` em uma única chamada.
- **reference_retain_by_audit_token (#28)**: Cria uma referência para um token de auditoria para uso em verificações de sandbox.
- **reference_release (#29)**: Libera uma referência de token de auditoria previamente retida.
- **rootless_allows_task_for_pid (#30)**: Verifica se `task_for_pid` é permitido (semelhante a verificações `csr`).
- **rootless_whitelist_push (#31)**: (macOS) Aplica um arquivo de manifesto de Proteção de Integridade do Sistema (SIP).
- **rootless_whitelist_check (preflight) (#32)**: Verifica o arquivo de manifesto SIP antes da execução.
- **rootless_protected_volume (#33)**: (macOS) Aplica proteções SIP a um disco ou partição.
- **rootless_mkdir_protected (#34)**: Aplica proteção SIP/DataVault a um processo de criação de diretório.

## Sandbox.kext

Observe que no iOS a extensão do kernel contém **todos os perfis codificados** dentro do segmento `__TEXT.__const` para evitar que sejam modificados. As seguintes são algumas funções interessantes da extensão do kernel:

- **`hook_policy_init`**: Ele conecta `mpo_policy_init` e é chamado após `mac_policy_register`. Realiza a maior parte das inicializações da Sandbox. Também inicializa o SIP.
- **`hook_policy_initbsd`**: Configura a interface sysctl registrando `security.mac.sandbox.sentinel`, `security.mac.sandbox.audio_active` e `security.mac.sandbox.debug_mode` (se inicializado com `PE_i_can_has_debugger`).
- **`hook_policy_syscall`**: É chamado por `mac_syscall` com "Sandbox" como primeiro argumento e um código indicando a operação no segundo. Um switch é usado para encontrar o código a ser executado de acordo com o código solicitado.

### MACF Hooks

**`Sandbox.kext`** usa mais de uma centena de hooks via MACF. A maioria dos hooks apenas verifica alguns casos triviais que permitem realizar a ação; se não, eles chamarão **`cred_sb_evalutate`** com as **credenciais** do MACF e um número correspondente à **operação** a ser realizada e um **buffer** para a saída.

Um bom exemplo disso é a função **`_mpo_file_check_mmap`** que conecta **`mmap`** e que começará a verificar se a nova memória será gravável (e se não, permitirá a execução), em seguida, verificará se está sendo usada para o cache compartilhado do dyld e, se sim, permitirá a execução, e finalmente chamará **`sb_evaluate_internal`** (ou um de seus wrappers) para realizar verificações adicionais de permissão.

Além disso, entre os centenas de hooks que a Sandbox usa, há 3 em particular que são muito interessantes:

- `mpo_proc_check_for`: Aplica o perfil se necessário e se não foi aplicado anteriormente.
- `mpo_vnode_check_exec`: Chamado quando um processo carrega o binário associado, então uma verificação de perfil é realizada e também uma verificação que proíbe execuções SUID/SGID.
- `mpo_cred_label_update_execve`: Isso é chamado quando o rótulo é atribuído. Este é o mais longo, pois é chamado quando o binário está totalmente carregado, mas ainda não foi executado. Ele realizará ações como criar o objeto sandbox, anexar a estrutura da sandbox às credenciais kauth, remover o acesso a portas mach...

Observe que **`_cred_sb_evalutate`** é um wrapper sobre **`sb_evaluate_internal`** e essa função obtém as credenciais passadas e, em seguida, realiza a avaliação usando a função **`eval`**, que geralmente avalia o **perfil da plataforma**, que por padrão é aplicado a todos os processos e, em seguida, o **perfil de processo específico**. Observe que o perfil da plataforma é um dos principais componentes do **SIP** no macOS.

## Sandboxd

A Sandbox também possui um daemon de usuário em execução, expondo o serviço XPC Mach `com.apple.sandboxd` e vinculando a porta especial 14 (`HOST_SEATBELT_PORT`), que a extensão do kernel usa para se comunicar com ele. Ele expõe algumas funções usando MIG.

## References

- [**\*OS Internals Volume III**](https://newosxbook.com/home.html)

{{#include ../../../../banners/hacktricks-training.md}}
