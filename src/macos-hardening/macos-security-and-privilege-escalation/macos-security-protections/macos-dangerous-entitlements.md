# macOS Dangerous Entitlements & TCC perms

{{#include ../../../banners/hacktricks-training.md}}

> [!WARNING]
> Observe que os entitlements que começam com **`com.apple`** não estão disponíveis para terceiros, apenas a Apple pode concedê-los... Ou, se você estiver usando um certificado empresarial, poderá criar seus próprios entitlements começando com **`com.apple`** e, na prática, contornar proteções baseadas nisso.

## High

### `com.apple.rootless.install.heritable`

O entitlement **`com.apple.rootless.install.heritable`** permite **bypass do SIP**. Consulte [esta página para mais informações](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

O entitlement **`com.apple.rootless.install`** permite **bypass do SIP**. Consulte [esta página para mais informações](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (previously called `task_for_pid-allow`)**

Este entitlement permite obter a **task port de qualquer** processo, exceto o kernel. Consulte [**esta página para mais informações**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.get-task-allow`

Este entitlement permite que outros processos com o entitlement **`com.apple.security.cs.debugger`** obtenham a task port do processo executado pelo binary com este entitlement e **injetem código nele**. Consulte [**esta página para mais informações**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.cs.debugger`

Apps com o Debugging Tool Entitlement podem chamar `task_for_pid()` para recuperar uma task port válida de unsigned e third-party apps com o entitlement `Get Task Allow` definido como `true`. No entanto, mesmo com o debugging tool entitlement, um debugger **não pode obter as task ports** de processos que **não possuem o `Get Task Allow entitlement`** e que, portanto, estão protegidos pelo System Integrity Protection. Consulte [**esta página para mais informações**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger).

### `com.apple.security.cs.disable-library-validation`

Este entitlement permite **carregar frameworks, plug-ins ou libraries sem que sejam assinados pela Apple ou com o mesmo Team ID** do executável principal, portanto, um atacante poderia abusar de algum carregamento arbitrário de library para injetar código. Consulte [**esta página para mais informações**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation).

### `com.apple.private.security.clear-library-validation`

Este entitlement é muito semelhante a **`com.apple.security.cs.disable-library-validation`**, mas **em vez de desabilitar** diretamente a validação de libraries, ele permite que o processo **chame uma system call `csops` para desabilitá-la** em runtime.

O nome do entitlement está hardcoded no XNU, próximo à operação de `csops` que o utiliza:<sup>[2]</sup>
```c
/* bsd/sys/codesign.h */
#define CLEAR_LV_ENTITLEMENT "com.apple.private.security.clear-library-validation"
...
#define CS_OPS_CLEAR_LV     15  /* clear the library validation flag */
```
O handler do kernel para `CS_OPS_CLEAR_LV` (`bsd/kern/kern_proc.c`) mostra exatamente quão restritiva é a primitive:<sup>[3]</sup>
```c
case CS_OPS_CLEAR_LV: {
#if !defined(XNU_TARGET_OS_OSX)
// We only support dropping library validation on macOS
error = ENOTSUP;
#else
if (forself == 1 && IOTaskHasEntitlement(proc_task(pt), CLEAR_LV_ENTITLEMENT)) {
proc_lock(pt);
if (!(proc_getcsflags(pt) & CS_INSTALLER) && (pt->p_subsystem_root_path == NULL)) {
proc_csflags_clear(pt, CS_REQUIRE_LV | CS_FORCED_LV);
error = 0;
```
Portanto, a operação:

- É **exclusiva do macOS** (`ENOTSUP` em todas as outras plataformas).
- Só funciona no próprio processo (`forself == 1`) — não é possível remover a validação de bibliotecas de outro processo com ela.
- Exige que o processo realmente **tenha o entitlement**, e recusa a operação se o processo estiver marcado como `CS_INSTALLER` ou estiver sendo executado em um caminho raiz de subsystem.
- Remove **`CS_REQUIRE_LV | CS_FORCED_LV`** dos flags de assinatura de código do processo.

O comentário do XNU explica o caso de uso pretendido e também por que isso é interessante para um atacante:

> Esta opção é usada para remover a validação de bibliotecas de um processo em execução. Ela é usada em arquiteturas de plugins quando um programa precisa carregar bibliotecas não confiáveis. [...] Depois que um processo carrega a biblioteca não confiável, confiar na validação de bibliotecas no futuro não será eficaz.

Em outras palavras, **qualquer binário que contenha esse entitlement é um alvo de dylib-injection**: execute código dentro dele (ou convença-o a carregar seu plugin) depois que ele tiver removido `CS_REQUIRE_LV`, e você herdará tudo o que o processo hospedeiro tem permissão para fazer.

### `com.apple.security.cs.allow-dyld-environment-variables`

Este entitlement permite **usar variáveis de ambiente DYLD**, que podem ser usadas para injetar bibliotecas e código. Consulte [**este link para mais informações**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables).

### `com.apple.private.tcc.manager` ou `com.apple.rootless.storage`.`TCC`

[**De acordo com este blog**](https://objective-see.org/blog/blog_0x4C.html) **e** [**este blog**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), esses entitlements permitem **modificar** o banco de dados do **TCC**.

### **`system.install.apple-software`** e **`system.install.apple-software.standar-user`**

Esses entitlements permitem **instalar software sem pedir permissão** ao usuário, o que pode ser útil para uma **escalada de privilégios**.

### `com.apple.private.security.kext-management`

Entitlement necessário para solicitar ao **kernel o carregamento de uma extensão do kernel**.

### **`com.apple.private.icloud-account-access`**

Com o entitlement **`com.apple.private.icloud-account-access`**, é possível se comunicar com o serviço XPC **`com.apple.iCloudHelper`**, que **fornecerá tokens do iCloud**.

O **iMovie** e o **Garageband** tinham esse entitlement.

Para obter mais **informações** sobre o exploit para **obter tokens do iCloud** usando esse entitlement, consulte a palestra: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: Não sei o que isso permite fazer

### `com.apple.private.apfs.revert-to-snapshot`

TODO: [**Este relatório**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **menciona que isso poderia ser usado para** atualizar o conteúdo protegido pelo SSV após uma reinicialização. Se você souber como fazer isso, envie um PR, por favor!

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: [**Este relatório**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **menciona que isso poderia ser usado para** atualizar o conteúdo protegido pelo SSV após uma reinicialização. Se você souber como fazer isso, envie um PR, por favor!

### `keychain-access-groups`

Esta lista de entitlements indica os grupos de **keychain** aos quais o aplicativo tem acesso:
```xml
<key>keychain-access-groups</key>
<array>
<string>ichat</string>
<string>apple</string>
<string>appleaccount</string>
<string>InternetAccounts</string>
<string>IMCore</string>
</array>
```
### **`kTCCServiceSystemPolicyAllFiles`**

Concede permissões de **Acesso Total ao Disco**, uma das permissões mais elevadas do TCC que você pode ter.

### **`kTCCServiceAppleEvents`**

Permite que o app envie eventos para outros aplicativos comumente usados para **automatizar tarefas**. Ao controlar outros apps, ele pode abusar das permissões concedidas a esses outros apps.

Como fazê-los solicitar ao usuário a sua senha:
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
Ou fazê-los executar **ações arbitrárias**.

### **`kTCCServiceEndpointSecurityClient`**

Permite, entre outras permissões, **escrever no banco de dados TCC do usuário**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Permite **alterar** o atributo **`NFSHomeDirectory`** de um usuário, o que altera o caminho da pasta pessoal e, portanto, permite **bypassar o TCC**.

### **`kTCCServiceSystemPolicyAppBundles`**

Permite modificar arquivos dentro dos bundles de aplicativos (dentro de app.app), algo que é **proibido por padrão**.

<figure><img src="../../../images/image (31).png" alt=""><figcaption></figcaption></figure>

É possível verificar quem tem esse acesso em _Ajustes do Sistema_ > _Privacidade e Segurança_ > _Gerenciamento de Apps._

### `kTCCServiceAccessibility`

O processo poderá **abusar dos recursos de acessibilidade do macOS**, o que significa que, por exemplo, poderá pressionar teclas. Assim, ele poderia solicitar acesso para controlar um aplicativo como o Finder e aprovar a caixa de diálogo com essa permissão.

## Entitlements relacionados ao Trustcache/CDhash

Há alguns entitlements que poderiam ser usados para bypassar as proteções do Trustcache/CDhash, que impedem a execução de versões downgraded de binários da Apple.

## Médio

### `com.apple.security.cs.allow-jit`

Esse entitlement permite **criar memória que pode ser gravada e executada** passando a flag `MAP_JIT` para a função de sistema `mmap()`. Consulte [**aqui para mais informações**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit).

### `com.apple.security.cs.allow-unsigned-executable-memory`

Esse entitlement permite **substituir ou modificar código C**, usar o **`NSCreateObjectFileImageFromMemory`** (há muito tempo obsoleto e fundamentalmente inseguro) ou usar o framework **DVDPlayback**. Consulte [**aqui para mais informações**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory).

> [!CAUTION]
> Incluir este entitlement expõe seu aplicativo a vulnerabilidades comuns em linguagens de programação com memória insegura. Considere cuidadosamente se seu aplicativo precisa dessa exceção.

### `com.apple.security.cs.disable-executable-page-protection`

Esse entitlement permite **modificar seções de seus próprios arquivos executáveis** no disco para forçar a saída. Consulte [**aqui para mais informações**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection).

> [!CAUTION]
> O Entitlement de Desativação da Proteção de Memória Executável é um entitlement extremo que remove uma proteção de segurança fundamental do seu aplicativo, possibilitando que um invasor reescreva o código executável do seu aplicativo sem ser detectado. Prefira entitlements mais restritos, se possível.

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

Esse entitlement permite montar um sistema de arquivos nullfs (proibido por padrão). Ferramenta: [**mount_nullfs**](https://github.com/JamaicanMoose/mount_nullfs/tree/master).

### `kTCCServiceAll`

De acordo com esta publicação de blog, essa permissão TCC geralmente é encontrada na forma:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
Permite que o processo **solicite todas as permissões do TCC**.

### **`kTCCServicePostEvent`**

Permite **injetar eventos sintéticos de teclado e mouse** em todo o sistema por meio de `CGEventPost()`. Um processo com essa permissão pode simular pressionamentos de teclas, cliques do mouse e eventos de rolagem em qualquer aplicativo — fornecendo efetivamente **controle remoto** da área de trabalho.

Isso é especialmente perigoso quando combinado com `kTCCServiceAccessibility` ou `kTCCServiceListenEvent`, pois permite tanto ler quanto injetar entradas.
```objc
// Inject a keystroke (Enter key)
CGEventRef keyDown = CGEventCreateKeyboardEvent(NULL, kVK_Return, true);
CGEventPost(kCGSessionEventTap, keyDown);
```
### **`kTCCServiceListenEvent`**

Permite **interceptar todos os eventos de teclado e mouse** em todo o sistema (input monitoring / keylogging). Um processo pode registrar um `CGEventTap` para capturar cada tecla digitada em qualquer aplicativo, incluindo senhas, números de cartão de crédito e mensagens privadas.

Para obter técnicas detalhadas de exploração, consulte:

{{#ref}}
macos-input-monitoring-screen-capture-accessibility.md
{{#endref}}

### **`kTCCServiceScreenCapture`**

Permite **ler o buffer de exibição** — tirar screenshots e gravar vídeos da tela de qualquer aplicativo, incluindo campos de texto seguros. Combinado com OCR, isso pode extrair automaticamente senhas e dados sensíveis da tela.

> [!WARNING]
> A partir do macOS Sonoma, o screen capture exibe um indicador persistente na barra de menus. Em versões mais antigas, a gravação da tela pode ser completamente silenciosa.

### **`kTCCServiceCamera`**

Permite **capturar fotos e vídeos** da câmera integrada ou de câmeras USB conectadas. A injeção de código em um binário com entitlement de câmera permite vigilância visual silenciosa.

### **`kTCCServiceMicrophone`**

Permite **gravar áudio** de todos os dispositivos de entrada. Daemons em segundo plano com acesso ao microfone fornecem vigilância persistente do ambiente, sem nenhuma janela de aplicativo visível.

### **`kTCCServiceLocation`**

Permite consultar a **localização física** do dispositivo por meio de triangulação Wi-Fi ou beacons Bluetooth. O monitoramento contínuo revela endereços residenciais e de trabalho, padrões de viagem e rotinas diárias.

### **`kTCCServiceAddressBook`** / **`kTCCServiceCalendar`** / **`kTCCServicePhotos`**

Acesso aos **Contatos** (nomes, e-mails, telefones — úteis para spear-phishing), **Calendário** (agendas de reuniões, listas de participantes) e **Fotos** (fotos pessoais, screenshots que podem conter credenciais, metadados de localização).

Para obter técnicas completas de exploração para credential theft via permissões do TCC, consulte:

{{#ref}}
macos-tcc/macos-tcc-credential-and-data-theft.md
{{#endref}}

## Entitlements de Sandbox & Code Signing

### `com.apple.security.temporary-exception.mach-lookup.global-name`

**Exceções temporárias do Sandbox** enfraquecem o App Sandbox ao permitir a comunicação com serviços Mach/XPC em todo o sistema que o sandbox normalmente bloqueia. Essa é a **principal primitive de sandbox escape** — um aplicativo comprometido em sandbox pode usar exceções de mach-lookup para alcançar daemons privilegiados e explorar suas interfaces XPC.
```bash
# Find apps with mach-lookup exceptions
find /Applications -name "*.app" -exec sh -c '
binary="$1/Contents/MacOS/$(defaults read "$1/Contents/Info.plist" CFBundleExecutable 2>/dev/null)"
[ -f "$binary" ] && codesign -d --entitlements - "$binary" 2>&1 | grep -q "mach-lookup" && echo "$(basename "$1")"
' _ {} \; 2>/dev/null
```
Para uma cadeia de exploração detalhada: app em sandbox → exceção de mach-lookup → daemon vulnerável → escape do sandbox, consulte:

{{#ref}}
macos-code-signing-weaknesses-and-sandbox-escapes.md
{{#endref}}

### `com.apple.developer.driverkit`

**Entitlements do DriverKit** permitem que binários de drivers em user space se comuniquem diretamente com o kernel por meio de interfaces do IOKit. Binários do DriverKit gerenciam hardware: USB, Thunderbolt, PCIe, dispositivos HID, áudio e rede.

Comprometer um binário do DriverKit possibilita:
- **Superfície de ataque do kernel** por meio de chamadas `IOConnectCallMethod` malformadas
- **Spoofing de dispositivos USB** (emular um teclado para injeção HID)
- **Ataques DMA** por meio de interfaces PCIe/Thunderbolt
```bash
# Find DriverKit binaries
find / -name "*.dext" -type d 2>/dev/null
systemextensionsctl list
```
Para uma exploração detalhada de IOKit/DriverKit, consulte:

{{#ref}}
../mac-os-architecture/macos-iokit.md
{{#endref}}

## Referências

- [1] [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
- [2] [XNU — `bsd/sys/codesign.h` (operações `CS_OPS_*` e `CLEAR_LV_ENTITLEMENT`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [3] [XNU — `bsd/kern/kern_proc.c` (handler de `csops` / `CS_OPS_CLEAR_LV`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)

{{#include ../../../banners/hacktricks-training.md}}
