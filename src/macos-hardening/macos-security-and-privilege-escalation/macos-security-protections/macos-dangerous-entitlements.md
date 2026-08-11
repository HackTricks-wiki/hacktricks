# Entitlements perigosos do macOS e permissões do TCC

{{#include ../../../banners/hacktricks-training.md}}

Entitlements declaram recursos e exceções de segurança que o sistema operacional concede a código assinado. As entradas abaixo se concentram naquelas especialmente úteis durante uma análise ofensiva.<sup>[[13]](#references)</sup>

> [!WARNING]
> Observe que entitlements iniciados com **`com.apple`** não estão disponíveis para terceiros; somente a Apple pode concedê-los... Ou, se você estiver usando um certificado empresarial, poderá criar seus próprios entitlements iniciados com **`com.apple`** e, na prática, contornar proteções baseadas nisso.

## Alta

### `com.apple.rootless.install.heritable`

O entitlement **`com.apple.rootless.install.heritable`** permite que um processo **ignore o SIP**. Consulte [aqui para mais informações](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

O entitlement **`com.apple.rootless.install`** permite que um processo **ignore o SIP**. Consulte [aqui para mais informações](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (anteriormente chamado `task_for_pid-allow`)**

Esse entitlement permite que um processo obtenha o **task port de qualquer** processo, exceto o kernel. Consulte [**aqui para mais informações**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.get-task-allow`

Esse entitlement permite que outros processos com o entitlement **`com.apple.security.cs.debugger`** obtenham o task port do processo executado pelo binário com esse entitlement e **injetem código nele**. Consulte [**aqui para mais informações**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.cs.debugger`

Apps com o Debugging Tool Entitlement podem chamar `task_for_pid()` para recuperar um task port válido de apps não assinados e de terceiros com o entitlement `Get Task Allow` definido como `true`. No entanto, mesmo com o debugging tool entitlement, um debugger **não pode obter os task ports** de processos que **não possuem o entitlement `Get Task Allow`** e que, portanto, estão protegidos pelo System Integrity Protection. Consulte [**aqui para mais informações**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger).<sup>[[3]](#references)</sup>

### `com.apple.security.cs.disable-library-validation`

Esse entitlement permite que um aplicativo **carregue frameworks, plug-ins ou libraries sem exigir que sejam assinados pela Apple ou com o mesmo Team ID** do executável principal; assim, um atacante poderia abusar de um carregamento arbitrário de library para injetar código. Consulte [**aqui para mais informações**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation).<sup>[[4]](#references)</sup>

### `com.apple.private.security.clear-library-validation`

Esse entitlement é muito semelhante a **`com.apple.security.cs.disable-library-validation`**, mas, **em vez de desabilitar diretamente** a validação de libraries, permite que o processo **chame uma system call `csops` para desabilitá-la** em tempo de execução.

O nome do entitlement está codificado no XNU, próximo à operação `csops` que o utiliza:<sup>[[1]](#references)</sup>
```c
/* bsd/sys/codesign.h */
#define CLEAR_LV_ENTITLEMENT "com.apple.private.security.clear-library-validation"
...
#define CS_OPS_CLEAR_LV     15  /* clear the library validation flag */
```
O handler do kernel para `CS_OPS_CLEAR_LV` (`bsd/kern/kern_proc.c`) mostra exatamente quão restrita é a primitive:<sup>[[2]](#references)</sup>
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
Assim, a operação:

- É **exclusiva do macOS** (`ENOTSUP` em todas as outras plataformas).
- Só funciona no **próprio processo** (`forself == 1`) — não é possível remover a validação de bibliotecas de outro processo com ela.
- Exige que o processo realmente **tenha o entitlement**, e recusa a operação se o processo estiver sinalizado como `CS_INSTALLER` ou estiver sendo executado em um caminho raiz de subsistema.
- Remove **`CS_REQUIRE_LV | CS_FORCED_LV`** das flags de assinatura de código do processo.

O comentário do XNU explica o caso de uso pretendido e também por que isso é interessante para um atacante:

> Esta opção é usada para remover a validação de bibliotecas de um processo em execução. Isso é usado em arquiteturas de plugins quando um programa precisa carregar bibliotecas não confiáveis. [...] Depois que um processo carrega a biblioteca não confiável, confiar na validação de bibliotecas no futuro não será eficaz.

Em outras palavras, **qualquer binário que tenha este entitlement é um alvo de dylib-injection**: execute código dentro dele (ou convença-o a carregar seu plugin) depois que ele tiver removido `CS_REQUIRE_LV`, e você herdará tudo o que o processo host tem permissão para fazer.

### `com.apple.security.cs.allow-dyld-environment-variables`

Este entitlement permite **usar variáveis de ambiente DYLD** que poderiam ser usadas para injetar bibliotecas e código. Consulte [**isto para obter mais informações**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables).<sup>[[5]](#references)</sup>

### `com.apple.private.tcc.manager` ou `com.apple.rootless.storage`.`TCC`

[**De acordo com este blog**](https://objective-see.org/blog/blog_0x4C.html) **e** [**este blog**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), esses entitlements permitem que um processo **modifique** o banco de dados do **TCC**.<sup>[[6]](#references)[[7]](#references)</sup>

### **`system.install.apple-software`** e **`system.install.apple-software.standar-user`**

Esses entitlements permitem que um processo **instale software sem pedir permissão ao usuário**, o que pode ser útil para **escalada de privilégios**.

### `com.apple.private.security.kext-management`

Entitlement necessário para solicitar ao **kernel o carregamento de uma extensão do kernel**.

### **`com.apple.private.icloud-account-access`**

O entitlement **`com.apple.private.icloud-account-access`** torna possível comunicar-se com o serviço XPC **`com.apple.iCloudHelper`**, que **fornecerá tokens do iCloud**.

O **iMovie** e o **Garageband** tinham este entitlement.

Para obter mais **informações** sobre o exploit para **obter tokens do iCloud** por meio desse entitlement, consulte a palestra: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)<sup>[[8]](#references)</sup>

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: Não sei o que isso permite fazer

### `com.apple.private.apfs.revert-to-snapshot`

TODO: [**Este relatório**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) menciona que este entitlement poderia ser usado para atualizar conteúdos protegidos pelo SSV após uma reinicialização. Se você souber como, envie um PR!<sup>[[9]](#references)</sup>

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: [**O mesmo relatório**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) menciona que a criação de um snapshot selado poderia ser usada para atualizar conteúdos protegidos pelo SSV após uma reinicialização. Se você souber como, envie um PR!<sup>[[9]](#references)</sup>

### `keychain-access-groups`

Este entitlement lista os grupos de **keychain** aos quais o aplicativo tem acesso:
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

Concede permissões de **Full Disk Access**, uma das permissões mais elevadas do TCC que você pode ter.

### **`kTCCServiceAppleEvents`**

Permite que o app envie eventos para outros aplicativos normalmente usados para **automatizar tarefas**. Ao controlar outros apps, ele pode abusar das permissões concedidas a esses outros apps.

Como fazê-los solicitar a senha do usuário:
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
Ou fazê-los executar **ações arbitrárias**.

### **`kTCCServiceEndpointSecurityClient`**

Permite, entre outras permissões, **escrever no banco de dados TCC do usuário**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Permite **alterar** o atributo **`NFSHomeDirectory`** de um usuário, o que altera o caminho da pasta pessoal e, portanto, permite **bypassar o TCC**.

### **`kTCCServiceSystemPolicyAppBundles`**

Permite modificar arquivos dentro de bundles de aplicativos (dentro de app.app), algo que é **proibido por padrão**.

<figure><img src="../../../images/image (31).png" alt=""><figcaption></figcaption></figure>

É possível verificar quem tem esse acesso em _Ajustes do Sistema_ > _Privacidade e Segurança_ > _Gerenciamento de Apps._

### `kTCCServiceAccessibility`

O processo poderá **abusar dos recursos de acessibilidade do macOS**, o que significa, por exemplo, que poderá pressionar teclas. Assim, ele poderia solicitar acesso para controlar um aplicativo como o Finder e aprovar a caixa de diálogo com essa permissão.

## Entitlements relacionados ao Trustcache/CDhash

Existem alguns entitlements que poderiam ser usados para bypassar as proteções do Trustcache/CDhash, que impedem a execução de versões downgraded de binários da Apple.

## Médio

### `com.apple.security.cs.allow-jit`

Esse entitlement permite que um processo **crie memória que seja gravável e executável** passando a flag `MAP_JIT` para a função de sistema `mmap()`. Consulte [**esta página para obter mais informações**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit).<sup>[[10]](#references)</sup>

### `com.apple.security.cs.allow-unsigned-executable-memory`

Esse entitlement permite **substituir ou fazer patch em código C**, usar o **`NSCreateObjectFileImageFromMemory`** (fundamentalmente inseguro), há muito depreciado, ou usar o framework **DVDPlayback**. Consulte [**esta página para obter mais informações**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory).<sup>[[11]](#references)</sup>

> [!CAUTION]
> Incluir esse entitlement expõe seu aplicativo a vulnerabilidades comuns em linguagens de código não seguras para memória. Considere cuidadosamente se seu aplicativo precisa dessa exceção.

### `com.apple.security.cs.disable-executable-page-protection`

Esse entitlement permite **modificar seções de seus próprios arquivos executáveis** no disco para forçar a saída. Consulte [**esta página para obter mais informações**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection).<sup>[[12]](#references)</sup>

> [!CAUTION]
> O Entitlement de Desativação da Proteção de Memória Executável é um entitlement extremo que remove uma proteção de segurança fundamental do seu aplicativo, possibilitando que um atacante reescreva o código executável do seu aplicativo sem ser detectado. Prefira entitlements mais específicos, se possível.

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

Esse entitlement permite montar um sistema de arquivos nullfs (proibido por padrão). Ferramenta: [**mount_nullfs**](https://github.com/JamaicanMoose/mount_nullfs/tree/master).

### `kTCCServiceAll`

De acordo com esta postagem de blog, essa permissão TCC geralmente é encontrada na forma:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
Permite que o processo **solicite todas as permissões TCC**.

### **`kTCCServicePostEvent`**

Permite **injetar eventos sintéticos de teclado e mouse** em todo o sistema por meio de `CGEventPost()`. Um processo com essa permissão pode simular pressionamentos de teclas, cliques do mouse e eventos de rolagem em qualquer aplicativo — fornecendo, efetivamente, **controle remoto** da área de trabalho.

Isso é especialmente perigoso quando combinado com `kTCCServiceAccessibility` ou `kTCCServiceListenEvent`, pois permite tanto ler quanto injetar entradas.
```objc
// Inject a keystroke (Enter key)
CGEventRef keyDown = CGEventCreateKeyboardEvent(NULL, kVK_Return, true);
CGEventPost(kCGSessionEventTap, keyDown);
```
### **`kTCCServiceListenEvent`**

Permite **interceptar todos os eventos de teclado e mouse** em todo o sistema (monitoramento de entrada / keylogging). Um processo pode registrar um `CGEventTap` para capturar cada tecla digitada em qualquer aplicativo, incluindo senhas, números de cartão de crédito e mensagens privadas.

Para obter técnicas detalhadas de exploração, consulte:

{{#ref}}
macos-input-monitoring-screen-capture-accessibility.md
{{#endref}}

### **`kTCCServiceScreenCapture`**

Permite **ler o buffer de exibição** — fazer capturas de tela e gravar vídeos da tela de qualquer aplicativo, incluindo campos de texto seguros. Combinado com OCR, isso pode extrair automaticamente senhas e dados confidenciais da tela.

> [!WARNING]
> A partir do macOS Sonoma, a captura de tela exibe um indicador persistente na barra de menus. Em versões anteriores, a gravação da tela pode ser completamente silenciosa.

### **`kTCCServiceCamera`**

Permite **capturar fotos e vídeos** da câmera integrada ou de câmeras USB conectadas. A injeção de código em um binário com direito de acesso à câmera permite vigilância visual silenciosa.

### **`kTCCServiceMicrophone`**

Permite **gravar áudio** de todos os dispositivos de entrada. Daemons em segundo plano com acesso ao microfone possibilitam vigilância persistente do áudio ambiente sem nenhuma janela de aplicativo visível.

### **`kTCCServiceLocation`**

Permite consultar a **localização física** do dispositivo por meio de triangulação Wi-Fi ou beacons Bluetooth. O monitoramento contínuo revela endereços residenciais e comerciais, padrões de deslocamento e rotinas diárias.

### **`kTCCServiceAddressBook`** / **`kTCCServiceCalendar`** / **`kTCCServicePhotos`**

Acesso aos **Contatos** (nomes, e-mails, telefones — úteis para spear-phishing), ao **Calendário** (agendas de reuniões, listas de participantes) e às **Fotos** (fotos pessoais, capturas de tela que podem conter credenciais e metadados de localização).

Para obter técnicas completas de exploração para roubo de credenciais via permissões TCC, consulte:

{{#ref}}
macos-tcc/macos-tcc-credential-and-data-theft.md
{{#endref}}

## Entitlements de Sandbox e Code Signing

### `com.apple.security.temporary-exception.mach-lookup.global-name`

**Exceções temporárias da Sandbox** enfraquecem o App Sandbox ao permitir a comunicação com serviços Mach/XPC de todo o sistema que a sandbox normalmente bloqueia. Esse é o **principal primitivo de escape da sandbox** — um aplicativo comprometido em sandbox pode usar exceções de mach-lookup para alcançar daemons privilegiados e explorar suas interfaces XPC.
```bash
# Find apps with mach-lookup exceptions
find /Applications -name "*.app" -exec sh -c '
binary="$1/Contents/MacOS/$(defaults read "$1/Contents/Info.plist" CFBundleExecutable 2>/dev/null)"
[ -f "$binary" ] && codesign -d --entitlements - "$binary" 2>&1 | grep -q "mach-lookup" && echo "$(basename "$1")"
' _ {} \; 2>/dev/null
```
Para obter uma cadeia de exploração detalhada: sandboxed app → mach-lookup exception → vulnerable daemon → sandbox escape, consulte:

{{#ref}}
macos-code-signing-weaknesses-and-sandbox-escapes.md
{{#endref}}

### `com.apple.developer.driverkit`

**DriverKit entitlements** permitem que binários de drivers no espaço do usuário se comuniquem diretamente com o kernel por meio de interfaces IOKit. Os binários DriverKit gerenciam hardware: USB, Thunderbolt, PCIe, dispositivos HID, áudio e rede.

Comprometer um binário DriverKit permite:
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

## References

- [1] [XNU — `bsd/sys/codesign.h` (operações `CS_OPS_*` e `CLEAR_LV_ENTITLEMENT)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/codesign.h)
- [2] [XNU — `bsd/kern/kern_proc.c` (manipulador de `csops` / `CS_OPS_CLEAR_LV`)](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
- [3] [Apple Developer — Entitlement de ferramenta de debugging (`com.apple.security.cs.debugger`)](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger)
- [4] [Apple Developer — Entitlement para desativar a validação de libraries](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation)
- [5] [Apple Developer — Entitlement para permitir variáveis de ambiente DYLD](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
- [6] [Objective-See — CVE-2020-9934: Bypassing TCC](https://objective-see.org/blog/blog_0x4C.html)
- [7] [Wojciech Reguła — Reproduza a música e ignore o TCC, também conhecido como CVE-2020-29621](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/)
- [8] [#OBTS v5.0: "O que acontece no seu Mac fica no iCloud da Apple?!" - Wojciech Regula (YouTube)](https://www.youtube.com/watch?v=_6e2LhmxVc0)
- [9] [O pesadelo da atualização OTA da Apple: ignorando a verificação de assinatura e comprometendo o kernel](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [10] [Apple Developer — Entitlement para permitir a execução de código compilado com JIT (`com.apple.security.cs.allow-jit`)](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit)
- [11] [Apple Developer — Entitlement para permitir memória executável não assinada](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory)
- [12] [Apple Developer — Entitlement para desativar a proteção de memória executável](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection)
- [13] [Apple Developer — Entitlements](https://developer.apple.com/documentation/bundleresources/entitlements)
{{#include ../../../banners/hacktricks-training.md}}
