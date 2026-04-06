# macOS Entitlements Perigosos & permissões TCC

{{#include ../../../banners/hacktricks-training.md}}

> [!WARNING]
> Observe que entitlements que começam com **`com.apple`** não estão disponíveis para terceiros; somente a Apple pode concedê-los... Ou, se você estiver usando um certificado enterprise, na prática você poderia criar seus próprios entitlements começando com **`com.apple`** e contornar proteções baseadas nisso.

## Alto

### `com.apple.rootless.install.heritable`

O entitlement **`com.apple.rootless.install.heritable`** permite **contornar o SIP**. Check [this for more info](macos-sip.md#com.apple.rootless.install.heritable).

### **`com.apple.rootless.install`**

O entitlement **`com.apple.rootless.install`** permite **contornar o SIP**. Check[ this for more info](macos-sip.md#com.apple.rootless.install).

### **`com.apple.system-task-ports` (previously called `task_for_pid-allow`)**

Este entitlement permite obter o **task port de qualquer** processo, exceto o kernel. Check [**this for more info**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.get-task-allow`

Este entitlement permite que outros processos com o entitlement **`com.apple.security.cs.debugger`** obtenham o task port do processo executado pelo binário com este entitlement e **injete código nele**. Check [**this for more info**](../macos-proces-abuse/macos-ipc-inter-process-communication/index.html).

### `com.apple.security.cs.debugger`

Aplicativos com o Debugging Tool Entitlement podem chamar `task_for_pid()` para recuperar um task port válido para apps não assinados e de terceiros com o entitlement `Get Task Allow` definido como `true`. Contudo, mesmo com o debugging tool entitlement, um depurador **não pode obter os task ports** de processos que **não têm o entitlement `Get Task Allow`**, e que, portanto, estão protegidos pelo System Integrity Protection. Check [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_debugger).

### `com.apple.security.cs.disable-library-validation`

Este entitlement permite **carregar frameworks, plug-ins ou bibliotecas sem que sejam assinados pela Apple ou assinados com o mesmo Team ID** do executável principal, então um atacante poderia abusar de algum carregamento arbitrário de biblioteca para injetar código. Check [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-library-validation).

### `com.apple.private.security.clear-library-validation`

Este entitlement é muito similar a **`com.apple.security.cs.disable-library-validation`**, mas **em vez de** **desabilitar diretamente** a validação de bibliotecas, ele permite que o processo **chame a syscall `csops` para desabilitá-la**.\
Check [**this for more info**](https://theevilbit.github.io/posts/com.apple.private.security.clear-library-validation/).

### `com.apple.security.cs.allow-dyld-environment-variables`

Este entitlement permite **usar variáveis de ambiente DYLD** que podem ser usadas para injetar bibliotecas e código. Check [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables).

### `com.apple.private.tcc.manager` or `com.apple.rootless.storage`.`TCC`

[**According to this blog**](https://objective-see.org/blog/blog_0x4C.html) **and** [**this blog**](https://wojciechregula.blog/post/play-the-music-and-bypass-tcc-aka-cve-2020-29621/), esses entitlements permitem **modificar** o banco de dados do **TCC**.

### **`system.install.apple-software`** and **`system.install.apple-software.standar-user`**

Esses entitlements permitem **instalar software sem pedir permissões** ao usuário, o que pode ser útil para uma **elevação de privilégio**.

### `com.apple.private.security.kext-management`

Entitlement necessário para solicitar ao **kernel o carregamento de uma kernel extension**.

### **`com.apple.private.icloud-account-access`**

Com o entitlement **`com.apple.private.icloud-account-access`** é possível comunicar-se com o serviço XPC **`com.apple.iCloudHelper`**, que irá **fornecer tokens iCloud**.

**iMovie** e **Garageband** tinham esse entitlement.

Para mais **informações** sobre o exploit para **obter tokens iCloud** a partir desse entitlement veja a palestra: [**#OBTS v5.0: "What Happens on your Mac, Stays on Apple's iCloud?!" - Wojciech Regula**](https://www.youtube.com/watch?v=_6e2LhmxVc0)

### `com.apple.private.tcc.manager.check-by-audit-token`

TODO: Não sei o que isso permite fazer

### `com.apple.private.apfs.revert-to-snapshot`

TODO: In [**this report**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **é mencionado que isto poderia ser usado para** atualizar os conteúdos protegidos por SSV após um reboot. Se você souber como, envie um PR por favor!

### `com.apple.private.apfs.create-sealed-snapshot`

TODO: In [**this report**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) **é mencionado que isto poderia ser usado para** atualizar os conteúdos protegidos por SSV após um reboot. Se você souber como, envie um PR por favor!

### `keychain-access-groups`

Este entitlement lista grupos do **keychain** aos quais o aplicativo tem acesso:
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

Concede permissões de **Full Disk Access**, uma das permissões mais altas do TCC que você pode ter.

### **`kTCCServiceAppleEvents`**

Permite que o app envie eventos para outras aplicações que são comumente usadas para **automatizar tarefas**. Ao controlar outros apps, pode abusar das permissões concedidas a esses apps.

Como fazê-los solicitar ao usuário a sua senha:
```bash
osascript -e 'tell app "App Store" to activate' -e 'tell app "App Store" to activate' -e 'tell app "App Store" to display dialog "App Store requires your password to continue." & return & return default answer "" with icon 1 with hidden answer with title "App Store Alert"'
```
Ou fazê-los executar **ações arbitrárias**.

### **`kTCCServiceEndpointSecurityClient`**

Permite, entre outras permissões, **escrever o banco de dados TCC do usuário**.

### **`kTCCServiceSystemPolicySysAdminFiles`**

Permite **alterar** o atributo **`NFSHomeDirectory`** de um usuário, o que muda o caminho da sua home e, portanto, permite **contornar o TCC**.

### **`kTCCServiceSystemPolicyAppBundles`**

Permite modificar arquivos dentro do bundle de apps (dentro de app.app), o que é **proibido por padrão**.

<figure><img src="../../../images/image (31).png" alt=""><figcaption></figcaption></figure>

É possível verificar quem tem esse acesso em _Configurações do Sistema_ > _Privacidade & Security_ > _App Management._

### `kTCCServiceAccessibility`

O processo poderá **abusar dos recursos de acessibilidade do macOS**, o que significa, por exemplo, que ele poderá simular pressionamento de teclas. Assim, ele poderia solicitar acesso para controlar um app como o Finder e aprovar o diálogo com essa permissão.

## Entitlements relacionados ao Trustcache/CDhash

Existem alguns entitlements que podem ser usados para contornar as proteções Trustcache/CDhash, que evitam a execução de versões rebaixadas de binários da Apple.

## Médio

### `com.apple.security.cs.allow-jit`

Esse entitlement permite **criar memória que seja gravável e executável** passando a flag `MAP_JIT` para a função de sistema `mmap()`. Veja [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-jit).

### `com.apple.security.cs.allow-unsigned-executable-memory`

Esse entitlement permite **sobrescrever ou patchar código C**, usar o já obsoleto **`NSCreateObjectFileImageFromMemory`** (que é fundamentalmente inseguro), ou usar o framework **DVDPlayback**. Veja [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-unsigned-executable-memory).

> [!CAUTION]
> Incluir esse entitlement expõe seu app a vulnerabilidades comuns em linguagens inseguras quanto à memória. Considere cuidadosamente se seu app precisa dessa exceção.

### `com.apple.security.cs.disable-executable-page-protection`

Esse entitlement permite **modificar seções dos seus próprios arquivos executáveis** no disco de forma forçada. Veja [**this for more info**](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_disable-executable-page-protection).

> [!CAUTION]
> The Disable Executable Memory Protection Entitlement é um entitlement extremo que remove uma proteção de segurança fundamental do seu app, tornando possível que um atacante reescreva o código executável do seu app sem detecção. Prefira entitlements mais restritos, se possível.

### `com.apple.security.cs.allow-relative-library-loads`

TODO

### `com.apple.private.nullfs_allow`

Esse entitlement permite montar um sistema de arquivos nullfs (proibido por padrão). Ferramenta: [**mount_nullfs**](https://github.com/JamaicanMoose/mount_nullfs/tree/master).

### `kTCCServiceAll`

De acordo com este blogpost, essa permissão TCC é geralmente encontrada na forma:
```
[Key] com.apple.private.tcc.allow-prompting
[Value]
[Array]
[String] kTCCServiceAll
```
Permite que o processo **solicite todas as permissões TCC**.

### **`kTCCServicePostEvent`**

Permite **injetar eventos sintéticos de teclado e mouse** em todo o sistema via `CGEventPost()`. Um processo com essa permissão pode simular pressionamentos de teclas, cliques do mouse e eventos de rolagem em qualquer aplicação — fornecendo efetivamente **controle remoto** da área de trabalho.

Isso é especialmente perigoso quando combinado com `kTCCServiceAccessibility` ou `kTCCServiceListenEvent`, pois permite tanto ler quanto injetar entradas.
```objc
// Inject a keystroke (Enter key)
CGEventRef keyDown = CGEventCreateKeyboardEvent(NULL, kVK_Return, true);
CGEventPost(kCGSessionEventTap, keyDown);
```
### **`kTCCServiceListenEvent`**

Permite **interceptar todos os eventos do teclado e do mouse** em todo o sistema (input monitoring / keylogging). Um processo pode registrar um `CGEventTap` para capturar cada tecla digitada em qualquer aplicação, incluindo senhas, números de cartão de crédito e mensagens privadas.

For detailed exploitation techniques see:

{{#ref}}
macos-input-monitoring-screen-capture-accessibility.md
{{#endref}}

### **`kTCCServiceScreenCapture`**

Permite **ler o buffer de exibição** — tirar capturas de tela e gravar vídeo da tela de qualquer aplicação, incluindo campos de texto seguros. Combinado com OCR, isso pode extrair automaticamente senhas e dados sensíveis da tela.

> [!WARNING]
> A partir do macOS Sonoma, a captura de tela exibe um indicador persistente na barra de menus. Em versões mais antigas, a gravação de tela pode ser completamente silenciosa.

### **`kTCCServiceCamera`**

Permite **capturar fotos e vídeo** da câmera integrada ou de câmeras USB conectadas. Injeção de código em um binário com entitlement de câmera possibilita vigilância visual silenciosa.

### **`kTCCServiceMicrophone`**

Permite **gravar áudio** de todos os dispositivos de entrada. Daemons em segundo plano com acesso ao microfone fornecem vigilância de áudio ambiente persistente sem janela de aplicação visível.

### **`kTCCServiceLocation`**

Permite consultar a **localização física** do dispositivo via triangulação por Wi‑Fi ou beacons Bluetooth. Monitoramento contínuo revela endereços de casa/trabalho, padrões de viagem e rotinas diárias.

### **`kTCCServiceAddressBook`** / **`kTCCServiceCalendar`** / **`kTCCServicePhotos`**

Acesso a **Contacts** (nomes, emails, telefones — útil para spear-phishing), **Calendar** (agendas de reuniões, listas de participantes) e **Photos** (fotos pessoais, capturas de tela que podem conter credenciais, metadados de localização).

For complete credential theft exploitation techniques via TCC permissions, see:

{{#ref}}
macos-tcc/macos-tcc-credential-and-data-theft.md
{{#endref}}

## Sandbox & Code Signing Entitlements

### `com.apple.security.temporary-exception.mach-lookup.global-name`

**Sandbox temporary exceptions** enfraquecem o App Sandbox permitindo comunicação com serviços Mach/XPC de todo o sistema que o sandbox normalmente bloqueia. Este é o principal primitivo de escape do sandbox — uma aplicação em sandbox comprometida pode usar exceções mach-lookup para alcançar daemons privilegiados e explorar suas interfaces XPC.
```bash
# Find apps with mach-lookup exceptions
find /Applications -name "*.app" -exec sh -c '
binary="$1/Contents/MacOS/$(defaults read "$1/Contents/Info.plist" CFBundleExecutable 2>/dev/null)"
[ -f "$binary" ] && codesign -d --entitlements - "$binary" 2>&1 | grep -q "mach-lookup" && echo "$(basename "$1")"
' _ {} \; 2>/dev/null
```
Para a cadeia de exploração detalhada: sandboxed app → mach-lookup exception → vulnerable daemon → sandbox escape, veja:

{{#ref}}
macos-code-signing-weaknesses-and-sandbox-escapes.md
{{#endref}}

### `com.apple.developer.driverkit`

**DriverKit entitlements** permitem que binários de driver em espaço de usuário comuniquem-se diretamente com o kernel através das interfaces IOKit. Binários DriverKit gerenciam hardware: USB, Thunderbolt, PCIe, dispositivos HID, áudio e rede.

Comprometer um binário DriverKit permite:
- **Kernel attack surface** por chamadas malformadas `IOConnectCallMethod`
- **USB device spoofing** (emular um teclado para HID injection)
- **DMA attacks** através de interfaces PCIe/Thunderbolt
```bash
# Find DriverKit binaries
find / -name "*.dext" -type d 2>/dev/null
systemextensionsctl list
```
Para exploitation detalhada de IOKit/DriverKit, veja:

{{#ref}}
../mac-os-architecture/macos-iokit.md
{{#endref}}



{{#include ../../../banners/hacktricks-training.md}}
