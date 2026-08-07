# Bundles do macOS

{{#include ../../../banners/hacktricks-training.md}}

## Informações básicas

Os bundles no macOS funcionam como contêineres para diversos recursos, incluindo aplicações, bibliotecas e outros arquivos necessários, fazendo com que apareçam como objetos únicos no Finder, como os conhecidos arquivos `*.app`. O bundle mais comum é o bundle `.app`, embora outros tipos, como `.framework`, `.systemextension` e `.kext`, também sejam frequentes.

### Componentes essenciais de um bundle

Dentro de um bundle, especialmente no diretório `<application>.app/Contents/`, vários recursos importantes são armazenados:

- **\_CodeSignature**: Este diretório armazena detalhes da assinatura de código, essenciais para verificar a integridade da aplicação. Você pode inspecionar as informações de assinatura de código usando comandos como:
```bash
openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64
```
- **MacOS**: Contém o binário executável do aplicativo, que é executado após a interação do usuário.
- **Resources**: Repositório dos componentes da interface do usuário do aplicativo, incluindo imagens, documentos e descrições da interface (arquivos nib/xib).
- **Info.plist**: Atua como o principal arquivo de configuração do aplicativo, sendo essencial para que o sistema reconheça e interaja adequadamente com o aplicativo.

#### Chaves importantes em Info.plist

O arquivo `Info.plist` é fundamental para a configuração do aplicativo e contém chaves como:

- **CFBundleExecutable**: Especifica o nome do arquivo executável principal localizado no diretório `Contents/MacOS`.
- **CFBundleIdentifier**: Fornece um identificador global para o aplicativo, usado extensivamente pelo macOS para o gerenciamento de aplicativos.
- **LSMinimumSystemVersion**: Indica a versão mínima do macOS necessária para executar o aplicativo.

### Explorando Bundles

Para explorar o conteúdo de um bundle, como `Safari.app`, o seguinte comando pode ser usado: `bash ls -lR /Applications/Safari.app/Contents`

Essa exploração revela diretórios como `_CodeSignature`, `MacOS`, `Resources` e arquivos como `Info.plist`, cada um com uma finalidade específica, desde proteger o aplicativo até definir sua interface do usuário e seus parâmetros operacionais.

#### Diretórios adicionais de Bundles

Além dos diretórios comuns, os bundles também podem incluir:

- **Frameworks**: Contém os frameworks incluídos usados pelo aplicativo. Frameworks são semelhantes a dylibs, mas com recursos adicionais.
- **PlugIns**: Diretório para plug-ins e extensões que aprimoram os recursos do aplicativo.
- **XPCServices**: Contém serviços XPC usados pelo aplicativo para comunicação fora do processo.

Essa estrutura garante que todos os componentes necessários estejam encapsulados no bundle, facilitando um ambiente de aplicativo modular e seguro.

Para obter informações mais detalhadas sobre as chaves de `Info.plist` e seus significados, a documentação para desenvolvedores da Apple fornece recursos abrangentes: [Apple Info.plist Key Reference](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html).<sup>[[3]](#references)</sup>

## Notas de segurança e vetores de abuso

- **Gatekeeper / App Translocation**: Quando um bundle em quarentena é executado pela primeira vez, o macOS realiza uma verificação profunda da assinatura e pode executá-lo a partir de um caminho translocado aleatório. Depois de aceito, os lançamentos seguintes realizam apenas verificações superficiais; historicamente, os arquivos de recursos em `Resources/`, `PlugIns/`, nibs etc. não eram verificados. Desde o macOS 13 Ventura, uma verificação profunda é aplicada na primeira execução, e a nova permissão TCC *App Management* restringe processos de terceiros de modificar outros bundles sem o consentimento do usuário, mas sistemas mais antigos continuam vulneráveis.
- **Colisões de Bundle Identifier**: Vários targets incorporados (PlugIns, ferramentas auxiliares) que reutilizam o mesmo `CFBundleIdentifier` podem interromper a validação da assinatura e, ocasionalmente, permitir o sequestro/confusão de esquemas de URL. Sempre enumere os sub-bundles e verifique se os IDs são exclusivos.

## Resource Hijacking (Dirty NIB / NIB Injection)

Antes do Ventura, substituir recursos de UI em um aplicativo assinado podia contornar a assinatura de código superficial e resultar em execução de código com os entitlements do aplicativo. Pesquisas atuais (2024) mostram que isso ainda funciona em sistemas anteriores ao Ventura e em builds sem quarentena:<sup>[[1]](#references)[[2]](#references)</sup>

1. Copie o aplicativo-alvo para um local com permissão de escrita (por exemplo, `/tmp/Victim.app`).
2. Substitua `Contents/Resources/MainMenu.nib` (ou qualquer nib declarado em `NSMainNibFile`) por um nib malicioso que instancie `NSAppleScript`, `NSTask` etc.
3. Execute o aplicativo. O nib malicioso é executado sob o bundle ID e os entitlements da vítima (concessões de TCC, microfone/câmera etc.).
4. O Ventura+ aplica como mitigação uma verificação profunda do bundle no primeiro lançamento e exige a permissão *App Management* para modificações posteriores; portanto, a persistência é mais difícil, mas ataques no lançamento inicial em versões mais antigas do macOS ainda são possíveis.<sup>[[1]](#references)</sup>

Exemplo mínimo de payload de nib malicioso (compile xib para nib com `ibtool`):
```bash
# create a nib that runs osascript -e 'do shell script "id"'
# ...build xib in Xcode, then
ibtool --compile MainMenu.nib MainMenu.xib
cp MainMenu.nib /tmp/Victim.app/Contents/Resources/
open /tmp/Victim.app
```
## Framework / PlugIn / dylib Hijacking dentro de Bundles

Como as buscas por `@rpath` dão preferência a Frameworks/PlugIns incluídos no bundle, inserir uma library maliciosa em `Contents/Frameworks/` ou `Contents/PlugIns/` pode redirecionar a ordem de carregamento quando o binário principal é assinado sem library validation ou com uma ordenação fraca de `LC_RPATH`.

Etapas típicas ao abusar de um bundle unsigned/ad-hoc:
```bash
cp evil.dylib /tmp/Victim.app/Contents/Frameworks/
install_name_tool -add_rpath @executable_path/../Frameworks /tmp/Victim.app/Contents/MacOS/Victim
# or patch an existing load command
install_name_tool -change @rpath/Legit.dylib @rpath/evil.dylib /tmp/Victim.app/Contents/MacOS/Victim
codesign -f -s - --timestamp=none /tmp/Victim.app/Contents/Frameworks/evil.dylib
codesign -f -s - --deep --timestamp=none /tmp/Victim.app
open /tmp/Victim.app
```
Notes:
- O hardened runtime com `com.apple.security.cs.disable-library-validation` ausente bloqueia dylibs de terceiros; verifique os entitlements primeiro.
- Os serviços XPC em `Contents/XPCServices/` frequentemente carregam frameworks irmãos — aplique patches aos binários deles de forma semelhante para obter persistência ou caminhos de privilege escalation.

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

- [1] [Trazendo a process injection para view(s): explorando apps macOS usando arquivos nib (2024)](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)
- [2] [Relato sobre adulteração de recursos de NIB & bundle (2024)](https://karol-mazurek.medium.com/snake-apple-app-bundle-ext-f5c43a3c84c4)
- [3] [Apple Developer - Referência de chaves do Info.plist da Apple](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html)

{{#include ../../../banners/hacktricks-training.md}}
