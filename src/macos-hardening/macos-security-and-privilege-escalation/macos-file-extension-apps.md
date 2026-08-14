# Aplicativos manipuladores de extensões de arquivo e esquemas de URL do macOS

{{#include ../../banners/hacktricks-training.md}}

## Banco de dados do LaunchServices

Este é um banco de dados de todos os aplicativos instalados no macOS que pode ser consultado para obter informações sobre cada aplicativo instalado, como **URL schemes**, **document types**, **UTIs** e manipuladores padrão.

É possível despejar este banco de dados com:
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
Ou usando a ferramenta [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

**`/usr/libexec/lsd`** é o cérebro do banco de dados. Ele fornece **vários serviços XPC**, como `.lsd.installation`, `.lsd.open`, `.lsd.openurl` e outros. Porém, ele também **exige alguns entitlements** para que os aplicativos possam usar as funcionalidades XPC expostas, como `.launchservices.changedefaulthandler` ou `.launchservices.changeurlschemehandler` para alterar os aplicativos padrão de tipos MIME ou esquemas de URL, entre outros.

**`/System/Library/CoreServices/launchservicesd`** registra o serviço `com.apple.coreservices.launchservicesd` e pode ser consultado para obter informações sobre aplicativos em execução. Ele pode ser consultado com a ferramenta do sistema **`/usr/bin/lsappinfo`** ou com o [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

Do ponto de vista de um operador, lembre-se de que geralmente existem **duas visões úteis**:

- O **banco de dados de registro** gerenciado pelo LaunchServices / `lsd` (respaldado por arquivos `.csstore`).
- Os **padrões efetivos por usuário** armazenados em `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist`, dentro do array `LSHandlers`.

Essa distinção é importante: um aplicativo pode estar **registrado** como capaz de lidar com um tipo ou esquema, mas o **padrão atual** ainda pode ser outro bundle ID.

Nas versões recentes do macOS, a descoberta de registros não se limita a `/Applications`: aplicativos em outras pastas visíveis pelo Spotlight e acessíveis, além de volumes montados/compartilhados, podem entrar no registro. Portanto, preserve as informações de `path` e do volume provenientes de `lsregister -dump` durante a triagem e não presuma que remover o registro de um aplicativo seja durável enquanto o bundle permanecer descobrível.<sup>[[4]](#references)</sup>

## Manipuladores de aplicativos para extensões de arquivo e esquemas de URL

A linha a seguir pode ser útil para encontrar os aplicativos que podem abrir arquivos com base na extensão:
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump | grep -E "path:|bindings:|name:"
```
Ou use algo como [**SwiftDefaultApps**](https://github.com/Lord-Kamina/SwiftDefaultApps):
```bash
./swda getSchemes #Get all the available schemes
./swda getApps #Get all the apps declared
./swda getUTIs #Get all the UTIs
./swda getHandler --URL ftp #Get ftp handler
```
Você também pode verificar as extensões compatíveis com um aplicativo fazendo:
```bash
cd /Applications/Safari.app/Contents
grep -A3 CFBundleTypeExtensions Info.plist  | grep string
<string>css</string>
<string>pdf</string>
<string>webarchive</string>
<string>webbookmark</string>
<string>webhistory</string>
<string>webloc</string>
<string>download</string>
<string>safariextz</string>
<string>gif</string>
<string>html</string>
<string>htm</string>
<string>js</string>
<string>jpg</string>
<string>jpeg</string>
<string>jp2</string>
<string>txt</string>
<string>text</string>
<string>png</string>
<string>tiff</string>
<string>tif</string>
<string>url</string>
<string>ico</string>
<string>xhtml</string>
<string>xht</string>
<string>xml</string>
<string>xbl</string>
<string>svg</string>
```
## Enumerando handlers efetivos

O arquivo mais útil para os **padrões do usuário atual** geralmente é:
```bash
~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist
```
Para extrair os **handlers** de **URL scheme** dele:
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerURLScheme != null) |
{scheme: .LSHandlerURLScheme, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
Para extrair os manipuladores de **content-type / UTI**:
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerContentType != null) |
{uti: .LSHandlerContentType, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
Para resolver a árvore UTI de um arquivo de amostra:
```bash
mdls -name kMDItemContentType -name kMDItemContentTypeTree ./sample.pdf
```
Se você quiser uma CLI mais amigável para consultar ou alterar os padrões:
```bash
# Classic tool
# https://github.com/moretension/duti
duti -x jpg                    # Show current default for extension
duti -s com.apple.Safari public.html all
duti -s com.apple.Finder ftp   # Set default for ftp://

# Newer tool
# https://github.com/jackchuka/dutix
dutix targets show public.html
dutix targets show ftp
dutix apps show Safari
```
### Substituições `Open With` por arquivo

A resolução do handler também tem uma camada **específica do arquivo**. Antes de recorrer à UTI do arquivo e ao padrão global do usuário, o LaunchServices verifica o atributo estendido `com.apple.LaunchServices.OpenWith`. O Finder o cria quando **Always Open With** é selecionado para um arquivo; seu valor é uma property list binária contendo um caminho de aplicativo, um identificador de bundle e um seletor de versão.<sup>[[3]](#references)</sup>

Inspecione e decodifique-o sem confiar na extensão do nome do arquivo:
```bash
xattr -px com.apple.LaunchServices.OpenWith ./suspicious.doc | xxd -r -p | plutil -p -
```
Isso é útil quando um único lure é aberto com um aplicativo inesperado, mesmo que `duti`, `dutix` ou `LSHandlers` indiquem um padrão global benigno. Em um laboratório controlado, o valor opaco exato pode ser copiado de um arquivo configurado pelo Finder; excluí-lo restaura a resolução normal baseada no tipo:
```bash
# Clone an existing per-file association
value="$(xattr -px com.apple.LaunchServices.OpenWith ./seed.doc | tr -d '[:space:]')"
xattr -wx com.apple.LaunchServices.OpenWith "$value" ./test.doc

# Remove the override
xattr -d com.apple.LaunchServices.OpenWith ./test.doc
```
## Chaves interessantes do Info.plist

Ao fazer a triagem de um application bundle, estas chaves são as mais importantes:

- **`CFBundleDocumentTypes`**: grupos de documentos que o bundle declara poder abrir.
- **`LSItemContentTypes`**: forma **moderna / preferida** de associar tipos de documentos a UTIs.
- **`LSHandlerRank`**: classificação usada pelo LaunchServices (`Owner`, `Default`, `Alternate`, `None`).
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**: esquemas de URI personalizados implementados pelo app.
- **`UTExportedTypeDeclarations`**: UTIs que o app **possui**.
- **`UTImportedTypeDeclarations`**: UTIs que o app não possui, mas que deseja que o sistema reconheça.

Um comando útil para uma triagem rápida é:
```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```
Um detalhe sutil, mas importante: se **`LSItemContentTypes`** estiver presente, chaves mais antigas como **`CFBundleTypeExtensions`**, **`CFBundleTypeMIMETypes`** e **`CFBundleTypeOSTypes`** são efetivamente dados legados de compatibilidade. Para a resolução real de handlers, priorize primeiro o caminho UTI.

## Notas ofensivas

Os aplicativos não precisam ser executados para se tornarem interessantes. Um bundle `.app` solto ou clonado pode ser **analisado automaticamente pelo `lsd` assim que é gravado no disco**, e seus tipos de documentos / URL schemes declarados podem ser registrados sem que o usuário jamais inicie o bundle.

Isso é útil tanto para **pesquisa de persistence / hijacking** quanto para **initial-access chains**:

- Um app malicioso pode reivindicar uma **extensão rara** ou uma **custom UTI** e aguardar a vítima abrir o arquivo-lure.
- Um app malicioso pode registrar uma **custom URL scheme** acessível a partir de um navegador, app Electron, documento do Office, chat client ou outro helper app.<sup>[[1]](#references)</sup>
- Para separar a resolução normal padrão do teste de um handler candidato específico, invoque o scheme por meio do LaunchServices com `open 'targetscheme://host/path?value=test'` e, em seguida, direcione para um bundle registrado específico com `open -b com.vendor.Target 'targetscheme://host/path?value=test'`. Isso é útil para auditar como o app receptor valida e decodifica componentes de URL controlados pelo atacante.<sup>[[1]](#references)</sup>
- Se você editar um app bundle depois de compilá-lo, poderá forçar o LaunchServices a analisá-lo novamente com:
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```
Ao testar bundles suspeitos, preste atenção especial a:

- **`LSHandlerRank=Owner`** em tipos incomuns.
- Arrays **`CFBundleDocumentTypes`** amplos que reivindicam muitas extensões.
- Apps **helper / wrapper** cujo único comportamento interessante está por trás de um handler de documento ou URI.
- Arquivos semelhantes a atalhos (`.webloc`, `.inetloc`, `.fileloc`) que acabam sendo direcionados para o LaunchServices. Para truques no estilo `.fileloc` e aspectos relacionados ao Gatekeeper, consulte [esta outra página](macos-security-protections/macos-fs-tricks/README.md).<sup>[[2]](#references)</sup>

Se o seu objetivo for obter code execution passiva apenas navegando até uma pasta ou selecionando um arquivo, consulte também a página dedicada a [geradores do Quick Look](macos-proces-abuse/macos-quicklook-generators.md), pois essa é uma superfície de file handler diferente, mas estreitamente relacionada.



## References

- [1] [Objective-See - Exploração remota de Mac via esquemas de URL personalizados](https://objective-see.org/blog/blog_0x38.html)
- [2] [Jamf Threat Labs - Contornando o Gate: uma análise mais detalhada das falhas do Gatekeeper no macOS](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)
- [3] [The Eclectic Light Company - Como o macOS abre um arquivo no app correto](https://eclecticlight.co/2024/04/10/how-macos-opens-a-file-in-the-correct-app/)
- [4] [The Eclectic Light Company - Controlando o LaunchServices no macOS Sequoia](https://eclecticlight.co/2025/03/27/controlling-launchservices-in-macos-sequoia/)
{{#include ../../banners/hacktricks-training.md}}
