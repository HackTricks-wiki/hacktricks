# Aplicativos de macOS para extensões de arquivo e handlers de esquemas de URL

{{#include ../../banners/hacktricks-training.md}}

## Banco de dados do LaunchServices

Este é um banco de dados de todos os aplicativos instalados no macOS, que pode ser consultado para obter informações sobre cada aplicativo instalado, como **URL schemes**, **document types**, **UTIs** e handlers padrão.

É possível fazer o dump deste banco de dados com:
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
Ou usando a ferramenta [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

**`/usr/libexec/lsd`** é o cérebro do banco de dados. Ele fornece **vários serviços XPC**, como `.lsd.installation`, `.lsd.open`, `.lsd.openurl` e outros. Mas também **exige alguns entitlements** dos aplicativos para que possam usar as funcionalidades XPC expostas, como `.launchservices.changedefaulthandler` ou `.launchservices.changeurlschemehandler` para alterar os aplicativos padrão para tipos MIME ou esquemas de URL, entre outros.

**`/System/Library/CoreServices/launchservicesd`** reivindica o serviço `com.apple.coreservices.launchservicesd` e pode ser consultado para obter informações sobre os aplicativos em execução. Ele pode ser consultado com a ferramenta do sistema **`/usr/bin/lsappinfo`** ou com [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

Do ponto de vista de um operador, tenha em mente que geralmente há **duas visualizações úteis**:

- O **banco de dados de registro** gerenciado pelo LaunchServices / `lsd` (armazenado em arquivos `.csstore`).
- Os **padrões efetivos por usuário** armazenados em `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist`, dentro do array `LSHandlers`.

Essa distinção é importante: um aplicativo pode estar **registrado** como capaz de lidar com um tipo ou esquema, mas o **padrão atual** ainda pode ser outro bundle ID.

## Handlers de aplicativos para extensões de arquivos e esquemas de URL

A linha a seguir pode ser útil para encontrar os aplicativos que podem abrir arquivos dependendo da extensão:
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
Para obter os **handlers de URL scheme** dele:
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerURLScheme != null) |
{scheme: .LSHandlerURLScheme, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
Para despejar os handlers de **content-type / UTI**:
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerContentType != null) |
{uti: .LSHandlerContentType, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
Para resolver a árvore UTI de um arquivo de exemplo:
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
## Chaves interessantes do Info.plist

Ao fazer a triagem de um application bundle, estas chaves são as mais importantes:

- **`CFBundleDocumentTypes`**: grupos de documentos que o bundle declara poder abrir.
- **`LSItemContentTypes`**: forma **moderna / preferida** de associar tipos de documentos a UTIs.
- **`LSHandlerRank`**: classificação usada pelo LaunchServices (`Owner`, `Default`, `Alternate`, `None`).
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**: URI schemes personalizados implementados pelo app.
- **`UTExportedTypeDeclarations`**: UTIs que o app **possui**.
- **`UTImportedTypeDeclarations`**: UTIs que o app não possui, mas que deseja que o sistema reconheça.

Um comando útil para uma triagem rápida é:
```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```
Um detalhe sutil, mas importante: se **`LSItemContentTypes`** estiver presente, chaves mais antigas como **`CFBundleTypeExtensions`**, **`CFBundleTypeMIMETypes`** e **`CFBundleTypeOSTypes`** são efetivamente dados de compatibilidade legados. Para a resolução real de handlers, priorize primeiro o caminho UTI.

## Notas ofensivas

Os aplicativos não precisam ser executados para se tornarem interessantes. Um bundle `.app` descartado ou clonado pode ser **analisado automaticamente pelo `lsd` assim que é gravado no disco**, e seus tipos de documentos / esquemas de URL declarados podem ser registrados sem que o usuário jamais inicie o bundle.

Isso é útil tanto para **pesquisa de persistência / hijacking** quanto para **cadeias de acesso inicial**:

- Um aplicativo malicioso pode reivindicar uma **extensão rara** ou uma **UTI personalizada** e aguardar a vítima abrir o arquivo-isca.
- Um aplicativo malicioso pode registrar um **esquema de URL personalizado** acessível a partir de um navegador, aplicativo Electron, documento do Office, cliente de chat ou outro aplicativo auxiliar.<sup>[[1]](#references)</sup>
- Se você editar um bundle de aplicativo depois de compilá-lo, poderá forçar o LaunchServices a analisá-lo novamente com:
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```
Ao testar bundles suspeitos, preste atenção especial a:

- **`LSHandlerRank=Owner`** em tipos incomuns.
- Arrays **`CFBundleDocumentTypes`** amplos, reivindicando muitas extensões.
- Apps **helper / wrapper** cujo único comportamento interessante está por trás de um document ou URI handler.
- Arquivos semelhantes a atalhos (`.webloc`, `.inetloc`, `.fileloc`) que acabam sendo encaminhados ao LaunchServices. Para truques no estilo `.fileloc` e outros vetores relacionados ao Gatekeeper, consulte [esta outra página](macos-security-protections/macos-fs-tricks/README.md).<sup>[[2]](#references)</sup>

Se o seu objetivo for obter execução de código passiva apenas ao navegar até uma pasta ou selecionar um arquivo, consulte também a página dedicada a [Quick Look generators](macos-proces-abuse/macos-quicklook-generators.md), pois essa é uma superfície de file-handler diferente, mas estreitamente relacionada.

## Referências


- [1] [Objective-See - Exploração remota de Mac via Custom URL Schemes](https://objective-see.org/blog/blog_0x38.html)
- [2] [Jamf Threat Labs - Bypassing the Gate: Uma análise mais detalhada das falhas do Gatekeeper no macOS](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)

{{#include ../../banners/hacktricks-training.md}}
