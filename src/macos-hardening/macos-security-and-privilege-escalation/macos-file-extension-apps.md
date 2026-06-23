# macOS File Extension & URL scheme app handlers

{{#include ../../banners/hacktricks-training.md}}

## Database do LaunchServices

Esta é uma base de dados de todos os aplicativos instalados no macOS que pode ser consultada para obter informações sobre cada aplicativo instalado, como os **URL schemes**, **document types**, **UTIs** e handlers padrão suportados.

É possível extrair esta base de dados com:
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
Ou usando a ferramenta [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

**`/usr/libexec/lsd`** é o cérebro do banco de dados. Ele fornece **vários serviços XPC** como `.lsd.installation`, `.lsd.open`, `.lsd.openurl`, e mais. Mas ele também **requer alguns entitlements** para que aplicações possam usar as funcionalidades XPC expostas, como `.launchservices.changedefaulthandler` ou `.launchservices.changeurlschemehandler` para alterar apps padrão para tipos MIME ou URL schemes e outros.

**`/System/Library/CoreServices/launchservicesd`** reivindica o serviço `com.apple.coreservices.launchservicesd` e pode ser consultado para obter informações sobre aplicações em execução. Ele pode ser consultado com a ferramenta do sistema **`/usr/bin/lsappinfo`** ou com [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

Do ponto de vista do operador, lembre-se de que normalmente existem **duas visões úteis**:

- A **registration database** gerenciada por LaunchServices / `lsd` (apoiada por arquivos `.csstore`).
- Os **effective defaults por usuário** armazenados em `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist` dentro do array `LSHandlers`.

Essa distinção importa: uma aplicação pode estar **registrada** como capaz de lidar com um tipo ou scheme, mas o **padrão atual** ainda pode ser outro bundle ID.

## File Extension & URL scheme app handlers

A seguinte linha pode ser útil para encontrar as aplicações que podem abrir arquivos dependendo da extensão:
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
Você também pode verificar as extensões suportadas por um aplicativo fazendo:
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

O arquivo mais útil para os **defaults do usuário atual** geralmente é:
```bash
~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist
```
Para extrair os handlers de **URL scheme** dele:
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerURLScheme != null) |
{scheme: .LSHandlerURLScheme, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
Para fazer dump dos handlers de **content-type / UTI**:
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerContentType != null) |
{uti: .LSHandlerContentType, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
Para resolver a árvore UTI de um arquivo de amostra:
```bash
mdls -name kMDItemContentType -name kMDItemContentTypeTree ./sample.pdf
```
Se você quiser uma CLI mais amigável para consultar ou alterar defaults:
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

Ao fazer triagem de um application bundle, estas chaves são as mais importantes:

- **`CFBundleDocumentTypes`**: grupos de documentos que o bundle afirma conseguir abrir.
- **`LSItemContentTypes`**: a forma **moderna / preferida** de vincular tipos de documento a UTIs.
- **`LSHandlerRank`**: classificação usada pelo LaunchServices (`Owner`, `Default`, `Alternate`, `None`).
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**: esquemas URI personalizados implementados pelo app.
- **`UTExportedTypeDeclarations`**: UTIs que o app **possui**.
- **`UTImportedTypeDeclarations`**: UTIs que o app não possui, mas quer que o sistema reconheça.

Um comando rápido e útil de triagem é:
```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```
Um detalhe sutil, mas importante: se **`LSItemContentTypes`** estiver presente, chaves mais antigas como **`CFBundleTypeExtensions`**, **`CFBundleTypeMIMETypes`** e **`CFBundleTypeOSTypes`** são efetivamente dados legados de compatibilidade. Para a resolução real do handler, foque primeiro no caminho UTI.

## Offensive notes

Applications não precisam ser executados para se tornarem interessantes. Um `.app` bundle descartado ou clonado pode ser **parsed automaticamente pelo `lsd` assim que é gravado no disco**, e seus tipos de documento / URL schemes declarados podem ser registrados sem que o usuário nunca inicie o bundle.

Isso é útil tanto para pesquisa de **persistence / hijacking** quanto para cadeias de **initial-access**:

- Um app malicioso pode reivindicar uma **extensão rara** ou uma **UTI customizada** e esperar a vítima abrir o arquivo isca.
- Um app malicioso pode registrar um **custom URL scheme** acessível a partir de um browser, Electron app, office document, chat client ou outro helper app.
- Se você editar um app bundle depois de construí-lo, pode forçar o LaunchServices a reanalisá-lo com:
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```
Ao testar bundles suspeitos, preste atenção especial em:

- **`LSHandlerRank=Owner`** em tipos incomuns.
- Matrizes **`CFBundleDocumentTypes`** amplas que reivindicam muitas extensões.
- Apps **helper / wrapper** cujo único comportamento interessante está atrás de um document ou URI handler.
- Arquivos no estilo **shortcut** (`.webloc`, `.inetloc`, `.fileloc`) que acabam sendo despachados para o LaunchServices. Para truques estilo `.fileloc` e ângulos relacionados ao Gatekeeper, veja [esta outra página](macos-security-protections/macos-fs-tricks/README.md).

Se o seu objetivo é code-execution passiva apenas ao navegar para uma pasta ou selecionar um arquivo, veja também a página dedicada a [Quick Look generators](macos-proces-abuse/macos-quicklook-generators.md), pois essa é uma superfície de file-handler diferente, mas intimamente relacionada.

## References

- [Objective-See - Remote Mac Exploitation Via Custom URL Schemes](https://objective-see.org/blog/blog_0x38.html)
- [Jamf Threat Labs - Bypassing the Gate: A closer look into Gatekeeper flaws on macOS](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)
{{#include ../../banners/hacktricks-training.md}}
