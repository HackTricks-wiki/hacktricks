# Manipuladores de Aplicativos de Extensão de Arquivo e Esquema de URL do macOS

{{#include ../../banners/hacktricks-training.md}}

## Banco de Dados LaunchServices

Este é um banco de dados de todos os aplicativos instalados no macOS que pode ser consultado para obter informações sobre cada aplicativo instalado, como esquemas de URL que ele suporta e tipos MIME.

É possível despejar este banco de dados com:
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
Ou usando a ferramenta [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

**`/usr/libexec/lsd`** é o cérebro do banco de dados. Ele fornece **vários serviços XPC** como `.lsd.installation`, `.lsd.open`, `.lsd.openurl`, e mais. Mas também **requer algumas permissões** para que os aplicativos possam usar as funcionalidades XPC expostas, como `.launchservices.changedefaulthandler` ou `.launchservices.changeurlschemehandler` para mudar aplicativos padrão para tipos mime ou esquemas de url e outros.

**`/System/Library/CoreServices/launchservicesd`** reivindica o serviço `com.apple.coreservices.launchservicesd` e pode ser consultado para obter informações sobre aplicativos em execução. Pode ser consultado com a ferramenta do sistema /**`usr/bin/lsappinfo`** ou com [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

## Manipuladores de aplicativos de extensão de arquivo e esquema de URL

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
Você também pode verificar as extensões suportadas por um aplicativo fazendo:
```
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
{{#include ../../banners/hacktricks-training.md}}
