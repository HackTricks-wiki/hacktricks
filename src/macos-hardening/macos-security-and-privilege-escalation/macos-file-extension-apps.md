# Manipuladores de extensões de arquivo e esquemas de URL de apps do macOS

{{#include ../../banners/hacktricks-training.md}}

## Banco de dados do LaunchServices

Este é um banco de dados de todos os aplicativos instalados no macOS, que pode ser consultado para obter informações sobre cada aplicativo instalado, como **esquemas de URL**, **tipos de documentos**, **UTIs** e manipuladores padrão.

É possível despejar este banco de dados com:

```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```

Ou usando a ferramenta [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

**`/usr/libexec/lsd`** é o cérebro do banco de dados. Ele fornece **vários serviços XPC**, como `.lsd.installation`, `.lsd.open`, `.lsd.openurl` e outros. Mas também **exige alguns entitlements** dos aplicativos para que possam usar as funcionalidades XPC expostas, como `.launchservices.changedefaulthandler` ou `.launchservices.changeurlschemehandler`, para alterar os aplicativos padrão para tipos MIME ou esquemas de URL, entre outros.

**`/System/Library/CoreServices/launchservicesd`** reivindica o serviço `com.apple.coreservices.launchservicesd` e pode ser consultado para obter informações sobre aplicativos em execução. Ele pode ser consultado com a ferramenta do sistema **`/usr/bin/lsappinfo`** ou com [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

Do ponto de vista de um operador, tenha em mente que geralmente há **duas visualizações úteis**:

- O **banco de dados de registro** gerenciado pelo LaunchServices / `lsd` (respaldado por arquivos `.csstore`).
- Os **padrões efetivos por usuário** armazenados em `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist`, dentro do array `LSHandlers`.

Essa distinção importa: um aplicativo pode estar **registrado** como capaz de manipular um tipo ou esquema, mas o **padrão atual** ainda pode ser outro bundle ID.

Nas versões recentes do macOS, a descoberta de registros não se limita a `/Applications`: aplicativos em outras pastas acessíveis e visíveis pelo Spotlight, assim como em volumes montados/compartilhados, podem entrar no registro. Portanto, durante a triagem, preserve as informações de `path` e volume de `lsregister -dump` e não presuma que cancelar o registro de um aplicativo seja algo duradouro enquanto o bundle continuar visível.<sup>[[4]](#references)</sup>

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

## Enumerando manipuladores efetivos

O arquivo mais útil para os **padrões do usuário atual** geralmente é:

```bash
~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist
```

Para extrair os handlers de **URL scheme** dele:

```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
  jq '.[] | select(.LSHandlerURLScheme != null) |
      {scheme: .LSHandlerURLScheme, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```

Para despejar handlers de **content-type / UTI**:

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

### Substituições `Open With` por arquivo

A resolução do handler também tem uma camada **específica do arquivo**. Antes de recorrer à UTI do arquivo e ao padrão global do usuário, o LaunchServices verifica o atributo estendido `com.apple.LaunchServices.OpenWith`. O Finder o cria quando **Sempre Abrir Com** é selecionado para um arquivo; seu valor é uma lista de propriedades binária que contém um caminho de aplicativo, um identificador de bundle e um seletor de versão.<sup>[[3]](#references)</sup>

Inspecione e decodifique-o sem confiar na extensão do nome do arquivo:

```bash
xattr -px com.apple.LaunchServices.OpenWith ./suspicious.doc | xxd -r -p | plutil -p -
```

Isso é útil quando uma única isca abre com um aplicativo inesperado, embora `duti`, `dutix` ou `LSHandlers` indiquem um padrão global inofensivo. Em um laboratório controlado, o valor opaco exato pode ser copiado de um arquivo configurado pelo Finder; removê-lo restaura a resolução normal baseada no tipo:

```bash
# Clone an existing per-file association
value="$(xattr -px com.apple.LaunchServices.OpenWith ./seed.doc | tr -d '[:space:]')"
xattr -wx com.apple.LaunchServices.OpenWith "$value" ./test.doc

# Remove the override
xattr -d com.apple.LaunchServices.OpenWith ./test.doc
```

## Chaves interessantes de Info.plist

Ao fazer a triagem de um pacote de aplicativo, estas são as chaves mais importantes:

- **`CFBundleDocumentTypes`**: grupos de documentos que o pacote declara poder abrir.
- **`LSItemContentTypes`**: a forma **moderna / preferencial** de associar tipos de documentos a UTIs.
- **`LSHandlerRank`**: classificação usada pelo LaunchServices (`Owner`, `Default`, `Alternate`, `None`).
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**: esquemas URI personalizados implementados pelo aplicativo.
- **`UTExportedTypeDeclarations`**: UTIs que o aplicativo **possui**.
- **`UTImportedTypeDeclarations`**: UTIs que o aplicativo não possui, mas que deseja que o sistema reconheça.

Um comando útil para uma triagem rápida é:

```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
  rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```

Um detalhe sutil, mas importante: se **`LSItemContentTypes`** estiver presente, chaves mais antigas, como **`CFBundleTypeExtensions`**, **`CFBundleTypeMIMETypes`** e **`CFBundleTypeOSTypes`**, são, na prática, dados de compatibilidade legados. Para a resolução efetiva do handler, priorize o caminho UTI.

## Notas ofensivas

Os aplicativos não precisam ser executados para se tornarem interessantes. Um bundle `.app` descartado ou clonado pode ser **analisado automaticamente pelo `lsd` assim que é gravado em disco**, e os tipos de documento / esquemas de URL declarados nele podem ser registrados sem que o usuário jamais abra o bundle.

Isso é útil tanto para pesquisas de **persistência / hijacking** quanto para **cadeias de acesso inicial**:

- Um aplicativo malicioso pode reivindicar uma **extensão rara** ou uma **UTI personalizada** e aguardar que a vítima abra o arquivo-isca.
- Um aplicativo malicioso pode registrar um **esquema de URL personalizado** acessível por um navegador, aplicativo Electron, documento do Office, cliente de chat ou outro aplicativo auxiliar.<sup>[[1]](#references)</sup>
- Para separar a resolução padrão normal dos testes de um handler candidato específico, invoque o esquema pelo LaunchServices com `open 'targetscheme://host/path?value=test'` e, em seguida, direcione para um bundle registrado específico com `open -b com.vendor.Target 'targetscheme://host/path?value=test'`. Isso é útil para auditar como o aplicativo receptor valida e decodifica componentes de URL controlados pelo atacante.<sup>[[1]](#references)</sup>
- Se você editar um bundle de aplicativo depois de compilá-lo, poderá forçar o LaunchServices a analisá-lo novamente com:

```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```

Ao testar bundles suspeitos, preste atenção especial a:

- **`LSHandlerRank=Owner`** em tipos incomuns.
- Arrays **`CFBundleDocumentTypes`** abrangentes que reivindicam muitas extensões.
- Apps auxiliares / wrappers cujo único comportamento interessante só ocorre por meio de um handler de documentos ou URI.
- Arquivos semelhantes a atalhos (`.webloc`, `.inetloc`, `.fileloc`) que acabam sendo encaminhados ao LaunchServices. Para truques no estilo `.fileloc` e aspectos relacionados ao Gatekeeper, consulte [esta outra página](macos-security-protections/macos-fs-tricks/README.md).<sup>[[2]](#references)</sup>

Se o seu objetivo é a execução passiva de código apenas ao navegar até uma pasta ou selecionar um arquivo, consulte também a página específica sobre [geradores do Quick Look](macos-proces-abuse/macos-quicklook-generators.md), pois essa é uma superfície de handler de arquivos diferente, mas estreitamente relacionada.



## References

- [1] [Objective-See - Exploração remota de Macs por meio de esquemas de URL personalizados](https://objective-see.org/blog/blog_0x38.html)
- [2] [Jamf Threat Labs - Bypass do Gate: uma análise mais detalhada das falhas do Gatekeeper no macOS](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)
- [3] [The Eclectic Light Company - Como o macOS abre um arquivo no app correto](https://eclecticlight.co/2024/04/10/how-macos-opens-a-file-in-the-correct-app/)
- [4] [The Eclectic Light Company - Como controlar o LaunchServices no macOS Sequoia](https://eclecticlight.co/2025/03/27/controlling-launchservices-in-macos-sequoia/)
{{#include ../../banners/hacktricks-training.md}}
