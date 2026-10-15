# Manipuladores de apps para extensões de arquivo e esquemas de URL do macOS

{{#include ../../banners/hacktricks-training.md}}

## Banco de dados do LaunchServices

Este é um banco de dados de todos os aplicativos instalados no macOS, que pode ser consultado para obter informações sobre cada aplicativo instalado, como **esquemas de URL** compatíveis, **tipos de documento**, **UTIs** e manipuladores padrão.

É possível despejar este banco de dados com:

```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```

Ou usando a ferramenta [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

**`/usr/libexec/lsd`** é o cérebro do banco de dados. Ele fornece **vários serviços XPC**, como `.lsd.installation`, `.lsd.open`, `.lsd.openurl` e outros. Mas também **exige alguns entitlements** dos aplicativos para que possam usar as funcionalidades XPC expostas, como `.launchservices.changedefaulthandler` ou `.launchservices.changeurlschemehandler`, para alterar os aplicativos padrão para tipos MIME ou esquemas de URL, entre outros.

**`/System/Library/CoreServices/launchservicesd`** fornece o serviço `com.apple.coreservices.launchservicesd` e pode ser consultado para obter informações sobre aplicativos em execução. Ele pode ser consultado com a ferramenta do sistema **`/usr/bin/lsappinfo`** ou com [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html).

Do ponto de vista de um operador, tenha em mente que geralmente existem **duas visualizações úteis**:

- O **banco de dados de registro** gerenciado pelo LaunchServices / `lsd` (respaldado por arquivos `.csstore`).
- Os **padrões efetivos por usuário** armazenados em `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist`, dentro do array `LSHandlers`.

Essa distinção é importante: um aplicativo pode estar **registrado** como capaz de lidar com um tipo ou esquema, mas o **padrão atual** ainda pode ser outro bundle ID.

Nas versões recentes do macOS, a descoberta de registros não se limita a `/Applications`: aplicativos em outras pastas acessíveis e visíveis pelo Spotlight, bem como em volumes montados/compartilhados, podem ser adicionados ao registro. Portanto, durante a triagem, preserve as informações de `path` e do volume de `lsregister -dump` e não presuma que o cancelamento do registro de um aplicativo será permanente enquanto o bundle continuar sendo descoberto.<sup>[[4]](#references)</sup>

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

## Enumerando os handlers efetivos

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

### Substituições de `Open With` por arquivo

A resolução do handler também tem uma camada **específica do arquivo**. Antes de recorrer ao UTI do arquivo e ao padrão global do usuário, o LaunchServices verifica o atributo estendido `com.apple.LaunchServices.OpenWith`. O Finder o cria quando **Always Open With** é selecionado para um arquivo; seu valor é uma lista de propriedades binária contendo o caminho de um aplicativo, o identificador do bundle e um seletor de versão.<sup>[[3]](#references)</sup>

Inspecione e decodifique esse atributo sem confiar na extensão do nome do arquivo:

```bash
xattr -px com.apple.LaunchServices.OpenWith ./suspicious.doc | xxd -r -p | plutil -p -
```

Isso é útil quando uma única isca é aberta por um aplicativo inesperado, embora `duti`, `dutix` ou `LSHandlers` indiquem um padrão global benigno. Em um laboratório controlado, o valor opaco exato pode ser copiado de um arquivo configurado pelo Finder; excluí-lo restaura a resolução normal baseada no tipo:

```bash
# Clone an existing per-file association
value="$(xattr -px com.apple.LaunchServices.OpenWith ./seed.doc | tr -d '[:space:]')"
xattr -wx com.apple.LaunchServices.OpenWith "$value" ./test.doc

# Remove the override
xattr -d com.apple.LaunchServices.OpenWith ./test.doc
```

## Chaves interessantes do Info.plist

Ao fazer a triagem de um bundle de aplicativo, estas chaves são as mais importantes:

- **`CFBundleDocumentTypes`**: grupos de documentos que o bundle declara que pode abrir.
- **`LSItemContentTypes`**: forma **moderna / preferencial** de associar tipos de documentos a UTIs.
- **`LSHandlerRank`**: classificação usada pelo LaunchServices (`Owner`, `Default`, `Alternate`, `None`).
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**: esquemas de URI personalizados implementados pelo aplicativo.
- **`UTExportedTypeDeclarations`**: UTIs que o aplicativo **possui**.
- **`UTImportedTypeDeclarations`**: UTIs que o aplicativo não possui, mas que deseja que o sistema reconheça.

Um comando útil para uma triagem rápida é:

```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
  rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```

Um detalhe sutil, mas importante: se **`LSItemContentTypes`** estiver presente, chaves mais antigas, como **`CFBundleTypeExtensions`**, **`CFBundleTypeMIMETypes`** e **`CFBundleTypeOSTypes`**, são efetivamente dados de compatibilidade legados. Para a resolução real de handlers, priorize o caminho de UTI.

## Notas ofensivas

Os aplicativos não precisam ser executados para que suas reivindicações de handler se tornem relevantes, mas **gravar apenas um bundle `.app` não garante o registro imediato**. O Finder pode registrar um app ao descobri-lo, inclusive quando um usuário navega até sua pasta; o registro também pode ocorrer na inicialização ou no login, ou por meio de uma chamada explícita de registro. Verifique `lsregister -dump` antes de testar uma reivindicação. O registro, por si só, não inicia o app nem o torna o handler padrão efetivo.<sup>[[5]](#references)</sup> Para os pré-requisitos de persistência, consulte [URL Scheme & File-Type Handlers](../macos-auto-start-locations.md#url-scheme--file-type-handlers-launchservices).

Isso é útil tanto para **pesquisas sobre persistência / hijacking** quanto para **cadeias de acesso inicial**:

- Um app malicioso pode reivindicar uma **extensão rara** ou uma **UTI personalizada** e aguardar a vítima abrir o arquivo-isca.
- Um app malicioso pode registrar um **esquema de URL personalizado** acessível por um navegador, app Electron, documento do Office, cliente de chat ou outro app auxiliar.<sup>[[1]](#references)</sup>
- Para distinguir a resolução padrão normal do teste de um handler candidato específico, invoque o esquema pelo LaunchServices com `open 'targetscheme://host/path?value=test'` e, em seguida, direcione a chamada a um bundle registrado específico com `open -b com.vendor.Target 'targetscheme://host/path?value=test'`. Isso é útil para auditar como o app receptor valida e decodifica componentes de URL controlados pelo atacante.<sup>[[1]](#references)</sup>
- Se você editar um bundle de app após compilá-lo, poderá forçar o LaunchServices a analisá-lo novamente com:

```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```

Ao testar bundles suspeitos, preste atenção especial a:

- **`LSHandlerRank=Owner`** em tipos incomuns.
- Arrays **`CFBundleDocumentTypes`** abrangentes que reivindicam muitas extensões.
- Apps auxiliares / wrapper cujo único comportamento interessante ocorre por meio de um handler de documentos ou URI.
- Arquivos semelhantes a atalhos (`.webloc`, `.inetloc`, `.fileloc`) que acabam sendo encaminhados ao LaunchServices. Para truques do tipo `.fileloc` e aspectos relacionados ao Gatekeeper, consulte [esta outra página](macos-security-protections/macos-fs-tricks/README.md).<sup>[[2]](#references)</sup>

### Parâmetros de URL encaminhados para opções downstream

A confirmação de protocolo externo de um navegador apenas aprova a abertura do handler; ela não torna confiáveis os parâmetros da URL. Rastreie o parser de URL do app receptor até qualquer biblioteca, mecanismo de mídia, processo auxiliar ou opção de gravação de arquivo. Procure um prefixo de chave de query que transforme campos da URL em nomes de opções downstream. Teste separadores literais e codificados em percentuais com um marcador inofensivo em uma conta descartável.<sup>[[6]](#references)</sup>

Verifique a **opção final aceita pelo componente downstream**, não apenas o parsing inicial do app. Um handler permitia que chaves de query com prefixo chegassem a comandos de entrada do mpv; bloquear essa opção ainda deixava disponível uma rota de gravação de arquivo. Teste a classe de opções acessível, não apenas uma chave perigosa conhecida.<sup>[[7]](#references)</sup>

### Handler integrado `applescript://`

O handler de URL `applescript://com.apple.scripteditor` aceita `action=new` e um parâmetro `script` codificado em URL. Portanto, um link no navegador pode abrir o Script Editor com AppleScript controlado pelo atacante já no editor, evitando uma etapa de colagem no Terminal. Isso **não é execução automática**: o navegador pode perguntar se deve abrir o Script Editor, e o usuário precisa executar o script.<sup>[[8]](#references)</sup>

Versões recentes do macOS podem exibir um aviso sobre o documento de script, enquanto o XProtect verifica o AppleScript durante a execução.<sup>[[8]](#references)[[9]](#references)</sup>

Use uma sondagem local inofensiva para verificar o handler e os avisos na versão do macOS em avaliação; ela deve apenas preencher o editor até que se clique em **Run**.<sup>[[8]](#references)</sup>

```bash
open 'applescript://com.apple.scripteditor?action=new&script=display%20dialog%20%22handler%20probe%22'
```

Se seu objetivo é executar código passivamente apenas ao navegar até uma pasta ou selecionar um arquivo, confira também a página dedicada aos [Quick Look generators](macos-proces-abuse/macos-quicklook-generators.md), pois essa é uma superfície de manipuladores de arquivos diferente, mas estreitamente relacionada.



## References

- [1] [Objective-See - Exploração remota de Mac por meio de esquemas de URL personalizados](https://objective-see.org/blog/blog_0x38.html)
- [2] [Jamf Threat Labs - Contornando o Gate: uma análise mais detalhada das falhas do Gatekeeper no macOS](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)
- [3] [The Eclectic Light Company - Como o macOS abre um arquivo no app correto](https://eclecticlight.co/2024/04/10/how-macos-opens-a-file-in-the-correct-app/)
- [4] [The Eclectic Light Company - Controlando o LaunchServices no macOS Sequoia](https://eclecticlight.co/2025/03/27/controlling-launchservices-in-macos-sequoia/)
- [5] [Apple - Conceitos do Launch Services](https://developer.apple.com/library/archive/documentation/Carbon/Conceptual/LaunchServicesConcepts/LSCConcepts/LSCConcepts.html)
- [6] [stackpointer - Pesquisa sobre execução de comandos pelo esquema de URL do IINA](https://binary.stackpointer.re/iina-142-url-scheme-command-execution)
- [7] [IINA - Tratamento inseguro de opções do mpv no esquema de URL](https://github.com/iina/iina/security/advisories/GHSA-w5xh-98j7-jp5q)
- [8] [Jamf Threat Labs - A técnica ClickFix usa o Script Editor em vez do Terminal](https://www.jamf.com/blog/clickfix-macos-script-editor-atomic-stealer/)
- [9] [Apple - Proteções do Terminal e de scripts](https://support.apple.com/en-ie/guide/security/sece3b202c4b/web)
{{#include ../../banners/hacktricks-training.md}}
