# Artefatos do navegador

{{#include ../../../banners/hacktricks-training.md}}

## Artefatos do navegador <a href="#id-3def" id="id-3def"></a>

Os artefatos do navegador incluem vários tipos de dados armazenados pelos navegadores, como histórico de navegação, favoritos e dados de cache. Esses artefatos são mantidos em pastas específicas do sistema operacional, que variam de localização e nome entre navegadores, mas geralmente armazenam tipos de dados semelhantes.

Veja um resumo dos artefatos de navegador mais comuns:

- **Histórico de navegação**: Registra as visitas do usuário a sites, sendo útil para identificar visitas a sites maliciosos.
- **Dados de preenchimento automático**: Sugestões baseadas em pesquisas frequentes, que oferecem informações úteis quando combinadas com o histórico de navegação.
- **Favoritos**: Sites salvos pelo usuário para acesso rápido.
- **Extensões e complementos**: Extensões ou complementos instalados pelo usuário.
- **Cache**: Armazena conteúdo da Web (por exemplo, imagens e arquivos JavaScript) para melhorar o tempo de carregamento dos sites, sendo valioso para análise forense.
- **Logins**: Credenciais de login armazenadas.
- **Favicons**: Ícones associados a sites, exibidos em abas e favoritos, úteis para obter informações adicionais sobre as visitas do usuário.
- **Sessões do navegador**: Dados relacionados às sessões abertas do navegador.
- **Downloads**: Registros dos arquivos baixados pelo navegador.
- **Dados de formulários**: Informações inseridas em formulários da Web e salvas para futuras sugestões de preenchimento automático.
- **Miniaturas**: Imagens de pré-visualização de sites.
- **Custom Dictionary.txt**: Palavras adicionadas pelo usuário ao dicionário do navegador.

## Firefox

O Firefox organiza os dados do usuário em perfis, armazenados em locais específicos conforme o sistema operacional:<sup>[[1]](#references)</sup>

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

Um arquivo `profiles.ini` nesses diretórios lista os perfis de usuário. Os dados de cada perfil são armazenados em uma pasta cujo nome é definido na variável `Path` dentro de `profiles.ini`, localizada no mesmo diretório que o próprio `profiles.ini`. Se a pasta de um perfil estiver ausente, ela pode ter sido excluída.

Em cada pasta de perfil, você encontrará vários arquivos importantes:<sup>[[1]](#references)</sup>

- **places.sqlite**: Armazena o histórico, os favoritos e os downloads. Ferramentas como [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) no Windows podem acessar os dados do histórico.
  - Use consultas SQL específicas para extrair informações do histórico e dos downloads.
- **bookmarkbackups**: Contém backups dos favoritos.
- **formhistory.sqlite**: Armazena dados de formulários da Web.
- **handlers.json**: Gerencia manipuladores de protocolo.
- **persdict.dat**: Palavras do dicionário personalizado.
- **addons.json** e **extensions.sqlite**: Informações sobre complementos e extensões instalados.
- **cookies.sqlite**: Armazenamento de cookies; no Windows, é possível inspecioná-lo com [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html).
- **cache2/entries** ou **startupCache**: Dados de cache, acessíveis por ferramentas como [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html).
- **favicons.sqlite**: Armazena favicons.
- **prefs.js**: Configurações e preferências do usuário.
- **downloads.sqlite**: Banco de dados de downloads mais antigo, agora integrado ao places.sqlite.
- **thumbnails**: Miniaturas de sites.
- **logins.json**: Informações de login criptografadas.
- **key4.db** ou **key3.db**: Armazena chaves de criptografia usadas para proteger informações confidenciais.

Além disso, é possível verificar as configurações antiphishing do navegador procurando entradas `browser.safebrowsing` em `prefs.js`, que indicam se os recursos de navegação segura estão ativados ou desativados.<sup>[[2]](#references)</sup>

Para descriptografar logins salvos em um perfil acessível, é necessário fornecer ou recuperar separadamente a [Firefox Primary Password](https://support.mozilla.org/en-US/kb/use-primary-password-protect-stored-logins), caso esteja configurada; o perfil não revela essa senha. Confirme se qualquer login recuperado autentica na conta da Web correspondente. O acesso root do Unix exige uma prova separada de que a credencial também é aceita pela autenticação Unix para root. Você pode revisar os logins salvos com [firefox_decrypt](https://github.com/unode/firefox_decrypt). O exemplo a seguir testa senhas candidatas de Primary Password de um arquivo de senhas:

```bash:brute.sh
#!/bin/bash

#./brute.sh top-passwords.txt 2>/dev/null | grep -A2 -B2 "chrome:"
passfile=$1
while read pass; do
  echo "Trying $pass"
  echo "$pass" | python firefox_decrypt.py
done < $passfile
```

![Artefatos dos navegadores - Firefox: echo "$pass" | python firefox decrypt.py](<../../../images/image (692).png>)

## Google Chrome

O Google Chrome armazena os perfis de usuário em locais específicos, de acordo com o sistema operacional:<sup>[[1]](#references)</sup>

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

Nesses diretórios, a maioria dos dados do usuário pode ser encontrada nas pastas **Default/** ou **ChromeDefaultData/**. Os seguintes arquivos contêm dados importantes:<sup>[[1]](#references)</sup>

- **History**: contém URLs, downloads e palavras-chave de pesquisa. No Windows, o [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html) pode ser usado para ler o histórico. A coluna "Transition Type" tem vários significados, incluindo cliques do usuário em links, URLs digitadas, envios de formulários e recarregamentos de páginas.
- **Cookies**: armazena cookies. Para inspecioná-los, há o [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html).
- **Cache**: contém dados em cache. Para inspecioná-los, usuários do Windows podem utilizar o [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html).

  Aplicativos para desktop baseados em Electron (por exemplo, Discord) também usam Chromium Simple Cache e deixam muitos artefatos no disco. Veja:

  {{#ref}}
  discord-cache-forensics.md
  {{#endref}}
- **Bookmarks**: favoritos do usuário.
- **Web Data**: contém o histórico de formulários.
- **Favicons**: armazena os favicons dos sites.
- **Login Data**: inclui credenciais de login, como nomes de usuário e senhas.
- **Current Session**/**Current Tabs**: dados sobre a sessão de navegação atual e as abas abertas.
- **Last Session**/**Last Tabs**: informações sobre os sites ativos durante a última sessão antes de o Chrome ser fechado.
- **Extensions**: diretórios das extensões e dos complementos do navegador.
- **Thumbnails**: armazena miniaturas de sites.
- **Preferences**: um arquivo com muitas informações, incluindo configurações de plugins, extensões, pop-ups, notificações e muito mais.
- **Proteção integrada contra phishing do navegador**: para verificar se a proteção contra phishing e malware está ativada, execute `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`. Procure por `{"enabled: true,"}` na saída.<sup>[[2]](#references)</sup>

O diretório `Local Extension Settings/<extension-id>/` de um perfil do Chromium pode conter dados locais de extensões, incluindo material de chave de gerenciadores de senhas. Por exemplo, o [Passbolt informa que sua chave privada criptografada é armazenada no armazenamento local da extensão do navegador](https://www.passbolt.com/docs/user/faq/why-a-browser-extension/), e o [ID da extensão do Chrome](https://chromewebstore.google.com/detail/passbolt-open-source-pass/didegimhafipceonhjepacocaffmoppf) identifica o diretório relevante. A presença do diretório, por si só, não comprova que há uma chave nem desbloqueia um cofre: o usuário precisa ter acesso aos dados do perfil, a uma chave privada utilizável e à frase secreta, além de um caminho autorizado de recuperação/autenticação no servidor. Um item do cofre que contenha uma senha de conta do sistema operacional exige uma verificação separada de reutilização da conta. A enumeração de rotina deve informar apenas o caminho de armazenamento, sem despejar arquivos LevelDB ou valores secretos.

## **Recuperação de dados de DB SQLite**

Como você pode observar nas seções anteriores, tanto o Chrome quanto o Firefox usam bancos de dados **SQLite** para armazenar os dados. É possível **recuperar entradas excluídas usando a ferramenta** [**sqlparse**](https://github.com/padfoot999/sqlparse) **ou** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases).

## **Internet Explorer 11**

O Internet Explorer 11 gerencia seus dados e metadados em vários locais, ajudando a separar as informações armazenadas dos detalhes correspondentes para facilitar o acesso e o gerenciamento.

### Armazenamento de metadados

Os metadados do Internet Explorer são armazenados em `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` (sendo VX V01, V16 ou V24). O arquivo `V01.log` associado pode apresentar discrepâncias no horário de modificação em relação a `WebcacheVX.data`, indicando a necessidade de reparo usando `esentutl /r V01 /d`. Esses metadados, armazenados em um banco de dados ESE, podem ser recuperados e inspecionados, respectivamente, com ferramentas como photorec e [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html). Na tabela **Containers**, é possível identificar as tabelas ou os contêineres específicos onde cada segmento de dados é armazenado, incluindo detalhes de cache de outras ferramentas da Microsoft, como o Skype.

### Inspeção do cache

A ferramenta [IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) permite inspecionar o cache e exige o caminho da pasta onde os dados do cache foram extraídos. Os metadados do cache incluem nome do arquivo, diretório, contagem de acessos, origem da URL e timestamps que indicam os horários de criação, acesso, modificação e expiração do cache.

### Gerenciamento de cookies

Os cookies podem ser examinados usando o [IECookiesView](https://www.nirsoft.net/utils/iecookies.html), cujos metadados incluem nomes, URLs, contagens de acesso e vários detalhes relacionados ao tempo. Os cookies persistentes são armazenados em `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies`, enquanto os cookies de sessão permanecem na memória.

### Detalhes dos downloads

Os metadados dos downloads podem ser acessados pelo [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html), com contêineres específicos que armazenam dados como URL, tipo de arquivo e local do download. Os arquivos físicos podem ser encontrados em `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory`.

### Histórico de navegação

Para revisar o histórico de navegação, pode-se usar o [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html), que exige o local dos arquivos de histórico extraídos e a configuração do Internet Explorer. Os metadados incluem horários de modificação e acesso, além de contagens de acesso. Os arquivos de histórico estão em `%userprofile%\Appdata\Local\Microsoft\Windows\History`.

### URLs digitadas

As URLs digitadas e os horários de uso são armazenados no registro, em `NTUSER.DAT`, nos caminhos `Software\Microsoft\InternetExplorer\TypedURLs` e `Software\Microsoft\InternetExplorer\TypedURLsTime`. Eles registram as últimas 50 URLs inseridas pelo usuário e os horários em que foram digitadas pela última vez.

## Microsoft Edge

O Microsoft Edge armazena os dados do usuário em `%userprofile%\Appdata\Local\Packages`. Os caminhos dos vários tipos de dados são:<sup>[[1]](#references)</sup>

- **Caminho do perfil**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **Histórico, cookies e downloads**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Configurações, favoritos e lista de leitura**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Cache**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Últimas sessões ativas**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Os dados do Safari são armazenados em `/Users/$User/Library/Safari`. Os principais arquivos incluem:<sup>[[3]](#references)</sup>

- **History.db**: contém as tabelas `history_visits` e `history_items`, com URLs e timestamps de visita. Use `sqlite3` para consultar.
- **Downloads.plist**: informações sobre arquivos baixados.
- **Bookmarks.plist**: armazena URLs salvas nos favoritos.
- **TopSites.plist**: sites visitados com mais frequência.
- **Extensions.plist**: lista das extensões do navegador Safari. Use `plutil` ou `pluginkit` para consultar.
- **UserNotificationPermissions.plist**: domínios autorizados a enviar notificações push. Use `plutil` para analisar.
- **LastSession.plist**: abas da última sessão. Use `plutil` para analisar.
- **Proteção integrada contra phishing do navegador**: verifique usando `defaults read com.apple.Safari WarnAboutFraudulentWebsites`. Uma resposta igual a 1 indica que o recurso está ativo.<sup>[[2]](#references)</sup>

## Opera

Os dados do Opera ficam em `/Users/$USER/Library/Application Support/com.operasoftware.Opera` e usam o mesmo formato do Chrome para histórico e downloads.

- **Proteção integrada contra phishing do navegador**: verifique com `grep` se `fraud_protection_enabled` no arquivo Preferences está definido como `true`.<sup>[[2]](#references)</sup>

Esses caminhos e comandos são essenciais para acessar e entender os dados de navegação armazenados por diferentes navegadores.

## References

- [1] [Perícia em navegadores da Web: um guia para realizar análise forense de navegadores da Web](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [2] [Resposta a incidentes no macOS | Parte 3: Manipulação do sistema](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [3] [Resposta a incidentes no OS X: scripts e análise, de Jaron Bradley](https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file)
{{#include ../../../banners/hacktricks-training.md}}
