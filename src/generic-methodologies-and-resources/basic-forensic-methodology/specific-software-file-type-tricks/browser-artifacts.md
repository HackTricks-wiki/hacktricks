# Artefatos de Navegadores

{{#include ../../../banners/hacktricks-training.md}}

## Artefatos dos Navegadores <a href="#id-3def" id="id-3def"></a>

Os artefatos dos navegadores incluem vários tipos de dados armazenados pelos navegadores web, como histórico de navegação, favoritos e dados de cache. Esses artefatos são mantidos em pastas específicas dentro do sistema operacional, com localização e nome diferentes entre os navegadores, mas geralmente armazenando tipos de dados semelhantes.

Aqui está um resumo dos artefatos de navegador mais comuns:

- **Histórico de Navegação**: Registra as visitas do usuário a sites, sendo útil para identificar visitas a sites maliciosos.
- **Dados de Autocomplete**: Sugestões baseadas em pesquisas frequentes, oferecendo informações úteis quando combinadas com o histórico de navegação.
- **Favoritos**: Sites salvos pelo usuário para acesso rápido.
- **Extensões e Add-ons**: Extensões ou add-ons do navegador instalados pelo usuário.
- **Cache**: Armazena conteúdo web (por exemplo, imagens e arquivos JavaScript) para melhorar o tempo de carregamento dos sites, sendo valioso para análise forense.
- **Logins**: Credenciais de login armazenadas.
- **Favicons**: Ícones associados a sites, exibidos em abas e favoritos, úteis para obter informações adicionais sobre as visitas do usuário.
- **Sessões do Navegador**: Dados relacionados às sessões abertas do navegador.
- **Downloads**: Registros de arquivos baixados por meio do navegador.
- **Dados de Formulários**: Informações inseridas em formulários web, salvas para futuras sugestões de preenchimento automático.
- **Miniaturas**: Imagens de pré-visualização de sites.
- **Custom Dictionary.txt**: Palavras adicionadas pelo usuário ao dicionário do navegador.

## Firefox

O Firefox organiza os dados do usuário em perfis, armazenados em locais específicos de acordo com o sistema operacional:<sup>[[1]](#references)</sup>

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

Um arquivo `profiles.ini` dentro desses diretórios lista os perfis de usuário. Os dados de cada perfil são armazenados em uma pasta nomeada na variável `Path` dentro de `profiles.ini`, localizada no mesmo diretório que o próprio arquivo `profiles.ini`. Se a pasta de um perfil estiver ausente, ela pode ter sido excluída.

Dentro de cada pasta de perfil, é possível encontrar vários arquivos importantes:<sup>[[1]](#references)</sup>

- **places.sqlite**: Armazena histórico, favoritos e downloads. Ferramentas como [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) no Windows podem acessar os dados do histórico.
- Use consultas SQL específicas para extrair informações de histórico e downloads.
- **bookmarkbackups**: Contém backups dos favoritos.
- **formhistory.sqlite**: Armazena dados de formulários web.
- **handlers.json**: Gerencia handlers de protocolos.
- **persdict.dat**: Palavras do dicionário personalizado.
- **addons.json** e **extensions.sqlite**: Informações sobre add-ons e extensões instalados.
- **cookies.sqlite**: Armazena cookies, podendo ser inspecionado no Windows com o [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html).
- **cache2/entries** ou **startupCache**: Dados de cache, acessíveis por meio de ferramentas como o [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html).
- **favicons.sqlite**: Armazena favicons.
- **prefs.js**: Configurações e preferências do usuário.
- **downloads.sqlite**: Banco de dados antigo de downloads, atualmente integrado ao places.sqlite.
- **thumbnails**: Miniaturas de sites.
- **logins.json**: Informações de login criptografadas.
- **key4.db** ou **key3.db**: Armazena chaves de criptografia usadas para proteger informações confidenciais.

Além disso, é possível verificar as configurações anti-phishing do navegador pesquisando entradas `browser.safebrowsing` em `prefs.js`, indicando se os recursos de navegação segura estão habilitados ou desabilitados.<sup>[[2]](#references)</sup>

Para tentar descriptografar a senha principal, você pode usar [https://github.com/unode/firefox_decrypt](https://github.com/unode/firefox_decrypt)\
Com o script e a chamada a seguir, é possível especificar um arquivo de senhas para realizar brute force:
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

O Google Chrome armazena os perfis dos usuários em locais específicos com base no sistema operacional:<sup>[[1]](#references)</sup>

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

Nesses diretórios, a maioria dos dados do usuário pode ser encontrada nas pastas **Default/** ou **ChromeDefaultData/**. Os arquivos a seguir contêm dados importantes:<sup>[[1]](#references)</sup>

- **History**: Contém URLs, downloads e palavras-chave de pesquisa. No Windows, o [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html) pode ser usado para ler o histórico. A coluna "Transition Type" possui vários significados, incluindo cliques do usuário em links, URLs digitadas, envios de formulários e recarregamentos de páginas.
- **Cookies**: Armazena cookies. Para inspeção, o [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html) está disponível.
- **Cache**: Armazena dados em cache. Para inspecioná-los, usuários do Windows podem utilizar o [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html).

Aplicativos desktop baseados em Electron (por exemplo, Discord) também usam Chromium Simple Cache e deixam artefatos ricos no disco. Veja:

{{#ref}}
discord-cache-forensics.md
{{#endref}}
- **Bookmarks**: Favoritos do usuário.
- **Web Data**: Contém o histórico de formulários.
- **Favicons**: Armazena favicons dos sites.
- **Login Data**: Inclui credenciais de login, como nomes de usuário e senhas.
- **Current Session**/**Current Tabs**: Dados sobre a sessão de navegação atual e as abas abertas.
- **Last Session**/**Last Tabs**: Informações sobre os sites ativos durante a última sessão antes de o Chrome ser fechado.
- **Extensions**: Diretórios das extensões e addons do navegador.
- **Thumbnails**: Armazena miniaturas dos sites.
- **Preferences**: Um arquivo rico em informações, incluindo configurações de plugins, extensões, pop-ups, notificações e muito mais.
- **Browser’s built-in anti-phishing**: Para verificar se a proteção anti-phishing e contra malware está habilitada, execute `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`. Procure por `{"enabled: true,"}` na saída.<sup>[[2]](#references)</sup>

## **Recuperação de dados de DB SQLite**

Como pode ser observado nas seções anteriores, tanto o Chrome quanto o Firefox usam bancos de dados **SQLite** para armazenar os dados. É possível **recuperar entradas excluídas usando a ferramenta** [**sqlparse**](https://github.com/padfoot999/sqlparse) **ou** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases).

## **Internet Explorer 11**

O Internet Explorer 11 gerencia seus dados e metadados em vários locais, ajudando a separar as informações armazenadas e seus detalhes correspondentes para facilitar o acesso e o gerenciamento.

### Armazenamento de metadados

Os metadados do Internet Explorer são armazenados em `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` (sendo VX V01, V16 ou V24). O arquivo `V01.log` associado pode mostrar discrepâncias no horário de modificação em relação a `WebcacheVX.data`, indicando a necessidade de reparo usando `esentutl /r V01 /d`. Esses metadados, armazenados em um banco de dados ESE, podem ser recuperados e inspecionados usando ferramentas como photorec e [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html), respectivamente. Na tabela **Containers**, é possível identificar as tabelas ou os containers específicos onde cada segmento de dados está armazenado, incluindo detalhes de cache de outras ferramentas da Microsoft, como o Skype.

### Inspeção do cache

A ferramenta [IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) permite inspecionar o cache, exigindo a localização da pasta de extração dos dados do cache. Os metadados do cache incluem nome do arquivo, diretório, contagem de acessos, origem da URL e timestamps que indicam os horários de criação, acesso, modificação e expiração do cache.

### Gerenciamento de cookies

Os cookies podem ser explorados usando o [IECookiesView](https://www.nirsoft.net/utils/iecookies.html), com metadados que incluem nomes, URLs, contagens de acesso e vários detalhes relacionados ao tempo. Os cookies persistentes são armazenados em `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies`, enquanto os cookies de sessão permanecem na memória.

### Detalhes dos downloads

Os metadados dos downloads podem ser acessados por meio do [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html), com containers específicos contendo dados como URL, tipo de arquivo e local do download. Os arquivos físicos podem ser encontrados em `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory`.

### Histórico de navegação

Para revisar o histórico de navegação, o [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) pode ser usado, exigindo a localização dos arquivos de histórico extraídos e a configuração do Internet Explorer. Os metadados incluem horários de modificação e acesso, além das contagens de acesso. Os arquivos de histórico estão localizados em `%userprofile%\Appdata\Local\Microsoft\Windows\History`.

### URLs digitadas

As URLs digitadas e os horários de uso são armazenados no registro, em `NTUSER.DAT`, nos caminhos `Software\Microsoft\InternetExplorer\TypedURLs` e `Software\Microsoft\InternetExplorer\TypedURLsTime`, registrando as últimas 50 URLs inseridas pelo usuário e os horários em que foram digitadas pela última vez.

## Microsoft Edge

O Microsoft Edge armazena os dados do usuário em `%userprofile%\Appdata\Local\Packages`. Os caminhos para vários tipos de dados são:<sup>[[1]](#references)</sup>

- **Profile Path**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **History, Cookies, and Downloads**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Settings, Bookmarks, and Reading List**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Cache**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Last Active Sessions**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Os dados do Safari são armazenados em `/Users/$User/Library/Safari`. Os principais arquivos incluem:<sup>[[3]](#references)</sup>

- **History.db**: Contém as tabelas `history_visits` e `history_items`, com URLs e timestamps de visitas. Use `sqlite3` para consultar.
- **Downloads.plist**: Informações sobre arquivos baixados.
- **Bookmarks.plist**: Armazena URLs adicionadas aos favoritos.
- **TopSites.plist**: Sites visitados com maior frequência.
- **Extensions.plist**: Lista de extensões do navegador Safari. Use `plutil` ou `pluginkit` para obter essas informações.
- **UserNotificationPermissions.plist**: Domínios autorizados a enviar notificações push. Use `plutil` para analisar.
- **LastSession.plist**: Abas da última sessão. Use `plutil` para analisar.
- **Browser’s built-in anti-phishing**: Verifique usando `defaults read com.apple.Safari WarnAboutFraudulentWebsites`. Uma resposta igual a 1 indica que o recurso está ativo.<sup>[[2]](#references)</sup>

## Opera

Os dados do Opera estão localizados em `/Users/$USER/Library/Application Support/com.operasoftware.Opera` e compartilham o formato do Chrome para histórico e downloads.

- **Browser’s built-in anti-phishing**: Verifique se `fraud_protection_enabled` no arquivo Preferences está definido como `true`, usando `grep`.<sup>[[2]](#references)</sup>

Esses caminhos e comandos são essenciais para acessar e compreender os dados de navegação armazenados por diferentes navegadores.

## Referências

- [1] [Web Browsers Forensics: A Guide On Doing Web Browsers Forensic Analysis](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [2] [macOS Incident Response | Part 3: System Manipulation](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [3] [OS X Incident Response: Scripting and Analysis by Jaron Bradley](https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file)

{{#include ../../../banners/hacktricks-training.md}}
