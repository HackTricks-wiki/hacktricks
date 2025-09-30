# Artefatos do Navegador

{{#include ../../../banners/hacktricks-training.md}}

## Artefatos dos Navegadores <a href="#id-3def" id="id-3def"></a>

Os artefatos do navegador incluem vários tipos de dados armazenados por navegadores web, como histórico de navegação, favoritos e dados de cache. Esses artefatos são mantidos em pastas específicas dentro do sistema operacional, variando em localização e nome entre os navegadores, mas geralmente armazenando tipos de dados similares.

Aqui está um resumo dos artefatos de navegador mais comuns:

- **Histórico de Navegação**: Rastreia as visitas do usuário a sites, útil para identificar acessos a sites maliciosos.
- **Dados de Autocompletar**: Sugestões baseadas em pesquisas frequentes, oferecendo insights quando combinadas com o histórico de navegação.
- **Favoritos**: Sites salvos pelo usuário para acesso rápido.
- **Extensões e complementos**: Extensões ou add-ons instalados no navegador pelo usuário.
- **Cache**: Armazena conteúdo web (por exemplo, imagens, arquivos JavaScript) para melhorar o tempo de carregamento de sites, valioso para análise forense.
- **Logins**: Credenciais de login armazenadas.
- **Favicons**: Ícones associados aos sites, aparecendo em abas e favoritos, úteis para informações adicionais sobre visitas do usuário.
- **Sessões do Navegador**: Dados relacionados a sessões abertas do navegador.
- **Downloads**: Registros de arquivos baixados através do navegador.
- **Dados de Formulário**: Informações inseridas em formulários web, salvas para sugestões de preenchimento automático.
- **Miniaturas**: Imagens de pré-visualização de sites.
- **Custom Dictionary.txt**: Palavras adicionadas pelo usuário ao dicionário do navegador.

## Firefox

Firefox organiza os dados do usuário dentro de perfis, armazenados em locais específicos dependendo do sistema operacional:

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

Um arquivo `profiles.ini` dentro desses diretórios lista os perfis de usuário. Os dados de cada perfil são armazenados em uma pasta nomeada na variável `Path` dentro de `profiles.ini`, localizada no mesmo diretório que o `profiles.ini` em si. Se a pasta de um perfil estiver ausente, ela pode ter sido excluída.

Dentro de cada pasta de perfil, você pode encontrar vários arquivos importantes:

- **places.sqlite**: Armazena histórico, favoritos e downloads. Ferramentas como [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) no Windows podem acessar os dados de histórico.
- Use consultas SQL específicas para extrair informações de histórico e downloads.
- **bookmarkbackups**: Contém backups dos favoritos.
- **formhistory.sqlite**: Armazena dados de formulários web.
- **handlers.json**: Gerencia handlers de protocolo.
- **persdict.dat**: Palavras do dicionário personalizado.
- **addons.json** e **extensions.sqlite**: Informações sobre add-ons e extensões instalados.
- **cookies.sqlite**: Armazenamento de cookies, com [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html) disponível para inspeção no Windows.
- **cache2/entries** ou **startupCache**: Dados de cache, acessíveis por ferramentas como [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html).
- **favicons.sqlite**: Armazena favicons.
- **prefs.js**: Configurações e preferências do usuário.
- **downloads.sqlite**: Banco de dados de downloads mais antigo, agora integrado ao places.sqlite.
- **thumbnails**: Miniaturas de sites.
- **logins.json**: Informações de login criptografadas.
- **key4.db** ou **key3.db**: Armazenam chaves de criptografia para proteger informações sensíveis.

Adicionalmente, verificar as configurações anti-phishing do navegador pode ser feito procurando por entradas `browser.safebrowsing` em `prefs.js`, indicando se os recursos de navegação segura estão habilitados ou desabilitados.

To try to decrypt the master password, you can use [https://github.com/unode/firefox_decrypt]\
With the following script and call you can specify a password file to brute force:
```bash:brute.sh
#!/bin/bash

#./brute.sh top-passwords.txt 2>/dev/null | grep -A2 -B2 "chrome:"
passfile=$1
while read pass; do
echo "Trying $pass"
echo "$pass" | python firefox_decrypt.py
done < $passfile
```
![](<../../../images/image (692).png>)

## Google Chrome

Google Chrome armazena perfis de usuário em locais específicos conforme o sistema operacional:

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

Nesses diretórios, a maior parte dos dados do usuário pode ser encontrada nas pastas **Default/** ou **ChromeDefaultData/**. Os arquivos a seguir contêm dados relevantes:

- **History**: Contém URLs, downloads e palavras-chave de busca. No Windows, [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html) pode ser usado para ler o histórico. A coluna "Transition Type" tem vários significados, incluindo cliques do usuário em links, URLs digitadas, submissões de formulários e recarregamentos de página.
- **Cookies**: Armazena cookies. Para inspeção, [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html) está disponível.
- **Cache**: Armazena dados em cache. Para inspecionar, usuários Windows podem usar [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html).

Electron-based desktop apps (e.g., Discord) também usam Chromium Simple Cache e deixam artefatos ricos no disco. Veja:

{{#ref}}
discord-cache-forensics.md
{{#endref}}
- **Bookmarks**: Marcadores do usuário.
- **Web Data**: Contém histórico de formulários.
- **Favicons**: Armazena favicons de sites.
- **Login Data**: Inclui credenciais de login como nomes de usuário e senhas.
- **Current Session**/**Current Tabs**: Dados sobre a sessão de navegação atual e abas abertas.
- **Last Session**/**Last Tabs**: Informações sobre os sites ativos na última sessão antes do fechamento do Chrome.
- **Extensions**: Diretórios de extensões e add-ons do navegador.
- **Thumbnails**: Armazena miniaturas (thumbnails) dos sites.
- **Preferences**: Um arquivo rico em informações, incluindo configurações de plugins, extensões, pop-ups, notificações e mais.
- **Browser’s built-in anti-phishing**: Para verificar se a proteção anti-phishing e contra malware está ativada, execute `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`. Procure por `{"enabled: true,"}` na saída.

## **SQLite DB Data Recovery**

Como pode-se observar nas seções anteriores, tanto o Chrome quanto o Firefox usam bancos de dados **SQLite** para armazenar dados. É possível **recuperar entradas deletadas usando a ferramenta** [**sqlparse**](https://github.com/padfoot999/sqlparse) **ou** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases).

## **Internet Explorer 11**

O Internet Explorer 11 gerencia seus dados e metadados em vários locais, o que ajuda a separar a informação armazenada dos detalhes correspondentes para facilitar acesso e análise.

### Metadata Storage

Os metadados do Internet Explorer são armazenados em %userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data (com VX sendo V01, V16 ou V24). O arquivo `V01.log` pode mostrar discrepâncias de tempo de modificação em relação a `WebcacheVX.data`, indicando necessidade de reparo usando `esentutl /r V01 /d`. Esses metadados, contidos em um banco ESE, podem ser recuperados e inspecionados com ferramentas como photorec e [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html), respectivamente. Na tabela **Containers** é possível identificar as tabelas ou containers específicos onde cada segmento de dados é armazenado, incluindo detalhes de cache para outras ferramentas Microsoft como Skype.

### Cache Inspection

A ferramenta [IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) permite inspeção de cache, exigindo a localização da pasta com os dados de cache extraídos. Os metadados do cache incluem nome do arquivo, diretório, contador de acessos, URL de origem e timestamps indicando criação, acesso, modificação e expiração do cache.

### Cookies Management

Cookies podem ser explorados usando [IECookiesView](https://www.nirsoft.net/utils/iecookies.html), com metadados abrangendo nomes, URLs, contagens de acesso e vários detalhes temporais. Cookies persistentes são armazenados em %userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies, enquanto cookies de sessão residem na memória.

### Download Details

Metadados de downloads são acessíveis via [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html), com containers específicos contendo dados como URL, tipo de arquivo e local do download. Arquivos físicos podem ser encontrados em %userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory.

### Browsing History

Para revisar o histórico de navegação, [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) pode ser usado, exigindo a localização dos arquivos de histórico extraídos e a configuração para o Internet Explorer. Os metadados aqui incluem tempos de modificação e acesso, além de contagens de acesso. Arquivos de histórico estão localizados em %userprofile%\Appdata\Local\Microsoft\Windows\History.

### Typed URLs

URLs digitadas e seus tempos de uso são armazenados no registro dentro do `NTUSER.DAT` em `Software\Microsoft\InternetExplorer\TypedURLs` e `Software\Microsoft\InternetExplorer\TypedURLsTime`, rastreando as últimas 50 URLs inseridas pelo usuário e seus últimos horários de entrada.

## Microsoft Edge

O Microsoft Edge armazena dados do usuário em %userprofile%\Appdata\Local\Packages. Os caminhos para vários tipos de dados são:

- **Profile Path**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **History, Cookies, and Downloads**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Settings, Bookmarks, and Reading List**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Cache**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Last Active Sessions**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Dados do Safari são armazenados em `/Users/$User/Library/Safari`. Arquivos chave incluem:

- **History.db**: Contém as tabelas `history_visits` e `history_items` com URLs e timestamps de visita. Use `sqlite3` para consultar.
- **Downloads.plist**: Informações sobre arquivos baixados.
- **Bookmarks.plist**: Armazena URLs marcadas (bookmarks).
- **TopSites.plist**: Sites mais visitados.
- **Extensions.plist**: Lista de extensões do Safari. Use `plutil` ou `pluginkit` para recuperar.
- **UserNotificationPermissions.plist**: Domínios permitidos a enviar notificações. Use `plutil` para analisar.
- **LastSession.plist**: Abas da última sessão. Use `plutil` para analisar.
- **Browser’s built-in anti-phishing**: Verifique usando `defaults read com.apple.Safari WarnAboutFraudulentWebsites`. Uma resposta de `1` indica que o recurso está ativado.

## Opera

Os dados do Opera residem em `/Users/$USER/Library/Application Support/com.operasoftware.Opera` e seguem o mesmo formato do Chrome para histórico e downloads.

- **Browser’s built-in anti-phishing**: Verifique se a proteção anti-phishing do navegador está ativa checando se `fraud_protection_enabled` no arquivo Preferences está definido como `true` usando `grep`.

Esses caminhos e comandos são cruciais para acessar e entender os dados de navegação armazenados por diferentes navegadores web.

## References

- [https://nasbench.medium.com/web-browsers-forensics-7e99940c579a](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file](https://books.google.com/books?id=jfMqCgAAQBAJ&pg=PA128&lpg=PA128&dq=%22This+file)
- **Livro: OS X Incident Response: Scripting and Analysis By Jaron Bradley pág. 123**


{{#include ../../../banners/hacktricks-training.md}}
