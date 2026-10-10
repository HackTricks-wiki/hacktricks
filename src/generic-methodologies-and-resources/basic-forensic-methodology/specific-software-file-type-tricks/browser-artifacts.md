# Artefatos do navegador

{{#include ../../../banners/hacktricks-training.md}}

## Artefatos do navegador <a href="#id-3def" id="id-3def"></a>

Os artefatos do navegador incluem vários tipos de dados armazenados por navegadores da web, como histórico de navegação, favoritos e dados de cache. Esses artefatos são mantidos em pastas específicas do sistema operacional, que variam de localização e nome entre os navegadores, mas geralmente armazenam tipos de dados semelhantes.

Veja um resumo dos artefatos de navegador mais comuns:

- **Histórico de navegação**: Registra as visitas do usuário a sites, útil para identificar visitas a sites maliciosos.
- **Dados de preenchimento automático**: Sugestões baseadas em pesquisas frequentes, que oferecem informações úteis quando combinadas com o histórico de navegação.
- **Favoritos**: Sites salvos pelo usuário para acesso rápido.
- **Extensões e complementos**: Extensões ou complementos do navegador instalados pelo usuário.
- **Cache**: Armazena conteúdo da web (por exemplo, imagens e arquivos JavaScript) para melhorar o tempo de carregamento dos sites, sendo valioso para análise forense.
- **Credenciais de login**: Credenciais de login armazenadas.
- **Favicons**: Ícones associados a sites, exibidos em abas e favoritos, úteis para obter informações adicionais sobre as visitas do usuário.
- **Sessões do navegador**: Dados relacionados às sessões abertas do navegador.
- **Downloads**: Registros de arquivos baixados pelo navegador.
- **Dados de formulários**: Informações inseridas em formulários da web, salvas para sugestões futuras de preenchimento automático.
- **Miniaturas**: Imagens de pré-visualização de sites.
- **Custom Dictionary.txt**: Palavras adicionadas pelo usuário ao dicionário do navegador.

## Firefox

O Firefox organiza os dados do usuário em perfis, armazenados em locais específicos de acordo com o sistema operacional:<sup>[[1]](#references)</sup>

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

Um arquivo `profiles.ini` nesses diretórios lista os perfis do usuário. Os dados de cada perfil são armazenados em uma pasta cujo nome é definido pela variável `Path` em `profiles.ini`, localizada no mesmo diretório que o próprio `profiles.ini`. Se a pasta de um perfil estiver ausente, ela pode ter sido excluída.

Em cada pasta de perfil, você pode encontrar vários arquivos importantes:<sup>[[1]](#references)</sup>

- **places.sqlite**: Armazena o histórico, os favoritos e os downloads. Ferramentas como [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) no Windows podem acessar os dados do histórico.
  - Use consultas SQL específicas para extrair informações do histórico e dos downloads.
- **bookmarkbackups**: Contém backups dos favoritos.
- **formhistory.sqlite**: Armazena dados de formulários da web.
- **handlers.json**: Gerencia manipuladores de protocolo.
- **persdict.dat**: Palavras do dicionário personalizado.
- **addons.json** e **extensions.sqlite**: Informações sobre complementos e extensões instalados.
- **cookies.sqlite**: Armazenamento de cookies; [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html) está disponível para inspeção no Windows.
- **cache2/entries** ou **startupCache**: Dados de cache, acessíveis por ferramentas como [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html).
- **favicons.sqlite**: Armazena favicons.
- **prefs.js**: Configurações e preferências do usuário.
- **downloads.sqlite**: Banco de dados antigo de downloads, agora integrado ao places.sqlite.
- **thumbnails**: Miniaturas de sites.
- **logins.json**: Informações de login criptografadas.
- **key4.db** ou **key3.db**: Armazena chaves de criptografia para proteger informações confidenciais.

Além disso, é possível verificar as configurações anti-phishing do navegador procurando entradas `browser.safebrowsing` em `prefs.js`, que indicam se os recursos de navegação segura estão ativados ou desativados.<sup>[[2]](#references)</sup>

Para descriptografar logins salvos de um perfil acessível, é necessário fornecer ou recuperar separadamente a [Firefox Primary Password](https://support.mozilla.org/en-US/kb/use-primary-password-protect-stored-logins), caso esteja configurada; o perfil não revela essa senha. Confirme que qualquer login recuperado autentica na respectiva conta web. O acesso root no Unix exige uma prova separada de que a credencial também é aceita pela autenticação Unix para root. Você pode revisar os logins salvos com [firefox_decrypt](https://github.com/unode/firefox_decrypt). O exemplo a seguir testa possíveis Primary Passwords de um arquivo de senhas:

```bash:brute.sh
#!/bin/bash

#./brute.sh top-passwords.txt 2>/dev/null | grep -A2 -B2 "chrome:"
passfile=$1
while read pass; do
  echo "Trying $pass"
  echo "$pass" | python firefox_decrypt.py
done < $passfile
```

![Artefatos de navegadores - Firefox: echo "$pass" | python firefox decrypt.py](<../../../images/image (692).png>)

## Google Chrome

O Google Chrome armazena os perfis de usuário em locais específicos, dependendo do sistema operacional:<sup>[[1]](#references)</sup>

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

Nesses diretórios, a maioria dos dados do usuário pode ser encontrada nas pastas **Default/** ou **ChromeDefaultData/**. Os seguintes arquivos contêm dados importantes:<sup>[[1]](#references)</sup>

- **History**: Contém URLs, downloads e palavras-chave de pesquisa. No Windows, é possível usar [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html) para ler o histórico. A coluna "Transition Type" tem vários significados, incluindo cliques do usuário em links, URLs digitadas, envios de formulários e recarregamentos de páginas.
- **Cookies**: Armazena cookies. Para inspecioná-los, está disponível o [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html).
- **Cache**: Armazena dados em cache. Para inspecioná-los, usuários do Windows podem usar o [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html).

  Aplicativos desktop baseados em Electron (por exemplo, Discord) também usam o Chromium Simple Cache e deixam muitos artefatos no disco. Consulte:

  {{#ref}}
  discord-cache-forensics.md
  {{#endref}}
- **Bookmarks**: Marcadores do usuário.
- **Web Data**: Contém o histórico de formulários.
- **Favicons**: Armazena favicons de sites.
- **Login Data**: Inclui credenciais de login, como nomes de usuário e senhas.
- **Current Session**/**Current Tabs**: Dados sobre a sessão de navegação atual e as abas abertas.
- **Last Session**/**Last Tabs**: Informações sobre os sites ativos durante a última sessão antes do Chrome ser fechado.
- **Extensions**: Diretórios de extensões e complementos do navegador.
- **Thumbnails**: Armazena miniaturas de sites.
- **Preferences**: Um arquivo rico em informações, incluindo configurações de plugins, extensões, pop-ups, notificações e muito mais.
- **Proteção antiphishing integrada do navegador**: Para verificar se a proteção antiphishing e contra malware está ativada, execute `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`. Procure `{"enabled: true,"}` na saída.<sup>[[2]](#references)</sup>

O diretório `Local Extension Settings/<extension-id>/` de um perfil do Chromium pode conter dados locais da extensão, inclusive material de chave de password manager. Por exemplo, [o Passbolt informa que sua chave privada criptografada é armazenada no armazenamento local da extensão do navegador](https://www.passbolt.com/docs/user/faq/why-a-browser-extension/), e o [ID da extensão do Chrome](https://chromewebstore.google.com/detail/passbolt-open-source-pass/didegimhafipceonhjepacocaffmoppf) identifica o diretório relevante. A presença do diretório, por si só, não comprova que há uma chave nem desbloqueia um vault: o usuário precisa ter acesso aos dados do perfil, a uma chave privada e a uma passphrase utilizáveis, além de um caminho autorizado de recuperação/autenticação para o servidor. Um item do vault que contenha uma senha de conta do sistema operacional exige uma verificação separada de reutilização da conta. A enumeração rotineira deve informar apenas o caminho de armazenamento, sem despejar os arquivos LevelDB ou valores secretos.

## **Recuperação de dados de DB SQLite**

Como você pode observar nas seções anteriores, Chrome e Firefox usam bancos de dados **SQLite** para armazenar os dados. É possível **recuperar entradas excluídas usando a ferramenta** [**sqlparse**](https://github.com/padfoot999/sqlparse) **ou** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases).

## **Internet Explorer 11**

O Internet Explorer 11 gerencia seus dados e metadados em vários locais, ajudando a separar as informações armazenadas de seus detalhes correspondentes para facilitar o acesso e o gerenciamento.

### Armazenamento de metadados

Os metadados do Internet Explorer são armazenados em `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` (em que VX pode ser V01, V16 ou V24). O arquivo `V01.log` associado pode apresentar divergências no horário de modificação em relação a `WebcacheVX.data`, indicando a necessidade de reparo com `esentutl /r V01 /d`. Esses metadados, armazenados em um banco de dados ESE, podem ser recuperados e inspecionados, respectivamente, com ferramentas como photorec e [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html). Na tabela **Containers**, é possível identificar as tabelas ou os contêineres específicos onde cada segmento de dados é armazenado, incluindo detalhes de cache de outras ferramentas da Microsoft, como o Skype.

### Inspeção do cache

A ferramenta [IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) permite inspecionar o cache e requer o local da pasta onde os dados do cache foram extraídos. Os metadados do cache incluem nome do arquivo, diretório, contagem de acessos, URL de origem e timestamps de criação, acesso, modificação e expiração do cache.

### Gerenciamento de cookies

É possível explorar cookies com o [IECookiesView](https://www.nirsoft.net/utils/iecookies.html). Os metadados incluem nomes, URLs, contagens de acesso e diversos detalhes temporais. Os cookies persistentes são armazenados em `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies`, enquanto os cookies de sessão ficam na memória.

### Detalhes dos downloads

Os metadados de downloads podem ser acessados pelo [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html), com contêineres específicos que armazenam dados como URL, tipo de arquivo e local do download. Os arquivos físicos podem ser encontrados em `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory`.

### Histórico de navegação

Para revisar o histórico de navegação, pode-se usar o [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html), que requer o local dos arquivos de histórico extraídos e a configuração para o Internet Explorer. Os metadados incluem horários de modificação e acesso, além da contagem de acessos. Os arquivos de histórico ficam em `%userprofile%\Appdata\Local\Microsoft\Windows\History`.

### URLs digitadas

As URLs digitadas e os horários em que foram usadas são armazenados no registro, em `NTUSER.DAT`, nos caminhos `Software\Microsoft\InternetExplorer\TypedURLs` e `Software\Microsoft\InternetExplorer\TypedURLsTime`. Eles registram as últimas 50 URLs inseridas pelo usuário e os horários em que foram digitadas pela última vez.

## Microsoft Edge

O Microsoft Edge armazena dados do usuário em `%userprofile%\Appdata\Local\Packages`. Os caminhos para os diferentes tipos de dados são:<sup>[[1]](#references)</sup>

- **Caminho do perfil**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **Histórico, cookies e downloads**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Configurações, marcadores e lista de leitura**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Cache**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Últimas sessões ativas**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Os dados do Safari são armazenados em `/Users/$User/Library/Safari`. Os principais arquivos incluem:<sup>[[3]](#references)</sup>

- **History.db**: Contém as tabelas `history_visits` e `history_items`, com URLs e timestamps de visitas. Use `sqlite3` para fazer consultas.
- **Downloads.plist**: Informações sobre arquivos baixados.
- **Bookmarks.plist**: Armazena URLs marcadas.
- **TopSites.plist**: Sites visitados com mais frequência.
- **Extensions.plist**: Lista de extensões do navegador Safari. Use `plutil` ou `pluginkit` para obter os dados.
- **UserNotificationPermissions.plist**: Domínios autorizados a enviar notificações push. Use `plutil` para analisar o arquivo.
- **LastSession.plist**: Abas da última sessão. Use `plutil` para analisar o arquivo.
- **Proteção antiphishing integrada do navegador**: Verifique com `defaults read com.apple.Safari WarnAboutFraudulentWebsites`. Uma resposta igual a 1 indica que o recurso está ativo.<sup>[[2]](#references)</sup>

## Opera

Os dados do Opera ficam em `/Users/$USER/Library/Application Support/com.operasoftware.Opera`, e o navegador usa o mesmo formato do Chrome para o histórico e os downloads.

- **Proteção antiphishing integrada do navegador**: Verifique se `fraud_protection_enabled` está definido como `true` no arquivo Preferences, usando `grep`.<sup>[[2]](#references)</sup>

Esses caminhos e comandos são essenciais para acessar e compreender os dados de navegação armazenados por diferentes navegadores.

## References

- [1] [Perícia em navegadores: um guia para realizar análises forenses de navegadores](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [2] [Resposta a incidentes no macOS | Parte 3: Manipulação do sistema](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [3] [Resposta a incidentes no OS X: scripting e análise, de Jaron Bradley](https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file)
{{#include ../../../banners/hacktricks-training.md}}
