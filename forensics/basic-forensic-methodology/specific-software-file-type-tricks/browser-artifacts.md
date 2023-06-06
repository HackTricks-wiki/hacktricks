# Artefatos do Navegador

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

![](<../.gitbook/assets/image (9) (1) (2).png>)

\
Use [**Trickest**](https://trickest.io/) para construir e **automatizar fluxos de trabalho** facilmente com as ferramentas comunitárias mais avançadas do mundo.\
Obtenha acesso hoje:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Artefatos do Navegador <a href="#3def" id="3def"></a>

Quando falamos sobre artefatos do navegador, estamos falando sobre o histórico de navegação, favoritos, lista de arquivos baixados, dados de cache, etc.

Esses artefatos são arquivos armazenados em pastas específicas no sistema operacional.

Cada navegador armazena seus arquivos em um lugar diferente dos outros navegadores e todos têm nomes diferentes, mas todos armazenam (na maioria das vezes) o mesmo tipo de dados (artefatos).

Vamos dar uma olhada nos artefatos mais comuns armazenados pelos navegadores.

* **Histórico de Navegação:** Contém dados sobre o histórico de navegação do usuário. Pode ser usado para rastrear se o usuário visitou alguns sites maliciosos, por exemplo.
* **Dados de Autocompletar:** Estes são os dados que o navegador sugere com base no que você mais procura. Pode ser usado em conjunto com o histórico de navegação para obter mais informações.
* **Favoritos:** Autoexplicativo.
* **Extensões e Add-ons:** Autoexplicativo.
* **Cache:** Ao navegar em sites, o navegador cria todos os tipos de dados de cache (imagens, arquivos javascript...etc) por muitas razões. Por exemplo, para acelerar o tempo de carregamento de sites. Esses arquivos de cache podem ser uma ótima fonte de dados durante uma investigação forense.
* **Logins:** Autoexplicativo.
* **Favicons:** Eles são os pequenos ícones encontrados em guias, URLs, favoritos e outros. Eles podem ser usados como outra fonte para obter mais informações sobre o site ou lugares que o usuário visitou.
* **Sessões do Navegador:** Autoexplicativo.
* **Downloads**: Autoexplicativo.
* **Dados de Formulário:** Qualquer coisa digitada dentro de formulários é frequentemente armazenada pelo navegador, para que da próxima vez que o usuário digitar algo dentro de um formulário, o navegador possa sugerir dados inseridos anteriormente.
* **Miniaturas:** Autoexplicativo.
* **Custom Dictionary.txt**: Palavras adicionadas ao dicionário pelo usuário.

## Firefox

O Firefox cria a pasta de perfis em \~/_**.mozilla/firefox/**_ (Linux), em **/Users/$USER/Library/Application Support/Firefox/Profiles/** (MacOS), _**%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\\**_ (Windows)_**.**_\
Dentro desta pasta, o arquivo _**profiles.ini**_ deve aparecer com o nome(s) do(s) perfil(s) do usuário.\
Cada perfil tem uma variável "**Path**" com o nome da pasta onde seus dados serão armazenados. A pasta deve estar **presente no mesmo diretório onde o \_profiles.ini**\_\*\* existe\*\*. Se não estiver, provavelmente foi excluída.

Dentro da pasta **de cada perfil** (_\~/.mozilla/firefox/\<ProfileName>/_) você deve ser capaz de encontrar os seguintes arquivos interessantes:

* _**places.sqlite**_ : Histórico (moz\_\_places), favoritos (moz\_bookmarks) e downloads (moz\_\_annos). No Windows, a ferramenta [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing\_history\_view.html) pode ser usada para ler o histórico dentro de _**places.sqlite**_.
  * Consulta para despejar o histórico: `select datetime(lastvisitdate/1000000,'unixepoch') as visit_date, url, title, visit_count, visit_type FROM moz_places,moz_historyvisits WHERE moz_places.id = moz_historyvisits.place_id;`
    * Observe que o tipo de link é um número que indica:
      * 1: Usuário seguiu um link
      * 2: Usuário escreveu o URL
      * 3: Usuário usou um favorito
      * 4: Carregado a partir de Iframe
      * 5: Acessado via redirecionamento HTTP 301
      * 6: Acessado via redirecionamento HTTP 302
      * 7: Arquivo baixado
      * 8: Usuário seguiu um link dentro de um Iframe
  * Consulta para despejar downloads: `SELECT datetime(lastModified/1000000,'unixepoch') AS down_date, content as File, url as URL FROM moz_places, moz_annos WHERE moz_places.id = moz_annos.place_id;`
  *
* _**bookmarkbackups/**_ : Backups de favoritos
* _**formhistory.sqlite**_ : **Dados de formulário da web** (como e-mails)
* _**handlers.json**_ : Manipuladores de protocolo (como, qual aplicativo vai lidar com o protocolo _mailto://_)
* _**persdict.dat**_ : Palavras adicionadas ao dicionário
* _**addons.json**_ e \_**extensions.sqlite** \_ : Add-ons e extensões instalados
* _**cookies.sqlite**_ : Contém **cookies**. [**MZCookiesView**](https://www.nirsoft.net/utils/mzcv.html) pode ser usado no Windows para inspecionar este arquivo.
*   _**cache2/entries**_ ou _**startupCache**_ : Dados de cache (\~350MB). Truques como **data carving** também podem ser usados para obter os arquivos salvos no cache. [MozillaCacheView](https://www.nirsoft.net/utils/mozilla\_cache\_viewer.html) pode ser usado para ver os **arquivos salvos no cache**.

    Informações que podem ser obtidas:

    * URL, Contagem de busca, Nome do arquivo, Tipo de conteúdo, Tamanho do arquivo, Última hora modificada, Última hora buscada, Última modificação do servidor, Resposta do servidor
*
```bash
#!/bin/bash

#./brute.sh top-passwords.txt 2>/dev/null | grep -A2 -B2 "chrome:"
passfile=$1
while read pass; do
  echo "Trying $pass"
  echo "$pass" | python firefox_decrypt.py
done < $passfile
```
{% endcode %}

![](<../../../.gitbook/assets/image (417).png>)

## Google Chrome

O Google Chrome cria o perfil dentro da pasta do usuário _**\~/.config/google-chrome/**_ (Linux), em _**C:\Users\XXX\AppData\Local\Google\Chrome\User Data\\**_ (Windows), ou em \_**/Users/$USER/Library/Application Support/Google/Chrome/** \_ (MacOS).\
A maioria das informações será salva dentro das pastas _**Default/**_ ou _**ChromeDefaultData/**_ nos caminhos indicados anteriormente. Aqui você pode encontrar os seguintes arquivos interessantes:

* _**History**_: URLs, downloads e até palavras-chave pesquisadas. No Windows, você pode usar a ferramenta [ChromeHistoryView](https://www.nirsoft.net/utils/chrome\_history\_view.html) para ler o histórico. A coluna "Tipo de transição" significa:
  * Link: O usuário clicou em um link
  * Digitado: A URL foi escrita
  * Auto Bookmark
  * Auto Subframe: Adicionar
  * Página inicial: Página inicial
  * Enviar formulário: Um formulário foi preenchido e enviado
  * Recarregado
* _**Cookies**_: Cookies. [ChromeCookiesView](https://www.nirsoft.net/utils/chrome\_cookies\_view.html) pode ser usado para inspecionar os cookies.
* _**Cache**_: Cache. No Windows, você pode usar a ferramenta [ChromeCacheView](https://www.nirsoft.net/utils/chrome\_cache\_view.html) para inspecionar o cache.
* _**Bookmarks**_: Favoritos
* _**Web Data**_: Histórico de formulários
* _**Favicons**_: Favicons
* _**Login Data**_: Informações de login (nomes de usuário, senhas...)
* _**Current Session**_ e _**Current Tabs**_: Dados da sessão atual e guias atuais
* _**Last Session**_ e _**Last Tabs**_: Esses arquivos contêm sites que estavam ativos no navegador quando o Chrome foi fechado pela última vez.
* _**Extensions**_: Pasta de extensões e complementos
* **Thumbnails** : Miniaturas
* **Preferences**: Este arquivo contém uma infinidade de boas informações, como plugins, extensões, sites que usam geolocalização, pop-ups, notificações, pré-busca de DNS, exceções de certificado e muito mais. Se você está tentando pesquisar se uma configuração específica do Chrome estava ativada, provavelmente encontrará essa configuração aqui.
* **Anti-phishing integrado do navegador:** `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`
  * Você pode simplesmente procurar por “**safebrowsing**” e procurar por `{"enabled: true,"}` no resultado para indicar que a proteção contra phishing e malware está ativada.

## **Recuperação de dados do banco de dados SQLite**

Como você pode observar nas seções anteriores, tanto o Chrome quanto o Firefox usam bancos de dados **SQLite** para armazenar os dados. É possível **recuperar entradas excluídas usando a ferramenta** [**sqlparse**](https://github.com/padfoot999/sqlparse) **ou** [**sqlparse\_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases).

## **Internet Explorer 11**

O Internet Explorer armazena **dados** e **metadados** em locais diferentes. Os metadados permitirão encontrar os dados.

Os **metadados** podem ser encontrados na pasta `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data`, onde VX pode ser V01, V16 ou V24.\
Na pasta anterior, você também pode encontrar o arquivo V01.log. Caso o **horário de modificação** deste arquivo e o arquivo WebcacheVX.data **sejam diferentes**, pode ser necessário executar o
