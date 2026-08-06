# Artefacts du navigateur

{{#include ../../../banners/hacktricks-training.md}}

## Artefacts des navigateurs <a href="#id-3def" id="id-3def"></a>

Les artefacts des navigateurs comprennent différents types de données stockées par les navigateurs web, comme l’historique de navigation, les favoris et les données du cache. Ces artefacts sont conservés dans des dossiers spécifiques du système d’exploitation, dont l’emplacement et le nom varient selon les navigateurs, tout en stockant généralement des types de données similaires.

Voici un résumé des artefacts de navigateur les plus courants :

- **Historique de navigation** : suit les visites de l’utilisateur sur les sites web, ce qui permet notamment d’identifier les visites de sites malveillants.
- **Données de saisie automatique** : suggestions basées sur les recherches fréquentes, fournissant des informations utiles lorsqu’elles sont associées à l’historique de navigation.
- **Favoris** : sites enregistrés par l’utilisateur pour un accès rapide.
- **Extensions et modules complémentaires** : extensions ou modules complémentaires installés par l’utilisateur.
- **Cache** : stocke du contenu web (par exemple, des images et des fichiers JavaScript) afin d’améliorer les temps de chargement des sites web, ce qui est utile pour l’analyse forensique.
- **Identifiants de connexion** : identifiants de connexion stockés.
- **Favicons** : icônes associées aux sites web, affichées dans les onglets et les favoris, utiles pour obtenir des informations supplémentaires sur les visites de l’utilisateur.
- **Sessions du navigateur** : données relatives aux sessions ouvertes du navigateur.
- **Téléchargements** : enregistrements des fichiers téléchargés via le navigateur.
- **Données de formulaire** : informations saisies dans les formulaires web et enregistrées pour de futures suggestions de saisie automatique.
- **Miniatures** : images d’aperçu des sites web.
- **Custom Dictionary.txt** : mots ajoutés par l’utilisateur au dictionnaire du navigateur.

## Firefox

Firefox organise les données utilisateur au sein de profils, stockés dans des emplacements spécifiques selon le système d’exploitation :<sup>[[1]](#references)</sup>

- **Linux** : `~/.mozilla/firefox/`
- **MacOS** : `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows** : `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

Un fichier `profiles.ini` situé dans ces répertoires répertorie les profils utilisateur. Les données de chaque profil sont stockées dans un dossier dont le nom est défini par la variable `Path` dans `profiles.ini`, situé dans le même répertoire que `profiles.ini`. Si le dossier d’un profil est absent, il a peut-être été supprimé.

Dans chaque dossier de profil, plusieurs fichiers importants sont présents :<sup>[[1]](#references)</sup>

- **places.sqlite** : stocke l’historique, les favoris et les téléchargements. Des outils comme [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) sous Windows peuvent accéder aux données d’historique.
- Utilisez des requêtes SQL spécifiques pour extraire les informations relatives à l’historique et aux téléchargements.
- **bookmarkbackups** : contient des sauvegardes des favoris.
- **formhistory.sqlite** : stocke les données des formulaires web.
- **handlers.json** : gère les gestionnaires de protocoles.
- **persdict.dat** : mots du dictionnaire personnalisé.
- **addons.json** et **extensions.sqlite** : informations sur les modules complémentaires et extensions installés.
- **cookies.sqlite** : stockage des cookies, avec [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html) disponible pour leur inspection sous Windows.
- **cache2/entries** ou **startupCache** : données du cache, accessibles via des outils comme [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html).
- **favicons.sqlite** : stocke les favicons.
- **prefs.js** : paramètres et préférences de l’utilisateur.
- **downloads.sqlite** : ancienne base de données des téléchargements, désormais intégrée à places.sqlite.
- **thumbnails** : miniatures des sites web.
- **logins.json** : informations de connexion chiffrées.
- **key4.db** ou **key3.db** : stocke les clés de chiffrement utilisées pour protéger les informations sensibles.

De plus, les paramètres anti-phishing du navigateur peuvent être vérifiés en recherchant les entrées `browser.safebrowsing` dans `prefs.js`, ce qui indique si les fonctionnalités de navigation sécurisée sont activées ou désactivées.<sup>[[2]](#references)</sup>

Pour tenter de déchiffrer le mot de passe maître, vous pouvez utiliser [https://github.com/unode/firefox_decrypt](https://github.com/unode/firefox_decrypt)\
Avec le script et l’appel suivants, vous pouvez spécifier un fichier de mots de passe pour effectuer du brute force :
```bash:brute.sh
#!/bin/bash

#./brute.sh top-passwords.txt 2>/dev/null | grep -A2 -B2 "chrome:"
passfile=$1
while read pass; do
echo "Trying $pass"
echo "$pass" | python firefox_decrypt.py
done < $passfile
```
![Artefacts des navigateurs - Firefox: echo "$pass" | python firefox decrypt.py](<../../../images/image (692).png>)

## Google Chrome

Google Chrome stocke les profils utilisateur dans des emplacements spécifiques selon le système d’exploitation :<sup>[[1]](#references)</sup>

- **Linux** : `~/.config/google-chrome/`
- **Windows** : `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS** : `/Users/$USER/Library/Application Support/Google/Chrome/`

Dans ces répertoires, la plupart des données utilisateur se trouvent dans les dossiers **Default/** ou **ChromeDefaultData/**. Les fichiers suivants contiennent des données importantes :<sup>[[1]](#references)</sup>

- **History** : contient les URL, les téléchargements et les mots-clés de recherche. Sous Windows, [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html) peut être utilisé pour lire l’historique. La colonne « Transition Type » possède différentes significations, notamment les clics de l’utilisateur sur des liens, les URL saisies, les soumissions de formulaires et les rechargements de pages.
- **Cookies** : stocke les cookies. Pour les inspecter, [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html) est disponible.
- **Cache** : contient les données mises en cache. Pour l’inspecter, les utilisateurs Windows peuvent utiliser [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html).

Les applications de bureau basées sur Electron (par exemple Discord) utilisent également Chromium Simple Cache et laissent de nombreux artefacts sur disque. Voir :

{{#ref}}
discord-cache-forensics.md
{{#endref}}
- **Bookmarks** : signets de l’utilisateur.
- **Web Data** : contient l’historique des formulaires.
- **Favicons** : stocke les favicons des sites web.
- **Login Data** : contient les identifiants de connexion, comme les noms d’utilisateur et les mots de passe.
- **Current Session**/**Current Tabs** : données sur la session de navigation actuelle et les onglets ouverts.
- **Last Session**/**Last Tabs** : informations sur les sites actifs lors de la dernière session avant la fermeture de Chrome.
- **Extensions** : répertoires des extensions et addons du navigateur.
- **Thumbnails** : stocke les miniatures des sites web.
- **Preferences** : fichier riche en informations, notamment les paramètres des plugins, des extensions, des fenêtres pop-up, des notifications, etc.
- **Anti-phishing intégré au navigateur** : pour vérifier si la protection anti-phishing et contre les malwares est activée, exécutez `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`. Recherchez `{"enabled: true,"}` dans la sortie.<sup>[[2]](#references)</sup>

## **Récupération des données des bases SQLite**

Comme vous pouvez l’observer dans les sections précédentes, Chrome et Firefox utilisent tous deux des bases de données **SQLite** pour stocker leurs données. Il est possible de **récupérer les entrées supprimées à l’aide de l’outil** [**sqlparse**](https://github.com/padfoot999/sqlparse) **ou de** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases).

## **Internet Explorer 11**

Internet Explorer 11 gère ses données et métadonnées à différents emplacements, ce qui permet de séparer les informations stockées des détails correspondants afin de faciliter leur accès et leur gestion.

### Stockage des métadonnées

Les métadonnées d’Internet Explorer sont stockées dans `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` (où VX correspond à V01, V16 ou V24). Le fichier `V01.log` associé peut révéler des différences entre les heures de modification et celles de `WebcacheVX.data`, indiquant qu’une réparation avec `esentutl /r V01 /d` est nécessaire. Ces métadonnées, stockées dans une base de données ESE, peuvent être récupérées et inspectées respectivement avec des outils tels que photorec et [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html). Dans la table **Containers**, il est possible d’identifier les tables ou conteneurs spécifiques dans lesquels chaque segment de données est stocké, y compris les détails du cache d’autres outils Microsoft tels que Skype.

### Inspection du cache

L’outil [IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) permet d’inspecter le cache et nécessite l’emplacement du dossier d’extraction des données du cache. Les métadonnées du cache comprennent le nom du fichier, le répertoire, le nombre d’accès, l’origine de l’URL et les horodatages indiquant les heures de création, d’accès, de modification et d’expiration du cache.

### Gestion des cookies

Les cookies peuvent être explorés avec [IECookiesView](https://www.nirsoft.net/utils/iecookies.html), dont les métadonnées comprennent les noms, les URL, le nombre d’accès et différents détails temporels. Les cookies persistants sont stockés dans `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies`, tandis que les cookies de session résident en mémoire.

### Détails des téléchargements

Les métadonnées des téléchargements sont accessibles via [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html), certains conteneurs contenant des données telles que l’URL, le type de fichier et l’emplacement du téléchargement. Les fichiers physiques se trouvent dans `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory`.

### Historique de navigation

Pour examiner l’historique de navigation, [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) peut être utilisé. Il nécessite l’emplacement des fichiers d’historique extraits ainsi que la configuration d’Internet Explorer. Les métadonnées comprennent ici les heures de modification et d’accès, ainsi que le nombre d’accès. Les fichiers d’historique se trouvent dans `%userprofile%\Appdata\Local\Microsoft\Windows\History`.

### URL saisies

Les URL saisies et leurs heures d’utilisation sont stockées dans le registre, dans `NTUSER.DAT`, sous `Software\Microsoft\InternetExplorer\TypedURLs` et `Software\Microsoft\InternetExplorer\TypedURLsTime`. Elles enregistrent les 50 dernières URL saisies par l’utilisateur ainsi que les heures de leur dernière saisie.

## Microsoft Edge

Microsoft Edge stocke les données utilisateur dans `%userprofile%\Appdata\Local\Packages`. Les chemins correspondant aux différents types de données sont les suivants :<sup>[[1]](#references)</sup>

- **Profile Path** : `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **History, Cookies, and Downloads** : `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Settings, Bookmarks, and Reading List** : `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Cache** : `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Last Active Sessions** : `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Les données de Safari sont stockées dans `/Users/$User/Library/Safari`. Les principaux fichiers comprennent :<sup>[[3]](#references)</sup>

- **History.db** : contient les tables `history_visits` et `history_items`, avec les URL et les horodatages des visites. Utilisez `sqlite3` pour effectuer des requêtes.
- **Downloads.plist** : informations sur les fichiers téléchargés.
- **Bookmarks.plist** : stocke les URL enregistrées dans les signets.
- **TopSites.plist** : sites les plus fréquemment visités.
- **Extensions.plist** : liste des extensions du navigateur Safari. Utilisez `plutil` ou `pluginkit` pour les récupérer.
- **UserNotificationPermissions.plist** : domaines autorisés à envoyer des notifications push. Utilisez `plutil` pour l’analyser.
- **LastSession.plist** : onglets de la dernière session. Utilisez `plutil` pour l’analyser.
- **Anti-phishing intégré au navigateur** : vérifiez-le avec `defaults read com.apple.Safari WarnAboutFraudulentWebsites`. Une réponse égale à 1 indique que la fonctionnalité est active.<sup>[[2]](#references)</sup>

## Opera

Les données d’Opera se trouvent dans `/Users/$USER/Library/Application Support/com.operasoftware.Opera` et utilisent le même format que Chrome pour l’historique et les téléchargements.

- **Anti-phishing intégré au navigateur** : vérifiez que `fraud_protection_enabled` dans le fichier Preferences est défini sur `true` à l’aide de `grep`.<sup>[[2]](#references)</sup>

Ces chemins et commandes sont essentiels pour accéder aux données de navigation stockées par les différents navigateurs web et les comprendre.

## Références

- [1] [Web Browsers Forensics: A Guide On Doing Web Browsers Forensic Analysis](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [2] [macOS Incident Response | Part 3: System Manipulation](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [3] [OS X Incident Response: Scripting and Analysis by Jaron Bradley](https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file)

{{#include ../../../banners/hacktricks-training.md}}
