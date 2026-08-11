# Artefacts des navigateurs

{{#include ../../../banners/hacktricks-training.md}}

## Artefacts des navigateurs <a href="#id-3def" id="id-3def"></a>

Les artefacts des navigateurs comprennent différents types de données stockées par les navigateurs web, comme l'historique de navigation, les favoris et les données du cache. Ces artefacts sont conservés dans des dossiers spécifiques du système d'exploitation, dont l'emplacement et le nom varient selon les navigateurs, mais qui stockent généralement des types de données similaires.

Voici un résumé des artefacts de navigateur les plus courants :

- **Historique de navigation** : Enregistre les visites de l'utilisateur sur les sites web, ce qui permet notamment d'identifier les visites sur des sites malveillants.
- **Données de saisie semi-automatique** : Suggestions basées sur les recherches fréquentes, offrant des informations utiles lorsqu'elles sont combinées à l'historique de navigation.
- **Favoris** : Sites enregistrés par l'utilisateur pour un accès rapide.
- **Extensions et modules complémentaires** : Extensions ou modules complémentaires installés par l'utilisateur.
- **Cache** : Stocke le contenu web (par exemple, les images et les fichiers JavaScript) afin d'améliorer les temps de chargement des sites web, ce qui est utile pour l'analyse forensic.
- **Connexions** : Identifiants de connexion stockés.
- **Favicons** : Icônes associées aux sites web, affichées dans les onglets et les favoris, utiles pour obtenir des informations supplémentaires sur les visites de l'utilisateur.
- **Sessions du navigateur** : Données liées aux sessions ouvertes du navigateur.
- **Téléchargements** : Enregistrements des fichiers téléchargés via le navigateur.
- **Données des formulaires** : Informations saisies dans les formulaires web et enregistrées pour fournir ultérieurement des suggestions de remplissage automatique.
- **Miniatures** : Images d'aperçu des sites web.
- **Custom Dictionary.txt** : Mots ajoutés par l'utilisateur au dictionnaire du navigateur.

## Firefox

Firefox organise les données utilisateur dans des profils, stockés à des emplacements spécifiques selon le système d'exploitation :<sup>[[1]](#references)</sup>

- **Linux** : `~/.mozilla/firefox/`
- **MacOS** : `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows** : `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

Un fichier `profiles.ini` situé dans ces répertoires répertorie les profils utilisateur. Les données de chaque profil sont stockées dans un dossier dont le nom est défini par la variable `Path` dans `profiles.ini`, situé dans le même répertoire que le fichier `profiles.ini` lui-même. Si le dossier d'un profil est absent, il a peut-être été supprimé.

Dans chaque dossier de profil, plusieurs fichiers importants sont présents :<sup>[[1]](#references)</sup>

- **places.sqlite** : Stocke l'historique, les favoris et les téléchargements. Des outils comme [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) sous Windows peuvent accéder aux données d'historique.
- Utiliser des requêtes SQL spécifiques pour extraire les informations d'historique et de téléchargements.
- **bookmarkbackups** : Contient des sauvegardes des favoris.
- **formhistory.sqlite** : Stocke les données des formulaires web.
- **handlers.json** : Gère les gestionnaires de protocoles.
- **persdict.dat** : Mots du dictionnaire personnalisé.
- **addons.json** et **extensions.sqlite** : Informations sur les modules complémentaires et extensions installés.
- **cookies.sqlite** : Stockage des cookies, avec [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html) disponible pour l'inspection sous Windows.
- **cache2/entries** ou **startupCache** : Données du cache, accessibles via des outils comme [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html).
- **favicons.sqlite** : Stocke les favicons.
- **prefs.js** : Paramètres et préférences utilisateur.
- **downloads.sqlite** : Ancienne base de données des téléchargements, désormais intégrée à places.sqlite.
- **thumbnails** : Miniatures des sites web.
- **logins.json** : Informations de connexion chiffrées.
- **key4.db** ou **key3.db** : Stocke les clés de chiffrement utilisées pour protéger les informations sensibles.

De plus, il est possible de vérifier les paramètres anti-phishing du navigateur en recherchant les entrées `browser.safebrowsing` dans `prefs.js`, afin de déterminer si les fonctionnalités de navigation sécurisée sont activées ou désactivées.<sup>[[2]](#references)</sup>

Pour tenter de déchiffrer le mot de passe principal, vous pouvez utiliser [https://github.com/unode/firefox_decrypt](https://github.com/unode/firefox_decrypt)\
Avec le script et l'appel suivants, vous pouvez spécifier un fichier de mots de passe à brute force :
```bash:brute.sh
#!/bin/bash

#./brute.sh top-passwords.txt 2>/dev/null | grep -A2 -B2 "chrome:"
passfile=$1
while read pass; do
echo "Trying $pass"
echo "$pass" | python firefox_decrypt.py
done < $passfile
```
![Browsers Artifacts - Firefox: echo "$pass" | python firefox decrypt.py](<../../../images/image (692).png>)

## Google Chrome

Google Chrome stocke les profils utilisateur dans des emplacements spécifiques selon le système d'exploitation :<sup>[[1]](#references)</sup>

- **Linux** : `~/.config/google-chrome/`
- **Windows** : `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS** : `/Users/$USER/Library/Application Support/Google/Chrome/`

Dans ces répertoires, la plupart des données utilisateur se trouvent dans les dossiers **Default/** ou **ChromeDefaultData/**. Les fichiers suivants contiennent des données importantes :<sup>[[1]](#references)</sup>

- **History** : contient les URL, les téléchargements et les mots-clés de recherche. Sous Windows, [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html) peut être utilisé pour lire l'historique. La colonne "Transition Type" possède plusieurs significations, notamment les clics de l'utilisateur sur des liens, les URL saisies, les envois de formulaires et les rechargements de pages.
- **Cookies** : stocke les cookies. Pour l'inspection, [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html) est disponible.
- **Cache** : contient les données mises en cache. Pour l'inspecter, les utilisateurs Windows peuvent utiliser [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html).

Les desktop apps basées sur Electron (par exemple, Discord) utilisent également Chromium Simple Cache et laissent des artifacts riches sur le disque. Voir :

{{#ref}}
discord-cache-forensics.md
{{#endref}}
- **Bookmarks** : signets utilisateur.
- **Web Data** : contient l'historique des formulaires.
- **Favicons** : stocke les favicons des sites web.
- **Login Data** : contient les identifiants de connexion tels que les noms d'utilisateur et les mots de passe.
- **Current Session**/**Current Tabs** : données concernant la session de navigation actuelle et les onglets ouverts.
- **Last Session**/**Last Tabs** : informations sur les sites actifs durant la dernière session avant la fermeture de Chrome.
- **Extensions** : répertoires des extensions et addons du navigateur.
- **Thumbnails** : stocke les miniatures des sites web.
- **Preferences** : fichier riche en informations, notamment les paramètres des plugins, extensions, pop-ups, notifications, etc.
- **Browser’s built-in anti-phishing** : pour vérifier si la protection anti-phishing et anti-malware est activée, exécutez `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`. Recherchez `{"enabled: true,"}` dans la sortie.<sup>[[2]](#references)</sup>

## **Récupération des données des bases SQLite**

Comme vous pouvez l'observer dans les sections précédentes, Chrome et Firefox utilisent tous deux des bases de données **SQLite** pour stocker les données. Il est possible de **récupérer les entrées supprimées à l'aide de l'outil** [**sqlparse**](https://github.com/padfoot999/sqlparse) **ou** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases).

## **Internet Explorer 11**

Internet Explorer 11 gère ses données et métadonnées dans différents emplacements, ce qui facilite la séparation des informations stockées et des détails correspondants pour un accès et une gestion simplifiés.

### Stockage des métadonnées

Les métadonnées d'Internet Explorer sont stockées dans `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` (VX correspondant à V01, V16 ou V24). Le fichier `V01.log` associé peut présenter des divergences d'horodatage de modification avec `WebcacheVX.data`, indiquant qu'une réparation avec `esentutl /r V01 /d` est nécessaire. Ces métadonnées, contenues dans une base de données ESE, peuvent être récupérées et inspectées respectivement avec des outils tels que photorec et [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html). Dans la table **Containers**, il est possible d'identifier les tables ou conteneurs spécifiques dans lesquels chaque segment de données est stocké, y compris les détails du cache d'autres outils Microsoft tels que Skype.

### Inspection du cache

L'outil [IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) permet d'inspecter le cache et nécessite l'emplacement du dossier d'extraction des données du cache. Les métadonnées du cache comprennent le nom du fichier, le répertoire, le nombre d'accès, l'origine de l'URL ainsi que les horodatages indiquant les heures de création, d'accès, de modification et d'expiration du cache.

### Gestion des cookies

Les cookies peuvent être examinés avec [IECookiesView](https://www.nirsoft.net/utils/iecookies.html), dont les métadonnées comprennent les noms, les URL, le nombre d'accès et divers détails temporels. Les cookies persistants sont stockés dans `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies`, tandis que les cookies de session résident en mémoire.

### Détails des téléchargements

Les métadonnées des téléchargements sont accessibles via [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html), certains conteneurs contenant des données telles que l'URL, le type de fichier et l'emplacement du téléchargement. Les fichiers physiques se trouvent sous `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory`.

### Historique de navigation

Pour consulter l'historique de navigation, [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) peut être utilisé. Il nécessite l'emplacement des fichiers d'historique extraits ainsi que la configuration d'Internet Explorer. Les métadonnées comprennent les heures de modification et d'accès, ainsi que le nombre d'accès. Les fichiers d'historique se trouvent dans `%userprofile%\Appdata\Local\Microsoft\Windows\History`.

### URL saisies

Les URL saisies et leurs horaires d'utilisation sont stockés dans le registre, sous `NTUSER.DAT`, aux emplacements `Software\Microsoft\InternetExplorer\TypedURLs` et `Software\Microsoft\InternetExplorer\TypedURLsTime`. Ils permettent de suivre les 50 dernières URL saisies par l'utilisateur ainsi que les dernières heures de saisie correspondantes.

## Microsoft Edge

Microsoft Edge stocke les données utilisateur dans `%userprofile%\Appdata\Local\Packages`. Les chemins correspondant aux différents types de données sont les suivants :<sup>[[1]](#references)</sup>

- **Profile Path** : `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **History, Cookies, and Downloads** : `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Settings, Bookmarks, and Reading List** : `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Cache** : `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Last Active Sessions** : `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Les données de Safari sont stockées dans `/Users/$User/Library/Safari`. Les fichiers principaux comprennent :<sup>[[3]](#references)</sup>

- **History.db** : contient les tables `history_visits` et `history_items`, avec les URL et les horodatages des visites. Utilisez `sqlite3` pour effectuer des requêtes.
- **Downloads.plist** : informations sur les fichiers téléchargés.
- **Bookmarks.plist** : stocke les URL enregistrées dans les signets.
- **TopSites.plist** : sites les plus fréquemment visités.
- **Extensions.plist** : liste des extensions du navigateur Safari. Utilisez `plutil` ou `pluginkit` pour les récupérer.
- **UserNotificationPermissions.plist** : domaines autorisés à envoyer des push notifications. Utilisez `plutil` pour analyser le fichier.
- **LastSession.plist** : onglets de la dernière session. Utilisez `plutil` pour analyser le fichier.
- **Browser’s built-in anti-phishing** : vérifiez à l'aide de `defaults read com.apple.Safari WarnAboutFraudulentWebsites`. Une réponse égale à 1 indique que la fonctionnalité est active.<sup>[[2]](#references)</sup>

## Opera

Les données d'Opera se trouvent dans `/Users/$USER/Library/Application Support/com.operasoftware.Opera` et utilisent le même format que Chrome pour l'historique et les téléchargements.

- **Browser’s built-in anti-phishing** : vérifiez si `fraud_protection_enabled` dans le fichier Preferences est défini sur `true` à l'aide de `grep`.<sup>[[2]](#references)</sup>

Ces chemins et commandes sont essentiels pour accéder aux données de navigation stockées par les différents navigateurs web et les comprendre.

## References

- [1] [Forensics des navigateurs web : guide de l'analyse forensic des navigateurs web](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [2] [Réponse aux incidents macOS | Partie 3 : manipulation du système](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [3] [Réponse aux incidents sous OS X : scripting et analyse par Jaron Bradley](https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file)
{{#include ../../../banners/hacktricks-training.md}}
