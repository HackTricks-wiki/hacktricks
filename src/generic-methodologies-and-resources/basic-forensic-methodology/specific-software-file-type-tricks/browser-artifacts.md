# Artefacts du navigateur

{{#include ../../../banners/hacktricks-training.md}}

## Artefacts des navigateurs <a href="#id-3def" id="id-3def"></a>

Les artefacts du navigateur comprennent divers types de données stockées par les navigateurs web, tels que l'historique de navigation, les signets et les données de cache. Ces artefacts sont conservés dans des dossiers spécifiques au sein du système d'exploitation, dont l'emplacement et le nom varient selon les navigateurs, mais contenant généralement des types de données similaires.

Voici un résumé des artefacts de navigateur les plus courants :

- **Historique de navigation** : Suit les visites de l'utilisateur sur les sites web, utile pour identifier les visites de sites malveillants.
- **Données d'autocomplétion** : Suggestions basées sur des recherches fréquentes, offrant des indications lorsqu'elles sont combinées avec l'historique de navigation.
- **Signets** : Sites sauvegardés par l'utilisateur pour un accès rapide.
- **Extensions et modules complémentaires** : Extensions ou add-ons installés par l'utilisateur.
- **Cache** : Stocke le contenu web (par ex. images, fichiers JavaScript) pour améliorer les temps de chargement des sites, utile en analyse médico-légale.
- **Identifiants** : Identifiants de connexion stockés.
- **Favicons** : Icônes associées aux sites web, apparaissant dans les onglets et les signets, utiles pour obtenir des informations supplémentaires sur les visites utilisateur.
- **Sessions du navigateur** : Données liées aux sessions de navigateur ouvertes.
- **Téléchargements** : Enregistrements des fichiers téléchargés via le navigateur.
- **Données de formulaire** : Informations saisies dans les formulaires web, sauvegardées pour les suggestions d'autocomplétion futures.
- **Vignettes** : Images d'aperçu des sites web.
- **Custom Dictionary.txt** : Mots ajoutés par l'utilisateur au dictionnaire du navigateur.

## Firefox

Firefox organise les données utilisateur au sein de profils, stockés à des emplacements spécifiques selon le système d'exploitation :

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

Un fichier `profiles.ini` dans ces répertoires liste les profils utilisateur. Les données de chaque profil sont stockées dans un dossier nommé dans la variable Path à l'intérieur de `profiles.ini`, situé dans le même répertoire que `profiles.ini` lui-même. Si le dossier d'un profil manque, il peut avoir été supprimé.

Dans chaque dossier de profil, vous pouvez trouver plusieurs fichiers importants :

- **places.sqlite**: Stocke l'historique, les signets et les téléchargements. Des outils comme [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) sous Windows peuvent accéder aux données d'historique.
- Utiliser des requêtes SQL spécifiques pour extraire les informations d'historique et de téléchargements.
- **bookmarkbackups**: Contient des sauvegardes des signets.
- **formhistory.sqlite**: Stocke les données des formulaires web.
- **handlers.json**: Gère les protocol handlers.
- **persdict.dat**: Mots du dictionnaire personnalisé.
- **addons.json** et **extensions.sqlite**: Informations sur les add-ons et extensions installés.
- **cookies.sqlite**: Stockage des cookies, avec [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html) disponible pour inspection sous Windows.
- **cache2/entries** ou **startupCache**: Données de cache, accessibles via des outils comme [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html).
- **favicons.sqlite**: Stocke les favicons.
- **prefs.js**: Paramètres et préférences utilisateur.
- **downloads.sqlite**: Ancienne base de données des téléchargements, maintenant intégrée dans places.sqlite.
- **thumbnails**: Vignettes des sites web.
- **logins.json**: Informations de connexion chiffrées.
- **key4.db** ou **key3.db**: Stocke les clés de chiffrement pour sécuriser les informations sensibles.

De plus, vérifier les paramètres anti-phishing du navigateur peut se faire en recherchant des entrées `browser.safebrowsing` dans `prefs.js`, indiquant si les fonctionnalités de safe browsing sont activées ou désactivées.

Pour tenter de décrypter le mot de passe maître, vous pouvez utiliser [https://github.com/unode/firefox_decrypt](https://github.com/unode/firefox_decrypt)\
Avec le script suivant et l'appel vous pouvez spécifier un fichier de mots de passe pour une attaque par force brute :
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

Google Chrome stocke les profils utilisateur dans des emplacements spécifiques selon le système d'exploitation :

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

Dans ces répertoires, la plupart des données utilisateur se trouvent dans les dossiers **Default/** ou **ChromeDefaultData/**. Les fichiers suivants contiennent des données importantes :

- **History** : Contient les URL, les téléchargements et les mots-clés de recherche. Sur Windows, [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html) peut être utilisé pour lire l'historique. La colonne "Transition Type" a plusieurs significations, incluant les clics utilisateur sur des liens, les URL tapées, les soumissions de formulaires et les rechargements de page.
- **Cookies** : Stocke les cookies. Pour les inspecter, [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html) est disponible.
- **Cache** : Contient des données mises en cache. Pour les inspecter, les utilisateurs Windows peuvent utiliser [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html).

Les applications desktop basées sur Electron (par ex. Discord) utilisent également Chromium Simple Cache et laissent des artefacts riches sur disque. Voir :

{{#ref}}
discord-cache-forensics.md
{{#endref}}
- **Bookmarks** : Favoris utilisateur.
- **Web Data** : Contient l'historique de formulaires.
- **Favicons** : Stocke les favicons des sites web.
- **Login Data** : Contient les identifiants de connexion tels que noms d'utilisateur et mots de passe.
- **Current Session**/**Current Tabs** : Données sur la session de navigation en cours et les onglets ouverts.
- **Last Session**/**Last Tabs** : Informations sur les sites actifs pendant la dernière session avant la fermeture de Chrome.
- **Extensions** : Répertoires pour les extensions et addons du navigateur.
- **Thumbnails** : Stocke les miniatures des sites web.
- **Preferences** : Fichier riche en informations, incluant les paramètres des plugins, extensions, pop-ups, notifications, et plus.
- **Browser’s built-in anti-phishing** : Pour vérifier si la protection contre le phishing et les malwares est activée, lancez `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`. Recherchez `{"enabled: true,"}` dans la sortie.

## **SQLite DB Data Recovery**

Comme vous pouvez le constater dans les sections précédentes, Chrome et Firefox utilisent des bases de données **SQLite** pour stocker les données. Il est possible de **récupérer des entrées supprimées en utilisant l'outil** [**sqlparse**](https://github.com/padfoot999/sqlparse) **ou** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases).

## **Internet Explorer 11**

Internet Explorer 11 gère ses données et métadonnées à travers plusieurs emplacements, ce qui aide à séparer l'information stockée et ses détails correspondants pour un accès et une gestion facilités.

### Metadata Storage

Les métadonnées pour Internet Explorer sont stockées dans `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` (avec VX étant V01, V16, ou V24). Le fichier `V01.log` peut présenter des divergences d'horodatage de modification avec `WebcacheVX.data`, indiquant un besoin de réparation via `esentutl /r V01 /d`. Ces métadonnées, hébergées dans une base ESE, peuvent être récupérées et inspectées respectivement avec des outils comme photorec et [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html). Dans la table **Containers**, on peut discerner les tables ou containers spécifiques où chaque segment de données est stocké, incluant les détails du cache pour d'autres outils Microsoft comme Skype.

### Cache Inspection

L'outil [IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) permet d'inspecter le cache, nécessitant l'emplacement du dossier d'extraction des données du cache. Les métadonnées du cache incluent le nom de fichier, le répertoire, le nombre d'accès, l'URL d'origine et des horodatages indiquant la création, l'accès, la modification et l'expiration du cache.

### Cookies Management

Les cookies peuvent être explorés avec [IECookiesView](https://www.nirsoft.net/utils/iecookies.html), les métadonnées comprenant noms, URL, comptes d'accès et divers détails temporels. Les cookies persistants sont stockés dans `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies`, tandis que les cookies de session résident en mémoire.

### Download Details

Les métadonnées des téléchargements sont accessibles via [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html), avec des containers spécifiques contenant des données telles que l'URL, le type de fichier et l'emplacement du téléchargement. Les fichiers physiques peuvent se trouver sous `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory`.

### Browsing History

Pour consulter l'historique de navigation, [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) peut être utilisé, en fournissant l'emplacement des fichiers d'historique extraits et la configuration pour Internet Explorer. Les métadonnées incluent les temps de modification et d'accès, ainsi que les comptes d'accès. Les fichiers d'historique se trouvent dans `%userprofile%\Appdata\Local\Microsoft\Windows\History`.

### Typed URLs

Les URL tapées et leurs horaires d'utilisation sont stockées dans le registre sous `NTUSER.DAT` à `Software\Microsoft\InternetExplorer\TypedURLs` et `Software\Microsoft\InternetExplorer\TypedURLsTime`, suivant les 50 dernières URL entrées par l'utilisateur et leurs derniers temps de saisie.

## Microsoft Edge

Microsoft Edge stocke les données utilisateur dans `%userprofile%\Appdata\Local\Packages`. Les chemins pour divers types de données sont :

- **Profile Path**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **History, Cookies, and Downloads**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Settings, Bookmarks, and Reading List**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Cache**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Last Active Sessions**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Les données Safari sont stockées dans `/Users/$User/Library/Safari`. Les fichiers clés incluent :

- **History.db** : Contient les tables `history_visits` et `history_items` avec les URL et les horodatages des visites. Utilisez `sqlite3` pour interroger.
- **Downloads.plist** : Informations sur les fichiers téléchargés.
- **Bookmarks.plist** : Stocke les URLs mises en favoris.
- **TopSites.plist** : Sites les plus visités.
- **Extensions.plist** : Liste des extensions Safari. Utilisez `plutil` ou `pluginkit` pour récupérer.
- **UserNotificationPermissions.plist** : Domaines autorisés à envoyer des notifications. Utilisez `plutil` pour analyser.
- **LastSession.plist** : Onglets de la dernière session. Utilisez `plutil` pour analyser.
- **Browser’s built-in anti-phishing** : Vérifiez avec `defaults read com.apple.Safari WarnAboutFraudulentWebsites`. Une réponse de 1 indique que la fonctionnalité est active.

## Opera

Les données d'Opera résident dans `/Users/$USER/Library/Application Support/com.operasoftware.Opera` et partagent le format de Chrome pour l'historique et les téléchargements.

- **Browser’s built-in anti-phishing** : Vérifiez en regardant si `fraud_protection_enabled` dans le fichier Preferences est défini sur `true` avec `grep`.

Ces chemins et commandes sont essentiels pour accéder et comprendre les données de navigation stockées par les différents navigateurs web.

## Références

- [https://nasbench.medium.com/web-browsers-forensics-7e99940c579a](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file](https://books.google.com/books?id=jfMqCgAAQBAJ&pg=PA128&lpg=PA128&dq=%22This+file)
- **Livre : OS X Incident Response: Scripting and Analysis By Jaron Bradley p. 123**


{{#include ../../../banners/hacktricks-training.md}}
