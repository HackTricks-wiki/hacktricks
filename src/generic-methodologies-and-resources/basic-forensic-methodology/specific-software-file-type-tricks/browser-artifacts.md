# Artefacts du Navigateur

{{#include ../../../banners/hacktricks-training.md}}

## Artefacts des Navigateurs <a href="#id-3def" id="id-3def"></a>

Les artefacts des navigateurs incluent divers types de données stockées par les navigateurs web, telles que l'historique de navigation, les signets et les données de cache. Ces artefacts sont conservés dans des dossiers spécifiques au sein du système d'exploitation, variant en emplacement et en nom selon les navigateurs, mais stockant généralement des types de données similaires.

Voici un résumé des artefacts de navigateur les plus courants :

- **Historique de Navigation** : Suit les visites des utilisateurs sur des sites web, utile pour identifier les visites sur des sites malveillants.
- **Données d'Autocomplétion** : Suggestions basées sur des recherches fréquentes, offrant des aperçus lorsqu'elles sont combinées avec l'historique de navigation.
- **Signets** : Sites enregistrés par l'utilisateur pour un accès rapide.
- **Extensions et Modules Complémentaires** : Extensions de navigateur ou modules installés par l'utilisateur.
- **Cache** : Stocke le contenu web (par exemple, images, fichiers JavaScript) pour améliorer les temps de chargement des sites, précieux pour l'analyse judiciaire.
- **Identifiants** : Informations d'identification stockées.
- **Favicons** : Icônes associées aux sites web, apparaissant dans les onglets et les signets, utiles pour des informations supplémentaires sur les visites des utilisateurs.
- **Sessions de Navigateur** : Données liées aux sessions de navigateur ouvertes.
- **Téléchargements** : Enregistrements des fichiers téléchargés via le navigateur.
- **Données de Formulaire** : Informations saisies dans des formulaires web, sauvegardées pour des suggestions d'autocomplétion futures.
- **Vignettes** : Images d'aperçu des sites web.
- **Custom Dictionary.txt** : Mots ajoutés par l'utilisateur au dictionnaire du navigateur.

## Firefox

Firefox organise les données utilisateur au sein de profils, stockés à des emplacements spécifiques selon le système d'exploitation :

- **Linux** : `~/.mozilla/firefox/`
- **MacOS** : `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows** : `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

Un fichier `profiles.ini` dans ces répertoires liste les profils utilisateur. Les données de chaque profil sont stockées dans un dossier nommé dans la variable `Path` au sein de `profiles.ini`, situé dans le même répertoire que `profiles.ini` lui-même. Si le dossier d'un profil est manquant, il a peut-être été supprimé.

Dans chaque dossier de profil, vous pouvez trouver plusieurs fichiers importants :

- **places.sqlite** : Stocke l'historique, les signets et les téléchargements. Des outils comme [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) sur Windows peuvent accéder aux données d'historique.
- Utilisez des requêtes SQL spécifiques pour extraire les informations d'historique et de téléchargements.
- **bookmarkbackups** : Contient des sauvegardes de signets.
- **formhistory.sqlite** : Stocke les données des formulaires web.
- **handlers.json** : Gère les gestionnaires de protocoles.
- **persdict.dat** : Mots du dictionnaire personnalisé.
- **addons.json** et **extensions.sqlite** : Informations sur les modules et extensions installés.
- **cookies.sqlite** : Stockage des cookies, avec [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html) disponible pour inspection sur Windows.
- **cache2/entries** ou **startupCache** : Données de cache, accessibles via des outils comme [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html).
- **favicons.sqlite** : Stocke les favicons.
- **prefs.js** : Paramètres et préférences utilisateur.
- **downloads.sqlite** : Base de données des anciens téléchargements, maintenant intégrée dans places.sqlite.
- **thumbnails** : Vignettes de sites web.
- **logins.json** : Informations de connexion chiffrées.
- **key4.db** ou **key3.db** : Stocke les clés de chiffrement pour sécuriser les informations sensibles.

De plus, vérifier les paramètres anti-phishing du navigateur peut être fait en recherchant les entrées `browser.safebrowsing` dans `prefs.js`, indiquant si les fonctionnalités de navigation sécurisée sont activées ou désactivées.

Pour essayer de déchiffrer le mot de passe principal, vous pouvez utiliser [https://github.com/unode/firefox_decrypt](https://github.com/unode/firefox_decrypt)\
Avec le script et l'appel suivants, vous pouvez spécifier un fichier de mot de passe à forcer :
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

Google Chrome stocke les profils utilisateurs à des emplacements spécifiques en fonction du système d'exploitation :

- **Linux** : `~/.config/google-chrome/`
- **Windows** : `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS** : `/Users/$USER/Library/Application Support/Google/Chrome/`

Dans ces répertoires, la plupart des données utilisateur peuvent être trouvées dans les dossiers **Default/** ou **ChromeDefaultData/**. Les fichiers suivants contiennent des données significatives :

- **History** : Contient des URL, des téléchargements et des mots-clés de recherche. Sur Windows, [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html) peut être utilisé pour lire l'historique. La colonne "Transition Type" a diverses significations, y compris les clics des utilisateurs sur des liens, les URL tapées, les soumissions de formulaires et les rechargements de pages.
- **Cookies** : Stocke les cookies. Pour inspection, [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html) est disponible.
- **Cache** : Contient des données mises en cache. Pour inspecter, les utilisateurs de Windows peuvent utiliser [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html).
- **Bookmarks** : Signets de l'utilisateur.
- **Web Data** : Contient l'historique des formulaires.
- **Favicons** : Stocke les favicons des sites web.
- **Login Data** : Inclut les identifiants de connexion comme les noms d'utilisateur et les mots de passe.
- **Current Session**/**Current Tabs** : Données sur la session de navigation actuelle et les onglets ouverts.
- **Last Session**/**Last Tabs** : Informations sur les sites actifs lors de la dernière session avant la fermeture de Chrome.
- **Extensions** : Répertoires pour les extensions et addons du navigateur.
- **Thumbnails** : Stocke les vignettes des sites web.
- **Preferences** : Un fichier riche en informations, y compris les paramètres pour les plugins, les extensions, les pop-ups, les notifications, et plus encore.
- **Browser’s built-in anti-phishing** : Pour vérifier si la protection anti-phishing et contre les logiciels malveillants est activée, exécutez `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`. Recherchez `{"enabled: true,"}` dans la sortie.

## **Récupération de données SQLite DB**

Comme vous pouvez l'observer dans les sections précédentes, Chrome et Firefox utilisent des bases de données **SQLite** pour stocker les données. Il est possible de **récupérer des entrées supprimées à l'aide de l'outil** [**sqlparse**](https://github.com/padfoot999/sqlparse) **ou** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases).

## **Internet Explorer 11**

Internet Explorer 11 gère ses données et métadonnées à travers divers emplacements, aidant à séparer les informations stockées et leurs détails correspondants pour un accès et une gestion faciles.

### Stockage des métadonnées

Les métadonnées pour Internet Explorer sont stockées dans `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` (avec VX étant V01, V16, ou V24). Accompagnant cela, le fichier `V01.log` peut montrer des écarts de temps de modification avec `WebcacheVX.data`, indiquant un besoin de réparation en utilisant `esentutl /r V01 /d`. Ces métadonnées, logées dans une base de données ESE, peuvent être récupérées et inspectées à l'aide d'outils comme photorec et [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html), respectivement. Dans la table **Containers**, on peut discerner les tables ou conteneurs spécifiques où chaque segment de données est stocké, y compris les détails de cache pour d'autres outils Microsoft tels que Skype.

### Inspection du cache

L'outil [IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) permet l'inspection du cache, nécessitant l'emplacement du dossier d'extraction des données de cache. Les métadonnées pour le cache incluent le nom de fichier, le répertoire, le nombre d'accès, l'origine de l'URL, et des horodatages indiquant les temps de création, d'accès, de modification et d'expiration du cache.

### Gestion des cookies

Les cookies peuvent être explorés à l'aide de [IECookiesView](https://www.nirsoft.net/utils/iecookies.html), avec des métadonnées englobant les noms, les URL, les comptes d'accès, et divers détails temporels. Les cookies persistants sont stockés dans `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies`, tandis que les cookies de session résident en mémoire.

### Détails des téléchargements

Les métadonnées des téléchargements sont accessibles via [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html), avec des conteneurs spécifiques contenant des données comme l'URL, le type de fichier, et l'emplacement de téléchargement. Les fichiers physiques peuvent être trouvés sous `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory`.

### Historique de navigation

Pour examiner l'historique de navigation, [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) peut être utilisé, nécessitant l'emplacement des fichiers d'historique extraits et la configuration pour Internet Explorer. Les métadonnées ici incluent les temps de modification et d'accès, ainsi que les comptes d'accès. Les fichiers d'historique sont situés dans `%userprofile%\Appdata\Local\Microsoft\Windows\History`.

### URL tapées

Les URL tapées et leurs temps d'utilisation sont stockés dans le registre sous `NTUSER.DAT` à `Software\Microsoft\InternetExplorer\TypedURLs` et `Software\Microsoft\InternetExplorer\TypedURLsTime`, suivant les 50 dernières URL saisies par l'utilisateur et leurs derniers temps d'entrée.

## Microsoft Edge

Microsoft Edge stocke les données utilisateur dans `%userprofile%\Appdata\Local\Packages`. Les chemins pour divers types de données sont :

- **Profile Path** : `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **History, Cookies, and Downloads** : `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Settings, Bookmarks, and Reading List** : `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Cache** : `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Last Active Sessions** : `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Les données de Safari sont stockées à `/Users/$User/Library/Safari`. Les fichiers clés incluent :

- **History.db** : Contient les tables `history_visits` et `history_items` avec des URL et des horodatages de visite. Utilisez `sqlite3` pour interroger.
- **Downloads.plist** : Informations sur les fichiers téléchargés.
- **Bookmarks.plist** : Stocke les URL des signets.
- **TopSites.plist** : Sites les plus fréquemment visités.
- **Extensions.plist** : Liste des extensions du navigateur Safari. Utilisez `plutil` ou `pluginkit` pour récupérer.
- **UserNotificationPermissions.plist** : Domaines autorisés à envoyer des notifications. Utilisez `plutil` pour analyser.
- **LastSession.plist** : Onglets de la dernière session. Utilisez `plutil` pour analyser.
- **Browser’s built-in anti-phishing** : Vérifiez en utilisant `defaults read com.apple.Safari WarnAboutFraudulentWebsites`. Une réponse de 1 indique que la fonctionnalité est active.

## Opera

Les données d'Opera résident dans `/Users/$USER/Library/Application Support/com.operasoftware.Opera` et partagent le format de Chrome pour l'historique et les téléchargements.

- **Browser’s built-in anti-phishing** : Vérifiez en vérifiant si `fraud_protection_enabled` dans le fichier Preferences est défini sur `true` en utilisant `grep`.

Ces chemins et commandes sont cruciaux pour accéder et comprendre les données de navigation stockées par différents navigateurs web.

## Références

- [https://nasbench.medium.com/web-browsers-forensics-7e99940c579a](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file](https://books.google.com/books?id=jfMqCgAAQBAJ&pg=PA128&lpg=PA128&dq=%22This+file)
- **Livre : OS X Incident Response: Scripting and Analysis par Jaron Bradley pag 123**

{{#include ../../../banners/hacktricks-training.md}}
