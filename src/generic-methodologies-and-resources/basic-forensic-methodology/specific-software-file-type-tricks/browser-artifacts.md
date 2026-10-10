# Artefacts du navigateur

{{#include ../../../banners/hacktricks-training.md}}

## Artefacts du navigateur <a href="#id-3def" id="id-3def"></a>

Les artefacts du navigateur comprennent divers types de données stockées par les navigateurs web, comme l’historique de navigation, les favoris et les données du cache. Ces artefacts sont conservés dans des dossiers spécifiques du système d’exploitation. Leur emplacement et leur nom varient selon les navigateurs, mais ils contiennent généralement des types de données similaires.

Voici un résumé des artefacts de navigateur les plus courants :

- **Historique de navigation** : suit les visites de l’utilisateur sur les sites web, ce qui permet notamment d’identifier les visites de sites malveillants.
- **Données de saisie semi-automatique** : suggestions basées sur les recherches fréquentes, qui peuvent fournir des informations utiles lorsqu’elles sont associées à l’historique de navigation.
- **Favoris** : sites enregistrés par l’utilisateur pour y accéder rapidement.
- **Extensions et modules complémentaires** : extensions ou modules complémentaires installés par l’utilisateur.
- **Cache** : stocke le contenu web (par exemple, des images et des fichiers JavaScript) afin d’accélérer le chargement des sites web. Il est utile pour l’analyse forensique.
- **Identifiants de connexion** : identifiants enregistrés.
- **Favicons** : icônes associées aux sites web, affichées dans les onglets et les favoris, utiles pour obtenir des informations supplémentaires sur les visites de l’utilisateur.
- **Sessions du navigateur** : données relatives aux sessions ouvertes du navigateur.
- **Téléchargements** : enregistrements des fichiers téléchargés via le navigateur.
- **Données de formulaire** : informations saisies dans des formulaires web et enregistrées pour proposer des suggestions de saisie automatique ultérieurement.
- **Miniatures** : images d’aperçu des sites web.
- **Custom Dictionary.txt** : mots ajoutés par l’utilisateur au dictionnaire du navigateur.

## Firefox

Firefox organise les données utilisateur dans des profils, stockés à des emplacements spécifiques selon le système d’exploitation :<sup>[[1]](#references)</sup>

- **Linux** : `~/.mozilla/firefox/`
- **MacOS** : `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows** : `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

Un fichier `profiles.ini` situé dans ces répertoires répertorie les profils utilisateur. Les données de chaque profil sont stockées dans un dossier dont le nom est indiqué dans la variable `Path` du fichier `profiles.ini`, situé dans le même répertoire que ce dernier. Si le dossier d’un profil est absent, il a peut-être été supprimé.

Chaque dossier de profil contient plusieurs fichiers importants :<sup>[[1]](#references)</sup>

- **places.sqlite** : stocke l’historique, les favoris et les téléchargements. Des outils comme [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) sous Windows permettent d’accéder aux données de l’historique.
  - Utilisez des requêtes SQL spécifiques pour extraire les informations relatives à l’historique et aux téléchargements.
- **bookmarkbackups** : contient des sauvegardes des favoris.
- **formhistory.sqlite** : stocke les données des formulaires web.
- **handlers.json** : gère les gestionnaires de protocoles.
- **persdict.dat** : mots du dictionnaire personnalisé.
- **addons.json** et **extensions.sqlite** : informations sur les modules complémentaires et les extensions installés.
- **cookies.sqlite** : stockage des cookies. Sous Windows, [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html) permet de les examiner.
- **cache2/entries** ou **startupCache** : données du cache, accessibles avec des outils comme [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html).
- **favicons.sqlite** : stocke les favicons.
- **prefs.js** : paramètres et préférences de l’utilisateur.
- **downloads.sqlite** : ancienne base de données des téléchargements, désormais intégrée à places.sqlite.
- **thumbnails** : miniatures des sites web.
- **logins.json** : informations de connexion chiffrées.
- **key4.db** ou **key3.db** : stocke les clés de chiffrement utilisées pour protéger les informations sensibles.

Vous pouvez également vérifier les paramètres anti-hameçonnage du navigateur en recherchant les entrées `browser.safebrowsing` dans `prefs.js`, qui indiquent si les fonctions de navigation sécurisée sont activées ou désactivées.<sup>[[2]](#references)</sup>

Pour déchiffrer les identifiants enregistrés dans un profil auquel vous avez accès, vous devez fournir le [mot de passe principal de Firefox](https://support.mozilla.org/en-US/kb/use-primary-password-protect-stored-logins), s’il est configuré, ou le récupérer séparément ; le profil ne révèle pas ce mot de passe. Vérifiez que tout identifiant récupéré permet de se connecter au compte web correspondant. Un accès root sous Unix exige une preuve distincte que l’identifiant est également accepté par l’authentification Unix pour root. Vous pouvez consulter les identifiants enregistrés avec [firefox_decrypt](https://github.com/unode/firefox_decrypt). L’exemple suivant teste des mots de passe principaux candidats à partir d’un fichier de mots de passe :

```bash:brute.sh
#!/bin/bash

#./brute.sh top-passwords.txt 2>/dev/null | grep -A2 -B2 "chrome:"
passfile=$1
while read pass; do
  echo "Trying $pass"
  echo "$pass" | python firefox_decrypt.py
done < $passfile
```

![Artefacts des navigateurs - Firefox : echo "$pass" | python firefox decrypt.py](<../../../images/image (692).png>)

## Google Chrome

Google Chrome stocke les profils utilisateur à des emplacements spécifiques selon le système d’exploitation :<sup>[[1]](#references)</sup>

- **Linux** : `~/.config/google-chrome/`
- **Windows** : `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS** : `/Users/$USER/Library/Application Support/Google/Chrome/`

Dans ces répertoires, la plupart des données utilisateur se trouvent dans les dossiers **Default/** ou **ChromeDefaultData/**. Les fichiers suivants contiennent des données importantes :<sup>[[1]](#references)</sup>

- **History** : contient les URL, les téléchargements et les mots-clés de recherche. Sous Windows, [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html) permet de consulter l’historique. La colonne « Transition Type » peut indiquer différentes actions, notamment des clics sur des liens, la saisie d’URL, l’envoi de formulaires et le rechargement de pages.
- **Cookies** : stocke les cookies. [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html) permet de les examiner.
- **Cache** : contient les données mises en cache. Sous Windows, [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html) permet de les examiner.

  Les applications de bureau basées sur Electron (par exemple, Discord) utilisent également Chromium Simple Cache et laissent de nombreux artefacts sur le disque. Voir :

  {{#ref}}
  discord-cache-forensics.md
  {{#endref}}
- **Bookmarks** : favoris de l’utilisateur.
- **Web Data** : contient l’historique des formulaires.
- **Favicons** : stocke les favicons des sites web.
- **Login Data** : contient des identifiants de connexion, comme les noms d’utilisateur et les mots de passe.
- **Current Session**/**Current Tabs** : données sur la session de navigation en cours et les onglets ouverts.
- **Last Session**/**Last Tabs** : informations sur les sites actifs lors de la dernière session avant la fermeture de Chrome.
- **Extensions** : répertoires des extensions et modules complémentaires du navigateur.
- **Thumbnails** : stocke les miniatures des sites web.
- **Preferences** : fichier riche en informations, notamment sur les paramètres des plug-ins, des extensions, des fenêtres pop-up, des notifications, etc.
- **Protection anti-hameçonnage intégrée au navigateur** : pour vérifier si la protection contre l’hameçonnage et les logiciels malveillants est activée, exécutez `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`. Recherchez `{"enabled: true,"}` dans la sortie.<sup>[[2]](#references)</sup>

Le répertoire `Local Extension Settings/<extension-id>/` d’un profil Chromium peut contenir l’état local d’une extension, notamment des éléments cryptographiques utilisés par un gestionnaire de mots de passe. Par exemple, [Passbolt indique que sa clé privée chiffrée est stockée dans le stockage local de l’extension du navigateur](https://www.passbolt.com/docs/user/faq/why-a-browser-extension/), et son [ID d’extension Chrome](https://chromewebstore.google.com/detail/passbolt-open-source-pass/didegimhafipceonhjepacocaffmoppf) permet d’identifier le répertoire concerné. La présence du répertoire ne prouve pas qu’une clé s’y trouve et ne permet pas, à elle seule, de déverrouiller un coffre-fort : l’utilisateur doit avoir accès aux données du profil, disposer d’une clé privée utilisable et de sa phrase secrète, ainsi que d’une procédure de récupération ou d’authentification autorisée auprès du serveur. Un élément du coffre-fort contenant le mot de passe d’un compte du système d’exploitation nécessite une vérification distincte de la réutilisation du mot de passe. Lors d’une énumération courante, indiquez uniquement le chemin de stockage, sans extraire les fichiers LevelDB ni les valeurs secrètes.

## **Récupération de données SQLite**

Comme vous pouvez le constater dans les sections précédentes, Chrome et Firefox utilisent tous deux des bases de données **SQLite** pour stocker les données. Il est possible de **récupérer les entrées supprimées à l’aide de l’outil** [**sqlparse**](https://github.com/padfoot999/sqlparse) **ou de** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases).

## **Internet Explorer 11**

Internet Explorer 11 gère ses données et métadonnées à plusieurs emplacements, ce qui permet de séparer les informations stockées des détails qui leur correspondent et de faciliter leur accès et leur gestion.

### Stockage des métadonnées

Les métadonnées d’Internet Explorer sont stockées dans `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` (VX correspondant à V01, V16 ou V24). Le fichier `V01.log` associé peut présenter des différences d’horodatage de modification avec `WebcacheVX.data`, ce qui peut indiquer qu’une réparation est nécessaire à l’aide de `esentutl /r V01 /d`. Ces métadonnées, stockées dans une base de données ESE, peuvent être récupérées et examinées à l’aide d’outils tels que photorec et [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html), respectivement. Dans la table **Containers**, on peut repérer les tables ou conteneurs spécifiques où chaque segment de données est stocké, notamment les détails du cache d’autres outils Microsoft comme Skype.

### Inspection du cache

L’outil [IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) permet d’inspecter le cache et nécessite le chemin du dossier d’extraction des données du cache. Les métadonnées du cache comprennent le nom du fichier, le répertoire, le nombre d’accès, l’URL d’origine et les horodatages de création, d’accès, de modification et d’expiration du cache.

### Gestion des cookies

Les cookies peuvent être examinés à l’aide de [IECookiesView](https://www.nirsoft.net/utils/iecookies.html). Les métadonnées comprennent les noms, les URL, les nombres d’accès et différents horodatages. Les cookies persistants sont stockés dans `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies`, tandis que les cookies de session résident en mémoire.

### Détails des téléchargements

Les métadonnées des téléchargements sont accessibles avec [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html). Certains conteneurs contiennent des données telles que l’URL, le type de fichier et l’emplacement de téléchargement. Les fichiers se trouvent dans `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory`.

### Historique de navigation

Pour consulter l’historique de navigation, [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) peut être utilisé. Il nécessite l’emplacement des fichiers d’historique extraits ainsi qu’une configuration pour Internet Explorer. Les métadonnées comprennent les heures de modification et d’accès, ainsi que le nombre d’accès. Les fichiers d’historique se trouvent dans `%userprofile%\Appdata\Local\Microsoft\Windows\History`.

### URL saisies

Les URL saisies et leurs heures d’utilisation sont stockées dans le registre, dans `NTUSER.DAT`, sous `Software\Microsoft\InternetExplorer\TypedURLs` et `Software\Microsoft\InternetExplorer\TypedURLsTime`. Ces entrées suivent les 50 dernières URL saisies par l’utilisateur et l’heure de leur dernière saisie.

## Microsoft Edge

Microsoft Edge stocke les données utilisateur dans `%userprofile%\Appdata\Local\Packages`. Les chemins d’accès aux différents types de données sont les suivants :<sup>[[1]](#references)</sup>

- **Chemin du profil** : `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **Historique, cookies et téléchargements** : `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Paramètres, favoris et liste de lecture** : `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Cache** : `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Dernières sessions actives** : `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Les données de Safari sont stockées dans `/Users/$User/Library/Safari`. Les principaux fichiers comprennent :<sup>[[3]](#references)</sup>

- **History.db** : contient les tables `history_visits` et `history_items`, qui comprennent les URL et les horodatages des visites. Utilisez `sqlite3` pour effectuer des requêtes.
- **Downloads.plist** : informations sur les fichiers téléchargés.
- **Bookmarks.plist** : stocke les URL enregistrées dans les favoris.
- **TopSites.plist** : sites les plus fréquemment visités.
- **Extensions.plist** : liste des extensions du navigateur Safari. Utilisez `plutil` ou `pluginkit` pour l’obtenir.
- **UserNotificationPermissions.plist** : domaines autorisés à envoyer des notifications push. Utilisez `plutil` pour analyser le fichier.
- **LastSession.plist** : onglets de la dernière session. Utilisez `plutil` pour analyser le fichier.
- **Protection anti-hameçonnage intégrée au navigateur** : vérifiez son état avec `defaults read com.apple.Safari WarnAboutFraudulentWebsites`. Une réponse égale à 1 indique que la fonctionnalité est active.<sup>[[2]](#references)</sup>

## Opera

Les données d’Opera se trouvent dans `/Users/$USER/Library/Application Support/com.operasoftware.Opera`. Le navigateur utilise le même format que Chrome pour l’historique et les téléchargements.

- **Protection anti-hameçonnage intégrée au navigateur** : vérifiez avec `grep` si `fraud_protection_enabled` est défini sur `true` dans le fichier Preferences.<sup>[[2]](#references)</sup>

Ces chemins et commandes sont essentiels pour accéder aux données de navigation stockées par les différents navigateurs web et les comprendre.

## References

- [1] [Analyse forensique des navigateurs web : guide d’analyse forensique des navigateurs web](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [2] [Réponse aux incidents macOS | Partie 3 : manipulation du système](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [3] [Réponse aux incidents sous OS X : scripting et analyse, par Jaron Bradley](https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file)
{{#include ../../../banners/hacktricks-training.md}}
