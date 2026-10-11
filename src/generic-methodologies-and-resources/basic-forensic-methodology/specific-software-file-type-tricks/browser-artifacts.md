# Artefacts du navigateur

{{#include ../../../banners/hacktricks-training.md}}

## Artefacts des navigateurs <a href="#id-3def" id="id-3def"></a>

Les artefacts des navigateurs comprennent différents types de données stockées par les navigateurs web, comme l’historique de navigation, les marque-pages et les données du cache. Ces artefacts sont conservés dans des dossiers spécifiques du système d’exploitation, dont l’emplacement et le nom varient selon le navigateur, mais qui stockent généralement des types de données similaires.

Voici un résumé des artefacts de navigateur les plus courants :

- **Historique de navigation** : suit les sites web consultés par l’utilisateur, ce qui permet notamment d’identifier les visites de sites malveillants.
- **Données de saisie semi-automatique** : suggestions basées sur les recherches fréquentes, qui peuvent fournir des informations lorsqu’elles sont combinées à l’historique de navigation.
- **Marque-pages** : sites enregistrés par l’utilisateur pour y accéder rapidement.
- **Extensions et modules complémentaires** : extensions ou modules complémentaires installés par l’utilisateur.
- **Cache** : stocke le contenu web (par exemple, des images et des fichiers JavaScript) pour accélérer le chargement des sites ; ces données sont utiles pour l’analyse forensique.
- **Identifiants** : identifiants de connexion stockés.
- **Favicons** : icônes associées aux sites web, affichées dans les onglets et les marque-pages, utiles pour obtenir des informations supplémentaires sur les visites de l’utilisateur.
- **Sessions du navigateur** : données relatives aux sessions ouvertes du navigateur.
- **Téléchargements** : enregistrements des fichiers téléchargés via le navigateur.
- **Données de formulaire** : informations saisies dans les formulaires web et enregistrées pour proposer des suggestions de remplissage automatique.
- **Miniatures** : images d’aperçu des sites web.
- **Custom Dictionary.txt** : mots ajoutés par l’utilisateur au dictionnaire du navigateur.

## Firefox

Firefox organise les données utilisateur dans des profils, stockés dans des emplacements spécifiques selon le système d’exploitation :<sup>[[1]](#references)</sup>

- **Linux** : `~/.mozilla/firefox/`
- **MacOS** : `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows** : `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

Un fichier `profiles.ini` présent dans ces répertoires répertorie les profils utilisateur. Les données de chaque profil sont stockées dans un dossier dont le nom est indiqué par la variable `Path` dans `profiles.ini`, situé dans le même répertoire que le fichier `profiles.ini`. Si le dossier d’un profil est absent, il a peut-être été supprimé.

Dans chaque dossier de profil, vous trouverez plusieurs fichiers importants :<sup>[[1]](#references)</sup>

- **places.sqlite** : stocke l’historique, les marque-pages et les téléchargements. Des outils comme [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) sous Windows permettent d’accéder aux données de l’historique.
  - Utilisez des requêtes SQL spécifiques pour extraire l’historique et les informations sur les téléchargements.
- **bookmarkbackups** : contient des sauvegardes des marque-pages.
- **formhistory.sqlite** : stocke les données des formulaires web.
- **handlers.json** : gère les gestionnaires de protocoles.
- **persdict.dat** : mots du dictionnaire personnalisé.
- **addons.json** et **extensions.sqlite** : informations sur les modules complémentaires et extensions installés.
- **cookies.sqlite** : stockage des cookies ; [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html) permet de les examiner sous Windows.
- **cache2/entries** ou **startupCache** : données du cache, accessibles avec des outils comme [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html).
- **favicons.sqlite** : stocke les favicons.
- **prefs.js** : paramètres et préférences de l’utilisateur.
- **downloads.sqlite** : ancienne base de données des téléchargements, désormais intégrée à places.sqlite.
- **thumbnails** : miniatures des sites web.
- **logins.json** : informations de connexion chiffrées.
- **key4.db** ou **key3.db** : stocke les clés de chiffrement qui protègent les informations sensibles.

Par ailleurs, vous pouvez vérifier les paramètres anti-hameçonnage du navigateur en recherchant les entrées `browser.safebrowsing` dans `prefs.js`, qui indiquent si les fonctionnalités de navigation sécurisée sont activées ou désactivées.<sup>[[2]](#references)</sup>

Pour déchiffrer les identifiants enregistrés dans un profil accessible, il faut fournir ou récupérer séparément le [mot de passe principal de Firefox](https://support.mozilla.org/en-US/kb/use-primary-password-protect-stored-logins), s’il a été configuré ; le profil ne révèle pas ce mot de passe. Vérifiez que tout identifiant récupéré permet de se connecter au compte web correspondant. L’accès root Unix nécessite une preuve distincte que l’identifiant est également accepté par l’authentification Unix pour root. Vous pouvez consulter les identifiants enregistrés avec [firefox_decrypt](https://github.com/unode/firefox_decrypt). L’exemple suivant teste des mots de passe principaux candidats à partir d’un fichier de mots de passe :

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

- **History** : contient les URL, les téléchargements et les mots-clés de recherche. Sous Windows, [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html) permet de consulter l’historique. La colonne « Transition Type » peut avoir plusieurs significations : clics de l’utilisateur sur des liens, URL saisies, envois de formulaires et rechargements de pages.
- **Cookies** : stocke les cookies. [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html) permet de les examiner.
- **Cache** : contient les données mises en cache. Sous Windows, [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html) permet de les examiner.

  Les applications de bureau basées sur Electron (par exemple, Discord) utilisent également Chromium Simple Cache et laissent de nombreux artefacts sur le disque. Voir :

  {{#ref}}
  discord-cache-forensics.md
  {{#endref}}
- **Bookmarks** : marque-pages de l’utilisateur.
- **Web Data** : contient l’historique des formulaires.
- **Favicons** : stocke les favicons des sites web.
- **Login Data** : contient les identifiants de connexion, comme les noms d’utilisateur et les mots de passe.
- **Current Session**/**Current Tabs** : données sur la session de navigation en cours et les onglets ouverts.
- **Last Session**/**Last Tabs** : informations sur les sites actifs lors de la dernière session avant la fermeture de Chrome.
- **Extensions** : répertoires des extensions et modules complémentaires du navigateur.
- **Thumbnails** : stocke les miniatures des sites web.
- **Preferences** : fichier riche en informations, notamment sur les paramètres des plugins, extensions, fenêtres pop-up, notifications, etc.
- **Protection anti-hameçonnage intégrée au navigateur** : pour vérifier si la protection contre l’hameçonnage et les logiciels malveillants est activée, exécutez `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`. Recherchez `{"enabled: true,"}` dans la sortie.<sup>[[2]](#references)</sup>

Le répertoire `Local Extension Settings/<extension-id>/` d’un profil Chromium peut contenir l’état local d’une extension, notamment des éléments de clé d’un gestionnaire de mots de passe. Par exemple, [Passbolt indique que sa clé privée chiffrée est stockée dans le stockage local de l’extension du navigateur](https://www.passbolt.com/docs/user/faq/why-a-browser-extension/), et son [ID d’extension Chrome](https://chromewebstore.google.com/detail/passbolt-open-source-pass/didegimhafipceonhjepacocaffmoppf) permet d’identifier le répertoire correspondant. La seule présence du répertoire ne prouve pas qu’une clé s’y trouve et ne déverrouille pas un coffre-fort : l’utilisateur doit avoir accès aux données du profil, disposer d’une clé privée utilisable et de sa phrase de passe, ainsi que d’un moyen autorisé de récupération ou d’authentification auprès du serveur. Un élément du coffre-fort contenant le mot de passe d’un compte du système d’exploitation nécessite une vérification distincte de la réutilisation de ce mot de passe. Lors d’une énumération de routine, indiquez uniquement le chemin de stockage, sans extraire les fichiers LevelDB ni les valeurs secrètes.

## **Récupération des données SQLite DB**

Comme indiqué dans les sections précédentes, Chrome et Firefox utilisent tous deux des bases de données **SQLite** pour stocker les données. Il est possible de **récupérer des entrées supprimées avec l’outil** [**sqlparse**](https://github.com/padfoot999/sqlparse) **ou** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases).

## **Internet Explorer 11**

Internet Explorer 11 gère ses données et métadonnées à plusieurs emplacements afin de séparer les informations stockées des détails correspondants, pour en faciliter l’accès et la gestion.

### Stockage des métadonnées

Les métadonnées d’Internet Explorer sont stockées dans `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` (VX correspondant à V01, V16 ou V24). Le fichier `V01.log` associé peut présenter une heure de modification différente de celle de `WebcacheVX.data`, ce qui peut indiquer la nécessité d’une réparation à l’aide de `esentutl /r V01 /d`. Ces métadonnées, contenues dans une base de données ESE, peuvent être récupérées et examinées respectivement avec des outils comme photorec et [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html). Dans la table **Containers**, il est possible d’identifier les tables ou conteneurs spécifiques où sont stockés les différents segments de données, notamment les détails du cache d’autres outils Microsoft comme Skype.

### Inspection du cache

L’outil [IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) permet d’inspecter le cache ; il faut lui indiquer l’emplacement du dossier contenant les données du cache extraites. Les métadonnées du cache comprennent le nom du fichier, le répertoire, le nombre d’accès, l’URL d’origine et les horodatages de création, d’accès, de modification et d’expiration du cache.

### Gestion des cookies

Les cookies peuvent être examinés à l’aide de [IECookiesView](https://www.nirsoft.net/utils/iecookies.html). Les métadonnées comprennent les noms, les URL, le nombre d’accès et divers détails temporels. Les cookies persistants sont stockés dans `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies`, tandis que les cookies de session résident en mémoire.

### Détails des téléchargements

Les métadonnées des téléchargements sont accessibles avec [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) ; certains conteneurs contiennent des données telles que l’URL, le type de fichier et l’emplacement de téléchargement. Les fichiers se trouvent dans `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory`.

### Historique de navigation

Pour consulter l’historique de navigation, [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) peut être utilisé ; il faut lui indiquer l’emplacement des fichiers d’historique extraits et le configurer pour Internet Explorer. Les métadonnées comprennent les heures de modification et d’accès, ainsi que le nombre d’accès. Les fichiers d’historique se trouvent dans `%userprofile%\Appdata\Local\Microsoft\Windows\History`.

### URL saisies

Les URL saisies et leurs heures d’utilisation sont stockées dans le registre, sous `NTUSER.DAT`, aux clés `Software\Microsoft\InternetExplorer\TypedURLs` et `Software\Microsoft\InternetExplorer\TypedURLsTime`. Elles suivent les 50 dernières URL saisies par l’utilisateur et l’heure de leur dernière saisie.

## Microsoft Edge

Microsoft Edge stocke les données utilisateur dans `%userprofile%\Appdata\Local\Packages`. Les chemins des différents types de données sont les suivants :<sup>[[1]](#references)</sup>

- **Chemin du profil** : `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **Historique, cookies et téléchargements** : `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Paramètres, marque-pages et liste de lecture** : `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Cache** : `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Dernières sessions actives** : `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Les données de Safari sont stockées dans `/Users/$User/Library/Safari`. Les principaux fichiers sont les suivants :<sup>[[3]](#references)</sup>

- **History.db** : contient les tables `history_visits` et `history_items`, qui renferment les URL et les horodatages des visites. Utilisez `sqlite3` pour effectuer des requêtes.
- **Downloads.plist** : informations sur les fichiers téléchargés.
- **Bookmarks.plist** : stocke les URL mises en marque-page.
- **TopSites.plist** : sites les plus fréquemment visités.
- **Extensions.plist** : liste des extensions du navigateur Safari. Utilisez `plutil` ou `pluginkit` pour l’obtenir.
- **UserNotificationPermissions.plist** : domaines autorisés à envoyer des notifications push. Utilisez `plutil` pour analyser le fichier.
- **LastSession.plist** : onglets de la dernière session. Utilisez `plutil` pour analyser le fichier.
- **Protection anti-hameçonnage intégrée au navigateur** : vérifiez son état avec `defaults read com.apple.Safari WarnAboutFraudulentWebsites`. Une réponse égale à 1 indique que la fonctionnalité est active.<sup>[[2]](#references)</sup>

## Opera

Les données d’Opera se trouvent dans `/Users/$USER/Library/Application Support/com.operasoftware.Opera`. Le navigateur utilise le même format que Chrome pour l’historique et les téléchargements.

- **Protection anti-hameçonnage intégrée au navigateur** : vérifiez que `fraud_protection_enabled` est défini sur `true` dans le fichier Preferences à l’aide de `grep`.<sup>[[2]](#references)</sup>

Ces chemins et commandes sont essentiels pour accéder aux données de navigation stockées par différents navigateurs web et les comprendre.

## References

- [1] [Analyse forensique des navigateurs web : guide d’analyse forensique des navigateurs web](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [2] [Réponse aux incidents macOS | Partie 3 : manipulation du système](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [3] [Réponse aux incidents OS X : scripts et analyse, par Jaron Bradley](https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file)
{{#include ../../../banners/hacktricks-training.md}}
