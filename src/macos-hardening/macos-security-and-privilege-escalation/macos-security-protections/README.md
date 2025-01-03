# Protections de sécurité macOS

{{#include ../../../banners/hacktricks-training.md}}

## Gatekeeper

Gatekeeper est généralement utilisé pour désigner la combinaison de **Quarantine + Gatekeeper + XProtect**, 3 modules de sécurité macOS qui essaieront de **prévenir les utilisateurs d'exécuter des logiciels potentiellement malveillants téléchargés**.

Plus d'informations dans :

{{#ref}}
macos-gatekeeper.md
{{#endref}}

## Processus Limitants

### MACF

### SIP - Protection de l'intégrité du système

{{#ref}}
macos-sip.md
{{#endref}}

### Sandbox

Le Sandbox macOS **limite les applications** s'exécutant à l'intérieur du sandbox aux **actions autorisées spécifiées dans le profil Sandbox** avec lequel l'application s'exécute. Cela aide à garantir que **l'application n'accédera qu'aux ressources attendues**.

{{#ref}}
macos-sandbox/
{{#endref}}

### TCC - **Transparence, Consentement et Contrôle**

**TCC (Transparence, Consentement et Contrôle)** est un cadre de sécurité. Il est conçu pour **gérer les autorisations** des applications, en régulant spécifiquement leur accès à des fonctionnalités sensibles. Cela inclut des éléments tels que **les services de localisation, les contacts, les photos, le microphone, la caméra, l'accessibilité et l'accès complet au disque**. TCC garantit que les applications ne peuvent accéder à ces fonctionnalités qu'après avoir obtenu le consentement explicite de l'utilisateur, renforçant ainsi la confidentialité et le contrôle sur les données personnelles.

{{#ref}}
macos-tcc/
{{#endref}}

### Contraintes de Lancement/Environnement & Cache de Confiance

Les contraintes de lancement dans macOS sont une fonctionnalité de sécurité pour **réguler l'initiation des processus** en définissant **qui peut lancer** un processus, **comment** et **d'où**. Introduites dans macOS Ventura, elles catégorisent les binaires système en catégories de contraintes au sein d'un **cache de confiance**. Chaque binaire exécutable a des **règles** définies pour son **lancement**, y compris des contraintes **soi**, **parent** et **responsable**. Étendues aux applications tierces en tant que **Contraintes d'Environnement** dans macOS Sonoma, ces fonctionnalités aident à atténuer les exploitations potentielles du système en régissant les conditions de lancement des processus.

{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

## MRT - Outil de Suppression de Malware

L'Outil de Suppression de Malware (MRT) est une autre partie de l'infrastructure de sécurité de macOS. Comme son nom l'indique, la fonction principale de MRT est de **supprimer les malwares connus des systèmes infectés**.

Une fois qu'un malware est détecté sur un Mac (soit par XProtect, soit par d'autres moyens), MRT peut être utilisé pour **supprimer automatiquement le malware**. MRT fonctionne silencieusement en arrière-plan et s'exécute généralement chaque fois que le système est mis à jour ou lorsqu'une nouvelle définition de malware est téléchargée (il semble que les règles que MRT doit suivre pour détecter les malwares soient à l'intérieur du binaire).

Bien que XProtect et MRT fassent tous deux partie des mesures de sécurité de macOS, ils remplissent des fonctions différentes :

- **XProtect** est un outil préventif. Il **vérifie les fichiers au fur et à mesure de leur téléchargement** (via certaines applications), et s'il détecte des types de malwares connus, il **empêche le fichier de s'ouvrir**, empêchant ainsi le malware d'infecter votre système dès le départ.
- **MRT**, en revanche, est un **outil réactif**. Il fonctionne après qu'un malware a été détecté sur un système, dans le but de supprimer le logiciel incriminé pour nettoyer le système.

L'application MRT se trouve dans **`/Library/Apple/System/Library/CoreServices/MRT.app`**

## Gestion des Tâches en Arrière-plan

**macOS** alerte désormais chaque fois qu'un outil utilise une **technique bien connue pour persister l'exécution de code** (comme les éléments de connexion, les démons...), afin que l'utilisateur sache mieux **quel logiciel persiste**.

<figure><img src="../../../images/image (1183).png" alt=""><figcaption></figcaption></figure>

Cela fonctionne avec un **démon** situé dans `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd` et l'**agent** dans `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app`

La façon dont **`backgroundtaskmanagementd`** sait qu'un élément est installé dans un dossier persistant est en **obtenant les FSEvents** et en créant des **gestionnaires** pour ceux-ci.

De plus, il existe un fichier plist qui contient des **applications bien connues** qui persistent fréquemment, maintenu par Apple, situé dans : `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist`
```json
[...]
"us.zoom.ZoomDaemon" => {
"AssociatedBundleIdentifiers" => [
0 => "us.zoom.xos"
]
"Attribution" => "Zoom"
"Program" => "/Library/PrivilegedHelperTools/us.zoom.ZoomDaemon"
"ProgramArguments" => [
0 => "/Library/PrivilegedHelperTools/us.zoom.ZoomDaemon"
]
"TeamIdentifier" => "BJ4HAAB9B3"
}
[...]
```
### Énumération

Il est possible de **énumérer tous** les éléments d'arrière-plan configurés en exécutant l'outil cli d'Apple :
```bash
# The tool will always ask for the users password
sfltool dumpbtm
```
De plus, il est également possible de lister ces informations avec [**DumpBTM**](https://github.com/objective-see/DumpBTM).
```bash
# You need to grant the Terminal Full Disk Access for this to work
chmod +x dumpBTM
xattr -rc dumpBTM # Remove quarantine attr
./dumpBTM
```
Ces informations sont stockées dans **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm`** et le Terminal nécessite FDA.

### Manipulation avec BTM

Lorsqu'une nouvelle persistance est trouvée, un événement de type **`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`** est généré. Donc, toute méthode pour **prévenir** cet **événement** d'être envoyé ou pour empêcher **l'agent d'alerter** l'utilisateur aidera un attaquant à _**contourner**_ BTM.

- **Réinitialiser la base de données** : Exécuter la commande suivante réinitialisera la base de données (devrait la reconstruire depuis le début), cependant, pour une raison quelconque, après avoir exécuté cela, **aucune nouvelle persistance ne sera signalée jusqu'à ce que le système soit redémarré**.
- **root** est requis.
```bash
# Reset the database
sfltool resettbtm
```
- **Arrêter l'Agent** : Il est possible d'envoyer un signal d'arrêt à l'agent afin qu'il **n'alerte pas l'utilisateur** lorsque de nouvelles détections sont trouvées.
```bash
# Get PID
pgrep BackgroundTaskManagementAgent
1011

# Stop it
kill -SIGSTOP 1011

# Check it's stopped (a T means it's stopped)
ps -o state 1011
T
```
- **Bug** : Si le **processus qui a créé la persistance existe rapidement juste après**, le démon essaiera de **récupérer des informations** à son sujet, **échouera** et **ne pourra pas envoyer l'événement** indiquant qu'une nouvelle chose persiste.

Références et **plus d'informations sur BTM** :

- [https://youtu.be/9hjUmT031tc?t=26481](https://youtu.be/9hjUmT031tc?t=26481)
- [https://www.patreon.com/posts/new-developer-77420730?l=fr](https://www.patreon.com/posts/new-developer-77420730?l=fr)
- [https://support.apple.com/en-gb/guide/deployment/depdca572563/web](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)

{{#include ../../../banners/hacktricks-training.md}}
