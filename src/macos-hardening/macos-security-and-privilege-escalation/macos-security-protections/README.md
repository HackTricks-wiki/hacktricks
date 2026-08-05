# Protections de sécurité de macOS

{{#include ../../../banners/hacktricks-training.md}}

## Gatekeeper

Gatekeeper désigne généralement la combinaison de **Quarantine + Gatekeeper + XProtect**, 3 modules de sécurité de macOS qui tenteront **d'empêcher les utilisateurs d'exécuter des logiciels potentiellement malveillants téléchargés**.

Plus d'informations dans :


{{#ref}}
macos-gatekeeper.md
{{#endref}}

## Processus limitants

### MACF

### SIP - System Integrity Protection


{{#ref}}
macos-sip.md
{{#endref}}

### Sandbox

MacOS Sandbox **limite les applications** exécutées dans la sandbox aux **actions autorisées spécifiées dans le profil Sandbox** avec lequel l'application s'exécute. Cela contribue à garantir que **l'application n'accédera qu'aux ressources attendues**.


{{#ref}}
macos-sandbox/
{{#endref}}

### TCC - **Transparency, Consent, and Control**

**TCC (Transparency, Consent, and Control)** est un framework de sécurité. Il est conçu pour **gérer les permissions** des applications, notamment en régulant leur accès aux fonctionnalités sensibles. Cela inclut des éléments tels que **les services de localisation, les contacts, les photos, le microphone, la caméra, l'accessibilité et l'accès complet au disque**. TCC garantit que les applications ne peuvent accéder à ces fonctionnalités qu'après avoir obtenu le consentement explicite de l'utilisateur, renforçant ainsi la confidentialité et le contrôle des données personnelles.


{{#ref}}
macos-tcc/
{{#endref}}

### Launch/Environment Constraints & Trust Cache

Les launch constraints dans macOS sont une fonctionnalité de sécurité qui vise à **réguler le démarrage des processus** en définissant **qui peut lancer** un processus, **comment** et **depuis où**. Introduites dans macOS Ventura, elles classent les binaires système dans des catégories de contraintes au sein d'un **trust cache**. Chaque binaire exécutable possède un ensemble de **règles** pour son **lancement**, notamment des contraintes **self**, **parent** et **responsible**. Étendues aux applications tierces sous la forme de contraintes **Environment** dans macOS Sonoma, ces fonctionnalités contribuent à limiter les exploitations potentielles du système en contrôlant les conditions de lancement des processus.


{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

## MRT - Malware Removal Tool

Le Malware Removal Tool (MRT) constitue une autre partie de l'infrastructure de sécurité de macOS. Comme son nom l'indique, la fonction principale de MRT est de **supprimer les malwares connus des systèmes infectés**.

Une fois qu'un malware est détecté sur un Mac (par XProtect ou par un autre moyen), MRT peut être utilisé pour **supprimer automatiquement le malware**. MRT fonctionne silencieusement en arrière-plan et s'exécute généralement lorsque le système est mis à jour ou lorsqu'une nouvelle définition de malware est téléchargée (il semble que les règles utilisées par MRT pour détecter les malwares se trouvent dans le binaire).

Bien que XProtect et MRT fassent tous deux partie des mesures de sécurité de macOS, ils remplissent des fonctions différentes :

- **XProtect** est un outil préventif. Il **vérifie les fichiers lors de leur téléchargement** (via certaines applications) et, s'il détecte un type de malware connu, il **empêche l'ouverture du fichier**, évitant ainsi que le malware n'infecte le système dès le départ.
- **MRT**, en revanche, est un outil **réactif**. Il intervient après la détection d'un malware sur un système, dans le but de supprimer le logiciel malveillant afin de nettoyer le système.

L'application MRT se trouve dans **`/Library/Apple/System/Library/CoreServices/MRT.app`**

## Gestion des tâches en arrière-plan

**macOS** affiche désormais une **alerte** chaque fois qu'un outil utilise une **technique connue pour maintenir une exécution de code** (telle que Login Items, Daemons...), afin que l'utilisateur sache mieux **quels logiciels assurent leur persistance**.<sup>[3]</sup>

<figure><img src="../../../images/image (1183).png" alt=""><figcaption></figcaption></figure>

Cela fonctionne avec un **daemon** situé dans `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd` et l'**agent** dans `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app`<sup>[1]</sup>

La manière dont **`backgroundtaskmanagementd`** sait qu'un élément est installé dans un dossier persistant consiste à **récupérer les FSEvents** et à créer des **handlers** pour ceux-ci.<sup>[1]</sup>

De plus, un fichier plist contenant les **applications bien connues** qui assurent fréquemment leur persistance, maintenu par Apple, se trouve à l'emplacement suivant : `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist`<sup>[3]</sup>
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

Il est possible d’**énumérer tous** les éléments d’arrière-plan configurés à l’aide de l’outil CLI d’Apple :<sup>[3]</sup>
```bash
# The tool will always ask for the users password
sfltool dumpbtm
```
De plus, il est également possible de lister ces informations avec [**DumpBTM**](https://github.com/objective-see/DumpBTM).<sup>[2]</sup>
```bash
# You need to grant the Terminal Full Disk Access for this to work
chmod +x dumpBTM
xattr -rc dumpBTM # Remove quarantine attr
./dumpBTM
```
Ces informations sont stockées dans **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm`**, et Terminal nécessite la FDA.<sup>[2]</sup>

### Manipulation de BTM

Lorsqu’une nouvelle persistence est détectée, un événement de type **`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`** est généré. Ainsi, tout moyen d’**empêcher** l’envoi de cet **événement** ou d’empêcher **l’agent d’alerter** l’utilisateur aidera un attaquant à _**contourner**_ BTM.<sup>[1]</sup>

- **Réinitialisation de la base de données** : L’exécution de la commande suivante réinitialisera la base de données (elle devrait être reconstruite depuis zéro). Cependant, pour une raison inconnue, après cette opération, **aucune nouvelle persistence ne sera signalée jusqu’au redémarrage du système**.<sup>[1]</sup>
- **root** est requis.
```bash
# Reset the database
sfltool resettbtm
```
- **Arrêter l'agent** : Il est possible d'envoyer un signal d'arrêt à l'agent afin qu'il **n'alerte pas l'utilisateur** lorsque de nouvelles détections sont trouvées.<sup>[1]</sup>
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
- **Bug** : Si le **processus qui a créé la persistence se termine rapidement juste après**, le daemon essaiera d'obtenir des **informations** à son sujet, échouera et **ne pourra pas envoyer l'événement** indiquant qu'un nouvel élément établit une persistence.<sup>[1]</sup>

## Références

- [1] [OBTS v6.0 : « Démystifier (& contourner) la gestion des tâches en arrière-plan de macOS » - Patrick Wardle & Chris Lopez](https://youtu.be/9hjUmT031tc?t=26481)
- [2] [Nouvel outil (pour développeurs) : « DumpBTM » - Patrick Wardle (Patreon)](https://www.patreon.com/posts/new-developer-77420730?l=fr)
- [3] [Gérer les login items et les tâches en arrière-plan sur Mac - Apple Platform Deployment](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)

{{#include ../../../banners/hacktricks-training.md}}
