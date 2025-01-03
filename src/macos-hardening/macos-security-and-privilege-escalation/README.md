# Sécurité macOS & Escalade de Privilèges

{{#include ../../banners/hacktricks-training.md}}

## MacOS de Base

Si vous n'êtes pas familier avec macOS, vous devriez commencer à apprendre les bases de macOS :

- Fichiers et **permissions** spéciales macOS :

{{#ref}}
macos-files-folders-and-binaries/
{{#endref}}

- **Utilisateurs** macOS courants

{{#ref}}
macos-users.md
{{#endref}}

- **AppleFS**

{{#ref}}
macos-applefs.md
{{#endref}}

- L'**architecture** du k**ernel**

{{#ref}}
mac-os-architecture/
{{#endref}}

- Services et **protocoles** réseau macOS courants

{{#ref}}
macos-protocols.md
{{#endref}}

- macOS **Open Source** : [https://opensource.apple.com/](https://opensource.apple.com/)
- Pour télécharger un `tar.gz`, changez une URL comme [https://opensource.apple.com/**source**/dyld/](https://opensource.apple.com/source/dyld/) en [https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

### MDM MacOS

Dans les entreprises, les systèmes **macOS** seront très probablement **gérés avec un MDM**. Par conséquent, du point de vue d'un attaquant, il est intéressant de savoir **comment cela fonctionne** :

{{#ref}}
../macos-red-teaming/macos-mdm/
{{#endref}}

### MacOS - Inspection, Débogage et Fuzzing

{{#ref}}
macos-apps-inspecting-debugging-and-fuzzing/
{{#endref}}

## Protections de Sécurité MacOS

{{#ref}}
macos-security-protections/
{{#endref}}

## Surface d'Attaque

### Permissions de Fichier

Si un **processus s'exécutant en tant que root écrit** un fichier qui peut être contrôlé par un utilisateur, l'utilisateur pourrait en abuser pour **escalader les privilèges**.\
Cela pourrait se produire dans les situations suivantes :

- Le fichier utilisé a déjà été créé par un utilisateur (appartenant à l'utilisateur)
- Le fichier utilisé est modifiable par l'utilisateur en raison d'un groupe
- Le fichier utilisé se trouve dans un répertoire appartenant à l'utilisateur (l'utilisateur pourrait créer le fichier)
- Le fichier utilisé se trouve dans un répertoire appartenant à root mais l'utilisateur a un accès en écriture grâce à un groupe (l'utilisateur pourrait créer le fichier)

Être capable de **créer un fichier** qui va être **utilisé par root**, permet à un utilisateur de **profiter de son contenu** ou même de créer des **symlinks/hardlinks** pour le pointer vers un autre endroit.

Pour ce type de vulnérabilités, n'oubliez pas de **vérifier les installateurs `.pkg` vulnérables** :

{{#ref}}
macos-files-folders-and-binaries/macos-installers-abuse.md
{{#endref}}

### Gestion des Extensions de Fichier & des URL

Des applications étranges enregistrées par des extensions de fichier pourraient être abusées et différentes applications peuvent être enregistrées pour ouvrir des protocoles spécifiques

{{#ref}}
macos-file-extension-apps.md
{{#endref}}

## Escalade de Privilèges TCC / SIP macOS

Dans macOS, les **applications et binaires peuvent avoir des permissions** pour accéder à des dossiers ou des paramètres qui les rendent plus privilégiés que d'autres.

Par conséquent, un attaquant qui souhaite compromettre avec succès une machine macOS devra **escalader ses privilèges TCC** (ou même **contourner SIP**, selon ses besoins).

Ces privilèges sont généralement accordés sous forme de **droits** avec lesquels l'application est signée, ou l'application peut demander certains accès et après que **l'utilisateur les approuve**, ils peuvent être trouvés dans les **bases de données TCC**. Une autre façon pour un processus d'obtenir ces privilèges est d'être un **enfant d'un processus** ayant ces **privilèges** car ils sont généralement **hérités**.

Suivez ces liens pour trouver différentes façons de [**escalader les privilèges dans TCC**](macos-security-protections/macos-tcc/#tcc-privesc-and-bypasses), pour [**contourner TCC**](macos-security-protections/macos-tcc/macos-tcc-bypasses/) et comment dans le passé [**SIP a été contourné**](macos-security-protections/macos-sip.md#sip-bypasses).

## Escalade de Privilèges Traditionnelle macOS

Bien sûr, du point de vue des équipes rouges, vous devriez également être intéressé par l'escalade vers root. Consultez le post suivant pour quelques indices :

{{#ref}}
macos-privilege-escalation.md
{{#endref}}

## Conformité macOS

- [https://github.com/usnistgov/macos_security](https://github.com/usnistgov/macos_security)

## Références

- [**OS X Incident Response: Scripting and Analysis**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
- [**https://github.com/NicolasGrimonpont/Cheatsheet**](https://github.com/NicolasGrimonpont/Cheatsheet)
- [**https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ**](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
- [**https://www.youtube.com/watch?v=vMGiplQtjTY**](https://www.youtube.com/watch?v=vMGiplQtjTY)

{{#include ../../banners/hacktricks-training.md}}
