# Sécurité et escalade de privilèges macOS

{{#include ../../banners/hacktricks-training.md}}

## Bases de MacOS

Si vous ne connaissez pas bien macOS, vous devriez commencer par apprendre les bases de macOS :

- **Fichiers et permissions** spéciaux de macOS :


{{#ref}}
macos-files-folders-and-binaries/
{{#endref}}

- **Utilisateurs** courants de macOS


{{#ref}}
macos-users.md
{{#endref}}

- **AppleFS**


{{#ref}}
macos-applefs.md
{{#endref}}

- L’**architecture** du **kernel**


{{#ref}}
mac-os-architecture/
{{#endref}}

- **Services et protocoles réseau** courants de macOS


{{#ref}}
macos-protocols.md
{{#endref}}

- macOS **Opensource** : [https://opensource.apple.com/](https://opensource.apple.com/)
- Pour télécharger un `tar.gz`, remplacez une URL telle que [https://opensource.apple.com/**source**/dyld/](https://opensource.apple.com/source/dyld/) par [https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

### MacOS MDM

Dans les entreprises, les systèmes **macOS** vont très probablement être **gérés avec un MDM**. Par conséquent, du point de vue d’un attaquant, il est intéressant de savoir **comment cela fonctionne** :


{{#ref}}
../macos-red-teaming/macos-mdm/
{{#endref}}

### MacOS - Inspection, débogage et fuzzing


{{#ref}}
macos-apps-inspecting-debugging-and-fuzzing/
{{#endref}}

## Protections de sécurité de MacOS


{{#ref}}
macos-security-protections/
{{#endref}}

## Surface d’attaque

### Permissions des fichiers

Si un **processus exécuté en tant que root écrit** dans un fichier contrôlable par un utilisateur, celui-ci pourrait exploiter cette situation pour **escalader ses privilèges**.\
Cela peut se produire dans les situations suivantes :

- Le fichier utilisé a déjà été créé par un utilisateur (il appartient à l’utilisateur)
- Le fichier utilisé est accessible en écriture par l’utilisateur grâce à un groupe
- Le fichier utilisé se trouve dans un répertoire appartenant à l’utilisateur (celui-ci pourrait créer le fichier)
- Le fichier utilisé se trouve dans un répertoire appartenant à root, mais l’utilisateur dispose d’un accès en écriture grâce à un groupe (celui-ci pourrait créer le fichier)

Pouvoir **créer un fichier** qui va être **utilisé par root** permet à un utilisateur de **tirer parti de son contenu**, voire de créer des **symlinks/hardlinks** pour le faire pointer vers un autre emplacement.

Pour ce type de vulnérabilités, n’oubliez pas de **vérifier les installateurs `.pkg` vulnérables** :


{{#ref}}
macos-files-folders-and-binaries/macos-installers-abuse.md
{{#endref}}

### Extensions de fichiers et gestionnaires de schémas d’URL

Les applications inhabituelles enregistrées par des extensions de fichiers pourraient être exploitées, et différentes applications peuvent être enregistrées pour ouvrir des protocoles spécifiques.


{{#ref}}
macos-file-extension-apps.md
{{#endref}}

## Escalade de privilèges macOS TCC / SIP

Dans macOS, les **applications et binaires peuvent disposer de permissions** leur permettant d’accéder à des dossiers ou à des paramètres, ce qui les rend plus privilégiés que d’autres.

Par conséquent, un attaquant souhaitant compromettre avec succès une machine macOS devra **escalader ses privilèges TCC** (ou même **contourner SIP**, selon ses besoins).

Ces privilèges sont généralement accordés sous la forme d’**entitlements** avec lesquels l’application est signée, ou l’application peut demander certains accès qui, après leur **approbation par l’utilisateur**, peuvent être trouvés dans les **bases de données TCC**. Un autre moyen pour un processus d’obtenir ces privilèges est d’être un **enfant d’un processus** possédant ces **privilèges**, car ils sont généralement **hérités**.

Suivez ces liens pour découvrir différentes façons d’[**escalader les privilèges dans TCC**](macos-security-protections/macos-tcc/index.html#tcc-privesc-and-bypasses), de [**contourner TCC**](macos-security-protections/macos-tcc/macos-tcc-bypasses/index.html) et comment, par le passé, [**SIP a été contourné**](macos-security-protections/macos-sip.md#sip-bypasses).

## Escalade de privilèges traditionnelle sur macOS

Bien sûr, du point de vue d’une red team, vous devriez également vous intéresser à l’escalade vers root. Consultez l’article suivant pour obtenir quelques indications :


{{#ref}}
macos-privilege-escalation.md
{{#endref}}

## Conformité macOS

- [https://github.com/usnistgov/macos_security](https://github.com/usnistgov/macos_security)

## Références

- [1] [OS X Incident Response: Scripting and Analysis](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [2] [The Art of Mac Malware, Vol. 1 — Analysis (Patrick Wardle)](https://taomm.org/vol1/analysis.html)
- [3] [NicolasGrimonpont/Cheatsheet — macOS/Linux/Windows commands & security tools cheatsheet](https://github.com/NicolasGrimonpont/Cheatsheet)
- [4] [SentinelOne — macOS Security Resource](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
- [5] [2022 - macOS local security: escaping the sandbox and bypassing TCC (YouTube)](https://www.youtube.com/watch?v=vMGiplQtjTY)

{{#include ../../banners/hacktricks-training.md}}
