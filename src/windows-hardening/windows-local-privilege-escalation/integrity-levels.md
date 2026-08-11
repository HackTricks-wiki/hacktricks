# Niveaux d’intégrité

{{#include ../../banners/hacktricks-training.md}}

## Niveaux d’intégrité

Dans Windows Vista et les versions ultérieures, les objets sécurisables peuvent porter un label de **niveau d’intégrité**. La plupart des objets sont considérés comme ayant une intégrité moyenne, tandis que certains emplacements destinés aux applications à faible intégrité peuvent être marqués comme ayant une faible intégrité. Les processus démarrés par des utilisateurs standard s’exécutent normalement avec une intégrité moyenne, les applications élevées avec une intégrité élevée, et de nombreux services avec une intégrité système.<sup>[[1]](#references)</sup>

Une règle essentielle est qu’un objet ne peut pas être modifié par des processus dont le niveau d’intégrité est inférieur à celui de l’objet. Windows applique cette vérification Mandatory Integrity Control (MIC) avant d’évaluer la liste de contrôle d’accès discrétionnaire (DACL) de l’objet. Les niveaux couramment rencontrés sont les suivants :<sup>[[1]](#references)[[2]](#references)</sup>

- **Untrusted** : Le niveau le plus bas, représenté par `SECURITY_MANDATORY_UNTRUSTED_RID` (`S-1-16-0`). Ne confondez pas ce label d’intégrité avec l’identité **Anonymous Logon** (`S-1-5-7`) ; les identités d’authentification et les labels MIC appartiennent à des espaces de noms SID distincts. Par exemple, le sandbox Windows de Chromium attribue initialement une intégrité Low aux cibles sandboxées, puis abaisse les cibles de rendu au niveau d’intégrité Untrusted après le démarrage.<sup>[[5]](#references)[[6]](#references)</sup>
- **Low** : Principalement utilisé pour les interactions Internet, notamment dans le Protected Mode d’Internet Explorer, qui affecte les fichiers et processus associés, ainsi que certains dossiers comme le **Temporary Internet Folder**. Les processus à faible intégrité sont soumis à d’importantes restrictions, notamment l’absence d’accès en écriture au registre et un accès en écriture limité au profil utilisateur.
- **Medium** : Le niveau par défaut pour la plupart des activités, attribué aux utilisateurs standard et aux objets ne possédant pas de niveau d’intégrité spécifique. Même les membres du groupe Administrators s’exécutent par défaut à ce niveau.
- **High** : Réservé aux administrateurs, leur permettant de modifier les objets appartenant à des niveaux d’intégrité inférieurs, y compris ceux du niveau High lui-même.
- **System** : Le niveau opérationnel le plus élevé pour le kernel Windows et les services principaux, inaccessible même aux administrateurs, afin d’assurer la protection des fonctions système essentielles.

Windows définit également une valeur d’intégrité de protected process supérieure à System. **TrustedInstaller** est toutefois une identité de service Windows et non un niveau MIC distinct ; sa capacité à modifier les ressources protégées du système d’exploitation provient des permissions accordées à cette identité.

Ne supposez pas qu’un emplacement tel que la racine d’un lecteur système possède toujours un label d’intégrité High fixe. Inspectez la DACL effective ainsi que tout label obligatoire explicite avec `icacls` ; un objet sans label est traité comme Medium par le MIC, tandis que sa DACL et son propriétaire peuvent toujours restreindre indépendamment l’accès.<sup>[[1]](#references)[[4]](#references)</sup>

Vous pouvez obtenir le niveau d’intégrité d’un processus avec **Process Explorer** de **Sysinternals**, en ouvrant les propriétés du processus et en consultant l’onglet **Security** :<sup>[[3]](#references)</sup>

![Niveaux d’intégrité - Niveaux d’intégrité : vous pouvez obtenir le niveau d’intégrité d’un processus avec Process Explorer de Sysinternals, en accédant aux propriétés du processus et en consultant l’onglet « ...](<../../images/image (824).png>)

Vous pouvez également obtenir votre **niveau d’intégrité actuel** avec `whoami /groups` :

![Niveaux d’intégrité - Niveaux d’intégrité : vous pouvez également obtenir votre niveau d’intégrité actuel avec whoami /groups](<../../images/image (325).png>)

### Niveaux d’intégrité dans le système de fichiers

Un objet du système de fichiers peut avoir une **exigence de niveau d’intégrité minimal**. Un processus situé en dessous de ce niveau est soumis à la stratégie obligatoire de l’objet, même lorsque sa DACL lui accorderait autrement l’accès. Par exemple, créez un fichier standard depuis une console d’utilisateur standard et inspectez ses permissions :<sup>[[1]](#references)[[4]](#references)</sup>
```
echo asd >asd.txt
icacls asd.txt
asd.txt BUILTIN\Administrators:(I)(F)
DESKTOP-IDJHTKP\user:(I)(F)
NT AUTHORITY\SYSTEM:(I)(F)
NT AUTHORITY\INTERACTIVE:(I)(M,DC)
NT AUTHORITY\SERVICE:(I)(M,DC)
NT AUTHORITY\BATCH:(I)(M,DC)
```
Maintenant, attribuez un niveau d’intégrité minimal de **High** au fichier. Cela **doit être effectué depuis une console** exécutée en tant qu’**administrateur**, car une console standard s’exécute avec un niveau d’intégrité Medium et **ne sera pas autorisée** à attribuer le niveau d’intégrité High à un objet :
```
icacls asd.txt /setintegritylevel(oi)(ci) High
processed file: asd.txt
Successfully processed 1 files; Failed processing 0 files

C:\Users\Public>icacls asd.txt
asd.txt BUILTIN\Administrators:(I)(F)
DESKTOP-IDJHTKP\user:(I)(F)
NT AUTHORITY\SYSTEM:(I)(F)
NT AUTHORITY\INTERACTIVE:(I)(M,DC)
NT AUTHORITY\SERVICE:(I)(M,DC)
NT AUTHORITY\BATCH:(I)(M,DC)
Mandatory Label\High Mandatory Level:(NW)
```
L’utilisateur `DESKTOP-IDJHTKP\user` dispose de **FULL privileges** sur le fichier, car c’est lui qui l’a créé. Cependant, le label obligatoire empêche l’utilisateur de modifier le fichier, sauf si le processus s’exécute avec un niveau d’intégrité High. L’utilisateur peut toujours le lire, car la mandatory policy affichée est `(NW)`, soit no-write-up :
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
> [!TIP]
> **Par conséquent, lorsqu’un fichier possède un niveau d’intégrité minimal, vous devez être exécuté au moins à ce niveau d’intégrité pour pouvoir le modifier.**

### Niveaux d’intégrité dans les binaires

L’exemple suivant utilise une copie de `cmd.exe` située dans `C:\Windows\System32\cmd-low.exe` et lui attribue un **niveau d’intégrité Low depuis une console administrateur** :
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
Mandatory Label\Low Mandatory Level:(NW)
```
Désormais, lorsque j’exécute `cmd-low.exe`, il s’exécute **avec un niveau d’intégrité faible** au lieu d’un niveau moyen :

![Niveaux d’intégrité dans le système de fichiers - Niveaux d’intégrité dans les binaires : Désormais, lorsque j’exécute cmd-low.exe, il s’exécute avec un niveau d’intégrité faible au lieu d’un niveau moyen](<../../images/image (313).png>)

Attribuer une étiquette d’intégrité élevée à un binaire (`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`) ne le fait pas s’exécuter automatiquement avec une intégrité élevée. S’il est lancé depuis un processus avec une intégrité moyenne, il s’exécute avec une intégrité moyenne, car un nouveau processus reçoit le niveau d’intégrité le plus faible entre celui du fichier exécutable et celui de l’appelant.<sup>[[1]](#references)</sup>

### Niveaux d’intégrité des processus

Tous les fichiers et dossiers n’ont pas d’étiquette d’intégrité minimale explicite, **mais chaque processus s’exécute avec un niveau d’intégrité**. Comme pour les objets du système de fichiers, **un processus qui souhaite obtenir un accès en écriture à un autre processus doit avoir au moins le même niveau d’intégrité**. Par conséquent, un processus avec une faible intégrité ne peut pas ouvrir un processus avec une intégrité moyenne avec un accès complet.<sup>[[1]](#references)</sup>

En raison de ces restrictions, l’approche la plus sûre consiste à **exécuter chaque processus avec le niveau d’intégrité le plus faible qui lui permet encore d’effectuer le travail prévu**.

## References

- [1] [Microsoft Learn – Contrôle d’intégrité obligatoire](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control)
- [2] [Microsoft Learn – Énumération MANDATORY_LEVEL](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-mandatory_level)
- [3] [Microsoft Sysinternals – Process Explorer](https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer)
- [4] [Microsoft Learn – icacls](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls)
- [5] [Code source de Chromium – Politique d’isolation Windows par défaut](https://github.com/chromium/chromium/blob/main/sandbox/policy/win/sandbox_win.cc#L212-L216)
- [6] [Microsoft Learn – SID connus](https://learn.microsoft.com/en-us/windows/win32/secauthz/well-known-sids)
{{#include ../../banners/hacktricks-training.md}}
