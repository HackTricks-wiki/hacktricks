# Niveaux d’intégrité

{{#include ../../banners/hacktricks-training.md}}

## Niveaux d’intégrité

Dans Windows Vista et les versions ultérieures, tous les éléments protégés sont associés à une balise de **niveau d’intégrité**. Cette configuration attribue principalement un niveau d’intégrité « moyen » aux fichiers et aux clés de registre, à l’exception de certains dossiers et fichiers dans lesquels Internet Explorer 7 peut écrire avec un niveau d’intégrité faible. Par défaut, les processus lancés par les utilisateurs standard disposent d’un niveau d’intégrité moyen, tandis que les services fonctionnent généralement avec un niveau d’intégrité système. Un label d’intégrité élevé protège le répertoire racine.

Une règle essentielle est que les objets ne peuvent pas être modifiés par des processus dont le niveau d’intégrité est inférieur à celui de l’objet. Les niveaux d’intégrité sont les suivants :

- **Untrusted** : Ce niveau est destiné aux processus utilisant des connexions anonymes. Exemple : Chrome
- **Low** : Principalement utilisé pour les interactions Internet, notamment dans le Protected Mode d’Internet Explorer, affectant les fichiers et processus associés, ainsi que certains dossiers comme le **Temporary Internet Folder**. Les processus à faible niveau d’intégrité sont soumis à d’importantes restrictions, notamment l’absence d’accès en écriture au registre et un accès en écriture limité au profil utilisateur.
- **Medium** : Le niveau par défaut pour la plupart des activités, attribué aux utilisateurs standard et aux objets ne disposant pas de niveau d’intégrité spécifique. Même les membres du groupe Administrators utilisent ce niveau par défaut.
- **High** : Réservé aux administrateurs, leur permettant de modifier les objets dont le niveau d’intégrité est inférieur, y compris ceux possédant eux-mêmes un niveau élevé.
- **System** : Le niveau opérationnel le plus élevé pour le kernel Windows et les services essentiels, inaccessible même aux administrateurs, afin d’assurer la protection des fonctions système vitales.
- **Installer** : Un niveau unique qui se situe au-dessus de tous les autres et permet aux objets associés à ce niveau de désinstaller n’importe quel autre objet.

Vous pouvez obtenir le niveau d’intégrité d’un processus à l’aide de **Process Explorer** de **Sysinternals**, en accédant aux **properties** du processus et en consultant l’onglet "**Security**" :

![Niveaux d’intégrité - Niveaux d’intégrité : Vous pouvez obtenir le niveau d’intégrité d’un processus à l’aide de Process Explorer de Sysinternals, en accédant aux properties du processus et en consultant l’onglet "...](<../../images/image (824).png>)

Vous pouvez également obtenir votre **niveau d’intégrité actuel** à l’aide de `whoami /groups`

![Niveaux d’intégrité - Niveaux d’intégrité : Vous pouvez également obtenir votre niveau d’intégrité actuel à l’aide de whoami /groups](<../../images/image (325).png>)

### Niveaux d’intégrité dans le système de fichiers

Un objet du système de fichiers peut nécessiter un **niveau d’intégrité minimum** et, si un processus ne possède pas ce niveau d’intégrité, il ne pourra pas interagir avec lui.\
Par exemple, **créons un fichier standard depuis une console d’un utilisateur standard et vérifions les permissions** :
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
Maintenant, attribuons un niveau d’intégrité minimal **High** au fichier. Cela **doit être effectué depuis une console** exécutée en tant qu’**administrator**, car une **console classique** s’exécute au niveau d’intégrité Medium et **ne sera pas autorisée** à attribuer le niveau d’intégrité High à un objet :
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
C'est ici que les choses deviennent intéressantes. Vous pouvez voir que l'utilisateur `DESKTOP-IDJHTKP\user` dispose de **FULL privileges** sur le fichier (il s'agit effectivement de l'utilisateur qui a créé le fichier). Cependant, en raison du minimum integrity level implémenté, il ne pourra plus modifier le fichier, sauf s'il s'exécute dans un High Integrity Level (notez qu'il pourra toujours le lire) :
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
> [!TIP]
> **Par conséquent, lorsqu’un fichier possède un niveau d’intégrité minimal, vous devez l’exécuter au moins à ce niveau d’intégrité pour pouvoir le modifier.**

### Niveaux d’intégrité dans les binaires

J’ai créé une copie de `cmd.exe` dans `C:\Windows\System32\cmd-low.exe` et lui ai attribué un **niveau d’intégrité faible depuis une console administrateur** :
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

![Niveaux d’intégrité dans le système de fichiers - Niveaux d’intégrité dans les binaires : désormais, lorsque j’exécute cmd-low.exe, il s’exécute avec un niveau d’intégrité faible au lieu d’un niveau moyen](<../../images/image (313).png>)

Pour les plus curieux, si vous attribuez un niveau d’intégrité élevé à un binaire (`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`), il ne s’exécutera pas automatiquement avec un niveau d’intégrité élevé (si vous l’invoquez depuis un niveau d’intégrité moyen --par défaut--, il s’exécutera avec un niveau d’intégrité moyen).

### Niveaux d’intégrité des processus

Tous les fichiers et dossiers n’ont pas de niveau d’intégrité minimal, **mais tous les processus s’exécutent avec un niveau d’intégrité**. Et comme pour le système de fichiers, **si un processus veut écrire dans un autre processus, il doit avoir au moins le même niveau d’intégrité**. Cela signifie qu’un processus avec un niveau d’intégrité faible ne peut pas ouvrir un handle avec un accès total à un processus avec un niveau d’intégrité moyen.

En raison des restrictions mentionnées dans cette section et dans la précédente, d’un point de vue de la sécurité, il est toujours **recommandé d’exécuter un processus avec le niveau d’intégrité le plus faible possible**.

{{#include ../../banners/hacktricks-training.md}}
