# Clés de Registre Windows Intéressantes

### Clés de Registre Windows Intéressantes

{{#include ../../../banners/hacktricks-training.md}}

### **Informations sur la Version de Windows et le Propriétaire**

- Situé à **`Software\Microsoft\Windows NT\CurrentVersion`**, vous trouverez la version de Windows, le Service Pack, l'heure d'installation et le nom du propriétaire enregistré de manière simple.

### **Nom de l'Ordinateur**

- Le nom d'hôte se trouve sous **`System\ControlSet001\Control\ComputerName\ComputerName`**.

### **Paramètre de Fuseau Horaire**

- Le fuseau horaire du système est stocké dans **`System\ControlSet001\Control\TimeZoneInformation`**.

### **Suivi du Temps d'Accès**

- Par défaut, le suivi du dernier temps d'accès est désactivé (**`NtfsDisableLastAccessUpdate=1`**). Pour l'activer, utilisez :
`fsutil behavior set disablelastaccess 0`

### Versions de Windows et Service Packs

- La **version de Windows** indique l'édition (par exemple, Home, Pro) et sa version (par exemple, Windows 10, Windows 11), tandis que les **Service Packs** sont des mises à jour qui incluent des corrections et, parfois, de nouvelles fonctionnalités.

### Activation du Temps d'Accès

- L'activation du suivi du dernier temps d'accès vous permet de voir quand les fichiers ont été ouverts pour la dernière fois, ce qui peut être crucial pour l'analyse judiciaire ou la surveillance du système.

### Détails sur les Informations Réseau

- Le registre contient des données étendues sur les configurations réseau, y compris **types de réseaux (sans fil, câble, 3G)** et **catégories de réseau (Public, Privé/Domicile, Domaine/Travail)**, qui sont essentielles pour comprendre les paramètres de sécurité réseau et les autorisations.

### Mise en Cache Côté Client (CSC)

- **CSC** améliore l'accès aux fichiers hors ligne en mettant en cache des copies de fichiers partagés. Différents paramètres **CSCFlags** contrôlent comment et quels fichiers sont mis en cache, affectant les performances et l'expérience utilisateur, en particulier dans des environnements avec une connectivité intermittente.

### Programmes de Démarrage Automatique

- Les programmes listés dans diverses clés de registre `Run` et `RunOnce` sont lancés automatiquement au démarrage, affectant le temps de démarrage du système et pouvant être des points d'intérêt pour identifier des logiciels malveillants ou indésirables.

### Shellbags

- Les **Shellbags** non seulement stockent des préférences pour les vues de dossiers mais fournissent également des preuves judiciaires d'accès aux dossiers même si le dossier n'existe plus. Ils sont inestimables pour les enquêtes, révélant l'activité des utilisateurs qui n'est pas évidente par d'autres moyens.

### Informations sur les USB et Analyse Judiciaire

- Les détails stockés dans le registre concernant les appareils USB peuvent aider à retracer quels appareils ont été connectés à un ordinateur, liant potentiellement un appareil à des transferts de fichiers sensibles ou à des incidents d'accès non autorisés.

### Numéro de Série de Volume

- Le **Numéro de Série de Volume** peut être crucial pour suivre l'instance spécifique d'un système de fichiers, utile dans des scénarios judiciaires où l'origine d'un fichier doit être établie à travers différents appareils.

### **Détails sur l'Arrêt**

- L'heure et le nombre d'arrêts (ce dernier uniquement pour XP) sont conservés dans **`System\ControlSet001\Control\Windows`** et **`System\ControlSet001\Control\Watchdog\Display`**.

### **Configuration Réseau**

- Pour des informations détaillées sur l'interface réseau, référez-vous à **`System\ControlSet001\Services\Tcpip\Parameters\Interfaces{GUID_INTERFACE}`**.
- Les heures de première et de dernière connexion réseau, y compris les connexions VPN, sont enregistrées sous divers chemins dans **`Software\Microsoft\Windows NT\CurrentVersion\NetworkList`**.

### **Dossiers Partagés**

- Les dossiers partagés et les paramètres se trouvent sous **`System\ControlSet001\Services\lanmanserver\Shares`**. Les paramètres de Mise en Cache Côté Client (CSC) dictent la disponibilité des fichiers hors ligne.

### **Programmes qui Démarrent Automatiquement**

- Des chemins comme **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`** et des entrées similaires sous `Software\Microsoft\Windows\CurrentVersion` détaillent les programmes configurés pour s'exécuter au démarrage.

### **Recherches et Chemins Saisis**

- Les recherches dans l'Explorateur et les chemins saisis sont suivis dans le registre sous **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer`** pour WordwheelQuery et TypedPaths, respectivement.

### **Documents Récents et Fichiers Office**

- Les documents récents et les fichiers Office accessibles sont notés dans `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs` et des chemins spécifiques à la version d'Office.

### **Éléments les Plus Récemment Utilisés (MRU)**

- Les listes MRU, indiquant les chemins de fichiers récents et les commandes, sont stockées dans diverses sous-clés `ComDlg32` et `Explorer` sous `NTUSER.DAT`.

### **Suivi de l'Activité Utilisateur**

- La fonctionnalité User Assist enregistre des statistiques détaillées sur l'utilisation des applications, y compris le nombre d'exécutions et l'heure de la dernière exécution, à **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`**.

### **Analyse des Shellbags**

- Les Shellbags, révélant des détails d'accès aux dossiers, sont stockés dans `USRCLASS.DAT` et `NTUSER.DAT` sous `Software\Microsoft\Windows\Shell`. Utilisez **[Shellbag Explorer](https://ericzimmerman.github.io/#!index.md)** pour l'analyse.

### **Historique des Appareils USB**

- **`HKLM\SYSTEM\ControlSet001\Enum\USBSTOR`** et **`HKLM\SYSTEM\ControlSet001\Enum\USB`** contiennent des détails riches sur les appareils USB connectés, y compris le fabricant, le nom du produit et les horodatages de connexion.
- L'utilisateur associé à un appareil USB spécifique peut être identifié en recherchant dans les hives `NTUSER.DAT` pour le **{GUID}** de l'appareil.
- Le dernier appareil monté et son numéro de série de volume peuvent être retracés via `System\MountedDevices` et `Software\Microsoft\Windows NT\CurrentVersion\EMDMgmt`, respectivement.

Ce guide condense les chemins et méthodes cruciaux pour accéder à des informations détaillées sur le système, le réseau et l'activité des utilisateurs sur les systèmes Windows, visant la clarté et l'utilisabilité.

{{#include ../../../banners/hacktricks-training.md}}
