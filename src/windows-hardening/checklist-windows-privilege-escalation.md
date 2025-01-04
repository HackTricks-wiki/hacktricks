# Liste de contrôle - Élévation de privilèges locale Windows

{{#include ../banners/hacktricks-training.md}}

### **Meilleur outil pour rechercher des vecteurs d'élévation de privilèges locaux Windows :** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Informations système](windows-local-privilege-escalation/index.html#system-info)

- [ ] Obtenir [**Informations système**](windows-local-privilege-escalation/index.html#system-info)
- [ ] Rechercher des **exploits de noyau** [**en utilisant des scripts**](windows-local-privilege-escalation/index.html#version-exploits)
- [ ] Utiliser **Google pour rechercher** des **exploits de noyau**
- [ ] Utiliser **searchsploit pour rechercher** des **exploits de noyau**
- [ ] Informations intéressantes dans [**env vars**](windows-local-privilege-escalation/index.html#environment)?
- [ ] Mots de passe dans [**l'historique PowerShell**](windows-local-privilege-escalation/index.html#powershell-history)?
- [ ] Informations intéressantes dans [**les paramètres Internet**](windows-local-privilege-escalation/index.html#internet-settings)?
- [ ] [**Lecteurs**](windows-local-privilege-escalation/index.html#drives)?
- [ ] [**Exploitation WSUS**](windows-local-privilege-escalation/index.html#wsus)?
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/index.html#alwaysinstallelevated)?

### [Énumération des journaux/AV](windows-local-privilege-escalation/index.html#enumeration)

- [ ] Vérifier les paramètres [**Audit** ](windows-local-privilege-escalation/index.html#audit-settings)et [**WEF** ](windows-local-privilege-escalation/index.html#wef)
- [ ] Vérifier [**LAPS**](windows-local-privilege-escalation/index.html#laps)
- [ ] Vérifier si [**WDigest** ](windows-local-privilege-escalation/index.html#wdigest)est actif
- [ ] [**Protection LSA**](windows-local-privilege-escalation/index.html#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/index.html#credentials-guard)[?](windows-local-privilege-escalation/index.html#cached-credentials)
- [ ] [**Identifiants mis en cache**](windows-local-privilege-escalation/index.html#cached-credentials)?
- [ ] Vérifier si un [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)
- [ ] [**Politique AppLocker**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**Privilèges utilisateur**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Vérifier les [**privilèges** de l'utilisateur **actuel**](windows-local-privilege-escalation/index.html#users-and-groups)
- [ ] Êtes-vous [**membre d'un groupe privilégié**](windows-local-privilege-escalation/index.html#privileged-groups)?
- [ ] Vérifier si vous avez [l'un de ces jetons activés](windows-local-privilege-escalation/index.html#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] [**Sessions utilisateurs**](windows-local-privilege-escalation/index.html#logged-users-sessions)?
- [ ] Vérifier[ **les dossiers des utilisateurs**](windows-local-privilege-escalation/index.html#home-folders) (accès?)
- [ ] Vérifier la [**Politique de mot de passe**](windows-local-privilege-escalation/index.html#password-policy)
- [ ] Que contient[ **le Presse-papiers**](windows-local-privilege-escalation/index.html#get-the-content-of-the-clipboard)?

### [Réseau](windows-local-privilege-escalation/index.html#network)

- [ ] Vérifier les **informations** [**réseau** **actuelles**](windows-local-privilege-escalation/index.html#network)
- [ ] Vérifier les **services locaux cachés** restreints à l'extérieur

### [Processus en cours](windows-local-privilege-escalation/index.html#running-processes)

- [ ] Permissions des fichiers et dossiers des **binaries des processus**](windows-local-privilege-escalation/index.html#file-and-folder-permissions)
- [ ] [**Extraction de mots de passe en mémoire**](windows-local-privilege-escalation/index.html#memory-password-mining)
- [ ] [**Applications GUI non sécurisées**](windows-local-privilege-escalation/index.html#insecure-gui-apps)
- [ ] Voler des identifiants avec des **processus intéressants** via `ProcDump.exe` ? (firefox, chrome, etc ...)

### [Services](windows-local-privilege-escalation/index.html#services)

- [ ] [Pouvez-vous **modifier un service**?](windows-local-privilege-escalation/index.html#permissions)
- [ ] [Pouvez-vous **modifier** le **binaire** qui est **exécuté** par un **service**?](windows-local-privilege-escalation/index.html#modify-service-binary-path)
- [ ] [Pouvez-vous **modifier** le **registre** de tout **service**?](windows-local-privilege-escalation/index.html#services-registry-modify-permissions)
- [ ] [Pouvez-vous tirer parti de tout **chemin de binaire de service non cité**?](windows-local-privilege-escalation/index.html#unquoted-service-paths)

### [**Applications**](windows-local-privilege-escalation/index.html#applications)

- [ ] **Écrire** [**permissions sur les applications installées**](windows-local-privilege-escalation/index.html#write-permissions)
- [ ] [**Applications de démarrage**](windows-local-privilege-escalation/index.html#run-at-startup)
- [ ] **Pilotes vulnérables** [**Drivers**](windows-local-privilege-escalation/index.html#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/index.html#path-dll-hijacking)

- [ ] Pouvez-vous **écrire dans un dossier à l'intérieur de PATH**?
- [ ] Y a-t-il un binaire de service connu qui **essaie de charger une DLL non existante**?
- [ ] Pouvez-vous **écrire** dans un **dossier de binaries**?

### [Réseau](windows-local-privilege-escalation/index.html#network)

- [ ] Énumérer le réseau (partages, interfaces, routes, voisins, ...)
- [ ] Faire attention aux services réseau écoutant sur localhost (127.0.0.1)

### [Identifiants Windows](windows-local-privilege-escalation/index.html#windows-credentials)

- [ ] [**Winlogon** ](windows-local-privilege-escalation/index.html#winlogon-credentials)identifiants
- [ ] [**Windows Vault**](windows-local-privilege-escalation/index.html#credentials-manager-windows-vault) identifiants que vous pourriez utiliser?
- [ ] Informations intéressantes sur les [**identifiants DPAPI**](windows-local-privilege-escalation/index.html#dpapi)?
- [ ] Mots de passe des [**réseaux Wifi enregistrés**](windows-local-privilege-escalation/index.html#wifi)?
- [ ] Informations intéressantes dans [**les connexions RDP enregistrées**](windows-local-privilege-escalation/index.html#saved-rdp-connections)?
- [ ] Mots de passe dans [**les commandes récemment exécutées**](windows-local-privilege-escalation/index.html#recently-run-commands)?
- [ ] Mots de passe du [**Gestionnaire d'identifiants de bureau à distance**](windows-local-privilege-escalation/index.html#remote-desktop-credential-manager)?
- [ ] [**AppCmd.exe** existe](windows-local-privilege-escalation/index.html#appcmd-exe)? Identifiants?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/index.html#scclient-sccm)? Chargement latéral de DLL?

### [Fichiers et Registre (Identifiants)](windows-local-privilege-escalation/index.html#files-and-registry-credentials)

- [ ] **Putty :** [**Identifiants**](windows-local-privilege-escalation/index.html#putty-creds) **et** [**clés hôtes SSH**](windows-local-privilege-escalation/index.html#putty-ssh-host-keys)
- [ ] [**Clés SSH dans le registre**](windows-local-privilege-escalation/index.html#ssh-keys-in-registry)?
- [ ] Mots de passe dans [**fichiers non surveillés**](windows-local-privilege-escalation/index.html#unattended-files)?
- [ ] Toute sauvegarde de [**SAM & SYSTEM**](windows-local-privilege-escalation/index.html#sam-and-system-backups)?
- [ ] [**Identifiants Cloud**](windows-local-privilege-escalation/index.html#cloud-credentials)?
- [ ] Fichier [**McAfee SiteList.xml**](windows-local-privilege-escalation/index.html#mcafee-sitelist.xml)?
- [ ] [**Mot de passe GPP mis en cache**](windows-local-privilege-escalation/index.html#cached-gpp-pasword)?
- [ ] Mot de passe dans le [**fichier de configuration IIS Web**](windows-local-privilege-escalation/index.html#iis-web-config)?
- [ ] Informations intéressantes dans [**journaux web**](windows-local-privilege-escalation/index.html#logs)?
- [ ] Voulez-vous [**demander des identifiants**](windows-local-privilege-escalation/index.html#ask-for-credentials) à l'utilisateur?
- [ ] Fichiers intéressants [**dans la Corbeille**](windows-local-privilege-escalation/index.html#credentials-in-the-recyclebin)?
- [ ] Autre [**registre contenant des identifiants**](windows-local-privilege-escalation/index.html#inside-the-registry)?
- [ ] À l'intérieur des [**données du navigateur**](windows-local-privilege-escalation/index.html#browsers-history) (dbs, historique, signets, ...)?
- [ ] [**Recherche de mots de passe génériques**](windows-local-privilege-escalation/index.html#generic-password-search-in-files-and-registry) dans les fichiers et le registre
- [ ] [**Outils**](windows-local-privilege-escalation/index.html#tools-that-search-for-passwords) pour rechercher automatiquement des mots de passe

### [Gestionnaires fuyants](windows-local-privilege-escalation/index.html#leaked-handlers)

- [ ] Avez-vous accès à un gestionnaire d'un processus exécuté par l'administrateur?

### [Impersonation de client de pipe](windows-local-privilege-escalation/index.html#named-pipe-client-impersonation)

- [ ] Vérifiez si vous pouvez en abuser

{{#include ../banners/hacktricks-training.md}}
