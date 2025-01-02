# Liste de contrôle - Élévation de privilèges locale Windows

{{#include ../banners/hacktricks-training.md}}

### **Meilleur outil pour rechercher des vecteurs d'élévation de privilèges locaux Windows :** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Informations système](windows-local-privilege-escalation/#system-info)

- [ ] Obtenir [**Informations système**](windows-local-privilege-escalation/#system-info)
- [ ] Rechercher des **exploits de noyau** [**en utilisant des scripts**](windows-local-privilege-escalation/#version-exploits)
- [ ] Utiliser **Google pour rechercher** des **exploits de noyau**
- [ ] Utiliser **searchsploit pour rechercher** des **exploits de noyau**
- [ ] Informations intéressantes dans [**env vars**](windows-local-privilege-escalation/#environment)?
- [ ] Mots de passe dans [**l'historique PowerShell**](windows-local-privilege-escalation/#powershell-history)?
- [ ] Informations intéressantes dans [**paramètres Internet**](windows-local-privilege-escalation/#internet-settings)?
- [ ] [**Lecteurs**](windows-local-privilege-escalation/#drives)?
- [ ] [**Exploitation WSUS**](windows-local-privilege-escalation/#wsus)?
- [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/#alwaysinstallelevated)?

### [Énumération des journaux/AV](windows-local-privilege-escalation/#enumeration)

- [ ] Vérifier les paramètres [**Audit**](windows-local-privilege-escalation/#audit-settings) et [**WEF**](windows-local-privilege-escalation/#wef)
- [ ] Vérifier [**LAPS**](windows-local-privilege-escalation/#laps)
- [ ] Vérifier si [**WDigest**](windows-local-privilege-escalation/#wdigest) est actif
- [ ] [**Protection LSA**](windows-local-privilege-escalation/#lsa-protection)?
- [ ] [**Credentials Guard**](windows-local-privilege-escalation/#credentials-guard)[?](windows-local-privilege-escalation/#cached-credentials)
- [ ] [**Identifiants mis en cache**](windows-local-privilege-escalation/#cached-credentials)?
- [ ] Vérifier si un [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)
- [ ] [**Politique AppLocker**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
- [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
- [ ] [**Privilèges utilisateur**](windows-local-privilege-escalation/#users-and-groups)
- [ ] Vérifier les [**privilèges**] de l'utilisateur [**actuel**](windows-local-privilege-escalation/#users-and-groups)
- [ ] Êtes-vous [**membre d'un groupe privilégié**](windows-local-privilege-escalation/#privileged-groups)?
- [ ] Vérifier si vous avez [l'un de ces jetons activés](windows-local-privilege-escalation/#token-manipulation) : **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
- [ ] [**Sessions des utilisateurs**](windows-local-privilege-escalation/#logged-users-sessions)?
- [ ] Vérifier les [**dossiers des utilisateurs**](windows-local-privilege-escalation/#home-folders) (accès ?)
- [ ] Vérifier la [**Politique de mot de passe**](windows-local-privilege-escalation/#password-policy)
- [ ] Qu'est-ce qu'il y a [**dans le Presse-papiers**](windows-local-privilege-escalation/#get-the-content-of-the-clipboard)?

### [Réseau](windows-local-privilege-escalation/#network)

- [ ] Vérifier les **informations** [**réseau** **actuelles**](windows-local-privilege-escalation/#network)
- [ ] Vérifier les **services locaux cachés** restreints à l'extérieur

### [Processus en cours](windows-local-privilege-escalation/#running-processes)

- [ ] Permissions des fichiers et dossiers des binaires [**des processus**](windows-local-privilege-escalation/#file-and-folder-permissions)
- [ ] [**Extraction de mots de passe en mémoire**](windows-local-privilege-escalation/#memory-password-mining)
- [ ] [**Applications GUI non sécurisées**](windows-local-privilege-escalation/#insecure-gui-apps)
- [ ] Voler des identifiants avec des **processus intéressants** via `ProcDump.exe` ? (firefox, chrome, etc ...)

### [Services](windows-local-privilege-escalation/#services)

- [ ] [Pouvez-vous **modifier un service** ?](windows-local-privilege-escalation/#permissions)
- [ ] [Pouvez-vous **modifier** le **binaire** qui est **exécuté** par un **service** ?](windows-local-privilege-escalation/#modify-service-binary-path)
- [ ] [Pouvez-vous **modifier** le **registre** de n'importe quel **service** ?](windows-local-privilege-escalation/#services-registry-modify-permissions)
- [ ] [Pouvez-vous tirer parti de n'importe quel **chemin de binaire de service non cité** ?](windows-local-privilege-escalation/#unquoted-service-paths)

### [**Applications**](windows-local-privilege-escalation/#applications)

- [ ] **Écrire** [**permissions sur les applications installées**](windows-local-privilege-escalation/#write-permissions)
- [ ] [**Applications de démarrage**](windows-local-privilege-escalation/#run-at-startup)
- [ ] **Pilotes vulnérables** [**Drivers**](windows-local-privilege-escalation/#drivers)

### [Détournement de DLL](windows-local-privilege-escalation/#path-dll-hijacking)

- [ ] Pouvez-vous **écrire dans n'importe quel dossier à l'intérieur de PATH** ?
- [ ] Y a-t-il un binaire de service connu qui **essaie de charger une DLL non existante** ?
- [ ] Pouvez-vous **écrire** dans n'importe quel **dossier de binaires** ?

### [Réseau](windows-local-privilege-escalation/#network)

- [ ] Énumérer le réseau (partages, interfaces, routes, voisins, ...)
- [ ] Faire attention aux services réseau écoutant sur localhost (127.0.0.1)

### [Identifiants Windows](windows-local-privilege-escalation/#windows-credentials)

- [ ] [**Identifiants Winlogon**](windows-local-privilege-escalation/#winlogon-credentials)
- [ ] [**Identifiants Windows Vault**](windows-local-privilege-escalation/#credentials-manager-windows-vault) que vous pourriez utiliser ?
- [ ] Identifiants [**DPAPI intéressants**](windows-local-privilege-escalation/#dpapi)?
- [ ] Mots de passe des [**réseaux Wifi enregistrés**](windows-local-privilege-escalation/#wifi)?
- [ ] Informations intéressantes dans [**Connexions RDP enregistrées**](windows-local-privilege-escalation/#saved-rdp-connections)?
- [ ] Mots de passe dans [**commandes récemment exécutées**](windows-local-privilege-escalation/#recently-run-commands)?
- [ ] Mots de passe du [**Gestionnaire d'identifiants de bureau à distance**](windows-local-privilege-escalation/#remote-desktop-credential-manager)?
- [ ] [**AppCmd.exe** existe](windows-local-privilege-escalation/#appcmd-exe)? Identifiants ?
- [ ] [**SCClient.exe**](windows-local-privilege-escalation/#scclient-sccm)? Chargement latéral de DLL ?

### [Fichiers et Registre (Identifiants)](windows-local-privilege-escalation/#files-and-registry-credentials)

- [ ] **Putty :** [**Identifiants**](windows-local-privilege-escalation/#putty-creds) **et** [**clés hôtes SSH**](windows-local-privilege-escalation/#putty-ssh-host-keys)
- [ ] [**Clés SSH dans le registre**](windows-local-privilege-escalation/#ssh-keys-in-registry)?
- [ ] Mots de passe dans [**fichiers non surveillés**](windows-local-privilege-escalation/#unattended-files)?
- [ ] Y a-t-il une sauvegarde de [**SAM & SYSTEM**](windows-local-privilege-escalation/#sam-and-system-backups) ?
- [ ] [**Identifiants Cloud**](windows-local-privilege-escalation/#cloud-credentials)?
- [ ] Fichier [**McAfee SiteList.xml**](windows-local-privilege-escalation/#mcafee-sitelist.xml) ?
- [ ] [**Mot de passe GPP mis en cache**](windows-local-privilege-escalation/#cached-gpp-pasword)?
- [ ] Mot de passe dans le [**fichier de configuration IIS Web**](windows-local-privilege-escalation/#iis-web-config)?
- [ ] Informations intéressantes dans les [**journaux web**](windows-local-privilege-escalation/#logs)?
- [ ] Voulez-vous [**demander des identifiants**](windows-local-privilege-escalation/#ask-for-credentials) à l'utilisateur ?
- [ ] Fichiers intéressants [**dans la Corbeille**](windows-local-privilege-escalation/#credentials-in-the-recyclebin)?
- [ ] Autre [**registre contenant des identifiants**](windows-local-privilege-escalation/#inside-the-registry)?
- [ ] À l'intérieur des [**données du navigateur**](windows-local-privilege-escalation/#browsers-history) (dbs, historique, signets, ...) ?
- [ ] [**Recherche de mots de passe génériques**](windows-local-privilege-escalation/#generic-password-search-in-files-and-registry) dans les fichiers et le registre
- [ ] [**Outils**](windows-local-privilege-escalation/#tools-that-search-for-passwords) pour rechercher automatiquement des mots de passe

### [Gestionnaires fuyants](windows-local-privilege-escalation/#leaked-handlers)

- [ ] Avez-vous accès à un gestionnaire d'un processus exécuté par l'administrateur ?

### [Impersonation de client de pipe](windows-local-privilege-escalation/#named-pipe-client-impersonation)

- [ ] Vérifiez si vous pouvez en abuser

{{#include ../banners/hacktricks-training.md}}
