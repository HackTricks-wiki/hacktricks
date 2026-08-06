# Local NTLM Reflection via SMB Arbitrary Port

{{#include ../../banners/hacktricks-training.md}}

Les versions récentes de Windows ont introduit le **support client SMB des ports TCP alternatifs**. Cette fonctionnalité peut être exploitée pour transformer une **authentification NTLM locale** en une **élévation de privilèges locale vers SYSTEM** lorsque l'attaquant peut :<sup>[[1]](#references)</sup>

1. Ouvrir une connexion SMB vers un listener contrôlé par l'attaquant sur un **port différent de 445**
2. Maintenir cette connexion TCP active
3. Forcer un **client local privilégié** à accéder au **même chemin de partage SMB**
4. Relayer l'**authentification NTLM locale** résultante vers le véritable service SMB de la machine

Il s'agit de la primitive à l'origine de **CVE-2026-24294**, corrigée en **mars 2026**.<sup>[[1]](#references)[[4]](#references)</sup>

## Pourquoi cela fonctionne

L'ancienne technique de reflection CMTI / serialized-SPN est présentée ici :

{{#ref}}
../ntlm/README.md
{{#endref}}

Cette nouvelle variante n'a **pas** besoin d'un hostname marshalé. Elle abuse plutôt de deux comportements du client SMB :<sup>[[1]](#references)</sup>

- **Support des ports alternatifs** sur **Windows 11 24H2** et **Windows Server 2025**, accessible aux utilisateurs avec `net use \\host\share /tcpport:<port>`
- **Réutilisation / multiplexage des connexions SMB**, où plusieurs sessions authentifiées peuvent utiliser la même connexion TCP

Cela signifie qu'un utilisateur disposant de faibles privilèges peut d'abord créer une connexion TCP depuis le client SMB vers un serveur SMB contrôlé par l'attaquant sur un port élevé, puis forcer un service privilégié à accéder à l'**exact même chemin UNC**. Si Windows décide de réutiliser la connexion TCP existante, l'échange NTLM privilégié est envoyé via le transport contrôlé par l'attaquant et peut être relayé vers le serveur SMB local.<sup>[[1]](#references)</sup>

## Prérequis

- La cible prend en charge les ports SMB alternatifs :<sup>[[2]](#references)</sup>
- **Windows 11 24H2** ou version ultérieure
- **Windows Server 2025** ou version ultérieure
- L'attaquant peut exécuter un serveur SMB local ou distant sur un port élevé choisi
- L'attaquant peut forcer un service privilégié à accéder à un chemin UNC
- L'authentification privilégiée doit être une **authentification NTLM locale**
- La cible doit être relayable :<sup>[[1]](#references)</sup>
- Synacktiv a indiqué que cela fonctionnait par défaut sur **Windows Server 2025**
- Leur chaîne ne fonctionnait **pas** sur **Windows 11 24H2**, car la signature SMB sortante y est activée par défaut

## Userland et internals

Depuis la ligne de commande, la fonctionnalité paraît simple :
```cmd
net use \\192.168.56.3\share /tcpport:12345
```
Programmatically, le client utilise `WNetAddConnection4W` avec des données `lpUseOptions` non documentées. L’option pertinente est `TraP` (transport parameters), qui atteint finalement le client SMB du kernel via un FSCTL et est analysée par `mrxsmb`.<sup>[[1]](#references)[[3]](#references)</sup>

Points pratiques importants :<sup>[[1]](#references)</sup>

- **La syntaxe UNC ne comporte toujours aucun champ de port**
- **`net use` est propre à chaque session de logon**
- Le bypass fonctionne toujours, car **la connexion TCP et la session SMB sont des objets distincts**
- La réutilisation du **même chemin de partage** est obligatoire si l’exploit dépend de la réutilisation, par le client SMB, de la connexion TCP créée précédemment

## Déroulement de l’exploitation

### 1. Créer le transport SMB contrôlé par l’attaquant

Exécutez un serveur SMB sur un port élevé et faites-y connecter Windows :
```cmd
net use \\192.168.56.3\share /tcpport:12345
```
Le serveur peut accepter toute paire d'identifiants que vous contrôlez, par exemple `user:user`. L'objectif de cette étape n'est pas encore l'escalade de privilèges, mais uniquement de faire ouvrir au client Windows SMB une connexion TCP réutilisable vers votre listener et de la maintenir ouverte.<sup>[[1]](#references)</sup>

### 2. Coerce a privileged service to the same UNC path

Utilisez une primitive de coercion telle que **PetitPotam** contre le même chemin `\\192.168.56.3\share`. Si le client soumis à la coercion est privilégié et que le nom cible est local (`localhost` ou une IP/un hôte local), Windows effectue une **NTLM local authentication**.

Comme la connexion TCP est réutilisée, cet échange NTLM privilégié est envoyé au service SMB de l'attaquant au lieu d'être transmis directement au véritable serveur SMB local.<sup>[[1]](#references)</sup>

### 3. Relay the privileged authentication back to local SMB

Le service SMB contrôlé par l'attaquant transmet l'échange NTLM privilégié à `ntlmrelayx.py`, qui le relaie vers le véritable listener SMB de la machine et obtient une session en tant que `NT AUTHORITY\SYSTEM`.<sup>[[1]](#references)</sup>

Outils typiques mentionnés dans la writeup publique :<sup>[[1]](#references)</sup>

- `smbserver.py` sur un port personnalisé pour recevoir l'authentification privilégiée via la connexion TCP réutilisée
- `ntlmrelayx.py` pour relayer le NTLM capturé vers le SMB local
- `PetitPotam.exe` ou une autre primitive de coercion pour forcer l'authentification privilégiée

## Operator notes

- Il s'agit d'une technique d'**escalade de privilèges locale**, et non d'une technique générique de remote relay<sup>[[1]](#references)</sup>
- Le service SMB contrôlé par l'attaquant doit gérer l'authentification privilégiée sur la **même connexion TCP** utilisée initialement pour monter le partage<sup>[[1]](#references)</sup>
- Si l'accès soumis à la coercion utilise un **chemin de partage différent**, Windows peut établir une connexion différente, ce qui interrompt la chaîne<sup>[[1]](#references)</sup>
- Les exigences de signature SMB peuvent empêcher le relay même lorsque l'étape utilisant un port arbitraire fonctionne<sup>[[1]](#references)</sup>
- Si vous disposez uniquement de matériel Kerberos ou si vous ne pouvez pas forcer l'utilisation de NTLM local, cette variante précise ne suffit pas<sup>[[1]](#references)</sup>

## Detection and hardening

- Appliquez le correctif **CVE-2026-24294** du **Patch Tuesday de mars 2026**<sup>[[4]](#references)</sup>
- Surveillez l'utilisation de `net use` ou `New-SmbMapping` avec des **ports SMB non standard**<sup>[[1]](#references)</sup>
- Déclenchez une alerte en cas de trafic SMB sortant inhabituel depuis des postes de travail ou des serveurs vers des **ports TCP élevés**<sup>[[1]](#references)</sup>
- Examinez les possibilités de coercion telles que les déclencheurs de type **EFSRPC / PetitPotam**<sup>[[1]](#references)</sup>
- Activez la signature SMB lorsque cela est possible ; Synacktiv indique spécifiquement que celle-ci a bloqué leur relay sur Windows 11 24H2<sup>[[1]](#references)</sup>

## References

- [1] [Synacktiv - Bypassing Windows authentication reflection mitigations for SYSTEM shells - Part 1](https://www.synacktiv.com/en/publications/bypassing-windows-authentication-reflection-mitigations-for-system-shells-part-1.html)
- [2] [Microsoft Learn - Configure alternative SMB ports for Windows Server 2025](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ports)
- [3] [Microsoft Learn - WNetAddConnection4W](https://learn.microsoft.com/en-us/windows/win32/api/winnetwk/nf-winnetwk-wnetaddconnection4w)
- [4] [MSRC - CVE-2026-24294](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-24294)

{{#include ../../banners/hacktricks-training.md}}
