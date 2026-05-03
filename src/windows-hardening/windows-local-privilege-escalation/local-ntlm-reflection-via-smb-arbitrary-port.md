# Local NTLM Reflection via SMB Arbitrary Port

{{#include ../../banners/hacktricks-training.md}}

Les versions récentes de Windows ont introduit la **prise en charge par le client SMB de ports TCP alternatifs**. Cette fonctionnalité peut être abusée pour transformer une **authentification NTLM locale** en une **élévation de privilèges locale SYSTEM** lorsque l’attaquant peut :

1. Ouvrir une connexion SMB vers un listener contrôlé par l’attaquant sur un **port autre que 445**
2. Maintenir cette connexion TCP active
3. Contraindre un **client local privilégié** à accéder au **même chemin de partage SMB**
4. Relayer la **local NTLM authentication** obtenue vers le vrai service SMB de la machine

C’est le mécanisme derrière **CVE-2026-24294**, corrigé en **mars 2026**.

## Pourquoi ça fonctionne

L’ancienne astuce de reflection CMTI / serialized-SPN est décrite ici :

{{#ref}}
../ntlm/README.md
{{#endref}}

Cette nouvelle variante n’a **pas** besoin d’un hostname marshalled. Elle abuse à la place de deux comportements du client SMB :

- La **prise en charge des ports alternatifs** sur **Windows 11 24H2** et **Windows Server 2025**, exposée aux utilisateurs avec `net use \\host\share /tcpport:<port>`
- La **réutilisation / multiplexage des connexions SMB**, où plusieurs sessions authentifiées peuvent emprunter la même connexion TCP

Cela signifie qu’un utilisateur à faibles privilèges peut d’abord créer une connexion TCP depuis le client SMB vers un serveur SMB de l’attaquant sur un port élevé, puis contraindre un service privilégié à accéder au **même chemin UNC exact**. Si Windows décide de réutiliser la connexion TCP existante, l’échange NTLM privilégié est envoyé via le transport contrôlé par l’attaquant et peut être relayé vers le service SMB local.

## Prérequis

- La cible prend en charge les ports SMB alternatifs :
- **Windows 11 24H2** ou plus récent
- **Windows Server 2025** ou plus récent
- L’attaquant peut exécuter un serveur SMB local ou distant sur un port élevé choisi
- L’attaquant peut contraindre un service privilégié à accéder à un chemin UNC
- L’authentification privilégiée doit être une **local authentication NTLM**
- La cible doit être relayable :
- Synacktiv a indiqué que cela fonctionnait par défaut sur **Windows Server 2025**
- Leur chaîne ne fonctionnait **pas** sur **Windows 11 24H2** car SMB signing sortant y est imposé par défaut

## Userland and internals

Depuis la ligne de commande, la fonctionnalité semble simple :
```cmd
net use \\192.168.56.3\share /tcpport:12345
```
Programmatiquement, le client utilise `WNetAddConnection4W` avec des données `lpUseOptions` non documentées. L’option pertinente est `TraP` (transport parameters), qui atteint finalement le client SMB du noyau via un FSCTL et est interprétée par `mrxsmb`.

Notes pratiques importantes :

- **La syntaxe UNC n’a toujours pas de champ de port**
- **`net use` est propre à la session de connexion**
- Le bypass fonctionne toujours parce que **la connexion TCP et la session SMB sont des objets distincts**
- Réutiliser le **même share path** est obligatoire si l’exploit dépend du fait que le client SMB réutilise la connexion TCP créée précédemment

## Exploitation flow

### 1. Create the attacker-controlled SMB transport

Run an SMB server on a high port and make Windows connect to it:
```cmd
net use \\192.168.56.3\share /tcpport:12345
```
Le serveur peut accepter n’importe quelle paire d’identifiants que vous contrôlez, par exemple `user:user`. L’objectif de cette étape n’est pas encore une privilege escalation, mais seulement de faire ouvrir au client SMB Windows et conserver une connexion TCP réutilisable vers votre listener.

### 2. Coerce un service privilégié vers le même chemin UNC

Utilisez un primitive de coercion comme **PetitPotam** contre le **même** chemin `\\192.168.56.3\share`. Si le client forcé est privilégié et que le nom cible est local (`localhost` ou une IP/host locale), Windows effectue une **NTLM local authentication**.

Comme la connexion TCP est réutilisée, cet échange NTLM privilégié est envoyé au service SMB de l’attaquant au lieu d’aller directement vers le vrai serveur SMB local.

### 3. Relay the privileged authentication back to local SMB

Le service SMB contrôlé par l’attaquant transfère l’échange NTLM privilégié à `ntlmrelayx.py`, qui le relaie vers le vrai listener SMB de la machine et obtient une session en tant que `NT AUTHORITY\SYSTEM`.

Outils typiques issus du writeup public :

- `smbserver.py` sur un port personnalisé pour recevoir l’auth privilégiée via la connexion TCP réutilisée
- `ntlmrelayx.py` pour relayer le NTLM capturé vers le SMB local
- `PetitPotam.exe` ou un autre primitive de coercion pour forcer l’authentification privilégiée

## Operator notes

- C’est une technique de **local privilege escalation**, pas un trick de relay distant générique
- Le service SMB contrôlé par l’attaquant doit gérer l’authentification privilégiée sur la **même connexion TCP** utilisée à l’origine pour le montage du partage
- Si l’accès forcé touche un **chemin de partage différent**, Windows peut établir une connexion différente et la chaîne se casse
- Les exigences de SMB signing peuvent casser le relay même lorsque l’étape du port arbitraire fonctionne
- Si vous n’avez que du matériel Kerberos ou si vous ne pouvez pas forcer le NTLM local, cette variante exacte ne suffit pas

## Detection and hardening

- Patch **CVE-2026-24294** du **March 2026 Patch Tuesday**
- Surveillez `net use` ou `New-SmbMapping` utilisant des **ports SMB non par défaut**
- Alertez sur du SMB sortant inhabituel depuis des postes de travail ou des serveurs vers des **ports TCP élevés**
- Examinez les opportunités de coercion comme les triggers **EFSRPC / PetitPotam-style**
- Activez SMB signing quand c’est possible ; Synacktiv note spécifiquement que cela a bloqué leur relay sur Windows 11 24H2

## References

- [Synacktiv - Bypassing Windows authentication reflection mitigations for SYSTEM shells - Part 1](https://www.synacktiv.com/en/publications/bypassing-windows-authentication-reflection-mitigations-for-system-shells-part-1.html)
- [Microsoft Learn - Configure alternative SMB ports for Windows Server 2025](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ports)
- [Microsoft Learn - WNetAddConnection4W](https://learn.microsoft.com/en-us/windows/win32/api/winnetwk/nf-winnetwk-wnetaddconnection4w)
- [Project Zero - Windows Exploitation Tricks: Trapping Virtual Memory Access (2025 Update)](https://projectzero.google/2025/01/windows-exploitation-tricks-trapping.html)
- [MSRC - CVE-2026-24294](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-24294)

{{#include ../../banners/hacktricks-training.md}}
