# Mythic

{{#include ../banners/hacktricks-training.md}}

## Qu'est-ce que Mythic ?

Mythic est un framework open-source, modulaire et collaboratif de command and control (C2) conçu pour le red teaming. Il permet aux operators de gérer et déployer des agents (payloads) sur différents systèmes d'exploitation, y compris Windows, Linux et macOS. Mythic fournit une interface UI dans le navigateur pour le tasking multi-operator, la gestion de fichiers, la gestion SOCKS/rpfwd, et la génération de payloads.

Contrairement aux frameworks monolithiques, le dépôt Mythic lui-même ne fournit **pas** de types de payloads ni de profils C2. Les agents, wrappers et profils C2 sont généralement installés comme composants externes et peuvent être mis à jour indépendamment du noyau de Mythic.

### Installation

Pour installer Mythic, suivez les instructions sur le **[Mythic repo](https://github.com/its-a-feature/Mythic)** officiel. Un bootstrap courant depuis le répertoire Mythic est :
```bash
sudo make
sudo ./mythic-cli start
```
Si Mythic est déjà en cours d’exécution, vous pouvez normalement ajouter un nouvel agent ou profile avec `./mythic-cli install github ...` puis soit redémarrer Mythic, soit simplement démarrer directement le nouveau composant.

### Agents

Mythic prend en charge plusieurs agents, qui sont les **payloads qui exécutent des tâches sur les systèmes compromis**. Chaque agent peut être adapté à des besoins spécifiques et peut fonctionner sur différents systèmes d’exploitation.

Par défaut, Mythic n’a aucun agent installé. Les agents open-source de la communauté se trouvent dans [**https://github.com/MythicAgents**](https://github.com/MythicAgents), et la [**community feature matrix**](https://mythicmeta.github.io/overview/agent_matrix.html) est utile pour vérifier rapidement les systèmes d’exploitation pris en charge, les formats de payload, les wrappers et les profiles C2.

Pour installer un agent depuis cette org, vous pouvez exécuter :
```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
sudo -E ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
La forme `sudo -E` est utile lorsque vous installez depuis un environnement non-root. Vous pouvez ajouter de nouveaux agents avec la commande précédente même si Mythic est déjà en cours d'exécution.

### C2 Profiles

Les C2 profiles dans Mythic définissent **comment les agents communiquent avec le serveur Mythic**. Ils spécifient le protocole de communication, les méthodes de chiffrement et d'autres paramètres. Vous pouvez créer et gérer des C2 profiles via l'interface web de Mythic.

Par défaut, Mythic est installé sans profiles, cependant, il est possible de télécharger certains profiles depuis le repo [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles) en exécutant:
```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```
Current operator-relevant profiles to keep in mind:

- [`http`](https://github.com/MythicC2Profiles/http): trafic GET/POST asynchrone basique.
- [`httpx`](https://github.com/MythicC2Profiles/httpx): trafic HTTP plus flexible avec plusieurs callback domains, rotation fail-over/round-robin, custom headers/query parameters, et transformations de message (`base64`, `base64url`, `xor`, `netbios`, `prepend`, `append`) placées dans les cookies, headers, query parameters, ou le body.
- [`dynamichttp`](https://github.com/MythicC2Profiles/dynamichttp): façonnage de messages HTTP piloté par JSON/TOML quand le profil statique `http` est trop reconnaissable.

### Wrapper payloads

Wrapper payloads te permettent de garder la même logique d'agent tout en changeant la représentation sur disque qui est livrée ou persistée.

- `service_wrapper`: transforme un autre payload en exécutable de service Windows, ce qui est utile quand le chemin d'exécution nécessite un binaire de service valide.
- `scarecrow_wrapper`: enveloppe du shellcode compatible avec le loader ScareCrow pour générer des sorties basées sur un loader telles que EXE/DLL/CPL.

## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Apollo est un agent Windows écrit en C# utilisant le .NET Framework 4.0, conçu pour être utilisé dans les offres de formation SpecterOps.

Install it with:
```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
### Notes actuelles de build/profile

- Apollo peut actuellement émettre des payloads `WinExe`, `Shellcode`, `Service` et `Source`.
- Les profiles Apollo les plus utilisés sont `http`, `httpx`, `smb`, `tcp` et `websocket`.
- `httpx` est généralement l’option la plus flexible lorsque vous avez besoin de rotation de domaine, de support proxy, de placement personnalisé des messages et de transforms de messages, au lieu de l’ancien profile statique `http`.
- Apollo prend en charge des payloads wrapper tels que `service_wrapper` et `scarecrow_wrapper`.
- `register_file` et `register_assembly` sont les primitives de staging pour `execute_assembly`, `execute_pe`, `inline_assembly`, `execute_coff`, `powershell_import` et `powerpick`. Dans les builds Apollo actuels, ces artifacts staged sont mis en cache côté client sous forme de blobs AES256 protégés par DPAPI.
- Les résultats de `ls` et `ps` s’intègrent particulièrement bien avec les browser scripts de Mythic et le browser fichiers/processus, ce qui rend le triage opérateur nettement plus rapide lors d’opérations collaboratives.

Cet agent a beaucoup de commandes, ce qui le rend très similaire à Beacon de Cobalt Strike avec quelques extras. Parmi elles, il prend en charge :

### Actions courantes

- `cat`: Afficher le contenu d’un fichier
- `cd`: Changer le répertoire de travail actuel
- `cp`: Copier un fichier d’un emplacement à un autre
- `ls`: Lister les fichiers et répertoires dans le répertoire courant ou le chemin spécifié
- `ifconfig`: Obtenir les adaptateurs et interfaces réseau
- `netstat`: Obtenir les informations de connexion TCP et UDP
- `pwd`: Afficher le répertoire de travail actuel
- `ps`: Lister les processus en cours d’exécution sur le système cible (avec des infos supplémentaires)
- `jobs`: Lister tous les jobs en cours associés à des tâches de longue durée
- `download`: Télécharger un fichier du système cible vers la machine locale
- `upload`: Envoyer un fichier de la machine locale vers le système cible
- `reg_query`: Interroger les clés et valeurs de registre sur le système cible
- `reg_write_value`: Écrire une nouvelle valeur dans une clé de registre spécifiée
- `sleep`: Modifier l’intervalle de sommeil de l’agent, qui détermine à quelle fréquence il contacte le serveur Mythic
- Et beaucoup d’autres, utilisez `help` pour voir la liste complète des commandes disponibles.

### Élévation de privilèges

- `getprivs`: Activer autant de privilèges que possible sur le token du thread actuel
- `getsystem`: Ouvrir un handle vers winlogon et dupliquer le token, en élevant effectivement les privilèges au niveau SYSTEM
- `make_token`: Créer une nouvelle session de logon et l’appliquer à l’agent, permettant l’impersonation d’un autre utilisateur
- `steal_token`: Voler un token primaire d’un autre processus, permettant à l’agent d’imiter l’utilisateur de ce processus
- `pth`: Attaque Pass-the-Hash, permettant à l’agent de s’authentifier en tant qu’utilisateur en utilisant son hash NTLM sans avoir besoin du mot de passe en clair
- `mimikatz`: Exécuter des commandes Mimikatz pour extraire des credentials, des hashes et d’autres informations sensibles depuis la mémoire ou la base de données SAM
- `rev2self`: Revenir au token primaire de l’agent, en abandonnant effectivement les privilèges pour revenir au niveau d’origine
- `ppid`: Modifier le processus parent des jobs post-exploitation en spécifiant un nouvel ID de processus parent, permettant un meilleur contrôle du contexte d’exécution des jobs
- `printspoofer`: Exécuter des commandes PrintSpoofer pour contourner les mesures de sécurité du spooler d’impression, permettant une élévation de privilèges ou l’exécution de code
- `dcsync`: Synchroniser les clés Kerberos d’un utilisateur vers la machine locale, permettant un craquage hors ligne du mot de passe ou d’autres attaques
- `ticket_cache_add`: Ajouter un ticket Kerberos à la session de logon actuelle ou à une session spécifiée, permettant la réutilisation de tickets ou l’impersonation

### Exécution de processus

- `assembly_inject`: Permet d’injecter un chargeur d’assembly .NET dans un processus distant
- `blockdlls`: Bloquer le chargement de DLL non signées par Microsoft dans les jobs post-exploitation
- `execute_assembly`: Exécute un assembly .NET dans le contexte de l’agent
- `execute_coff`: Exécute un fichier COFF en mémoire, permettant l’exécution en mémoire de code compilé
- `execute_pe`: Exécute un exécutable unmanaged (PE)
- `get_injection_techniques`: Afficher les techniques d’injection disponibles et celle actuellement sélectionnée
- `inline_assembly`: Exécute un assembly .NET dans un AppDomain jetable, permettant une exécution temporaire du code sans affecter le processus principal de l’agent
- `register_assembly`: Enregistrer un assembly .NET pour une exécution ultérieure
- `register_file`: Enregistrer un fichier dans le cache de l’agent pour un futur tasking `execute_*` ou PowerShell
- `run`: Exécute un binaire sur le système cible, en utilisant le PATH du système pour trouver l’exécutable
- `set_injection_technique`: Modifier la primitive d’injection utilisée par les jobs post-exploitation
- `shinject`: Injecte du shellcode dans un processus distant, permettant l’exécution en mémoire de code arbitraire
- `inject`: Injecte le shellcode de l’agent dans un processus distant, permettant l’exécution en mémoire du code de l’agent
- `spawn`: Lance une nouvelle session d’agent dans l’exécutable spécifié, permettant l’exécution de shellcode dans un nouveau processus
- `spawnto_x64` et `spawnto_x86`: Modifier le binaire par défaut utilisé dans les jobs post-exploitation vers un chemin spécifié au lieu d’utiliser `rundll32.exe` sans paramètres, ce qui est très bruyant.

### Mythic Forge

Cela permet de **charger des fichiers COFF/BOF** depuis Mythic Forge, qui est un dépôt de payloads et d’outils précompilés pouvant être exécutés sur le système cible. Avec toutes les commandes qui peuvent être chargées, il sera possible d’effectuer des actions courantes en les exécutant dans le processus actuel de l’agent comme des BOFs (généralement avec une meilleure OPSEC que de lancer un processus séparé).

Commencez à les installer avec :
```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```
Then, use `forge_collections` to show the COFF/BOF modules from the Mythic Forge to be able to select and load them into the agent's memory for execution. By default, the following 2 collections are added in Apollo:

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

After one module is loaded, it'll appear in the list as another command like `forge_bof_sa-whoami` or `forge_bof_sa-netuser`.

### PowerShell & scripting execution

- `powershell_import`: Importe un nouveau script PowerShell (.ps1) dans le cache de l'agent pour une exécution ultérieure
- `powershell`: Exécute une commande PowerShell dans le contexte de l'agent, permettant des scripts avancés et l'automatisation
- `powerpick`: Injecte un assembly de chargeur PowerShell dans un processus sacrificiel et exécute une commande PowerShell (sans journalisation powershell).
- `psinject`: Exécute PowerShell dans un processus spécifié, permettant une exécution ciblée de scripts dans le contexte d'un autre processus
- `shell`: Exécute une commande shell dans le contexte de l'agent, similaire à l'exécution d'une commande dans cmd.exe

### Lateral Movement

- `jump_psexec`: Utilise la technique PsExec pour se déplacer latéralement vers un nouvel hôte en copiant d'abord l'exécutable de l'agent Apollo (apollo.exe) puis en l'exécutant.
- `jump_wmi`: Utilise la technique WMI pour se déplacer latéralement vers un nouvel hôte en copiant d'abord l'exécutable de l'agent Apollo (apollo.exe) puis en l'exécutant.
- `link` and `unlink`: Crée et supprime des liens P2P (par exemple via SMB/TCP) entre callbacks.
- `wmiexecute`: Exécute une commande sur le système local ou distant spécifié en utilisant WMI, avec des identifiants facultatifs pour l'usurpation.
- `net_dclist`: Récupère une liste de contrôleurs de domaine pour le domaine spécifié, utile pour identifier des cibles potentielles pour le lateral movement.
- `net_localgroup`: Liste les groupes locaux sur l'ordinateur spécifié, localhost étant utilisé par défaut si aucun ordinateur n'est spécifié.
- `net_localgroup_member`: Récupère l'appartenance aux groupes locaux pour un groupe spécifié sur l'ordinateur local ou distant, permettant l'énumération des utilisateurs dans des groupes spécifiques.
- `net_shares`: Liste les partages distants et leur accessibilité sur l'ordinateur spécifié, utile pour identifier des cibles potentielles pour le lateral movement.
- `socks`: Active un proxy compatible SOCKS 5 sur le réseau cible, permettant de tunneliser le trafic via l'hôte compromis. Compatible avec des outils comme proxychains.
- `rpfwd`: Commence à écouter sur un port spécifié sur l'hôte cible et redirige le trafic via Mythic vers une IP et un port distants, permettant un accès distant aux services sur le réseau cible.
- `listpipes`: Liste tous les named pipes sur le système local, ce qui peut être utile pour le lateral movement ou l'élévation de privilèges en interagissant avec les mécanismes IPC.

Pour les primitives d'exécution WMI de plus bas niveau utilisées sous `jump_wmi` ou `wmiexecute`, consultez [WmiExec](lateral-movement/wmiexec.md). Pour des patterns de pivoting plus larges, consultez [Tunneling and Port Forwarding](../generic-hacking/tunneling-and-port-forwarding.md).

### Miscellaneous Commands
- `help`: Affiche des informations détaillées sur des commandes spécifiques ou des informations générales sur toutes les commandes disponibles dans l'agent.
- `clear`: Marque les tâches comme 'cleared' afin qu'elles ne puissent pas être récupérées par les agents. Vous pouvez spécifier `all` pour effacer toutes les tâches ou `task Num` pour effacer une tâche spécifique.


## [Poseidon Agent](https://github.com/MythicAgents/poseidon)

Poseidon est un agent Golang qui se compile en exécutables **Linux et macOS**.
```bash
./mythic-cli install github https://github.com/MythicAgents/poseidon.git
```
### Notes sur la build/le profil actuel

- Les builds Poseidon actuels ciblent Linux et macOS sur `x86_64` et `arm64`.
- Les formats de sortie pris en charge incluent les exécutables natifs ainsi que des sorties de type bibliothèque partagée comme `dylib` et `so`.
- Poseidon prend en charge `http`, `websocket`, `tcp` et `dynamichttp`, et les builders actuels exposent des paramètres multi-egress comme `egress_order` et des seuils de basculement.
- Les options de build comme `proxy_bypass` et `garble` valent la peine d’être vérifiées quand vous avez besoin d’un comportement réseau plus propre ou d’une obfuscation supplémentaire du binaire Go.

Pour le tradecraft spécifique à macOS autour des opérations basées sur Mythic, de l’abus de JAMF, ou d’idées de MDM-as-C2, consultez [macOS Red Teaming](../macos-hardening/macos-red-teaming/README.md).

Lorsqu’il est utilisé sur Linux ou macOS, il a quelques commandes intéressantes :

### Actions courantes

- `cat`: Afficher le contenu d’un fichier
- `cd`: Changer le répertoire de travail actuel
- `chmod`: Modifier les permissions d’un fichier
- `config`: Afficher la config actuelle et les informations de l’hôte
- `cp`: Copier un fichier d’un emplacement à un autre
- `curl`: Exécuter une seule requête web avec des en-têtes et une méthode optionnels
- `upload`: Téléverser un fichier vers la cible
- `download`: Télécharger un fichier depuis le système cible vers la machine locale
- Et bien plus encore

### Rechercher des informations sensibles

- `triagedirectory`: Trouver des fichiers intéressants dans un répertoire sur un hôte, comme des fichiers sensibles ou des identifiants.
- `getenv`: Obtenir toutes les variables d’environnement actuelles.

### Mouvement latéral

- `ssh`: SSH vers un hôte en utilisant les identifiants désignés et ouvrir un PTY sans lancer ssh.
- `sshauth`: SSH vers le ou les hôtes spécifiés en utilisant les identifiants désignés. Vous pouvez aussi l’utiliser pour exécuter une commande spécifique sur les hôtes distants via SSH ou pour copier des fichiers via SCP.
- `link_tcp`: Se relier à un autre agent via TCP, permettant une communication directe entre agents.
- `link_webshell`: Se relier à un agent en utilisant le profil P2P webshell, permettant un accès distant à l’interface web de l’agent.
- `rpfwd`: Démarrer ou arrêter un Reverse Port Forward, permettant un accès distant aux services sur le réseau cible.
- `socks`: Démarrer ou arrêter un proxy SOCKS5 sur le réseau cible, permettant le tunneling du trafic via l’hôte compromis. Compatible avec des outils comme proxychains.
- `portscan`: Scanner le ou les hôtes à la recherche de ports ouverts, utile pour identifier des cibles potentielles pour le mouvement latéral ou d’autres attaques.

### Exécution de processus

- `shell`: Exécuter une seule commande shell via /bin/sh, permettant l’exécution directe de commandes sur le système cible.
- `run`: Exécuter une commande depuis le disque avec des arguments, permettant l’exécution de binaires ou de scripts sur le système cible.
- `pty`: Ouvrir un PTY interactif, permettant une interaction directe avec le shell sur le système cible.




## Références

- [Mythic Community Agent Feature Matrix](https://mythicmeta.github.io/overview/agent_matrix.html)
- [Apollo README](https://github.com/MythicAgents/Apollo/blob/master/README.md)
{{#include ../banners/hacktricks-training.md}}
