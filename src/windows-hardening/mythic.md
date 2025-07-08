# Mythic

{{#include ../banners/hacktricks-training.md}}

## Qu'est-ce que Mythic ?

Mythic est un framework de commande et de contrôle (C2) modulaire et open-source conçu pour le red teaming. Il permet aux professionnels de la sécurité de gérer et de déployer divers agents (payloads) sur différents systèmes d'exploitation, y compris Windows, Linux et macOS. Mythic fournit une interface web conviviale pour gérer les agents, exécuter des commandes et collecter des résultats, ce qui en fait un outil puissant pour simuler des attaques du monde réel dans un environnement contrôlé.

### Installation

Pour installer Mythic, suivez les instructions sur le **[repo Mythic](https://github.com/its-a-feature/Mythic)** officiel.

### Agents

Mythic prend en charge plusieurs agents, qui sont les **payloads qui effectuent des tâches sur les systèmes compromis**. Chaque agent peut être adapté à des besoins spécifiques et peut fonctionner sur différents systèmes d'exploitation.

Par défaut, Mythic n'a aucun agent installé. Cependant, il propose quelques agents open source sur [**https://github.com/MythicAgents**](https://github.com/MythicAgents).

Pour installer un agent depuis ce repo, vous devez simplement exécuter :
```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/apfell
```
Vous pouvez ajouter de nouveaux agents avec la commande précédente même si Mythic est déjà en cours d'exécution.

### Profils C2

Les profils C2 dans Mythic définissent **comment les agents communiquent avec le serveur Mythic**. Ils spécifient le protocole de communication, les méthodes de cryptage et d'autres paramètres. Vous pouvez créer et gérer des profils C2 via l'interface web de Mythic.

Par défaut, Mythic est installé sans profils, cependant, il est possible de télécharger certains profils depuis le dépôt [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles) en exécutant :
```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```
## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Apollo est un agent Windows écrit en C# utilisant le .NET Framework 4.0, conçu pour être utilisé dans les formations de SpecterOps.

Installez-le avec :
```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
Cet agent a beaucoup de commandes qui le rendent très similaire à Beacon de Cobalt Strike avec quelques extras. Parmi elles, il prend en charge :

### Actions courantes

- `cat`: Afficher le contenu d'un fichier
- `cd`: Changer le répertoire de travail actuel
- `cp`: Copier un fichier d'un emplacement à un autre
- `ls`: Lister les fichiers et répertoires dans le répertoire actuel ou le chemin spécifié
- `pwd`: Afficher le répertoire de travail actuel
- `ps`: Lister les processus en cours d'exécution sur le système cible (avec des informations supplémentaires)
- `download`: Télécharger un fichier du système cible vers la machine locale
- `upload`: Télécharger un fichier de la machine locale vers le système cible
- `reg_query`: Interroger les clés et valeurs du registre sur le système cible
- `reg_write_value`: Écrire une nouvelle valeur dans une clé de registre spécifiée
- `sleep`: Changer l'intervalle de sommeil de l'agent, qui détermine la fréquence à laquelle il se connecte au serveur Mythic
- Et bien d'autres, utilisez `help` pour voir la liste complète des commandes disponibles.

### Élévation de privilèges

- `getprivs`: Activer autant de privilèges que possible sur le jeton de thread actuel
- `getsystem`: Ouvrir un handle à winlogon et dupliquer le jeton, élevant ainsi les privilèges au niveau SYSTEM
- `make_token`: Créer une nouvelle session de connexion et l'appliquer à l'agent, permettant l'imitation d'un autre utilisateur
- `steal_token`: Voler un jeton principal d'un autre processus, permettant à l'agent d'imiter l'utilisateur de ce processus
- `pth`: Attaque Pass-the-Hash, permettant à l'agent de s'authentifier en tant qu'utilisateur en utilisant leur hachage NTLM sans avoir besoin du mot de passe en clair
- `mimikatz`: Exécuter des commandes Mimikatz pour extraire des identifiants, des hachages et d'autres informations sensibles de la mémoire ou de la base de données SAM
- `rev2self`: Revenir au jeton principal de l'agent, réduisant ainsi les privilèges au niveau d'origine
- `ppid`: Changer le processus parent pour les travaux de post-exploitation en spécifiant un nouvel ID de processus parent, permettant un meilleur contrôle sur le contexte d'exécution des travaux
- `printspoofer`: Exécuter des commandes PrintSpoofer pour contourner les mesures de sécurité du spouleur d'impression, permettant l'élévation de privilèges ou l'exécution de code
- `dcsync`: Synchroniser les clés Kerberos d'un utilisateur avec la machine locale, permettant le craquage de mots de passe hors ligne ou d'autres attaques
- `ticket_cache_add`: Ajouter un ticket Kerberos à la session de connexion actuelle ou à une spécifiée, permettant la réutilisation de tickets ou l'imitation

### Exécution de processus

- `assembly_inject`: Permet d'injecter un chargeur d'assemblage .NET dans un processus distant
- `execute_assembly`: Exécute un assemblage .NET dans le contexte de l'agent
- `execute_coff`: Exécute un fichier COFF en mémoire, permettant l'exécution en mémoire de code compilé
- `execute_pe`: Exécute un exécutable non géré (PE)
- `inline_assembly`: Exécute un assemblage .NET dans un AppDomain jetable, permettant l'exécution temporaire de code sans affecter le processus principal de l'agent
- `run`: Exécute un binaire sur le système cible, en utilisant le PATH du système pour trouver l'exécutable
- `shinject`: Injecte du shellcode dans un processus distant, permettant l'exécution en mémoire de code arbitraire
- `inject`: Injecte le shellcode de l'agent dans un processus distant, permettant l'exécution en mémoire du code de l'agent
- `spawn`: Lance une nouvelle session d'agent dans l'exécutable spécifié, permettant l'exécution de shellcode dans un nouveau processus
- `spawnto_x64` et `spawnto_x86`: Changer le binaire par défaut utilisé dans les travaux de post-exploitation vers un chemin spécifié au lieu d'utiliser `rundll32.exe` sans paramètres, ce qui est très bruyant.

### Mithic Forge

Cela permet de **charger des fichiers COFF/BOF** depuis le Mythic Forge, qui est un dépôt de charges utiles et d'outils précompilés pouvant être exécutés sur le système cible. Avec toutes les commandes qui peuvent être chargées, il sera possible d'effectuer des actions courantes en les exécutant dans le processus actuel de l'agent en tant que BOFs (plus furtif généralement).

Commencez à les installer avec :
```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```
Ensuite, utilisez `forge_collections` pour afficher les modules COFF/BOF du Mythic Forge afin de pouvoir les sélectionner et les charger dans la mémoire de l'agent pour exécution. Par défaut, les 2 collections suivantes sont ajoutées dans Apollo :

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

Après qu'un module soit chargé, il apparaîtra dans la liste comme une autre commande telle que `forge_bof_sa-whoami` ou `forge_bof_sa-netuser`.

### Exécution de Powershell & scripting

- `powershell_import`: Importe un nouveau script PowerShell (.ps1) dans le cache de l'agent pour une exécution ultérieure
- `powershell`: Exécute une commande PowerShell dans le contexte de l'agent, permettant un scripting et une automatisation avancés
- `powerpick`: Injecte un assembly de loader PowerShell dans un processus sacrificiel et exécute une commande PowerShell (sans journalisation de PowerShell).
- `psinject`: Exécute PowerShell dans un processus spécifié, permettant une exécution ciblée de scripts dans le contexte d'un autre processus
- `shell`: Exécute une commande shell dans le contexte de l'agent, similaire à l'exécution d'une commande dans cmd.exe

### Mouvement latéral

- `jump_psexec`: Utilise la technique PsExec pour se déplacer latéralement vers un nouvel hôte en copiant d'abord l'exécutable de l'agent Apollo (apollo.exe) et en l'exécutant.
- `jump_wmi`: Utilise la technique WMI pour se déplacer latéralement vers un nouvel hôte en copiant d'abord l'exécutable de l'agent Apollo (apollo.exe) et en l'exécutant.
- `wmiexecute`: Exécute une commande sur le système local ou spécifié à distance en utilisant WMI, avec des identifiants optionnels pour l'usurpation d'identité.
- `net_dclist`: Récupère une liste de contrôleurs de domaine pour le domaine spécifié, utile pour identifier des cibles potentielles pour le mouvement latéral.
- `net_localgroup`: Liste les groupes locaux sur l'ordinateur spécifié, par défaut sur localhost si aucun ordinateur n'est spécifié.
- `net_localgroup_member`: Récupère l'appartenance à un groupe local pour un groupe spécifié sur l'ordinateur local ou distant, permettant l'énumération des utilisateurs dans des groupes spécifiques.
- `net_shares`: Liste les partages distants et leur accessibilité sur l'ordinateur spécifié, utile pour identifier des cibles potentielles pour le mouvement latéral.
- `socks`: Active un proxy conforme SOCKS 5 sur le réseau cible, permettant le tunneling du trafic à travers l'hôte compromis. Compatible avec des outils comme proxychains.
- `rpfwd`: Commence à écouter sur un port spécifié sur l'hôte cible et redirige le trafic à travers Mythic vers une IP et un port distants, permettant un accès à distance aux services sur le réseau cible.
- `listpipes`: Liste tous les pipes nommés sur le système local, ce qui peut être utile pour le mouvement latéral ou l'escalade de privilèges en interagissant avec des mécanismes IPC.

### Commandes diverses
- `help`: Affiche des informations détaillées sur des commandes spécifiques ou des informations générales sur toutes les commandes disponibles dans l'agent.
- `clear`: Marque les tâches comme 'effacées' afin qu'elles ne puissent pas être prises en charge par les agents. Vous pouvez spécifier `all` pour effacer toutes les tâches ou `task Num` pour effacer une tâche spécifique.


## [Poseidon Agent](https://github.com/MythicAgents/Poseidon)

Poseidon est un agent Golang qui se compile en exécutables **Linux et macOS**.
```bash
./mythic-cli install github https://github.com/MythicAgents/Poseidon.git
```
Lorsque l'utilisateur est sur Linux, il dispose de certaines commandes intéressantes :

### Actions courantes

- `cat`: Afficher le contenu d'un fichier
- `cd`: Changer le répertoire de travail actuel
- `chmod`: Changer les permissions d'un fichier
- `config`: Voir la configuration actuelle et les informations sur l'hôte
- `cp`: Copier un fichier d'un emplacement à un autre
- `curl`: Exécuter une seule requête web avec des en-têtes et une méthode optionnels
- `upload`: Télécharger un fichier vers la cible
- `download`: Télécharger un fichier depuis le système cible vers la machine locale
- Et bien d'autres

### Rechercher des informations sensibles

- `triagedirectory`: Trouver des fichiers intéressants dans un répertoire sur un hôte, tels que des fichiers sensibles ou des identifiants.
- `getenv`: Obtenir toutes les variables d'environnement actuelles.

### Se déplacer latéralement

- `ssh`: SSH vers l'hôte en utilisant les identifiants désignés et ouvrir un PTY sans lancer ssh.
- `sshauth`: SSH vers l'hôte(s) spécifié(s) en utilisant les identifiants désignés. Vous pouvez également l'utiliser pour exécuter une commande spécifique sur les hôtes distants via SSH ou l'utiliser pour SCP des fichiers.
- `link_tcp`: Lier à un autre agent via TCP, permettant une communication directe entre les agents.
- `link_webshell`: Lier à un agent en utilisant le profil P2P webshell, permettant un accès à distance à l'interface web de l'agent.
- `rpfwd`: Démarrer ou arrêter un transfert de port inversé, permettant un accès à distance aux services sur le réseau cible.
- `socks`: Démarrer ou arrêter un proxy SOCKS5 sur le réseau cible, permettant le tunnelage du trafic à travers l'hôte compromis. Compatible avec des outils comme proxychains.
- `portscan`: Scanner l'hôte(s) pour des ports ouverts, utile pour identifier des cibles potentielles pour un mouvement latéral ou d'autres attaques.

### Exécution de processus

- `shell`: Exécuter une seule commande shell via /bin/sh, permettant l'exécution directe de commandes sur le système cible.
- `run`: Exécuter une commande depuis le disque avec des arguments, permettant l'exécution de binaires ou de scripts sur le système cible.
- `pty`: Ouvrir un PTY interactif, permettant une interaction directe avec le shell sur le système cible.


{{#include ../banners/hacktricks-training.md}}
