# Mythic

{{#include ../banners/hacktricks-training.md}}

## Qu'est-ce que Mythic ?

Mythic est un framework open source, modulaire et collaboratif de command and control (C2), conçu pour le red teaming. Il permet aux opérateurs de gérer et de déployer des agents (payloads) sur différents systèmes d'exploitation, notamment Windows, Linux et macOS. Mythic fournit une interface utilisateur dans le navigateur pour le tasking multi-opérateur, la gestion des fichiers, la gestion de SOCKS/rpfwd et la génération de payloads.

Contrairement aux frameworks monolithiques, le repository Mythic lui-même n'inclut **pas** de types de payloads ni de profils C2. Les agents, wrappers et profils C2 sont généralement installés comme composants externes et peuvent être mis à jour indépendamment du cœur de Mythic.

### Installation

Pour installer Mythic, suivez les instructions du **[Mythic repo officiel](https://github.com/its-a-feature/Mythic)**. Un bootstrap courant depuis le répertoire Mythic est le suivant :
```bash
sudo make
sudo ./mythic-cli start
```
Si Mythic est déjà en cours d'exécution, vous pouvez normalement ajouter un nouvel agent ou profile avec `./mythic-cli install github ...`, puis redémarrer Mythic ou démarrer directement le nouveau composant.

### Agents

Mythic prend en charge plusieurs agents, qui sont les **payloads effectuant des tâches sur les systèmes compromis**. Chaque agent peut être adapté à des besoins spécifiques et s'exécuter sur différents systèmes d'exploitation.

Par défaut, Mythic n'a aucun agent installé. Les agents open source de la communauté sont disponibles sur [**https://github.com/MythicAgents**](https://github.com/MythicAgents), et la [**matrice des fonctionnalités de la communauté**](https://mythicmeta.github.io/overview/agent_matrix.html) est utile pour vérifier rapidement les systèmes d'exploitation pris en charge, les formats de payload, les wrappers et les profils C2.<sup>[[1]](#references)</sup>

Pour installer un agent depuis cette organisation, vous pouvez exécuter :
```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
sudo -E ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
La forme `sudo -E` est utile lorsque vous installez depuis un environnement non-root. Vous pouvez ajouter de nouveaux agents avec la commande précédente, même si Mythic est déjà en cours d'exécution.

### C2 Profiles

Les C2 profiles dans Mythic définissent **la manière dont les agents communiquent avec le serveur Mythic**. Ils spécifient le protocole de communication, les méthodes de chiffrement et d'autres paramètres. Vous pouvez créer et gérer les C2 profiles via l'interface web de Mythic.

Par défaut, Mythic est installé sans profiles, mais il est possible de télécharger certains profiles depuis le repo [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles) en exécutant :
```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```
Profils pertinents pour les opérateurs à garder à l'esprit :

- [`http`](https://github.com/MythicC2Profiles/http) : trafic asynchrone GET/POST basique.
- [`httpx`](https://github.com/MythicC2Profiles/httpx) : trafic HTTP plus flexible avec plusieurs domaines de callback, rotation fail-over/round-robin, en-têtes/paramètres de requête personnalisés et transformations de messages (`base64`, `base64url`, `xor`, `netbios`, `prepend`, `append`) placées dans les cookies, les en-têtes, les paramètres de requête ou le corps.
- [`dynamichttp`](https://github.com/MythicC2Profiles/dynamichttp) : modelage des messages HTTP piloté par JSON/TOML lorsque le profile statique `http` est trop reconnaissable.

### Notes actuelles sur la plateforme

- De nombreux agents et profiles publics s'installent désormais avec des images de conteneurs distantes préconstruites.
Si vous forkiez un composant ou le modifiez localement et que Mythic continue d'utiliser l'ancien
comportement, inspectez les entrées `.env` générées pour `*_REMOTE_IMAGE`,
`*_USE_BUILD_CONTEXT` et `*_USE_VOLUME` ; activer
`*_USE_BUILD_CONTEXT="true"` est généralement ce qui permet à Mythic de reconstruire depuis votre
contexte Docker local au lieu de réutiliser silencieusement l'image distante.
- Les scripts de navigateur font partie des fonctionnalités les plus utiles de Mythic
pour améliorer le quotidien des opérateurs : ils peuvent transformer la sortie brute des commandes en tableaux,
visualiseurs de captures d'écran, liens de téléchargement, liens de recherche et boutons qui envoient directement
de nouvelles tâches depuis l'interface. Les builds Mythic actuels permettent à chaque opérateur de conserver
ses propres scripts, de les activer ou désactiver globalement ou par tâche, et donnent de meilleurs résultats
lorsque les agents renvoient du JSON structuré plutôt que du texte brut. Cela est particulièrement
utile pour les workflows répétitifs `ls`, `ps`, de triage et d'exploration de fichiers.<sup>[[4]](#references)[[6]](#references)</sup>
- Les builds Mythic plus récents prennent également en charge le tasking interactif et les patterns Push C2,
ce qui réduit le besoin de polling `sleep 0` pendant les opérations reposant fortement sur PTY/SOCKS/rpfwd.
Lorsqu'un agent/profile le prend en charge, cette méthode génère généralement moins de surcharge
que de marteler le serveur avec des check-ins constants uniquement pour maintenir un canal interactif utilisable.<sup>[[3]](#references)</sup>
- Les builders Mythic actuels de l'ère 3.4 sont davantage sensibles au contexte que ne le laissent entendre les anciens writeups :
les paramètres de build peuvent désormais être regroupés ou masqués selon l'OS sélectionné
ou d'autres options de build, les types de payload peuvent indiquer s'ils prennent en charge
plusieurs profiles C2 ou plusieurs instances du même C2 dans un seul build, et les déviations
de paramètres C2 permettent à un agent de masquer les champs qu'il n'implémente pas réellement.
Cela est important lorsque vous alternez entre `http`, `httpx`, `smb`,
`tcp` et `websocket`, car la surface de build sûre/valide n'est plus un formulaire statique uniforme.<sup>[[5]](#references)</sup>
- Si vous construisez une paire agent/profile personnalisée et que vous ne voulez pas du format de message JSON
de Mythic ni du chiffrement par défaut sur le wire, utilisez un
`translation_container` : Mythic retire l'UUID, transmet le blob chiffré et le matériel de clé
au translator via gRPC, puis attend en retour des octets natifs de l'agent. C'est la méthode propre
pour prendre en charge les protocoles binaires, le framing personnalisé ou le chiffrement côté agent
sans réécrire l'ensemble du serveur.
- N'oubliez pas que les callbacks liés/P2P ne se contentent pas de transférer le tasking. Le flux
`get_tasking` peut également transporter des réponses ainsi que des données `delegates`,
`socks`, `rpfwd` et `interactive`. En pratique, un callback d'egress peut gérer les callbacks internes
et les canaux de pivot dans la même boucle de polling ; si les agents enfants effectuent leurs propres
check-ins périodiques, `get_delegate_tasks=false` empêche le parent de consommer accidentellement
les jobs en attente du callback interne.

### Wrapper payloads

Les wrapper payloads permettent de conserver la même logique d'agent tout en modifiant la représentation sur disque qui est livrée ou persistée.

- `service_wrapper` : transforme un autre payload en exécutable de service Windows, ce qui est utile lorsque le chemin d'exécution exige un binaire de service valide.
- `scarecrow_wrapper` : enveloppe du shellcode compatible avec le loader ScareCrow afin de générer des sorties reposant sur un loader, telles que EXE/DLL/CPL.

## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Apollo est un agent Windows écrit en C# avec le .NET Framework 4.0, conçu pour être utilisé dans les formations de SpecterOps.<sup>[[2]](#references)</sup>

Installez-le avec :
```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
### Notes actuelles sur le build/profil

- Apollo peut actuellement générer des payloads `WinExe`, `Shellcode`, `Service` et `Source`.
- Les profils Apollo couramment utilisés sont `http`, `httpx`, `smb`, `tcp` et `websocket`.
- `httpx` est généralement l'option la plus flexible lorsque vous avez besoin de domain rotation, du support des proxy, du placement personnalisé des messages et de message transforms, contrairement à l'ancien profil statique `http`.
- Apollo est l'un des agents communautaires les plus complets et expose actuellement des intégrations côté Mythic telles que les browser scripts, les vues file/process browser, les screenshots, le keylogging, SOCKS, rpfwd, Push C2 et le routage P2P.
- Apollo prend en charge des wrapper payloads tels que `service_wrapper` et `scarecrow_wrapper`.
- Apollo prend en charge le chargement dynamique des commandes : vous pouvez donc conserver un payload initial léger et charger ultérieurement des commandes ou des modules Forge supplémentaires au lieu de compiler toutes les capacités de post-exploitation dans le premier build.
- Lors de la génération d'une sortie shellcode, le builder actuel d'Apollo expose également les choix de format Donut (`Binary`, `Base64`, `C`, `Ruby`, `Python`, `Powershell`, `C#`, `Hex`) ainsi que le comportement de bypass de Donut (`None`, `Abort on fail`, `Continue on fail`). Cela est utile si l'objectif final est de re-wrapper le shellcode avec `service_wrapper`, `scarecrow_wrapper` ou un loader personnalisé.
- `register_file` et `register_assembly` sont les primitives de staging pour `execute_assembly`, `execute_pe`, `inline_assembly`, `execute_coff`, `powershell_import` et `powerpick`. Dans les builds Apollo actuels, ces artefacts mis en staging sont mis en cache côté client sous forme de blobs AES256 protégés par DPAPI.
- Les résultats de `ls` et `ps` s'intègrent particulièrement bien aux browser scripts et au file/process browser de Mythic, ce qui accélère sensiblement le triage de l'opérateur lors des opérations collaboratives.
- Les jobs fork-and-run d'Apollo héritent des paramètres de leur processus sacrificial depuis
`spawnto_x86` / `spawnto_x64`, héritent de la sélection du parent depuis `ppid`, puis
utilisent la primitive d'injection actuellement sélectionnée. En pratique, cela signifie que
votre réglage OPSEC pour une commande affecte souvent simultanément
`execute_assembly`, `powerpick`, `mimikatz`, `pth`, `dcsync`, `execute_pe` et `spawn`.
- Les backends d'injection Apollo actuellement documentés incluent `CreateRemoteThread`,
`QueueUserAPC` (style early-bird) et `NtCreateThreadEx` via des syscalls. Utilisez
`get_injection_techniques` avant une post-exploitation bruyante et
`set_injection_technique` si vous devez abandonner une primitive qui entre en conflit avec
la cible ou avec la commande que vous souhaitez exécuter.
- `blockdlls` n'affecte que les processus sacrificial créés pour les jobs de post-exploitation.
Combiné à une cible `spawnto_x64` moins suspecte que le `rundll32.exe` nu par défaut,
il s'agit de l'une des modifications côté Apollo les plus simples à effectuer
avant d'exécuter des tâches fortement basées sur les assemblies/PowerShell.

Cet agent possède de nombreuses commandes qui le rendent très similaire au Beacon de Cobalt Strike, avec quelques fonctionnalités supplémentaires. Parmi celles-ci, il prend en charge :

### Actions courantes

- `cat` : Afficher le contenu d'un fichier
- `cd` : Modifier le répertoire de travail actuel
- `cp` : Copier un fichier d'un emplacement vers un autre
- `ls` : Lister les fichiers et répertoires du répertoire actuel ou du chemin spécifié
- `ifconfig` : Obtenir les adaptateurs et interfaces réseau
- `netstat` : Obtenir les informations sur les connexions TCP et UDP
- `pwd` : Afficher le répertoire de travail actuel
- `ps` : Lister les processus en cours d'exécution sur le système cible (avec des informations supplémentaires)
- `jobs` : Lister tous les jobs en cours associés aux tâches de longue durée
- `download` : Télécharger un fichier du système cible vers la machine locale
- `upload` : Envoyer un fichier de la machine locale vers le système cible
- `reg_query` : Interroger les clés et valeurs du registre sur le système cible
- `reg_write_value` : Écrire une nouvelle valeur dans une clé de registre spécifiée
- `sleep` : Modifier l'intervalle de sleep de l'agent, qui détermine la fréquence à laquelle il contacte le serveur Mythic
- Et bien d'autres ; utilisez `help` pour voir la liste complète des commandes disponibles.

### Élévation de privilèges

- `getprivs` : Activer autant de privilèges que possible sur le token du thread actuel
- `getsystem` : Ouvrir un handle vers winlogon et dupliquer le token, ce qui élève effectivement les privilèges au niveau SYSTEM
- `make_token` : Créer une nouvelle session de logon et l'appliquer à l'agent, ce qui permet l'impersonation d'un autre utilisateur
- `steal_token` : Voler un token primaire depuis un autre processus, ce qui permet à l'agent d'impersoner l'utilisateur de ce processus
- `pth` : Attaque Pass-the-Hash, permettant à l'agent de s'authentifier en tant qu'un utilisateur à l'aide de son hash NTLM, sans avoir besoin du mot de passe en clair
- `mimikatz` : Exécuter des commandes Mimikatz pour extraire des credentials, des hashes et d'autres informations sensibles depuis la mémoire ou la base de données SAM
- `rev2self` : Rétablir le token primaire de l'agent, ce qui supprime effectivement les privilèges et revient au niveau initial
- `ppid` : Modifier le processus parent des jobs de post-exploitation en spécifiant un nouvel ID de processus parent, ce qui permet un meilleur contrôle du contexte d'exécution du job
- `printspoofer` : Exécuter des commandes PrintSpoofer pour contourner les mesures de sécurité du print spooler, ce qui permet une élévation de privilèges ou une exécution de code
- `dcsync` : Synchroniser les clés Kerberos d'un utilisateur vers la machine locale, ce qui permet un password cracking hors ligne ou d'autres attaques
- `ticket_cache_add` : Ajouter un ticket Kerberos à la session de logon actuelle ou à une session spécifiée, ce qui permet la réutilisation d'un ticket ou l'impersonation

### Exécution de processus

- `assembly_inject` : Permet d'injecter un .NET assembly loader dans un processus distant
- `blockdlls` : Bloquer le chargement des DLL non signées par Microsoft dans les jobs de post-exploitation
- `execute_assembly` : Exécuter un .NET assembly dans le contexte de l'agent
- `execute_coff` : Exécuter un fichier COFF en mémoire, ce qui permet l'exécution en mémoire de code compilé
- `execute_pe` : Exécuter un exécutable non managé (PE)
- `keylog_inject` : Injecter un keylogger dans un autre processus et transmettre les frappes à la vue keylog de Mythic
- `screenshot` / `screenshot_inject` : Capturer directement le bureau actuel ou
en injectant un screenshot assembly dans un processus/une session cible
- `get_injection_techniques` : Afficher les techniques d'injection disponibles et celle actuellement sélectionnée
- `inline_assembly` : Exécuter un .NET assembly dans un AppDomain jetable, ce qui permet une exécution temporaire de code sans affecter le processus principal de l'agent
- `register_assembly` : Enregistrer un .NET assembly pour une exécution ultérieure
- `register_file` : Enregistrer un fichier dans le cache de l'agent pour une exécution ultérieure avec `execute_*` ou pour des tâches PowerShell
- `run` : Exécuter un binaire sur le système cible en utilisant le PATH du système pour trouver l'exécutable
- `set_injection_technique` : Modifier la primitive d'injection utilisée par les jobs de post-exploitation
- `shinject` : Injecter du shellcode dans un processus distant, ce qui permet l'exécution en mémoire de code arbitraire
- `inject` : Injecter le shellcode de l'agent dans un processus distant, ce qui permet l'exécution en mémoire du code de l'agent
- `spawn` : Créer une nouvelle session d'agent dans l'exécutable spécifié, ce qui permet l'exécution de shellcode dans un nouveau processus
- `spawnto_x64` et `spawnto_x86` : Modifier le binaire par défaut utilisé dans les jobs de post-exploitation en spécifiant un chemin, au lieu d'utiliser `rundll32.exe` sans paramètres, ce qui est très bruyant.

### Mythic Forge

Cela permet de **charger des fichiers COFF/BOF** depuis Mythic Forge, qui est un dépôt de payloads et d'outils précompilés pouvant être exécutés sur le système cible. Avec toutes les commandes pouvant être chargées, il sera possible d'effectuer des actions courantes en les exécutant dans le processus de l'agent actuel sous forme de BOFs (généralement avec un meilleur OPSEC que le lancement d'un processus séparé).

Commencez leur installation avec :
```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```
Ensuite, utilisez `forge_collections` pour afficher les modules COFF/BOF du Mythic Forge afin de pouvoir les sélectionner et les charger dans la mémoire de l’agent pour leur exécution. Par défaut, les 2 collections suivantes sont ajoutées dans Apollo :

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

Après le chargement d’un module, celui-ci apparaîtra dans la liste comme une autre commande, telle que `forge_bof_sa-whoami` ou `forge_bof_sa-netuser`.

Pour les BOFs, rappelez-vous que Forge ne transmet **pas** simplement une chaîne d’arguments plate
à Apollo. Il mappe les paramètres des BOFs au format typed-array de Mythic, puis les transmet au flux `execute_coff` d’Apollo. Si un BOF chargé depuis Forge se comporte de manière étrange, vérifiez les types d’arguments BOF attendus / l’entrypoint plutôt que de vous limiter à la ligne de commande saisie. Notez également que le nouveau BOF loader d’Apollo a modifié la gestion des arguments par rapport aux builds beaucoup plus anciens de l’ère 2.3.1 ; les BOFs obsolètes ou les anciennes collections peuvent donc échouer simplement parce que les attentes en matière de marshaling ont changé.

### Exécution de PowerShell et de scripts

- `powershell_import` : Importe un nouveau script PowerShell (.ps1) dans le cache de l’agent pour une exécution ultérieure
- `powershell` : Exécute une commande PowerShell dans le contexte de l’agent, permettant des scripts avancés et l’automatisation
- `powerpick` : Injecte un assembly PowerShell loader dans un processus sacrifiable et exécute une commande PowerShell (sans logging de PowerShell).
- `psinject` : Exécute PowerShell dans un processus spécifié, permettant l’exécution ciblée de scripts dans le contexte d’un autre processus
- `shell` : Exécute une commande shell dans le contexte de l’agent, de manière similaire à l’exécution d’une commande dans cmd.exe

### Mouvement latéral

- `jump_psexec` : Utilise la technique PsExec pour effectuer un mouvement latéral vers un nouvel hôte en copiant d’abord l’exécutable de l’agent Apollo (apollo.exe), puis en l’exécutant.
- `jump_wmi` : Utilise la technique WMI pour effectuer un mouvement latéral vers un nouvel hôte en copiant d’abord l’exécutable de l’agent Apollo (apollo.exe), puis en l’exécutant.
- `link` et `unlink` : Créent et suppriment des liens P2P (par exemple via SMB/TCP) entre les callbacks.
- `wmiexecute` : Exécute une commande sur le système local ou distant spécifié à l’aide de WMI, avec des identifiants facultatifs pour l’impersonation.
- `net_dclist` : Récupère la liste des contrôleurs de domaine pour le domaine spécifié, ce qui est utile pour identifier des cibles potentielles de mouvement latéral.
- `net_localgroup` : Répertorie les groupes locaux sur l’ordinateur spécifié ; localhost est utilisé par défaut si aucun ordinateur n’est spécifié.
- `net_localgroup_member` : Récupère les membres d’un groupe local spécifié sur l’ordinateur local ou distant, ce qui permet d’énumérer les utilisateurs appartenant à des groupes spécifiques.
- `net_shares` : Répertorie les partages distants et leur accessibilité sur l’ordinateur spécifié, ce qui est utile pour identifier des cibles potentielles de mouvement latéral.
- `socks` : Active un proxy compatible SOCKS 5 sur le réseau cible, permettant de tunneler le trafic via l’hôte compromis. Compatible avec des outils tels que proxychains.
- `rpfwd` : Commence à écouter sur un port spécifié de l’hôte cible et transfère le trafic via Mythic vers une IP et un port distants, permettant l’accès distant aux services du réseau cible.
- `listpipes` : Répertorie tous les named pipes du système local, ce qui peut être utile pour le mouvement latéral ou l’élévation de privilèges en interagissant avec les mécanismes IPC.

Pour les primitives d’exécution WMI de plus bas niveau utilisées par `jump_wmi` ou `wmiexecute`, consultez [WmiExec](lateral-movement/wmiexec.md). Pour des modèles de pivoting plus larges, consultez [Tunneling and Port Forwarding](../generic-hacking/tunneling-and-port-forwarding.md).

### Commandes diverses
- `help` : Affiche des informations détaillées sur des commandes spécifiques ou des informations générales sur toutes les commandes disponibles dans l’agent.
- `clear` : Marque les tâches comme « cleared » afin qu’elles ne puissent pas être récupérées par les agents. Vous pouvez spécifier `all` pour effacer toutes les tâches ou `task Num` pour effacer une tâche spécifique.


## [Poseidon Agent](https://github.com/MythicAgents/poseidon)

Poseidon est un agent Golang qui se compile en exécutables **Linux et macOS**.
```bash
./mythic-cli install github https://github.com/MythicAgents/poseidon.git
```
### Notes actuelles sur les builds/profils

- Les builds Poseidon actuels ciblent Linux et macOS sur `x86_64` et `arm64`.
- Les formats de sortie pris en charge incluent les exécutables natifs ainsi que des formats de type bibliothèque partagée comme `dylib` et `so`.
- Poseidon prend en charge `http`, `websocket`, `tcp` et `dynamichttp`, et les builders actuels exposent des paramètres de multi-egress tels que `egress_order` et les seuils de failover.
- Les métadonnées actuelles des capacités de Poseidon annoncent également les browser scripts, l'intégration du file/process browser, l'interactive tasking, le keylogging, les screenshots, Push C2, SOCKS, rpfwd et P2P. Il peut donc fonctionner comme un véritable nœud pivot Linux/macOS, plutôt que comme un simple remote shell.
- Les options au moment du build, telles que `proxy_bypass` et `garble`, méritent d'être vérifiées lorsque vous avez besoin soit d'un comportement réseau plus propre, soit d'une obfuscation supplémentaire des binaires Go.
- `pty` est l'une des commandes récentes les plus utiles pour améliorer la qualité de vie lors des opérations Linux/macOS, car elle ouvre un PTY interactif et peut exposer un port côté Mythic pour une interaction terminal plus complète, sans recourir à l'ancienne méthode `sleep 0` + SOCKS.
- La documentation actuelle de Poseidon est particulièrement intéressante pour le tradecraft axé sur macOS : `jxa` exécute du JavaScript for Automation en mémoire, `screencapture` capture le bureau de l'utilisateur connecté, `clipboard_monitor` transmet les modifications du pasteboard, `execute_library` charge une dylib locale et appelle une fonction, et `libinject` force un processus distant à charger une dylib présente sur le disque.
- Pour les tâches de longue durée, rappelez-vous que Poseidon exécute le post-exploitation dans des goroutines/threads coopératifs qui ne peuvent pas être interrompus brutalement. La documentation précise également qu'il n'existe actuellement aucune obfuscation intégrée de l'agent ; le tradecraft au niveau du build/profil est donc plus important qu'avec des implants commerciaux fortement obfusqués.

Pour le tradecraft spécifique à macOS autour des opérations basées sur Mythic, de l'abus de JAMF ou des idées de MDM-as-C2, consultez [macOS Red Teaming](../macos-hardening/macos-red-teaming/README.md).

Lorsqu'il est utilisé sous Linux ou macOS, il propose des commandes intéressantes :

### Actions courantes

- `cat` : Afficher le contenu d'un fichier
- `cd` : Modifier le répertoire de travail courant
- `chmod` : Modifier les permissions d'un fichier
- `config` : Afficher la configuration actuelle et les informations sur l'hôte
- `cp` : Copier un fichier d'un emplacement à un autre
- `curl` : Exécuter une seule requête web avec des en-têtes et une méthode facultatifs
- `upload` : Envoyer un fichier vers la cible
- `download` : Télécharger un fichier du système cible vers la machine locale
- Et bien plus encore

### Rechercher des informations sensibles

- `triagedirectory` : Rechercher des fichiers intéressants dans un répertoire sur un hôte, tels que des fichiers sensibles ou des credentials.
- `getenv` : Récupérer toutes les variables d'environnement actuelles.

### Tradecraft spécifique à macOS

- `jxa` : Exécuter du JavaScript for Automation en mémoire via `OSAScript`, ce qui est utile pour le post-exploitation natif de macOS sans déposer de fichiers de script séparés.
- `clipboard_monitor` : Interroger le pasteboard et signaler les modifications à Mythic, ce qui est pratique pour les workflows de vol de credentials/tokens reposant sur le copier-coller.
- `screencapture` : Capturer le bureau de l'utilisateur sous macOS.
- `execute_library` : Charger une dylib depuis le disque et appeler une fonction exportée spécifique.
- `libinject` : Injecter un stub de shellcode qui force un autre processus macOS à charger une dylib depuis le disque.
- `persist_launchd` : Créer directement une persistance LaunchAgent / LaunchDaemon depuis l'agent.

### Déplacement latéral

- `ssh` : Se connecter en SSH à un hôte avec les credentials désignés et ouvrir un PTY sans lancer ssh.
- `sshauth` : Se connecter en SSH au(x) hôte(s) spécifié(s) avec les credentials désignés. Vous pouvez également l'utiliser pour exécuter une commande spécifique sur les hôtes distants via SSH ou pour copier des fichiers avec SCP.
- `link_tcp` : Relier un autre agent via TCP, ce qui permet une communication directe entre les agents.
- `link_webshell` : Relier un agent à l'aide du profil P2P webshell, ce qui permet un accès distant à l'interface web de l'agent.
- `rpfwd` : Démarrer ou arrêter un Reverse Port Forward, permettant un accès distant aux services présents sur le réseau cible.
- `socks` : Démarrer ou arrêter un proxy SOCKS5 sur le réseau cible, permettant de tunneler le trafic via l'hôte compromis. Compatible avec des outils tels que proxychains.
- `portscan` : Scanner le ou les hôtes à la recherche de ports ouverts, ce qui est utile pour identifier des cibles potentielles de déplacement latéral ou d'autres attaques.

### Exécution de processus

- `shell` : Exécuter une seule commande shell via /bin/sh, permettant l'exécution directe de commandes sur le système cible.
- `run` : Exécuter une commande depuis le disque avec des arguments, permettant l'exécution de binaires ou de scripts sur le système cible.
- `pty` : Ouvrir un PTY interactif, permettant une interaction directe avec le shell du système cible.

## Références

- [1] [Mythic Community Agent Feature Matrix](https://mythicmeta.github.io/overview/agent_matrix.html)
- [2] [Apollo README](https://github.com/MythicAgents/Apollo/blob/master/README.md)
- [3] [Mythic v3.2 Highlights: Interactive Tasking, Push C2, and Dynamic File Browser](https://posts.specterops.io/mythic-v3-2-highlights-interactive-tasking-push-c2-and-dynamic-file-browser-7035065e2b3d)
- [4] [Browser Scripts - Mythic Documentation](https://docs.mythic-c2.net/operational-pieces/browser-scripts)
- [5] [Mythic 3.3->3.4 Updates](https://docs.mythic-c2.net/updating/mythic-3.3-greater-than-3.4-updates)
- [6] [Transforming Red Team Ops with Mythic's Hidden Gems: Browser Scripting](https://specterops.io/blog/2025/08/21/transforming-red-team-ops-with-mythics-hidden-gems-browser-scripting/)

{{#include ../banners/hacktricks-training.md}}
