# Mythic

{{#include ../banners/hacktricks-training.md}}

## Qu'est-ce que Mythic ?

Mythic est un framework open-source, modulaire et collaboratif de command and control (C2), conçu pour le red teaming. Il permet aux opérateurs de gérer et de déployer des agents (payloads) sur différents systèmes d'exploitation, notamment Windows, Linux et macOS. Mythic fournit une interface web pour le tasking multi-opérateur, la gestion de fichiers, la gestion de SOCKS/rpfwd, et la génération de payloads.

Contrairement aux frameworks monolithiques, le dépôt Mythic lui-même ne fournit **pas** de types de payloads ni de profils C2. Les agents, wrappers et profils C2 sont généralement installés comme composants externes et peuvent être mis à jour indépendamment du noyau de Mythic.

### Installation

Pour installer Mythic, suivez les instructions sur le **[Mythic repo](https://github.com/its-a-feature/Mythic)** officiel. Un bootstrap courant depuis le répertoire Mythic est :
```bash
sudo make
sudo ./mythic-cli start
```
Si Mythic est déjà en cours d’exécution, vous pouvez normalement ajouter un nouvel agent ou profile avec `./mythic-cli install github ...` puis soit redémarrer Mythic, soit simplement démarrer directement le nouveau composant.

### Agents

Mythic prend en charge plusieurs agents, qui sont les **payloads qui exécutent des tâches sur les systèmes compromis**. Chaque agent peut être adapté à des besoins spécifiques et peut s’exécuter sur différents systèmes d’exploitation.

Par défaut, Mythic n’a aucun agent installé. Les agents open-source de la communauté se trouvent dans [**https://github.com/MythicAgents**](https://github.com/MythicAgents), et la [**community feature matrix**](https://mythicmeta.github.io/overview/agent_matrix.html) est utile pour vérifier rapidement les systèmes d’exploitation pris en charge, les formats de payload, les wrappers et les profils C2.

Pour installer un agent depuis cette organisation, vous pouvez exécuter :
```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
sudo -E ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
La forme `sudo -E` est utile lorsque vous installez depuis un environnement non-root. Vous pouvez ajouter de nouveaux agents avec la commande précédente même si Mythic est déjà en cours d'exécution.

### C2 Profiles

Les C2 profiles dans Mythic définissent **comment les agents communiquent avec le serveur Mythic**. Ils spécifient le protocole de communication, les méthodes de chiffrement et d’autres paramètres. Vous pouvez créer et gérer des C2 profiles via l’interface web Mythic.

Par défaut, Mythic est installé sans aucun profile, cependant, il est possible de télécharger certains profiles depuis le repo [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles) en exécutant :
```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```
Current operator-relevant profiles to keep in mind:

- [`http`](https://github.com/MythicC2Profiles/http): trafic GET/POST asynchrone de base.
- [`httpx`](https://github.com/MythicC2Profiles/httpx): trafic HTTP plus flexible avec plusieurs domaines de callback, rotation fail-over/round-robin, en-têtes personnalisés/paramètres de requête, et transformations de message (`base64`, `base64url`, `xor`, `netbios`, `prepend`, `append`) placées dans des cookies, des en-têtes, des paramètres de requête ou le body.
- [`dynamichttp`](https://github.com/MythicC2Profiles/dynamichttp): shaping HTTP piloté par JSON/TOML quand le profil `http` statique est trop reconnaissable.

### Current platform notes

- Many public agents and profiles now install with pre-built remote container images.
If you fork a component or patch it locally and Mythic keeps using the old
behavior, inspect the generated `.env` entries for `*_REMOTE_IMAGE`,
`*_USE_BUILD_CONTEXT`, and `*_USE_VOLUME`; enabling
`*_USE_BUILD_CONTEXT="true"` is usually what makes Mythic rebuild from your
local Docker context instead of silently reusing the remote image.
- Browser scripts are one of Mythic's highest-value quality-of-life features
for operators: they can turn raw command output into tables, screenshot
viewers, download links, and buttons that issue follow-on tasking directly
from the UI. This is especially useful for repetitive `ls`, `ps`, triage,
and file-browser workflows.
- Newer Mythic builds also support interactive tasking and Push C2 patterns
that reduce the need for `sleep 0` polling during PTY/SOCKS/rpfwd-heavy
operations. When an agent/profile supports it, this is usually lower-overhead
than hammering the server with constant check-ins just to keep an interactive
channel usable.

### Wrapper payloads

Wrapper payloads let you keep the same agent logic while changing the on-disk representation that gets delivered or persisted.

- `service_wrapper`: turns another payload into a Windows service executable, which is useful when the execution path requires a valid service binary.
- `scarecrow_wrapper`: wraps compatible shellcode with the ScareCrow loader to generate loader-backed outputs such as EXE/DLL/CPL.

## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Apollo is a Windows agent written in C# using the 4.0 .NET Framework designed to be used in SpecterOps training offerings.

Install it with:
```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
### Notes actuelles de build/profile

- Apollo peut actuellement émettre des payloads `WinExe`, `Shellcode`, `Service`, et `Source`.
- Les profils Apollo couramment utilisés sont `http`, `httpx`, `smb`, `tcp`, et `websocket`.
- `httpx` est généralement l’option la plus flexible quand vous avez besoin de rotation de domaine, du support des proxy, d’un placement personnalisé des messages, et de transforms de messages, plutôt que l’ancien profil statique `http`.
- Apollo prend en charge des wrapper payloads tels que `service_wrapper` et `scarecrow_wrapper`.
- `register_file` et `register_assembly` sont les primitives de staging pour `execute_assembly`, `execute_pe`, `inline_assembly`, `execute_coff`, `powershell_import`, et `powerpick`. Dans les builds Apollo actuels, ces artefacts staged sont mis en cache côté client sous forme de blobs AES256 protégés par DPAPI.
- Les résultats de `ls` et `ps` s’intègrent particulièrement bien avec les scripts navigateur et le browser fichiers/processus de Mythic, ce qui rend le triage opérateur nettement plus rapide dans les opérations collaboratives.
- Les jobs fork-and-run d’Apollo héritent de leurs paramètres de processus sacrificiel depuis `spawnto_x86` / `spawnto_x64`, héritent de la sélection du parent depuis `ppid`, puis utilisent la primitive d’injection actuellement sélectionnée. En pratique, cela signifie que votre tuning OPSEC pour une commande affecte souvent en même temps `execute_assembly`, `powerpick`, `mimikatz`, `pth`, `dcsync`, `execute_pe`, et `spawn`.
- Les backends d’injection Apollo documentés actuellement incluent `CreateRemoteThread`, `QueueUserAPC` (style early-bird), et `NtCreateThreadEx` via syscalls. Utilisez `get_injection_techniques` avant un post-exploitation bruyant et `set_injection_technique` si vous devez basculer depuis une primitive qui entre en conflit avec la cible ou avec la commande que vous voulez exécuter.
- `blockdlls` n’affecte que les processus sacrificiels créés pour les jobs de post-exploitation. Combiné à une cible `spawnto_x64` moins suspecte que le `rundll32.exe` nu par défaut, c’est l’un des changements les plus simples à faire côté Apollo avant d’exécuter des tâches lourdes en assembly/PowerShell.

Cet agent a beaucoup de commandes, ce qui le rend très similaire à Beacon de Cobalt Strike avec quelques extras. Parmi elles, il prend en charge :

### Actions courantes

- `cat`: Afficher le contenu d’un fichier
- `cd`: Changer le répertoire de travail actuel
- `cp`: Copier un fichier d’un emplacement à un autre
- `ls`: Lister les fichiers et répertoires dans le répertoire courant ou le chemin spécifié
- `ifconfig`: Obtenir les adaptateurs réseau et les interfaces
- `netstat`: Obtenir les informations de connexion TCP et UDP
- `pwd`: Afficher le répertoire de travail actuel
- `ps`: Lister les processus en cours d’exécution sur le système cible (avec des infos supplémentaires)
- `jobs`: Lister tous les jobs en cours associés au tasking de longue durée
- `download`: Télécharger un fichier du système cible vers la machine locale
- `upload`: Envoyer un fichier de la machine locale vers le système cible
- `reg_query`: Interroger les clés et valeurs du registre sur le système cible
- `reg_write_value`: Écrire une nouvelle valeur dans une clé de registre spécifiée
- `sleep`: Modifier l’intervalle de sommeil de l’agent, ce qui détermine à quelle fréquence il contacte le serveur Mythic
- Et bien d’autres, utilisez `help` pour voir la liste complète des commandes disponibles.

### Élévation de privilèges

- `getprivs`: Activer autant de privilèges que possible sur le token du thread courant
- `getsystem`: Ouvrir un handle vers winlogon et dupliquer le token, en élevant efficacement les privilèges au niveau SYSTEM
- `make_token`: Créer une nouvelle session de logon et l’appliquer à l’agent, ce qui permet l’usurpation d’un autre utilisateur
- `steal_token`: Voler un token primaire à partir d’un autre processus, ce qui permet à l’agent d’usurper l’utilisateur de ce processus
- `pth`: Attaque Pass-the-Hash, permettant à l’agent de s’authentifier en tant qu’utilisateur en utilisant son hash NTLM sans avoir besoin du mot de passe en clair
- `mimikatz`: Exécuter des commandes Mimikatz pour extraire des identifiants, des hashes et d’autres informations sensibles depuis la mémoire ou la base SAM
- `rev2self`: Rétablir le token de l’agent à son token primaire, en revenant effectivement au niveau de privilège d’origine
- `ppid`: Modifier le processus parent pour les jobs de post-exploitation en spécifiant un nouvel identifiant de processus parent, ce qui permet un meilleur contrôle du contexte d’exécution du job
- `printspoofer`: Exécuter des commandes PrintSpoofer pour contourner les mesures de sécurité du spooler d’impression, ce qui permet une élévation de privilèges ou l’exécution de code
- `dcsync`: Synchroniser les clés Kerberos d’un utilisateur vers la machine locale, ce qui permet un craquage hors ligne du mot de passe ou d’autres attaques
- `ticket_cache_add`: Ajouter un ticket Kerberos à la session de logon courante ou à une session spécifiée, ce qui permet la réutilisation de tickets ou l’usurpation

### Exécution de processus

- `assembly_inject`: Permet d’injecter un chargeur d’assembly .NET dans un processus distant
- `blockdlls`: Bloquer le chargement des DLL non signées par Microsoft dans les jobs de post-exploitation
- `execute_assembly`: Exécute un assembly .NET dans le contexte de l’agent
- `execute_coff`: Exécute un fichier COFF en mémoire, ce qui permet l’exécution en mémoire de code compilé
- `execute_pe`: Exécute un exécutable unmanaged (PE)
- `keylog_inject`: Injecte un keylogger dans un autre processus et transmet les frappes vers la vue keylog de Mythic
- `screenshot` / `screenshot_inject`: Capturer le bureau actuel directement ou en injectant un assembly de capture d’écran dans un processus/session cible
- `get_injection_techniques`: Afficher les techniques d’injection disponibles et celle actuellement sélectionnée
- `inline_assembly`: Exécute un assembly .NET dans un AppDomain jetable, ce qui permet une exécution temporaire du code sans affecter le processus principal de l’agent
- `register_assembly`: Enregistrer un assembly .NET pour une exécution ultérieure
- `register_file`: Enregistrer un fichier dans le cache de l’agent pour un futur tasking `execute_*` ou PowerShell
- `run`: Exécute un binaire sur le système cible, en utilisant le PATH du système pour trouver l’exécutable
- `set_injection_technique`: Modifier la primitive d’injection utilisée par les jobs de post-exploitation
- `shinject`: Injecte du shellcode dans un processus distant, ce qui permet l’exécution en mémoire de code arbitraire
- `inject`: Injecte le shellcode de l’agent dans un processus distant, ce qui permet l’exécution en mémoire du code de l’agent
- `spawn`: Lance une nouvelle session agent dans l’exécutable spécifié, ce qui permet l’exécution du shellcode dans un nouveau processus
- `spawnto_x64` et `spawnto_x86`: Modifier le binaire par défaut utilisé dans les jobs de post-exploitation vers un chemin spécifié au lieu d’utiliser `rundll32.exe` sans paramètres, ce qui est très bruyant.

### Mythic Forge

Cela permet de **charger des fichiers COFF/BOF** depuis Mythic Forge, qui est un dépôt de payloads et d’outils précompilés pouvant être exécutés sur le système cible. Avec toutes les commandes qui peuvent être chargées, il sera possible d’effectuer des actions courantes en les exécutant dans le processus actuel de l’agent sous forme de BOFs (généralement avec une meilleure OPSEC que de lancer un processus séparé).

Commencez à les installer avec :
```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```
Alors, utilisez `forge_collections` pour afficher les modules COFF/BOF du Mythic Forge afin de pouvoir les sélectionner et les charger dans la mémoire de l’agent pour exécution. Par défaut, les 2 collections suivantes sont ajoutées dans Apollo :

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

Une fois qu’un module est chargé, il apparaîtra dans la liste comme une autre commande, par exemple `forge_bof_sa-whoami` ou `forge_bof_sa-netuser`.

Pour les BOFs, rappelez-vous que Forge ne transmet **pas** simplement une chaîne d’arguments plate à Apollo. Il mappe les paramètres BOF vers le format tableau typé de Mythic, puis les transmet dans le flux `execute_coff` d’Apollo. Si un BOF chargé depuis Forge se comporte de façon étrange, vérifiez les types d’arguments BOF attendus / le point d’entrée plutôt que seulement la ligne de commande que vous avez tapée.

### Exécution PowerShell & scripting

- `powershell_import`: Importe un nouveau script PowerShell (.ps1) dans le cache de l’agent pour une exécution ultérieure
- `powershell`: Exécute une commande PowerShell dans le contexte de l’agent, permettant du scripting avancé et de l’automatisation
- `powerpick`: Injecte une assembly chargeuse PowerShell dans un processus sacrificiel et exécute une commande PowerShell (sans journalisation PowerShell).
- `psinject`: Exécute PowerShell dans un processus spécifié, permettant une exécution ciblée de scripts dans le contexte d’un autre processus
- `shell`: Exécute une commande shell dans le contexte de l’agent, similaire à l’exécution d’une commande dans cmd.exe

### Mouvement latéral

- `jump_psexec`: Utilise la technique PsExec pour se déplacer latéralement vers un nouvel hôte en copiant d’abord l’exécutable de l’agent Apollo (apollo.exe) puis en l’exécutant.
- `jump_wmi`: Utilise la technique WMI pour se déplacer latéralement vers un nouvel hôte en copiant d’abord l’exécutable de l’agent Apollo (apollo.exe) puis en l’exécutant.
- `link` et `unlink`: Créent et suppriment des liens P2P (par exemple via SMB/TCP) entre callbacks.
- `wmiexecute`: Exécute une commande sur le système local ou distant spécifié en utilisant WMI, avec des identifiants facultatifs pour l’impersonation.
- `net_dclist`: Récupère une liste de contrôleurs de domaine pour le domaine spécifié, utile pour identifier des cibles potentielles de mouvement latéral.
- `net_localgroup`: Liste les groupes locaux sur l’ordinateur spécifié, en utilisant localhost par défaut si aucun ordinateur n’est indiqué.
- `net_localgroup_member`: Récupère l’appartenance à un groupe local pour un groupe spécifié sur l’ordinateur local ou distant, permettant l’énumération des utilisateurs dans des groupes spécifiques.
- `net_shares`: Liste les partages distants et leur accessibilité sur l’ordinateur spécifié, utile pour identifier des cibles potentielles de mouvement latéral.
- `socks`: সক?```
```bash
./mythic-cli install github https://github.com/MythicAgents/poseidon.git
```
### Notes actuelles de build/profile

- Les builds Poseidon actuels ciblent Linux et macOS sur `x86_64` et `arm64`.
- Les formats de sortie pris en charge incluent les exécutables natifs ainsi que des sorties de type shared-library comme `dylib` et `so`.
- Poseidon prend en charge `http`, `websocket`, `tcp`, et `dynamichttp`, et les builders actuels exposent des paramètres multi-egress tels que `egress_order` et des seuils de failover.
- Les options de build comme `proxy_bypass` et `garble` valent la peine d’être vérifiées quand vous avez besoin d’un comportement réseau plus propre ou d’une obfuscation supplémentaire du binaire Go.
- `pty` est l’une des commandes récentes les plus utiles pour les opérations Linux/macOS
car elle ouvre un PTY interactif et peut exposer un port côté Mythic pour une interaction terminal plus complète sans recourir à l’ancien contournement `sleep 0`
+ SOCKS.
- La documentation actuelle de Poseidon est particulièrement intéressante pour le tradecraft axé sur macOS : `jxa` exécute du JavaScript for Automation en mémoire,
`screencapture` capture le bureau de l’utilisateur connecté, `clipboard_monitor` diffuse les changements du pasteboard, `execute_library` charge un dylib local et appelle une fonction depuis celui-ci, et `libinject` force un processus distant à charger un dylib sur disque.
- Pour les tâches de longue durée, souvenez-vous que Poseidon exécute le post-exploitation dans des goroutines/threads coopératifs plutôt que strictement non terminables. La documentation indique aussi explicitement qu’il n’existe actuellement aucune obfuscation d’agent intégrée, donc le tradecraft au niveau build/profile compte davantage qu’avec des implants commerciaux fortement obfusqués.

Pour le tradecraft spécifique à macOS autour des opérations basées sur Mythic, de l’abus de JAMF, ou des idées MDM-as-C2, consultez [macOS Red Teaming](../macos-hardening/macos-red-teaming/README.md).

Lorsqu’il est utilisé sur Linux ou macOS, il a plusieurs commandes intéressantes :

### Actions courantes

- `cat`: Afficher le contenu d’un fichier
- `cd`: Changer le répertoire de travail courant
- `chmod`: Modifier les permissions d’un fichier
- `config`: Voir la config actuelle et les informations d’hôte
- `cp`: Copier un fichier d’un emplacement à un autre
- `curl`: Exécuter une seule requête web avec en-têtes et méthode optionnels
- `upload`: Envoyer un fichier vers la cible
- `download`: Télécharger un fichier depuis le système cible vers la machine locale
- Et bien plus encore

### Rechercher des informations sensibles

- `triagedirectory`: Trouver des fichiers intéressants dans un répertoire sur un hôte, tels que des fichiers sensibles ou des credentials.
- `getenv`: Obtenir toutes les variables d’environnement actuelles.

### Tradecraft spécifique à macOS

- `jxa`: Exécuter du JavaScript for Automation en mémoire via `OSAScript`, ce qui est
utile pour du post-exploitation natif sur macOS sans déposer de fichiers de script séparés.
- `clipboard_monitor`: Interroger le pasteboard et signaler les changements à Mythic,
ce qui est pratique pour les workflows de vol de credentials/tokens qui reposent sur le copier/coller.
- `screencapture`: Capturer le bureau de l’utilisateur sur macOS.
- `execute_library`: Charger un dylib depuis le disque et appeler une fonction exportée spécifique.
- `libinject`: Injecter un stub shellcode qui force un autre processus macOS à charger un dylib depuis le disque.
- `persist_launchd`: Créer une persistance LaunchAgent / LaunchDaemon directement depuis l’agent.

### Se déplacer latéralement

- `ssh`: Se connecter en SSH à l’hôte en utilisant les credentials désignés et ouvrir un PTY sans lancer ssh.
- `sshauth`: Se connecter en SSH aux hôtes spécifiés en utilisant les credentials désignés. Vous pouvez aussi l’utiliser pour exécuter une commande spécifique sur les hôtes distants via SSH ou pour utiliser SCP afin de copier des fichiers.
- `link_tcp`: Relier à un autre agent via TCP, permettant une communication directe entre agents.
- `link_webshell`: Relier à un agent en utilisant le profil P2P webshell, permettant un accès distant à l’interface web de l’agent.
- `rpfwd`: Démarrer ou arrêter un Reverse Port Forward, permettant un accès distant aux services sur le réseau cible.
- `socks`: Démarrer ou arrêter un proxy SOCKS5 sur le réseau cible, permettant le tunneling du trafic via l’hôte compromis. Compatible avec des outils comme proxychains.
- `portscan`: Scanner les ports ouverts sur le ou les hôtes, utile pour identifier des cibles potentielles pour le mouvement latéral ou d’autres attaques.

### Exécution de processus

- `shell`: Exécuter une seule commande shell via /bin/sh, permettant une exécution directe des commandes sur le système cible.
- `run`: Exécuter une commande depuis le disque avec des arguments, permettant l’exécution de binaires ou de scripts sur le système cible.
- `pty`: Ouvrir un PTY interactif, permettant une interaction directe avec le shell sur le système cible.




## Références

- [Mythic Community Agent Feature Matrix](https://mythicmeta.github.io/overview/agent_matrix.html)
- [Apollo README](https://github.com/MythicAgents/Apollo/blob/master/README.md)
- [Mythic v3.2 Highlights: Interactive Tasking, Push C2, and Dynamic File Browser](https://posts.specterops.io/mythic-v3-2-highlights-interactive-tasking-push-c2-and-dynamic-file-browser-7035065e2b3d)
- [Browser Scripts - Mythic Documentation](https://docs.mythic-c2.net/operational-pieces/browser-scripts)
{{#include ../banners/hacktricks-training.md}}
