# Mythic

{{#include ../banners/hacktricks-training.md}}

## Qu’est-ce que Mythic ?

Mythic est un framework open source, modulaire et collaboratif de command and control (C2), conçu pour le red teaming. Il permet aux opérateurs de gérer et de déployer des agents (payloads) sur différents systèmes d’exploitation, notamment Windows, Linux et macOS. Mythic fournit une interface Web pour la gestion des tâches de plusieurs opérateurs, la gestion des fichiers, la gestion de SOCKS/rpfwd et la génération de payloads.

Contrairement aux frameworks monolithiques, le dépôt Mythic lui-même ne fournit **ni types de payloads ni profils C2**. Les agents, wrappers et profils C2 sont généralement installés en tant que composants externes et peuvent être mis à jour indépendamment du cœur de Mythic.

### Installation

Pour installer Mythic, suivez les instructions du **[dépôt Mythic officiel](https://github.com/its-a-feature/Mythic)**. Une commande d’amorçage courante à exécuter depuis le répertoire Mythic est :

```bash
sudo make
sudo ./mythic-cli start
```

Si Mythic est déjà en cours d’exécution, vous pouvez normalement ajouter un nouvel agent ou profil avec `./mythic-cli install github ...`, puis redémarrer Mythic ou démarrer directement le nouveau composant.

### Agents

Mythic prend en charge plusieurs agents, qui sont les **payloads chargés d’effectuer des tâches sur les systèmes compromis**. Chaque agent peut être adapté à des besoins spécifiques et s’exécuter sur différents systèmes d’exploitation.

Par défaut, aucun agent n’est installé dans Mythic. Les agents open source de la communauté sont disponibles sur [**https://github.com/MythicAgents**](https://github.com/MythicAgents), et la [**matrice des fonctionnalités de la communauté**](https://mythicmeta.github.io/overview/agent_matrix.html) permet de vérifier rapidement les systèmes d’exploitation, les formats de payload, les wrappers et les profils C2 pris en charge.<sup>[[1]](#references)</sup>

Pour installer un agent de cette organisation, vous pouvez exécuter :

```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
sudo -E ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```

La forme `sudo -E` est utile lorsque vous installez depuis un environnement non-root. Vous pouvez ajouter de nouveaux agents avec la commande précédente, même si Mythic est déjà en cours d’exécution.

### Profils C2

Les profils C2 dans Mythic définissent **la manière dont les agents communiquent avec le serveur Mythic**. Ils spécifient le protocole de communication, les méthodes de chiffrement et d’autres paramètres. Vous pouvez créer et gérer des profils C2 via l’interface web de Mythic.

Par défaut, Mythic est installé sans aucun profil. Cependant, il est possible de télécharger certains profils depuis le dépôt [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles) en exécutant :

```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```

Profils actuels utiles aux opérateurs à garder à l’esprit :

- [`http`](https://github.com/MythicC2Profiles/http) : trafic GET/POST asynchrone de base.
- [`httpx`](https://github.com/MythicC2Profiles/httpx) : trafic HTTP plus flexible, avec plusieurs domaines de callback, basculement/rotation round-robin, en-têtes/paramètres de requête personnalisés et transformations de messages (`base64`, `base64url`, `xor`, `netbios`, `prepend`, `append`) placées dans les cookies, les en-têtes, les paramètres de requête ou le corps.
- [`dynamichttp`](https://github.com/MythicC2Profiles/dynamichttp) : personnalisation des messages HTTP pilotée par JSON/TOML lorsque le profil `http` statique est trop reconnaissable.

### Notes actuelles sur la plateforme

- De nombreux agents et profils publics s’installent désormais avec des images de conteneur distantes préconstruites.
  Si vous forkez un composant ou le modifiez localement et que Mythic conserve l’ancien
  comportement, inspectez les entrées `.env` générées pour `*_REMOTE_IMAGE`,
  `*_USE_BUILD_CONTEXT` et `*_USE_VOLUME` ; activer
  `*_USE_BUILD_CONTEXT="true"` est généralement nécessaire pour que Mythic reconstruise à partir de votre contexte Docker local au lieu de réutiliser silencieusement l’image distante.
- Les scripts de navigateur sont l’une des fonctionnalités de qualité de vie les plus utiles de Mythic
  pour les opérateurs : ils peuvent transformer la sortie brute des commandes en tableaux,
  visionneuses de captures d’écran, liens de téléchargement, liens de recherche et boutons qui lancent directement des tâches de suivi depuis l’interface. Les versions actuelles de Mythic permettent à chaque opérateur de conserver ses propres scripts, de les activer ou de les désactiver globalement ou par tâche, et donnent les meilleurs résultats
  lorsque les agents renvoient du JSON structuré plutôt que du texte brut. C’est particulièrement
  utile pour les workflows répétitifs `ls`, `ps`, de triage et d’exploration de fichiers.<sup>[[4]](#references)[[6]](#references)</sup>
- Les versions plus récentes de Mythic prennent également en charge le tasking interactif et les modèles Push C2,
  qui réduisent le besoin de sonder avec `sleep 0` lors d’opérations faisant largement appel à PTY/SOCKS/rpfwd. Lorsqu’un agent/profil le prend en charge, cette approche sollicite généralement moins le système
  que d’interroger constamment le serveur juste pour maintenir un canal interactif utilisable.<sup>[[3]](#references)</sup>
- Les builders Mythic actuels de l’ère 3.4 tiennent davantage compte du contexte que ne le laissent entendre les anciens articles : les paramètres de build peuvent désormais être regroupés ou masqués selon le système d’exploitation sélectionné
  ou d’autres options de build, les types de payload peuvent déclarer s’ils prennent en charge
  plusieurs profils C2 ou plusieurs instances du même C2 dans un seul build, et les écarts de paramètres C2 permettent à un agent de masquer les champs qu’il n’implémente pas réellement. C’est important lorsque vous passez de `http`, `httpx`, `smb`,
  `tcp` et `websocket`, car les options de build valides et sûres ne se limitent plus à
  un formulaire statique uniforme.<sup>[[5]](#references)</sup>
- Si vous créez une paire agent/profil personnalisée et que vous ne voulez pas du format de message JSON de Mythic ni de son chiffrement par défaut sur le réseau, utilisez un
  `translation_container` : Mythic supprime l’UUID, transmet le blob chiffré et les éléments de clé au traducteur via gRPC, puis attend en retour des octets au format natif de l’agent. C’est la méthode recommandée pour prendre en charge les protocoles binaires, le framing personnalisé ou le chiffrement côté agent sans réécrire tout le serveur.
- N’oubliez pas que les callbacks liés/P2P ne font pas que relayer le tasking. Le flux `get_tasking` de Mythic peut également transporter des réponses ainsi que des données `delegates`,
  `socks`, `rpfwd` et `interactive`. En pratique, un callback de sortie peut gérer les callbacks internes et les canaux de pivot dans la même boucle d’interrogation ; si les agents enfants effectuent leurs propres check-ins périodiques, `get_delegate_tasks=false` empêche le parent de consommer accidentellement les tâches en attente du callback interne.

### Payloads wrapper

Les payloads wrapper vous permettent de conserver la même logique d’agent tout en modifiant la représentation sur disque du payload livré ou stocké.

- `service_wrapper` : transforme un autre payload en exécutable de service Windows, utile lorsque le chemin d’exécution exige un binaire de service valide.
- `scarecrow_wrapper` : enveloppe le shellcode compatible avec le loader ScareCrow pour générer des fichiers de sortie utilisant un loader, tels que EXE/DLL/CPL.

## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Apollo est un agent Windows écrit en C# avec le .NET Framework 4.0, conçu pour les formations de SpecterOps.<sup>[[2]](#references)</sup>

Installez-le avec :

```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```

### Notes sur le build/profil actuel

- Apollo peut actuellement générer des payloads `WinExe`, `Shellcode`, `Service` et `Source`.
- Les profils Apollo couramment utilisés sont `http`, `httpx`, `smb`, `tcp` et `websocket`.
- `httpx` est généralement l’option la plus flexible lorsque vous avez besoin de rotation de domaines, de prise en charge des proxys, de placement personnalisé des messages et de transformations des messages, plutôt que de l’ancien profil statique `http`.
- Apollo est l’un des agents communautaires les plus complets en fonctionnalités et expose actuellement des intégrations côté Mythic telles que des scripts de navigateur, des vues de navigation des fichiers/processus, des captures d’écran, l’enregistrement des frappes clavier, SOCKS, rpfwd, Push C2 et le routage P2P.
- Apollo prend en charge des payloads wrapper comme `service_wrapper` et `scarecrow_wrapper`.
- Apollo prend en charge le chargement dynamique des commandes : vous pouvez ainsi garder le payload initial léger et charger des commandes ou des modules Forge supplémentaires ultérieurement, au lieu de compiler toutes les capacités post-exploitation dans le premier build.
- Lors de la génération d’une sortie shellcode, le builder actuel d’Apollo expose également les formats Donut (`Binary`, `Base64`, `C`, `Ruby`, `Python`, `Powershell`, `C#`, `Hex`) et le comportement de bypass Donut (`None`, `Abort on fail`, `Continue on fail`). Cela peut être utile si l’objectif final est de ré-emballer le shellcode avec `service_wrapper`, `scarecrow_wrapper` ou un loader personnalisé.
- `register_file` et `register_assembly` sont les primitives de staging pour `execute_assembly`, `execute_pe`, `inline_assembly`, `execute_coff`, `powershell_import` et `powerpick`. Dans les builds Apollo actuels, ces artefacts mis en staging sont mis en cache côté client sous forme de blobs AES256 protégés par DPAPI.
- Les résultats de `ls` et `ps` s’intègrent particulièrement bien aux scripts de navigateur et à l’outil de navigation des fichiers/processus de Mythic, ce qui accélère nettement le triage par les opérateurs lors d’opérations collaboratives.
- Les tâches fork-and-run héritent des paramètres de processus sacrificiel depuis
  `spawnto_x86` / `spawnto_x64`, héritent de la sélection du processus parent depuis `ppid`, puis
  utilisent la primitive d’injection actuellement sélectionnée. En pratique, cela signifie
  que votre configuration OPSEC pour une commande affecte souvent `execute_assembly`,
  `powerpick`, `mimikatz`, `pth`, `dcsync`, `execute_pe` et `spawn` en même temps.
- Les backends d’injection Apollo actuellement documentés comprennent `CreateRemoteThread`,
  `QueueUserAPC` (style early-bird) et `NtCreateThreadEx` via des syscalls. Utilisez
  `get_injection_techniques` avant une post-exploitation bruyante et
  `set_injection_technique` si vous devez abandonner une primitive qui
  entre en conflit avec la cible ou la commande que vous souhaitez exécuter.
- `blockdlls` n’affecte que les processus sacrificiels créés pour les tâches de post-exploitation. Combiné à une cible `spawnto_x64` moins suspecte que le `rundll32.exe` nu utilisé par défaut, c’est l’un des changements les plus simples à effectuer côté Apollo avant de lancer des tâches faisant largement appel à l’assembly ou à PowerShell.

### Pipeline de build d’un agent .NET tenant compte de la détection

Un fork d’Apollo tenant compte de la détection doit être considéré comme un **problème touchant l’ensemble du système de build**, et non comme une étape finale d’`obfuscate.exe`. Cette étude de cas complète la [AV evasion methodology](av-bypass.md) générale et les [outils d’inspection .NET](../reversing/reversing-tools-basic-methods/README.md) : les modifications apportées aux identifiants wire, aux métadonnées IL, au packaging des dépendances, à la réflexion et aux tâches compilées dynamiquement forment une même frontière de compatibilité.<sup>[[8]](#references)</sup>

#### Mutation du protocole tenant compte des règles YARA

Auditez les règles publiques portant sur les fichiers et la mémoire avant de modifier le code. Par exemple, `Multi_Trojan_Mythic_4beb7e17` d’Elastic détecte une correspondance lorsque **7 des 11** chaînes JSON/action de Mythic sont présentes, notamment `task_id`, `post_response`, `c2_profile`, `get_tasking` et `get_delegate_tasks`. Renommer suffisamment de champs peut permettre de contourner ce seuil, mais il s’agit de valeurs de protocole, pas de symboles cosmétiques : l’agent et l’implémentation serveur/profil correspondante doivent être modifiés ensemble.<sup>[[7]](#references)[[8]](#references)</sup>

Cela ne supprime qu’un seul ensemble de caractéristiques statiques. La cadence des check-in, la structure des messages, le flux des tâches/réponses et la reconstruction des chaînes à l’exécution peuvent rester des indicateurs comportementaux ou mémoire ; il faut donc valider à la fois l’artefact généré et un callback effectivement exécuté, plutôt que de considérer une analyse de chaînes sans résultat comme une réussite.<sup>[[8]](#references)</sup>

#### Fusionner avant d’appliquer les transformations globales

L’intégration de ressources avec des outils comme Costura laisse les assemblies associées sous forme de ressources compressées. Un obfuscateur qui ne traite que le module externe ignore donc leurs noms de types et leurs métadonnées ; obfusquer chaque DLL séparément peut au contraire attribuer des noms incompatibles aux contrats inter-assemblies. Fusionnez d’abord les sorties de build au niveau IL (par exemple avec [ILRepack](https://github.com/gluck/il-repack)), puis appliquez une seule table de renommage au module obtenu.<sup>[[8]](#references)</sup>

```text
agent.exe + dependency DLLs
          -> ILRepack -> merged.exe
          -> dnlib IL/metadata transforms
          -> AsmResolver PE/resource patching
          -> final payload
```

Une passe personnalisée peut utiliser [dnlib](https://github.com/0xd4d/dnlib) pour transformer l’IL/les métadonnées managés et [AsmResolver](https://github.com/Washi1337/AsmResolver) pour modifier les PE/ressources après écriture. Dans l’étude de cas, les instructions `ldstr` admissibles ont été remplacées par des appels utilisant des tokens entiers et un déchiffreur, avec une nouvelle clé rolling-XOR de 16 octets. Les symboles et les espaces de noms ont été renommés avec des noms plausibles de type entreprise plutôt qu’avec des identifiants courts et séquentiels. D’autres passes ont supprimé certains attributs de compilateur/de débogueur, effacé les références à la fusion et à l’incorporation, renommé les ressources et modifié les informations de version. Réinitialisez les noms, le code mort et le matériel de chiffrement pour chaque build indépendant : modifier le texte chiffré supprime les octets stables, mais un déchiffreur stable ou un motif de transformation reconnaissable constitue en soi une signature.<sup>[[8]](#references)</sup>

#### Synchroniser les tâches dynamiques avec le payload

Apollo peut compiler le code source des tâches côté serveur, envoyer les octets de la DLL et les charger avec `Assembly.Load()`. Une fois les types publics de l’agent de base renommés, les tâches compilées ultérieurement avec l’API d’origine ne sont plus résolues. Traitez la map de renommage exportée comme un artefact ABI propre au payload :<sup>[[8]](#references)</sup>

1. Associez la map et le contexte de types à l’identifiant exact du payload/build.
2. Pour chaque build de tâche, récupérez cette map et réécrivez une arborescence source temporaire.
3. Réécrivez uniquement les références résolues aux espaces de noms, aux types, aux types imbriqués/génériques, aux champs et aux propriétés, puis compilez avec l’assembly fusionnée et obfusquée.
4. Rejetez les maps manquantes ou incompatibles avant la livraison de la tâche, puis effectuez un test d’initialisation après la compilation.

Le remplacement global à l’aveugle est dangereux, car un identifiant peut aussi apparaître dans une chaîne, une déclaration locale, un accès à un membre, un type de framework ou un espace de noms sans rapport. Si vous conservez un réécrivain textuel/regex, protégez explicitement ces contextes et testez-le en non-régression chaque fois que le schéma de la map ou une passe de renommage change.<sup>[[8]](#references)</sup>

#### Rendre les contrats de réflexion indépendants des espaces de noms

Le code de découverte qui vérifie `t.FullName.StartsWith("Tasks.")` dépend de l’espace de noms et échoue après le remappage des espaces de noms. Basez plutôt la découverte sur une relation de type stable, tout en préservant les noms des classes de commande si le dispatch utilise toujours `t.Name` :<sup>[[8]](#references)</sup>

```csharp
foreach (Type t in _tasksAsm.GetExportedTypes())
{
    if (t.IsSubclassOf(typeof(Tasking)) && !t.IsAbstract)
        _loadedTaskTypes[t.Name] = t;
}
```

Maintenez une allowlist explicite des noms visibles par réflexion, des champs du sérialiseur, des points d’entrée et des API inter-assemblies qui ne doivent pas être renommés. Enfin, décompilez le résultat avec ILSpy/dnSpy, analysez les représentations sur disque et en mémoire, puis testez chaque chemin de commande et de loader dans un lab EDR ; une compilation qui démarre correctement peut tout de même contenir des tâches cassées par le renommage ou des comportements détectés uniquement après exécution.<sup>[[8]](#references)</sup>

Cet agent dispose de nombreuses commandes qui le rendent très similaire au Beacon de Cobalt Strike, avec quelques fonctionnalités supplémentaires. Parmi celles-ci, il prend en charge :

### Actions courantes

- `cat` : Afficher le contenu d’un fichier
- `cd` : Changer le répertoire de travail courant
- `cp` : Copier un fichier d’un emplacement à un autre
- `ls` : Lister les fichiers et répertoires du répertoire courant ou du chemin spécifié
- `ifconfig` : Récupérer les adaptateurs et interfaces réseau
- `netstat` : Récupérer des informations sur les connexions TCP et UDP
- `pwd` : Afficher le répertoire de travail courant
- `ps` : Lister les processus en cours d’exécution sur le système cible (avec des informations supplémentaires)
- `jobs` : Lister tous les jobs en cours d’exécution associés aux tâches de longue durée
- `download` : Télécharger un fichier du système cible vers la machine locale
- `upload` : Envoyer un fichier de la machine locale vers le système cible
- `reg_query` : Interroger les clés et valeurs du registre sur le système cible
- `reg_write_value` : Écrire une nouvelle valeur dans la clé de registre spécifiée
- `sleep` : Modifier l’intervalle de sommeil de l’agent, qui détermine la fréquence à laquelle il communique avec le serveur Mythic
- Et bien d’autres ; utilisez `help` pour afficher la liste complète des commandes disponibles.

### Élévation de privilèges

- `getprivs` : Activer autant de privilèges que possible sur le token du thread courant
- `getsystem` : Ouvrir un handle vers winlogon et dupliquer le token, afin d’élever effectivement les privilèges au niveau SYSTEM
- `make_token` : Créer une nouvelle session de connexion et l’appliquer à l’agent, ce qui permet d’usurper l’identité d’un autre utilisateur
- `steal_token` : Voler un token principal d’un autre processus, afin que l’agent puisse usurper l’identité de l’utilisateur de ce processus
- `pth` : Attaque Pass-the-Hash, qui permet à l’agent de s’authentifier en tant qu’utilisateur à l’aide de son hash NTLM, sans avoir besoin du mot de passe en clair
- `mimikatz` : Exécuter des commandes Mimikatz pour extraire des identifiants, des hashes et d’autres informations sensibles depuis la mémoire ou la base de données SAM
- `rev2self` : Rétablir le token principal de l’agent, ce qui supprime effectivement les privilèges et ramène au niveau initial
- `ppid` : Définir un nouveau processus parent pour les jobs de post-exploitation en spécifiant son ID, afin de mieux contrôler le contexte d’exécution des jobs
- `printspoofer` : Exécuter des commandes PrintSpoofer pour contourner les mesures de sécurité du service Spouleur d’impression, ce qui permet une élévation de privilèges ou l’exécution de code
- `dcsync` : Synchroniser les clés Kerberos d’un utilisateur sur la machine locale, afin de permettre le cassage de mots de passe hors ligne ou d’autres attaques
- `ticket_cache_add` : Ajouter un ticket Kerberos à la session de connexion courante ou à une session spécifiée, afin de permettre la réutilisation du ticket ou l’usurpation d’identité

### Exécution de processus

- `assembly_inject` : Permet d’injecter un loader d’assembly .NET dans un processus distant
- `blockdlls` : Bloquer le chargement des DLL non signées par Microsoft dans les jobs de post-exploitation
- `execute_assembly` : Exécuter un assembly .NET dans le contexte de l’agent
- `execute_coff` : Exécuter un fichier COFF en mémoire, ce qui permet l’exécution en mémoire de code compilé
- `execute_pe` : Exécuter un exécutable non managé (PE)
- `keylog_inject` : Injecter un keylogger dans un autre processus et renvoyer les frappes dans la vue keylog de Mythic
- `screenshot` / `screenshot_inject` : Capturer directement le bureau courant ou
  injecter un assembly de capture d’écran dans un processus/une session cible
- `get_injection_techniques` : Afficher les techniques d’injection disponibles et celle actuellement sélectionnée
- `inline_assembly` : Exécuter un assembly .NET dans un AppDomain jetable, ce qui permet d’exécuter temporairement du code sans affecter le processus principal de l’agent
- `register_assembly` : Enregistrer un assembly .NET pour une exécution ultérieure
- `register_file` : Enregistrer un fichier dans le cache de l’agent pour une tâche `execute_*` ou PowerShell ultérieure
- `run` : Exécuter un binaire sur le système cible en utilisant le PATH du système pour trouver l’exécutable
- `set_injection_technique` : Modifier la primitive d’injection utilisée par les jobs de post-exploitation
- `shinject` : Injecter du shellcode dans un processus distant, ce qui permet l’exécution en mémoire de code arbitraire
- `inject` : Injecter le shellcode de l’agent dans un processus distant, ce qui permet l’exécution en mémoire du code de l’agent
- `spawn` : Démarrer une nouvelle session d’agent dans l’exécutable spécifié, ce qui permet d’exécuter du shellcode dans un nouveau processus
- `spawnto_x64` et `spawnto_x86` : Remplacer le binaire par défaut utilisé dans les jobs de post-exploitation par le chemin spécifié, au lieu d’utiliser `rundll32.exe` sans paramètres, ce qui est très bruyant.

### Mythic Forge

Cela permet de **charger des fichiers COFF/BOF** depuis le Mythic Forge, un dépôt de payloads et d’outils précompilés qui peuvent être exécutés sur le système cible. Grâce à toutes les commandes qui peuvent être chargées, il sera possible d’effectuer des actions courantes en les exécutant dans le processus courant de l’agent sous forme de BOF (généralement avec un meilleur OPSEC que le lancement d’un processus distinct).

Commencez par les installer avec :

```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```

Ensuite, utilisez `forge_collections` pour afficher les modules COFF/BOF du Mythic Forge, afin de pouvoir les sélectionner et les charger dans la mémoire de l’agent pour exécution. Par défaut, les 2 collections suivantes sont ajoutées dans Apollo :

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

Une fois un module chargé, il apparaît dans la liste comme une autre commande, par exemple `forge_bof_sa-whoami` ou `forge_bof_sa-netuser`.

Pour les BOF, n’oubliez pas que Forge ne transmet **pas** simplement une chaîne d’arguments unique à Apollo. Il convertit les paramètres du BOF au format de tableau typé de Mythic, puis les transmet au flux `execute_coff` d’Apollo. Si un BOF chargé par Forge se comporte de façon étrange, vérifiez les types d’arguments BOF et le point d’entrée attendus, plutôt que de vous fier uniquement à la ligne de commande saisie. Notez également que le chargeur BOF plus récent d’Apollo a modifié la gestion des arguments par rapport aux versions bien plus anciennes de l’ère 2.3.1 ; des BOF obsolètes ou d’anciennes collections peuvent donc échouer simplement parce que les attentes en matière de marshaling ont changé.

### Exécution de PowerShell et de scripts

- `powershell_import` : importe un nouveau script PowerShell (.ps1) dans le cache de l’agent pour l’exécuter ultérieurement
- `powershell` : exécute une commande PowerShell dans le contexte de l’agent, permettant une automatisation et des scripts avancés
- `powerpick` : injecte un assembly chargeur PowerShell dans un processus sacrifiable et exécute une commande PowerShell (sans journalisation PowerShell).
- `psinject` : exécute PowerShell dans un processus spécifié, permettant l’exécution ciblée de scripts dans le contexte d’un autre processus
- `shell` : exécute une commande shell dans le contexte de l’agent, comme l’exécution d’une commande dans cmd.exe

### Mouvement latéral

- `jump_psexec` : utilise la technique PsExec pour se déplacer latéralement vers un nouvel hôte en y copiant d’abord l’exécutable de l’agent Apollo (apollo.exe), puis en l’exécutant.
- `jump_wmi` : utilise la technique WMI pour se déplacer latéralement vers un nouvel hôte en y copiant d’abord l’exécutable de l’agent Apollo (apollo.exe), puis en l’exécutant.
- `link` et `unlink` : créent et interrompent des liens P2P (par exemple via SMB/TCP) entre des callbacks.
- `wmiexecute` : exécute une commande sur le système local ou sur un système distant spécifié au moyen de WMI, avec la possibilité d’utiliser des identifiants pour l’usurpation d’identité.
- `net_dclist` : récupère la liste des contrôleurs de domaine du domaine spécifié, utile pour identifier des cibles potentielles de mouvement latéral.
- `net_localgroup` : répertorie les groupes locaux sur l’ordinateur spécifié ; utilise localhost par défaut si aucun ordinateur n’est indiqué.
- `net_localgroup_member` : récupère les membres d’un groupe local spécifié sur l’ordinateur local ou distant, afin de recenser les utilisateurs appartenant à des groupes particuliers.
- `net_shares` : répertorie les partages distants et leur accessibilité sur l’ordinateur spécifié, utile pour identifier des cibles potentielles de mouvement latéral.
- `socks` : active un proxy compatible SOCKS 5 sur le réseau cible, permettant de faire transiter le trafic par l’hôte compromis. Compatible avec des outils comme proxychains.
- `rpfwd` : écoute sur un port spécifié de l’hôte cible et achemine le trafic via Mythic vers une adresse IP et un port distants, afin de permettre l’accès à distance aux services du réseau cible.
- `listpipes` : répertorie tous les named pipes du système local, ce qui peut être utile pour le mouvement latéral ou l’élévation de privilèges par interaction avec les mécanismes IPC.

Pour les primitives d’exécution WMI de bas niveau utilisées par `jump_wmi` ou `wmiexecute`, consultez [WmiExec](lateral-movement/wmiexec.md). Pour des méthodes de pivotement plus générales, consultez [Tunneling and Port Forwarding](../generic-hacking/tunneling-and-port-forwarding.md).

### Commandes diverses
- `help` : affiche des informations détaillées sur des commandes spécifiques ou des informations générales sur toutes les commandes disponibles dans l’agent.
- `clear` : marque des tâches comme « cleared » afin que les agents ne puissent pas les récupérer. Vous pouvez spécifier `all` pour effacer toutes les tâches ou `task Num` pour effacer une tâche spécifique.  


## [Poseidon Agent](https://github.com/MythicAgents/poseidon)

Poseidon est un agent Golang qui se compile en exécutables pour **Linux et macOS**.

```bash
./mythic-cli install github https://github.com/MythicAgents/poseidon.git
```

### Notes actuelles sur les builds/profils

- Les builds Poseidon actuels ciblent Linux et macOS sur `x86_64` et `arm64`.
- Les formats de sortie pris en charge incluent les exécutables natifs et les sorties de type bibliothèque partagée, comme `dylib` et `so`.
- Poseidon prend en charge `http`, `websocket`, `tcp` et `dynamichttp`. Les builders actuels proposent des paramètres multi-egress tels que `egress_order` et des seuils de failover.
- Les métadonnées de capacités actuelles de Poseidon annoncent également des scripts de navigateur, l’intégration du navigateur de fichiers/processus, le tasking interactif, le keylogging, les captures d’écran, Push C2, SOCKS, rpfwd et P2P. Il peut donc servir de véritable nœud pivot Linux/macOS plutôt que de simple shell distant.
- Les options de build telles que `proxy_bypass` et `garble` méritent d’être examinées si vous avez besoin d’un comportement réseau plus discret ou d’une obfuscation supplémentaire des binaires Go.
- `pty` est l’une des commandes récentes les plus utiles pour améliorer le confort d’utilisation lors des opérations Linux/macOS : elle ouvre un PTY interactif et peut exposer un port côté Mythic pour une interaction plus complète avec le terminal, sans recourir à l’ancienne solution de contournement `sleep 0` + SOCKS.
- La documentation actuelle de Poseidon est particulièrement intéressante pour le tradecraft axé sur macOS : `jxa` exécute en mémoire du JavaScript for Automation, `screencapture` capture le bureau de l’utilisateur connecté, `clipboard_monitor` transmet les changements du pasteboard, `execute_library` charge une dylib locale et appelle l’une de ses fonctions, et `libinject` force un processus distant à charger une dylib depuis le disque.
- Pour les tâches de longue durée, gardez à l’esprit que Poseidon exécute le post-exploitation dans des goroutines/threads coopératifs qui ne peuvent pas être arrêtés brutalement. La documentation précise également qu’il n’existe actuellement aucune obfuscation intégrée de l’agent ; le tradecraft au niveau du build/profil compte donc davantage qu’avec des implants commerciaux fortement obfusqués.

Pour le tradecraft macOS associé aux opérations basées sur Mythic, aux abus de JAMF ou aux idées de MDM-as-C2, consultez [Mac Red Teaming](../macos-hardening/macos-red-teaming/README.md).

Sous Linux ou macOS, il propose des commandes intéressantes :

### Actions courantes

- `cat` : Afficher le contenu d’un fichier
- `cd` : Changer le répertoire de travail actuel
- `chmod` : Modifier les permissions d’un fichier
- `config` : Afficher la configuration actuelle et les informations sur l’hôte
- `cp` : Copier un fichier d’un emplacement à un autre
- `curl` : Effectuer une requête web unique avec des en-têtes et une méthode facultatifs
- `upload` : Téléverser un fichier sur la cible
- `download` : Télécharger un fichier du système cible vers la machine locale
- Et bien plus encore

### Recherche d’informations sensibles

- `triagedirectory` : Rechercher des fichiers intéressants dans un répertoire sur un hôte, comme des fichiers sensibles ou des identifiants.
- `getenv` : Récupérer toutes les variables d’environnement actuelles.

### Tradecraft spécifique à macOS

- `jxa` : Exécuter en mémoire du JavaScript for Automation via `OSAScript`, ce qui
  est utile pour le post-exploitation macOS native sans déposer de fichiers de
  script distincts.
- `clipboard_monitor` : Interroger le pasteboard et transmettre les changements à Mythic,
  pratique pour les workflows de vol d’identifiants/de jetons reposant sur le copier-coller.
- `screencapture` : Capturer le bureau de l’utilisateur sur macOS.
- `execute_library` : Charger une dylib depuis le disque et appeler une fonction exportée spécifique.
- `libinject` : Injecter un stub de shellcode qui force un autre processus macOS à charger une dylib depuis le disque.
- `persist_launchd` : Créer une persistance LaunchAgent / LaunchDaemon directement depuis l’agent.

### Mouvement latéral

- `ssh` : Se connecter à un hôte en SSH avec les identifiants désignés et ouvrir un PTY sans lancer ssh.
- `sshauth` : Se connecter en SSH aux hôtes spécifiés avec les identifiants désignés. Vous pouvez aussi l’utiliser pour exécuter une commande spécifique sur les hôtes distants via SSH ou pour transférer des fichiers avec SCP.
- `link_tcp` : Établir une liaison TCP vers un autre agent, permettant une communication directe entre agents.
- `link_webshell` : Établir une liaison vers un agent à l’aide du profil P2P webshell, permettant l’accès à distance à son interface web.
- `rpfwd` : Démarrer ou arrêter un Reverse Port Forward, permettant l’accès à distance aux services du réseau cible.
- `socks` : Démarrer ou arrêter un proxy SOCKS5 sur le réseau cible, permettant le tunneling du trafic via l’hôte compromis. Compatible avec des outils tels que proxychains.
- `portscan` : Analyser des hôtes à la recherche de ports ouverts, afin d’identifier d’éventuelles cibles pour un mouvement latéral ou d’autres attaques.

### Exécution de processus

- `shell` : Exécuter une commande shell unique via /bin/sh, permettant l’exécution directe de commandes sur le système cible.
- `run` : Exécuter une commande depuis le disque avec des arguments, permettant de lancer des binaires ou des scripts sur le système cible.
- `pty` : Ouvrir un PTY interactif, permettant d’interagir directement avec le shell sur le système cible.

## References

- [1] [Matrice des fonctionnalités des agents de la communauté Mythic](https://mythicmeta.github.io/overview/agent_matrix.html)
- [2] [Fichier README d’Apollo](https://github.com/MythicAgents/Apollo/blob/master/README.md)
- [3] [Points forts de Mythic v3.2 : tasking interactif, Push C2 et navigateur de fichiers dynamique](https://posts.specterops.io/mythic-v3-2-highlights-interactive-tasking-push-c2-and-dynamic-file-browser-7035065e2b3d)
- [4] [Scripts de navigateur - Documentation Mythic](https://docs.mythic-c2.net/operational-pieces/browser-scripts)
- [5] [Mises à jour de Mythic 3.3->3.4](https://docs.mythic-c2.net/updating/mythic-3.3-greater-than-3.4-updates)
- [6] [Transformer les opérations Red Team grâce aux pépites cachées de Mythic : les scripts de navigateur](https://specterops.io/blog/2025/08/21/transforming-red-team-ops-with-mythics-hidden-gems-browser-scripting/)
- [7] [protections-artifacts d’Elastic : règles YARA Multi_Trojan_Mythic](https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Multi_Trojan_Mythic.yar)
- [8] [Du fork au framework : ce que la modification d’Apollo nous a appris sur l’invasion d’agents](https://bishopfox.com/blog/from-fork-to-framework-what-modifying-apollo-taught-us-about-agent-invasion)
{{#include ../banners/hacktricks-training.md}}
