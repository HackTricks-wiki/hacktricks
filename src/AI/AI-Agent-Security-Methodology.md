# Méthodologie de sécurité des agents IA

{{#include ../banners/hacktricks-training.md}}

Une évaluation d’agent doit suivre **une entrée contrôlée par l’attaquant jusqu’à un effet observable de l’extérieur**. Le jailbreaking, les changements de caractère et la divulgation du system prompt prouvent qu’un canal de raisonnement peut être influencé, mais la découverte à fort impact est la chaîne qui mène à l’accès aux données, à une action non autorisée via un outil, à un point d’injection en aval, à une persistance ou à un autre agent.<sup>[[2]](#references)</sup>

L’[OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) est utile pour étiqueter la couverture (détournement des objectifs, mauvais usage des outils, abus de privilèges, chaîne d’approvisionnement, exécution de code, empoisonnement de la mémoire, confiance inter-agents, défaillances en cascade, confiance humaine et agents malveillants). Utilisez ces étiquettes après avoir établi un chemin d’attaque de bout en bout, au lieu de considérer un texte inattendu généré par le modèle comme la fin du test.<sup>[[1]](#references)[[2]](#references)</sup>

## Cartographier la cible

Avant de rédiger des payloads, consignez ces cinq dimensions pour chaque workflow d’agent :<sup>[[2]](#references)</sup>

| Dimension | Éléments à répertorier | Question de sécurité |
|---|---|---|
| **Entrées non fiables** | Paramètres de chat/API, URL, documents, e-mails, tickets, entrées de calendrier, fragments récupérés, mémoire, résultats d’outils et messages d’agents pairs | Où un attaquant peut-il placer du contenu qui sera ensuite intégré au contexte du modèle ? |
| **Outils** | Noms et schémas des outils, effets secondaires, exécution automatique, comportement de confirmation et outils chargés dynamiquement | Quels appels lisent des secrets, modifient l’état, envoient des messages, suppriment des données, exécutent du code ou transfèrent de la valeur ? |
| **Autorité** | Délégation utilisateur, comptes de service, jetons API, durée de vie des identifiants, portée sur les locataires/ressources et accès réseau | Avec quelle identité chaque appel s’exécute-t-il, et l’autorisation est-elle vérifiée à nouveau à la frontière de l’outil ? |
| **Traitement** | Constructeurs de requêtes, shells, récupérateurs d’URL, moteurs de templates, interpréteurs, parseurs, opérations sur les fichiers et désérialiseurs | Où les données générées par le modèle deviennent-elles de la syntaxe pour un autre interpréteur ? |
| **Sorties** | Réponses, Markdown/HTML rendu, liens, chargements d’images, webhooks, e-mails, fichiers, journaux, rapports, métriques et trafic entre agents pairs | Quel canal observable peut transporter un secret ou déclencher une requête secondaire ? |

Ne réduisez pas cette analyse à une liste d’intégrations annoncées. Un livrable utile relie chaque source à la position exacte qu’elle atteint dans le contexte, aux outils disponibles à ce stade, à l’identifiant utilisé par chaque outil, à l’interpréteur en aval et à toutes les voies de sortie. Un même outil peut avoir un faible impact avec un jeton de lecture par utilisateur et un impact critique avec un identifiant administrateur partagé.<sup>[[2]](#references)</sup>

## Reconnaissance

### Cartographier tous les chemins de livraison et d’ingestion

Commencez par la surface de livraison (web, mobile, API, e-mail, plateforme de chat, extension de navigateur) et interceptez le trafic entre le client et le backend via un proxy. Examinez les champs masqués par l’interface, les paramètres de recherche/saisie semi-automatique/filtrage, les objets d’état de conversation, les tâches de téléversement et d’indexation, les réponses des outils et le trafic des sous-agents. Les clients exclusivement mobiles peuvent nécessiter un émulateur et de l’instrumentation pour contourner le certificate pinning avant que le véritable schéma des requêtes soit visible.<sup>[[2]](#references)</sup>

Cartographiez ensuite la pile sous-jacente au modèle : framework d’orchestration, assemblage des prompts, magasins de récupération et de mémoire, environnement d’exécution (par exemple Python, conteneur ou WASM), volumes montés, services hôtes, API internes, accès aux métadonnées cloud et réseaux voisins. Les valeurs par défaut du framework sont importantes, car certains « appels d’outils » sont implémentés en générant ou en évaluant du code ; la frontière de l’environnement d’exécution/sandbox détermine si ce résultat reste confiné.<sup>[[2]](#references)</sup>

### Identifier le routage avec des sondes non destructives

Comparez une requête dans le périmètre à plusieurs requêtes sans rapport, en conservant la réponse complète, le code d’état, la latence et le comportement de streaming. Un rejet stable avant tout raisonnement propre à la tâche peut indiquer une passerelle/classificateur distinct ; un refus contextuel suggère que la requête a atteint le modèle ; une réponse vide ou purement extractive peut indiquer une recherche par mot-clé ou une récupération limitée. Traitez ces observations comme des hypothèses et confirmez-les en rejouant la même sonde via d’autres champs d’API et chemins d’ingestion.<sup>[[2]](#references)</sup>

La reconnaissance est terminée lorsque l’évaluation peut nommer la première source contrôlée par l’attaquant qui modifie le comportement de l’agent **ainsi que** les outils, identités, interpréteurs et sorties accessibles depuis cette source.<sup>[[2]](#references)</sup>

## Exploitation : franchir une frontière de confiance

Testez les canaux, pas seulement la formulation des prompts. Commencez par une injection directe pour établir ce que bloque la porte d’entrée visible, puis répétez une intention équivalente via les chemins moins visibles ci-dessous :<sup>[[2]](#references)</sup>

- **Contenu indirect :** pages, fichiers, e-mails, tickets, métadonnées, texte alternatif, commentaires HTML, texte hors écran ou caractères de largeur nulle. Voir [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection) pour les techniques de livraison des payloads.
- **Récupération et mémoire :** empoisonnez le contenu qui sera récupéré ultérieurement ou l’état qui sera rechargé lors de sessions ultérieures. Notez si la suppression de la source d’origine élimine le comportement.
- **Résultats d’outils et agents pairs :** placez le marqueur dans une réponse d’outil ou un message entre agents pour vérifier si le trafic interne contourne les filtres appliqués uniquement aux entrées utilisateur et aux sorties finales.
- **Chaîne d’approvisionnement :** examinez les descripteurs d’outils, plugins, serveurs connectés, skills, modèles et dépendances en tant que sources d’instructions fiables. Pour les tests spécifiques à MCP, voir [MCP Servers](AI-MCP-Servers.md#mcp-vulns).
- **Approbation humaine :** comparez l’appel d’outil structuré réel au texte d’approbation généré par le modèle. Vérifiez si l’influence de l’attaquant peut omettre la destination, la portée, les objets concernés ou les effets secondaires irréversibles.

Commencez par un marqueur unique et inoffensif. Conservez l’artefact source, le contexte assemblé s’il est observable, l’appel d’outil sélectionné, les données d’approbation, la requête/réponse backend et l’état final. Cela permet de distinguer une réelle influence d’une affirmation hallucinée selon laquelle une action aurait eu lieu.<sup>[[2]](#references)</sup>

### Isolation du contexte des sous-agents

Un sous-agent non-fork du Claude Agent SDK reçoit son propre `AgentDefinition.prompt`, le prompt de délégation et les outils à sa disposition, mais pas le system prompt ni la conversation du parent. Si `tools` est omis de sa définition, il hérite des outils disponibles aux sous-agents ; le fichier de projet `CLAUDE.md` peut tout de même être chargé. Une restriction de prompt appliquée uniquement au parent constitue donc une frontière peu fiable lorsque l’enfant peut utiliser les mêmes outils de système de fichiers ou d’exécution.<sup>[[4]](#references)</sup>

Testez cette frontière en comparant une requête directe refusée par le parent à la même tâche déléguée à un sous-agent nommé. NCC Group rapporte qu’une énumération de fichiers du système d’exploitation, refusée au parent, a réussi lorsqu’elle était reformulée pour l’enfant comme une simple « carte de disposition ».<sup>[[3]](#references)</sup>

Examinez les appels d’outils réels de l’enfant et sa liste effective d’outils autorisés, et pas seulement la réponse finale du parent ; vérifiez si l’enfant a accédé à des fichiers auxquels le parent n’aurait pas accès.<sup>[[4]](#references)</sup> Il s’agit d’un défaut d’héritage des garde-fous, et non d’une preuve de contournement d’un [Python sandbox](../generic-methodologies-and-resources/python/bypass-python-sandboxes/) ou d’évasion de conteneur.<sup>[[3]](#references)[[4]](#references)</sup>

## Exécution : prouver l’impact réel

Il existe deux voies distinctes entre l’influence et l’impact :<sup>[[2]](#references)</sup>

1. **Abus de capacité :** l’outil autorisé réalise déjà l’objectif. Exemples : lire l’enregistrement d’un locataire et l’écrire dans un rapport visible par l’attaquant, envoyer un e-mail, modifier des enregistrements, supprimer un fichier ou lancer un paiement. Aucune vulnérabilité logicielle secondaire n’est nécessaire.
2. **Exploitation d’un point d’injection en aval :** la sortie du modèle dirigée par l’attaquant devient de la syntaxe pour un autre composant. Examinez les requêtes de base de données à la recherche d’[injection SQL](../pentesting-web/sql-injection/README.md) ou d’[injection NoSQL](../pentesting-web/nosql-injection.md), les wrappers shell à la recherche d’[injection de commande](../pentesting-web/command-injection.md), les URL choisies à la recherche de [SSRF](../pentesting-web/ssrf-server-side-request-forgery/README.md), les opérations sur les fichiers à la recherche de traversal, les évaluateurs de templates/code à la recherche de RCE, et les parseurs d’objets à la recherche de [désérialisation non sécurisée](../pentesting-web/deserialization/README.md).

Pour chaque piste, prouvez cette chaîne :<sup>[[2]](#references)</sup>

```text
attacker-controlled source
  -> model/context influence
  -> selected tool and arguments
  -> effective identity/credential
  -> capability or vulnerable sink
  -> externally verified state change or data egress
```

Une intégration en lecture seule reste exploitable dès lors qu’un composant ultérieur peut publier ce qu’elle a lu. Testez les réponses ordinaires ainsi que les moyens d’egress moins évidents, comme les liens contrôlés par l’attaquant, la récupération automatique d’images, les webhooks, les logs, les rapports, les compteurs, les notifications et les messages envoyés à d’autres agents.<sup>[[2]](#references)</sup>

## Actions sur les objectifs

Après avoir confirmé une action, évaluez l’ensemble du rayon d’impact au lieu de vous arrêter au premier effet visible :<sup>[[2]](#references)</sup>

- **Exfiltration :** des secrets, des dossiers utilisateur, des fichiers internes, des données de conversation ou du contenu de prompt/contexte sont transmis par un canal observable.
- **Action non autorisée :** l’agent utilise des capacités d’écriture légitimes au profit de l’attaquant.
- **Déni de service :** des outils destructeurs ou des opérations coûteuses répétées affectent l’intégrité ou la disponibilité.
- **Persistance :** une mémoire empoisonnée, du contenu indexé, un état de confiance ou des modifications du runtime subsistent après la fin de la session ou la suppression de la source.
- **Propagation :** un pair de confiance consomme le message ou l’état partagé de l’agent compromis et répète l’action avec ses propres outils et identifiants.

La sévérité doit dépendre des données accessibles, des privilèges effectifs, de l’exploitabilité du sink, de l’egress, de la persistance et de la propagation — et non du caractère surprenant du texte produit par le modèle.<sup>[[2]](#references)</sup>

## Contrôles à valider pendant l’évaluation

Les filtres de prompt et un meilleur system prompt peuvent augmenter le coût pour l’attaquant, mais ne doivent pas être considérés comme des limites d’autorisation. Validez les contrôles ci-dessous en réexécutant la même chaîne via les entrées directes, le contenu indirect, la mémoire, les outils et les agents pairs :<sup>[[2]](#references)</sup>

- Une couche de stratégie déterministe vérifie l’utilisateur authentifié, le tenant, l’objet, l’action et la destination lors de **chaque invocation d’outil** ; le modèle ne peut pas fournir ni remplacer l’identité de l’appelant.
- Les capacités de lecture et d’écriture utilisent des identifiants distincts, à privilèges minimaux et de courte durée ; les outils à fort impact ne sont exposés qu’au moment opportun et ne s’exécutent jamais automatiquement à partir du contenu ingéré.
- L’egress réseau et les destinations internes sont définis par des listes d’autorisations indépendantes des URL choisies par le modèle ; l’accès du runtime aux endpoints de métadonnées, aux secrets montés et aux services voisins est bloqué, sauf nécessité.
- L’interface d’approbation est générée à partir de la requête structurée canonique et affiche les arguments exacts, l’identité, la destination, les objets concernés et les effets secondaires — et non un résumé libre du modèle.
- La réussite est vérifiée auprès du système de destination ou du système de référence. Le récit de l’agent, une demande d’appel d’outil ou une redirection HTTP ne prouvent pas que le changement d’état annoncé a eu lieu.
- Les entrées de mémoire et de récupération conservent leur provenance et leurs étiquettes de confiance, peuvent être invalidées et font l’objet d’une nouvelle autorisation lors de leur utilisation pour une action ultérieure.
- Les messages inter-agents sont authentifiés et autorisés comme des requêtes non fiables ; la réputation d’un pair ou sa fiche d’agent ne délègue pas implicitement les outils du destinataire.

## References

- [1] [Top 10 OWASP des applications agentiques pour 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [2] [Le guide du hacker pour attaquer les agents IA](https://darkmarc.substack.com/p/the-hackers-guide-to-attacking-ai)
- [3] [À quel point est-il vraiment difficile de faire sortir un agent IA de son sandbox ?](https://www.nccgroup.com/research/how-hard-is-it-really-to-break-an-ai-agent-out-of-its-sandbox/)
- [4] [Sous-agents dans le SDK](https://code.claude.com/docs/en/agent-sdk/subagents)
{{#include ../banners/hacktricks-training.md}}
