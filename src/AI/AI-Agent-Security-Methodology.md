# Méthodologie de sécurité des agents IA

{{#include ../banners/hacktricks-training.md}}

Une évaluation d’agent doit suivre **une entrée contrôlée par l’attaquant jusqu’à un effet observable de l’extérieur**. Le jailbreaking, les changements de caractère et la divulgation du system prompt prouvent qu’un canal de raisonnement peut être influencé, mais la découverte à fort impact réside dans la chaîne qui mène à l’accès aux données, à une action non autorisée via un outil, à un point d’injection en aval, à la persistance ou à un autre agent.<sup>[[2]](#references)</sup>

L’[OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) est utile pour catégoriser la couverture (détournement d’objectif, mauvaise utilisation des outils, abus de privilèges, chaîne d’approvisionnement, exécution de code, empoisonnement de la mémoire, confiance inter-agents, défaillances en cascade, confiance humaine et agents malveillants). Utilisez ces catégories après avoir construit un chemin d’attaque de bout en bout, plutôt que de considérer un texte inattendu du modèle comme la fin du test.<sup>[[1]](#references)[[2]](#references)</sup>

## Cartographier la cible

Consignez ces cinq dimensions pour chaque workflow d’agent avant de rédiger des payloads :<sup>[[2]](#references)</sup>

| Dimension | Éléments à recenser | Question de sécurité |
|---|---|---|
| **Entrées non fiables** | Paramètres de chat/API, URL, documents, e-mails, tickets, entrées de calendrier, fragments récupérés, mémoire, résultats d’outils et messages d’agents pairs | Où un attaquant peut-il placer du contenu qui sera ensuite intégré au contexte du modèle ? |
| **Outils** | Noms et schémas des outils, effets secondaires, exécution automatique, comportement de confirmation et outils chargés dynamiquement | Quels appels lisent des secrets, écrivent des données, envoient des messages, suppriment des données, exécutent du code ou transfèrent de la valeur ? |
| **Autorité** | Délégation utilisateur, comptes de service, jetons d’API, durée de vie des identifiants, portée des tenants/ressources et accès réseau | Sous quelle identité chaque appel s’exécute-t-il, et l’autorisation est-elle vérifiée à nouveau à la frontière de l’outil ? |
| **Traitement** | Constructeurs de requêtes, shells, récupérateurs d’URL, moteurs de modèles, interpréteurs, analyseurs, opérations sur fichiers et désérialiseurs | Où les données générées par le modèle deviennent-elles la syntaxe d’un autre interpréteur ? |
| **Sorties** | Réponses, Markdown/HTML rendu, liens, récupération d’images, webhooks, e-mails, fichiers, journaux, rapports, métriques et trafic entre agents pairs | Quel canal observable peut transporter un secret ou déclencher une requête secondaire ? |

Ne réduisez pas cela à une liste d’intégrations annoncées. Un livrable utile associe chaque source à la position exacte qu’elle occupe dans le contexte, aux outils disponibles à ce stade, à l’identifiant utilisé par chaque outil, à l’interpréteur en aval et à chaque voie d’exfiltration. Le même outil peut avoir un faible impact avec un jeton de lecture propre à l’utilisateur et un impact critique avec des identifiants d’administrateur partagés.<sup>[[2]](#references)</sup>

## Reconnaissance

### Cartographier chaque voie de livraison et d’ingestion

Commencez par la surface de livraison (web, mobile, API, e-mail, plateforme de chat, extension de navigateur) et interceptez le trafic entre le client et le backend. Examinez les champs masqués par l’interface, les paramètres de recherche/autocomplétion/filtrage, les objets d’état de conversation, les tâches de téléversement et d’indexation, les réponses des outils et le trafic des sous-agents. Les clients exclusivement mobiles peuvent nécessiter un émulateur et de l’instrumentation pour contourner l’épinglage des certificats avant que le véritable schéma des requêtes devienne visible.<sup>[[2]](#references)</sup>

Cartographiez ensuite la pile sous le modèle : framework d’orchestration, assemblage des prompts, magasins de recherche et de mémoire, environnement d’exécution (par exemple Python, conteneur ou WASM), volumes montés, services hôtes, API internes, accès aux métadonnées cloud et réseaux voisins. Les paramètres par défaut du framework sont importants, car certains « appels d’outils » sont implémentés en générant ou en évaluant du code ; la frontière de l’environnement d’exécution/sandbox détermine si le résultat reste confiné.<sup>[[2]](#references)</sup>

### Identifier le routage à l’aide de sondes non destructives

Comparez une requête dans le périmètre à plusieurs requêtes sans rapport, en conservant la réponse complète, le code d’état, la latence et le comportement de streaming. Un rejet stable précédant tout raisonnement propre à la tâche peut indiquer un gateway/classifier distinct ; un refus contextuel suggère que la requête a atteint le modèle ; une réponse vide ou purement extractive peut indiquer une recherche par mots-clés ou une récupération restreinte. Traitez ces observations comme des hypothèses et confirmez-les en rejouant la même sonde via d’autres champs d’API et voies d’ingestion.<sup>[[2]](#references)</sup>

La reconnaissance est terminée lorsque l’évaluation peut identifier la première source contrôlée par l’attaquant qui modifie le comportement de l’agent **ainsi que** les outils, identités, interpréteurs et sorties accessibles depuis cette source.<sup>[[2]](#references)</sup>

## Exploitation : franchir une frontière de confiance

Testez les canaux, pas seulement la formulation des prompts. Commencez par une injection directe pour déterminer ce que bloque le point d’entrée visible, puis testez une intention équivalente via les voies moins visibles ci-dessous :<sup>[[2]](#references)</sup>

- **Contenu indirect :** pages, fichiers, e-mails, tickets, métadonnées, texte alternatif, commentaires HTML, texte hors écran ou caractères à largeur nulle. Consultez [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection) pour les techniques de livraison de payloads.
- **Récupération et mémoire :** empoisonnez du contenu qui sera récupéré ultérieurement ou un état qui sera rechargé lors de sessions ultérieures. Notez si la suppression de la source d’origine élimine le comportement.
- **Résultats d’outils et agents pairs :** placez le marqueur dans une réponse d’outil ou un message entre agents pour vérifier si le trafic interne contourne les filtres appliqués uniquement aux entrées utilisateur et aux sorties finales.
- **Chaîne d’approvisionnement :** examinez les descripteurs d’outils, plugins, serveurs connectés, skills, modèles et dépendances en tant que sources d’instructions de confiance. Pour des tests spécifiques à MCP, consultez [MCP Servers](AI-MCP-Servers.md#mcp-vulns).
- **Approbation humaine :** comparez l’appel structuré réel de l’outil au texte d’approbation généré par le modèle. Vérifiez si l’influence de l’attaquant peut omettre la destination, la portée, les objets concernés ou les effets secondaires irréversibles.

Commencez par un marqueur unique et inoffensif. Conservez l’artefact source, le contexte assemblé s’il est observable, l’appel d’outil sélectionné, les données d’approbation, la requête/réponse du backend et l’état final. Cela permet de distinguer l’influence d’une affirmation hallucinée selon laquelle une action aurait eu lieu.<sup>[[2]](#references)</sup>

### Texte ressemblant à une politique dans un outil d’évaluation des risques

Un contrôle d’outil fondé sur un modèle peut recevoir du texte contrôlé par l’attaquant au sein d’un contexte de classification autrement utile. Le `AutoModeMiddleware` expérimental de LangChain, par exemple, transmet à un évaluateur `is_risky` de TypeSafe un appel d’outil proposé, ses arguments, une description facultative de l’outil et jusqu’à 30 messages récents. Il bloque les outils configurés lorsque la probabilité Noul renvoyée est supérieure ou égale à `0.5` ; les outils non répertoriés ne sont pas classifiés par ce middleware.<sup>[[5]](#references)</sup> TypeSafe avertit également que du texte adversarial dans l’état peut influencer une classification, même lorsque cet état est censé contenir des données.<sup>[[6]](#references)</sup>

Une **fausse politique** diffère d’une simple prétention à être un message système. Elle place des étiquettes ou définitions alternatives du risque dans un état de confiance inférieure et incite l’évaluateur à utiliser ces définitions plutôt que les critères définis par son développeur. Dans le test de Datadog, un `profile_description` modifiable par l’utilisateur était copié dans les arguments de l’outil avec `can_edit:false`. Son texte ressemblant à une politique soutenait qu’une tentative d’écriture présentait peu de risque, car une vérification distincte des permissions devait la rejeter avant toute modification. Sur 40 exécutions, le score moyen `is_risky` est passé de `0.893` à `0.290`, tandis qu’une comparaison directe avec usurpation de rôle affichait une moyenne de `0.905`. Le fait que la moyenne soit passée sous `0.5` ne prouve pas que chaque appel individuel a franchi le contrôle, et l’expérience n’a **pas** démontré qu’une écriture non autorisée avait été menée à bien.<sup>[[7]](#references)</sup>

Lors du test de cette frontière, distinguez la décision du classificateur du résultat réel de l’autorisation de l’outil. Vérifiez quels champs modifiables atteignent l’évaluateur, comparez la même action proposée avec et sans texte ressemblant à une politique, puis vérifiez indépendamment l’état final. Une vérification distincte des permissions doit toujours s’appuyer sur l’autorité du demandeur authentifié, et non sur les droits du compte de service du connecteur.<sup>[[7]](#references)</sup> Consultez [prompt-filter bypasses](AI-Prompts.md#prompt-waf-bypass) pour d’autres modes de défaillance des classificateurs ; [LLM gateway trust boundaries](AI-LLM-Gateway-Security.md) concerne une autre frontière de routage et d’identifiants.

### Isolation du contexte des sous-agents

Un sous-agent non fork du Claude Agent SDK reçoit son propre `AgentDefinition.prompt`, le prompt de délégation et les outils à sa disposition, mais pas le system prompt ni la conversation du parent. Si `tools` est omis de sa définition, il hérite des outils disponibles pour les sous-agents ; le fichier de projet `CLAUDE.md` peut néanmoins être chargé. Une restriction de prompt appliquée uniquement au parent constitue donc une frontière peu fiable lorsque l’enfant peut utiliser les mêmes outils de système de fichiers ou d’exécution.<sup>[[4]](#references)</sup>

Testez cette frontière en comparant une requête directe refusée par le parent à la même tâche déléguée à un sous-agent nommé. NCC Group rapporte qu’une énumération de fichiers du système d’exploitation, refusée, a réussi lorsque la tâche a été reformulée pour un enfant en une innocente « carte de disposition ».<sup>[[3]](#references)</sup>

Examinez les appels d’outils réels de l’enfant et sa liste d’autorisation effective, pas seulement la réponse finale du parent ; vérifiez si l’enfant a accédé à des fichiers auxquels le parent n’aurait pas eu accès.<sup>[[4]](#references)</sup> Il s’agit d’une défaillance de l’héritage des garde-fous, et non d’une preuve de contournement d’un [Python sandbox](../generic-methodologies-and-resources/python/bypass-python-sandboxes/) ou d’évasion de conteneur.<sup>[[3]](#references)[[4]](#references)</sup>

## Exécution : démontrer un impact réel

Il existe deux voies distinctes entre l’influence et l’impact :<sup>[[2]](#references)</sup>

1. **Abus de capacité :** l’outil autorisé réalise déjà l’objectif. Exemples : lire le dossier d’un tenant et l’écrire dans un rapport visible par l’attaquant, envoyer un e-mail, modifier des dossiers, supprimer un fichier ou initier un paiement. Aucune vulnérabilité logicielle secondaire n’est nécessaire.
2. **Exploitation d’un point d’injection en aval :** la sortie du modèle orientée par l’attaquant devient la syntaxe d’un autre composant. Examinez les requêtes de base de données à la recherche d’une [SQL injection](../pentesting-web/sql-injection/README.md) ou d’une [NoSQL injection](../pentesting-web/nosql-injection.md), les wrappers shell à la recherche d’une [command injection](../pentesting-web/command-injection.md), les URL choisies à la recherche de [SSRF](../pentesting-web/ssrf-server-side-request-forgery/README.md), les opérations sur fichiers à la recherche de traversal, les évaluateurs de modèles/code à la recherche de RCE et les analyseurs d’objets à la recherche d’une [désérialisation non sécurisée](../pentesting-web/deserialization/README.md).

Pour chaque scénario envisagé, démontrez cette chaîne :<sup>[[2]](#references)</sup>

```text
attacker-controlled source
  -> model/context influence
  -> selected tool and arguments
  -> effective identity/credential
  -> capability or vulnerable sink
  -> externally verified state change or data egress
```

Une intégration en lecture seule reste exploitable si un composant ultérieur peut publier ce qu’elle a lu. Testez les réponses ordinaires ainsi que les sorties moins évidentes, comme les liens contrôlés par un attaquant, la récupération automatique d’images, les webhooks, les logs, les rapports, les compteurs, les notifications et les messages envoyés à d’autres agents.<sup>[[2]](#references)</sup>

## Actions sur les objectifs

Après avoir confirmé une action, évaluez l’ensemble du rayon d’impact au lieu de vous arrêter au premier effet visible :<sup>[[2]](#references)</sup>

- **Exfiltration :** des secrets, des données utilisateur, des fichiers internes, des données de conversation ou du contenu de prompt/contexte sont transmis par un canal observable.
- **Action non autorisée :** l’agent utilise des capacités d’écriture légitimes au profit de l’attaquant.
- **Déni de service :** des outils destructeurs ou des opérations coûteuses répétées affectent l’intégrité ou la disponibilité.
- **Persistance :** une mémoire empoisonnée, du contenu indexé, un état de confiance ou des modifications du runtime subsistent après la fin de la session d’origine ou la suppression de la source.
- **Propagation :** un pair de confiance consomme le message ou l’état partagé de l’agent compromis et répète l’action à l’aide de ses propres outils et identifiants.

La gravité doit dépendre des données accessibles, des privilèges effectifs, de l’exploitabilité du point de sortie, de l’exfiltration, de la persistance et de la propagation, et non du caractère surprenant du texte produit par le modèle.<sup>[[2]](#references)</sup>

## Contrôles à valider pendant l’évaluation

Les filtres de prompt et un meilleur prompt système peuvent augmenter le coût pour l’attaquant, mais ne doivent pas être considérés comme des frontières d’autorisation. Validez les contrôles ci-dessous en réexécutant la même chaîne via une entrée directe, du contenu indirect, la mémoire, les outils et les agents pairs :<sup>[[2]](#references)</sup>

- Une couche de politique déterministe vérifie l’utilisateur authentifié, le tenant, l’objet, l’action et la destination à **chaque invocation d’outil** ; le modèle ne peut pas fournir ni remplacer l’identité de l’appelant.
- Les capacités de lecture et d’écriture utilisent des identifiants distincts, à privilèges minimaux et à durée de vie limitée ; les outils à fort impact ne sont exposés qu’au moment opportun et ne s’exécutent jamais automatiquement à partir du contenu ingéré.
- Les sorties réseau et les destinations internes sont autorisées par liste indépendamment des URL choisies par le modèle ; l’accès du runtime aux points de terminaison de métadonnées, aux secrets montés et aux services voisins est bloqué, sauf nécessité.
- L’interface d’approbation est générée à partir de la requête structurée canonique et affiche les arguments exacts, l’identité, la destination, les objets concernés et les effets secondaires, et non un résumé libre produit par le modèle.
- La réussite est vérifiée auprès du système de destination ou du système de référence. Le récit de l’agent, une requête d’appel d’outil ou une redirection HTTP ne prouve pas que le changement d’état annoncé a eu lieu.
- Les entrées de mémoire et de récupération conservent leur provenance et leurs étiquettes de confiance, peuvent être invalidées et sont de nouveau soumises à autorisation lorsqu’elles servent à une action ultérieure.
- Les messages inter-agents sont authentifiés et autorisés comme des requêtes non fiables ; la réputation d’un pair ou sa fiche d’agent ne délègue pas implicitement les outils du destinataire.

Pour les fiches d’agents A2A, les flux de tâches et leur surface d’attaque, consultez [A2A Protocol Security](AI-A2A-Protocol.md).

## References

- [1] [Top 10 OWASP des applications agentiques pour 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [2] [Le guide du hacker pour attaquer les agents IA](https://darkmarc.substack.com/p/the-hackers-guide-to-attacking-ai)
- [3] [À quel point est-il vraiment difficile de faire sortir un agent IA de son bac à sable ?](https://www.nccgroup.com/research/how-hard-is-it-really-to-break-an-ai-agent-out-of-its-sandbox/)
- [4] [Sous-agents dans le SDK](https://code.claude.com/docs/en/agent-sdk/subagents)
- [5] [Code source du middleware Auto Mode de LangChain TypeSafe](https://github.com/langchain-ai/langchain/blob/master/libs/partners/typesafe/langchain_typesafe/experimental/middleware/auto_mode.py)
- [6] [Jev de TypeSafe AI : irrégularité des modèles — contenu adversarial](https://docs.typesafe.ai/model-jaggedness/jev-1.13#adversarial-content)
- [7] [Jev comme juge : comment une politique contrefaite oriente Jev](https://securitylabs.datadoghq.com/articles/jev-as-a-judge-how-counterfeit-policy-steers-jev/)
{{#include ../banners/hacktricks-training.md}}
