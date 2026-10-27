# Méthodologie de sécurité des agents IA

{{#include ../banners/hacktricks-training.md}}

Une évaluation d’agent doit suivre le chemin **d’une entrée contrôlée par l’attaquant jusqu’à un effet observable de l’extérieur**. Le jailbreaking, les changements de caractère et la divulgation du system prompt prouvent qu’un canal de raisonnement peut être influencé, mais la découverte à fort impact réside dans la chaîne qui mène à l’accès aux données, à une action non autorisée via un outil, à un point d’injection en aval, à la persistance ou à un autre agent.<sup>[[2]](#references)</sup>

L’[OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) est utile pour catégoriser la couverture (détournement d’objectif, mauvais usage des outils, abus de privilèges, chaîne d’approvisionnement, exécution de code, empoisonnement de la mémoire, confiance inter-agents, défaillances en cascade, confiance humaine et agents voyous). Utilisez ces catégories après avoir établi un chemin d’attaque de bout en bout, plutôt que de considérer un texte inattendu généré par le modèle comme la fin du test.<sup>[[1]](#references)[[2]](#references)</sup>

## Cartographier la cible

Avant de rédiger des payloads, consignez ces cinq dimensions pour chaque workflow d’agent :<sup>[[2]](#references)</sup>

| Dimension | Éléments à répertorier | Question de sécurité |
|---|---|---|
| **Entrée non fiable** | Paramètres de chat/API, URL, documents, e-mails, tickets, entrées de calendrier, extraits récupérés, mémoire, résultats d’outils et messages d’agents pairs | Où un attaquant peut-il placer du contenu qui sera ensuite ajouté au contexte du modèle ? |
| **Outils** | Noms et schémas des outils, effets secondaires, exécution automatique, comportement de confirmation et outils chargés dynamiquement | Quels appels lisent des secrets, modifient l’état, envoient des messages, suppriment des données, exécutent du code ou transfèrent de la valeur ? |
| **Autorité** | Délégation utilisateur, comptes de service, jetons API, durée de vie des identifiants, portée du tenant/de la ressource et accès réseau | Sous quelle identité chaque appel s’exécute-t-il, et l’autorisation est-elle vérifiée à nouveau à la limite de l’outil ? |
| **Traitement** | Constructeurs de requêtes, shells, récupérateurs d’URL, moteurs de templates, interpréteurs, parseurs, opérations sur les fichiers et désérialiseurs | Où les données générées par le modèle deviennent-elles de la syntaxe pour un autre interpréteur ? |
| **Sortie** | Réponses, Markdown/HTML rendu, liens, récupération d’images, webhooks, e-mails, fichiers, journaux, rapports, métriques et échanges entre agents pairs | Quel canal observable peut transmettre un secret ou déclencher une requête secondaire ? |

Ne réduisez pas cette analyse à une liste d’intégrations annoncées. Un livrable utile relie chaque source à la position exacte qu’elle atteint dans le contexte, aux outils disponibles à ce stade, aux identifiants utilisés par chaque outil, à l’interpréteur en aval et à chaque voie d’exfiltration. Un même outil peut avoir un faible impact avec un jeton de lecture propre à l’utilisateur et être critique avec un identifiant partagé d’administrateur.<sup>[[2]](#references)</sup>

## Reconnaissance

### Cartographier chaque voie de livraison et d’ingestion

Commencez par la surface de livraison (Web, mobile, API, e-mail, plateforme de chat, extension de navigateur) et interceptez le trafic entre le client et le backend. Examinez les champs masqués par l’interface, les paramètres de recherche/complétion automatique/filtrage, les objets d’état de conversation, les tâches de téléversement et d’indexation, les réponses des outils et le trafic des sous-agents. Les clients réservés au mobile peuvent nécessiter un émulateur et de l’instrumentation pour contourner l’épinglage de certificat avant que le véritable schéma des requêtes soit visible.<sup>[[2]](#references)</sup>

Cartographiez ensuite la pile sous le modèle : framework d’orchestration, assemblage des prompts, magasins de récupération et de mémoire, runtime (par exemple Python, conteneur ou WASM), volumes montés, services hôtes, API internes, accès aux métadonnées cloud et réseaux voisins. Les paramètres par défaut du framework comptent, car certains « appels d’outils » sont implémentés en générant ou en évaluant du code ; la limite du runtime/sandbox détermine si le résultat reste confiné.<sup>[[2]](#references)</sup>

### Identifier le routage avec des probes non destructives

Comparez une requête dans le périmètre à plusieurs requêtes sans rapport, en conservant la réponse complète, le code d’état, la latence et le comportement du streaming. Un rejet stable avant tout raisonnement propre à la tâche peut indiquer un gateway/classifieur distinct ; un refus contextuel suggère que la requête a atteint le modèle ; une réponse vide ou purement extractive peut indiquer une recherche par mots-clés ou une récupération limitée. Considérez ces éléments comme des hypothèses et confirmez-les en rejouant la même probe via d’autres champs d’API et voies d’ingestion.<sup>[[2]](#references)</sup>

La reconnaissance est terminée lorsque l’évaluation peut désigner la première source contrôlée par l’attaquant qui modifie le comportement de l’agent **et** les outils, identités, interpréteurs et sorties accessibles depuis cette source.<sup>[[2]](#references)</sup>

## Exploitation : franchir une limite de confiance

Testez les canaux, pas uniquement la formulation du prompt. Commencez par une injection directe afin d’établir ce que bloque le point d’entrée visible, puis répétez une intention équivalente via les voies moins visibles ci-dessous :<sup>[[2]](#references)</sup>

- **Contenu indirect :** pages, fichiers, e-mails, tickets, métadonnées, texte alternatif, commentaires HTML, texte hors écran ou caractères de largeur nulle. Consultez [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection) pour les techniques de livraison des payloads.
- **Récupération et mémoire :** empoisonnez du contenu qui sera récupéré ultérieurement ou un état qui sera rechargé lors de sessions ultérieures. Notez si la suppression de la source originale élimine le comportement.
- **Sortie d’outil et agents pairs :** placez le marqueur dans une réponse d’outil ou un message entre agents pour vérifier si le trafic interne contourne les filtres appliqués uniquement à l’entrée utilisateur et à la sortie finale.
- **Chaîne d’approvisionnement :** examinez les descripteurs d’outils, plugins, serveurs connectés, skills, modèles et dépendances comme des sources d’instructions fiables. Pour les tests spécifiques à MCP, consultez [MCP Servers](AI-MCP-Servers.md#mcp-vulns).
- **Approbation humaine :** comparez l’appel structuré réel de l’outil au texte d’approbation généré par le modèle. Vérifiez si l’influence de l’attaquant peut omettre la destination, la portée, les objets concernés ou les effets secondaires irréversibles.

Commencez par un marqueur unique et inoffensif. Conservez l’artefact source, le contexte assemblé s’il est observable, l’appel d’outil sélectionné, les données d’approbation, la requête/réponse backend et l’état final. Cela permet de distinguer une influence d’une affirmation hallucinée selon laquelle une action aurait eu lieu.<sup>[[2]](#references)</sup>

### Texte imitant une politique dans un évaluateur de risque d’outil

Un filtre d’outil basé sur un modèle peut recevoir du texte contrôlé par l’attaquant dans un contexte de classification par ailleurs utile. Par exemple, le `AutoModeMiddleware` expérimental de LangChain transmet à un évaluateur TypeSafe `is_risky` un appel d’outil proposé, ses arguments, une description facultative de l’outil et jusqu’à 30 messages récents. Il bloque les outils configurés lorsque la probabilité Noul renvoyée est supérieure ou égale à `0.5` ; les outils non répertoriés ne sont pas classifiés par ce middleware.<sup>[[5]](#references)</sup> TypeSafe avertit également que du texte adversarial dans l’état peut influencer une classification, même lorsque cet état est censé être constitué de données.<sup>[[6]](#references)</sup>

Une **fausse politique** diffère d’une simple prétention à être un message système. Elle introduit des étiquettes ou définitions de risque alternatives dans un état de moindre confiance et incite l’évaluateur à les utiliser au lieu des critères définis par le développeur. Dans le test de Datadog, un `profile_description` modifiable par l’utilisateur était copié dans les arguments de l’outil avec `can_edit:false`. Son texte, formulé comme une politique, soutenait qu’une tentative d’écriture présentait peu de risques, car une vérification distincte des permissions devait la rejeter avant toute modification. Sur 40 exécutions, le score moyen `is_risky` est passé de `0.893` à `0.290`, tandis qu’une comparaison directe par usurpation de rôle affichait une moyenne de `0.905`. Le fait que la moyenne passe sous `0.5` ne prouve pas que chaque appel individuel a franchi le filtre, et l’expérience n’a **pas** démontré qu’une écriture non autorisée avait abouti.<sup>[[7]](#references)</sup>

Lors du test de cette limite, distinguez le verdict du classifieur du résultat réel de l’autorisation de l’outil. Vérifiez quels champs modifiables parviennent à l’évaluateur, comparez la même action proposée avec et sans texte imitant une politique, et vérifiez indépendamment l’état final. Une vérification distincte des permissions doit toujours s’appuyer sur les autorisations du demandeur authentifié, et non sur les droits du compte de service du connecteur.<sup>[[7]](#references)</sup> Consultez [prompt-filter bypasses](AI-Prompts.md#prompt-waf-bypass) pour d’autres modes de défaillance des classifieurs ; [LLM gateway trust boundaries](AI-LLM-Gateway-Security.md) traite d’une autre limite de routage et d’identifiants.

### Isolation du contexte des sous-agents

Un sous-agent non fork du Claude Agent SDK reçoit son propre `AgentDefinition.prompt`, le prompt de délégation et les outils mis à sa disposition, mais pas le system prompt ni la conversation du parent. Si `tools` est omis de sa définition, il hérite des outils disponibles pour les sous-agents ; le fichier projet `CLAUDE.md` peut tout de même être chargé. Une restriction du prompt appliquée uniquement au parent constitue donc une limite peu fiable lorsque l’enfant peut utiliser les mêmes outils de système de fichiers ou d’exécution.<sup>[[4]](#references)</sup>

Testez cette limite en comparant une requête directe refusée par le parent à la même tâche déléguée à un sous-agent nommé. NCC Group rapporte qu’une énumération de fichiers du système d’exploitation refusée a réussi lorsqu’elle a été reformulée pour un enfant comme une inoffensive « carte de la structure ».<sup>[[3]](#references)</sup>

Examinez les appels d’outils réels de l’enfant et sa liste effective d’outils autorisés, et pas seulement la réponse finale du parent ; vérifiez si l’enfant a accédé à des fichiers auxquels le parent n’aurait pas dû accéder.<sup>[[4]](#references)</sup> Il s’agit d’une défaillance de transmission des garde-fous, et non d’une preuve de contournement d’une [Python sandbox](../generic-methodologies-and-resources/python/bypass-python-sandboxes/) ou d’évasion de conteneur.<sup>[[3]](#references)[[4]](#references)</sup>

### Agents GUI mobiles : instructions à l’écran et redirection d’action

Un agent GUI mobile peut envoyer chaque capture d’écran à un modèle cloud avant de choisir la prochaine action inter-applications. Pour tester une **injection visuelle indirecte**, placez du texte contrôlé par l’attaquant dans un SMS, un e-mail ou une page que l’agent examinera pendant une tâche autorisée. Comparez un prompt de tâche direct à la même instruction visible uniquement dans la capture d’écran, puis examinez l’action suivante et toute décision concernant une opération à haut risque. Dans l’assistant évalué, `checkPrompt` côté client filtrait le texte des tâches directes, mais n’appliquait pas de filtrage équivalent au contenu des captures d’écran. Il s’agit d’une variante mobile et inter-applications de l’[injection de capture d’écran dans les navigateurs agentiques](../generic-methodologies-and-resources/phishing-methodology/ai-agent-mode-phishing-abusing-hosted-agent-browsers.md), et non d’un moyen de contourner l’authentification des composants Android.<sup>[[9]](#references)</sup>

Un test illustratif d’effet secondaire utilise un formulaire contrôlé par l’attaquant qui demande à l’agent de remplir des champs sensibles, puis sollicite un clic humain sur « téléverser », tandis que la page soumet les champs renseignés dès qu’ils changent. Le transfert à un humain ne protège pas les données déjà envoyées par le code de la page ; vérifiez la soumission réelle plutôt que de considérer le récit de l’agent comme une preuve. La source présente cela comme un scénario possible, et non comme une compromission démontrée de chaque assistant.<sup>[[9]](#references)</sup>

Le **TOCTOU GUI / redirection d’action** est un mode de défaillance distinct : l’agent planifie une saisie à partir d’un écran observé à `t0`, mais l’interface au premier plan change avant l’injection de la saisie à `t1`.<sup>[[8]](#references)</sup> Une capture d’écran ultérieure à `t2` ne peut pas annuler une action déjà effectuée.<sup>[[9]](#references)</sup> Dans le cadre d’un test Android autorisé, le workflow réutilisable est le suivant :<sup>[[8]](#references)</sup>

1. Repérez les coordonnées à l’écran du contrôle cible et affichez un contrôle inoffensif au même emplacement dans une application contrôlée.
2. Laissez ce support visible jusqu’à ce que l’agent l’observe, puis déclenchez une transition normale au premier plan pendant le délai entre l’observation et l’action.
3. Vérifiez si le toucher prévu atteint le contrôle de la nouvelle application et confirmez l’état obtenu dans l’application cible, au lieu de vous fier au récit de l’agent.

L’étude originale sur la redirection d’action démontre cette technique avec une application ne disposant d’aucune permission dangereuse ; elle décrit également la répétition de la transition via la boucle de récupération de tâche de l’agent pour les workflows en plusieurs étapes.<sup>[[8]](#references)</sup>

Ne **supposez pas** que le principe fonctionne à l’identique avec tous les assistants. Lors de l’évaluation de Doubao, `OpClickUI` ignorait les clics si l’Activity de premier niveau avait changé et comparait les captures d’écran lorsque `OpOpenApp` figurait dans les trois étapes précédentes. Les simples clics, appuis longs et doubles clics n’offraient donc que peu de possibilités fiables de synchronisation contrôlées par l’attaquant. `OpTypeText`, `OpSwipeUI` et `OpScrollWheelAction` ne disposaient pas de protections équivalentes, mais le rapport considérait leur impact pratique comme plus limité.<sup>[[9]](#references)</sup>

## Exécution : démontrer l’impact réel

Il existe deux voies distinctes entre l’influence et l’impact :<sup>[[2]](#references)</sup>

1. **Abus de capacité :** l’outil autorisé effectue déjà l’objectif. Par exemple, lire l’enregistrement d’un tenant et l’écrire dans un rapport visible par l’attaquant, envoyer un e-mail, modifier des enregistrements, supprimer un fichier ou initier un paiement. Aucune vulnérabilité logicielle secondaire n’est nécessaire.
2. **Exploitation d’un point de traitement en aval :** la sortie du modèle influencée par l’attaquant devient de la syntaxe pour un autre composant. Examinez les requêtes de base de données pour repérer l’[injection SQL](../pentesting-web/sql-injection/README.md) ou l’[injection NoSQL](../pentesting-web/nosql-injection.md), les wrappers shell pour l’[injection de commande](../pentesting-web/command-injection.md), les URL choisies pour le [SSRF](../pentesting-web/ssrf-server-side-request-forgery/README.md), les opérations sur les fichiers pour la traversée de répertoires, les évaluateurs de templates/code pour le RCE, et les parseurs d’objets pour la [désérialisation non sécurisée](../pentesting-web/deserialization/README.md).

Pour chaque scénario envisagé, démontrez cette chaîne :<sup>[[2]](#references)</sup>

```text
attacker-controlled source
  -> model/context influence
  -> selected tool and arguments
  -> effective identity/credential
  -> capability or vulnerable sink
  -> externally verified state change or data egress
```

Une intégration en lecture seule reste exploitable si un composant en aval peut publier ce qu’elle a lu. Testez les réponses ordinaires ainsi que les voies de sortie moins évidentes, comme les liens contrôlés par l’attaquant, le chargement automatique d’images, les webhooks, les journaux, les rapports, les compteurs, les notifications et les messages envoyés à d’autres agents.<sup>[[2]](#references)</sup>

## Actions sur les objectifs

Après avoir confirmé une action, évaluez l’ensemble du rayon d’impact au lieu de vous arrêter au premier effet visible :<sup>[[2]](#references)</sup>

- **Exfiltration :** des secrets, des données utilisateur, des fichiers internes, des données de conversation ou du contenu de prompt/context quittent le système par un canal observable.
- **Action non autorisée :** l’agent utilise des capacités légitimes d’écriture au profit de l’attaquant.
- **Déni de service :** des outils destructeurs ou des opérations coûteuses répétées nuisent à l’intégrité ou à la disponibilité.
- **Persistance :** une mémoire empoisonnée, du contenu indexé, un état de confiance ou des changements d’exécution subsistent après la fin de la session ou la suppression de la source.
- **Propagation :** un pair de confiance consomme le message ou l’état partagé de l’agent compromis et répète l’action avec ses propres outils et identifiants.

La gravité doit dépendre des données accessibles, des privilèges effectifs, de l’exploitabilité du point de sortie, de l’exfiltration, de la persistance et de la propagation, et non du caractère surprenant du texte produit par le modèle.<sup>[[2]](#references)</sup>

## Contrôles à valider pendant l’évaluation

Les filtres de prompt et une meilleure invite système peuvent augmenter le coût pour l’attaquant, mais ne doivent pas être considérés comme des limites d’autorisation. Validez les contrôles ci-dessous en réexécutant la même chaîne via une entrée directe, du contenu indirect, la mémoire, les outils et les agents pairs :<sup>[[2]](#references)</sup>

- Une couche de politique déterministe vérifie l’utilisateur authentifié, le locataire, l’objet, l’action et la destination à **chaque invocation d’outil** ; le modèle ne peut pas fournir ni remplacer l’identité de l’appelant.
- Les capacités de lecture et d’écriture utilisent des identifiants distincts, à privilèges minimaux et à durée de vie courte ; les outils à fort impact ne sont exposés qu’au moment opportun et ne s’exécutent jamais automatiquement à partir du contenu ingéré.
- Les sorties réseau et les destinations internes sont autorisées par liste blanche indépendamment des URL choisies par le modèle ; l’accès de l’environnement d’exécution aux endpoints de métadonnées, aux secrets montés et aux services voisins est bloqué sauf nécessité.
- L’interface d’approbation est générée à partir de la requête structurée canonique et affiche les arguments exacts, l’identité, la destination, les objets affectés et les effets secondaires, et non un résumé libre du modèle.
- La réussite est vérifiée auprès du système de destination ou du système de référence. Le récit de l’agent, une demande d’appel d’outil ou une redirection HTTP ne prouve pas le changement d’état revendiqué.
- Les entrées de mémoire et de récupération conservent leur provenance et leurs étiquettes de confiance, peuvent être invalidées et sont soumises à une nouvelle autorisation lors d’une action ultérieure.
- Les messages entre agents sont authentifiés et autorisés comme des requêtes non fiables ; la réputation d’un pair ou sa fiche d’agent ne délègue pas implicitement les outils du destinataire.

Pour les fiches d’agent A2A, les flux de tâches et leur surface d’attaque, consultez [Sécurité du protocole A2A](AI-A2A-Protocol.md).

## References

- [1] [Top 10 OWASP des applications agentiques pour 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [2] [Le guide du hacker pour attaquer les agents IA](https://darkmarc.substack.com/p/the-hackers-guide-to-attacking-ai)
- [3] [Est-il vraiment difficile de faire sortir un agent IA de son bac à sable ?](https://www.nccgroup.com/research/how-hard-is-it-really-to-break-an-ai-agent-out-of-its-sandbox/)
- [4] [Sous-agents dans le SDK](https://code.claude.com/docs/en/agent-sdk/subagents)
- [5] [Code source du middleware Auto Mode de LangChain TypeSafe](https://github.com/langchain-ai/langchain/blob/master/libs/partners/typesafe/langchain_typesafe/experimental/middleware/auto_mode.py)
- [6] [Irrégularité du modèle TypeSafe AI Jev : contenu adversarial](https://docs.typesafe.ai/model-jaggedness/jev-1.13#adversarial-content)
- [7] [Jev en tant que juge : comment une politique contrefaite influence Jev](https://securitylabs.datadoghq.com/articles/jev-as-a-judge-how-counterfeit-policy-steers-jev/)
- [8] [Manipulation sans permission : peut-on faire confiance aux agents d’interface graphique alimentés par de grands modèles multimodaux ?](https://arxiv.org/html/2601.12349v1)
- [9] [Quand un assistant IA entre dans la chaîne d’attaque d’un hacker | Analyse de sécurité de Doubao Phone](https://www.darknavy.org/blog/security_analysis_of_doubao_phone/)
{{#include ../banners/hacktricks-training.md}}
