# Méthodologie de sécurité des agents IA

{{#include ../banners/hacktricks-training.md}}

Une évaluation d’agent doit suivre le chemin **d’une entrée contrôlée par l’attaquant jusqu’à un effet observable de l’extérieur**. Le jailbreaking, les changements de caractère et la divulgation du system prompt prouvent qu’un canal de raisonnement peut être influencé, mais la découverte à fort impact réside dans la chaîne menant à l’accès aux données, à une action d’outil non autorisée, à un point d’injection en aval, à la persistance ou à un autre agent.<sup>[[2]](#references)</sup>

L’[OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) est utile pour classer la couverture (détournement d’objectif, mauvaise utilisation des outils, abus de privilèges, chaîne d’approvisionnement, exécution de code, empoisonnement de la mémoire, confiance inter-agents, défaillances en cascade, confiance humaine et agents voyous). Utilisez ces catégories après avoir construit un chemin d’attaque de bout en bout, au lieu de considérer un texte inattendu du modèle comme la fin du test.<sup>[[1]](#references)[[2]](#references)</sup>

## Cartographier la cible

Pour chaque workflow d’agent, consignez ces cinq dimensions avant de rédiger des payloads :<sup>[[2]](#references)</sup>

| Dimension | Éléments à recenser | Question de sécurité |
|---|---|---|
| **Entrée non fiable** | Paramètres Chat/API, URL, documents, e-mails, tickets, entrées de calendrier, segments récupérés, mémoire, résultats d’outils et messages d’agents pairs | Où un attaquant peut-il placer du contenu qui entrera ensuite dans le contexte du modèle ? |
| **Outils** | Noms et schémas des outils, effets de bord, exécution automatique, comportement de confirmation et outils chargés dynamiquement | Quels appels lisent des secrets, modifient l’état, envoient des messages, suppriment des données, exécutent du code ou transfèrent de la valeur ? |
| **Autorité** | Délégation utilisateur, comptes de service, jetons API, durée de vie des identifiants, portée des tenants/ressources et accès réseau | Sous quelle identité chaque appel est-il exécuté, et l’autorisation est-elle vérifiée à nouveau à la frontière de l’outil ? |
| **Traitement** | Constructeurs de requêtes, shells, récupérateurs d’URL, moteurs de templates, interpréteurs, parseurs, opérations sur fichiers et désérialiseurs | Où les données générées par le modèle deviennent-elles de la syntaxe pour un autre interpréteur ? |
| **Sortie** | Réponses, Markdown/HTML rendu, liens, récupérations d’images, webhooks, e-mails, fichiers, journaux, rapports, métriques et trafic entre agents pairs | Quel canal observable peut transporter un secret ou déclencher une requête secondaire ? |

Ne réduisez pas cela à une liste d’intégrations annoncées. Un artefact utile relie chaque source à la position exacte qu’elle atteint dans le contexte, aux outils disponibles à cet endroit, aux identifiants utilisés par chaque outil, à l’interpréteur en aval et à toutes les voies de sortie. Le même outil peut avoir un faible impact avec un jeton de lecture par utilisateur et un impact critique avec des identifiants d’administrateur partagés.<sup>[[2]](#references)</sup>

## Reconnaissance

### Cartographier chaque voie de livraison et d’ingestion

Commencez par la surface de livraison (web, mobile, API, e-mail, plateforme de chat, extension de navigateur) et interceptez le trafic entre le client et le backend. Examinez les champs masqués par l’interface, les paramètres de recherche/autocomplétion/filtrage, les objets d’état de conversation, les tâches de téléversement et d’indexation, les réponses des outils et le trafic des sous-agents. Les clients uniquement mobiles peuvent nécessiter un émulateur et de l’instrumentation pour contourner l’épinglage des certificats avant que le véritable schéma de requête devienne visible.<sup>[[2]](#references)</sup>

Cartographiez ensuite la pile sous le modèle : framework d’orchestration, assemblage des prompts, magasins de récupération et de mémoire, environnement d’exécution (par exemple Python, conteneur ou WASM), volumes montés, services hôtes, API internes, accès aux métadonnées cloud et réseaux voisins. Les paramètres par défaut du framework sont importants, car certains « appels d’outils » sont réalisés en générant ou en évaluant du code ; la frontière entre l’environnement d’exécution et le sandbox détermine si le résultat reste contenu.<sup>[[2]](#references)</sup>

### Identifier le routage avec des sondes non destructives

Comparez une requête dans le périmètre à plusieurs requêtes sans rapport, en conservant la réponse complète, le code d’état, la latence et le comportement de streaming. Un rejet stable avant tout raisonnement propre à la tâche peut indiquer une passerelle/classificateur distinct ; un refus contextuel suggère que la requête a atteint le modèle ; une réponse vide ou purement extractive peut indiquer une recherche par mots-clés ou une récupération limitée. Considérez ces observations comme des hypothèses et confirmez-les en rejouant la même sonde par d’autres champs API et voies d’ingestion.<sup>[[2]](#references)</sup>

La reconnaissance est terminée lorsque l’évaluation peut nommer la première source contrôlée par l’attaquant qui modifie le comportement de l’agent **et** les outils, identités, interpréteurs et sorties accessibles depuis cette source.<sup>[[2]](#references)</sup>

## Exploitation : franchir une frontière de confiance

Testez les canaux, pas seulement la formulation des prompts. Commencez par une injection directe pour déterminer ce que bloque l’interface visible, puis répétez une intention équivalente par les voies moins visibles ci-dessous :<sup>[[2]](#references)</sup>

- **Contenu indirect :** pages, fichiers, e-mails, tickets, métadonnées, texte alternatif, commentaires HTML, texte hors écran ou caractères de largeur nulle. Consultez [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection) pour les techniques de livraison de payloads.
- **Récupération et mémoire :** empoisonnez du contenu qui sera récupéré plus tard ou un état qui sera rechargé lors de sessions ultérieures. Notez si la suppression de la source d’origine met fin au comportement.
- **Sortie d’outil et agents pairs :** placez le marqueur dans une réponse d’outil ou un message entre agents afin de vérifier si le trafic interne contourne les filtres appliqués uniquement aux entrées utilisateur et aux sorties finales.
- **Chaîne d’approvisionnement :** examinez les descripteurs d’outils, plugins, serveurs connectés, skills, modèles et dépendances en tant que sources d’instructions de confiance. Pour les tests spécifiques à MCP, consultez [MCP Servers](AI-MCP-Servers.md#mcp-vulns).
- **Approbation humaine :** comparez l’appel d’outil structuré réel au texte d’approbation généré par le modèle. Testez si l’influence de l’attaquant peut omettre la destination, la portée, les objets concernés ou les effets de bord irréversibles.

Commencez par un marqueur unique et inoffensif. Conservez l’artefact source, le contexte assemblé s’il est observable, l’appel d’outil sélectionné, les données d’approbation, la requête/réponse backend et l’état final. Cela permet de distinguer une influence d’une affirmation hallucinée selon laquelle une action aurait eu lieu.<sup>[[2]](#references)</sup>

### Texte imitant une politique dans un évaluateur de risque d’outil

Un contrôle d’outil basé sur un modèle peut recevoir du texte contrôlé par l’attaquant au sein d’un contexte de classification autrement utile. Le `AutoModeMiddleware` expérimental de LangChain, par exemple, transmet à un évaluateur `is_risky` de TypeSafe un appel d’outil proposé, ses arguments, une description d’outil facultative et jusqu’à 30 messages récents. Il bloque les outils configurés lorsque la probabilité Noul retournée est supérieure ou égale à `0.5` ; les outils non répertoriés ne sont pas classifiés par ce middleware.<sup>[[5]](#references)</sup> TypeSafe avertit également que du texte adversarial dans l’état peut influencer une classification, même lorsque cet état est censé contenir des données.<sup>[[6]](#references)</sup>

Une **fausse politique** diffère d’une simple prétention à être un message système. Elle introduit des étiquettes ou des définitions de risque alternatives dans un état de confiance inférieure et incite l’évaluateur à utiliser ces définitions plutôt que ses critères définis par le développeur. Dans le test de Datadog, un `profile_description` modifiable par l’utilisateur était copié dans les arguments de l’outil avec `can_edit:false`. Son texte imitant une politique soutenait qu’une tentative d’écriture présentait un faible risque, car une vérification distincte des autorisations devait la rejeter avant toute modification. Sur 40 exécutions, le score moyen `is_risky` est passé de `0.893` à `0.290`, tandis qu’une comparaison directe par usurpation de rôle donnait une moyenne de `0.905`. Le fait que la moyenne soit inférieure à `0.5` ne prouve pas que chaque appel individuel a franchi le contrôle, et l’expérience n’a **pas** démontré qu’une écriture non autorisée avait effectivement abouti.<sup>[[7]](#references)</sup>

Lors du test de cette frontière, distinguez le verdict du classificateur du résultat réel de l’autorisation de l’outil. Vérifiez quels champs modifiables atteignent l’évaluateur, comparez la même action proposée avec et sans texte imitant une politique, puis vérifiez indépendamment l’état final. Une vérification distincte des autorisations doit toujours utiliser les droits du demandeur authentifié, et non ceux du compte de service du connecteur.<sup>[[7]](#references)</sup> Consultez [prompt-filter bypasses](AI-Prompts.md#prompt-waf-bypass) pour d’autres modes de défaillance des classificateurs ; [LLM gateway trust boundaries](AI-LLM-Gateway-Security.md) concerne une autre frontière de routage et d’identifiants.

### Isolation du contexte des sous-agents

Un sous-agent non fork du Claude Agent SDK reçoit son propre `AgentDefinition.prompt`, le prompt de délégation et les outils dont il dispose, mais pas le system prompt ni la conversation du parent. Si `tools` est omis de sa définition, il hérite des outils disponibles pour les sous-agents ; le fichier de projet `CLAUDE.md` peut tout de même être chargé. Une restriction de prompt appliquée uniquement au parent constitue donc une frontière peu fiable lorsque l’enfant peut utiliser les mêmes outils de système de fichiers ou d’exécution.<sup>[[4]](#references)</sup>

Testez cette frontière en comparant une requête directe refusée par le parent avec la même tâche déléguée à un sous-agent nommé. NCC Group rapporte qu’une énumération de fichiers du système d’exploitation refusée a réussi lorsque la demande a été reformulée pour un enfant comme une innocente « carte de disposition ».<sup>[[3]](#references)</sup>

Examinez les appels d’outils réels de l’enfant et sa liste effective d’outils autorisés, pas seulement la réponse finale du parent ; confirmez si l’enfant a accédé à des fichiers auxquels le parent n’aurait pas eu accès.<sup>[[4]](#references)</sup> Il s’agit d’une défaillance de transmission des garde-fous, et non de la preuve d’un [Python sandbox](../generic-methodologies-and-resources/python/bypass-python-sandboxes/) ou d’une évasion de conteneur.<sup>[[3]](#references)[[4]](#references)</sup>

## Exécution : démontrer un impact réel

Il existe deux voies distinctes entre l’influence et l’impact :<sup>[[2]](#references)</sup>

1. **Abus de capacité :** l’outil autorisé réalise déjà l’objectif. Par exemple, lire l’enregistrement d’un tenant et l’écrire dans un rapport visible par l’attaquant, envoyer un e-mail, modifier des enregistrements, supprimer un fichier ou initier un paiement. Aucun bug logiciel secondaire n’est nécessaire.
2. **Exploitation d’un point d’injection en aval :** la sortie du modèle influencée par l’attaquant devient de la syntaxe pour un autre composant. Examinez les requêtes de base de données à la recherche d’[injection SQL](../pentesting-web/sql-injection/README.md) ou d’[injection NoSQL](../pentesting-web/nosql-injection.md), les wrappers shell à la recherche d’[injection de commandes](../pentesting-web/command-injection.md), les URL choisies à la recherche de [SSRF](../pentesting-web/ssrf-server-side-request-forgery/README.md), les opérations sur fichiers à la recherche de traversée de répertoires, les évaluateurs de templates/code à la recherche de RCE, et les parseurs d’objets à la recherche de [désérialisation non sécurisée](../pentesting-web/deserialization/README.md).

Pour chaque scénario envisagé, démontrez cette chaîne :<sup>[[2]](#references)</sup>

```text
attacker-controlled source
  -> model/context influence
  -> selected tool and arguments
  -> effective identity/credential
  -> capability or vulnerable sink
  -> externally verified state change or data egress
```

Une intégration en lecture seule reste exploitable si un composant ultérieur peut publier ce qu’il a lu. Testez les réponses ordinaires ainsi que les canaux d’egress moins évidents, comme les liens contrôlés par un attaquant, la récupération automatique d’images, les webhooks, les logs, les rapports, les compteurs, les notifications et les messages envoyés à d’autres agents.<sup>[[2]](#references)</sup>

## Actions sur les objectifs

Après avoir confirmé une action, évaluez l’ensemble de son rayon d’impact plutôt que de vous arrêter au premier effet visible :<sup>[[2]](#references)</sup>

- **Exfiltration :** des secrets, des données utilisateur, des fichiers internes, des données de conversation ou du contenu de prompt/contexte sont transmis par un canal observable.
- **Action non autorisée :** l’agent utilise des capacités légitimes d’écriture pour servir l’objectif de l’attaquant.
- **Déni de service :** des outils destructeurs ou des opérations coûteuses répétées affectent l’intégrité ou la disponibilité.
- **Persistance :** une mémoire empoisonnée, du contenu indexé, un état de confiance ou des modifications du runtime survivent à la session d’origine ou à la suppression de la source.
- **Propagation :** un pair de confiance consomme le message ou l’état partagé de l’agent compromis et répète l’action avec ses propres outils et identifiants.

La gravité doit dépendre des données accessibles, des privilèges effectifs, de l’exploitabilité du sink, de l’egress, de la persistance et de la propagation, et non du caractère surprenant du texte généré par le modèle.<sup>[[2]](#references)</sup>

## Contrôles à valider pendant l’évaluation

Les filtres de prompt et un meilleur prompt système peuvent augmenter le coût pour l’attaquant, mais ne doivent pas être considérés comme des limites d’autorisation. Validez les contrôles ci-dessous en relançant la même chaîne via une entrée directe, du contenu indirect, la mémoire, les outils et les agents pairs :<sup>[[2]](#references)</sup>

- Une couche de politique déterministe vérifie l’utilisateur authentifié, le tenant, l’objet, l’action et la destination à **chaque invocation d’outil** ; le modèle ne peut pas fournir ni remplacer l’identité de l’appelant.
- Les capacités de lecture et d’écriture utilisent des identifiants distincts, de moindre privilège et à durée de vie limitée ; les outils à fort impact ne sont exposés qu’au moment opportun et ne s’exécutent jamais automatiquement à partir du contenu ingéré.
- L’egress réseau et les destinations internes sont autorisés par liste blanche indépendamment des URL choisies par le modèle ; l’accès du runtime aux endpoints de métadonnées, aux secrets montés et aux services voisins est bloqué sauf nécessité.
- L’interface d’approbation est générée à partir de la requête structurée canonique et affiche les arguments exacts, l’identité, la destination, les objets concernés et les effets secondaires — pas un résumé libre du modèle.
- La réussite est vérifiée auprès du système de destination ou du système de référence. Le récit de l’agent, une demande d’appel d’outil ou une redirection HTTP ne prouvent pas que le changement d’état annoncé a eu lieu.
- Les entrées de mémoire et de récupération conservent leur provenance et leurs étiquettes de confiance, peuvent être invalidées et font l’objet d’une nouvelle autorisation lors de leur utilisation pour une action ultérieure.
- Les messages entre agents sont authentifiés et autorisés comme des requêtes non fiables ; la réputation d’un pair ou sa fiche d’agent ne délègue pas implicitement les outils du destinataire.

## References

- [1] [Top 10 OWASP des applications agentiques pour 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [2] [Le guide du hacker pour attaquer les agents IA](https://darkmarc.substack.com/p/the-hackers-guide-to-attacking-ai)
- [3] [À quel point est-il vraiment difficile de faire sortir un agent IA de son sandbox ?](https://www.nccgroup.com/research/how-hard-is-it-really-to-break-an-ai-agent-out-of-its-sandbox/)
- [4] [Sous-agents dans le SDK](https://code.claude.com/docs/en/agent-sdk/subagents)
- [5] [Code source du middleware LangChain TypeSafe Auto Mode](https://github.com/langchain-ai/langchain/blob/master/libs/partners/typesafe/langchain_typesafe/experimental/middleware/auto_mode.py)
- [6] [Jaguosité du modèle Jev de TypeSafe AI : contenu adversarial](https://docs.typesafe.ai/model-jaggedness/jev-1.13#adversarial-content)
- [7] [Jev en tant que juge : comment une politique contrefaite influence Jev](https://securitylabs.datadoghq.com/articles/jev-as-a-judge-how-counterfeit-policy-steers-jev/)
{{#include ../banners/hacktricks-training.md}}
