# Méthodologie de sécurité des agents IA

{{#include ../banners/hacktricks-training.md}}

Une évaluation d’agent doit suivre **un chemin allant d’une entrée contrôlée par l’attaquant à un effet observable de l’extérieur**. Le jailbreaking, les changements de caractère et la divulgation du system prompt prouvent qu’un canal de raisonnement peut être influencé, mais la découverte à fort impact est la chaîne qui mène à l’accès aux données, à une action non autorisée via un outil, à un sink d’injection en aval, à une persistance ou à un autre agent.<sup>[[2]](#references)</sup>

L’[OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) est utile pour étiqueter la couverture (détournement d’objectif, mauvaise utilisation des outils, abus de privilèges, chaîne d’approvisionnement, exécution de code, empoisonnement de la mémoire, confiance inter-agents, défaillances en cascade, confiance humaine et agents malveillants). Utilisez ces étiquettes après avoir construit un chemin d’attaque de bout en bout, plutôt que de considérer le texte inattendu d’un modèle comme la fin du test.<sup>[[1]](#references)[[2]](#references)</sup>

## Établir la carte de la cible

Pour chaque workflow d’agent, consignez ces cinq dimensions avant de rédiger des payloads :<sup>[[2]](#references)</sup>

| Dimension | Éléments à inventorier | Question de sécurité |
|---|---|---|
| **Entrée non fiable** | Paramètres Chat/API, URL, documents, e-mails, tickets, entrées de calendrier, fragments récupérés, mémoire, résultats d’outils et messages d’agents pairs | Où un attaquant peut-il placer du contenu qui sera ensuite intégré au contexte du modèle ? |
| **Outils** | Noms et schémas des outils, effets secondaires, exécution automatique, comportement de confirmation et outils chargés dynamiquement | Quels appels lisent des secrets, modifient l’état, envoient des messages, suppriment des données, exécutent du code ou transfèrent de la valeur ? |
| **Autorité** | Délégation de l’utilisateur, comptes de service, API tokens, durée de vie des identifiants, portée des tenants/ressources et accès réseau | Sous quelle identité chaque appel s’exécute-t-il, et l’autorisation est-elle vérifiée à nouveau à la frontière de l’outil ? |
| **Traitement** | Constructeurs de requêtes, shells, récupérateurs d’URL, moteurs de templates, interpréteurs, parseurs, opérations sur fichiers et désérialiseurs | Où les données générées par le modèle deviennent-elles une syntaxe destinée à un autre interpréteur ? |
| **Sortie** | Réponses, Markdown/HTML rendu, liens, récupération d’images, webhooks, e-mails, fichiers, journaux, rapports, métriques et trafic entre agents pairs | Quel canal observable peut transporter un secret ou déclencher une requête secondaire ? |

Ne réduisez pas cette analyse à une liste d’intégrations annoncées. Un livrable utile relie chaque source à la position exacte du contexte qu’elle atteint, aux outils disponibles à cet endroit, aux identifiants utilisés par chaque outil, à l’interpréteur en aval et à toutes les voies de sortie. Un même outil peut avoir un impact faible avec un token de lecture propre à l’utilisateur et être critique avec un identifiant administrateur partagé.<sup>[[2]](#references)</sup>

## Reconnaissance

### Cartographier chaque voie de livraison et d’ingestion

Commencez par la surface de livraison (web, mobile, API, e-mail, plateforme de chat, extension de navigateur) et interceptez le trafic entre le client et le backend. Examinez les champs masqués par l’interface, les paramètres de recherche/autocomplétion/filtrage, les objets d’état de conversation, les tâches d’importation et d’indexation, les réponses des outils et le trafic des sous-agents. Les clients exclusivement mobiles peuvent nécessiter un émulateur et une instrumentation pour contourner le certificate pinning avant que le véritable schéma de requête soit visible.<sup>[[2]](#references)</sup>

Cartographiez ensuite la pile sous le modèle : framework d’orchestration, assemblage des prompts, stockage de la récupération et de la mémoire, runtime (par exemple Python, conteneur ou WASM), volumes montés, services hôtes, API internes, accès aux métadonnées cloud et réseaux voisins. Les valeurs par défaut du framework comptent, car certains « appels d’outils » sont implémentés en générant ou en évaluant du code ; la frontière entre runtime et sandbox détermine si le résultat reste confiné.<sup>[[2]](#references)</sup>

### Identifier le routage avec des sondes non destructives

Comparez une requête dans le périmètre à plusieurs requêtes sans rapport, en conservant la réponse complète, le code d’état, la latence et le comportement du streaming. Un rejet stable avant tout raisonnement propre à la tâche peut indiquer une passerelle/classificateur distinct ; un refus contextuel suggère que la requête a atteint le modèle ; une réponse vide ou purement extractive peut indiquer une recherche par mots-clés ou une récupération limitée. Considérez ces éléments comme des hypothèses et confirmez-les en rejouant la même sonde via d’autres champs API et voies d’ingestion.<sup>[[2]](#references)</sup>

La reconnaissance est terminée lorsque l’évaluation peut nommer la première source contrôlée par l’attaquant qui modifie le comportement de l’agent **ainsi que** les outils, identités, interpréteurs et sorties accessibles depuis cette source.<sup>[[2]](#references)</sup>

## Exploitation : franchir une frontière de confiance

Testez les canaux, pas seulement la formulation des prompts. Commencez par une injection directe pour établir ce que bloque la porte d’entrée visible, puis répétez une intention équivalente via les voies moins visibles ci-dessous :<sup>[[2]](#references)</sup>

- **Contenu indirect :** pages, fichiers, e-mails, tickets, métadonnées, texte alternatif, commentaires HTML, texte hors écran ou caractères de largeur nulle. Consultez [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection) pour les techniques de livraison de payloads.
- **Récupération et mémoire :** empoisonnez du contenu qui sera récupéré ultérieurement ou un état qui sera rechargé lors de sessions ultérieures. Notez si la suppression de la source d’origine élimine le comportement.
- **Sortie d’outil et agents pairs :** placez le marqueur dans une réponse d’outil ou un message entre agents afin de vérifier si le trafic interne contourne les filtres appliqués uniquement aux entrées utilisateur et aux sorties finales.
- **Chaîne d’approvisionnement :** examinez les descripteurs d’outils, les plugins, les serveurs connectés, les skills, les modèles et les dépendances en tant que sources d’instructions fiables. Pour des tests spécifiques à MCP, consultez [MCP Servers](AI-MCP-Servers.md#mcp-vulns).
- **Approbation humaine :** comparez l’appel d’outil structuré réel au texte d’approbation généré par le modèle. Vérifiez si l’influence de l’attaquant peut omettre la destination, la portée, les objets concernés ou les effets secondaires irréversibles.

Commencez par un marqueur unique et inoffensif. Conservez l’artefact source, le contexte assemblé si celui-ci est observable, l’appel d’outil sélectionné, les données d’approbation, la requête/réponse du backend et l’état final. Cela permet de distinguer l’influence d’une affirmation hallucinée selon laquelle une action aurait eu lieu.<sup>[[2]](#references)</sup>

## Exécution : démontrer un impact réel

Il existe deux voies distinctes entre l’influence et l’impact :<sup>[[2]](#references)</sup>

1. **Abus de capacités :** l’outil autorisé réalise déjà l’objectif. Par exemple, lire le dossier d’un tenant et l’écrire dans un rapport visible par l’attaquant, envoyer un e-mail, modifier des dossiers, supprimer un fichier ou initier un paiement. Aucun bug logiciel secondaire n’est nécessaire.
2. **Exploitation d’un sink en aval :** la sortie du modèle, orientée par l’attaquant, devient une syntaxe destinée à un autre composant. Examinez les requêtes de base de données pour détecter des [SQL injection](../pentesting-web/sql-injection/README.md) ou [NoSQL injection](../pentesting-web/nosql-injection.md), les wrappers shell pour détecter une [command injection](../pentesting-web/command-injection.md), les URL choisies pour détecter une [SSRF](../pentesting-web/ssrf-server-side-request-forgery/README.md), les opérations sur fichiers pour détecter du path traversal, les évaluateurs de templates/code pour détecter du RCE et les parseurs d’objets pour détecter une [unsafe deserialization](../pentesting-web/deserialization/README.md).

Pour chaque piste, démontrez cette chaîne :<sup>[[2]](#references)</sup>

```text
attacker-controlled source
  -> model/context influence
  -> selected tool and arguments
  -> effective identity/credential
  -> capability or vulnerable sink
  -> externally verified state change or data egress
```

Une intégration en lecture seule reste exploitable si un composant ultérieur peut publier ce qu’elle a lu. Testez les réponses ordinaires ainsi que les canaux d’egress moins évidents, tels que les liens contrôlés par l’attaquant, la récupération automatique d’images, les webhooks, les logs, les rapports, les compteurs, les notifications et les messages envoyés à d’autres agents.<sup>[[2]](#references)</sup>

## Actions sur les objectifs

Après avoir confirmé une action, évaluez l’ensemble du périmètre d’impact au lieu de vous arrêter au premier effet visible :<sup>[[2]](#references)</sup>

- **Exfiltration :** des secrets, des dossiers utilisateur, des fichiers internes, des données de conversation ou le contenu du prompt/contexte sortent par un canal observable.
- **Action non autorisée :** l’agent utilise des capacités d’écriture légitimes pour servir l’objectif de l’attaquant.
- **Déni de service :** des outils destructeurs ou des opérations coûteuses répétées affectent l’intégrité ou la disponibilité.
- **Persistance :** une mémoire empoisonnée, du contenu indexé, un état de confiance ou des modifications du runtime persistent après la session ou la suppression de la source à l’origine de l’attaque.
- **Propagation :** un pair de confiance consomme le message ou l’état partagé de l’agent compromis et répète l’action avec ses propres outils et identifiants.

La gravité doit dépendre des données accessibles, des privilèges effectifs, de l’exploitabilité du sink, de l’egress, de la persistance et de la propagation — et non du caractère surprenant du texte généré par le modèle.<sup>[[2]](#references)</sup>

## Contrôles à valider pendant l’évaluation

Les filtres de prompt et un meilleur prompt système peuvent augmenter le coût pour l’attaquant, mais ne doivent pas être considérés comme des frontières d’autorisation. Validez les contrôles ci-dessous en rejouant la même chaîne via les entrées directes, le contenu indirect, la mémoire, les outils et les agents pairs :<sup>[[2]](#references)</sup>

- Une couche de policy déterministe vérifie l’utilisateur authentifié, le tenant, l’objet, l’action et la destination à **chaque invocation d’outil** ; le modèle ne peut ni fournir ni remplacer l’identité de l’appelant.
- Les capacités de lecture et d’écriture utilisent des identifiants distincts, à privilèges minimaux et de courte durée ; les outils à fort impact ne sont exposés qu’au moment opportun et ne s’exécutent jamais automatiquement à partir du contenu ingéré.
- L’egress réseau et les destinations internes sont soumises à une liste d’autorisation indépendante des URL choisies par le modèle ; l’accès du runtime aux endpoints de métadonnées, aux secrets montés et aux services voisins est bloqué, sauf nécessité.
- L’interface d’approbation est générée à partir de la requête structurée canonique et affiche les arguments exacts, l’identité, la destination, les objets concernés et les effets secondaires — pas un résumé en texte libre généré par le modèle.
- La réussite est vérifiée auprès du système de destination ou du système de référence. Le récit de l’agent, une demande d’appel d’outil ou une redirection HTTP ne prouvent pas que le changement d’état annoncé a eu lieu.
- Les entrées de mémoire et de récupération conservent leur provenance et leurs labels de confiance, peuvent être invalidées et sont soumises à une nouvelle autorisation lorsqu’elles servent à une action ultérieure.
- Les messages inter-agents sont authentifiés et autorisés en tant que requêtes non fiables ; la réputation d’un pair ou sa fiche d’agent ne délègue pas implicitement les outils du destinataire.

## References

- [1] [Top 10 OWASP des applications agentiques pour 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [2] [Le guide du hacker pour attaquer les agents IA](https://darkmarc.substack.com/p/the-hackers-guide-to-attacking-ai)
{{#include ../banners/hacktricks-training.md}}
