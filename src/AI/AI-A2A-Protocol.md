# Sécurité du protocole A2A (Agent2Agent)

{{#include ../banners/hacktricks-training.md}}

## Qu’est-ce que A2A

A2A (Agent2Agent) est un protocole ouvert qui permet à un agent d’IA de découvrir un autre agent et de lui envoyer du travail via HTTP. MCP connecte un agent à des **outils et des données** ; A2A connecte un agent à **d’autres agents**, qui sont généralement des services distants gérés par une autre équipe ou entreprise. Un serveur A2A est une API web avec un agent LLM en arrière-plan : les objets propres au protocole (cartes d’agent, tâches, webhooks de notification push, cartes étendues) ajoutent donc des vérifications spécifiques d’authentification, d’IDOR et de SSRF à un test d’API classique.<sup>[[1]](#references)[[2]](#references)</sup>

Les principaux éléments sont :

- **Agent Card:** un document JSON qui décrit l’agent : nom, description, compétences, URL de service, transports pris en charge, capacités (streaming, notifications push, carte étendue) et `securitySchemes` que le client doit utiliser. Il est publié à l’adresse `https://<host>/.well-known/agent-card.json`. Les déploiements plus anciens conformes à la spécification 0.2.x utilisent `/.well-known/agent.json`.<sup>[[1]](#references)[[3]](#references)</sup>
- **Task:** l’unité de travail. Un message crée une tâche (avec un `id` et un `contextId` générés par le serveur), que le client peut ensuite consulter, annuler ou suivre.<sup>[[1]](#references)</sup>
- **Transports :** JSON-RPC 2.0 sur HTTP (avec SSE pour le streaming), gRPC et une liaison REST HTTP+JSON.<sup>[[1]](#references)</sup>
- **Authentification :** les identifiants sont transmis dans les en-têtes HTTP (par exemple `Authorization: Bearer ...`), jamais dans la charge utile JSON-RPC. La carte de l’agent indique le schéma requis.<sup>[[1]](#references)</sup>

Les noms des méthodes ont changé d’une version à l’autre ; essayez donc les deux ensembles :<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

| Opération | JSON-RPC 0.2/0.3 | JSON-RPC 1.0 | REST 1.0 |
| --- | --- | --- | --- |
| Envoyer un message | `message/send` | `SendMessage` | `POST /message:send` |
| Envoi en streaming | `message/stream` | `SendStreamingMessage` | `POST /message:stream` |
| Récupérer une tâche | `tasks/get` | `GetTask` | `GET /tasks/{id}` |
| Lister les tâches | - | `ListTasks` | `GET /tasks` |
| Annuler une tâche | `tasks/cancel` | `CancelTask` | `POST /tasks/{id}:cancel` |
| Configuration des notifications push | `tasks/pushNotificationConfig/set` | `CreateTaskPushNotificationConfig` | `POST /tasks/{id}/pushNotificationConfigs` |
| Carte étendue | `agent/getAuthenticatedExtendedCard` (0.3) ; HTTP `GET agent/authenticatedExtendedCard` (0.2.5) | `GetExtendedAgentCard` | `GET /extendedAgentCard` |

La spécification 1.0 utilise l’en-tête `A2A-Version` (ou un paramètre de requête) pour sélectionner la version ; les requêtes qui ne le précisent pas sont traitées comme des requêtes 0.3.<sup>[[1]](#references)</sup>

## Découverte

```bash
curl -s https://target/.well-known/agent-card.json | jq .
curl -s https://target/.well-known/agent.json | jq .
```

Depuis la carte, notez :

- Chaque `url` de service : dans la version 1.0, ces URL figurent sous `supportedInterfaces`, tandis que les anciennes cartes peuvent exposer une `url` de premier niveau. Notez chaque endpoint et son transport, y compris les noms d’hôte internes, les URL de staging et les ports alternatifs.<sup>[[1]](#references)[[7]](#references)</sup>
- `skills` : elles indiquent ce que l’agent peut faire et quels tools ou données se trouvent derrière lui.
- `securitySchemes` / `security` : s’ils sont vides ou absents, l’agent est probablement conçu pour être appelé sans identifiants.
- `capabilities.pushNotifications` et `capabilities.extendedAgentCard` (dans la version 0.3, `supportsAuthenticatedExtendedCard`).

La spécification indique que la carte publique ne doit pas contenir d’identifiants ni de détails sur l’implémentation interne. La présence d’URL internes, de clés ou de listes détaillées de tools dans une carte publique constitue donc déjà une constatation.<sup>[[1]](#references)</sup>

### Collision de noms d’Agent Card dans un hôte multi-agent

Le `name` d’une carte est un libellé lisible par un humain, et non une identité de routage stable.<sup>[[1]](#references)[[5]](#references)</sup> Si un hôte enregistre deux pairs distants distincts sous le même nom local, son arbre d’agents, le nom de tool généré, sa map de clients ou sa route de broker peut envoyer une tâche destinée au pair de confiance à l’autre pair.<sup>[[5]](#references)</sup> Cela nécessite que le pair contrôlé par l’attaquant soit admis dans le **même espace de noms de routage** ; publier une carte en double sur Internet ne suffit pas à lui seul.<sup>[[5]](#references)</sup>

Testez le parcours **admission-vers-dispatch** de l’hôte avec deux pairs sous votre contrôle, des URL distinctes et un marqueur inoffensif :<sup>[[5]](#references)</sup>

1. Notez la carte, l’origine et le sélecteur local du pair de confiance. Enregistrez un second pair dont la carte possède le même `name`, mais dont l’URL pointe vers un endpoint que vous contrôlez.
2. Déclenchez l’opération qui sélectionne le pair de confiance par son nom. Essayez les deux ordres d’enregistrement et, si les noms deviennent des identifiants de tool, la normalisation habituelle des noms de l’hôte. Capturez l’endpoint qui reçoit le marqueur et l’agent qui renvoie la réponse.
3. Modifiez uniquement le nom de la seconde carte et recommencez. Si une requête atteint le second endpoint uniquement en cas de collision, cela prouve un dispatch vers le mauvais pair. Vérifiez séparément si un contexte sensible ou un identifiant a réellement été joint ; la collision de noms ne prouve **pas**, à elle seule, un transfert d’identifiants ou de l’autorité sur les tools.

Si l’appelant adresse un endpoint fixe lié à une origine plutôt que de résoudre un nom de carte, ce test ne s’applique pas.<sup>[[5]](#references)</sup> Pour examiner les réponses ultérieures d’un pair malveillant et l’impact d’une prompt injection, suivez [AI Agent Security Methodology](AI-Agent-Security-Methodology.md#exploitation-cross-a-trust-boundary).

## Tester les endpoints A2A

### Soumission de tâche sans authentification

Envoyez un message minimal, sans identifiants, à chaque `url` répertoriée dans la carte :

```bash
# 0.2 / 0.3 style
curl -s https://target/a2a -H 'Content-Type: application/json' -d '{
  "jsonrpc":"2.0","id":1,"method":"message/send",
  "params":{"message":{"role":"user","messageId":"6f1c2b9e-0000-4000-8000-000000000001",
            "parts":[{"kind":"text","text":"Reply only with the word PONG."}]}}}'

# 1.0 style
curl -s https://target/a2a -H 'Content-Type: application/json' -H 'A2A-Version: 1.0' -d '{
  "jsonrpc":"2.0","id":1,"method":"SendMessage",
  "params":{"message":{"role":"ROLE_USER","messageId":"6f1c2b9e-0000-4000-8000-000000000002",
            "parts":[{"text":"Reply only with the word PONG."}]}}}'
```

Un résultat `Task` ou `Message` contenant `PONG`, alors que la card déclare un schéma de sécurité, signifie que l’authentification n’est pas appliquée sur le endpoint RPC (elle peut l’être uniquement sur l’UI ou sur la card). Si la card ne déclare aucun schéma, vérifiez ce à quoi les skills de l’agent peuvent accéder : un agent non authentifié capable de lire des données internes ou d’appeler des outils équivaut à une API non authentifiée pour ces outils.

### IDOR sur les tâches (`tasks/get`, `GetTask`, annulation, abonnement)

La spécification exige que le serveur vérifie, à chaque requête, que l’appelant peut accéder à la tâche, et que `ListTasks` soit limité aux tâches de l’appelant, même si aucun filtre n’est fourni.<sup>[[1]](#references)</sup> Testez avec deux identités (A et B) :

1. En tant que A, créez une tâche et enregistrez son `id` et son `contextId`.
2. En tant que B (ou sans identifiants), appelez `tasks/get` / `GetTask` avec l’`id` de A, puis `ListTasks` sans paramètres.
3. Essayez également d’annuler la tâche de A et de vous y abonner, puis envoyez un nouveau message en tant que B contenant le `taskId` ou le `contextId` de A (cela ajouterait le texte de B à la conversation de A).

```json
{"jsonrpc":"2.0","id":2,"method":"tasks/get","params":{"id":"<task id of user A>","historyLength":10}}
```

Vulnérable : B reçoit l'historique, les artefacts ou le statut de A, ou peut modifier la tâche de A. Sécurisé : une `TaskNotFoundError`, sans différence entre « existe, mais ne vous appartient pas » et « n'existe pas ».<sup>[[1]](#references)</sup> Les ID de tâche sont souvent des UUID : recherchez-les aux endroits où ils peuvent leak (liens partagés, logs, payloads de notifications push, messages d'erreur).

### SSRF via le webhook de notification push

Lorsque `capabilities.pushNotifications` est défini sur `true`, le client fournit à l'agent une URL de webhook, puis l'agent envoie des requêtes `POST` contenant les mises à jour de tâche à cette URL. La spécification indique que les agents doivent rejeter les plages privées, localhost et les adresses link-local, et utiliser des allowlists.<sup>[[1]](#references)</sup> Créez une tâche, enregistrez une configuration de notification push dont `url` pointe vers votre hôte OAST pour confirmer les requêtes sortantes, puis (uniquement si le périmètre l'autorise) ciblez des systèmes internes tels que `http://127.0.0.1:<port>/` ou `http://169.254.169.254/`. Comparez les erreurs et les délais pour cartographier les services internes. L'agent ajoute également l'en-tête d'authentification configuré à ces requêtes : vérifiez donc qu'il n'est pas envoyé à un hôte choisi par un attaquant lorsque vous pouvez modifier l'URL de la configuration d'un autre utilisateur. Voir [SSRF](../pentesting-web/ssrf-server-side-request-forgery/).

### Les parties File-URL comme deuxième point d'entrée SSRF

A2A 1.0 permet à un message ou à un artefact de contenir une référence de fichier sous forme de `Part` avec `url` (la version 0.3 utilise `kind: "file"` et `file.uri`).<sup>[[1]](#references)[[4]](#references)[[7]](#references)</sup> Le protocole transporte la référence ; la récupérer relève du comportement de l'application et n'est pas une exigence du SDK A2A.<sup>[[6]](#references)</sup> Ce point est distinct de l'URL de callback de notification push ci-dessus. Testez les deux sens : un fichier fourni par le client et envoyé à un serveur A2A, et une URL de fichier renvoyée par un pair moins fiable à un orchestrateur.<sup>[[1]](#references)[[6]](#references)</sup>

Pour un endpoint JSON-RPC 1.0 autorisé, remplacez la partie texte habituelle par une URL vers un chemin OAST unique et vérifiez **quel composant** effectue la requête :<sup>[[1]](#references)[[7]](#references)</sup>

```bash
curl -s https://target/a2a -H 'Content-Type: application/json' -H 'A2A-Version: 1.0' -d '{
  "jsonrpc":"2.0","id":1,"method":"SendMessage",
  "params":{"message":{"role":"ROLE_USER",
    "messageId":"6f1c2b9e-0000-4000-8000-000000000003",
    "parts":[{"url":"https://oast.example/part-probe","filename":"probe.txt","mediaType":"text/plain"}]}}}'
```

Uniquement si le destinataire le déréférence, testez les destinations internes dans le périmètre, les redirections et les changements de résolution DNS à l’aide du [workflow SSRF](../pentesting-web/ssrf-server-side-request-forgery/). Un `Part` valide ou une réponse de tâche réussie ne prouve pas à lui seul l’existence d’une SSRF ; confirmez que la destination a bien effectué la requête et que le contenu récupéré est transmis à l’agent.<sup>[[6]](#references)</sup>

### Accès à la fiche d’agent étendue

`GetExtendedAgentCard` doit exiger une authentification et peut renvoyer davantage de compétences et de configuration que la fiche publique.<sup>[[1]](#references)</sup> Appelez-le sans identifiants, puis avec une identité disposant de faibles privilèges, et comparez le résultat avec la fiche publique.

### Configuration des notifications push et leaks d’identifiants pendant une tâche

Les configurations de notifications push stockent une URL de webhook et les identifiants que l’agent lui transmet. La spécification exige que chaque opération sur une configuration de notification push (création, récupération, liste, suppression) vérifie que l’appelant peut accéder à la tâche.<sup>[[1]](#references)</sup> Répétez sur ces routes le test avec deux identités de la [section sur l’IDOR des tâches](#task-idor-tasksget-gettask-cancel-subscribe). Une configuration lisible appartenant à un autre utilisateur révèle un token de webhook ; une configuration modifiable redirige les mises à jour de tâche de cet utilisateur vers votre hôte.

Lorsqu’un agent a besoin d’une autorisation supplémentaire pendant une tâche, il fait passer la tâche à `TASK_STATE_AUTH_REQUIRED`. Le client peut organiser l’autorisation hors bande ; la spécification indique que les agents doivent recevoir les identifiants hors bande, sauf si un mécanisme intrabande a été négocié. Un échange intrabande peut transmettre un identifiant le long d’une chaîne d’agents A2A et l’exposer à chaque agent de cette chaîne.<sup>[[1]](#references)</sup> Lors d’un test d’orchestrateur, vérifiez si un identifiant fourni par l’utilisateur pour un agent en aval apparaît dans des messages, des artefacts ou l’historique de la tâche consultables par d’autres agents (ou par d’autres utilisateurs via un IDOR de tâche).

Les champs de la fiche d’agent et les résultats des tâches sont également des entrées non fiables pour l’agent appelant. Testez-les à l’aide des techniques d’injection indirecte de prompt dans [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection) et des vérifications de confiance inter-agents dans [AI Agent Security Methodology](AI-Agent-Security-Methodology.md).



## References

- [1] [Spécification du protocole A2A](https://a2a-protocol.org/latest/specification/)
- [2] [Blog des développeurs Google — Annonce du protocole Agent2Agent (A2A)](https://developers.googleblog.com/en/a2a-a-new-era-of-agent-interoperability/)
- [3] [Spécification A2A v0.2.5](https://github.com/a2aproject/A2A/blob/v0.2.5/docs/specification.md)
- [4] [Spécification A2A v0.3.0](https://github.com/a2aproject/A2A/blob/v0.3.0/docs/specification.md)
- [5] [Attaques par collision de noms d’agents dans les systèmes multi-agents](https://arxiv.org/abs/2609.27624)
- [6] [Guide de sécurité du SDK A2A .NET](https://github.com/a2aproject/a2a-dotnet/blob/main/docs/security.md)
- [7] [Guide de migration A2A Python v1.0](https://github.com/a2aproject/a2a-python/blob/main/docs/migrations/v1_0/README.md)
{{#include ../banners/hacktricks-training.md}}
