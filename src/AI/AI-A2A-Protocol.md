# Sécurité du protocole A2A (Agent2Agent)

{{#include ../banners/hacktricks-training.md}}

## Qu'est-ce que A2A

A2A (Agent2Agent) est un protocole ouvert qui permet à un agent IA d'en découvrir un autre et de lui confier du travail via HTTP. MCP connecte un agent à des **outils et des données** ; A2A connecte un agent à **d'autres agents**, qui sont généralement des services distants détenus par une autre équipe ou entreprise. Un serveur A2A est une API web avec un agent LLM en arrière-plan ; les objets propres au protocole (agent cards, tasks, webhooks de push notifications, extended cards) nécessitent donc des vérifications spécifiques d'authentification, d'IDOR et de SSRF, en plus des tests habituels d'API.<sup>[[1]](#references)[[2]](#references)</sup>

Les principaux éléments sont :

- **Agent Card :** un document JSON qui décrit l'agent : nom, description, compétences, URL(s) de service, transports pris en charge, capacités (streaming, push notifications, extended card) et `securitySchemes` que le client doit utiliser. Il est publié à l'adresse `https://<host>/.well-known/agent-card.json`. Les déploiements plus anciens conformes à la spécification 0.2.x utilisent `/.well-known/agent.json`.<sup>[[1]](#references)[[3]](#references)</sup>
- **Task :** l'unité de travail. Un message crée une tâche (avec un `id` et un `contextId` générés par le serveur), que le client peut ensuite lire, annuler ou suivre.<sup>[[1]](#references)</sup>
- **Transports :** JSON-RPC 2.0 sur HTTP (avec SSE pour le streaming), gRPC et une liaison REST HTTP+JSON.<sup>[[1]](#references)</sup>
- **Authentification :** les identifiants sont transmis dans les en-têtes HTTP (par exemple `Authorization: Bearer ...`), jamais dans le payload JSON-RPC. L'agent card indique le schéma requis.<sup>[[1]](#references)</sup>

Les noms des méthodes ont changé selon les versions ; essayez donc les deux ensembles :<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

| Opération | JSON-RPC 0.2/0.3 | JSON-RPC 1.0 | REST 1.0 |
| --- | --- | --- | --- |
| Envoyer un message | `message/send` | `SendMessage` | `POST /message:send` |
| Envoi en streaming | `message/stream` | `SendStreamingMessage` | `POST /message:stream` |
| Récupérer une tâche | `tasks/get` | `GetTask` | `GET /tasks/{id}` |
| Lister les tâches | - | `ListTasks` | `GET /tasks` |
| Annuler une tâche | `tasks/cancel` | `CancelTask` | `POST /tasks/{id}:cancel` |
| Configuration des push notifications | `tasks/pushNotificationConfig/set` | `CreateTaskPushNotificationConfig` | `POST /tasks/{id}/pushNotificationConfigs` |
| Extended card | `agent/getAuthenticatedExtendedCard` (0.3) ; HTTP `GET agent/authenticatedExtendedCard` (0.2.5) | `GetExtendedAgentCard` | `GET /extendedAgentCard` |

La spécification 1.0 utilise l'en-tête `A2A-Version` (ou un paramètre de requête) pour sélectionner la version ; les requêtes qui ne le contiennent pas sont considérées comme relevant de la version 0.3.<sup>[[1]](#references)</sup>

## Découverte

```bash
curl -s https://target/.well-known/agent-card.json | jq .
curl -s https://target/.well-known/agent.json | jq .
```

À partir de la carte, notez :

- Chaque `url` de service (souvent un nom d’hôte interne, une URL de staging ou un port différent de celui du site public).
- `skills` : elles indiquent ce que l’agent peut faire et quels outils ou quelles données sont accessibles via lui.
- `securitySchemes` / `security` : s’ils sont vides ou absents, l’agent est probablement conçu pour être appelé sans identifiants.
- `capabilities.pushNotifications` et `capabilities.extendedAgentCard` (dans la version 0.3, `supportsAuthenticatedExtendedCard`).

La spécification indique que la carte publique ne doit pas contenir d’identifiants ni de détails sur l’implémentation interne. La présence d’URL internes, de clés ou de listes détaillées d’outils dans une carte publique constitue donc déjà un finding.<sup>[[1]](#references)</sup>

## Test des endpoints A2A

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

Un résultat `Task` ou `Message` contenant `PONG`, alors que la card déclare un schéma de sécurité, signifie que l’authentification n’est pas appliquée sur le endpoint RPC (elle peut l’être uniquement sur l’interface utilisateur ou sur la card). Si la card ne déclare aucun schéma, vérifiez ce à quoi les skills de l’agent peuvent accéder : un agent non authentifié capable de lire des données internes ou d’appeler des outils équivaut à une API non authentifiée pour ces outils.

### Task IDOR (`tasks/get`, `GetTask`, cancel, subscribe)

La spec exige que le serveur vérifie, à chaque requête, que l’appelant peut accéder à la tâche, et que `ListTasks` soit limité aux tâches de l’appelant, même lorsqu’aucun filtre n’est fourni.<sup>[[1]](#references)</sup> Testez cela avec deux identités (A et B) :

1. En tant que A, créez une tâche et enregistrez son `id` et son `contextId`.
2. En tant que B (ou sans identifiants), appelez `tasks/get` / `GetTask` avec l’`id` de A, puis appelez `ListTasks` sans paramètres.
3. Essayez également d’annuler et de suivre la tâche de A, puis envoyez un nouveau message en tant que B en incluant le `taskId` ou le `contextId` de A (cela ajouterait le texte de B à la conversation de A).

```json
{"jsonrpc":"2.0","id":2,"method":"tasks/get","params":{"id":"<task id of user A>","historyLength":10}}
```

Vulnérable : B reçoit l’historique, les artefacts ou l’état de A, ou peut modifier la tâche de A. Sécurisé : une `TaskNotFoundError`, sans différence entre « existe mais ne vous appartient pas » et « n’existe pas ».<sup>[[1]](#references)</sup> Les ID de tâche sont souvent des UUID ; cherchez-les là où ils peuvent fuiter (liens partagés, journaux, payloads de notification push, messages d’erreur).

### SSRF dans le webhook de notification push

Lorsque `capabilities.pushNotifications` vaut `true`, le client fournit à l’agent une URL de webhook, puis l’agent envoie des requêtes `POST` à cette URL avec les mises à jour de tâche. La spécification indique que les agents doivent rejeter les plages privées, localhost et les adresses link-local, et utiliser des listes d’autorisation.<sup>[[1]](#references)</sup> Créez une tâche, enregistrez une configuration de notification push dont le champ `url` pointe vers votre hôte OAST pour confirmer les requêtes sortantes, puis (uniquement si le périmètre l’autorise) vers des cibles internes telles que `http://127.0.0.1:<port>/` ou `http://169.254.169.254/`. Comparez les erreurs et les temps de réponse pour cartographier les services internes. L’agent ajoute également l’en-tête d’authentification configuré à ces requêtes ; vérifiez donc qu’il n’est pas envoyé à un hôte choisi par un attaquant lorsque vous pouvez modifier l’URL de la configuration d’un autre utilisateur. Voir [SSRF](../pentesting-web/ssrf-server-side-request-forgery/).

### Accès à la fiche d’agent étendue

`GetExtendedAgentCard` doit exiger une authentification et peut renvoyer plus de compétences et de configuration que la fiche publique.<sup>[[1]](#references)</sup> Appelez-le sans identifiants, puis avec une identité disposant de faibles privilèges, et comparez le résultat à la fiche publique.

### Configuration de notification push et fuites d’identifiants pendant une tâche

Les configurations de notification push stockent une URL de webhook et les identifiants que l’agent lui envoie. La spécification exige que chaque opération sur une configuration de notification push (création, consultation, liste, suppression) vérifie que l’appelant peut accéder à la tâche.<sup>[[1]](#references)</sup> Répétez sur ces routes le test avec deux identités décrit dans la [section IDOR sur les tâches](#task-idor-tasksget-gettask-cancel-subscribe). La consultation de la configuration d’un autre utilisateur révèle un token de webhook ; sa modification redirige les mises à jour des tâches de cet utilisateur vers votre hôte.

Lorsqu’un agent a besoin d’une autorisation supplémentaire pendant une tâche, il fait passer la tâche à l’état `TASK_STATE_AUTH_REQUIRED`. Le client peut organiser l’autorisation hors bande ; la spécification indique que les agents doivent recevoir les identifiants hors bande, sauf si un mécanisme en bande a été négocié. Un échange en bande peut transmettre un identifiant entre plusieurs agents A2A et l’exposer à chaque agent de cette chaîne.<sup>[[1]](#references)</sup> Lors d’un test d’orchestrateur, vérifiez si un identifiant fourni par l’utilisateur pour un agent en aval apparaît dans des messages, des artefacts ou l’historique de tâche que d’autres agents (ou d’autres utilisateurs via un IDOR sur les tâches) peuvent consulter.

Les champs de la fiche d’agent et les résultats des tâches sont également des entrées non fiables pour l’agent appelant. Testez-les avec les techniques d’injection de prompt indirecte dans [AI Prompts](AI-Prompts.md#third-party-or-indirect-prompt-injection) et les vérifications de confiance inter-agents dans [AI Agent Security Methodology](AI-Agent-Security-Methodology.md).

## References

- [1] [Spécification du protocole A2A](https://a2a-protocol.org/latest/specification/)
- [2] [Blog Google Developers — Annonce du protocole Agent2Agent (A2A)](https://developers.googleblog.com/en/a2a-a-new-era-of-agent-interoperability/)
- [3] [Spécification A2A v0.2.5](https://github.com/a2aproject/A2A/blob/v0.2.5/docs/specification.md)
- [4] [Spécification A2A v0.3.0](https://github.com/a2aproject/A2A/blob/v0.3.0/docs/specification.md)
{{#include ../banners/hacktricks-training.md}}
