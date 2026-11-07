# Limites de confiance des passerelles LLM

{{#include ../banners/hacktricks-training.md}}

Une passerelle LLM gère le routage des modèles et détient souvent les identifiants des fournisseurs. Ses appelants API ordinaires ne doivent donc pas hériter des privilèges de configuration ni des autorisations au niveau du fournisseur. L’évaluation de la passerelle LiteLLM en version 1.77.7 illustre deux limites distinctes : l’autorisation des sessions UI pour la configuration administrative et la configuration de routage fournie par l’appelant pour l’inférence. Les problèmes signalés ont été corrigés dans la version 1.83.9.<sup>[[1]](#references)</sup>

## La classification des routes UI n’est pas une autorisation

Dans la version de LiteLLM évaluée, les clés de connexion à l’UI appartenaient à l’équipe `litellm-dashboard`. L’autorisation identifiait une clé comme jeton UI à partir de l’identifiant de cette équipe, quel que soit le rôle de l’utilisateur. La vérification des routes UI acceptait ensuite toute route commençant par un préfixe autorisé. Par conséquent, l’entrée `/config` correspondait aussi au handler administratif `/config/update`. Ce handler exigeait une authentification générique, mais ne vérifiait pas indépendamment que l’utilisateur disposait du rôle `PROXY_ADMIN`. Une session UI aux privilèges inférieurs pouvait donc accéder à l’écriture de configuration.<sup>[[1]](#references)</sup>

Il ne s’agit pas d’un désaccord entre le proxy et le backend sur la normalisation d’un chemin : le code d’autorisation et le handler n’accordent pas les mêmes privilèges sur la *même* route.<sup>[[1]](#references)</sup> Lors de l’examen d’une passerelle, comparez la classification des jetons, la correspondance exacte des routes et des méthodes, ainsi que la vérification du rôle effectuée par le handler lui-même.<sup>[[1]](#references)</sup> Consultez [l’autorisation des API web](../pentesting-web/web-api-pentesting.md), les [contournements 401/403](../pentesting-web/403-and-401-bypasses.md) et les [exemptions de préfixe du proxy](../pentesting-web/proxy-waf-protections-bypass.md#prefix-exemptions-become-routing-keys) pour découvrir des limites connexes, mais distinctes.

## Les écritures de configuration dépassent le simple stockage de la configuration

La même mise à jour de configuration LiteLLM acceptait des valeurs de variables d’environnement et les appliquait au processus en cours. Un composant utilisait `UI_LOGO_PATH` comme chemin local pour un `FileResponse`, sans vérifier qu’il s’agissait d’un logo ; un autre lisait `UI_USERNAME` et `UI_PASSWORD` lors d’une connexion hors SSO et attribuait le rôle `PROXY_ADMIN` si les valeurs correspondaient. Ainsi, un droit d’écriture de configuration pouvait entraîner la divulgation de fichiers locaux ou la modification d’une identité administrative, selon le composant en aval. Le type MIME de la réponse ne garantit pas que le fichier servi soit une image.<sup>[[1]](#references)</sup>

La configuration des endpoints pass-through constituait un autre point d’injection en aval. L’initialisation acceptait des cibles d’adaptateurs S3/GCS distantes, téléchargeait des modules Python et les importait avec `exec_module` de `importlib`. L’import exécute le code de niveau supérieur avant l’utilisation d’une instance d’adaptateur ; restreindre uniquement l’invocation de l’adaptateur ne supprime donc pas cette limite d’exécution. Traitez cela comme un chargement de code contrôlé par la configuration, et non comme une désérialisation de fichier de modèle.<sup>[[1]](#references)</sup> Pour la primitive distincte de lecture de fichiers, consultez [l’inclusion de fichiers et le path traversal](../pentesting-web/file-inclusion/).

## Le routage des modèles par requête peut provoquer un leak des identifiants de la passerelle

La fonctionnalité d’identifiants côté client de LiteLLM acceptait un objet `user_config` dans une requête LLM. La route évaluée créait un `litellm.Router` temporaire à partir de cet objet, notamment sa liste de modèles et le `api_base` du fournisseur. Une destination de fournisseur contrôlée par l’appelant pouvait recevoir la requête de complétion sortante de la passerelle ainsi que les en-têtes d’authentification configurés pour le fournisseur. Les restrictions portant sur les champs `api_base` ou `api_key` de premier niveau ne couvraient pas ce chemin de configuration imbriqué distinct. Il s’agit d’une limite SSRF impliquant des identifiants, et non d’un problème d’injection de prompt.<sup>[[1]](#references)</sup>

Lors d’une évaluation autorisée de la passerelle, comparez tous les chemins susceptibles de créer un routeur ou un client fournisseur, y compris la configuration par requête, avec la politique de destination et d’identifiants appliquée par la route normalement configurée.<sup>[[1]](#references)</sup> Le [guide SSRF](../pentesting-web/ssrf-server-side-request-forgery/) traite du contrôle général des destinations côté serveur ; la défaillance propre à la passerelle consiste à laisser un objet de requête moins fiable choisir une destination tout en réutilisant des identifiants sortants privilégiés.<sup>[[1]](#references)</sup>

## L’enregistrement d’un guardrail peut contourner un bac à sable réservé à l’UI

Le chemin de test de code d’une passerelle et son chemin d’enregistrement de code peuvent appliquer des validations différentes. Dans LiteLLM avant la version 1.82.0, le test de custom guardrail dans l’UI rejetait la syntaxe dangereuse et exécutait le code avec `__builtins__ = {}`, mais `POST /guardrails` compilait le `custom_code` soumis avec `exec(compile(...), exec_globals)` sans appliquer aucun de ces contrôles. Python insère les builtins dans un dictionnaire global dépourvu de `__builtins__`. Les imports et commandes de niveau module s’exécutaient donc **lors de l’enregistrement du guardrail**, avant tout appel d’inférence. Le callback ultérieur `apply_guardrail` pouvait exposer un résultat stocké dans son motif de blocage.<sup>[[2]](#references)[[3]](#references)</sup>

Lors d’un test autorisé, comparez les handlers de test et d’enregistrement au lieu de supposer qu’un test réussi dans le bac à sable de l’UI garantit la sécurité de l’enregistrement. La forme de la requête signalée avant le correctif était la suivante :<sup>[[2]](#references)</sup>

```http
POST /guardrails HTTP/1.1
Authorization: Bearer <master_key>
Content-Type: application/json

{
  "guardrail": {
    "guardrail_name": "probe",
    "litellm_params": {
      "guardrail": "custom_code", "mode": "pre_call", "default_on": true,
      "custom_code": "import os\nresult = os.popen('id').read()\ndef apply_guardrail(inputs, request_data, input_type):\n    return {'action': 'block', 'reason': result}"
    }
  }
}
```

Le point de terminaison d’inscription acceptait également les clés API ordinaires, car il ne vérifiait pas le rôle `PROXY_ADMIN`. Lorsqu’aucune clé principale ni authentification JWT/OAuth2 n’était configurée, le gestionnaire d’authentification antérieur au correctif attribuait le rôle `PROXY_ADMIN`, même aux requêtes anonymes. Le correctif a remplacé le rôle sans authentification par `INTERNAL_USER`, ajouté des contrôles admin de garde-fou, et validé et restreint les builtins lors de l’inscription. Ces frontières entre rôles et exécution de code sont distinctes du [problème de repli de jeton MCP](AI-MCP-Servers.md#mcp-token-passthrough-must-not-create-an-anonymous-session).<sup>[[2]](#references)[[3]](#references)</sup>

## Les routes de relais administratives peuvent accéder aux métadonnées cloud

La fonctionnalité de points de terminaison pass-through de LiteLLM permet à un administrateur de configurer une cible HTTP et, éventuellement, d’y ajouter des sous-chemins. Contrairement au problème de routage `user_config` par requête ci-dessus, cela nécessite une **autorité d’écriture de la configuration** ; la fonctionnalité est conçue pour faire confiance aux administrateurs. Dans le déploiement signalé, la cible n’était pas vérifiée pour exclure les adresses privées ou de liaison locale.<sup>[[2]](#references)[[4]](#references)</sup> Avant la v1.83.0, les clés authentifiées ordinaires pouvaient également accéder à `/config/update`, car cette route ne vérifiait pas le rôle administrateur ; voir [classification des routes de l’interface utilisateur](#ui-route-classification-is-not-authorization) pour la frontière connexe concernant l’écriture de la configuration.<sup>[[2]](#references)[[6]](#references)</sup>

Avec cette autorité et une connectivité réseau entre le proxy et les métadonnées EC2, une route telle que celle qui suit expose les métadonnées via la passerelle. Le paramètre `include_subpath` fait correspondre `/meta/meta-data/iam/security-credentials/` à un chemin sous `/latest/`.<sup>[[2]](#references)[[4]](#references)</sup>

```http
POST /config/pass_through_endpoint HTTP/1.1
Authorization: Bearer <master_key>
Content-Type: application/json

{"path":"/meta","target":"http://169.254.169.254/latest/","headers":{},"include_subpath":true}
```

Le [guide Cloud SSRF](../pentesting-web/ssrf-server-side-request-forgery/cloud-ssrf.md#aws) couvre l’échange de jeton IMDSv2 ; cette route doit autoriser sa requête `PUT` et relayer les deux en-têtes de métadonnées.<sup>[[5]](#references)</sup> Le traitement générique des en-têtes pass-through de LiteLLM supprime le préfixe `x-pass-` avant le transfert ; `x-pass-X-aws-ec2-metadata-token-ttl-seconds: 21600` et `x-pass-X-aws-ec2-metadata-token: <token>` peuvent donc fournir ces en-têtes.<sup>[[2]](#references)[[7]](#references)</sup> Le proxy doit pouvoir atteindre IMDS, la réponse du jeton doit traverser la limite de sauts configurée et la requête du jeton ne doit pas inclure `X-Forwarded-For`.<sup>[[5]](#references)</sup> La variante propre à la gateway consiste à associer une **route persistante contrôlée par l’administrateur et un relais des en-têtes de requête**.

## References

- [1] [Check Point Research — Quand les gateways LLM déraillent : conclusions de l’analyse de LiteLLM](https://research.checkpoint.com/2026/when-llm-gateways-go-wrong-findings-from-litellm/)
- [2] [Wiz — À l’abri ? Briser LiteLLM, du contournement de l’authentification à la compromission du cloud](https://wiz.io/blog/off-guard-breaking-litellm-from-authentication-bypass-to-cloud-compromise)
- [3] [LiteLLM PR #22095 — corriger la RCE sans authentification et l’évasion du sandbox dans la protection du code personnalisé](https://github.com/BerriAI/litellm/pull/22095)
- [4] [LiteLLM — Créer des endpoints Pass Through](https://docs.litellm.ai/docs/proxy/pass_through)
- [5] [AWS — Fonctionnement de la version 2 du service de métadonnées d’instance](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-metadata-v2-how-it-works.html)
- [6] [Avis LiteLLM — endpoint de configuration du proxy sans restriction](https://github.com/advisories/GHSA-53mr-6c8q-9789)
- [7] [Implémentation du transfert des en-têtes pass-through de LiteLLM](https://github.com/BerriAI/litellm/blob/v1.84.0/litellm/passthrough/utils.py)
{{#include ../banners/hacktricks-training.md}}
