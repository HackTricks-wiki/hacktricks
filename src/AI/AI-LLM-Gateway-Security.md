# Limites de confiance des passerelles LLM

{{#include ../banners/hacktricks-training.md}}

Une passerelle LLM gère le routage des modèles et détient souvent les identifiants des fournisseurs. Ses appelants API ordinaires ne doivent donc pas hériter des privilèges liés à la configuration ou aux fournisseurs. L’évaluation de la passerelle LiteLLM en version 1.77.7 illustre deux limites distinctes : l’autorisation des sessions UI pour la configuration administrative et la configuration de routage fournie par l’appelant pour l’inférence. Les problèmes signalés ont été corrigés dans la version 1.83.9.<sup>[[1]](#references)</sup>

## La classification des routes UI ne constitue pas une autorisation

Dans la version de LiteLLM évaluée, les clés de connexion à l’UI appartenaient à l’équipe `litellm-dashboard`. L’autorisation classait une clé comme jeton UI en fonction de l’identifiant de cette équipe, quel que soit le rôle de l’utilisateur. La vérification des routes UI acceptait ensuite toute route commençant par un préfixe autorisé. Par conséquent, l’entrée `/config` correspondait aussi au handler administratif `/config/update`. Ce handler exigeait une authentification générique, mais ne vérifiait pas indépendamment que l’utilisateur avait le rôle `PROXY_ADMIN`. Une session UI disposant de privilèges inférieurs pouvait donc accéder à l’écriture de la configuration.<sup>[[1]](#references)</sup>

Il ne s’agit pas d’une incohérence de normalisation des chemins entre un proxy et un backend : le code d’autorisation et le handler ne s’accordent pas sur les privilèges associés à la *même* route.<sup>[[1]](#references)</sup> Lors de l’analyse d’une passerelle, comparez la classification des jetons, la correspondance exacte des routes et des méthodes, ainsi que la vérification du rôle effectuée par le handler lui-même.<sup>[[1]](#references)</sup> Voir [l’autorisation des API web](../pentesting-web/web-api-pentesting.md), les [contournements de 401/403](../pentesting-web/403-and-401-bypasses.md) et les [exemptions de préfixe de proxy](../pentesting-web/proxy-waf-protections-bypass.md#prefix-exemptions-become-routing-keys) pour découvrir des limites connexes, mais distinctes.

## Les écritures de configuration ont des effets au-delà du stockage de la configuration

La même mise à jour de configuration LiteLLM acceptait des valeurs de variables d’environnement et les appliquait au processus en cours d’exécution. Un composant utilisait `UI_LOGO_PATH` comme chemin local pour un `FileResponse`, sans vérifier qu’il désignait un logo ; un autre lisait `UI_USERNAME` et `UI_PASSWORD` lors d’une connexion sans SSO et attribuait le rôle `PROXY_ADMIN` en cas de correspondance. Ainsi, le droit d’écriture de la configuration pouvait entraîner à la fois la divulgation de fichiers locaux et la modification d’une identité administrative, selon le composant en aval. Le type MIME de la réponse ne garantit pas que le fichier servi est une image.<sup>[[1]](#references)</sup>

La configuration de l’endpoint pass-through constituait un autre point d’entrée en aval. À l’initialisation, les cibles d’adaptateur S3/GCS distantes étaient acceptées, les modules Python étaient téléchargés, puis importés à l’aide de `exec_module` d’`importlib`. L’importation exécute le code de niveau supérieur avant l’utilisation d’une instance d’adaptateur ; restreindre uniquement l’invocation de l’adaptateur ne supprimerait donc pas cette limite d’exécution. Traitez cela comme un chargement de code contrôlé par la configuration, et non comme une désérialisation de fichier de modèle.<sup>[[1]](#references)</sup> Pour le primitive distincte de lecture de fichiers, voir [l’inclusion de fichiers et le path traversal](../pentesting-web/file-inclusion/).

## Le routage des modèles par requête peut leak les identifiants de la passerelle

La fonctionnalité d’identifiants côté client de LiteLLM acceptait un objet `user_config` dans une requête LLM. La route évaluée créait un `litellm.Router` temporaire à partir de cet objet, y compris sa liste de modèles et le `api_base` du fournisseur. Une destination de fournisseur contrôlée par l’appelant pouvait recevoir la requête de complétion sortante de la passerelle et les en-têtes d’authentification configurés du fournisseur. Les restrictions visant les champs `api_base` ou `api_key` de premier niveau ne couvraient pas cette autre voie de configuration imbriquée. Il s’agit d’une limite SSRF portant des identifiants, et non d’un problème d’injection de prompt.<sup>[[1]](#references)</sup>

Lors d’une évaluation autorisée d’une passerelle, comparez chaque voie pouvant construire un routeur ou un client de fournisseur — y compris la configuration par requête — à la politique de destination et d’identifiants utilisée par la route normalement configurée.<sup>[[1]](#references)</sup> Le [guide SSRF](../pentesting-web/ssrf-server-side-request-forgery/) couvre le contrôle général des destinations côté serveur ; la faille propre aux passerelles consiste à laisser un objet de requête moins fiable choisir une destination tout en réutilisant des identifiants sortants privilégiés.<sup>[[1]](#references)</sup>

## References

- [1] [Check Point Research — Quand les passerelles LLM déraillent : découvertes issues de LiteLLM](https://research.checkpoint.com/2026/when-llm-gateways-go-wrong-findings-from-litellm/)
{{#include ../banners/hacktricks-training.md}}
